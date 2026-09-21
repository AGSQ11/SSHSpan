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
        }
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

#[derive(Clone)]
pub struct Database {
    pub pool: SqlitePool,

    pub db_path: PathBuf,
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

/// Run an async block to completion, blocking the current thread.
///
/// When called from inside the Tauri/tokio async runtime (an async command)
/// it uses `block_in_place` to run the future on the current worker instead
/// of nesting a runtime. When called from a plain thread (startup, sync
/// commands, tests) it uses a cached runtime to avoid re-creating one per
/// call.
fn block<F: std::future::Future<Output = T>, T>(f: F) -> T {
    if tokio::runtime::Handle::try_current().is_ok() {
        tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(f))
    } else {
        cached_runtime().block_on(f)
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

    /// Open/migrate a database at an explicit path. Test/isolation entry point
    /// (the app itself always goes through [`Database::new`], which honors the
    /// `SSHSPAN_DB` override and the platform data dir).
    #[cfg(test)]
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
                    updated_at          TEXT NOT NULL
                )
                "#,
            )
            .execute(&self.pool)
            .await?;
            sqlx::query(
                "CREATE INDEX IF NOT EXISTS idx_transfer_queue_state ON transfer_queue(state)",
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

    pub fn update_key(&self, key: &KeyRecord) -> Result<()> {
        block(async {
            sqlx::query(
                r#"
                UPDATE keys SET
                    name = ?, key_type = ?, public_key = ?, private_key_encrypted = ?,
                    fingerprint_sha256 = ?, fingerprint_md5 = ?, comment = ?, updated_at = ?,
                    deployed = ?, deploy_path = ?, bitwarden_id = ?, bitwarden_sync = ?,
                    bitwarden_revision_ts = ?, bitwarden_updated_at = ?
                WHERE id = ?
                "#,
            )
            .bind(&key.name)
            .bind(&key.key_type)
            .bind(&key.public_key)
            .bind(&key.private_key_encrypted)
            .bind(&key.fingerprint_sha256)
            .bind(&key.fingerprint_md5)
            .bind(&key.comment)
            .bind(key.updated_at.to_rfc3339())
            .bind(key.deployed as i64)
            .bind(&key.deploy_path)
            .bind(&key.bitwarden_id)
            .bind(key.bitwarden_sync as i64)
            .bind(key.bitwarden_revision_ts.map(|v| v.to_string()))
            .bind(key.bitwarden_updated_at.map(|v| v.to_string()))
            .bind(&key.id)
            .execute(&self.pool)
            .await?;
            Ok(())
        })
    }

    pub fn delete_key(&self, id: &str) -> Result<()> {
        block(async {
            sqlx::query("DELETE FROM keys WHERE id = ?")
                .bind(id)
                .execute(&self.pool)
                .await?;
            Ok(())
        })
    }

    /// Update only Bitwarden sync metadata on a key row (lightweight, no full record needed).
    pub fn update_key_sync_meta(
        &self,
        id: &str,
        bitwarden_id: &str,
        revision_date: Option<&str>,
    ) -> Result<()> {
        let rev_ts = revision_date
            .and_then(|rd| chrono::DateTime::parse_from_rfc3339(rd).ok())
            .map(|rd| rd.timestamp_millis().to_string());
        let now_ts = chrono::Utc::now().timestamp_millis().to_string();
        block(async {
            sqlx::query(
                "UPDATE keys SET bitwarden_id = ?, bitwarden_revision_ts = ?, bitwarden_updated_at = ? WHERE id = ?"
            )
            .bind(bitwarden_id)
            .bind(&rev_ts)
            .bind(&now_ts)
            .bind(id)
            .execute(&self.pool)
            .await?;
            Ok(())
        })
    }

    pub fn get_key(&self, id: &str) -> Result<Option<KeyRecord>> {
        block(async {
            let row = sqlx::query("SELECT * FROM keys WHERE id = ?")
                .bind(id)
                .fetch_optional(&self.pool)
                .await?;
            Ok(row.map(|r| Self::row_to_key(r)))
        })
    }

    pub fn list_keys(&self) -> Result<Vec<KeyRecord>> {
        block(async {
            let rows = sqlx::query("SELECT * FROM keys ORDER BY created_at DESC")
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

    pub fn save_bitwarden_config(&self, config: &BitwardenConfig) -> Result<()> {
        block(async {
            let fields: [(&str, Option<String>); 8] = [
                ("server_url", config.server_url.clone()),
                ("email", config.email.clone()),
                ("master_password", config.master_password.clone()),
                ("folder_name", config.folder_name.clone()),
                ("servers_folder_name", config.servers_folder_name.clone()),
                ("device_id", config.device_id.clone()),
                ("last_sync", config.last_sync.map(|d| d.to_rfc3339())),
                ("last_result", config.last_result.clone()),
            ];

            for (key, value) in fields {
                if let Some(v) = value {
                    sqlx::query(
                        "INSERT INTO bitwarden_config (key, value, updated_at) VALUES (?, ?, ?) \
                         ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at"
                    )
                    .bind(key)
                    .bind(v)
                    .bind(Utc::now().to_rfc3339())
                    .execute(&self.pool)
                    .await?;
                }
            }
            Ok(())
        })
    }

    pub fn load_bitwarden_config(&self) -> Result<BitwardenConfig> {
        block(async {
            let rows = sqlx::query("SELECT key, value FROM bitwarden_config")
                .fetch_all(&self.pool)
                .await?;

            let mut config = BitwardenConfig::default();
            for row in rows {
                let key: String = row.get("key");
                let value: String = row.get("value");
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
                    _ => {}
                }
            }
            Ok(config)
        })
    }

    // ── AI assistant config ────────────────────────────────────────────────

    pub fn save_assistant_config(&self, config: &AssistantConfig) -> Result<()> {
        block(async {
            let fields: [(&str, Option<String>); 4] = [
                ("provider", config.provider.clone()),
                ("base_url", config.base_url.clone()),
                ("model", config.model.clone()),
                ("api_key", config.api_key.clone()),
            ];

            for (key, value) in fields {
                if let Some(v) = value {
                    sqlx::query(
                        "INSERT INTO assistant_config (key, value, updated_at) VALUES (?, ?, ?) \
                         ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at"
                    )
                    .bind(key)
                    .bind(v)
                    .bind(Utc::now().to_rfc3339())
                    .execute(&self.pool)
                    .await?;
                } else {
                    // None means "clear this row" - the bitwarden table keeps
                    // stale values on None, which is fine for folder names but
                    // wrong for a sealed secret: clearing the provider must
                    // not leave its key behind.
                    sqlx::query("DELETE FROM assistant_config WHERE key = ?")
                        .bind(key)
                        .execute(&self.pool)
                        .await?;
                }
            }
            Ok(())
        })
    }

    pub fn load_assistant_config(&self) -> Result<AssistantConfig> {
        block(async {
            let rows = sqlx::query("SELECT key, value FROM assistant_config")
                .fetch_all(&self.pool)
                .await?;

            let mut config = AssistantConfig::default();
            for row in rows {
                let key: String = row.get("key");
                let value: String = row.get("value");
                match key.as_str() {
                    "provider" => config.provider = Some(value),
                    "base_url" => config.base_url = Some(value),
                    "model" => config.model = Some(value),
                    "api_key" => config.api_key = Some(value),
                    _ => {}
                }
            }
            Ok(config)
        })
    }

    // ── Category operations ───────────────────────────────────────────────

    /// All categories, ordered for tree display: roots first, then by sibling sort_index, then by name.
    pub fn list_categories(&self) -> Result<Vec<Category>> {
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

    pub fn update_category(&self, c: &Category) -> Result<()> {
        block(async {
            sqlx::query(
                "UPDATE categories SET name = ?, parent_id = ?, scope = ?, color = ?, sort_index = ?, updated_at = ? WHERE id = ?"
            )
            .bind(&c.name)
            .bind(&c.parent_id)
            .bind(&c.scope)
            .bind(&c.color)
            .bind(c.sort_index)
            .bind(c.updated_at.to_rfc3339())
            .bind(&c.id)
            .execute(&self.pool)
            .await?;
            Ok(())
        })
    }

    /// Delete a category. Children are reassigned to the deleted node's parent
    /// (or become roots if the deleted node was itself a root). All
    /// `key_categories` rows for this category are removed. Returns the list
    /// of category IDs that were reassigned.
    pub fn delete_category(&self, id: &str) -> Result<Vec<String>> {
        block(async {
            let mut tx = self.pool.begin().await?;
            let parent: Option<String> =
                sqlx::query_scalar("SELECT parent_id FROM categories WHERE id = ?")
                    .bind(id)
                    .fetch_optional(&mut *tx)
                    .await?
                    .flatten();
            // Reassign children to the deleted node's parent.
            sqlx::query("UPDATE categories SET parent_id = ? WHERE parent_id IS ?")
                .bind(&parent)
                .bind(&Some(id.to_string()))
                .execute(&mut *tx)
                .await?;
            // Drop the join rows for this category.
            sqlx::query("DELETE FROM key_categories WHERE category_id = ?")
                .bind(id)
                .execute(&mut *tx)
                .await?;
            // Finally, drop the category itself.
            sqlx::query("DELETE FROM categories WHERE id = ?")
                .bind(id)
                .execute(&mut *tx)
                .await?;
            // Return the children we just reassigned.
            let mut reassigned: Vec<String> = Vec::new();
            let children: Vec<Option<String>> = sqlx::query_scalar(
                "SELECT id FROM categories WHERE parent_id IS ? OR (parent_id IS NULL AND ? IS NULL)"
            )
            .bind(&parent)
            .bind(&parent)
            .fetch_all(&mut *tx)
            .await?;
            for c in children.into_iter().flatten() {
                if c != id {
                    reassigned.push(c);
                }
            }
            tx.commit().await?;
            Ok(reassigned)
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
            let rows = sqlx::query("SELECT * FROM keys ORDER BY created_at DESC")
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
            let row = sqlx::query("SELECT * FROM keys WHERE id = ?")
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

    /// Walk parent chain and return the slash-joined category path.
    pub fn category_path_string(&self, id: &str) -> String {
        let mut out = Vec::new();
        let mut cur: Option<String> = Some(id.to_string());
        while let Some(cid) = cur {
            match self.get_category(&cid) {
                Ok(Some(c)) => {
                    out.push(c.name);
                    cur = c.parent_id;
                }
                _ => break,
            }
        }
        out.reverse();
        out.join("/")
    }

    /// Ensure a category chain for the given slash-joined path exists locally.
    /// Returns the leaf category's id. If a node along the path is missing,
    /// it is created with a deterministic id derived from the path so
    /// re-imports converge to the same uuid.
    pub fn ensure_category_path(&self, path: &str) -> Result<Option<String>> {
        self.ensure_category_path_scoped(path, "key")
    }

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
        block(async {
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
            .execute(&self.pool).await?;
            Ok(())
        })
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
    /// The audit's F3/F6: previously each key/server UPDATE was its own
    /// pool-backed statement and the master verifier was a third write, so an
    /// I/O error or a crash part-way left some rows sealed under the new
    /// password and the rest (plus the verifier) under the old - a vault that
    /// unlocks but cannot decrypt half its contents. And the Bitwarden master
    /// password was never re-sealed at all, stranding sync on the old
    /// password. Here every re-sealed record AND the verifier commit inside a
    /// single SQLite transaction: the database holds either the complete old
    /// state or the complete new state, never a split.
    pub fn apply_vault_rotation(
        &self,
        keys: &[KeyRecord],
        servers: &[ServerRecord],
        bitwarden_master_password: Option<&str>,
        assistant_api_key: Option<&str>,
        new_master_hash: &str,
    ) -> Result<()> {
        block(async {
            let mut tx = self.pool.begin().await?;
            for key in keys {
                sqlx::query(
                    r#"
                    UPDATE keys SET
                        name = ?, key_type = ?, public_key = ?, private_key_encrypted = ?,
                        fingerprint_sha256 = ?, fingerprint_md5 = ?, comment = ?, updated_at = ?,
                        deployed = ?, deploy_path = ?, bitwarden_id = ?, bitwarden_sync = ?,
                        bitwarden_revision_ts = ?, bitwarden_updated_at = ?
                    WHERE id = ?
                    "#,
                )
                .bind(&key.name)
                .bind(&key.key_type)
                .bind(&key.public_key)
                .bind(&key.private_key_encrypted)
                .bind(&key.fingerprint_sha256)
                .bind(&key.fingerprint_md5)
                .bind(&key.comment)
                .bind(key.updated_at.to_rfc3339())
                .bind(key.deployed as i64)
                .bind(&key.deploy_path)
                .bind(&key.bitwarden_id)
                .bind(key.bitwarden_sync as i64)
                .bind(key.bitwarden_revision_ts.map(|v| v.to_string()))
                .bind(key.bitwarden_updated_at.map(|v| v.to_string()))
                .bind(&key.id)
                .execute(&mut *tx)
                .await?;
            }
            for s in servers {
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
                .execute(&mut *tx)
                .await?;
            }
            // The Bitwarden master password is sealed with the SAME vault
            // password; it must rotate in the same transaction or sync is
            // stranded on the old password (F6).
            if let Some(sealed) = bitwarden_master_password {
                sqlx::query(
                    "INSERT INTO bitwarden_config (key, value, updated_at) VALUES ('master_password', ?, ?) \
                     ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
                )
                .bind(sealed)
                .bind(Utc::now().to_rfc3339())
                .execute(&mut *tx)
                .await?;
            }
            // The AI assistant API key is sealed with the same vault password;
            // it must rotate in the same transaction or every assistant call
            // fails at unseal after the change.
            if let Some(sealed) = assistant_api_key {
                sqlx::query(
                    "INSERT INTO assistant_config (key, value, updated_at) VALUES ('api_key', ?, ?) \
                     ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
                )
                .bind(sealed)
                .bind(Utc::now().to_rfc3339())
                .execute(&mut *tx)
                .await?;
            }
            // The verifier rotates last, inside the same transaction: if any
            // earlier statement failed, the whole rotation rolls back and the
            // old password keeps working against untouched rows.
            sqlx::query(
                "INSERT INTO config (key, value, updated_at) VALUES (?, ?, ?) \
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
            )
            .bind("master.hash")
            .bind(new_master_hash)
            .bind(Utc::now().to_rfc3339())
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            Ok(())
        })
    }

    pub fn get_server(&self, id: &str) -> Result<Option<ServerRecord>> {
        block(async {
            let row = sqlx::query("SELECT * FROM servers WHERE id = ?")
                .bind(id)
                .fetch_optional(&self.pool)
                .await?;
            Ok(row.map(|r| Self::row_to_server(r)))
        })
    }

    pub fn list_servers(&self) -> Result<Vec<ServerRecord>> {
        block(async {
            let rows = sqlx::query("SELECT * FROM servers ORDER BY name COLLATE NOCASE ASC")
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
        KnownHost {
            host: row.get("host"),
            host_key: row.get("host_key"),
            fingerprint_sha256: row.get("fingerprint_sha256"),
            first_seen: DateTime::parse_from_rfc3339(row.get::<String, _>("first_seen").as_str())
                .ok()
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(|| Utc::now()),
            source: row
                .try_get::<String, _>("source")
                .unwrap_or_else(|_| "connection".to_string()),
        }
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
    async fn migrate_known_hosts_port_qualify(&self) -> Result<()> {
        let rows: Vec<String> = sqlx::query_scalar::<_, String>("SELECT host FROM known_hosts")
            .fetch_all(&self.pool)
            .await?;

        let mut tx = self.pool.begin().await?;
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
    pub fn add_known_host(&self, host: &str, host_key: &str, fingerprint: &str) -> Result<bool> {
        block(async {
            let existing =
                sqlx::query_scalar::<_, String>("SELECT host_key FROM known_hosts WHERE host = ?")
                    .bind(host)
                    .fetch_optional(&self.pool)
                    .await?;
            match existing {
                Some(current) if current == host_key => Ok(true),
                Some(_) => Ok(false),
                None => {
                    sqlx::query(
                        "INSERT INTO known_hosts (host, host_key, fingerprint_sha256, first_seen, source) VALUES (?, ?, ?, ?, 'connection')"
                    )
                    .bind(host).bind(host_key).bind(fingerprint).bind(chrono::Utc::now().to_rfc3339())
                    .execute(&self.pool).await?;
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
            let row = sqlx::query("SELECT * FROM known_hosts WHERE host = ?")
                .bind(host)
                .fetch_optional(&self.pool)
                .await?;
            Ok(row.map(|r| Self::row_to_known_host(r)))
        })
    }

    pub fn list_known_hosts(&self) -> Result<Vec<KnownHost>> {
        block(async {
            let rows = sqlx::query("SELECT * FROM known_hosts ORDER BY host COLLATE NOCASE ASC")
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
                    attempts, verify, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    updated_at = excluded.updated_at
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
            .execute(&self.pool)
            .await?;
            Ok(())
        })
    }

    /// Delete one job's persisted row.
    pub fn delete_queue_job(&self, id: i64) -> Result<()> {
        block(async {
            sqlx::query("DELETE FROM transfer_queue WHERE id = ?")
                .bind(id)
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
    pub fn list_pending_queue_jobs(&self) -> Result<Vec<QueueJobRow>> {
        block(async {
            let rows = sqlx::query(
                "SELECT * FROM transfer_queue WHERE state IN ('queued', 'active', 'paused') \
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
        }
    }

    // ── Backup / restore ───────────────────────────────────────────────────

    /// Upsert every entity from an (already unsealed) backup payload in one
    /// transaction. Existing rows with the same id/host are overwritten -
    /// re-running a restore is safe. Returns per-entity row counts.
    pub fn restore_backup(&self, data: &serde_json::Value) -> Result<serde_json::Value> {
        block(async {
            let mut tx = self.pool.begin().await?;
            let (mut keys_n, mut cats_n, mut kc_n) = (0u32, 0u32, 0u32);
            let (mut servers_n, mut hosts_n, mut settings_n) = (0u32, 0u32, 0u32);

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
                        let _ = self.add_audit(
                            "keys.name_sanitized",
                            None,
                            &format!("{raw_name:?} -> {sanitized:?}"),
                        );
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
                    // backup (F9): `deployed`/`deploy_path` describe a
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
                    .bind(s("bitwarden_revision_ts"))
                    .bind(s("bitwarden_updated_at"))
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
                            .bind(host).bind(host_key).bind(fp).bind(seen)
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

            tx.commit().await?;
            Ok(serde_json::json!({
                "keys": keys_n, "categories": cats_n, "keyCategoryLinks": kc_n,
                "servers": servers_n, "knownHosts": hosts_n,
                "knownHostsImported": known_hosts_imported,
                "knownHostsConflicts": known_hosts_conflicts, "settings": settings_n,
            }))
        })
    }
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
    }

    // ── F3/F6: atomic vault rotation ─────────────────────────────────────────

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

    /// F3/F6 regression: a full rotation (keys + the Bitwarden credential +
    /// the verifier) commits in one transaction, so after `apply_vault_rotation`
    /// every record unseals under the NEW password and the old password fails.
    #[test]
    fn apply_vault_rotation_reseals_keys_and_bitwarden_and_verifier() {
        let db = test_db();
        let old_pw = "old-master-pw";
        let new_pw = "new-master-pw";
        db.insert_key(&rotation_key("k1", old_pw)).unwrap();

        // Seed a Bitwarden credential sealed under the OLD password.
        let bw_old = crate::crypto::vault::seal(old_pw, b"bw-master-secret").unwrap();
        let mut cfg = BitwardenConfig::default();
        cfg.master_password = Some(bw_old);
        db.save_bitwarden_config(&cfg).unwrap();
        // And an assistant API key sealed under the OLD password.
        let ai_old = crate::crypto::vault::seal(old_pw, b"sk-assistant-key").unwrap();
        let mut ai = AssistantConfig::default();
        ai.api_key = Some(ai_old);
        db.save_assistant_config(&ai).unwrap();
        db.set_config("master.hash", "OLD-VERIFIER").unwrap();

        // Rotate: re-seal key + BW cred in memory, commit atomically.
        let mut key = db.get_key("k1").unwrap().unwrap();
        let plain = crate::crypto::vault::unseal(old_pw, &key.private_key_encrypted).unwrap();
        key.private_key_encrypted = crate::crypto::vault::seal(new_pw, &plain).unwrap();
        let bw_new = crate::crypto::vault::seal(new_pw, b"bw-master-secret").unwrap();
        let ai_new = crate::crypto::vault::seal(new_pw, b"sk-assistant-key").unwrap();
        db.apply_vault_rotation(&[key], &[], Some(&bw_new), Some(&ai_new), "NEW-VERIFIER")
            .unwrap();

        // Key unseals under NEW, not OLD.
        let stored = db.get_key("k1").unwrap().unwrap();
        assert!(crate::crypto::vault::unseal(new_pw, &stored.private_key_encrypted).is_ok());
        assert!(crate::crypto::vault::unseal(old_pw, &stored.private_key_encrypted).is_err());
        // The Bitwarden credential rotated too (F6): NEW unseals, OLD fails.
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
        // Verifier rotated.
        assert_eq!(
            db.get_config("master.hash").unwrap().as_deref(),
            Some("NEW-VERIFIER")
        );
    }

    // ── F9: restore clears machine-local deployment state ───────────────────

    /// F9 regression: a backup carrying `deployed`/`deploy_path` must NOT
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
}

fn short_hash(s: &str) -> u32 {
    let mut h: u32 = 0x811c9dc5;
    for b in s.as_bytes() {
        h ^= *b as u32;
        h = h.wrapping_mul(0x01000193);
    }
    h
}

fn get_db_path(_app: &AppHandle) -> Result<PathBuf> {
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
