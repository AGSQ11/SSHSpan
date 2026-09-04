//! Database layer using sqlx with SQLite
//! Replaces database.js (sql.js WASM)

use sqlx::{SqlitePool, Row, sqlite::SqliteRow};
use tauri::AppHandle;
use directories::ProjectDirs;
use std::path::PathBuf;
use std::collections::HashMap;
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use anyhow::Result;

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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnownHost {
    pub host: String,
    /// SSH wire-format host public key, base64-encoded.
    pub host_key: String,
    pub fingerprint_sha256: String,
    pub first_seen: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitwardenConfig {
    pub server_url: Option<String>,
    pub email: Option<String>,
    pub master_password: Option<String>,  // sealed JSON blob (encrypted with vault pw)
    pub folder_name: Option<String>,      // default "SSHSpan"
    pub device_id: Option<String>,
    pub last_sync: Option<DateTime<Utc>>,
    pub last_result: Option<String>,      // JSON sync summary
}

impl Default for BitwardenConfig {
    fn default() -> Self {
        Self {
            server_url: None, email: None, master_password: None,
            folder_name: None, device_id: None,
            last_sync: None, last_result: None,
        }
    }
}

#[derive(Clone)]
pub struct Database {
    pub pool: SqlitePool,
    
    pub db_path: PathBuf,
}

use std::sync::OnceLock;

/// Lazily-created, long-lived tokio runtime used by the DB layer when no
/// ambient runtime is available (sync commands, startup). Cached after the
/// first call so subsequent DB hits don't pay the ~300ms runtime-init cost.
fn cached_runtime() -> &'static tokio::runtime::Runtime {
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Runtime::new().expect("Failed to create DB tokio runtime")
    })
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
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(f)
        })
    } else {
        cached_runtime().block_on(f)
    }
}

impl Database {
    pub fn new(app: &AppHandle) -> Result<Self> {
        let db_path = get_db_path(app)?;
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let db_url = format!("sqlite:{}?mode=rwc", db_path.display());
        let pool = block(async {
            SqlitePool::connect(&db_url).await
        })?;
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
            ).execute(&self.pool).await?;

            sqlx::query(
                r#"
                CREATE TABLE IF NOT EXISTS config (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                "#,
            ).execute(&self.pool).await?;

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
            ).execute(&self.pool).await?;

            sqlx::query(
                r#"
                CREATE TABLE IF NOT EXISTS bitwarden_config (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                "#,
            ).execute(&self.pool).await?;

            sqlx::query("CREATE INDEX IF NOT EXISTS idx_keys_fingerprint ON keys(fingerprint_sha256)").execute(&self.pool).await?;
            sqlx::query("CREATE INDEX IF NOT EXISTS idx_keys_bitwarden_id ON keys(bitwarden_id)").execute(&self.pool).await?;
            sqlx::query("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp)").execute(&self.pool).await?;

            // Migration: add sync metadata columns if missing
            let _ = sqlx::query("ALTER TABLE keys ADD COLUMN bitwarden_revision_ts TEXT")
                .execute(&self.pool).await;
            let _ = sqlx::query("ALTER TABLE keys ADD COLUMN bitwarden_updated_at TEXT")
                .execute(&self.pool).await;

            // Categories: user-defined tree of named nodes that group keys.
            // Arbitrary depth via self-referential parent_id; many-to-many to
            // keys via the key_categories join table.
            sqlx::query(
                r#"
                CREATE TABLE IF NOT EXISTS categories (
                    id          TEXT PRIMARY KEY,
                    name        TEXT NOT NULL,
                    parent_id   TEXT,
                    color       TEXT,
                    sort_index  INTEGER NOT NULL DEFAULT 0,
                    created_at  TEXT NOT NULL,
                    updated_at  TEXT NOT NULL
                )
                "#,
            ).execute(&self.pool).await?;

            sqlx::query("CREATE INDEX IF NOT EXISTS idx_categories_parent ON categories(parent_id)")
                .execute(&self.pool).await?;

            sqlx::query(
                r#"
                CREATE TABLE IF NOT EXISTS key_categories (
                    key_id      TEXT NOT NULL,
                    category_id TEXT NOT NULL,
                    PRIMARY KEY (key_id, category_id)
                )
                "#,
            ).execute(&self.pool).await?;

            sqlx::query("CREATE INDEX IF NOT EXISTS idx_key_categories_cat ON key_categories(category_id)")
                .execute(&self.pool).await?;
            sqlx::query("CREATE INDEX IF NOT EXISTS idx_key_categories_key ON key_categories(key_id)")
                .execute(&self.pool).await?;

            // Connect: saved SSH servers (PuTTY-style sessions) + trusted host keys.
            // key_id references keys.id; the private key itself is never copied —
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
            ).execute(&self.pool).await?;

            sqlx::query(
                r#"
                CREATE TABLE IF NOT EXISTS known_hosts (
                    host             TEXT PRIMARY KEY,
                    host_key         TEXT NOT NULL,
                    fingerprint_sha256 TEXT NOT NULL,
                    first_seen       TEXT NOT NULL
                )
                "#,
            ).execute(&self.pool).await?;

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
    pub fn update_key_sync_meta(&self, id: &str, bitwarden_id: &str, revision_date: Option<&str>) -> Result<()> {
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
            created_at: DateTime::parse_from_rfc3339(row.get::<String, _>("created_at").as_str()).unwrap().with_timezone(&Utc),
            updated_at: DateTime::parse_from_rfc3339(row.get::<String, _>("updated_at").as_str()).unwrap().with_timezone(&Utc),
            deployed: row.get::<i64, _>("deployed") != 0,
            deploy_path: row.get("deploy_path"),
            bitwarden_id: row.get("bitwarden_id"),
            bitwarden_sync: row.get::<i64, _>("bitwarden_sync") != 0,
            bitwarden_revision_ts: row.get::<Option<String>, _>("bitwarden_revision_ts")
                .and_then(|s| s.parse().ok()),
            bitwarden_updated_at: row.get::<Option<String>, _>("bitwarden_updated_at")
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

    // ── Audit log ──────────────────────────────────────────────────────────

    pub fn add_audit(&self, action: &str, key_id: Option<&str>, details: &str) -> Result<()> {
        block(async {
            sqlx::query(
                "INSERT INTO audit_log (action, key_id, details, timestamp) VALUES (?, ?, ?, ?)"
            )
            .bind(action)
            .bind(key_id)
            .bind(details)
            .bind(Utc::now().to_rfc3339())
            .execute(&self.pool)
            .await?;
            Ok(())
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

            Ok(rows.into_iter().map(|row| AuditRecord {
                id: row.get("id"),
                action: row.get("action"),
                key_id: row.get("key_id"),
                details: row.get("details"),
                timestamp: DateTime::parse_from_rfc3339(row.get::<String, _>("timestamp").as_str())
                    .unwrap()
                    .with_timezone(&Utc),
            }).collect())
        })
    }

    // ── Bitwarden config ───────────────────────────────────────────────────

    pub fn save_bitwarden_config(&self, config: &BitwardenConfig) -> Result<()> {
        block(async {
            let fields: [(&str, Option<String>); 7] = [
                ("server_url", config.server_url.clone()),
                ("email", config.email.clone()),
                ("master_password", config.master_password.clone()),
                ("folder_name", config.folder_name.clone()),
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
                    "device_id" => config.device_id = Some(value),
                    "last_sync" => config.last_sync = DateTime::parse_from_rfc3339(&value).ok().map(|d| d.with_timezone(&Utc)),
                    "last_result" => config.last_result = Some(value),
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
                "SELECT id, name, parent_id, color, sort_index, created_at, updated_at \
                 FROM categories \
                 ORDER BY CASE WHEN parent_id IS NULL THEN 0 ELSE 1 END, sort_index, name"
            )
            .fetch_all(&self.pool)
            .await?;
            Ok(rows.into_iter().map(Self::row_to_category).collect())
        })
    }

    pub fn get_category(&self, id: &str) -> Result<Option<Category>> {
        block(async {
            let row = sqlx::query(
                "SELECT id, name, parent_id, color, sort_index, created_at, updated_at FROM categories WHERE id = ?"
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
                "INSERT INTO categories (id, name, parent_id, color, sort_index, created_at, updated_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?)"
            )
            .bind(&c.id)
            .bind(&c.name)
            .bind(&c.parent_id)
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
                "UPDATE categories SET name = ?, parent_id = ?, color = ?, sort_index = ?, updated_at = ? WHERE id = ?"
            )
            .bind(&c.name)
            .bind(&c.parent_id)
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
            let parent: Option<String> = sqlx::query_scalar("SELECT parent_id FROM categories WHERE id = ?")
                .bind(id)
                .fetch_optional(&mut *tx)
                .await?
                .flatten();
            // Reassign children to the deleted node's parent.
            sqlx::query("UPDATE categories SET parent_id = ? WHERE parent_id = ?")
                .bind(&parent)
                .bind(id)
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
                if c != id { reassigned.push(c); }
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
                    "INSERT OR IGNORE INTO key_categories (key_id, category_id) VALUES (?, ?)"
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
            let rows: Vec<Option<String>> = sqlx::query_scalar(
                "SELECT category_id FROM key_categories WHERE key_id = ?"
            )
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
            let rows: Vec<(String, Option<String>)> = sqlx::query_as(
                "SELECT key_id, category_id FROM key_categories"
            )
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
    pub fn insert_key_with_categories(&self, key: &KeyRecord, category_ids: &[String]) -> Result<()> {
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
                    "INSERT OR IGNORE INTO key_categories (key_id, category_id) VALUES (?, ?)"
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
            let Some(row) = row else { return Ok(None); };
            let mut k = Self::row_to_key(row);
            let kc_map = self.all_key_categories_inner(&self.pool).await?;
            if let Some(ids) = kc_map.get(&k.id) {
                k.category_ids = ids.clone();
            }
            Ok(Some(k))
        })
    }

    async fn all_key_categories_inner(&self, pool: &SqlitePool) -> Result<HashMap<String, Vec<String>>> {
        let rows: Vec<(String, Option<String>)> = sqlx::query_as(
            "SELECT key_id, category_id FROM key_categories"
        )
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
            color: row.get("color"),
            sort_index: row.get::<i64, _>("sort_index"),
            created_at: DateTime::parse_from_rfc3339(row.get::<String, _>("created_at").as_str())
                .unwrap().with_timezone(&Utc),
            updated_at: DateTime::parse_from_rfc3339(row.get::<String, _>("updated_at").as_str())
                .unwrap().with_timezone(&Utc),
        }
    }

    /// Walk parent chain and return the slash-joined category path.
    pub fn category_path_string(&self, id: &str) -> String {
        let mut out = Vec::new();
        let mut cur: Option<String> = Some(id.to_string());
        while let Some(cid) = cur {
            match self.get_category(&cid) {
                Ok(Some(c)) => { out.push(c.name); cur = c.parent_id; }
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
        let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        if segments.is_empty() { return Ok(None); }
        // Compute a deterministic id for the *root* based on its segment so
        // re-imports of the same root converge.
        let mut current_parent: Option<String> = None;
        let mut full_path = String::new();
        let mut last_id: Option<String> = None;
        for seg in segments {
            if !full_path.is_empty() { full_path.push('/'); }
            full_path.push_str(seg);
            // Search for a sibling with this parent_id and name.
            let existing: Option<Category> = {
                let rows = self.list_categories()?;
                rows.into_iter().find(|c| c.name == seg && c.parent_id == current_parent)
            };
            if let Some(c) = existing {
                let cid = c.id.clone();
                last_id = Some(cid.clone());
                current_parent = Some(cid);
            } else {
                // Create a new node with a deterministic id from the full path.
                let id = format!("path-{:x}", short_hash(&full_path));
                let now = Utc::now();
                let max_si = self.list_categories()?.into_iter()
                    .filter(|c| c.parent_id == current_parent)
                    .map(|c| c.sort_index).max().unwrap_or(-1);
                let cat = Category {
                    id: id.clone(), name: seg.to_string(),
                    parent_id: current_parent.clone(), color: None,
                    sort_index: max_si + 1, created_at: now, updated_at: now,
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
            s.and_then(|s| DateTime::parse_from_rfc3339(&s).ok()).map(|d| d.with_timezone(&Utc))
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
                .ok().map(|d| d.with_timezone(&Utc)).unwrap_or_else(|| Utc::now()),
            updated_at: DateTime::parse_from_rfc3339(row.get::<String, _>("updated_at").as_str())
                .ok().map(|d| d.with_timezone(&Utc)).unwrap_or_else(|| Utc::now()),
        }
    }

    pub fn insert_server(&self, s: &ServerRecord) -> Result<()> {
        block(async {
            sqlx::query(
                r#"
                INSERT INTO servers (id, name, host, port, username, key_id, pem_path, auth_method,
                                     saved_password, category_id, color, last_connected_at, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                "#,
            )
            .bind(&s.id).bind(&s.name).bind(&s.host).bind(s.port as i64)
            .bind(&s.username).bind(&s.key_id).bind(&s.pem_path).bind(&s.auth_method)
            .bind(&s.saved_password).bind(&s.category_id).bind(&s.color)
            .bind(s.last_connected_at.map(|d| d.to_rfc3339()))
            .bind(s.created_at.to_rfc3339()).bind(s.updated_at.to_rfc3339())
            .execute(&self.pool).await?;
            Ok(())
        })
    }

    pub fn update_server(&self, s: &ServerRecord) -> Result<()> {
        block(async {
            sqlx::query(
                r#"
                UPDATE servers SET name = ?, host = ?, port = ?, username = ?, key_id = ?, pem_path = ?,
                    auth_method = ?, saved_password = ?, category_id = ?, color = ?, last_connected_at = ?, updated_at = ?
                WHERE id = ?
                "#,
            )
            .bind(&s.name).bind(&s.host).bind(s.port as i64).bind(&s.username)
            .bind(&s.key_id).bind(&s.pem_path).bind(&s.auth_method).bind(&s.saved_password)
            .bind(&s.category_id).bind(&s.color)
            .bind(s.last_connected_at.map(|d| d.to_rfc3339()))
            .bind(s.updated_at.to_rfc3339())
            .bind(&s.id)
            .execute(&self.pool).await?;
            Ok(())
        })
    }

    pub fn delete_server(&self, id: &str) -> Result<()> {
        block(async {
            sqlx::query("DELETE FROM servers WHERE id = ?").bind(id)
                .execute(&self.pool).await?;
            Ok(())
        })
    }

    pub fn get_server(&self, id: &str) -> Result<Option<ServerRecord>> {
        block(async {
            let row = sqlx::query("SELECT * FROM servers WHERE id = ?")
                .bind(id).fetch_optional(&self.pool).await?;
            Ok(row.map(|r| Self::row_to_server(r)))
        })
    }

    pub fn list_servers(&self) -> Result<Vec<ServerRecord>> {
        block(async {
            let rows = sqlx::query("SELECT * FROM servers ORDER BY name COLLATE NOCASE ASC")
                .fetch_all(&self.pool).await?;
            Ok(rows.into_iter().map(|r| Self::row_to_server(r)).collect())
        })
    }

    pub fn get_key_name(&self, key_id: &str) -> Result<Option<(String, String)>> {
        block(async {
            let row = sqlx::query("SELECT name, key_type FROM keys WHERE id = ?")
                .bind(key_id).fetch_optional(&self.pool).await?;
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
                .ok().map(|d| d.with_timezone(&Utc)).unwrap_or_else(|| Utc::now()),
        }
    }

    /// Insert a newly-seen host key. Returns false if the host already exists
    /// with a DIFFERENT key (the caller should treat that as a mismatch).
    pub fn add_known_host(&self, host: &str, host_key: &str, fingerprint: &str) -> Result<bool> {
        block(async {
            let existing = sqlx::query_scalar::<_, String>(
                "SELECT host_key FROM known_hosts WHERE host = ?"
            ).bind(host).fetch_optional(&self.pool).await?;
            match existing {
                Some(current) if current == host_key => Ok(true),
                Some(_) => Ok(false),
                None => {
                    sqlx::query(
                        "INSERT INTO known_hosts (host, host_key, fingerprint_sha256, first_seen) VALUES (?, ?, ?, ?)"
                    )
                    .bind(host).bind(host_key).bind(fingerprint).bind(chrono::Utc::now().to_rfc3339())
                    .execute(&self.pool).await?;
                    Ok(true)
                }
            }
        })
    }

    /// Returns the stored host-key blob for a host, if any.
    pub fn get_known_host(&self, host: &str) -> Result<Option<KnownHost>> {
        block(async {
            let row = sqlx::query("SELECT * FROM known_hosts WHERE host = ?")
                .bind(host).fetch_optional(&self.pool).await?;
            Ok(row.map(|r| Self::row_to_known_host(r)))
        })
    }

    pub fn list_known_hosts(&self) -> Result<Vec<KnownHost>> {
        block(async {
            let rows = sqlx::query("SELECT * FROM known_hosts ORDER BY host COLLATE NOCASE ASC")
                .fetch_all(&self.pool).await?;
            Ok(rows.into_iter().map(|r| Self::row_to_known_host(r)).collect())
        })
    }

    pub fn delete_known_host(&self, host: &str) -> Result<()> {
        block(async {
            sqlx::query("DELETE FROM known_hosts WHERE host = ?").bind(host)
                .execute(&self.pool).await?;
            Ok(())
        })
    }
}

/// FNV-1a 32-bit hash of the string, formatted as 8 lowercase hex chars.
/// Used to derive a short deterministic id from a category path.
fn short_hash(s: &str) -> u32 {
    let mut h: u32 = 0x811c9dc5;
    for b in s.as_bytes() {
        h ^= *b as u32;
        h = h.wrapping_mul(0x01000193);
    }
    h
}

fn get_db_path(_app: &AppHandle) -> Result<PathBuf> {
    let dirs = ProjectDirs::from("org", "sshspan", "SSHSpan")
        .ok_or_else(|| anyhow::anyhow!("Could not determine app data directory"))?;
    Ok(dirs.data_dir().join("sshspan.db"))
}
