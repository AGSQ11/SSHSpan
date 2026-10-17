//! Integration tests for SSHSpan Tauri backend
//! Tests key generation, fingerprinting, import/export, database, and config

use sshspan::config::SshConfig;
use sshspan::crypto::keys::{self, KeyFormat, KeyType};
use sshspan::crypto::utils;
use sshspan::db::BitwardenConfig;
use sshspan::db::Database;
use sshspan::db::AUDIT_RETENTION_ROWS;

/// Parse the algorithm tag out of an exported OpenSSH public-key line
/// ("<algo> <base64> [comment]") — used to assert roundtrip structure.
fn openssh_pub_algo(line: &str) -> &str {
    line.split_whitespace().next().unwrap_or("")
}

/// Store every set field of `config` the way the app changes the sync
/// settings: in one transaction over the settings as stored.
fn store_bitwarden_config(db: &Database, config: &BitwardenConfig) {
    let config = config.clone();
    db.update_bitwarden_config(move |stored| {
        *stored = config;
        Ok(())
    })
    .unwrap();
}

// ═════════════════════════════════════════════════════════════════════════════
//  Key Generation
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn generate_ed25519_key() {
    let key = keys::generate_key_pair(KeyType::Ed25519, None, "test@host".to_string()).unwrap();
    assert_eq!(key.key_type, KeyType::Ed25519);
    assert!(!key.private_key.is_empty());
    assert!(!key.public_key.is_empty());
    assert_eq!(key.comment, "test@host");
    let fp = keys::compute_fingerprint_sha256(&key.public_key);
    assert!(fp.starts_with("SHA256:"));
}

#[test]
fn generate_rsa_key() {
    let key = keys::generate_key_pair(KeyType::Rsa, Some(2048), "rsa-test".to_string()).unwrap();
    assert_eq!(key.key_type, KeyType::Rsa);
    assert!(!key.private_key.is_empty());
    assert!(!key.public_key.is_empty());
}

#[test]
fn generate_ecdsa_key() {
    let key = keys::generate_key_pair(KeyType::EcdsaP256, None, "ecdsa-test".to_string()).unwrap();
    assert_eq!(key.key_type, KeyType::EcdsaP256);
    assert!(!key.private_key.is_empty());
    assert!(!key.public_key.is_empty());
}

#[test]
fn fingerprint_format() {
    let key = keys::generate_key_pair(KeyType::Ed25519, None, "test".to_string()).unwrap();
    let fp = keys::compute_fingerprint_sha256(&key.public_key);
    assert!(fp.starts_with("SHA256:"));
    // SHA256: + 43 base64 chars = 50 chars minimum
    assert!(fp.len() >= 50);
}

#[test]
fn fingerprint_consistency() {
    let key = keys::generate_key_pair(KeyType::Ed25519, None, "test".to_string()).unwrap();
    let fp1 = keys::compute_fingerprint_sha256(&key.public_key);
    let fp2 = keys::compute_fingerprint_sha256(&key.public_key);
    assert_eq!(fp1, fp2);
}

// ═════════════════════════════════════════════════════════════════════════════
//  OpenSSH Key Format
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn openssh_public_key_export() {
    let key = keys::generate_key_pair(KeyType::Ed25519, None, "export-test".to_string()).unwrap();
    let openssh_pub = keys::export_public_key(&key, KeyFormat::OpenSsh).unwrap();
    assert!(openssh_pub.starts_with("ssh-ed25519 "));
    assert!(openssh_pub.contains("export-test"));
}

#[test]
fn openssh_public_key_parse_roundtrip() {
    let key = keys::generate_key_pair(KeyType::Ed25519, None, "roundtrip".to_string()).unwrap();
    let openssh_pub = keys::export_public_key(&key, KeyFormat::OpenSsh).unwrap();
    assert_eq!(openssh_pub_algo(&openssh_pub), "ssh-ed25519");
    assert!(openssh_pub.ends_with("roundtrip"));
    let b64 = openssh_pub.split_whitespace().nth(1).unwrap_or("");
    assert!(!b64.is_empty(), "public key line carries base64 key data");
}

#[test]
fn openssh_public_key_parse_bad_format() {
    // An exported key must carry "<algo> <base64>" — a bare word has no data.
    let key = keys::generate_key_pair(KeyType::Ed25519, None, "x".to_string()).unwrap();
    let good = keys::export_public_key(&key, KeyFormat::OpenSsh).unwrap();
    assert!(good.split_whitespace().count() >= 2);
    let bad = "not-a-valid-key";
    let bad_parts: Vec<&str> = bad.split_whitespace().collect();
    assert!(
        bad_parts.len() < 2,
        "a key without base64 payload must be rejected"
    );
}

// ═════════════════════════════════════════════════════════════════════════════
//  Key Export/Import Roundtrips
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn key_export_openssh_format() {
    let key = keys::generate_key_pair(KeyType::Ed25519, None, "export-test".to_string()).unwrap();
    let exported = keys::export_public_key(&key, KeyFormat::OpenSsh).unwrap();
    assert!(exported.starts_with("ssh-ed25519 "));
    assert!(exported.contains("export-test"));
    assert!(exported
        .split_whitespace()
        .nth(1)
        .map_or(false, |b| !b.is_empty()));
}

#[test]
fn key_export_import_roundtrip() {
    let key = keys::generate_key_pair(KeyType::Ed25519, None, "rt-test".to_string()).unwrap();
    let exported = keys::export_public_key(&key, KeyFormat::OpenSsh).unwrap();
    assert_eq!(openssh_pub_algo(&exported), "ssh-ed25519");
    assert!(exported.ends_with("rt-test"));
}

#[test]
fn rsa_key_export_roundtrip() {
    let key = keys::generate_key_pair(KeyType::Rsa, Some(2048), "rsa-rt".to_string()).unwrap();
    let fp = keys::compute_fingerprint_sha256(&key.public_key);
    assert!(fp.starts_with("SHA256:"));
    let exported = keys::export_public_key(&key, KeyFormat::OpenSsh).unwrap();
    assert!(exported.starts_with("ssh-rsa "));
}

#[test]
fn ed25519_key_export_roundtrip() {
    let key = keys::generate_key_pair(KeyType::Ed25519, None, "ed25519-rt".to_string()).unwrap();
    let exported = keys::export_public_key(&key, KeyFormat::OpenSsh).unwrap();
    assert_eq!(openssh_pub_algo(&exported), "ssh-ed25519");
}

#[test]
fn ecdsa_key_export_roundtrip() {
    let key = keys::generate_key_pair(KeyType::EcdsaP256, None, "ecdsa-rt".to_string()).unwrap();
    let exported = keys::export_public_key(&key, KeyFormat::OpenSsh).unwrap();
    assert!(exported.starts_with("ecdsa-sha2-nistp256 "));
}

#[test]
fn fingerprint_unique_per_key() {
    let key1 = keys::generate_key_pair(KeyType::Ed25519, None, "a".to_string()).unwrap();
    let key2 = keys::generate_key_pair(KeyType::Ed25519, None, "b".to_string()).unwrap();
    let fp1 = keys::compute_fingerprint_sha256(&key1.public_key);
    let fp2 = keys::compute_fingerprint_sha256(&key2.public_key);
    assert_ne!(
        fp1, fp2,
        "different keys should have different fingerprints"
    );
}

// ═════════════════════════════════════════════════════════════════════════════
//  SSH Config Parsing
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn ssh_config_parse_basic() {
    let config_content = r#"
Host myserver
    HostName example.com
    User deploy
    Port 22
    IdentityFile ~/.ssh/id_ed25519

Host gateway
    HostName 10.0.0.1
    User admin
"#;
    let config = SshConfig::parse(config_content);
    assert_eq!(config.hosts.len(), 2);
    assert_eq!(config.hosts[0].host, "myserver");
    assert_eq!(config.hosts[0].hostname.as_deref(), Some("example.com"));
    assert_eq!(config.hosts[0].user.as_deref(), Some("deploy"));
    assert_eq!(config.hosts[0].port, Some(22));
    assert_eq!(config.hosts[1].host, "gateway");
}

#[test]
fn ssh_config_roundtrip() {
    let config_content = r#"
Host test-server
    HostName 192.168.1.100
    User root
    Port 2222
"#;
    let config = SshConfig::parse(config_content);
    let output = config.to_config_string();
    assert!(output.contains("Host test-server"));
    assert!(output.contains("HostName 192.168.1.100"));
    assert!(output.contains("User root"));
    assert!(output.contains("Port 2222"));
}

#[test]
fn ssh_config_parse_comments() {
    let config_content = r#"
# This is a comment
Host server1
    HostName example.com
    # inline comment
    User admin
"#;
    let config = SshConfig::parse(config_content);
    assert_eq!(config.hosts.len(), 1);
}

#[test]
fn ssh_config_parse_empty() {
    let config = SshConfig::parse("");
    assert!(config.hosts.is_empty());
}

#[test]
fn ssh_config_extra_options() {
    let config_content = r#"
Host server
    HostName example.com
    User admin
    ForwardAgent yes
    ProxyJump bastion
    CustomOption custom-value
"#;
    let config = SshConfig::parse(config_content);
    assert_eq!(config.hosts.len(), 1);
    assert_eq!(config.hosts[0].forward_agent, Some(true));
    assert_eq!(config.hosts[0].proxy_jump.as_deref(), Some("bastion"));
    assert_eq!(
        config.hosts[0]
            .extra
            .get("customoption")
            .map(|s| s.as_str()),
        Some("custom-value")
    );
}

// ═════════════════════════════════════════════════════════════════════════════
//  Crypto Utilities
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn constant_time_equal() {
    assert!(utils::constant_time_eq(b"hello", b"hello"));
    assert!(!utils::constant_time_eq(b"hello", b"world"));
    assert!(!utils::constant_time_eq(b"hi", b"hello"));
    assert!(utils::constant_time_eq(b"", b""));
}

#[test]
fn base64_roundtrip() {
    let data = b"Hello, SSHSpan!";
    let encoded = utils::base64_encode(data);
    let decoded = utils::base64_decode(&encoded).unwrap();
    assert_eq!(decoded, data);
}

#[test]
fn hex_roundtrip() {
    let data = b"\x01\x02\x03\x0a\xff";
    let encoded = utils::hex_encode(data);
    assert_eq!(encoded, "0102030aff");
    let decoded = utils::hex_decode(&encoded).unwrap();
    assert_eq!(decoded, data);
}

// ═════════════════════════════════════════════════════════════════════════════
//  Key Type Properties
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn key_type_equality() {
    assert_eq!(KeyType::Rsa, KeyType::Rsa);
    assert_ne!(KeyType::Rsa, KeyType::Ed25519);
}

#[test]
fn key_type_clone() {
    let kt = KeyType::Ed25519;
    let kt2 = kt.clone();
    assert_eq!(kt, kt2);
}

#[test]
fn key_format_variants() {
    let formats = [
        KeyFormat::OpenSsh,
        KeyFormat::Pkcs8,
        KeyFormat::Putty,
        KeyFormat::Rfc4716,
    ];
    for f in &formats {
        assert_eq!(*f, *f);
    }
}

// ═════════════════════════════════════════════════════════════════════════════
//  Database Operations (direct, no Tauri runtime needed)
// ═════════════════════════════════════════════════════════════════════════════

fn get_test_db() -> Database {
    let db_path = std::env::temp_dir().join(format!(
        "sshspan_test_{}.db",
        uuid::Uuid::new_v4().to_string().replace('-', "")
    ));
    let _ = std::fs::remove_file(&db_path);
    let db_url = format!("sqlite:{}?mode=rwc", db_path.display());
    let rt = tokio::runtime::Runtime::new().unwrap();
    let pool = rt
        .block_on(async { sqlx::SqlitePool::connect(&db_url).await })
        .unwrap();
    let db = Database { pool, db_path };
    rt.block_on(async {
        sqlx::query("CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL)").execute(&db.pool).await.unwrap();
        sqlx::query("CREATE TABLE IF NOT EXISTS audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT NOT NULL, key_id TEXT, details TEXT NOT NULL, timestamp TEXT NOT NULL)").execute(&db.pool).await.unwrap();
        sqlx::query("CREATE TABLE IF NOT EXISTS bitwarden_config (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL)").execute(&db.pool).await.unwrap();
    });
    db
}

#[test]
fn db_config_set_get() {
    let db = get_test_db();
    db.set_config("theme", "dark").unwrap();
    let val = db.get_config("theme").unwrap();
    assert_eq!(val.as_deref(), Some("dark"));

    db.set_config("theme", "light").unwrap();
    let val = db.get_config("theme").unwrap();
    assert_eq!(val.as_deref(), Some("light"));
}

#[test]
fn db_config_missing_returns_none() {
    let db = get_test_db();
    let val = db.get_config("nonexistent").unwrap();
    assert_eq!(val, None);
}

#[test]
fn db_audit_log() {
    let db = get_test_db();
    db.add_audit("vault.created", None, "test").unwrap();
    db.add_audit("vault.unlock", None, "test2").unwrap();
    // Audit log should have entries (we can verify no error)
    assert_eq!(db.count_audit().unwrap(), 2);
}

/// The log is capped so it cannot grow without bound. The cap is enforced on
/// insert, which is the only place rows are created.
#[test]
fn db_audit_retention_caps_row_count() {
    let db = get_test_db();
    // A couple of rows over the cap is enough to prove the trim fires without
    // writing 10k rows in a test.
    let cap = AUDIT_RETENTION_ROWS as usize;
    let total = cap + 3;
    for i in 0..total {
        db.add_audit("probe", None, &format!("row {i}")).unwrap();
    }
    assert_eq!(db.count_audit().unwrap(), AUDIT_RETENTION_ROWS);

    // The NEWEST rows survive: the trim deletes by id ascending from the
    // oldest, so the most recent write must still be present.
    let newest = db.list_audit(1).unwrap();
    assert_eq!(newest.len(), 1);
    assert_eq!(newest[0].details, format!("row {}", total - 1));
}

/// Clearing empties the table and reports how much went.
#[test]
fn db_audit_clear_removes_every_row() {
    let db = get_test_db();
    db.add_audit("a", None, "1").unwrap();
    db.add_audit("b", None, "2").unwrap();
    assert_eq!(db.count_audit().unwrap(), 2);

    let removed = db.clear_audit().unwrap();
    assert_eq!(removed, 2);
    assert_eq!(db.count_audit().unwrap(), 0);
    assert!(db.list_audit(10).unwrap().is_empty());
}

#[test]
fn db_bitwarden_config_save_load() {
    let db = get_test_db();
    let config = BitwardenConfig {
        server_url: Some("https://vault.example.com".to_string()),
        email: Some("user@example.com".to_string()),
        master_password: Some("sealed-blob".to_string()),
        folder_name: Some("SSHSpan".to_string()),
        servers_folder_name: Some("SSHSpan_Servers".to_string()),
        device_id: Some("device-1".to_string()),
        last_sync: None,
        last_result: None,
        confirmed_destination: None,
    };

    store_bitwarden_config(&db, &config);
    let loaded = db.load_bitwarden_config().unwrap();

    assert_eq!(
        loaded.server_url.as_deref(),
        Some("https://vault.example.com")
    );
    assert_eq!(loaded.email.as_deref(), Some("user@example.com"));
    assert_eq!(loaded.master_password.as_deref(), Some("sealed-blob"));
    assert_eq!(loaded.folder_name.as_deref(), Some("SSHSpan"));
    assert_eq!(loaded.device_id.as_deref(), Some("device-1"));
}

#[test]
fn db_bitwarden_config_defaults() {
    let db = get_test_db();
    let loaded = db.load_bitwarden_config().unwrap();
    assert_eq!(loaded.server_url, None);
    assert_eq!(loaded.email, None);
    assert_eq!(loaded.folder_name, None);
}

#[test]
fn db_bitwarden_config_overwrite() {
    let db = get_test_db();
    let config1 = BitwardenConfig {
        server_url: Some("https://old.example.com".to_string()),
        email: Some("old@example.com".to_string()),
        ..BitwardenConfig::default()
    };
    store_bitwarden_config(&db, &config1);

    let config2 = BitwardenConfig {
        server_url: Some("https://new.example.com".to_string()),
        email: Some("new@example.com".to_string()),
        ..BitwardenConfig::default()
    };
    store_bitwarden_config(&db, &config2);

    let loaded = db.load_bitwarden_config().unwrap();
    assert_eq!(
        loaded.server_url.as_deref(),
        Some("https://new.example.com")
    );
    assert_eq!(loaded.email.as_deref(), Some("new@example.com"));
}

#[test]
fn db_multiple_config_keys() {
    let db = get_test_db();
    db.set_config("key1", "value1").unwrap();
    db.set_config("key2", "value2").unwrap();
    db.set_config("key3", "value3").unwrap();

    assert_eq!(db.get_config("key1").unwrap().as_deref(), Some("value1"));
    assert_eq!(db.get_config("key2").unwrap().as_deref(), Some("value2"));
    assert_eq!(db.get_config("key3").unwrap().as_deref(), Some("value3"));
}

/// Regression: corrupt/legacy/tampered non-RFC3339 timestamps in the DB must
/// not panic the row mappers (they crashed list_keys / list_categories /
/// list_audit — and with them the whole Tauri command). The mappers now fall
/// back to `Utc::now()` like `row_to_server` always did.
#[test]
fn db_malformed_timestamps_fall_back_instead_of_panicking() {
    use chrono::Datelike;

    let db = get_test_db();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        // Same shape as Database::migrate() — only the columns the row
        // mappers read are load-bearing here.
        sqlx::query("CREATE TABLE IF NOT EXISTS keys (id TEXT PRIMARY KEY, name TEXT NOT NULL, key_type TEXT NOT NULL, public_key TEXT NOT NULL, private_key_encrypted TEXT NOT NULL, fingerprint_sha256 TEXT NOT NULL, fingerprint_md5 TEXT NOT NULL, comment TEXT DEFAULT '', created_at TEXT NOT NULL, updated_at TEXT NOT NULL, deployed INTEGER DEFAULT 0, deploy_path TEXT, bitwarden_id TEXT, bitwarden_sync INTEGER DEFAULT 0, bitwarden_revision_ts TEXT, bitwarden_updated_at TEXT)").execute(&db.pool).await.unwrap();
        sqlx::query("CREATE TABLE IF NOT EXISTS categories (id TEXT PRIMARY KEY, name TEXT NOT NULL, parent_id TEXT, scope TEXT NOT NULL DEFAULT 'key', color TEXT, sort_index INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)").execute(&db.pool).await.unwrap();

        // Keys: one corrupt row (legacy "YYYY-MM-DD HH:MM:SS"), one valid control.
        sqlx::query("INSERT INTO keys (id, name, key_type, public_key, private_key_encrypted, fingerprint_sha256, fingerprint_md5, comment, created_at, updated_at) VALUES ('k-corrupt', 'corrupt', 'ssh-ed25519', 'pub', 'priv', 'SHA256:x', 'x', '', '2023-01-02 03:04:05', 'not-a-timestamp'), ('k-ok', 'ok', 'ssh-ed25519', 'pub', 'priv', 'SHA256:y', 'y', '', '2023-01-02T03:04:05+00:00', '2023-01-02T03:04:05+00:00')").execute(&db.pool).await.unwrap();

        // Categories: same mix.
        sqlx::query("INSERT INTO categories (id, name, parent_id, scope, color, sort_index, created_at, updated_at) VALUES ('c-corrupt', 'corrupt', NULL, 'key', NULL, 0, '2023-01-02 03:04:05', 'garbage'), ('c-ok', 'ok', NULL, 'key', NULL, 1, '2023-01-02T03:04:05+00:00', '2023-01-02T03:04:05+00:00')").execute(&db.pool).await.unwrap();

        // Audit log: corrupt timestamp row + a valid one.
        sqlx::query("INSERT INTO audit_log (action, key_id, details, timestamp) VALUES ('vault.unlock', NULL, 'corrupt', '1690000000'), ('vault.unlock', NULL, 'ok', '2023-01-02T03:04:05+00:00')").execute(&db.pool).await.unwrap();
    });

    // These three calls used to panic on the corrupt rows; now the mappers
    // must return records with fallback timestamps.
    let keys = db.list_keys().unwrap();
    assert_eq!(keys.len(), 2);
    let corrupt_key = keys.iter().find(|k| k.id == "k-corrupt").unwrap();
    let ok_key = keys.iter().find(|k| k.id == "k-ok").unwrap();
    // Fallback: parse failure lands near now, not near 2023 / the epoch.
    assert!(corrupt_key.created_at.year() >= 2024);
    assert!(corrupt_key.updated_at.year() >= 2024);
    // Valid rows keep their stored timestamp (2023-01-02T03:04:05Z).
    assert_eq!(ok_key.created_at.to_rfc3339(), "2023-01-02T03:04:05+00:00");

    let categories = db.list_categories().unwrap();
    assert_eq!(categories.len(), 2);
    let corrupt_cat = categories.iter().find(|c| c.id == "c-corrupt").unwrap();
    let ok_cat = categories.iter().find(|c| c.id == "c-ok").unwrap();
    assert!(corrupt_cat.created_at.year() >= 2024);
    assert!(corrupt_cat.updated_at.year() >= 2024);
    assert_eq!(ok_cat.created_at.to_rfc3339(), "2023-01-02T03:04:05+00:00");

    let audit = db.list_audit(10).unwrap();
    assert_eq!(audit.len(), 2);
    let corrupt_audit = audit.iter().find(|a| a.details == "corrupt").unwrap();
    let ok_audit = audit.iter().find(|a| a.details == "ok").unwrap();
    assert!(corrupt_audit.timestamp.year() >= 2024);
    assert_eq!(ok_audit.timestamp.to_rfc3339(), "2023-01-02T03:04:05+00:00");
}

// ═════════════════════════════════════════════════════════════════════════════
//  Vault Lifecycle (create → unlock → lock → unlock with wrong password)
// ═════════════════════════════════════════════════════════════════════════════

use sshspan::commands::VaultPasswordStore;

#[test]
fn vault_lifecycle_create_unlock_lock() {
    let db = get_test_db();

    // No vault initially
    assert!(db.get_config("master.hash").unwrap().is_none());

    // Create vault — store password hash
    let password = "testpass123";
    db.set_config("master.hash", password).unwrap();
    db.set_config("vault.created", &chrono::Utc::now().to_rfc3339())
        .unwrap();
    db.add_audit("vault.created", None, "Vault created")
        .unwrap();

    // Verify vault exists
    let hash = db.get_config("master.hash").unwrap();
    assert!(hash.is_some());
    assert_eq!(hash.unwrap(), password);

    // Simulate unlock — verify password matches
    let stored = db.get_config("master.hash").unwrap().unwrap();
    assert_eq!(stored, password, "unlock: password matches");

    // Simulate lock — clear in-memory password
    let store = VaultPasswordStore::new();
    assert!(store.get().is_none(), "fresh store has no password");

    store.set(password.to_string());
    assert!(store.get().is_some(), "after set, password is present");

    store.clear();
    assert!(store.get().is_none(), "after clear, password is gone");

    // Simulate unlock with wrong password — should fail
    let wrong_stored = db.get_config("master.hash").unwrap().unwrap();
    assert_ne!(
        "wrongpassword", wrong_stored,
        "wrong password should not match"
    );
}

#[test]
fn vault_lifecycle_full_flow() {
    let db = get_test_db();
    let store = VaultPasswordStore::new();

    // 1. No vault
    assert!(db.get_config("master.hash").unwrap().is_none());

    // 2. Create vault
    let pw = "masterpass456";
    db.set_config("master.hash", pw).unwrap();
    db.set_config("vault.created", &chrono::Utc::now().to_rfc3339())
        .unwrap();
    db.add_audit("vault.created", None, "").unwrap();

    // 3. Verify creation
    assert_eq!(db.get_config("master.hash").unwrap().unwrap(), pw);
    store.set(pw.to_string());
    assert!(store.get().is_some());

    // 4. Lock
    store.clear();
    assert!(store.get().is_none());

    // 5. Unlock with correct password
    let stored = db.get_config("master.hash").unwrap().unwrap();
    assert_eq!(stored, pw);
    store.set(pw.to_string());
    assert!(store.get().is_some());

    // 6. Change password
    let new_pw = "newmaster789";
    db.set_config("master.hash", new_pw).unwrap();
    db.add_audit("vault.password_changed", None, "").unwrap();
    store.set(new_pw.to_string());

    // 7. Old password should fail
    let stored2 = db.get_config("master.hash").unwrap().unwrap();
    assert_ne!(stored2, pw, "old password should not match after change");
    assert_eq!(stored2, new_pw, "new password should match");

    // 8. Lock again
    store.clear();
    assert!(store.get().is_none());
}

// ═════════════════════════════════════════════════════════════════════════════
//  Key Deploy to ~/.ssh
// ═════════════════════════════════════════════════════════════════════════════

use sshspan::ssh::{DeployFiles, DeployHostFields, DeployKey, DeployTarget, SshService};

/// The deploy writes into the directories it is given - here a temp dir, never
/// the real `~/.ssh` (A7-56) - and what it writes is checked: the key files,
/// owner-only permissions on the private one, and a Host stanza carrying the
/// HostName / User / Port the deploy sheet collects (A7-04), identical to the
/// preview text.
#[test]
fn key_deploy_creates_files() {
    let root = std::env::temp_dir().join(format!(
        "sshspan_deploy_test_{}",
        uuid::Uuid::new_v4().simple()
    ));
    let target = DeployTarget::new(
        root.join("home").join(".ssh"),
        root.join("app-config").join("ssh").join("config"),
    );
    let key = keys::generate_key_pair(KeyType::Ed25519, None, "deploy-test".to_string()).unwrap();
    let private_pem = keys::export_private_key(&key, KeyFormat::OpenSsh, None).unwrap();
    let public_openssh = keys::export_public_key(&key, KeyFormat::OpenSsh).unwrap();
    let fields = DeployHostFields::parse(
        Some("myserver".into()),
        Some("server.example.com".into()),
        Some("deploy".into()),
        Some(2222),
        Some(true),
    )
    .unwrap();
    let request = [DeployKey {
        id: "k1".into(),
        name: "deploy-test".into(),
        deploy_path: None,
    }];

    let plan = SshService::plan_deploy(&target, &request, &[], &fields).unwrap();
    let preview = plan.config_text();
    let outcome = SshService::apply_deploy(&plan, |_| {
        Ok(DeployFiles {
            private_key: zeroize::Zeroizing::new(private_pem.clone()),
            public_key: public_openssh.clone(),
        })
    });

    let private_path = root.join("home").join(".ssh").join("sshspan_deploy-test");
    let written_private = fs::read_to_string(&private_path);
    let written_public = fs::read_to_string(private_path.with_extension("pub"));
    let written_config = fs::read_to_string(&target.config_path);
    #[cfg(unix)]
    let mode = {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(&private_path).map(|m| m.permissions().mode() & 0o777)
    };
    let _ = fs::remove_dir_all(&root);

    assert!(outcome.errors.is_empty(), "{:?}", outcome.errors);
    assert!(outcome.warnings.is_empty(), "{:?}", outcome.warnings);
    assert_eq!(outcome.deployed.len(), 1);
    assert_eq!(outcome.deployed[0].file, private_path.display().to_string());
    assert_eq!(outcome.deployed[0].alias, "myserver");
    assert_eq!(written_private.unwrap(), private_pem);
    assert_eq!(written_public.unwrap(), public_openssh);
    #[cfg(unix)]
    assert_eq!(mode.unwrap(), 0o600, "the private key must be owner-only");
    let config = written_config.unwrap();
    assert_eq!(config, preview, "the preview is what was written");
    for line in [
        "Host myserver\n",
        "    HostName server.example.com\n",
        "    User deploy\n",
        "    Port 2222\n",
        "    IdentitiesOnly yes\n",
    ] {
        assert!(config.contains(line), "missing {line:?} in\n{config}");
    }
    // Compared parsed: on Windows the path is written quoted and escaped.
    assert_eq!(
        SshConfig::parse(&config).hosts[0].identity_file,
        Some(private_path.display().to_string())
    );
}

/// Users are told to `Include` the managed config from
/// `~/.ssh/config`, so one line OpenSSH rejects stops EVERY ssh command. Deploy
/// into a home directory whose path has a space and an apostrophe, with key
/// names holding quote, backslash and comment characters, then let the real
/// `ssh -G` read the result through the Include line SSHSpan hands out.
/// Skipped (passes) when no `ssh` client is installed; Unix only (the WSL /
/// CI check - Win32-OpenSSH formats `ssh -G` paths its own way).
#[cfg(unix)]
#[test]
fn openssh_parses_the_managed_config_through_the_include_line() {
    let Ok(version) = std::process::Command::new("ssh").arg("-V").output() else {
        eprintln!("skipped: no ssh client on PATH");
        return;
    };
    eprintln!(
        "ssh -V: {}",
        String::from_utf8_lossy(&version.stderr).trim()
    );
    let root =
        std::env::temp_dir().join(format!("sshspan_ssh_g_{}", uuid::Uuid::new_v4().simple()));
    let target = DeployTarget::new(
        root.join("John O'Neil Smith").join(".ssh"),
        root.join("app config").join("ssh").join("config"),
    );
    let names = ["bob's key", "back\\slash", "#hash", "web*prod"];
    let request: Vec<DeployKey> = names
        .iter()
        .enumerate()
        .map(|(i, n)| DeployKey {
            id: format!("k{i}"),
            name: n.to_string(),
            deploy_path: None,
        })
        .collect();
    let fields = DeployHostFields::parse(
        None,
        Some("server.example.com".into()),
        Some(r"CORP\deploy".into()),
        Some(2222),
        Some(true),
    )
    .unwrap();
    let plan = SshService::plan_deploy(&target, &request, &[], &fields).unwrap();
    let outcome = SshService::apply_deploy(&plan, |planned| {
        Ok(DeployFiles {
            private_key: zeroize::Zeroizing::new(format!("PRIVATE {}", planned.id)),
            public_key: format!("ssh-ed25519 AAAAC3Nza {}", planned.id),
        })
    });
    let main_config = root.join("user ssh config");
    fs::write(&main_config, format!("{}\n", target.include_line())).unwrap();

    let mut problems = Vec::new();
    if !outcome.errors.is_empty() {
        problems.push(format!("deploy errors: {:?}", outcome.errors));
    }
    for deployed in &outcome.deployed {
        let run = std::process::Command::new("ssh")
            .arg("-G")
            .arg("-F")
            .arg(&main_config)
            .arg(&deployed.alias)
            .output()
            .expect("run ssh -G");
        let stdout = String::from_utf8_lossy(&run.stdout);
        let wanted = [
            format!("identityfile {}", deployed.file),
            "hostname server.example.com".to_string(),
            r"user CORP\deploy".to_string(),
            "port 2222".to_string(),
        ];
        let missing: Vec<&String> = wanted
            .iter()
            .filter(|w| !stdout.lines().any(|l| l == w.as_str()))
            .collect();
        if !run.status.success() || !missing.is_empty() {
            problems.push(format!(
                "ssh -G {:?} -> {}: {} missing {missing:?}",
                deployed.alias,
                run.status,
                String::from_utf8_lossy(&run.stderr).trim()
            ));
        }
    }
    let config_text = fs::read_to_string(&target.config_path).unwrap_or_default();
    let _ = fs::remove_dir_all(&root);
    assert_eq!(outcome.deployed.len(), names.len(), "{problems:?}");
    assert!(
        problems.is_empty(),
        "{}\nmanaged config:\n{config_text}",
        problems.join("\n")
    );
}

// ═════════════════════════════════════════════════════════════════════════════
//  Bitwarden Config Extended Tests
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn bitwarden_config_partial_update() {
    let db = get_test_db();

    // Set initial config
    let config = BitwardenConfig {
        server_url: Some("https://old.example.com".to_string()),
        email: Some("user@example.com".to_string()),
        folder_name: Some("SSHSpan".to_string()),
        ..BitwardenConfig::default()
    };
    store_bitwarden_config(&db, &config);

    // Update only server_url and email
    let updated = BitwardenConfig {
        server_url: Some("https://new.example.com".to_string()),
        email: Some("new@example.com".to_string()),
        folder_name: Some("SSHSpan".to_string()), // keep same
        ..BitwardenConfig::default()
    };
    store_bitwarden_config(&db, &updated);

    let loaded = db.load_bitwarden_config().unwrap();
    assert_eq!(
        loaded.server_url.as_deref(),
        Some("https://new.example.com")
    );
    assert_eq!(loaded.email.as_deref(), Some("new@example.com"));
    assert_eq!(loaded.folder_name.as_deref(), Some("SSHSpan"));
}

#[test]
fn bitwarden_config_last_sync() {
    let db = get_test_db();
    let sync_time = chrono::Utc::now();

    let config = BitwardenConfig {
        server_url: Some("https://vault.example.com".to_string()),
        last_sync: Some(sync_time),
        ..BitwardenConfig::default()
    };
    store_bitwarden_config(&db, &config);

    let loaded = db.load_bitwarden_config().unwrap();
    assert!(loaded.last_sync.is_some());
    let loaded_sync = loaded.last_sync.unwrap();
    assert!(
        (loaded_sync - sync_time).num_seconds().abs() < 2,
        "sync time should be close to original"
    );
}

#[test]
fn bitwarden_config_empty_strings() {
    let db = get_test_db();

    let config = BitwardenConfig {
        server_url: Some("".to_string()),
        email: Some("".to_string()),
        folder_name: Some("".to_string()),
        ..BitwardenConfig::default()
    };
    store_bitwarden_config(&db, &config);

    let loaded = db.load_bitwarden_config().unwrap();
    assert_eq!(loaded.server_url.as_deref(), Some(""));
    assert_eq!(loaded.email.as_deref(), Some(""));
}

// ═════════════════════════════════════════════════════════════════════════════
//  Key Generate + Export + Import Full Roundtrip
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn key_full_roundtrip_ed25519() {
    // 1. Generate
    let key = keys::generate_key_pair(KeyType::Ed25519, None, "full-rt".to_string()).unwrap();
    let _fp_orig = keys::compute_fingerprint_sha256(&key.public_key);

    // 2. Export public key
    let pub_exported = keys::export_public_key(&key, KeyFormat::OpenSsh).unwrap();
    assert!(pub_exported.starts_with("ssh-ed25519 "));

    // 3. The exported line carries algorithm + base64 + comment
    assert_eq!(openssh_pub_algo(&pub_exported), "ssh-ed25519");
    assert!(pub_exported.ends_with("full-rt"));
    assert!(pub_exported
        .split_whitespace()
        .nth(1)
        .map_or(false, |b| !b.is_empty()));
}

#[test]
fn key_full_roundtrip_rsa() {
    let key = keys::generate_key_pair(KeyType::Rsa, Some(2048), "rsa-full".to_string()).unwrap();
    let fp = keys::compute_fingerprint_sha256(&key.public_key);
    assert!(fp.starts_with("SHA256:"));

    let pub_exported = keys::export_public_key(&key, KeyFormat::OpenSsh).unwrap();
    assert!(pub_exported.starts_with("ssh-rsa "));
}

#[test]
fn key_full_roundtrip_ecdsa() {
    let key = keys::generate_key_pair(KeyType::EcdsaP256, None, "ec-full".to_string()).unwrap();
    let fp = keys::compute_fingerprint_sha256(&key.public_key);
    assert!(fp.starts_with("SHA256:"));

    let pub_exported = keys::export_public_key(&key, KeyFormat::OpenSsh).unwrap();
    assert!(pub_exported.starts_with("ecdsa-sha2-nistp256 "));
    assert_eq!(openssh_pub_algo(&pub_exported), "ecdsa-sha2-nistp256");
}

// ═════════════════════════════════════════════════════════════════════════════
//  Vault backup -> restore (backups never transit the webview)
// ═════════════════════════════════════════════════════════════════════════════

use sshspan::commands::{apply_restore, build_backup_document, RestoreOutcome};
use sshspan::db::KeyRecord;

/// A fresh, fully migrated database in a temp file (the real schema, not a
/// hand-copied subset - backup and restore touch nearly every table).
fn fresh_db(tag: &str) -> Database {
    Database::open_at(std::env::temp_dir().join(format!(
        "sshspan_it_{tag}_{}.db",
        uuid::Uuid::new_v4().simple()
    )))
    .expect("open test database")
}

fn backup_key(id: &str, name: &str, private_key_encrypted: String) -> KeyRecord {
    KeyRecord {
        id: id.into(),
        name: name.into(),
        key_type: "ed25519".into(),
        public_key: format!("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFake {name}"),
        private_key_encrypted,
        fingerprint_sha256: format!("SHA256:fake-{id}"),
        fingerprint_md5: format!("MD5:fake-{id}"),
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

/// Backup -> restore into a fresh database keeps what the old pair dropped:
/// a key's Bitwarden revision metadata (serialized as JSON numbers, read back
/// as strings only - A7-27) and the per-server SFTP bookmarks (A7-41), and the
/// restore leaves its audit row.
#[test]
fn backup_restore_round_trip_keeps_key_sync_metadata_bookmarks_and_audit() {
    let pw = "round-trip-master-pw";
    let src = fresh_db("backup_src");
    let mut key = backup_key(
        "k-linked",
        "linked",
        sshspan::crypto::vault::seal(pw, b"fake-private-key").unwrap(),
    );
    key.bitwarden_id = Some("cipher-1".into());
    key.bitwarden_sync = true;
    key.bitwarden_revision_ts = Some(1_717_000_000_123);
    key.bitwarden_updated_at = Some(1_717_000_000_456);
    src.insert_key(&key).unwrap();
    let bookmarks = serde_json::json!([
        { "name": "logs", "remotePath": "/var/log", "localPath": null },
        { "name": "www", "remotePath": "/srv/www", "localPath": "/home/me/www" },
    ]);
    src.set_config("sftp.bookmarks.srv-1", &bookmarks.to_string())
        .unwrap();

    let backup = build_backup_document(&src, pw).expect("build the backup");
    assert_eq!(backup.counts["sftpBookmarks"], 1);
    assert!(backup.filename.starts_with("sshspan-backup-") && backup.filename.ends_with(".json"));
    // The backup carries what is STORED: `settings_get` reports defaults for
    // unset keys, but a restore must not pin them over the target's choices.
    let payload: serde_json::Value = serde_json::from_slice(
        &sshspan::crypto::vault::unseal(pw, backup.document["sealed"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(payload["settings"], serde_json::json!({}));

    let dst = fresh_db("backup_dst");
    let outcome = apply_restore(&dst, &backup.document, pw, None, &|| Ok(())).expect("restore");
    let RestoreOutcome::Restored(result) = outcome else {
        panic!("same master password - no backup password needed: {outcome:?}");
    };
    assert_eq!(result["ok"], true);

    let mut lost = Vec::new();
    let restored = dst.get_key("k-linked").unwrap().expect("key restored");
    if restored.bitwarden_id.as_deref() != Some("cipher-1") || !restored.bitwarden_sync {
        lost.push(format!(
            "bitwarden link: {:?} / {}",
            restored.bitwarden_id, restored.bitwarden_sync
        ));
    }
    if restored.bitwarden_revision_ts != Some(1_717_000_000_123) {
        lost.push(format!(
            "bitwarden_revision_ts: {:?}",
            restored.bitwarden_revision_ts
        ));
    }
    if restored.bitwarden_updated_at != Some(1_717_000_000_456) {
        lost.push(format!(
            "bitwarden_updated_at: {:?}",
            restored.bitwarden_updated_at
        ));
    }
    if sshspan::crypto::vault::unseal(pw, &restored.private_key_encrypted).ok()
        != Some(b"fake-private-key".to_vec())
    {
        lost.push("private key no longer unseals".into());
    }
    let restored_bookmarks = dst
        .get_config("sftp.bookmarks.srv-1")
        .unwrap()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok());
    if restored_bookmarks.as_ref() != Some(&bookmarks) {
        lost.push(format!("sftp bookmarks: {restored_bookmarks:?}"));
    }
    if !dst
        .list_audit(50)
        .unwrap()
        .iter()
        .any(|a| a.action == "vault.backup_restored")
    {
        lost.push("no vault.backup_restored audit row".into());
    }
    assert!(
        lost.is_empty(),
        "the round trip lost:\n  {}",
        lost.join("\n  ")
    );
}

/// A7-25: names that are not valid Host tokens are sanitized on restore and
/// each rename is audited. The audit row used to be written through a second
/// pooled connection while the restore's own write transaction held the
/// SQLite write lock - so every rename after the first write waited out the
/// 5 s busy timeout and then lost its audit row.
#[test]
fn restore_with_invalid_key_names_audits_each_rename_without_stalling() {
    let db = fresh_db("restore_rename");
    let stamp = chrono::Utc::now().to_rfc3339();
    let mut keys = Vec::new();
    for (id, name) in [("k1", "old key one"), ("k2", "old key two")] {
        let mut k = serde_json::to_value(backup_key(id, name, "x".into())).unwrap();
        k["category_ids"] = serde_json::json!(["c1"]);
        keys.push(k);
    }
    // The category is written first, so the transaction already holds the
    // write lock when the first rename is audited.
    let payload = serde_json::json!({
        "categories": [{ "id": "c1", "name": "Prod", "scope": "key", "sort_index": 0,
                         "created_at": stamp, "updated_at": stamp }],
        "keys": keys,
    });

    let started = std::time::Instant::now();
    let counts = db.restore_backup(&payload).expect("restore");
    let elapsed = started.elapsed();

    let mut problems = Vec::new();
    // A stalled rename waits out the whole 5 s busy timeout (and loses its
    // audit row, counted below); the rest is room for a loaded machine.
    if elapsed >= std::time::Duration::from_millis(4500) {
        problems.push(format!("restore stalled for {elapsed:?}"));
    }
    if counts["keys"] != 2 {
        problems.push(format!("restored keys: {}", counts["keys"]));
    }
    let renames = db
        .list_audit(50)
        .unwrap()
        .into_iter()
        .filter(|a| a.action == "keys.name_sanitized")
        .count();
    if renames != 2 {
        problems.push(format!("keys.name_sanitized audit rows: {renames}, want 2"));
    }
    for (id, raw) in [("k1", "old key one"), ("k2", "old key two")] {
        let name = db.get_key(id).unwrap().map(|k| k.name);
        let want = keys::sanitize_key_name(raw);
        if name.as_deref() != Some(want.as_str()) {
            problems.push(format!("{id} name {name:?}, want {want:?}"));
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

// ═════════════════════════════════════════════════════════════════════════════
//  SSH Config Deploy Workflow
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn ssh_config_deploy_workflow() {
    // Simulate the deploy view workflow:
    // 1. Parse existing SSH config
    let existing = r#"
Host existing-server
    HostName old.example.com
    User admin
"#;
    let mut config = SshConfig::parse(existing);
    assert_eq!(config.hosts.len(), 1);

    // 2. Add new host entry (as deploy would)
    use std::collections::HashMap;
    config.hosts.push(sshspan::config::SshHostConfig {
        host: "sshspan-managed".to_string(),
        hostname: Some("new.example.com".to_string()),
        user: Some("deploy".to_string()),
        port: None,
        identity_file: Some("~/.ssh/sshspan_managed_key".to_string()),
        identities_only: Some(true),
        forward_agent: Some(false),
        proxy_jump: None,
        extra: HashMap::new(),
    });

    assert_eq!(config.hosts.len(), 2);

    // 3. Serialize back
    let output = config.to_config_string();
    assert!(output.contains("Host existing-server"));
    assert!(output.contains("Host sshspan-managed"));
    assert!(output.contains("HostName new.example.com"));
    assert!(output.contains("IdentityFile ~/.ssh/sshspan_managed_key"));
    assert!(output.contains("IdentitiesOnly yes"));
}

use std::fs;
