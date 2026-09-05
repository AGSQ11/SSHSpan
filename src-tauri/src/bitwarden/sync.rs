//! Two-way sync between the SSHSpan vault and Bitwarden vault —
//! 1:1 port of bitwardenSyncService.js
//!
//! Sync model (per row, newest side wins):
//!   - local key with no remote counterpart → pushed
//!   - remote SSH item with no local counterpart → pulled
//!   - matched by bitwarden_id or fingerprint: local updatedAt vs
//!     bitwardenUpdatedAt decides local; remote revisionDate vs
//!     stored bitwardenRevision decides remote. Both moved → local wins.
//!   - deletions are NEVER propagated automatically.

use anyhow::Result;
use crate::bitwarden::BitwardenClient;
use crate::db::{Database, KeyRecord};

const FOLDER_DEFAULT: &str = "SSHSpan";

/// Run a full two-way sync. Returns a JSON summary.
#[allow(clippy::too_many_arguments)]
pub async fn run_sync(
    server_url: &str,
    email: &str,
    master_password: &str,
    device_id: &str,
    folder_name: &str,
    servers_folder_name: &str,
    db: &Database,
    vault_password: &str,
) -> Result<serde_json::Value> {
    let mut client = BitwardenClient::new(server_url, email, master_password, device_id)?;
    client.connect().await?;

    let remote = client.sync().await?;

    // Find or create the sync folder
    let folder_name_lower = folder_name.to_lowercase();
    let folder = remote.folders.iter().find(|f| {
        f.name.as_ref().map_or(false, |n| n.to_lowercase() == folder_name_lower)
    });
    let folder_id = match folder {
        Some(f) => Some(f.id.clone()),
        None => {
            let created = client.create_folder(folder_name).await.ok();
            created.and_then(|v| v.get("id").and_then(|id| id.as_str()).map(String::from))
        }
    };

    // Folder migration: single-folder era -> SSHSpan_Keys / SSHSpan_Servers.
    // When the default key folder is requested and a legacy "SSHSpan" folder
    // exists, rename it instead of creating a duplicate.
    let keys_lower = folder_name.to_lowercase();
    let has_legacy = remote.folders.iter().any(|f| {
        f.name.as_ref().map_or(false, |n| n.to_lowercase() == "sshspan")
    });
    let has_keys_folder = remote.folders.iter().any(|f| {
        f.name.as_ref().map_or(false, |n| n.to_lowercase() == keys_lower)
    });
    if keys_lower == "sshspan_keys" && has_legacy && !has_keys_folder {
        let legacy = remote.folders.iter().find(|f| {
            f.name.as_ref().map_or(false, |n| n.to_lowercase() == "sshspan")
        }).cloned();
        if let Some(legacy) = legacy {
            if client.update_folder(&legacy.id, folder_name).await.is_ok() {
                let _ = db.add_audit("sync.folder_migrated", None, "SSHSpan -> SSHSpan_Keys");
            }
        }
    }

    // Resolve (or create) the servers folder.
    let servers_lower = servers_folder_name.to_lowercase();
    let servers_folder = remote.folders.iter().find(|f| {
        f.name.as_ref().map_or(false, |n| n.to_lowercase() == servers_lower)
    });
    let servers_folder_id = match servers_folder {
        Some(f) => Some(f.id.clone()),
        None => {
            let created = client.create_folder(servers_folder_name).await.ok();
            created.and_then(|v| v.get("id").and_then(|id| id.as_str()).map(String::from))
        }
    };

    // Build remote maps
    let remote_ssh: Vec<_> = remote.ciphers.iter().filter(|c| {
        c.cipher_type == 5 && c.deleted_date.is_none() && c.organization_id.is_none()
    }).collect();

    // Decrypt remote fingerprints for matching
    let mut fp_by_cipher_id = std::collections::HashMap::new();
    for c in &remote_ssh {
        if let Some(ref fp_enc) = c.ssh_key.as_ref().and_then(|sk| sk.key_fingerprint.as_ref()) {
            if let Ok(fp) = client.decrypt_field(fp_enc) {
                fp_by_cipher_id.insert(c.id.clone(), fp);
            }
        }
    }

    let local_keys = db.list_keys()?;
    let mut matched_remote = std::collections::HashSet::new();
    let mut pushed = 0usize;
    let mut updated_remote = 0usize;
    let mut pulled = 0usize;
    let mut updated_local = 0usize;
    let mut linked = 0usize;
    let mut conflicts = 0usize;
    let mut remote_deleted = 0usize;
    let mut errors = Vec::new();

    // ─── Pass 1: local → remote ──────────────────────────────────────────
    for row in &local_keys {
        if row.private_key_encrypted.is_empty() {
            continue; // public-only
        }

        // Find matching remote cipher
        let cipher = row.bitwarden_id.as_ref().and_then(|bw_id| {
            remote_ssh.iter().find(|c| c.id == *bw_id)
        }).or_else(|| {
            // Fingerprint match
            remote_ssh.iter().find(|c| {
                fp_by_cipher_id.get(&c.id).map_or(false, |fp| *fp == row.fingerprint_sha256)
            })
        });

        let cipher = match cipher {
            Some(c) => c,
            None => {
                // Push new item
                match push_local_key(&mut client, row, &folder_id, db, vault_password).await {
                    Ok(()) => { pushed += 1; }
                    Err(e) => { errors.push(serde_json::json!({"name": row.name, "error": e.to_string()})); }
                }
                continue;
            }
        };

        matched_remote.insert(cipher.id.clone());

        // First contact through fingerprint match: adopt the link
        if row.bitwarden_id.as_deref() != Some(&cipher.id) {
            db.update_key_sync_meta(&row.id, &cipher.id, cipher.revision_date.as_deref())
                .ok();
            linked += 1;
            continue;
        }

        // Compare timestamps
        let local_changed = row.updated_at.timestamp_millis() > (row.bitwarden_updated_at.unwrap_or(0));
        let remote_changed = cipher.revision_date.as_ref()
            .and_then(|rd| chrono::DateTime::parse_from_rfc3339(rd).ok())
            .map_or(false, |rd| rd.timestamp_millis() > (row.bitwarden_revision_ts.unwrap_or(0)));

        if !local_changed && !remote_changed { continue; }

        if local_changed {
            if remote_changed { conflicts += 1; } // local wins
            match push_local_key(&mut client, row, &folder_id, db, vault_password).await {
                Ok(()) => { updated_remote += 1; }
                Err(e) => { errors.push(serde_json::json!({"name": row.name, "error": e.to_string()})); }
            }
        } else {
            // Pull remote into local
            match pull_remote_item(&mut client, cipher, row, db, vault_password).await {
                Ok(()) => { updated_local += 1; }
                Err(e) => { errors.push(serde_json::json!({"name": row.name, "error": e.to_string()})); }
            }
        }
    }

    // ─── Pass 2: remote → local (unmatched items) ────────────────────────
    for cipher in &remote_ssh {
        if matched_remote.contains(&cipher.id) { continue; }

        let ssh = cipher.ssh_key.as_ref();
        let priv_key_enc = ssh.and_then(|sk| sk.private_key.as_ref());
        let pub_key_enc = ssh.and_then(|sk| sk.public_key.as_ref());
        let fp_enc = ssh.and_then(|sk| sk.key_fingerprint.as_ref());

        if priv_key_enc.is_none() {
            errors.push(serde_json::json!({"cipher_id": cipher.id, "error": "no privateKey in sshKey block"}));
            continue;
        }

        let priv_pem = match client.decrypt_field(priv_key_enc.unwrap()) {
            Ok(s) => s,
            Err(e) => {
                errors.push(serde_json::json!({"cipher_id": cipher.id, "error": format!("privateKey decrypt failed: {e}")}));
                continue;
            }
        };
        let pub_key = pub_key_enc.map(|e| client.decrypt_field(e)).transpose().unwrap_or_default();
        let fp = fp_enc.map(|e| client.decrypt_field(e)).transpose().unwrap_or_default();

        let name = cipher.name.as_ref()
            .and_then(|n| client.decrypt_field(n).ok())
            .unwrap_or_else(|| "imported key".to_string());

        // Import the private key
        let key_data = match crate::crypto::keys::import_openssh_private(&priv_pem, None) {
            Ok(kd) => kd,
            Err(e) => {
                errors.push(serde_json::json!({"cipher_id": cipher.id, "error": format!("OpenSSH private key import failed: {e}")}));
                continue;
            }
        };

        let public_openssh = crate::crypto::keys::export_public_key(&key_data, crate::crypto::keys::KeyFormat::OpenSsh).unwrap_or_default();
        let fingerprint = crate::crypto::keys::compute_fingerprint_sha256(&key_data.public_key);
        let fingerprint_md5 = crate::crypto::keys::compute_fingerprint_md5(&key_data.public_key);
        let sealed = crate::crypto::vault::seal(vault_password, &key_data.private_key).unwrap_or_default();

        let key_record = KeyRecord {
            id: uuid::Uuid::new_v4().to_string(),
            name,
            key_type: key_data.key_type.db_tag().to_string(),
            public_key: if pub_key.is_some() { pub_key.unwrap() } else { public_openssh },
            private_key_encrypted: sealed,
            fingerprint_sha256: if fp.is_some() { fp.unwrap() } else { fingerprint },
            fingerprint_md5,
            comment: key_data.comment.clone(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            deployed: false,
            deploy_path: None,
            bitwarden_id: Some(cipher.id.clone()),
            bitwarden_sync: true,
            bitwarden_revision_ts: None,
            bitwarden_updated_at: None,
            category_ids: Vec::new(),
        };

        // Check for duplicate by fingerprint
        let existing = db.list_keys().unwrap_or_default();
        if !existing.iter().any(|k| k.fingerprint_sha256 == key_record.fingerprint_sha256) {
            if db.insert_key(&key_record).is_ok() {
                // Resolve SSHSpan category metadata from the cipher's `notes`.
                if let Some(notes_enc) = cipher.notes.as_ref() {
                    if let Ok(plain) = client.decrypt_field(notes_enc) {
                        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&plain) {
                            if let Some(arr) = v.get("sshspan").and_then(|s| s.get("categories")).and_then(|c| c.as_array()) {
                                let resolved: Vec<String> = arr.iter().filter_map(|item| {
                                    let id = item.get("id").and_then(|i| i.as_str()).map(String::from);
                                    let path = item.get("path").and_then(|p| p.as_str()).map(String::from);
                                    match (id, path) {
                                        (Some(id), _) if db.get_category(&id).ok().flatten().is_some() => Some(id),
                                        (_, Some(path)) => db.ensure_category_path(&path).ok().flatten(),
                                        _ => None,
                                    }
                                }).collect();
                                let _ = db.set_key_categories(&key_record.id, &resolved);
                            }
                        }
                    }
                }
                pulled += 1;
            } else {
                errors.push(serde_json::json!({"cipher_id": cipher.id, "error": "db insert failed"}));
            }
        }
    }

    // Count remote deletions
    for row in &local_keys {
        if let Some(ref bw_id) = row.bitwarden_id {
            if !remote_ssh.iter().any(|c| c.id == *bw_id) {
                remote_deleted += 1;
            }
        }
    }

    // Server sync (Bitwarden Login-type ciphers in SSHSpan_Servers)
    let remote_logins: Vec<_> = remote.ciphers.iter().filter(|c| {
        c.cipher_type == 1
            && c.deleted_date.is_none()
            && c.organization_id.is_none()
            && c.folder_id.as_ref() == servers_folder_id.as_ref()
    }).collect();

    let local_servers = db.list_servers()?;
    let mut server_matched = std::collections::HashSet::new();
    let (mut servers_pushed, mut servers_updated_remote) = (0usize, 0usize);
    let (mut servers_pulled, mut servers_updated_local) = (0usize, 0usize);

    for sv in &local_servers {
        let cipher = sv.bitwarden_id.as_ref().and_then(|bw_id| {
            remote_logins.iter().find(|c| c.id == *bw_id)
        });

        let cipher = match cipher {
            Some(c) => c,
            None => {
                match push_local_server(&mut client, sv, &servers_folder_id, db, vault_password).await {
                    Ok(()) => { servers_pushed += 1; }
                    Err(e) => { errors.push(serde_json::json!({"server": sv.name, "error": e.to_string()})); }
                }
                continue;
            }
        };

        server_matched.insert(cipher.id.clone());

        // Timestamps are stored as RFC 3339 strings for servers.
        let local_changed = sv.updated_at.to_rfc3339() > sv.bitwarden_updated_at.clone().unwrap_or_default();
        let remote_changed = cipher.revision_date.as_ref()
            .map_or(false, |rd| rd.as_str() > sv.bitwarden_revision_ts.clone().unwrap_or_default().as_str());

        if !local_changed && !remote_changed { continue; }

        if local_changed {
            if remote_changed { conflicts += 1; } // local wins
            match push_local_server(&mut client, sv, &servers_folder_id, db, vault_password).await {
                Ok(()) => { servers_updated_remote += 1; }
                Err(e) => { errors.push(serde_json::json!({"server": sv.name, "error": e.to_string()})); }
            }
        } else {
            match pull_remote_server(&mut client, cipher, sv, db, vault_password).await {
                Ok(()) => { servers_updated_local += 1; }
                Err(e) => { errors.push(serde_json::json!({"server": sv.name, "error": e.to_string()})); }
            }
        }
    }

    for cipher in &remote_logins {
        if server_matched.contains(&cipher.id) { continue; }
        match pull_new_server(&mut client, cipher, db, vault_password).await {
            Ok(()) => { servers_pulled += 1; }
            Err(e) => { errors.push(serde_json::json!({"cipher_id": cipher.id, "error": e.to_string()})); }
        }
    }

    client.close();

    Ok(serde_json::json!({
        "ok": true,
        "pushed": pushed,
        "updatedRemote": updated_remote,
        "pulled": pulled,
        "updatedLocal": updated_local,
        "linked": linked,
        "conflicts": conflicts,
        "remoteDeleted": remote_deleted,
        "serversPushed": servers_pushed,
        "serversUpdatedRemote": servers_updated_remote,
        "serversPulled": servers_pulled,
        "serversUpdatedLocal": servers_updated_local,
        "errors": errors,
    }))
}

/// Push a local key to the remote vault as a cipher type-5 SSH item.
async fn push_local_key(
    client: &mut BitwardenClient,
    row: &KeyRecord,
    folder_id: &Option<String>,
    db: &Database,
    vault_password: &str,
) -> Result<()> {
    // Decrypt the private key
    let private_bytes = crate::crypto::vault::unseal(vault_password, &row.private_key_encrypted)
        .or_else(|_| Ok::<Vec<u8>, anyhow::Error>(row.private_key_encrypted.as_bytes().to_vec()))?;

    // Export as OpenSSH
    let key_type = crate::crypto::keys::KeyType::from_db_tag(&row.key_type)?;
    let public_bytes = parse_openssh_public_line(&row.public_key)?;
    let key_data = crate::crypto::keys::PrivateKeyData::new(key_type, private_bytes, public_bytes, row.comment.clone());
    let ossh_private = crate::crypto::keys::export_private_key(&key_data, crate::crypto::keys::KeyFormat::OpenSsh, None)?;
    let ossh_public = crate::crypto::keys::export_public_key(&key_data, crate::crypto::keys::KeyFormat::OpenSsh)?;

    let name_enc = client.encrypt_field(&row.name)?;
    let priv_enc = client.encrypt_field(&ossh_private)?;
    let pub_enc = client.encrypt_field(&ossh_public)?;
    let fp_enc = client.encrypt_field(&row.fingerprint_sha256)?;

    // Build the SSHSpan metadata blob for the cipher's `notes` field.
    // Contains category IDs and their human-readable paths so a remote
    // vault can reconstruct the tree on import.
    let categories = db.list_categories_for_key(&row.id)?;
    let mut ss_categories: Vec<serde_json::Value> = Vec::new();
    for cid in &categories {
        if let Some(cat) = db.get_category(cid)? {
            ss_categories.push(serde_json::json!({
                "id": cat.id,
                "path": db.category_path_string(&cat.id),
            }));
        }
    }
    let notes_plain = if ss_categories.is_empty() {
        String::new()
    } else {
        serde_json::to_string(&serde_json::json!({
            "v": 1,
            "sshspan": { "categories": ss_categories }
        }))?
    };
    let notes_enc = if notes_plain.is_empty() { None } else { Some(client.encrypt_field(&notes_plain)?) };

    let cipher = serde_json::json!({
        "type": 5,
        "organizationId": null,
        "folderId": folder_id,
        "name": name_enc,
        "notes": notes_enc,
        "favorite": false,
        "reprompt": 0,
        "sshKey": {
            "privateKey": priv_enc,
            "publicKey": pub_enc,
            "keyFingerprint": fp_enc,
        },
    });

    if let Some(ref bw_id) = row.bitwarden_id {
        // Update existing
        client.update_cipher(bw_id, &cipher).await?;
    } else {
        // Create new
        let created = client.create_cipher(&cipher).await?;
        let new_id = created.get("id").and_then(|v| v.as_str()).unwrap_or("");
        let rev = created.get("revisionDate").and_then(|v| v.as_str()).map(String::from);
        db.update_key_sync_meta(&row.id, new_id, rev.as_deref())?;
    }
    Ok(())
}

/// Pull a remote cipher into a local row (overwrite with newer remote data).
async fn pull_remote_item(
    client: &mut BitwardenClient,
    cipher: &crate::bitwarden::SyncCipher,
    row: &KeyRecord,
    db: &Database,
    vault_password: &str,
) -> Result<()> {
    let ssh = cipher.ssh_key.as_ref().ok_or_else(|| anyhow::anyhow!("No sshKey block"))?;
    let priv_enc = ssh.private_key.as_ref().ok_or_else(|| anyhow::anyhow!("No privateKey"))?;
    let priv_pem = client.decrypt_field(priv_enc)?;
    let pub_enc = ssh.public_key.as_ref();
    let pub_key = pub_enc.map(|e| client.decrypt_field(e)).transpose().unwrap_or_default();
    let fp_enc = ssh.key_fingerprint.as_ref();
    let fp = fp_enc.map(|e| client.decrypt_field(e)).transpose().unwrap_or_default();

    let name = cipher.name.as_ref()
        .and_then(|n| client.decrypt_field(n).ok())
        .unwrap_or_else(|| row.name.clone());

    let key_data = if priv_pem.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----") {
        crate::crypto::keys::import_openssh_private(&priv_pem, None).ok()
    } else {
        None
    };

    if let Some(kd) = key_data {
        let public_openssh = crate::crypto::keys::export_public_key(&kd, crate::crypto::keys::KeyFormat::OpenSsh).unwrap_or_default();
        let fingerprint = crate::crypto::keys::compute_fingerprint_sha256(&kd.public_key);
        let sealed = crate::crypto::vault::seal(vault_password, &kd.private_key).unwrap_or_default();

        let mut updated = row.clone();
        updated.name = name;
        updated.key_type = kd.key_type.db_tag().to_string();
        updated.public_key = pub_key.unwrap_or(public_openssh);
        updated.private_key_encrypted = sealed;
        updated.fingerprint_sha256 = fp.unwrap_or(fingerprint);
        updated.comment = kd.comment.clone();
        updated.updated_at = chrono::Utc::now();
        updated.bitwarden_revision_ts = cipher.revision_date.as_ref()
            .and_then(|rd| chrono::DateTime::parse_from_rfc3339(rd).ok())
            .map(|rd| rd.timestamp_millis());
        updated.bitwarden_updated_at = Some(chrono::Utc::now().timestamp_millis());
        db.update_key(&updated)?;

        // Resolve SSHSpan category metadata from the cipher's `notes`.
        let resolved: Vec<String> = if let Some(notes_enc) = cipher.notes.as_ref() {
            match client.decrypt_field(notes_enc) {
                Ok(plain) => match serde_json::from_str::<serde_json::Value>(&plain) {
                    Ok(v) => v.get("sshspan")
                        .and_then(|s| s.get("categories"))
                        .and_then(|c| c.as_array())
                        .map(|arr| arr.iter().filter_map(|item| {
                            let id = item.get("id").and_then(|i| i.as_str()).map(String::from);
                            let path = item.get("path").and_then(|p| p.as_str()).map(String::from);
                            match (id, path) {
                                (Some(id), _) if db.get_category(&id).ok().flatten().is_some() => Some(id),
                                (_, Some(path)) => db.ensure_category_path(&path).ok().flatten(),
                                _ => None,
                            }
                        }).collect())
                        .unwrap_or_default(),
                    Err(_) => Vec::new(),
                },
                Err(_) => Vec::new(),
            }
        } else { Vec::new() };
        db.set_key_categories(&updated.id, &resolved)?;
    }
    Ok(())
}

/// Parse an authorized_keys line back into raw SSH wire-format public key bytes.
fn parse_openssh_public_line(line: &str) -> Result<Vec<u8>> {
    use base64ct::Encoding;
    let b64 = line.split_whitespace().nth(1).ok_or_else(|| anyhow::anyhow!("Malformed stored public key"))?;
    base64ct::Base64::decode_vec(b64).map_err(|e| anyhow::anyhow!("Malformed stored public key: {e}"))
}

// ─── Server sync helpers (Bitwarden Login-type ciphers) ────────────────────

/// Build the `notes` metadata blob for a server cipher: auth method, the
/// bound key's fingerprint (so the pull side can re-link by fingerprint),
/// and the category path.
fn server_notes(client: &BitwardenClient, db: &Database, sv: &crate::db::ServerRecord) -> Result<Option<String>> {
    let key_fp = match &sv.key_id {
        Some(kid) => db.get_key(kid)?.map(|k| k.fingerprint_sha256),
        None => None,
    };
    let category = match &sv.category_id {
        Some(cid) => db.get_category(cid)?.map(|cat| serde_json::json!({
            "id": cat.id,
            "path": db.category_path_string(&cat.id),
        })),
        None => None,
    };
    if key_fp.is_none() && category.is_none() {
        return Ok(None);
    }
    let plain = serde_json::to_string(&serde_json::json!({
        "v": 1,
        "sshspan": {
            "authMethod": sv.auth_method,
            "keyFingerprint": key_fp,
            "category": category,
        }
    }))?;
    Ok(Some(client.encrypt_field(&plain)?))
}

async fn push_local_server(
    client: &mut BitwardenClient,
    sv: &crate::db::ServerRecord,
    folder_id: &Option<String>,
    db: &Database,
    vault_password: &str,
) -> Result<()> {
    let name_enc = client.encrypt_field(&sv.name)?;
    let user_enc = client.encrypt_field(&sv.username)?;
    let password_enc = match &sv.saved_password {
        Some(sealed) => {
            let plain = crate::crypto::vault::unseal(vault_password, sealed)
                .map_err(|e| anyhow::anyhow!("saved password unseal failed: {e}"))?;
            let plain_str = String::from_utf8(plain).unwrap_or_default();
            if plain_str.is_empty() { None } else { Some(client.encrypt_field(&plain_str)?) }
        }
        None => None,
    };
    let uri_plain = format!("ssh://{}:{}", sv.host, sv.port);
    let uri_enc = client.encrypt_field(&uri_plain)?;
    let notes_enc = server_notes(client, db, sv)?;

    let cipher = serde_json::json!({
        "type": 1,
        "organizationId": null,
        "folderId": folder_id,
        "name": name_enc,
        "notes": notes_enc,
        "favorite": false,
        "reprompt": 0,
        "login": {
            "username": user_enc,
            "password": password_enc,
            "uris": [{ "uri": uri_enc }],
        },
    });

    if let Some(ref bw_id) = sv.bitwarden_id {
        client.update_cipher(bw_id, &cipher).await?;
    } else {
        let created = client.create_cipher(&cipher).await?;
        let new_id = created.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let rev = created.get("revisionDate").and_then(|v| v.as_str()).map(String::from);
        let mut updated = sv.clone();
        updated.bitwarden_id = Some(new_id);
        updated.bitwarden_revision_ts = rev;
        updated.bitwarden_updated_at = Some(chrono::Utc::now().to_rfc3339());
        db.update_server(&updated)?;
    }
    Ok(())
}

/// Extract host/port from the cipher's ssh:// URI (falls back to the name).
fn server_host_port(client: &BitwardenClient, cipher: &crate::bitwarden::SyncCipher) -> (String, u16) {
    if let Some(login) = &cipher.login {
        if let Some(uris) = &login.uris {
            if let Some(first) = uris.first() {
                if let Some(enc) = &first.uri {
                    if let Ok(uri) = client.decrypt_field(enc) {
                        let rest = uri.strip_prefix("ssh://").unwrap_or(&uri);
                        let (h, p) = match rest.rsplit_once(':') {
                            Some((h, p)) => (h.to_string(), p.parse::<u16>().unwrap_or(22)),
                            None => (rest.to_string(), 22),
                        };
                        if !h.is_empty() {
                            return (h, p);
                        }
                    }
                }
            }
        }
    }
    let name = cipher.name.as_ref()
        .and_then(|n| client.decrypt_field(n).ok())
        .unwrap_or_else(|| "imported server".to_string());
    (name, 22)
}

/// notes -> (auth_method, key_fingerprint, category_id)
fn parse_server_notes(client: &BitwardenClient, cipher: &crate::bitwarden::SyncCipher, db: &Database)
    -> (Option<String>, Option<String>, Option<String>) {
    let Some(notes_enc) = cipher.notes.as_ref() else { return (None, None, None) };
    let Ok(plain) = client.decrypt_field(notes_enc) else { return (None, None, None) };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&plain) else { return (None, None, None) };
    let Some(ss) = v.get("sshspan") else { return (None, None, None) };
    let auth = ss.get("authMethod").and_then(|a| a.as_str()).map(String::from);
    let fp = ss.get("keyFingerprint").and_then(|f| f.as_str()).map(String::from);
    let cat = ss.get("category").and_then(|c| c.as_object()).and_then(|c| {
        let id = c.get("id").and_then(|i| i.as_str()).map(String::from);
        let path = c.get("path").and_then(|p| p.as_str()).map(String::from);
        match (id, path) {
            (Some(id), _) if db.get_category(&id).ok().flatten().is_some() => Some(id),
            (_, Some(path)) => db.ensure_category_path(&path).ok().flatten(),
            _ => None,
        }
    });
    (auth, fp, cat)
}

async fn pull_remote_server(
    client: &mut BitwardenClient,
    cipher: &crate::bitwarden::SyncCipher,
    sv: &crate::db::ServerRecord,
    db: &Database,
    vault_password: &str,
) -> Result<()> {
    let (host, port) = server_host_port(client, cipher);
    let username = cipher.login.as_ref()
        .and_then(|l| l.username.as_ref())
        .and_then(|u| client.decrypt_field(u).ok())
        .unwrap_or_else(|| sv.username.clone());
    let password_plain = cipher.login.as_ref()
        .and_then(|l| l.password.as_ref())
        .map(|p| client.decrypt_field(p))
        .transpose().unwrap_or(None);
    let name = cipher.name.as_ref()
        .and_then(|n| client.decrypt_field(n).ok())
        .unwrap_or_else(|| sv.name.clone());
    let (auth_method, key_fp, category_id) = parse_server_notes(client, cipher, db);

    // Re-link the key by fingerprint if the local vault has a match.
    let key_id = key_fp.as_ref().and_then(|fp| {
        db.list_keys().ok()?.into_iter().find(|k| &k.fingerprint_sha256 == fp).map(|k| k.id)
    }).or_else(|| sv.key_id.clone());

    let mut updated = sv.clone();
    updated.name = name;
    updated.host = host;
    updated.port = port;
    updated.username = username;
    updated.auth_method = auth_method.unwrap_or_else(|| sv.auth_method.clone());
    updated.key_id = key_id;
    updated.category_id = category_id.or_else(|| sv.category_id.clone());
    updated.saved_password = match password_plain {
        Some(p) if !p.is_empty() => crate::crypto::vault::seal(vault_password, p.as_bytes()).ok(),
        _ => None,
    };
    updated.updated_at = chrono::Utc::now();
    updated.bitwarden_revision_ts = cipher.revision_date.clone();
    updated.bitwarden_updated_at = Some(chrono::Utc::now().to_rfc3339());
    db.update_server(&updated)?;
    Ok(())
}

async fn pull_new_server(
    client: &mut BitwardenClient,
    cipher: &crate::bitwarden::SyncCipher,
    db: &Database,
    vault_password: &str,
) -> Result<()> {
    let (host, port) = server_host_port(client, cipher);
    let username = cipher.login.as_ref()
        .and_then(|l| l.username.as_ref())
        .and_then(|u| client.decrypt_field(u).ok())
        .unwrap_or_else(|| "root".to_string());
    let password_plain = cipher.login.as_ref()
        .and_then(|l| l.password.as_ref())
        .map(|p| client.decrypt_field(p))
        .transpose().unwrap_or(None);
    let name = cipher.name.as_ref()
        .and_then(|n| client.decrypt_field(n).ok())
        .unwrap_or_else(|| host.clone());
    let (auth_method, key_fp, category_id) = parse_server_notes(client, cipher, db);

    let key_id = key_fp.as_ref().and_then(|fp| {
        db.list_keys().ok()?.into_iter().find(|k| &k.fingerprint_sha256 == fp).map(|k| k.id)
    });

    let record = crate::db::ServerRecord {
        id: uuid::Uuid::new_v4().to_string(),
        name,
        host,
        port,
        username,
        key_id,
        pem_path: None,
        auth_method: auth_method.unwrap_or_else(|| "publickey".to_string()),
        saved_password: match password_plain {
            Some(p) if !p.is_empty() => crate::crypto::vault::seal(vault_password, p.as_bytes()).ok(),
            _ => None,
        },
        category_id,
        color: None,
        last_connected_at: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        bitwarden_id: Some(cipher.id.clone()),
        bitwarden_revision_ts: cipher.revision_date.clone(),
        bitwarden_updated_at: Some(chrono::Utc::now().to_rfc3339()),
    };
    db.insert_server(&record)?;
    Ok(())
}
