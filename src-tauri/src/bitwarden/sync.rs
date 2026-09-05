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
pub async fn run_sync(
    server_url: &str,
    email: &str,
    master_password: &str,
    device_id: &str,
    folder_name: &str,
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
