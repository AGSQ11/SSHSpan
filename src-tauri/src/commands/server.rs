//! IPC commands for saved SSH servers (the "Connect" feature).

use tauri::{AppHandle, Manager};
use uuid::Uuid;

use crate::db::{self, ServerRecord};
use crate::AppState;
use super::{CmdResult, CmdError};

/// Build the JSON a server row is returned as, resolving the referenced vault
/// key's name/type so the renderer needs no second round trip.
fn server_to_json(db: &db::Database, s: &ServerRecord) -> serde_json::Value {
    let (key_name, key_type, key_missing) = match &s.key_id {
        Some(kid) => match db.get_key_name(kid) {
            Ok(Some((name, kt))) => (Some(name), Some(kt), false),
            _ => (None, None, true),
        },
        None => (None, None, false),
    };
    serde_json::json!({
        "id": s.id,
        "name": s.name,
        "host": s.host,
        "port": s.port,
        "username": s.username,
        "authMethod": s.auth_method,
        "keyId": s.key_id,
        "keyName": key_name,
        "keyType": key_type,
        "keyMissing": key_missing,
        "pemPath": s.pem_path,
        "hasSavedPassword": s.saved_password.is_some(),
        "categoryId": s.category_id,
        "color": s.color,
        "lastConnectedAt": s.last_connected_at.map(|d| d.to_rfc3339()),
        "createdAt": s.created_at.to_rfc3339(),
        "updatedAt": s.updated_at.to_rfc3339(),
    })
}

#[tauri::command]
pub fn server_list(app: AppHandle) -> CmdResult<serde_json::Value> {
    let db = &app.state::<AppState>().db;
    let servers = db.list_servers().map_err(|e| e.to_string())?;
    let arr: Vec<serde_json::Value> = servers.iter().map(|s| server_to_json(db, s)).collect();
    Ok(serde_json::json!({ "servers": arr }))
}

#[tauri::command]
pub fn server_save(
    app: AppHandle,
    id: Option<String>,
    name: String,
    host: String,
    port: Option<u16>,
    username: String,
    auth_method: Option<String>,
    key_id: Option<String>,
    pem_path: Option<String>,
    saved_password: Option<String>,
    category_id: Option<String>,
    color: Option<String>,
) -> CmdResult<serde_json::Value> {
    let vault_pw = super::vault_password(&app)?;
    if vault_pw.is_empty() {
        return Err(CmdError("Vault is locked.".into()));
    }
    if name.trim().is_empty() {
        return Err(CmdError("Server name is required.".into()));
    }
    if host.trim().is_empty() {
        return Err(CmdError("Host is required.".into()));
    }
    if username.trim().is_empty() {
        return Err(CmdError("Username is required.".into()));
    }

    let method = auth_method.unwrap_or_else(|| "publickey".to_string());
    if method != "publickey" && method != "password" && method != "keyboard-interactive" {
        return Err(CmdError(format!("Unknown auth method: {method}")).into());
    }
    // publickey requires a key or pem path; password/kbd-interactive require a saved password
    // (the user may choose to leave it blank and type it at connect time, so only enforce
    // the key side).
    if method == "publickey" && key_id.is_none() && pem_path.as_deref().map(str::trim).unwrap_or("").is_empty() {
        return Err(CmdError("Choose a key for publickey auth (or pick a .pem file).".into()));
    }

    let db = &app.state::<AppState>().db;
    let now = chrono::Utc::now();

    // Seal the saved password with the vault password if provided.
    let saved_sealed: Option<String> = match saved_password {
        Some(p) if !p.is_empty() => Some(crate::crypto::vault::seal(&vault_pw, p.as_bytes())
            .map_err(|e| CmdError(e.to_string()))?),
        _ => None,
    };

    let trimmed_name = name.trim().to_string();
    let trimmed_host = host.trim().to_string();
    let trimmed_user = username.trim().to_string();
    let pem_clean = pem_path.map(|p| p.trim().to_string()).filter(|p| !p.is_empty());
    let key_clean = key_id.map(|k| k.trim().to_string()).filter(|k| !k.is_empty());

    let server = match &id {
        Some(existing_id) => {
            let mut existing = db.get_server(existing_id)
                .map_err(|e| e.to_string())?
                .ok_or_else(|| CmdError("Server not found.".into()))?;
            existing.name = trimmed_name;
            existing.host = trimmed_host;
            existing.port = port.unwrap_or(22);
            existing.username = trimmed_user;
            existing.auth_method = method;
            existing.key_id = key_clean;
            existing.pem_path = pem_clean;
            existing.saved_password = saved_sealed;
            existing.category_id = category_id.map(|c| c.trim().to_string()).filter(|c| !c.is_empty());
            existing.color = color;
            existing.updated_at = now;
            db.update_server(&existing).map_err(|e| e.to_string())?;
            existing
        }
        None => {
            let rec = ServerRecord {
                id: Uuid::new_v4().to_string(),
                name: trimmed_name,
                host: trimmed_host,
                port: port.unwrap_or(22),
                username: trimmed_user,
                auth_method: method,
                key_id: key_clean,
                pem_path: pem_clean,
                saved_password: saved_sealed,
                category_id: category_id.map(|c| c.trim().to_string()).filter(|c| !c.is_empty()),
                color,
                last_connected_at: None,
                created_at: now,
                updated_at: now,
            };
            db.insert_server(&rec).map_err(|e| e.to_string())?;
            rec
        }
    };

    let _ = db.add_audit("server.save", None, &format!("{} @ {}:{}", server.name, server.host, server.port));

    Ok(serde_json::json!({ "ok": true, "id": server.id }))
}

#[tauri::command]
pub fn server_delete(app: AppHandle, id: String) -> CmdResult<serde_json::Value> {
    let vault_pw = super::vault_password(&app)?;
    if vault_pw.is_empty() {
        return Err(CmdError("Vault is locked.".into()));
    }
    let db = &app.state::<AppState>().db;
    let server = db.get_server(&id).map_err(|e| e.to_string())?;
    let name = server.as_ref().map(|s| s.name.clone()).unwrap_or_default();
    db.delete_server(&id).map_err(|e| e.to_string())?;
    let _ = db.add_audit("server.delete", None, &name);
    Ok(serde_json::json!({ "ok": true }))
}
