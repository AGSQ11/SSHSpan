//! IPC commands for the Connect feature: streaming SSH sessions and helpers.
//!
//! `terminal_connect` resolves a saved server (or an ad-hoc descriptor) into a
//! `ResolvedConnection`, hands it to the russh glue, and returns immediately;
//! terminal bytes stream back through `on_data: tauri::ipc::Channel<String>`.
//! `terminal_send`/`terminal_resize`/`terminal_disconnect` address an in-memory
//! `SessionRegistry`; `vault_lock` clears every active session.

use std::sync::Arc;
use tauri::ipc::Channel;
use tauri::{AppHandle, Manager};

use crate::db::{self, Database};
use crate::ssh_client::{self, ResolvedConnection, SessionRegistry};
use crate::AppState;

use super::{CmdResult, CmdError};

// ─── Resolution helpers ─────────────────────────────────────────────────────

/// Decrypt the vault-stored key into the PEM bytes russh wants to load.
fn key_pem_for_id(db: &Database, vault_pw: &str, key_id: &str) -> Result<String, String> {
    let key = db.get_key(key_id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("Key not found: {key_id}"))?;
    let bytes = crate::crypto::vault::unseal(vault_pw, &key.private_key_encrypted)
        .map_err(|_| "Failed to decrypt key — vault password may have changed.".to_string())?;
    String::from_utf8(bytes).map_err(|_| "Key bytes are not valid UTF-8 PEM.".to_string())
}

/// Decrypt a server's saved password (sealed with the same vault master) if one is stored.
fn saved_pw_for_server(_db: &Database, vault_pw: &str, server: &db::ServerRecord) -> Result<Option<String>, String> {
    match &server.saved_password {
        Some(sealed) => {
            let bytes = crate::crypto::vault::unseal(vault_pw, sealed)
                .map_err(|_| "Failed to decrypt saved password.".to_string())?;
            Ok(Some(String::from_utf8(bytes).map_err(|_| "Saved password is not valid UTF-8.".to_string())?))
        }
        None => Ok(None),
    }
}

/// Build a `ResolvedConnection` for a saved server id.
///
/// `override_username` / `override_key_id` come from the renderer's "Use this
/// key to connect…" right-click flow — when the user picks a key right on a key
/// row, we want to keep the server's saved username but swap the key.
fn resolve_for_server(
    db: &Database,
    vault_pw: &str,
    server_id: &str,
    override_username: Option<String>,
    override_key_id: Option<String>,
    override_pem_path: Option<String>,
    prompt_password: Option<String>,
) -> Result<ResolvedConnection, String> {
    let server = db.get_server(server_id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("Server not found: {server_id}"))?;

    let username = override_username.unwrap_or_else(|| server.username.clone());
    let auth_method = server.auth_method.clone();

    let mut key_pem: Option<String> = None;
    let mut password: Option<String> = None;

    // publickey: prefer the override key (from key context menu), then the server's key_id, then its pem_path.
    if auth_method == "publickey" {
        if let Some(kid) = override_key_id.or_else(|| server.key_id.clone()) {
            key_pem = Some(key_pem_for_id(db, vault_pw, &kid)?);
        } else if let Some(p) = override_pem_path.or_else(|| server.pem_path.clone()) {
            // Read PEM from disk — leaves the file untouched, treats it as a public key on the SSH server side.
            key_pem = Some(std::fs::read_to_string(&p).map_err(|e| format!("Failed to read {p}: {e}"))?);
        }
    } else if auth_method == "password" || auth_method == "keyboard-interactive" {
        // Prefer the runtime prompt (always), then the saved password.
        password = prompt_password
            .filter(|p| !p.is_empty())
            .or(saved_pw_for_server(db, vault_pw, &server)?.filter(|p| !p.is_empty()));
    }

    Ok(ResolvedConnection {
        server,
        username,
        auth_method,
        key_pem,
        password,
    })
}

// ─── Commands ────────────────────────────────────────────────────────────────

/// Convert an `anyhow::Error` into a `CmdError` (which is `From<String>`).
/// Used at every `.map_err()` site that needs the result of an `anyhow::Result`.
fn anyhow_cmd(e: anyhow::Error) -> CmdError { CmdError(e.to_string()) }

#[tauri::command]
pub async fn terminal_connect(
    app: AppHandle,
    server_id: String,
    cols: u32,
    rows: u32,
    on_data: Channel<String>,
    override_username: Option<String>,
    override_key_id: Option<String>,
    override_pem_path: Option<String>,
    prompt_password: Option<String>,
) -> CmdResult<serde_json::Value> {
    let vault_pw = super::vault_password(&app)?;
    if vault_pw.is_empty() {
        return Err(CmdError("Vault is locked.".into()));
    }
    let db = app.state::<AppState>().db.clone();
    let registry = app.state::<Arc<SessionRegistry>>().inner().clone();

    let resolved = resolve_for_server(
        &db, &vault_pw, &server_id,
        override_username, override_key_id, override_pem_path, prompt_password,
    ).map_err(CmdError)?;

    // Emit a friendly banner the moment we know the host key is wrong, instead
    // of letting russh surface the failure as a bare error string. We can't
    // detect the mismatch here (we don't have the presented key yet) but we
    // can give the user a clear next-step hint after the fact by attaching a
    // small `mismatch_hint` flag the renderer can use to render a help line.
    let _ = on_data.send(format!(
        "\r\n\x1b[1;36mConnecting to {}:{} as {} (auth={})\x1b[0m\r\n",
        resolved.server.host, resolved.server.port, resolved.username, resolved.auth_method
    ));

    // Spawn the connection — returns the new session id.
    let session_id = ssh_client::start_interactive(
        resolved.clone(),
        db.clone(),
        registry.clone(),
        on_data,
    ).await.map_err(|e| {
        // Translate the most common russh errors into something readable.
        let msg = e.to_string();
        let friendly = if msg.contains("Key exchange failed") || msg.contains("key exchange") {
            "The host rejected the connection during key exchange. If this host's fingerprint changed, forget it in the known_hosts list and retry.".to_string()
        } else if msg.to_lowercase().contains("host key") {
            "Host key mismatch. The server presented a different key than the one stored for this host — possible MITM, or the host was rebuilt. Forget it in known_hosts and retry.".to_string()
        } else {
            msg
        };
        anyhow_cmd(anyhow::anyhow!(friendly))
    })?;

    // Push initial PTY size to the remote so the shell matches the renderer.
    if cols > 0 && rows > 0 {
        let _ = ssh_client::session_resize(&registry, &session_id, cols, rows);
    }

    let _ = db.add_audit(
        "connect.start",
        None,
        &format!("{} @ {}:{} as {}", resolved.server.name, resolved.server.host, resolved.server.port, resolved.username),
    );

    Ok(serde_json::json!({
        "ok": true,
        "sessionId": session_id,
        "server": {
            "id": resolved.server.id,
            "name": resolved.server.name,
            "host": resolved.server.host,
            "port": resolved.server.port,
            "username": resolved.username,
        },
    }))
}

#[tauri::command]
pub fn terminal_send(
    app: AppHandle,
    session_id: String,
    bytes: Vec<u8>,
) -> CmdResult<serde_json::Value> {
    let registry = app.state::<Arc<SessionRegistry>>().inner().clone();
    ssh_client::session_send(&registry, &session_id, bytes).map_err(anyhow_cmd)?;
    Ok(serde_json::json!({ "ok": true }))
}

#[tauri::command]
pub fn terminal_resize(
    app: AppHandle,
    session_id: String,
    cols: u32,
    rows: u32,
) -> CmdResult<serde_json::Value> {
    let registry = app.state::<Arc<SessionRegistry>>().inner().clone();
    ssh_client::session_resize(&registry, &session_id, cols, rows).map_err(anyhow_cmd)?;
    Ok(serde_json::json!({ "ok": true }))
}

#[tauri::command]
pub fn terminal_disconnect(
    app: AppHandle,
    session_id: String,
) -> CmdResult<serde_json::Value> {
    let registry = app.state::<Arc<SessionRegistry>>().inner().clone();
    let server_name = registry.list().into_iter()
        .find(|(id, _, _, _, _)| id == &session_id)
        .map(|(_, name, _, _, _)| name)
        .unwrap_or_default();
    ssh_client::session_disconnect(&registry, &session_id);
    let _ = app.state::<AppState>().db.add_audit("connect.stop", None, &server_name);
    Ok(serde_json::json!({ "ok": true }))
}

#[tauri::command]
pub fn terminal_list(app: AppHandle) -> CmdResult<serde_json::Value> {
    let registry = app.state::<Arc<SessionRegistry>>().inner().clone();
    let active: Vec<serde_json::Value> = registry.list().into_iter().map(|(id, name, host, port, since)| {
        serde_json::json!({
            "sessionId": id, "serverName": name,
            "host": host, "port": port, "sinceMs": since,
        })
    }).collect();
    Ok(serde_json::json!({ "active": active }))
}

/// Quick connectivity check: open + authenticate + immediately close.
/// Reports latency and any error verbatim so the renderer can surface it.
#[tauri::command]
pub async fn server_test(
    app: AppHandle,
    server_id: String,
    prompt_password: Option<String>,
) -> CmdResult<serde_json::Value> {
    let vault_pw = super::vault_password(&app)?;
    if vault_pw.is_empty() { return Err(CmdError("Vault is locked.".into())); }
    let db = app.state::<AppState>().db.clone();

    let resolved = resolve_for_server(
        &db, &vault_pw, &server_id, None, None, None, prompt_password,
    ).map_err(CmdError)?;

    let started = std::time::Instant::now();
    // Open + authenticate using the same russh glue as start_interactive,
    // then drop the channel immediately. We don't want this to land in the
    // SessionRegistry or persist.
    let db_for_handler = db.clone();
    let host_for_handler = resolved.server.host.clone();
    let result: anyhow::Result<()> = async {
        let config = Arc::new(ssh_client::base_client_config_pub());
        let handler = ssh_client::TerminalHandler {
            host: host_for_handler,
            db: db_for_handler,
        };
        let mut session = russh::client::connect(
            config,
            (resolved.server.host.as_str(), resolved.server.port),
            handler,
        ).await.map_err(|e| anyhow::anyhow!("Connect failed: {e}"))?;

        // Mirror the auth path used by start_interactive so the user gets the
        // same verdict here that they would get on a real connect.
        ssh_client::authenticate(&mut session, &ssh_client::ConnectParams {
            server: resolved.server.clone(),
            username: resolved.username.clone(),
            auth_method: resolved.auth_method.clone(),
            key_pem: resolved.key_pem.clone(),
            password: resolved.password.clone(),
        }).await?;
        Ok(())
    }.await;

    let elapsed = started.elapsed().as_millis() as u64;
    match result {
        Ok(()) => {
            let _ = db.add_audit(
                "server.test_ok", None,
                &format!("{} ({} ms)", resolved.server.name, elapsed),
            );
            Ok(serde_json::json!({ "ok": true, "latencyMs": elapsed }))
        }
        Err(e) => {
            let raw = e.to_string();
            let friendly = if raw.to_lowercase().contains("host key") {
                "Host key mismatch. Forget it in known_hosts and retry.".to_string()
            } else if raw.contains("Key exchange") || raw.contains("key exchange") {
                "Key exchange failed.".to_string()
            } else if raw.starts_with("Connect failed: ") {
                // Strip our own wrapper prefix for a cleaner surface.
                raw.trim_start_matches("Connect failed: ").to_string()
            } else {
                raw.clone()
            };
            let _ = db.add_audit("server.test_fail", None, &raw);
            Ok(serde_json::json!({ "ok": false, "error": friendly, "latencyMs": elapsed }))
        }
    }
}

#[tauri::command]
pub fn known_hosts_list(app: AppHandle) -> CmdResult<serde_json::Value> {
    let rows = app.state::<AppState>().db.list_known_hosts().map_err(|e| e.to_string())?;
    let arr: Vec<serde_json::Value> = rows.iter().map(|r| {
        serde_json::json!({
            "host": r.host,
            "fingerprintSha256": r.fingerprint_sha256,
            "firstSeen": r.first_seen.to_rfc3339(),
        })
    }).collect();
    Ok(serde_json::json!({ "hosts": arr }))
}

#[tauri::command]
pub fn known_hosts_forget(app: AppHandle, host: String) -> CmdResult<serde_json::Value> {
    app.state::<AppState>().db.delete_known_host(&host).map_err(|e| e.to_string())?;
    let _ = app.state::<AppState>().db.add_audit("known_hosts.forget", None, &host);
    Ok(serde_json::json!({ "ok": true }))
}