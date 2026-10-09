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

use super::{CmdError, CmdResult};

// ─── Resolution helpers ─────────────────────────────────────────────────────

/// Decrypt the vault-stored key into OpenSSH PRIVATE KEY text for russh.
/// The vault stores the private half as a raw binary OpenSSH blob (not PEM),
/// so route it through the same load+export path used by key_export/deploy.
fn key_pem_for_id(
    app: &AppHandle,
    db: &Database,
    vault_pw: &str,
    key_id: &str,
) -> Result<zeroize::Zeroizing<String>, String> {
    let key = db
        .get_key(key_id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("Key not found: {key_id}"))?;
    let key_data = super::load_private_key_data(app, &key, vault_pw)
        .map_err(|e| format!("Could not load vault key \"{}\": {e}", key.name))?;
    let pem = crate::crypto::keys::export_private_key(
        &key_data,
        crate::crypto::keys::KeyFormat::OpenSsh,
        None,
    )
    .map_err(|e| format!("Could not serialize key \"{}\" for SSH: {e}", key.name))?;
    Ok(zeroize::Zeroizing::new(pem))
}

/// Decrypt a server's saved password (sealed with the same vault master) if one is stored.
fn saved_pw_for_server(
    _db: &Database,
    vault_pw: &str,
    server: &db::ServerRecord,
) -> Result<Option<zeroize::Zeroizing<String>>, String> {
    match &server.saved_password {
        Some(sealed) => {
            let bytes = crate::crypto::vault::unseal(vault_pw, sealed)
                .map_err(|_| "Failed to decrypt saved password.".to_string())?;
            let pw = String::from_utf8(bytes)
                .map_err(|_| "Saved password is not valid UTF-8.".to_string())?;
            Ok(Some(zeroize::Zeroizing::new(pw)))
        }
        None => Ok(None),
    }
}

/// Build a `ResolvedConnection` for a saved server id.
///
/// `override_username` / `override_key_id` come from the renderer's "Use this
/// key to connect..." right-click flow - when the user picks a key right on a key
/// row, we want to keep the server's saved username but swap the key.
///
/// The `key_pem` and `password` fields are wrapped in `zeroize::Zeroizing`
/// so secret material is wiped from memory once the connect/auth path is
/// done with it.
fn resolve_for_server(
    app: &AppHandle,
    db: &Database,
    vault_pw: &str,
    server_id: &str,
    override_username: Option<String>,
    override_key_id: Option<String>,
    prompt_password: Option<String>,
) -> Result<ResolvedConnection, String> {
    let server = db
        .get_server(server_id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("Server not found: {server_id}"))?;

    let username = override_username.unwrap_or_else(|| server.username.clone());
    let auth_method = server.auth_method.clone();

    let mut key_pem: Option<zeroize::Zeroizing<String>> = None;
    let mut password: Option<zeroize::Zeroizing<String>> = None;

    // publickey: prefer the override key (from key context menu), then the server's key_id, then its pem_path.
    if auth_method == "publickey" {
        if let Some(kid) = override_key_id.or_else(|| server.key_id.clone()) {
            key_pem = Some(key_pem_for_id(app, db, vault_pw, &kid)?);
        } else if let Some(p) = server.pem_path.clone() {
            // Read PEM from disk - leaves the file untouched, treats it as a public key on the SSH server side.
            // This is a stored setting set by the user via the UI; validate it exists and is a regular file.
            let path = std::path::Path::new(&p);
            if !path.is_file() {
                return Err(format!("PEM path does not exist or is not a file: {p}"));
            }
            let _ = db.add_audit("connect.pem_path_used", None, &p);
            key_pem = Some(zeroize::Zeroizing::new(
                std::fs::read_to_string(&p).map_err(|e| format!("Failed to read {p}: {e}"))?,
            ));
        }
    } else if auth_method == "password" || auth_method == "keyboard-interactive" {
        // Prefer the runtime prompt (always), then the saved password.
        password = prompt_password
            .filter(|p| !p.is_empty())
            .map(zeroize::Zeroizing::new)
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
fn anyhow_cmd(e: anyhow::Error) -> CmdError {
    CmdError(e.to_string())
}

#[tauri::command(rename_all = "camelCase")]
pub async fn terminal_connect(
    app: AppHandle,
    server_id: String,
    cols: u32,
    rows: u32,
    // Rust param name uses snake_case to satisfy clippy; the JS side sends the
    // camelCase variant `onData` per Tauri v2's default argument-case rule.
    on_data: Channel<String>,
    override_username: Option<String>,
    override_key_id: Option<String>,
    prompt_password: Option<String>,
) -> CmdResult<serde_json::Value> {
    let vault_pw = super::vault_password(&app)?;
    if vault_pw.is_empty() {
        return Err(CmdError("Vault is locked.".into()));
    }
    // Capture the vault generation BEFORE any network await. If the vault is
    // locked while the handshake is in flight, `start_interactive` re-checks
    // this generation at the point it would register the session and aborts,
    // so a pending connect cannot complete into the locked state.
    let generation = super::capture_vault_generation(&app)?;
    let db = app.state::<AppState>().db.clone();
    let registry = app.state::<Arc<SessionRegistry>>().inner().clone();

    let resolved = resolve_for_server(
        &app,
        &db,
        &vault_pw,
        &server_id,
        override_username,
        override_key_id,
        prompt_password,
    )
    .map_err(CmdError)?;

    // Welcome banner so the user sees something even before the first
    // shell prompt arrives. If the channel to the webview is broken, FAIL
    // LOUDLY - a silent failure here looks exactly like a connected-but-blank
    // terminal, which cost us a debugging cycle already. Host/username/auth
    // are server-derived strings: control characters are stripped so this
    // app-composed line can never carry an injected escape sequence.
    on_data
        .send(format!(
            "\r\n\x1b[1;36mConnecting to {}:{} as {} (auth={})\x1b[0m\r\n",
            ssh_client::sanitize_terminal_text(&resolved.server.host),
            resolved.server.port,
            ssh_client::sanitize_terminal_text(&resolved.username),
            ssh_client::sanitize_terminal_text(&resolved.auth_method)
        ))
        .map_err(|e| {
            CmdError(format!(
                "Terminal channel to webview is not delivering data: {e}"
            ))
        })?;

    // Host-key consent is backend-owned: when the host is unpinned (or a
    // backup-imported pin is unconfirmed), the russh handler raises a native
    // dialog with the fingerprint. The renderer has no consent flag to forge.
    // A refused key, a declined dialog and a timeout already come back as
    // the message to show (A7-14, A7-15): nothing is guessed from russh's
    // error text here.
    let session_id = ssh_client::start_interactive(
        app.clone(),
        resolved.clone(),
        db.clone(),
        registry.clone(),
        on_data,
        Some(generation),
    )
    .await
    .map_err(anyhow_cmd)?;

    // Push initial PTY size to the remote so the shell matches the renderer.
    if cols > 0 && rows > 0 {
        let _ = ssh_client::session_resize(&registry, &session_id, cols, rows);
    }

    let _ = db.add_audit(
        "connect.start",
        None,
        &format!(
            "{} @ {}:{} as {}",
            resolved.server.name, resolved.server.host, resolved.server.port, resolved.username
        ),
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
    // Sending input to a live session consumes the authenticated channel;
    // refuse while the vault is locked so a stale renderer cannot drive a
    // session the lock was supposed to end.
    if super::vault_password(&app)?.is_empty() {
        return Err(CmdError("Vault is locked.".into()));
    }
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
pub fn terminal_disconnect(app: AppHandle, session_id: String) -> CmdResult<serde_json::Value> {
    let registry = app.state::<Arc<SessionRegistry>>().inner().clone();
    let server_name = registry
        .list()
        .into_iter()
        .find(|(id, _, _, _, _)| id == &session_id)
        .map(|(_, name, _, _, _)| name)
        .unwrap_or_default();
    ssh_client::session_disconnect(&registry, &session_id);
    app.state::<crate::sftp::EditRegistry>()
        .stop_all_for_session(&session_id);
    app.state::<crate::sftp::KeepaliveRegistry>()
        .stop(&session_id);
    app.state::<crate::sftp::SftpRegistry>().remove(&session_id);
    let _ = app
        .state::<AppState>()
        .db
        .add_audit("connect.stop", None, &server_name);
    Ok(serde_json::json!({ "ok": true }))
}

#[tauri::command]
pub fn terminal_list(app: AppHandle) -> CmdResult<serde_json::Value> {
    let registry = app.state::<Arc<SessionRegistry>>().inner().clone();
    let active: Vec<serde_json::Value> = registry
        .list()
        .into_iter()
        .map(|(id, name, host, port, since)| {
            serde_json::json!({
                "sessionId": id, "serverName": name,
                "host": host, "port": port, "sinceMs": since,
            })
        })
        .collect();
    Ok(serde_json::json!({ "active": active }))
}

/// Quick connectivity check: open + authenticate + immediately close.
/// Reports latency and any error verbatim so the renderer can surface it.
#[tauri::command(rename_all = "camelCase")]
pub async fn server_test(
    app: AppHandle,
    server_id: String,
    prompt_password: Option<String>,
) -> CmdResult<serde_json::Value> {
    let vault_pw = super::vault_password(&app)?;
    if vault_pw.is_empty() {
        return Err(CmdError("Vault is locked.".into()));
    }
    let db = app.state::<AppState>().db.clone();

    let resolved = resolve_for_server(
        &app,
        &db,
        &vault_pw,
        &server_id,
        None,
        None,
        prompt_password,
    )
    .map_err(CmdError)?;

    let started = std::time::Instant::now();
    // Open + authenticate exactly as a real connect does (same host-key
    // trust, deadlines and messages), then drop the connection: it never
    // lands in the SessionRegistry.
    let result = ssh_client::open_authenticated(
        &ssh_client::ConnectParams {
            server: resolved.server.clone(),
            username: resolved.username.clone(),
            auth_method: resolved.auth_method.clone(),
            key_pem: resolved.key_pem.clone(),
            password: resolved.password.clone(),
        },
        &db,
        ssh_client::native_host_trust_prompt(&app),
        ssh_client::Deadlines::INTERACTIVE,
    )
    .await
    .map(drop);

    let elapsed = started.elapsed().as_millis() as u64;
    match result {
        Ok(()) => {
            let _ = db.add_audit(
                "server.test_ok",
                None,
                &format!("{} ({} ms)", resolved.server.name, elapsed),
            );
            Ok(serde_json::json!({ "ok": true, "latencyMs": elapsed }))
        }
        Err(error) => {
            let _ = db.add_audit("server.test_fail", None, &error);
            Ok(serde_json::json!({ "ok": false, "error": error, "latencyMs": elapsed }))
        }
    }
}

#[tauri::command]
pub fn known_hosts_list(app: AppHandle) -> CmdResult<serde_json::Value> {
    let rows = app
        .state::<AppState>()
        .db
        .list_known_hosts()
        .map_err(|e| e.to_string())?;
    let arr: Vec<serde_json::Value> = rows.iter().map(known_host_json).collect();
    Ok(serde_json::json!({ "hosts": arr }))
}

/// One Known hosts row for the renderer. `fingerprintSha256` is
/// `SHA256:<unpadded base64>`, what `ssh-keygen -lf` prints (A7-46).
fn known_host_json(r: &db::KnownHost) -> serde_json::Value {
    serde_json::json!({
        "host": r.host,
        "fingerprintSha256": ssh_client::known_host_fingerprint(&r.host_key, &r.fingerprint_sha256),
        "firstSeen": r.first_seen.to_rfc3339(),
    })
}

/// NOT REGISTERED in `generate_handler!`, deliberately (A8-16): nothing in
/// the renderer calls it, and an unused command is IPC surface only a
/// compromised renderer could reach. Keepalives are sent at the SSH protocol
/// level (russh's `keepalive@openssh.com` every 30 s,
/// `base_client_config().keepalive_interval`). This command used to write a
/// NUL byte into the PTY data stream, which interactive programs received as
/// Ctrl-@ - it must never do that again. There is no keepalive setting: the
/// old `terminalKeepaliveSeconds` key is no longer accepted by `settings_set`.
#[tauri::command]
pub fn terminal_keepalive(app: AppHandle, session_id: String) -> CmdResult<serde_json::Value> {
    // Verify the session still exists so the call stays honest.
    let registry = app.state::<Arc<SessionRegistry>>().inner().clone();
    if registry.get_input_tx(&session_id).is_none() {
        return Err(CmdError("Session not found.".into()));
    }
    Ok(serde_json::json!({ "ok": true }))
}

#[tauri::command]
pub fn known_hosts_forget(app: AppHandle, host: String) -> CmdResult<serde_json::Value> {
    known_hosts_forget_in(
        &app.state::<AppState>().db,
        &app.state::<super::VaultPasswordStore>(),
        &host,
    )
}

/// [`known_hosts_forget`] without the `AppHandle`, so its lock gate is
/// testable. Refused while locked (A6-08): forgetting a pin downgrades the
/// next connection to that host to a first-use trust prompt.
pub(super) fn known_hosts_forget_in(
    db: &Database,
    vault: &super::VaultPasswordStore,
    host: &str,
) -> CmdResult<serde_json::Value> {
    super::require_unlocked(vault)?;
    db.delete_known_host(host).map_err(|e| e.to_string())?;
    let _ = db.add_audit("known_hosts.forget", None, host);
    Ok(serde_json::json!({ "ok": true }))
}

#[cfg(test)]
mod ru4_tests {
    use super::*;

    #[test]
    fn ru4_known_hosts_renderer_json_is_labelled_and_unpadded_even_for_legacy_rows() {
        use base64ct::Encoding;
        let blob = b"fixture public key blob";
        let host_key = base64ct::Base64::encode_string(blob);
        let want = crate::crypto::utils::ssh_fingerprint_sha256(blob);
        let old = format!("{}=", &want["SHA256:".len()..]);
        let row = db::KnownHost {
            host: "fixture.example:2222".into(),
            host_key,
            fingerprint_sha256: old,
            first_seen: chrono::Utc::now(),
            source: "connection".into(),
        };
        let out = known_host_json(&row);
        assert_eq!(out["host"], "fixture.example:2222");
        assert_eq!(out["fingerprintSha256"], want);
        assert_eq!(out["firstSeen"], row.first_seen.to_rfc3339());
        assert!(out.get("host_key").is_none());
    }

    #[test]
    fn ru4_terminal_keepalive_is_not_registered_in_the_ipc_handler() {
        let handlers = include_str!("../lib.rs");
        assert!(handlers.contains("terminal_disconnect,"));
        assert!(
            !handlers
                .lines()
                .any(|line| line.trim() == "terminal_keepalive,"),
            "no renderer caller at HEAD: do not expose a dead command"
        );
    }

    #[test]
    fn ru4_both_connect_callers_leave_host_key_and_timeout_errors_intact() {
        let source = include_str!("terminal.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        assert!(
            !production.contains("contains(\"host key\")"),
            "russh Display must not decide which host-key outcome the user sees"
        );
        assert!(!production.contains("contains(\"unknown key\")"));
        assert!(!production.contains("contains(\"key exchange\")"));
    }
}
