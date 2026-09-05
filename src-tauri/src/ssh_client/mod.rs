//! Embedded SSH client (PuTTY-style interactive terminal).
//!
//! Architecture:
//! - A `SessionRegistry` (Tauri-managed state) tracks live interactive sessions.
//! - Each session runs as a spawned tokio task that owns a russh client handle +
//!   a channel, reads keystrokes from an mpsc receiver, forwards channel data to a
//!   Tauri `ipc::Channel`, and handles resize/exit.
//! - Host keys are verified TOFU-style against the local `known_hosts` table.
//! - Private keys are decoded in-memory from the vault (never written to disk).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64ct::Encoding;
use russh::client::{self, Handle};
use russh::keys::*;
use russh::*;
use russh::Pty;
use tauri::ipc::Channel;

use crate::db::{Database, ServerRecord};

/// One live interactive session.
pub struct SessionHandle {
    pub session_id: String,
    pub server_name: String,
    pub host: String,
    pub port: u16,
    pub started_at_ms: i64,
    pub input_tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    pub resize_tx: tokio::sync::mpsc::UnboundedSender<(u32, u32)>,
}

/// Registry of all live SSH sessions (Tauri-managed state).
#[derive(Default)]
pub struct SessionRegistry {
    sessions: Mutex<HashMap<String, SessionHandle>>,
}

impl SessionRegistry {
    pub fn new() -> Self {
        Self { sessions: Mutex::new(HashMap::new()) }
    }

    pub fn insert(&self, handle: SessionHandle) {
        self.sessions.lock().unwrap().insert(handle.session_id.clone(), handle);
    }

    pub fn get_input_tx(&self, id: &str) -> Option<tokio::sync::mpsc::UnboundedSender<Vec<u8>>> {
        self.sessions.lock().unwrap().get(id).map(|s| s.input_tx.clone())
    }

    pub fn get_resize_tx(&self, id: &str) -> Option<tokio::sync::mpsc::UnboundedSender<(u32, u32)>> {
        self.sessions.lock().unwrap().get(id).map(|s| s.resize_tx.clone())
    }

    pub fn remove(&self, id: &str) -> Option<SessionHandle> {
        self.sessions.lock().unwrap().remove(id)
    }

    pub fn list(&self) -> Vec<(String, String, String, u16, i64)> {
        self.sessions.lock().unwrap().iter()
            .map(|(id, s)| (id.clone(), s.server_name.clone(), s.host.clone(), s.port, s.started_at_ms))
            .collect()
    }

    pub fn len(&self) -> usize {
        self.sessions.lock().unwrap().len()
    }

    /// Terminate every live session (used on vault lock / app quit).
    pub fn kill_all(&self) {
        let mut guard = self.sessions.lock().unwrap();
        // Dropping each input_tx makes the session task's recv() return None,
        // which the task treats as "disconnect requested".
        guard.clear();
    }
}

/// The russh client handler. Its only job is host-key verification (TOFU);
/// the interactive I/O runs on the channel side in the spawned task.
pub struct TerminalHandler {
    /// host used as the key in the known_hosts table
    pub host: String,
    /// database handle for host-key lookups
    pub db: Database,
}

impl client::Handler for TerminalHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let presented_b64: String = match server_public_key {
            PublicKeyOrCertificate::PublicKey { key, .. } => {
                let bytes = key.to_bytes().map_err(|e| russh::Error::from(e))?;
                base64ct::Base64::encode_string(&bytes)
            }
            PublicKeyOrCertificate::Certificate(cert) => {
                let bytes = cert.to_bytes().map_err(|e| russh::Error::from(e))?;
                base64ct::Base64::encode_string(&bytes)
            }
        };

        match self.db.get_known_host(&self.host) {
            Ok(Some(known)) => {
                // Known host: accept only if the presented key matches what we stored.
                Ok(known.host_key == presented_b64)
            }
            Ok(None) => {
                // First sight: TOFU-accept and store.
                let fp = fingerprint_of_blob(&presented_b64).unwrap_or_default();
                let _ = self.db.add_known_host(&self.host, &presented_b64, &fp);
                Ok(true)
            }
            Err(_) => Ok(false),
        }
    }
}

/// Base64(SHA-256(wire-format blob)) — the "SHA256:<this>" part of a
/// `ssh-keygen -lf` fingerprint, without the label.
pub fn fingerprint_of_blob(blob_b64: &str) -> Option<String> {
    use sha2::Digest;
    let bytes = base64ct::Base64::decode_vec(blob_b64).ok()?;
    Some(base64ct::Base64::encode_string(&sha2::Sha256::digest(&bytes)))
}

/// `ssh-keygen`-style display form: "SHA256:…".
pub fn hostkey_fingerprint_display(blob_b64: &str) -> String {
    fingerprint_of_blob(blob_b64).map(|f| format!("SHA256:{f}")).unwrap_or_else(|| "?".into())
}

/// Everything needed to open one connection.
pub struct ConnectParams {
    pub server: ServerRecord,
    pub username: String,
    pub auth_method: String,
    /// Decrypted private-key PEM text (in-memory), when auth_method == publickey
    /// and the key lives in the vault.
    pub key_pem: Option<String>,
    /// Password when auth_method == password (plaintext, in-memory only).
    pub password: Option<String>,
}

/// Streamed (interactive) session error sentinel types used across IPC.
pub type SessionId = String;

fn base_client_config() -> client::Config {
    client::Config {
        // None disables the inactivity timer so an interactive shell can sit
        // idle indefinitely while the user thinks. Some(Duration::from_secs(0))
        // would mean "fire after 0 seconds" — russh would tear down the
        // session the moment the channel went quiet between commands.
        inactivity_timeout: None,
        keepalive_interval: Some(Duration::from_secs(30)),
        ..<_>::default()
    }
}

/// Public re-export so the `server_test` IPC handler can reuse the same
/// client::Config that interactive sessions use.
pub fn base_client_config_pub() -> client::Config {
    base_client_config()
}

/// Authenticate to a live russh session handle. `auth_method` is one of
/// "publickey" | "password" | "keyboard-interactive".
pub async fn authenticate(
    session: &mut Handle<TerminalHandler>,
    params: &ConnectParams,
) -> anyhow::Result<()> {
    let user = params.username.clone();
    match params.auth_method.as_str() {
        "publickey" => {
            let pem = params.key_pem.as_deref()
                .ok_or_else(|| anyhow::anyhow!("No private key selected for this session"))?;
            let key_pair = decode_secret_key(pem, None)
                .map_err(|e| anyhow::anyhow!("Could not decode the selected private key: {e}"))?;
            let auth = session
                .authenticate_publickey(
                    &user,
                    PrivateKeyWithHashAlg::new(Arc::new(key_pair), None),
                )
                .await?;
            if !auth.success() {
                return Err(anyhow::anyhow!("Public-key authentication failed: the server rejected the key for user \"{user}\"."));
            }
        }
        "password" => {
            let pw = params.password.as_deref()
                .ok_or_else(|| anyhow::anyhow!("No password available for this session."))?;
            let auth = session.authenticate_password(&user, pw).await?;
            if !auth.success() {
                return Err(anyhow::anyhow!("Password authentication failed for user \"{user}\"."));
            }
        }
        "keyboard-interactive" => {
            let mut response = session.authenticate_keyboard_interactive_start(&user, None).await?;
            let mut attempts = 0;
            loop {
                attempts += 1;
                if attempts > 30 {
                    return Err(anyhow::anyhow!("Keyboard-interactive authentication did not complete."));
                }
                match response {
                    client::KeyboardInteractiveAuthResponse::Success => break,
                    client::KeyboardInteractiveAuthResponse::Failure { .. } => {
                        return Err(anyhow::anyhow!("Keyboard-interactive authentication failed."));
                    }
                    client::KeyboardInteractiveAuthResponse::InfoRequest { prompts, .. } => {
                        let mut responses = Vec::new();
                        for _prompt in &prompts {
                            // v1: only a saved password is offered; prompts that need
                            // other input (2FA codes, OTP) cannot be answered offline.
                            responses.push(params.password.clone().unwrap_or_default());
                        }
                        response = session.authenticate_keyboard_interactive_respond(responses).await?;
                    }
                }
            }
        }
        other => {
            return Err(anyhow::anyhow!("Unsupported auth method: {other}"));
        }
    }
    Ok(())
}

// ─── Session lifecycle ──────────────────────────────────────────────────────

/// Connection context resolved from a saved server record + the vault.
#[derive(Clone)]
pub struct ResolvedConnection {
    pub server: ServerRecord,
    pub username: String,
    pub auth_method: String,
    pub key_pem: Option<String>,
    pub password: Option<String>,
}

/// Connect, authenticate, request a PTY shell, register the session and stream
/// remote output to `on_data` until the channel closes or `disconnect` is called.
/// Returns the new session id.
pub async fn start_interactive(
    params: ResolvedConnection,
    db: Database,
    registry: Arc<SessionRegistry>,
    on_data: Channel<String>,
) -> anyhow::Result<String> {
    let target_host = params.server.host.clone();
    let target_port = params.server.port;

    let config = Arc::new(base_client_config());
    let handler = TerminalHandler { host: target_host.clone(), db: db.clone() };

    let mut session = client::connect(config, (&target_host[..], target_port), handler)
        .await
        .map_err(|e| anyhow::anyhow!("Connection failed: {e}"))?;
    eprintln!("[sshspan-terminal] tcp+kex established to {target_host}:{target_port}");

    authenticate(&mut session, &ConnectParams {
        server: params.server.clone(),
        username: params.username.clone(),
        auth_method: params.auth_method.clone(),
        key_pem: params.key_pem.clone(),
        password: params.password.clone(),
    }).await?;
    eprintln!("[sshspan-terminal] authenticated as {}", params.username);

    // Terminal dimensions start at 80x24; the renderer sends the real size right
    // after it learns the session id. The terminal_modes list must include
    // at least Pty::ECHO — many sshd implementations REJECT a PTY request with
    // no modes at all (silent PTY rejection = no input echo, no prompt).
    let mut channel = session.channel_open_session().await?;
    channel
        .request_pty(false, "xterm-256color", 80, 24, 0, 0, &[
            (Pty::ECHO, 1),
            (Pty::ICANON, 1),
            (Pty::ISIG, 1),
            (Pty::OPOST, 1),
            (Pty::ONLCR, 1),
        ])
        .await
        .map_err(|e| anyhow::anyhow!("PTY request failed: {e}"))?;
    channel
        .request_shell(true)
        .await
        .map_err(|e| anyhow::anyhow!("Shell request failed: {e}"))?;
    eprintln!("[sshspan-terminal] pty + shell ready, streaming");

    let session_id = uuid::Uuid::new_v4().to_string();
    let (input_tx, mut input_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    let (resize_tx, mut resize_rx) = tokio::sync::mpsc::unbounded_channel::<(u32, u32)>();

    registry.insert(SessionHandle {
        session_id: session_id.clone(),
        server_name: params.server.name.clone(),
        host: target_host.clone(),
        port: target_port,
        started_at_ms: chrono::Utc::now().timestamp_millis(),
        input_tx,
        resize_tx,
    });

    let server_name = params.server.name.clone();
    let reg_session_id = session_id.clone();
    let registry2 = registry.clone();
    let banner = format!(
        "\r\n\x1b[1;32mConnected to {target_host}:{target_port} as {} ({server_name})\x1b[0m\r\n",
        params.username
    );
    if let Err(e) = on_data.send(banner) {
        eprintln!("[sshspan-terminal] channel send failed right after connect: {e}");
    }

    tauri::async_runtime::spawn(async move {
        loop {
            tokio::select! {
                msg = channel.wait() => {
                    match msg {
                        Some(ChannelMsg::Data { data }) => {
                            let text = String::from_utf8_lossy(&data);
                            if let Err(e) = on_data.send(text.to_string()) {
                                // Renderer channel died — tear the session down,
                                // but leave a stderr trail so it is diagnosable.
                                eprintln!("[sshspan-terminal] data send failed, closing session {reg_session_id}: {e}");
                                break;
                            }
                        }
                        Some(ChannelMsg::ExtendedData { data, .. }) => {
                            let text = String::from_utf8_lossy(&data);
                            if let Err(e) = on_data.send(text.to_string()) {
                                eprintln!("[sshspan-terminal] stderr-send failed, closing session {reg_session_id}: {e}");
                                break;
                            }
                        }
                        Some(ChannelMsg::ExitStatus { exit_status }) => {
                            let _ = on_data.send(format!(
                                "\r\n\x1b[1;31m[process exited with status {exit_status}]\x1b[0m\r\n"
                            ));
                            break;
                        }
                        Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) | None => break,
                        _ => {}
                    }
                }
                input = input_rx.recv() => {
                    match input {
                        Some(bytes) => {
                            if channel.data(&bytes[..]).await.is_err() { break; }
                        }
                        None => break, // sender dropped => disconnect requested
                    }
                }
                resize = resize_rx.recv() => {
                    match resize {
                        Some((cols, rows)) => {
                            if channel.window_change(cols, rows, 0, 0).await.is_err() { break; }
                        }
                        None => break,
                    }
                }
            }
        }
        let _ = on_data.send("\r\n\x1b[1;33m[connection closed]\x1b[0m\r\n".to_string());
        registry2.remove(&reg_session_id);
    });

    // Mark the server as last-connected.
    let mut server = params.server;
    server.last_connected_at = Some(chrono::Utc::now());
    let _ = db.update_server(&server);

    Ok(session_id)
}

/// Send raw bytes (keystrokes) to a live session's stdin.
pub fn session_send(registry: &SessionRegistry, session_id: &str, bytes: Vec<u8>) -> anyhow::Result<()> {
    match registry.get_input_tx(session_id) {
        Some(tx) => tx.send(bytes).map_err(|_| anyhow::anyhow!("Session is closing.")),
        None => Err(anyhow::anyhow!("No such session.")),
    }
}

/// Resize a live session's remote PTY.
pub fn session_resize(registry: &SessionRegistry, session_id: &str, cols: u32, rows: u32) -> anyhow::Result<()> {
    match registry.get_resize_tx(session_id) {
        Some(tx) => tx.send((cols, rows)).map_err(|_| anyhow::anyhow!("Session is closing.")),
        None => Err(anyhow::anyhow!("No such session.")),
    }
}

/// Request a disconnect. Drops the sender; the session task closes the channel.
pub fn session_disconnect(registry: &SessionRegistry, session_id: &str) {
    if let Some(handle) = registry.remove(session_id) {
        drop(handle); // input_tx dropped => task recv() returns None => clean shutdown
    }
}
