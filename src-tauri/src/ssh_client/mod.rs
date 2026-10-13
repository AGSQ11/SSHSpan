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
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use base64ct::Encoding;
use russh::client::{self, Handle};
use russh::keys::*;
use russh::Pty;
use russh::*;
use tauri::ipc::Channel;
use tauri::AppHandle;
use zeroize::Zeroizing;

use crate::db::{Database, ServerRecord};

/// One live interactive session.
pub struct SessionHandle {
    pub session_id: String,
    /// Saved-server id this session was opened for. Session ids die with the
    /// connection; this is what the SFTP transfer queue matches a RECONNECTED
    /// session against so paused/restored transfers can resume (A7-17).
    pub server_id: String,
    pub server_name: String,
    pub host: String,
    pub port: u16,
    pub started_at_ms: i64,
    pub input_tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    pub resize_tx: tokio::sync::mpsc::UnboundedSender<(u32, u32)>,
    /// Requests an SFTP subsystem channel on the session's authenticated
    /// connection. The session task owns the russh `Handle` (it is not
    /// Clone), so SFTP open requests are sent to it over this channel and
    /// answered on a oneshot.
    pub sftp_tx: tokio::sync::mpsc::UnboundedSender<
        tokio::sync::oneshot::Sender<anyhow::Result<russh_sftp::client::SftpSession>>,
    >,
}

/// Registry of all live SSH sessions (Tauri-managed state).
#[derive(Default)]
pub struct SessionRegistry {
    sessions: Mutex<HashMap<String, SessionHandle>>,
}

impl SessionRegistry {
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
        }
    }

    pub fn insert(&self, handle: SessionHandle) {
        self.sessions
            .lock()
            .unwrap()
            .insert(handle.session_id.clone(), handle);
    }

    pub fn get_input_tx(&self, id: &str) -> Option<tokio::sync::mpsc::UnboundedSender<Vec<u8>>> {
        self.sessions
            .lock()
            .unwrap()
            .get(id)
            .map(|s| s.input_tx.clone())
    }

    pub fn get_resize_tx(
        &self,
        id: &str,
    ) -> Option<tokio::sync::mpsc::UnboundedSender<(u32, u32)>> {
        self.sessions
            .lock()
            .unwrap()
            .get(id)
            .map(|s| s.resize_tx.clone())
    }

    pub fn get_sftp_tx(
        &self,
        id: &str,
    ) -> Option<
        tokio::sync::mpsc::UnboundedSender<
            tokio::sync::oneshot::Sender<anyhow::Result<russh_sftp::client::SftpSession>>,
        >,
    > {
        self.sessions
            .lock()
            .unwrap()
            .get(id)
            .map(|s| s.sftp_tx.clone())
    }

    pub fn remove(&self, id: &str) -> Option<SessionHandle> {
        self.sessions.lock().unwrap().remove(id)
    }

    /// Saved-server id a live session was opened for.
    pub fn server_id_of(&self, id: &str) -> Option<String> {
        self.sessions
            .lock()
            .unwrap()
            .get(id)
            .map(|s| s.server_id.clone())
    }

    /// `(session_id, server_id, started_at_ms)` of every live session - what
    /// the SFTP transfer queue matches paused jobs against after a reconnect.
    pub fn live_server_sessions(&self) -> Vec<(String, String, i64)> {
        self.sessions
            .lock()
            .unwrap()
            .values()
            .map(|s| (s.session_id.clone(), s.server_id.clone(), s.started_at_ms))
            .collect()
    }

    pub fn list(&self) -> Vec<(String, String, String, u16, i64)> {
        self.sessions
            .lock()
            .unwrap()
            .iter()
            .map(|(id, s)| {
                (
                    id.clone(),
                    s.server_name.clone(),
                    s.host.clone(),
                    s.port,
                    s.started_at_ms,
                )
            })
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

/// Key used for a host-key pin in the `known_hosts` table. Pins are scoped
/// to `host:port` so the same hostname on different ports cannot share or
/// clobber each other.
pub fn known_host_key(host: &str, port: u16) -> String {
    // An IPv6 literal is made of colons, so "{host}:{port}" would produce
    // "2001:db8::1:22" - ambiguous, and impossible to tell from a hostname
    // that happens to contain colons. Bracket it, matching the URL-authority
    // convention and the form `db::qualify_legacy_known_host` migrates old
    // rows into, so a pin written by either path is found by the other.
    if host.starts_with('[') || host.matches(':').count() < 2 {
        format!("{}:{}", host, port)
    } else {
        format!("[{}]:{}", host, port)
    }
}

/// Asks the user whether to trust a host key:
/// `(host, port, fingerprint, imported) -> trusted`. Production uses the
/// native dialog ([`native_host_trust_prompt`]); tests answer without a GUI.
/// Like the dialog, it blocks until there is an answer.
pub type HostTrustPrompt = Arc<dyn Fn(&str, u16, &str, bool) -> bool + Send + Sync>;

/// [`ask_host_trust_native`] as a [`HostTrustPrompt`].
pub fn native_host_trust_prompt(app: &AppHandle) -> HostTrustPrompt {
    let app = app.clone();
    Arc::new(move |host, port, fingerprint, imported| {
        ask_host_trust_native(&app, host, port, fingerprint, imported)
    })
}

/// Why the host-key check refused a connection (A7-14). russh turns every
/// refusal into the same `Error::UnknownKey` ("Unknown server key"), so the
/// handler records the reason for the code awaiting `connect` instead of
/// anyone guessing it from russh's Display text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostKeyRefusal {
    /// The presented key differs from the one pinned for this host:port.
    Mismatch,
    /// The user refused (or closed) the trust dialog.
    Declined,
    /// The known-hosts store could not be read or updated, so nothing could
    /// be verified or recorded.
    StoreUnavailable,
}

impl HostKeyRefusal {
    /// The message the user sees for this refusal.
    pub fn message(self, host: &str, port: u16) -> String {
        let target = display_target(host, port);
        match self {
            Self::Mismatch => format!(
                "Host key mismatch for {target} - possible man-in-the-middle. If the server's key \
                 really changed, forget it under Settings > Known hosts and reconnect."
            ),
            Self::Declined => "Connection cancelled: host key not trusted.".to_string(),
            Self::StoreUnavailable => format!(
                "Could not check the host key for {target} against Known hosts, so the \
                 connection was refused. Try again."
            ),
        }
    }
}

/// `host:port` for a message: IPv6 literals bracketed (the known-hosts form)
/// and control characters removed (the text can end up in the terminal).
fn display_target(host: &str, port: u16) -> String {
    known_host_key(&sanitize_terminal_text(host), port)
}

/// A mutex lock that survives a panic elsewhere: the handshake state below
/// holds plain values that are never left half-updated.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// What one handshake learned that `connect`'s error cannot carry: why the
/// host key was refused (A7-14) and how long the user spent in the trust
/// dialog, which the connect deadline must not count (A7-15). Shared by the
/// russh handler and the code awaiting `connect`.
#[derive(Default)]
struct HandshakeWatch {
    refusal: Mutex<Option<HostKeyRefusal>>,
    dialog: Mutex<DialogClock>,
}

#[derive(Default)]
struct DialogClock {
    open_since: Option<Instant>,
    closed_total: Duration,
}

/// Marks the trust dialog as open until dropped (also on a panic).
struct DialogOpen<'a>(&'a HandshakeWatch);

impl Drop for DialogOpen<'_> {
    fn drop(&mut self) {
        let mut clock = lock(&self.0.dialog);
        if let Some(since) = clock.open_since.take() {
            clock.closed_total += since.elapsed();
        }
    }
}

impl HandshakeWatch {
    fn record_refusal(&self, why: HostKeyRefusal) {
        *lock(&self.refusal) = Some(why);
    }

    fn refusal(&self) -> Option<HostKeyRefusal> {
        *lock(&self.refusal)
    }

    fn dialog_open(&self) -> DialogOpen<'_> {
        lock(&self.dialog).open_since = Some(Instant::now());
        DialogOpen(self)
    }

    /// Whether the dialog is open now, and the total time spent in it so far.
    fn user_time(&self) -> (bool, Duration) {
        let clock = lock(&self.dialog);
        match clock.open_since {
            Some(since) => (true, clock.closed_total + since.elapsed()),
            None => (false, clock.closed_total),
        }
    }
}

/// The russh client handler. Its only job is host-key verification; the
/// interactive I/O runs on the channel side in the spawned task.
///
/// Host-key policy:
/// - a pinned `host:port` learned from a real connection must match exactly,
///   else the connection is refused;
/// - an UNPINNED host is accepted only after the user accepts a NATIVE
///   backend dialog raised here, at the moment the key arrives, showing the
///   fingerprint BEFORE the decision. Consent never travels through the
///   renderer: a compromised webview cannot mint it, suppress it, or fake
///   it - the worst it can do is relay the same OS dialog the user sees;
/// - a pin imported from a backup restore is marked `imported` and is NOT
///   silently trusted even when the presented key matches: the same native
///   dialog re-confirms the fingerprint on first use, then the pin is
///   upgraded to `connection` (see `confirm_imported_known_host`).
///
/// A refusal is recorded in the shared [`HandshakeWatch`] with its reason,
/// so a changed key and a click on "Refuse" reach the user as different
/// messages (A7-14).
pub struct TerminalHandler {
    /// host used as the key in the known_hosts table
    host: String,
    /// port used as part of the known_hosts key
    port: u16,
    /// database handle for host-key lookups
    db: Database,
    /// Raises the trust dialog (the native one outside tests).
    prompt: HostTrustPrompt,
    watch: Arc<HandshakeWatch>,
}

impl client::Handler for TerminalHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let presented_b64: String = match server_public_key {
            PublicKeyOrCertificate::PublicKey { key, .. } => {
                let bytes = key.to_bytes().map_err(russh::Error::from)?;
                base64ct::Base64::encode_string(&bytes)
            }
            PublicKeyOrCertificate::Certificate(cert) => {
                let bytes = cert.to_bytes().map_err(russh::Error::from)?;
                base64ct::Base64::encode_string(&bytes)
            }
        };
        let (host, port, prompt, watch) = (&self.host, self.port, &self.prompt, &self.watch);
        let verdict = verify_host_key(
            &self.db,
            host,
            port,
            &presented_b64,
            |fingerprint, imported| {
                let _open = watch.dialog_open();
                prompt(host, port, fingerprint, imported)
            },
        );
        match verdict {
            Ok(()) => Ok(true),
            Err(why) => {
                watch.record_refusal(why);
                Ok(false)
            }
        }
    }
}

/// The trust decision for one presented host key - the policy documented on
/// [`TerminalHandler`]. `ask(fingerprint, imported)` raises the trust dialog
/// and returns the user's answer.
fn verify_host_key(
    db: &Database,
    host: &str,
    port: u16,
    presented_b64: &str,
    mut ask: impl FnMut(&str, bool) -> bool,
) -> Result<(), HostKeyRefusal> {
    let host_key = known_host_key(host, port);
    let presented_fp = fingerprint_of_blob(presented_b64).unwrap_or_default();
    let shown_fp = hostkey_fingerprint_display(presented_b64);

    match db.get_known_host(&host_key) {
        Ok(Some(known)) => {
            if known.host_key != presented_b64 {
                // Mismatch is hard-failed - for a confirmed pin AND for an
                // imported one (a key that differs from any stored anchor is
                // an attack signal, never an upgrade). No dialog is offered.
                // Leave an audit trail so a silent MITM attempt is visible
                // after the fact.
                let _ = db.add_audit(
                    "known_hosts.mismatch_rejected",
                    None,
                    &format!(
                        "{} (expected {})",
                        &host_key,
                        hostkey_fingerprint_display(&known.host_key)
                    ),
                );
                return Err(HostKeyRefusal::Mismatch);
            }
            if known.source == "connection" {
                return Ok(());
            }
            // Exact match against an IMPORTED pin (backup restore, never used
            // against a live connection): not silently trusted. The user
            // confirms the fingerprint once in the dialog; the pin is then
            // upgraded to 'connection'. If the confirm fails (row gone,
            // already upgraded) refuse rather than trust something
            // unrecorded.
            if !ask(&shown_fp, true) {
                let _ = db.add_audit(
                    "known_hosts.imported_refused",
                    None,
                    &format!("{} ({})", &host_key, shown_fp),
                );
                return Err(HostKeyRefusal::Declined);
            }
            match db.confirm_imported_known_host(&host_key, presented_b64) {
                Ok(true) => {
                    let _ = db.add_audit(
                        "known_hosts.imported_confirmed",
                        None,
                        &format!("{} ({})", &host_key, shown_fp),
                    );
                    Ok(())
                }
                _ => {
                    let _ = db.add_audit(
                        "known_hosts.imported_confirm_failed",
                        None,
                        &format!("{} ({})", &host_key, shown_fp),
                    );
                    Err(HostKeyRefusal::StoreUnavailable)
                }
            }
        }
        Ok(None) => {
            // First sight: the trust decision is the dialog, with the
            // fingerprint shown before it. Without the user's click the key
            // is refused and nothing is stored.
            if !ask(&shown_fp, false) {
                // Refuse without storing anything, but record the attempt.
                let _ = db.add_audit(
                    "known_hosts.unknown_refused",
                    None,
                    &format!("{} (presented {})", &host_key, shown_fp),
                );
                return Err(HostKeyRefusal::Declined);
            }
            // First sight WITH user consent: store and record what was
            // trusted, and let the connect path surface a notice in the
            // terminal.
            let _ = db.add_known_host(&host_key, presented_b64, &presented_fp);
            let _ = db.add_audit(
                "known_hosts.trust_on_first_use",
                None,
                &format!("{} ({})", &host_key, shown_fp),
            );
            Ok(())
        }
        Err(_) => Err(HostKeyRefusal::StoreUnavailable),
    }
}

/// Native host-key trust prompt, raised from the backend at the moment the
/// key arrives - with the fingerprint displayed BEFORE the decision (the
/// property that makes TOFU honest). Returns true only when the user
/// accepted in the OS dialog; the webview cannot forge that click.
fn ask_host_trust_native(
    app: &AppHandle,
    host: &str,
    port: u16,
    fingerprint_display: &str,
    imported: bool,
) -> bool {
    use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogKind};
    let shown_host = sanitize_terminal_text(host);
    let message = if imported {
        format!(
            "A host key for {shown_host}:{port} came from a vault backup, \
             but this is its first real connection.\n\n\
             Presented fingerprint:\n{fingerprint_display}\n\n\
             Trust this key and connect?"
        )
    } else {
        format!(
            "The authenticity of host {shown_host}:{port} can't be established.\n\n\
             Presented fingerprint:\n{fingerprint_display}\n\n\
             Trust this host key and connect? \
             Compare the fingerprint out-of-band if you can."
        )
    };
    app.dialog()
        .message(message)
        .title("SSHSpan - Host key verification")
        .kind(MessageDialogKind::Warning)
        .buttons(MessageDialogButtons::OkCancelCustom(
            "Trust && connect".to_string(),
            "Refuse".to_string(),
        ))
        .blocking_show()
}

/// Strip control characters (C0, DEL, C1) from app-composed text that is
/// written into the terminal stream. App-composed strings interpolate
/// server-derived substrings (hostnames, usernames, server names); without
/// stripping, those become an ANSI injection channel where the APP is the
/// origin of escape sequences it never intended. Untrusted terminal output
/// itself is rendered by xterm.js by design and is not handled here.
pub(crate) fn sanitize_terminal_text(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).collect()
}

/// The fingerprint of a base64 wire-format host-key blob in the one form the
/// app stores and shows everywhere (A7-46): `SHA256:<unpadded base64>`,
/// exactly what `ssh-keygen -lf` prints and what keys already used. Hosts
/// used to get the bare, padded form (and a label only in the dialog).
pub fn fingerprint_of_blob(blob_b64: &str) -> Option<String> {
    let bytes = base64ct::Base64::decode_vec(blob_b64).ok()?;
    Some(crate::crypto::utils::ssh_fingerprint_sha256(&bytes))
}

/// [`fingerprint_of_blob`], or "?" for a blob that does not decode.
pub fn hostkey_fingerprint_display(blob_b64: &str) -> String {
    fingerprint_of_blob(blob_b64).unwrap_or_else(|| "?".into())
}

/// A SHA-256 fingerprint stored by an older release (bare and padded, or
/// labelled and padded) in the current form. Anything that is not a base64
/// SHA-256 digest is returned unchanged.
pub fn normalize_fingerprint(stored: &str) -> String {
    let body = stored
        .strip_prefix("SHA256:")
        .unwrap_or(stored)
        .trim_end_matches('=');
    match base64ct::Base64Unpadded::decode_vec(body) {
        Ok(digest) if digest.len() == 32 => format!("SHA256:{body}"),
        _ => stored.to_string(),
    }
}

/// The fingerprint shown and stored for a pinned host key: computed from the
/// pinned key itself, so text a crafted backup carried is never shown for it.
/// Only a key blob that does not decode falls back to the stored text,
/// normalized.
pub fn known_host_fingerprint(host_key_b64: &str, stored: &str) -> String {
    fingerprint_of_blob(host_key_b64).unwrap_or_else(|| normalize_fingerprint(stored))
}

/// Decodes one stream of terminal output into text without breaking
/// characters (A7-08). SSH cuts data packets at arbitrary byte offsets, so a
/// multi-byte character can arrive in two halves; decoding each packet on its
/// own turned both halves into U+FFFD. The incomplete tail of a packet (at
/// most 3 bytes) waits for the next one, and only genuinely invalid bytes
/// become U+FFFD - the same text as decoding the whole stream at once.
#[derive(Default)]
pub(crate) struct Utf8Stream {
    pending: Vec<u8>,
}

impl Utf8Stream {
    /// The text completed by `chunk`.
    pub(crate) fn push(&mut self, chunk: &[u8]) -> String {
        let mut bytes = std::mem::take(&mut self.pending);
        bytes.extend_from_slice(chunk);
        let mut text = String::with_capacity(bytes.len());
        let mut rest: &[u8] = &bytes;
        loop {
            match std::str::from_utf8(rest) {
                Ok(valid) => {
                    text.push_str(valid);
                    break;
                }
                Err(e) => {
                    let (valid, after) = rest.split_at(e.valid_up_to());
                    text.push_str(&String::from_utf8_lossy(valid));
                    match e.error_len() {
                        Some(invalid) => {
                            text.push(char::REPLACEMENT_CHARACTER);
                            rest = &after[invalid..];
                        }
                        None => {
                            self.pending = after.to_vec();
                            break;
                        }
                    }
                }
            }
        }
        text
    }

    /// At the end of the stream an unfinished character is invalid.
    pub(crate) fn finish(&mut self) -> String {
        let rest = std::mem::take(&mut self.pending);
        String::from_utf8_lossy(&rest).into_owned()
    }
}

/// Decide whether a first-trust notice should be shown for a connection:
/// the host had no known_hosts entry before connecting, so TOFU stored a new
/// key during the handshake. `pre_connect_known_host` is the lookup made
/// BEFORE `client::connect` (the race between the two is benign - the notice
/// is informational, and the authoritative record is the
/// `known_hosts.trust_on_first_use` audit entry).
pub fn first_trust_notice(
    pre_connect_known_host: Option<&crate::db::KnownHost>,
    host: &str,
    fingerprint_display: &str,
) -> Option<String> {
    if pre_connect_known_host.is_some() {
        return None;
    }
    Some(format!(
        "\r\n\x1b[1;33mTrusted new host key for {} ({fingerprint_display}) - manage in Known Hosts.\x1b[0m\r\n",
        sanitize_terminal_text(host)
    ))
}

/// Everything needed to open one connection.
pub struct ConnectParams {
    pub server: ServerRecord,
    pub username: String,
    pub auth_method: String,
    /// Decrypted private-key PEM text (in-memory), when auth_method == publickey
    /// and the key lives in the vault.
    pub key_pem: Option<Zeroizing<String>>,
    /// Password when auth_method == password (plaintext, in-memory only).
    pub password: Option<Zeroizing<String>>,
}

/// Streamed (interactive) session error sentinel types used across IPC.
pub type SessionId = String;

fn base_client_config() -> client::Config {
    client::Config {
        // None disables the inactivity timer so an interactive shell can sit
        // idle indefinitely while the user thinks. Some(Duration::from_secs(0))
        // would mean "fire after 0 seconds" - russh would tear down the
        // session the moment the channel went quiet between commands.
        inactivity_timeout: None,
        keepalive_interval: Some(Duration::from_secs(30)),
        ..<_>::default()
    }
}

/// Deadlines for opening a connection (A7-15). `inactivity_timeout` stays
/// `None` (see [`base_client_config`]): russh uses it as the only timer during
/// the handshake too, which is why an accept-and-stall server used to hang
/// "Connecting..." and "Test connection" forever.
#[derive(Debug, Clone, Copy)]
pub struct Deadlines {
    /// TCP, the SSH banner and key exchange - NOT the time the user spends
    /// in the host-key dialog (see [`within_network_time`]).
    pub connect: Duration,
    /// Authentication, which has no dialog.
    pub auth: Duration,
}

impl Deadlines {
    /// What the terminal and "Test connection" use.
    pub const INTERACTIVE: Self = Self {
        connect: Duration::from_secs(20),
        auth: Duration::from_secs(30),
    };
}

/// How often a deadline waiting on the trust dialog looks again.
const DIALOG_POLL: Duration = Duration::from_millis(250);

/// Run `fut` with `limit` for the NETWORK's share of the time: the host-key
/// dialog is answered inside the handshake, and a user reading a fingerprint
/// is not a stalled server. While the dialog is open the clock is stopped;
/// afterwards the network gets what was left. `None` when the time ran out.
async fn within_network_time<F: std::future::Future>(
    limit: Duration,
    watch: &HandshakeWatch,
    fut: F,
) -> Option<F::Output> {
    tokio::pin!(fut);
    let started = Instant::now();
    loop {
        let (dialog_open, user_time) = watch.user_time();
        let network_time = started.elapsed().saturating_sub(user_time);
        let wait = if dialog_open {
            DIALOG_POLL
        } else if network_time >= limit {
            return None;
        } else {
            limit - network_time
        };
        tokio::select! {
            biased;
            out = &mut fut => return Some(out),
            _ = tokio::time::sleep(wait) => {}
        }
    }
}

/// Open a connection, check the host key and authenticate: the path a
/// terminal session and "Test connection" share, so both report the same
/// outcomes. The error is the message the user sees: a refused host key is
/// reported for what it was (A7-14) and each stage has a deadline (A7-15).
pub async fn open_authenticated(
    params: &ConnectParams,
    db: &Database,
    prompt: HostTrustPrompt,
    deadlines: Deadlines,
) -> Result<Handle<TerminalHandler>, String> {
    let (host, port) = (params.server.host.as_str(), params.server.port);
    let watch = Arc::new(HandshakeWatch::default());
    let handler = TerminalHandler {
        host: host.to_string(),
        port,
        db: db.clone(),
        prompt,
        watch: watch.clone(),
    };
    let config = Arc::new(base_client_config());
    // russh runs the handshake in a task of its own that owns the socket; a
    // second handle to the socket lets a timed-out attempt shut it, instead
    // of leaving that task waiting on a silent server.
    let socket_handle: Mutex<Option<std::net::TcpStream>> = Mutex::new(None);
    let handshake = async {
        let tcp = tokio::net::TcpStream::connect((host, port))
            .await
            .map_err(|e| format!("Connection failed: {e}"))?;
        if config.nodelay {
            let _ = tcp.set_nodelay(true);
        }
        let tcp = keep_socket_handle(tcp, &socket_handle)
            .map_err(|e| format!("Connection failed: {e}"))?;
        client::connect_stream(config, tcp, handler)
            .await
            .map_err(|e| match watch.refusal() {
                Some(why) => why.message(host, port),
                None => format!("Connection failed: {e}"),
            })
    };
    let outcome = within_network_time(deadlines.connect, &watch, handshake).await;
    let socket = lock(&socket_handle).take();
    let mut session = match outcome {
        Some(result) => result?,
        None => {
            if let Some(socket) = socket {
                let _ = socket.shutdown(std::net::Shutdown::Both);
            }
            return Err(format!(
                "Timed out connecting to {}.",
                display_target(host, port)
            ));
        }
    };
    drop(socket);
    match tokio::time::timeout(deadlines.auth, authenticate(&mut session, params)).await {
        Ok(Ok(())) => Ok(session),
        Ok(Err(e)) => Err(e.to_string()),
        // Dropping the handle ends russh's session task and its socket.
        Err(_) => Err(format!(
            "Timed out during authentication with {}.",
            display_target(host, port)
        )),
    }
}

/// Keep a duplicate handle of `tcp` in `slot` (see [`open_authenticated`]).
fn keep_socket_handle(
    tcp: tokio::net::TcpStream,
    slot: &Mutex<Option<std::net::TcpStream>>,
) -> std::io::Result<tokio::net::TcpStream> {
    let tcp = tcp.into_std()?;
    *lock(slot) = Some(tcp.try_clone()?);
    tokio::net::TcpStream::from_std(tcp)
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
            let pem = params
                .key_pem
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("No private key selected for this session"))?;
            let key_pair = decode_secret_key(pem, None)
                .map_err(|e| anyhow::anyhow!("Could not decode the selected private key: {e}"))?;
            // RSA keys: pin the signature hash to SHA-256 (rsa-sha2-256)
            // instead of letting the algorithm negotiation fall back to the
            // legacy ssh-rsa (SHA-1) signature format. Non-RSA keys have a
            // single fixed hash - pass None.
            let hash_alg = match key_pair.algorithm() {
                russh::keys::Algorithm::Rsa { .. } => Some(russh::keys::HashAlg::Sha256),
                _ => None,
            };
            let auth = session
                .authenticate_publickey(
                    &user,
                    PrivateKeyWithHashAlg::new(Arc::new(key_pair), hash_alg),
                )
                .await?;
            if !auth.success() {
                return Err(anyhow::anyhow!("Public-key authentication failed: the server rejected the key for user \"{user}\"."));
            }
        }
        "password" => {
            let pw = params
                .password
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("No password available for this session."))?;
            // The residual plaintext (A6-11) is not the `String` this call
            // hands over: russh 0.63 moves it into `auth::Method::Password`,
            // which zeroizes it on drop. It is the USERAUTH_REQUEST packet,
            // assembled in cleartext in `Encrypted.write` - a plain `Vec<u8>`
            // russh treats as non-sensitive: `clear()` after sending leaves
            // the bytes, password included, in its spare capacity until later
            // packets overwrite them. No russh API avoids that buffer.
            let auth = session.authenticate_password(&user, pw).await?;
            if !auth.success() {
                return Err(anyhow::anyhow!(
                    "Password authentication failed for user \"{user}\"."
                ));
            }
        }
        "keyboard-interactive" => {
            let mut response = session
                .authenticate_keyboard_interactive_start(&user, None)
                .await?;
            let mut attempts = 0;
            loop {
                attempts += 1;
                if attempts > 30 {
                    return Err(anyhow::anyhow!(
                        "Keyboard-interactive authentication did not complete."
                    ));
                }
                match response {
                    client::KeyboardInteractiveAuthResponse::Success => break,
                    client::KeyboardInteractiveAuthResponse::Failure { .. } => {
                        return Err(anyhow::anyhow!(
                            "Keyboard-interactive authentication failed."
                        ));
                    }
                    client::KeyboardInteractiveAuthResponse::InfoRequest { prompts, .. } => {
                        // The saved password is answered for ONE round of
                        // prompts only. A hostile server can otherwise issue
                        // unlimited extra InfoRequests ("Enter OTP:", "Enter
                        // pet name:", ...) and harvest the saved password from
                        // every reply. A legitimate server re-prompts only
                        // after a Failure - which is rejected above.
                        if attempts > 1 {
                            return Err(anyhow::anyhow!(
                                "The server requested additional interactive authentication \
                                 beyond the saved password; not supported."
                            ));
                        }
                        let password = params.password.as_deref().map(|s| s.as_str()).unwrap_or("");
                        // v1: only a saved password is offered; prompts that
                        // need other input (2FA codes, OTP) cannot be answered
                        // offline. russh 0.63 takes the answers as owned
                        // `String`s and frees them unwiped after encoding them
                        // (A6-11) - the copies built here, for that call -
                        // and the encoded USERAUTH_INFO_RESPONSE stays in
                        // `Encrypted.write` like the password request above.
                        // Nothing else is copied out of the `Zeroizing`
                        // password.
                        let responses: Vec<String> =
                            prompts.iter().map(|_| password.to_owned()).collect();
                        response = session
                            .authenticate_keyboard_interactive_respond(responses)
                            .await?;
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
    pub key_pem: Option<Zeroizing<String>>,
    pub password: Option<Zeroizing<String>>,
}

/// Connect, authenticate, request a PTY shell, register the session and stream
/// remote output to `on_data` until the channel closes or `disconnect` is called.
/// Returns the new session id.
pub async fn start_interactive(
    app: AppHandle,
    params: ResolvedConnection,
    db: Database,
    registry: Arc<SessionRegistry>,
    on_data: Channel<String>,
    vault_generation: Option<u64>,
) -> anyhow::Result<String> {
    let target_host = params.server.host.clone();
    let target_port = params.server.port;
    let known_host_lookup = known_host_key(&target_host, target_port);

    // Pre-check made BEFORE connecting: if the host has no known_hosts entry,
    // the handler will raise the native first-trust dialog during the
    // handshake (see TerminalHandler). The lookup result drives the
    // informational first-trust notice; the small race with the handler's own
    // lookup is benign (a notice is advisory, the audit entry is
    // authoritative).
    let pre_connect_known_host = db.get_known_host(&known_host_lookup).ok().flatten();

    let t0 = std::time::Instant::now();
    let session = open_authenticated(
        &ConnectParams {
            server: params.server.clone(),
            username: params.username.clone(),
            auth_method: params.auth_method.clone(),
            key_pem: params.key_pem.clone(),
            password: params.password.clone(),
        },
        &db,
        native_host_trust_prompt(&app),
        Deadlines::INTERACTIVE,
    )
    .await
    .map_err(anyhow::Error::msg)?;
    eprintln!(
        "[sshspan-terminal] connected and authenticated in {}ms",
        t0.elapsed().as_millis()
    );

    // Terminal dimensions start at 80x24; the renderer sends the real size right
    // after it learns the session id. The terminal_modes list must include
    // at least Pty::ECHO - many sshd implementations REJECT a PTY request with
    // no modes at all (silent PTY rejection = no input echo, no prompt).
    let mut channel = session.channel_open_session().await?;
    channel
        .request_pty(
            false,
            "xterm-256color",
            80,
            24,
            0,
            0,
            &[
                (Pty::ECHO, 1),
                (Pty::ICANON, 1),
                (Pty::ISIG, 1),
                (Pty::IUTF8, 1),
                (Pty::OPOST, 1),
                (Pty::ONLCR, 1),
            ],
        )
        .await
        .map_err(|e| anyhow::anyhow!("PTY request failed: {e}"))?;
    // The PTY term is what OpenSSH normally uses for TERM, but also send the
    // environment request for servers that derive shell behavior from env.
    // Do not wait for a reply: AcceptEnv policy may reject it even though the
    // PTY and interactive shell are otherwise valid.
    channel
        .set_env(false, "TERM", "xterm-256color")
        .await
        .map_err(|e| anyhow::anyhow!("TERM environment request failed: {e}"))?;
    channel
        .request_shell(true)
        .await
        .map_err(|e| anyhow::anyhow!("Shell request failed: {e}"))?;
    eprintln!(
        "[sshspan-terminal] pty+shell in {}ms - streaming",
        t0.elapsed().as_millis()
    );

    // Lock-during-connect guard: re-check the captured vault generation at
    // the last moment before the session is registered. The network handshake
    // and authentication above are the long await during which a lock could
    // have landed; without this check a connection started before the lock
    // would register a live session into the now-locked vault. Aborting here
    // drops `session`, closing the just-established connection rather than
    // registering it.
    if let Some(gen) = vault_generation {
        crate::commands::require_generation_current(&app, gen).map_err(|e| anyhow::anyhow!(e.0))?;
    }

    let session_id = uuid::Uuid::new_v4().to_string();
    let (input_tx, mut input_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    let (resize_tx, mut resize_rx) = tokio::sync::mpsc::unbounded_channel::<(u32, u32)>();
    let (sftp_tx, mut sftp_rx) = tokio::sync::mpsc::unbounded_channel::<
        tokio::sync::oneshot::Sender<anyhow::Result<russh_sftp::client::SftpSession>>,
    >();

    registry.insert(SessionHandle {
        session_id: session_id.clone(),
        server_id: params.server.id.clone(),
        server_name: params.server.name.clone(),
        host: target_host.clone(),
        port: target_port,
        started_at_ms: chrono::Utc::now().timestamp_millis(),
        input_tx,
        resize_tx,
        sftp_tx,
    });

    let server_name = params.server.name.clone();
    let reg_session_id = session_id.clone();
    let registry2 = registry.clone();
    // App-composed text interpolates server-derived values (host, username,
    // server name) - strip control characters so the app never becomes the
    // origin of an escape sequence a server smuggled into its own identity.
    let banner = format!(
        "\r\n\x1b[1;32mConnected to {}:{target_port} as {} ({})\x1b[0m\r\n",
        sanitize_terminal_text(&target_host),
        sanitize_terminal_text(&params.username),
        sanitize_terminal_text(&server_name)
    );
    if let Err(e) = on_data.send(banner) {
        eprintln!("[sshspan-terminal] channel send failed right after connect: {e}");
    }

    // First-time trust: the TOFU handler stored a new host key during this
    // handshake - tell the user what fingerprint they now trust.
    if let Some(notice) = db
        .get_known_host(&known_host_lookup)
        .ok()
        .flatten()
        .map(|kh| kh.fingerprint_sha256)
        .and_then(|fp| first_trust_notice(pre_connect_known_host.as_ref(), &target_host, &fp))
    {
        if let Err(e) = on_data.send(notice) {
            eprintln!("[sshspan-terminal] first-trust notice send failed: {e}");
        }
    }

    // The spawned task owns the russh session handle (it is not Clone), so
    // SFTP channel opens are requested from the registry via sftp_tx and
    // serviced here alongside shell I/O.
    tauri::async_runtime::spawn(async move {
        // stdout and stderr are separate byte streams: each keeps its own
        // unfinished character (A7-08).
        let mut stdout_text = Utf8Stream::default();
        let mut stderr_text = Utf8Stream::default();
        loop {
            tokio::select! {
                msg = channel.wait() => {
                    match msg {
                        Some(ChannelMsg::Data { data }) => {
                            let text = stdout_text.push(&data);
                            if text.is_empty() {
                                continue;
                            }
                            if let Err(e) = on_data.send(text) {
                                // Renderer channel died - tear the session down,
                                // but leave a stderr trail so it is diagnosable.
                                eprintln!("[sshspan-terminal] data send failed, closing session {reg_session_id}: {e}");
                                break;
                            }
                        }
                        Some(ChannelMsg::ExtendedData { data, .. }) => {
                            let text = stderr_text.push(&data);
                            if text.is_empty() {
                                continue;
                            }
                            if let Err(e) = on_data.send(text) {
                                eprintln!("[sshspan-terminal] stderr-send failed, closing session {reg_session_id}: {e}");
                                break;
                            }
                        }
                        Some(ChannelMsg::ExitStatus { exit_status }) => {
                            for text in [stdout_text.finish(), stderr_text.finish()] {
                                if !text.is_empty() {
                                    let _ = on_data.send(text);
                                }
                            }
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
                req = sftp_rx.recv() => {
                    match req {
                        Some(reply) => {
                            // Open a fresh session channel on the authenticated
                            // connection and run the SFTP subsystem over it.
                            let result = (|| async {
                                let ch = session.channel_open_session().await
                                    .map_err(|e| anyhow::anyhow!("channel open failed: {e}"))?;
                                ch.request_subsystem(true, "sftp").await
                                    .map_err(|e| anyhow::anyhow!("sftp subsystem failed: {e}"))?;
                                russh_sftp::client::SftpSession::new(ch.into_stream()).await
                                    .map_err(|e| anyhow::anyhow!("sftp init failed: {e}"))
                            })().await;
                            let _ = reply.send(result);
                        }
                        None => {} // registry gone; keep the shell alive
                    }
                }
            }
        }
        for text in [stdout_text.finish(), stderr_text.finish()] {
            if !text.is_empty() {
                let _ = on_data.send(text);
            }
        }
        let _ = on_data.send("\r\n\x1b[1;33m[connection closed]\x1b[0m\r\n".to_string());
        registry2.remove(&reg_session_id);
    });

    // Mark the server as last-connected - that column only. Writing back the
    // whole row read before the handshake could put an old-sealed
    // saved_password over one a master-password change re-sealed
    // meanwhile.
    let _ = db.touch_server_last_connected(&params.server.id, chrono::Utc::now());

    Ok(session_id)
}

/// Send raw bytes (keystrokes) to a live session's stdin.
pub fn session_send(
    registry: &SessionRegistry,
    session_id: &str,
    bytes: Vec<u8>,
) -> anyhow::Result<()> {
    match registry.get_input_tx(session_id) {
        Some(tx) => tx
            .send(bytes)
            .map_err(|_| anyhow::anyhow!("Session is closing.")),
        None => Err(anyhow::anyhow!("No such session.")),
    }
}

/// Resize a live session's remote PTY.
pub fn session_resize(
    registry: &SessionRegistry,
    session_id: &str,
    cols: u32,
    rows: u32,
) -> anyhow::Result<()> {
    match registry.get_resize_tx(session_id) {
        Some(tx) => tx
            .send((cols, rows))
            .map_err(|_| anyhow::anyhow!("Session is closing.")),
        None => Err(anyhow::anyhow!("No such session.")),
    }
}

/// Request a disconnect. Drops the sender; the session task closes the channel.
pub fn session_disconnect(registry: &SessionRegistry, session_id: &str) {
    if let Some(handle) = registry.remove(session_id) {
        drop(handle); // input_tx dropped => task recv() returns None => clean shutdown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn known_host() -> crate::db::KnownHost {
        crate::db::KnownHost {
            host: "example.com".into(),
            host_key: "AAAAblob".into(),
            fingerprint_sha256: "abc123".into(),
            first_seen: chrono::Utc::now(),
            source: "connection".into(),
        }
    }

    #[test]
    fn first_trust_notice_only_fires_on_first_sight() {
        // Pre-check found no entry => TOFU stored a new key => notice.
        let notice = first_trust_notice(None, "example.com", "SHA256:abc123");
        assert!(notice.is_some());
        let text = notice.unwrap();
        assert!(text.contains("example.com"));
        assert!(text.contains("SHA256:abc123"));
        assert!(text.contains("Known Hosts"));

        // Host already known before connecting => no notice.
        let known = known_host();
        assert!(first_trust_notice(Some(&known), "example.com", "SHA256:abc123").is_none());
    }

    fn session(session_id: &str, server_id: &str, started_at_ms: i64) -> SessionHandle {
        let (input_tx, _) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
        let (resize_tx, _) = tokio::sync::mpsc::unbounded_channel::<(u32, u32)>();
        let (sftp_tx, _) = tokio::sync::mpsc::unbounded_channel();
        SessionHandle {
            session_id: session_id.into(),
            server_id: server_id.into(),
            server_name: format!("name of {server_id}"),
            host: "127.0.0.1".into(),
            port: 22,
            started_at_ms,
            input_tx,
            resize_tx,
            sftp_tx,
        }
    }

    /// What the SFTP transfer queue
    /// asks the registry - which saved server a session belongs to (stamped on
    /// every queued job) and every live session with its server and start
    /// time (what a paused job is re-pointed at after a reconnect).
    #[test]
    fn ru6a_the_registry_reports_each_live_session_with_its_saved_server() {
        let registry = SessionRegistry::new();
        for (sid, server, started) in [
            ("s1", "srv-a", 10),
            ("s2", "srv-b", 20),
            ("s3", "srv-a", 30),
        ] {
            registry.insert(session(sid, server, started));
        }
        assert_eq!(registry.server_id_of("s2").as_deref(), Some("srv-b"));
        assert_eq!(registry.server_id_of("s3").as_deref(), Some("srv-a"));
        assert_eq!(registry.server_id_of("never-opened"), None);
        let mut live = registry.live_server_sessions();
        live.sort();
        assert_eq!(
            live,
            vec![
                ("s1".to_string(), "srv-a".to_string(), 10),
                ("s2".to_string(), "srv-b".to_string(), 20),
                ("s3".to_string(), "srv-a".to_string(), 30),
            ]
        );
        // A closed session is gone from both answers.
        session_disconnect(&registry, "s1");
        assert_eq!(registry.server_id_of("s1"), None);
        let mut live = registry.live_server_sessions();
        live.sort();
        assert_eq!(
            live.iter().map(|(s, _, _)| s.as_str()).collect::<Vec<_>>(),
            vec!["s2", "s3"]
        );
        registry.kill_all();
        assert!(registry.live_server_sessions().is_empty());
    }
}

/// UTF-8 decoding of terminal output (A7-08), the one fingerprint format
/// (A7-46), host-key outcomes (A7-14), connect/auth deadlines (A7-15),
/// keyboard-interactive answers (A6-11) and disconnect safety (A2-12) -
/// against an in-process russh server on 127.0.0.1 with a throwaway host key
/// and a scripted trust prompt: no real host, account or credential.
#[cfg(test)]
mod ru4_tests {
    use super::*;
    use crate::crypto::keys::{export_private_key, generate_key_pair, KeyFormat, KeyType};
    use russh::server::{Auth, Response};
    use std::borrow::Cow;
    use tokio::io::AsyncReadExt;

    const SAMPLE: &str = "é€😀";
    const FIXTURE_PASSWORD: &str = "fixture-password-é€😀";
    /// For the tests that wait for a deadline to RUN OUT: short, so they do
    /// not drag.
    const TEST_DEADLINES: Deadlines = Deadlines {
        connect: Duration::from_millis(400),
        auth: Duration::from_millis(400),
    };
    /// For every test whose handshake has to COMPLETE - connected, or refused
    /// for a host-key or authentication reason. A loopback handshake (key
    /// exchange, an Ed25519 signature, authentication) needs milliseconds on
    /// an idle machine but far more than 400 ms of wall time when the CPU is
    /// busy: the full suite runs 16 tests at once, several of them Argon2 or
    /// RSA key generation, and these tests used [`TEST_DEADLINES`] - so they
    /// failed now and then with "Timed out connecting to 127.0.0.1:<port>."
    /// (reproduced with six busy loops sharing the test's CPU: 5 of 6 runs).
    /// Their outcome is not a timeout, so their deadline is far above any
    /// scheduling delay.
    const HANDSHAKE_DEADLINES: Deadlines = Deadlines {
        connect: Duration::from_secs(20),
        auth: Duration::from_secs(20),
    };
    /// The trust-dialog test needs a connect deadline SHORTER than the time
    /// the scripted dialog stays open (that is what it proves is not
    /// counted), yet long enough for the network part of a handshake on a
    /// machine saturated by other builds and suites.
    const DIALOG_TEST_DEADLINES: Deadlines = Deadlines {
        connect: Duration::from_secs(10),
        auth: Duration::from_secs(20),
    };
    /// Upper bound for one test's connect, so a missing deadline fails the
    /// test instead of hanging the suite (above every deadline used here).
    const GUARD: Duration = Duration::from_secs(60);

    // ── A7-08: a character split across SSH packets ─────────────────────────

    fn decode(chunks: &[&[u8]]) -> String {
        let mut stream = Utf8Stream::default();
        let mut out = String::new();
        for chunk in chunks {
            out.push_str(&stream.push(chunk));
        }
        out.push_str(&stream.finish());
        out
    }

    #[test]
    fn ru4_utf8_sample_survives_a_split_at_every_byte_offset() {
        let bytes = SAMPLE.as_bytes();
        for cut in 0..=bytes.len() {
            assert_eq!(
                decode(&[&bytes[..cut], &bytes[cut..]]),
                SAMPLE,
                "cut at {cut}"
            );
        }
    }

    #[test]
    fn ru4_utf8_sample_survives_every_two_cut_split_and_single_bytes() {
        let b = SAMPLE.as_bytes();
        for i in 0..=b.len() {
            for j in i..=b.len() {
                assert_eq!(
                    decode(&[&b[..i], &b[i..j], &b[j..]]),
                    SAMPLE,
                    "cuts {i},{j}"
                );
            }
        }
        let singles: Vec<&[u8]> = b.chunks(1).collect();
        assert_eq!(decode(&singles), SAMPLE);
    }

    /// Only genuinely invalid bytes become U+FFFD - exactly as decoding the
    /// whole stream at once would, wherever the packets were cut.
    #[test]
    fn ru4_utf8_invalid_bytes_decode_like_the_whole_stream_at_every_split() {
        let cases: [&[u8]; 7] = [
            b"a\xffb",
            b"\x80",
            b"\xe2\x28\xa1",
            b"\xf0\x9f\x98",
            b"\xf0\x9f\x98A",
            b"ok \xc3\xa9 \xed\xa0\x80 end",
            b"\xe2\x82\xac\xe2\x82",
        ];
        for whole in cases {
            let want = String::from_utf8_lossy(whole).into_owned();
            for cut in 0..=whole.len() {
                assert_eq!(
                    decode(&[&whole[..cut], &whole[cut..]]),
                    want,
                    "{whole:?} cut at {cut}"
                );
            }
        }
    }

    #[test]
    fn ru4_utf8_incomplete_tail_waits_for_the_next_packet() {
        let mut stream = Utf8Stream::default();
        assert_eq!(stream.push(b"x\xe2\x82"), "x");
        assert_eq!(stream.push(b"\xac y"), "\u{20ac} y");
        assert_eq!(stream.push(b"\xf0\x9f"), "");
        assert_eq!(
            stream.finish(),
            "\u{FFFD}",
            "a cut-off character at the end is invalid"
        );
        assert_eq!(stream.finish(), "");
    }

    // ── A7-46: one fingerprint format ───────────────────────────────────────

    #[test]
    fn ru4_fingerprint_of_blob_is_the_ssh_keygen_form() {
        let blob = [0u8, 1, 2, 3, 250, 251, 252];
        let b64 = base64ct::Base64::encode_string(&blob);
        let want = crate::crypto::utils::ssh_fingerprint_sha256(&blob);
        assert!(
            want.starts_with("SHA256:") && !want.ends_with('='),
            "{want}"
        );
        assert_eq!(fingerprint_of_blob(&b64).as_deref(), Some(want.as_str()));
        assert_eq!(hostkey_fingerprint_display(&b64), want);
        assert_eq!(fingerprint_of_blob("not base64!"), None);
        assert_eq!(hostkey_fingerprint_display("not base64!"), "?");
    }

    #[test]
    fn ru4_stored_fingerprints_normalize_to_the_labelled_unpadded_form() {
        let blob = b"fixture host key blob";
        let b64 = base64ct::Base64::encode_string(blob);
        let want = crate::crypto::utils::ssh_fingerprint_sha256(blob);
        let bare = want["SHA256:".len()..].to_string();
        let padded = format!("{bare}=");
        for old in [
            padded.clone(),
            format!("SHA256:{padded}"),
            bare,
            want.clone(),
        ] {
            assert_eq!(normalize_fingerprint(&old), want, "{old}");
            assert_eq!(known_host_fingerprint(&b64, &old), want, "{old}");
        }
        // The pinned key decides, not text a crafted backup carried.
        assert_eq!(known_host_fingerprint(&b64, "SHA256:forged"), want);
        // An unreadable key blob keeps the stored text, normalized if it is
        // a SHA-256 fingerprint.
        assert_eq!(known_host_fingerprint("%%%", &padded), want);
        assert_eq!(normalize_fingerprint("aa:bb:cc"), "aa:bb:cc");
        assert_eq!(known_host_fingerprint("%%%", "aa:bb:cc"), "aa:bb:cc");
    }

    // ── A7-15: the trust dialog is user time, not network time ──────────────

    /// The network's 100 ms fit its 1 s, the dialog's 1.5 s do not: counted,
    /// they would time the handshake out. The 0.9 s to spare are for a
    /// loaded machine, whose timers wake late.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ru4_network_deadline_excludes_time_in_the_trust_dialog() {
        let watch = Arc::new(HandshakeWatch::default());
        let in_dialog = watch.clone();
        let handshake = async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            {
                let _open = in_dialog.dialog_open();
                tokio::time::sleep(Duration::from_millis(1500)).await;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
            "done"
        };
        assert_eq!(
            within_network_time(Duration::from_secs(1), &watch, handshake).await,
            Some("done")
        );

        let idle = HandshakeWatch::default();
        let started = Instant::now();
        let never = std::future::pending::<()>();
        assert_eq!(
            within_network_time(Duration::from_millis(300), &idle, never).await,
            None
        );
        assert!(started.elapsed() >= Duration::from_millis(300));
        assert!(started.elapsed() < Duration::from_secs(15));
    }

    // ── in-process SSH server ────────────────────────────────────────────────

    #[derive(Clone, Copy, Default)]
    struct Behaviour {
        stall_auth: bool,
        second_kbd_round: bool,
    }

    struct FixtureHandler {
        behaviour: Behaviour,
        kbd_rounds: usize,
    }

    fn password_prompt() -> Auth {
        Auth::Partial {
            name: Cow::Borrowed(""),
            instructions: Cow::Borrowed(""),
            prompts: Cow::Owned(vec![(Cow::Borrowed("Password: "), false)]),
        }
    }

    impl russh::server::Handler for FixtureHandler {
        type Error = russh::Error;

        async fn auth_password(
            &mut self,
            _user: &str,
            password: &str,
        ) -> Result<Auth, Self::Error> {
            if self.behaviour.stall_auth {
                std::future::pending::<()>().await;
            }
            Ok(if password == FIXTURE_PASSWORD {
                Auth::Accept
            } else {
                Auth::reject()
            })
        }

        async fn auth_keyboard_interactive<'a>(
            &'a mut self,
            _user: &str,
            _submethods: &str,
            response: Option<Response<'a>>,
        ) -> Result<Auth, Self::Error> {
            let Some(response) = response else {
                return Ok(password_prompt());
            };
            self.kbd_rounds += 1;
            let answers: Vec<Vec<u8>> = response.map(|b| b.to_vec()).collect();
            if self.behaviour.second_kbd_round && self.kbd_rounds == 1 {
                return Ok(password_prompt());
            }
            Ok(if answers == [FIXTURE_PASSWORD.as_bytes().to_vec()] {
                Auth::Accept
            } else {
                Auth::reject()
            })
        }
    }

    struct FixtureServer {
        port: u16,
        blob_b64: String,
        openssh_public: String,
    }

    async fn start_server(behaviour: Behaviour) -> FixtureServer {
        let key = generate_key_pair(KeyType::Ed25519, None, "ru4-fixture-host".into()).unwrap();
        let pem = export_private_key(&key, KeyFormat::OpenSsh, None).unwrap();
        let host_key = russh::keys::decode_secret_key(&pem, None).unwrap();
        let public = host_key.public_key().clone();
        let blob_b64 = base64ct::Base64::encode_string(&public.to_bytes().unwrap());
        let openssh_public = public.to_openssh().unwrap();
        let config = Arc::new(russh::server::Config {
            keys: vec![host_key],
            auth_rejection_time: Duration::ZERO,
            auth_rejection_time_initial: Some(Duration::ZERO),
            ..Default::default()
        });
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                let config = config.clone();
                let handler = FixtureHandler {
                    behaviour,
                    kbd_rounds: 0,
                };
                tokio::spawn(async move {
                    if let Ok(running) = russh::server::run_stream(config, socket, handler).await {
                        let _ = running.await;
                    }
                });
            }
        });
        FixtureServer {
            port,
            blob_b64,
            openssh_public,
        }
    }

    /// A TCP server that accepts and then never completes a handshake:
    /// silent, or a banner followed by silence. The receiver fires once the
    /// client closed its end - a timed-out handshake must not linger.
    async fn stalling_server(
        banner: Option<&'static [u8]>,
    ) -> (u16, tokio::sync::oneshot::Receiver<()>) {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let (closed_tx, closed_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            if let Some(banner) = banner {
                use tokio::io::AsyncWriteExt;
                socket.write_all(banner).await.unwrap();
            }
            let mut buf = [0u8; 4096];
            while let Ok(n) = socket.read(&mut buf).await {
                if n == 0 {
                    break;
                }
            }
            let _ = closed_tx.send(());
        });
        (port, closed_rx)
    }

    struct TestDb {
        db: Database,
        path: std::path::PathBuf,
    }

    impl Drop for TestDb {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    fn test_db() -> TestDb {
        let path =
            std::env::temp_dir().join(format!("sshspan-ru4-ssh-{}.db", uuid::Uuid::new_v4()));
        TestDb {
            db: Database::open_at(path.clone()).unwrap(),
            path,
        }
    }

    fn params(port: u16, auth_method: &str) -> ConnectParams {
        let now = chrono::Utc::now();
        ConnectParams {
            server: ServerRecord {
                id: "fixture".into(),
                name: "fixture".into(),
                host: "127.0.0.1".into(),
                port,
                username: "fixture-user".into(),
                key_id: None,
                pem_path: None,
                auth_method: auth_method.into(),
                saved_password: None,
                category_id: None,
                color: None,
                last_connected_at: None,
                created_at: now,
                updated_at: now,
                bitwarden_id: None,
                bitwarden_revision_ts: None,
                bitwarden_updated_at: None,
            },
            username: "fixture-user".into(),
            auth_method: auth_method.into(),
            key_pem: None,
            password: Some(Zeroizing::new(FIXTURE_PASSWORD.into())),
        }
    }

    /// What a scripted prompt was shown: `("host:port fingerprint", imported)`.
    type Shown = Arc<Mutex<Vec<(String, bool)>>>;

    /// A scripted trust prompt that records what it was shown and answers
    /// after `delay` (blocking, like the native dialog).
    fn prompt(answer: bool, delay: Duration) -> (HostTrustPrompt, Shown) {
        let shown = Arc::new(Mutex::new(Vec::new()));
        let seen = shown.clone();
        let prompt: HostTrustPrompt = Arc::new(move |host, port, fingerprint, imported| {
            seen.lock()
                .unwrap()
                .push((format!("{host}:{port} {fingerprint}"), imported));
            std::thread::sleep(delay);
            answer
        });
        (prompt, shown)
    }

    /// Connect with [`HANDSHAKE_DEADLINES`]: for tests whose handshake must
    /// complete.
    async fn open(
        db: &Database,
        params: ConnectParams,
        prompt: HostTrustPrompt,
    ) -> Result<Handle<TerminalHandler>, String> {
        open_within(db, params, prompt, HANDSHAKE_DEADLINES).await
    }

    async fn open_within(
        db: &Database,
        params: ConnectParams,
        prompt: HostTrustPrompt,
        deadlines: Deadlines,
    ) -> Result<Handle<TerminalHandler>, String> {
        tokio::time::timeout(GUARD, open_authenticated(&params, db, prompt, deadlines))
            .await
            .unwrap_or_else(|_| Err("test guard: open_authenticated did not finish".into()))
    }

    fn pin(db: &Database, port: u16, blob_b64: &str) {
        let fp = fingerprint_of_blob(blob_b64).unwrap();
        assert!(db
            .add_known_host(&known_host_key("127.0.0.1", port), blob_b64, &fp)
            .unwrap());
    }

    // ── A7-15: deadlines ─────────────────────────────────────────────────────

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn ru4_connect_times_out_when_the_server_never_sends_a_banner() {
        let (port, closed) = stalling_server(None).await;
        let t = test_db();
        let (prompt, shown) = prompt(true, Duration::ZERO);
        let started = Instant::now();
        let err = open_within(&t.db, params(port, "password"), prompt, TEST_DEADLINES)
            .await
            .err()
            .unwrap();
        assert_eq!(err, format!("Timed out connecting to 127.0.0.1:{port}."));
        // The test's 0.4 s deadline, not the app's 20 s one; the rest is
        // room for a loaded machine.
        assert!(started.elapsed() < Duration::from_secs(15));
        assert!(shown.lock().unwrap().is_empty());
        tokio::time::timeout(Duration::from_secs(30), closed)
            .await
            .expect("the abandoned connection was left open")
            .unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn ru4_connect_times_out_and_closes_when_key_exchange_stalls() {
        let (port, closed) = stalling_server(Some(b"SSH-2.0-ru4-stall\r\n")).await;
        let t = test_db();
        let (prompt, _) = prompt(true, Duration::ZERO);
        let err = open_within(&t.db, params(port, "password"), prompt, TEST_DEADLINES)
            .await
            .err()
            .unwrap();
        assert_eq!(err, format!("Timed out connecting to 127.0.0.1:{port}."));
        // The handshake task russh spawned owns the socket: it must be shut
        // down, not left waiting for the server forever.
        tokio::time::timeout(Duration::from_secs(30), closed)
            .await
            .expect("the abandoned key exchange kept its connection open")
            .unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn ru4_authentication_has_its_own_deadline() {
        let server = start_server(Behaviour {
            stall_auth: true,
            ..Behaviour::default()
        })
        .await;
        let t = test_db();
        pin(&t.db, server.port, &server.blob_b64);
        let (prompt, shown) = prompt(true, Duration::ZERO);
        // The authentication deadline is what runs out here; the connect half
        // gets room, so a busy machine cannot turn this into a connect timeout.
        let deadlines = Deadlines {
            connect: HANDSHAKE_DEADLINES.connect,
            auth: TEST_DEADLINES.auth,
        };
        let err = open_within(&t.db, params(server.port, "password"), prompt, deadlines)
            .await
            .err()
            .unwrap();
        assert_eq!(
            err,
            format!(
                "Timed out during authentication with 127.0.0.1:{}.",
                server.port
            )
        );
        assert!(
            shown.lock().unwrap().is_empty(),
            "a pinned key needs no prompt"
        );
    }

    /// The user reading the trust dialog for longer than the whole connect
    /// deadline is not a stalled network: the connection completes.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn ru4_trust_dialog_time_does_not_count_against_the_connect_deadline() {
        let server = start_server(Behaviour::default()).await;
        let t = test_db();
        // Open a second longer than the whole connect deadline: counted, it
        // would time the connection out.
        let in_dialog = DIALOG_TEST_DEADLINES.connect + Duration::from_secs(1);
        let (prompt, shown) = prompt(true, in_dialog);
        let session = open_within(
            &t.db,
            params(server.port, "password"),
            prompt,
            DIALOG_TEST_DEADLINES,
        )
        .await;
        assert!(session.is_ok(), "{:?}", session.err());
        assert_eq!(shown.lock().unwrap().len(), 1);
    }

    // ── A7-14: mismatch vs declined ─────────────────────────────────────────

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn ru4_pinned_key_mismatch_is_a_possible_mitm_and_never_prompts() {
        let server = start_server(Behaviour::default()).await;
        let t = test_db();
        let other = base64ct::Base64::encode_string(b"a different pinned key");
        pin(&t.db, server.port, &other);
        let (prompt, shown) = prompt(true, Duration::ZERO);
        let err = open(&t.db, params(server.port, "password"), prompt)
            .await
            .err()
            .unwrap();
        assert_eq!(
            err,
            format!(
                "Host key mismatch for 127.0.0.1:{} - possible man-in-the-middle. If the server's \
                 key really changed, forget it under Settings > Known hosts and reconnect.",
                server.port
            )
        );
        assert!(
            shown.lock().unwrap().is_empty(),
            "a mismatch must not offer a trust prompt"
        );
        let kept =
            t.db.get_known_host(&known_host_key("127.0.0.1", server.port))
                .unwrap()
                .unwrap();
        assert_eq!(kept.host_key, other, "the pin is unchanged");
        assert!(t
            .db
            .list_audit(20)
            .unwrap()
            .iter()
            .any(|a| a.action == "known_hosts.mismatch_rejected"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn ru4_declined_first_trust_is_a_cancellation_and_stores_nothing() {
        let server = start_server(Behaviour::default()).await;
        let t = test_db();
        let (prompt, shown) = prompt(false, Duration::ZERO);
        let err = open(&t.db, params(server.port, "password"), prompt)
            .await
            .err()
            .unwrap();
        assert_eq!(err, "Connection cancelled: host key not trusted.");
        assert_eq!(shown.lock().unwrap().len(), 1);
        assert!(t
            .db
            .get_known_host(&known_host_key("127.0.0.1", server.port))
            .unwrap()
            .is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn ru4_declined_imported_pin_is_a_cancellation_and_stays_imported() {
        let server = start_server(Behaviour::default()).await;
        let t = test_db();
        let host = known_host_key("127.0.0.1", server.port);
        t.db.restore_backup(&serde_json::json!({
            "known_hosts": [{
                "host": host,
                "host_key": server.blob_b64,
                "fingerprint_sha256": "SHA256:forged",
                "first_seen": chrono::Utc::now().to_rfc3339(),
            }]
        }))
        .unwrap();
        let (prompt, shown) = prompt(false, Duration::ZERO);
        let err = open(&t.db, params(server.port, "password"), prompt)
            .await
            .err()
            .unwrap();
        assert_eq!(err, "Connection cancelled: host key not trusted.");
        assert!(shown.lock().unwrap()[0].1, "asked as an imported pin");
        assert_eq!(
            t.db.get_known_host(&host).unwrap().unwrap().source,
            "imported"
        );
    }

    // ── A7-46: what the dialog shows is what is stored and what ssh-keygen prints

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn ru4_first_trust_stores_and_shows_the_ssh_keygen_fingerprint() {
        let server = start_server(Behaviour::default()).await;
        let t = test_db();
        let (prompt, shown) = prompt(true, Duration::ZERO);
        let session = open(&t.db, params(server.port, "password"), prompt).await;
        assert!(session.is_ok(), "{:?}", session.err());
        let blob = base64ct::Base64::decode_vec(&server.blob_b64).unwrap();
        let want = crate::crypto::utils::ssh_fingerprint_sha256(&blob);
        let stored =
            t.db.get_known_host(&known_host_key("127.0.0.1", server.port))
                .unwrap()
                .unwrap();
        assert_eq!(stored.fingerprint_sha256, want);
        assert_eq!(
            shown.lock().unwrap()[0].0,
            format!("127.0.0.1:{} {want}", server.port)
        );
        let audit = t.db.list_audit(20).unwrap();
        assert!(audit
            .iter()
            .any(|a| a.action == "known_hosts.trust_on_first_use" && a.details.contains(&want)));

        // Independent check against OpenSSH itself when it is installed.
        let dir = std::env::temp_dir().join(format!("sshspan-ru4-keygen-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let pubfile = dir.join("host.pub");
        std::fs::write(&pubfile, format!("{}\n", server.openssh_public)).unwrap();
        match std::process::Command::new("ssh-keygen")
            .arg("-lf")
            .arg(&pubfile)
            .output()
        {
            Ok(out) if out.status.success() => {
                let text = String::from_utf8_lossy(&out.stdout);
                let printed = text
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or_default()
                    .to_string();
                assert_eq!(printed, want, "ssh-keygen -lf: {text}");
            }
            _ => eprintln!("ssh-keygen not available: OpenSSH cross-check skipped"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── A6-11: keyboard-interactive answers ─────────────────────────────────

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn ru4_keyboard_interactive_answers_one_round_with_the_saved_password() {
        let server = start_server(Behaviour::default()).await;
        let t = test_db();
        pin(&t.db, server.port, &server.blob_b64);
        let (ok_prompt, _) = prompt(true, Duration::ZERO);
        let session = open(
            &t.db,
            params(server.port, "keyboard-interactive"),
            ok_prompt,
        )
        .await;
        assert!(session.is_ok(), "{:?}", session.err());

        let hostile = start_server(Behaviour {
            second_kbd_round: true,
            ..Behaviour::default()
        })
        .await;
        pin(&t.db, hostile.port, &hostile.blob_b64);
        let (again, _) = prompt(true, Duration::ZERO);
        let err = open(&t.db, params(hostile.port, "keyboard-interactive"), again)
            .await
            .err()
            .unwrap();
        assert!(err.contains("beyond the saved password"), "{err}");
    }

    // ── A2-12 / A5-10: a tab closed while its connect was in flight ────────

    /// The renderer disconnects the id `terminal_connect` returns once the
    /// tab is already gone. The session is registered by then; disconnecting
    /// it - twice, or an id that never existed - reaps it without a panic.
    #[tokio::test]
    async fn ru4_disconnect_reaps_a_session_whose_connect_just_returned() {
        let registry = Arc::new(SessionRegistry::new());
        let (input_tx, mut input_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
        let (resize_tx, _resize_rx) = tokio::sync::mpsc::unbounded_channel::<(u32, u32)>();
        let (sftp_tx, _sftp_rx) = tokio::sync::mpsc::unbounded_channel();
        registry.insert(SessionHandle {
            session_id: "s1".into(),
            server_id: "srv".into(),
            server_name: "fixture".into(),
            host: "127.0.0.1".into(),
            port: 22,
            started_at_ms: 0,
            input_tx,
            resize_tx,
            sftp_tx,
        });
        // The session task as `start_interactive` spawns it: it ends when the
        // input sender is dropped and then deregisters itself.
        let task_registry = registry.clone();
        let task = tokio::spawn(async move {
            while input_rx.recv().await.is_some() {}
            task_registry.remove("s1");
        });
        session_disconnect(&registry, "s1");
        session_disconnect(&registry, "s1");
        session_disconnect(&registry, "never-registered");
        tokio::time::timeout(Duration::from_secs(30), task)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(registry.len(), 0);
        assert!(session_send(&registry, "s1", vec![1]).is_err());
        assert!(session_resize(&registry, "s1", 80, 24).is_err());
    }
}
