//! IPC commands of the PMXSpan integration (INTEGRATION-SPEC v1) and of
//! Quick connect (section 6).
//!
//! - Received `sshspan://` links ([`receive`], [`handoff_take_pending`]):
//!   validated in Rust, held in memory while the vault is locked, and handed
//!   to the renderer as typed data for a dialog - never acted on.
//! - Quick connect's unsaved servers ([`quick_connect_open`],
//!   [`quick_connect_forget`]): the in-memory registry in
//!   `crate::quick_connect`.
//! - PMXSpan discovery and launching ([`pmxspan_status`],
//!   [`pmxspan_manage_server`], [`pmxspan_add_key`], ...): every
//!   `pmxspan://` URL is built here; the renderer only names a server or a
//!   key.

use std::time::Instant;

use tauri::{AppHandle, Emitter, Manager};

use super::{CmdError, CmdResult, VaultPasswordStore};
use crate::db::{self, ServerRecord};
use crate::handoff::state::{HandoffState, Proposal, Received};
use crate::handoff::{self, Bundle, Link, Origin};
use crate::pmxspan;
use crate::quick_connect::{EphemeralRegistry, EphemeralServer};
use crate::AppState;

/// The event a received link raises; the renderer answers it with
/// [`handoff_take_pending`]. No payload: what the link says is only ever
/// handed out by that command, validated.
pub const HANDOFF_EVENT: &str = "handoff-received";

// ─── receiving links ────────────────────────────────────────────────────────

/// Take in one `sshspan://` URL from the command line, a second instance or
/// the OS handler. Anything that does not look like a link is ignored; a
/// link is validated at once (a refusal is kept as its message), held - one
/// at a time, ten minutes at most - and the window is brought forward.
pub fn receive(app: &AppHandle, raw: &str) {
    let raw = raw.trim();
    if !handoff::looks_like_link(raw) {
        return;
    }
    let Some(state) = app.try_state::<HandoffState>() else {
        return;
    };
    let now = Instant::now();
    if state.is_duplicate(raw, now) {
        return;
    }
    let received = match handoff::parse_link(raw) {
        Ok(_) => Received::Url(raw.to_string()),
        Err(message) => Received::Refused(message),
    };
    if let Some(app_state) = app.try_state::<AppState>() {
        let detail = match &received {
            Received::Url(url) => link_summary(url),
            Received::Refused(why) => format!("refused: {why}"),
        };
        super::audit_or_log(&app_state.db, "handoff.received", None, &detail);
    }
    state.hold(received, now);
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
    let _ = app.emit(HANDOFF_EVENT, ());
}

/// What the audit log says about a valid link: its action and target, no
/// host keys.
fn link_summary(url: &str) -> String {
    match handoff::parse_link(url) {
        Ok(Link::Connect(c)) => format!(
            "connect {}@{}:{} (source {})",
            c.user,
            c.host,
            c.port,
            c.source.as_deref().unwrap_or("-")
        ),
        Ok(Link::Import(i)) => format!(
            "import {} (source {})",
            i.bundle.display(),
            i.source.as_deref().unwrap_or("-")
        ),
        Err(why) => format!("refused: {why}"),
    }
}

/// The link waiting for the renderer, as typed data for its dialog:
///
/// - `{kind: "none"}` - nothing waits;
/// - `{kind: "error", message}` - a link was refused (shown locked or not);
/// - `{kind: "waiting"}` - a link waits for the vault to be unlocked (it is
///   kept, and taken by the call after the unlock);
/// - `{kind: "connect", token, link, match}` - for the Quick connect dialog;
/// - `{kind: "import", cluster, rows, ...}` - for the import dialog.
#[tauri::command]
pub async fn handoff_take_pending(app: AppHandle) -> CmdResult<serde_json::Value> {
    let state = app.state::<HandoffState>();
    let now = Instant::now();
    if state.pending_is_refusal() {
        if let Some(Received::Refused(message)) = state.take(now) {
            return Ok(serde_json::json!({ "kind": "error", "message": message }));
        }
    }
    if !app.state::<VaultPasswordStore>().is_set() {
        let kind = if state.has_pending(now) {
            "waiting"
        } else {
            "none"
        };
        return Ok(serde_json::json!({ "kind": kind }));
    }
    let Some(Received::Url(url)) = state.take(now) else {
        return Ok(serde_json::json!({ "kind": "none" }));
    };
    let link = match handoff::parse_link(&url) {
        Ok(link) => link,
        Err(message) => return Ok(serde_json::json!({ "kind": "error", "message": message })),
    };
    let worker = app.clone();
    super::run_blocking(move || {
        let db = &worker.state::<AppState>().db;
        let handoff = worker.state::<HandoffState>();
        match link {
            Link::Connect(c) => connect_offer(db, &handoff, &c, Instant::now()),
            Link::Import(i) => {
                let bundle = match handoff::read_bundle(&i.bundle, &i.sha256, chrono::Utc::now()) {
                    Ok(bundle) => bundle,
                    Err(message) => {
                        super::audit_or_log(db, "handoff.import_refused", None, &message);
                        return Ok(serde_json::json!({ "kind": "error", "message": message }));
                    }
                };
                // Read: the file has served its purpose (best effort).
                let _ = std::fs::remove_file(&i.bundle);
                super::audit_or_log(
                    db,
                    "handoff.import_read",
                    None,
                    &format!(
                        "{} host(s) from cluster {}",
                        bundle.hosts.len(),
                        bundle.cluster.id
                    ),
                );
                import_listing(db, &handoff, &bundle, Instant::now())
            }
        }
    })
    .await
}

/// A saved server that already is the host a link or bundle row names:
/// the same origin cluster and guest first, else the same host, port and
/// user.
pub(crate) fn find_saved_match<'a>(
    servers: &'a [ServerRecord],
    origins: &std::collections::HashMap<String, db::ServerOrigin>,
    host: &str,
    port: u16,
    user: &str,
    origin: Option<&Origin>,
) -> Option<&'a ServerRecord> {
    if let Some(o) = origin {
        let same_origin = servers.iter().find(|s| {
            origins.get(&s.id).is_some_and(|so| {
                so.cluster_id == o.cluster_id
                    && match o.guest_kind.as_str() {
                        "node" => so.guest_kind == "node" && so.node == o.node,
                        _ => so.guest_kind != "node" && so.vmid.is_some() && so.vmid == o.vmid,
                    }
            })
        });
        if same_origin.is_some() {
            return same_origin;
        }
    }
    servers.iter().find(|s| {
        s.host.trim().eq_ignore_ascii_case(host) && s.port == port && s.username.trim() == user
    })
}

/// The Quick connect offer for a `connect` link.
fn connect_offer(
    db: &db::Database,
    handoff: &HandoffState,
    link: &handoff::ConnectLink,
    now: Instant,
) -> CmdResult<serde_json::Value> {
    let servers = db.list_servers().map_err(|e| e.to_string())?;
    let origins = db.server_origins().map_err(|e| e.to_string())?;
    let matched = find_saved_match(
        &servers,
        &origins,
        &link.host,
        link.port,
        &link.user,
        link.origin.as_ref(),
    );
    let token = handoff.propose(Proposal::from_connect(link), now);
    let from_pmxspan = link
        .source
        .as_deref()
        .is_some_and(|s| s.eq_ignore_ascii_case(handoff::ORIGIN_PMXSPAN));
    Ok(serde_json::json!({
        "kind": "connect",
        "token": token,
        "link": {
            "host": link.host,
            "port": link.port,
            "user": link.user,
            "name": link.name,
            "source": link.source,
            "fromPmxspan": from_pmxspan,
            "origin": link.origin,
            "pool": link.pool,
            "hostKeys": link.host_keys.iter().map(|k| serde_json::json!({
                "type": handoff::key_type_of(k),
                "fingerprint": crate::ssh_client::hostkey_fingerprint_display(k),
            })).collect::<Vec<_>>(),
            "hostKeyRotated": link.host_key_rotated,
        },
        "match": matched.map(|s| serde_json::json!({ "id": s.id, "name": s.name })),
    }))
}

/// The host-key status of one bundle row against the pin stored for its
/// host:port: `none` (PMXSpan has no key for it), `new` (no pin yet),
/// `unchanged` (the pin is a proposed key), `rotated` (a different pin and
/// PMXSpan reports a rebuild: the connect will ask to replace it) or
/// `conflict` (a different pin and no rotation: the connect refuses as for
/// any changed key).
pub(crate) fn host_key_status(db: &db::Database, row: &handoff::BundleHost) -> serde_json::Value {
    if row.host_keys.is_empty() {
        return serde_json::json!({ "status": "none" });
    }
    let pin = db
        .get_known_host(&crate::ssh_client::known_host_key(&row.host, row.port))
        .ok()
        .flatten();
    let new_fp = row.host_keys[0].fingerprint.clone();
    match pin {
        None => serde_json::json!({ "status": "new", "new": new_fp }),
        Some(pin) if row.host_keys.iter().any(|k| k.key == pin.host_key) => {
            serde_json::json!({ "status": "unchanged" })
        }
        Some(pin) => serde_json::json!({
            "status": if row.host_key_rotated.is_some() { "rotated" } else { "conflict" },
            "old": crate::ssh_client::hostkey_fingerprint_display(&pin.host_key),
            "new": new_fp,
        }),
    }
}

/// The import dialog's rows for a validated bundle: each importable row
/// with a proposal token (what `server_save` attaches with `originToken`),
/// its host-key status and whether SSHSpan already has it; each other row
/// with the reason it cannot be imported.
pub(crate) fn import_listing(
    db: &db::Database,
    handoff: &HandoffState,
    bundle: &Bundle,
    now: Instant,
) -> CmdResult<serde_json::Value> {
    let servers = db.list_servers().map_err(|e| e.to_string())?;
    let origins = db.server_origins().map_err(|e| e.to_string())?;
    let rows: Vec<serde_json::Value> = bundle
        .hosts
        .iter()
        .map(|row| {
            let base = serde_json::json!({
                "index": row.index,
                "kind": row.kind,
                "vmid": row.vmid,
                "node": row.node,
                "name": row.name,
                "host": row.host,
                "port": row.port,
                "user": row.user,
                "pool": row.pool,
                "category": row.category,
            });
            let mut obj = base.as_object().cloned().unwrap_or_default();
            if let Some(problem) = &row.problem {
                obj.insert("problem".into(), serde_json::json!(problem));
                return serde_json::Value::Object(obj);
            }
            let origin = row.origin(&bundle.cluster);
            let matched = find_saved_match(
                &servers,
                &origins,
                &row.host,
                row.port,
                &row.user,
                Some(&origin),
            );
            let token =
                Proposal::from_bundle_row(bundle, row.index).map(|p| handoff.propose(p, now));
            obj.insert("token".into(), serde_json::json!(token));
            obj.insert("hostKey".into(), host_key_status(db, row));
            obj.insert(
                "alreadySaved".into(),
                serde_json::json!(
                    matched.map(|s| serde_json::json!({ "id": s.id, "name": s.name }))
                ),
            );
            serde_json::Value::Object(obj)
        })
        .collect();
    Ok(serde_json::json!({
        "kind": "import",
        "cluster": bundle.cluster,
        "pmxspanVersion": bundle.pmxspan_version,
        "rows": rows,
    }))
}

/// Attach what a link or bundle row proposed to the server just saved as
/// `server_id` (`server_save`'s `originToken`): the PMXSpan origin, and -
/// when the saved server still points at the proposal's host and port - the
/// proposed host keys, stored as proposals the host-key check verifies at
/// the first connect. Never a pin. Returns what it attached, for the audit.
pub(crate) fn apply_proposal(
    db: &db::Database,
    server_id: &str,
    proposal: &Proposal,
) -> CmdResult<Option<String>> {
    let Some(server) = db.get_server(server_id).map_err(|e| e.to_string())? else {
        return Ok(None);
    };
    let mut said = Vec::new();
    if let Some(origin) = proposal.origin.as_ref().filter(|o| o.is_valid()) {
        db.set_server_origin(server_id, Some(origin))
            .map_err(|e| e.to_string())?;
        said.push(format!(
            "PMXSpan {} / {}",
            origin.cluster_name.as_deref().unwrap_or(&origin.cluster_id),
            origin
                .vmid
                .map(|v| v.to_string())
                .or_else(|| origin.node.clone())
                .unwrap_or_default()
        ));
    }
    let same_target =
        server.host.trim().eq_ignore_ascii_case(&proposal.host) && server.port == proposal.port;
    if same_target && !proposal.host_keys.is_empty() {
        db.replace_proposed_host_keys(
            &crate::ssh_client::known_host_key(&proposal.host, proposal.port),
            &proposal.host_keys,
            proposal.rotated_at,
            handoff::ORIGIN_PMXSPAN,
        )
        .map_err(|e| e.to_string())?;
        said.push(format!("{} proposed host key(s)", proposal.host_keys.len()));
    }
    if said.is_empty() {
        return Ok(None);
    }
    let detail = format!("{}: {}", server.name, said.join(", "));
    super::audit_or_log(db, "server.origin", None, &detail);
    Ok(Some(detail))
}

/// The proposal `token` names, or the error to show.
pub(crate) fn proposal_for(app: &AppHandle, token: &str) -> CmdResult<Proposal> {
    app.state::<HandoffState>()
        .proposal(token, Instant::now())
        .ok_or_else(|| {
            CmdError(
                "The link from PMXSpan has expired (or the vault was locked) - send it again."
                    .into(),
            )
        })
}

// ─── Quick connect ──────────────────────────────────────────────────────────

/// What Quick connect asks for, checked like a server dialog save.
pub(crate) struct QuickConnectRequest {
    pub host: String,
    pub port: Option<u16>,
    pub username: String,
    pub auth_method: Option<String>,
    pub key_id: Option<String>,
    pub pem_path: Option<String>,
    pub password: Option<zeroize::Zeroizing<String>>,
    pub proposal: Option<Proposal>,
}

/// Register an unsaved Quick connect server: the server dialog's checks
/// (host, user name, port, auth method, a key or a key file for key
/// login), then a record named `user@host` in the ephemeral registry. The
/// password, if one was typed, stays with the record in memory. Proposed
/// host keys come along only for the host and port they were proposed for.
pub(crate) fn quick_connect_open_in(
    db: &db::Database,
    vault: &VaultPasswordStore,
    registry: &EphemeralRegistry,
    request: QuickConnectRequest,
) -> CmdResult<serde_json::Value> {
    super::require_unlocked(vault)?;
    let host = request.host.trim().to_string();
    let username = request.username.trim().to_string();
    if host.is_empty() {
        return Err("Host is required.".into());
    }
    if host.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err("The host cannot hold spaces or control characters.".into());
    }
    if username.is_empty() {
        return Err("Username is required.".into());
    }
    if username.chars().any(char::is_control) {
        return Err("The username cannot hold control characters.".into());
    }
    let port = request.port.unwrap_or(22);
    if port == 0 {
        return Err("Port must be between 1 and 65535.".into());
    }
    let method = request.auth_method.unwrap_or_else(|| "publickey".into());
    if !matches!(
        method.as_str(),
        "publickey" | "password" | "keyboard-interactive"
    ) {
        return Err(format!("Unknown auth method: {method}").into());
    }
    let key_id = request
        .key_id
        .map(|k| k.trim().to_string())
        .filter(|k| !k.is_empty() && method == "publickey");
    let pem_path = request
        .pem_path
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty() && method == "publickey");
    if method == "publickey" && key_id.is_none() && pem_path.is_none() {
        return Err("Choose a key for publickey auth (or pick a .pem file).".into());
    }
    let key_meta = match &key_id {
        Some(kid) => Some(
            db.get_key_name(kid)
                .map_err(|e| e.to_string())?
                .ok_or_else(|| CmdError("The chosen vault key no longer exists.".into()))?,
        ),
        None => None,
    };
    let password = request
        .password
        .filter(|p| !p.is_empty() && method != "publickey");
    let host_key_proposal = request
        .proposal
        .as_ref()
        .filter(|p| p.host.eq_ignore_ascii_case(&host) && p.port == port)
        .and_then(Proposal::host_key_proposal);
    let now = chrono::Utc::now();
    let record = ServerRecord {
        id: String::new(),
        name: format!("{username}@{host}"),
        host: host.clone(),
        port,
        username: username.clone(),
        key_id: key_id.clone(),
        pem_path: pem_path.clone(),
        auth_method: method.clone(),
        saved_password: None,
        category_id: None,
        color: None,
        last_connected_at: None,
        created_at: now,
        updated_at: now,
        bitwarden_id: None,
        bitwarden_revision_ts: None,
        bitwarden_updated_at: None,
    };
    let has_password = password.is_some();
    let warning = record
        .pem_path
        .as_deref()
        .filter(|_| record.key_id.is_none())
        .and_then(super::server::key_file_warning);
    let id = registry
        .insert(EphemeralServer {
            record: record.clone(),
            password,
            proposal: host_key_proposal,
        })
        .map_err(CmdError)?;
    Ok(serde_json::json!({
        "ok": true,
        "warning": warning,
        "server": {
            "id": id,
            "name": record.name,
            "host": host,
            "port": port,
            "username": username,
            "authMethod": method,
            "keyId": key_id,
            "keyName": key_meta.as_ref().map(|m| m.0.clone()),
            "keyType": key_meta.as_ref().map(|m| m.1.clone()),
            "keyMissing": false,
            "pemPath": pem_path,
            // Typed in the dialog: Reconnect uses it without asking again.
            "hasSavedPassword": has_password,
            "categoryId": null,
            "ephemeral": true,
        },
    }))
}

/// Quick connect without saving: an ephemeral server for the tab
/// (INTEGRATION-SPEC section 6). `handoffToken` names the `connect` link
/// the dialog was opened for, whose proposed host keys then apply.
#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub fn quick_connect_open(
    app: AppHandle,
    host: String,
    port: Option<u16>,
    username: String,
    auth_method: Option<String>,
    key_id: Option<String>,
    pem_path: Option<String>,
    password: Option<String>,
    handoff_token: Option<String>,
) -> CmdResult<serde_json::Value> {
    let password = password.map(zeroize::Zeroizing::new);
    let proposal = match handoff_token.as_deref().filter(|t| !t.is_empty()) {
        Some(token) => Some(proposal_for(&app, token)?),
        None => None,
    };
    quick_connect_open_in(
        &app.state::<AppState>().db,
        &app.state::<VaultPasswordStore>(),
        &app.state::<EphemeralRegistry>(),
        QuickConnectRequest {
            host,
            port,
            username,
            auth_method,
            key_id,
            pem_path,
            password,
            proposal,
        },
    )
}

/// Forget an ephemeral server - the last tab using it closed, or it was
/// saved. Its password is zeroized as it goes.
#[tauri::command]
pub fn quick_connect_forget(app: AppHandle, id: String) -> CmdResult<serde_json::Value> {
    let forgotten = app.state::<EphemeralRegistry>().remove(&id);
    Ok(serde_json::json!({ "ok": true, "forgotten": forgotten }))
}

/// Create (or find) the host category path `path` ("/"-separated, top
/// first) for an import's target category, and return the leaf's id.
#[tauri::command]
pub fn category_ensure_host_path(app: AppHandle, path: String) -> CmdResult<serde_json::Value> {
    category_ensure_host_path_in(
        &app.state::<AppState>().db,
        &app.state::<VaultPasswordStore>(),
        &path,
    )
}

/// The longest category path an import creates.
const MAX_CATEGORY_DEPTH: usize = 8;

pub(crate) fn category_ensure_host_path_in(
    db: &db::Database,
    vault: &VaultPasswordStore,
    path: &str,
) -> CmdResult<serde_json::Value> {
    super::require_unlocked(vault)?;
    let segments: Vec<String> = path
        .split('/')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if segments.is_empty() {
        return Ok(serde_json::json!({ "id": null }));
    }
    if segments.len() > MAX_CATEGORY_DEPTH {
        return Err(
            format!("A category path can have at most {MAX_CATEGORY_DEPTH} levels.").into(),
        );
    }
    for seg in &segments {
        if seg.chars().count() > handoff::MAX_NAME_CHARS || seg.chars().any(char::is_control) {
            return Err(
                "A category name must be at most 128 characters, without control characters."
                    .into(),
            );
        }
    }
    let id = db
        .ensure_category_path_scoped(&segments.join("/"), "host")
        .map_err(|e| e.to_string())?;
    Ok(serde_json::json!({ "id": id }))
}

// ─── PMXSpan discovery and launching ────────────────────────────────────────

/// The stored user path and approved path.
fn stored_paths(db: &db::Database) -> (Option<String>, Option<String>) {
    let get = |k: &str| db.get_config(k).ok().flatten().filter(|v| !v.is_empty());
    (get(pmxspan::USER_PATH_KEY), get(pmxspan::APPROVED_PATH_KEY))
}

/// The status Settings > Integrations and the menus show.
pub(crate) fn pmxspan_status_in(
    db: &db::Database,
    env: &pmxspan::DiscoveryEnv,
    scheme: impl FnOnce() -> bool,
) -> serde_json::Value {
    let (user_path, approved) = stored_paths(db);
    let user_problem = user_path
        .as_deref()
        .and_then(|p| pmxspan::validate_user_path(std::path::Path::new(p), env.windows).err());
    let detected = pmxspan::discover(env);
    let mut scheme_registered = None;
    let route = pmxspan::route(user_path.as_deref(), approved.as_deref(), env, || {
        let r = scheme();
        scheme_registered = Some(r);
        r
    });
    let (kind, path, is_approved) = match &route {
        pmxspan::Route::UserPath(p) => ("user", Some(p.display().to_string()), true),
        pmxspan::Route::Discovered { path, approved } => {
            ("detected", Some(path.display().to_string()), *approved)
        }
        pmxspan::Route::Scheme => ("scheme", None, true),
        pmxspan::Route::None => ("none", None, false),
    };
    let register_links = db
        .get_config("setting.deepLinkRegister")
        .ok()
        .flatten()
        .is_none_or(|v| v != "false");
    serde_json::json!({
        "available": kind != "none",
        "route": kind,
        "path": path,
        "approved": is_approved,
        "userPath": user_path,
        "userPathProblem": user_problem,
        "detectedPath": detected.map(|p| p.display().to_string()),
        "schemeRegistered": scheme_registered,
        "hint": (kind == "none").then_some(pmxspan::NOT_FOUND_HINT),
        "registerLinks": register_links,
    })
}

/// Whether PMXSpan can be reached, and how (spec section 1). Looks at the
/// disk (and on Linux runs `xdg-mime`), so it runs on the blocking pool and
/// only when asked - never at startup.
#[tauri::command]
pub async fn pmxspan_status(app: AppHandle) -> CmdResult<serde_json::Value> {
    super::run_blocking(move || {
        Ok(pmxspan_status_in(
            &app.state::<AppState>().db,
            &pmxspan::DiscoveryEnv::from_system(),
            pmxspan::scheme_registered,
        ))
    })
    .await
}

/// Set the path to PMXSpan with a native file dialog (the path never comes
/// from the page), validated (spec section 1). A path set here is started
/// without a further question.
#[tauri::command]
pub async fn pmxspan_pick_path(app: AppHandle) -> CmdResult<serde_json::Value> {
    use tauri_plugin_dialog::DialogExt;
    super::require_unlocked(&app.state::<VaultPasswordStore>())?;
    let worker = app.clone();
    let picked = super::run_blocking(move || {
        Ok(worker
            .dialog()
            .file()
            .set_title("Choose the PMXSpan program")
            .blocking_pick_file())
    })
    .await?;
    let Some(picked) = picked else {
        return Ok(serde_json::json!({ "canceled": true }));
    };
    let path = picked
        .into_path()
        .map_err(|_| CmdError("That location is not a file on this computer.".into()))?;
    pmxspan::validate_user_path(&path, cfg!(windows)).map_err(CmdError)?;
    super::require_unlocked(&app.state::<VaultPasswordStore>())?;
    let db = &app.state::<AppState>().db;
    let shown = path.display().to_string();
    db.set_config(pmxspan::USER_PATH_KEY, &shown)
        .map_err(|e| e.to_string())?;
    super::audit_or_log(db, "pmxspan.path_set", None, &shown);
    Ok(serde_json::json!({ "canceled": false, "path": shown }))
}

/// Forget the path set in Settings (discovery applies again).
#[tauri::command]
pub fn pmxspan_clear_path(app: AppHandle) -> CmdResult<serde_json::Value> {
    super::require_unlocked(&app.state::<VaultPasswordStore>())?;
    let db = &app.state::<AppState>().db;
    db.set_config(pmxspan::USER_PATH_KEY, "")
        .map_err(|e| e.to_string())?;
    super::audit_or_log(db, "pmxspan.path_cleared", None, "");
    Ok(serde_json::json!({ "ok": true }))
}

/// Deliver `url` to PMXSpan by the route of [`pmxspan::route`], asking
/// first for a discovered path not yet approved. `what` names the action
/// for the audit log. Blocks (a dialog, a spawn): blocking pool only.
#[allow(clippy::too_many_arguments)]
pub(crate) fn launch_in(
    db: &db::Database,
    questions: &super::CredentialQuestions,
    env: &pmxspan::DiscoveryEnv,
    url: &str,
    what: &str,
    ask: super::ConfirmCredential<'_>,
    spawn: &dyn Fn(&std::path::Path, &str) -> std::io::Result<()>,
    open_url: &dyn Fn(&str) -> std::io::Result<()>,
) -> CmdResult<serde_json::Value> {
    use super::CredentialAnswer;
    let (user_path, approved) = stored_paths(db);
    let route = pmxspan::route(
        user_path.as_deref(),
        approved.as_deref(),
        env,
        pmxspan::scheme_registered,
    );
    let (path, via) = match route {
        pmxspan::Route::UserPath(p) => (Some(p), "the path set in Settings"),
        pmxspan::Route::Discovered {
            path,
            approved: true,
        } => (Some(path), "the approved path"),
        pmxspan::Route::Discovered {
            path,
            approved: false,
        } => {
            let Some(_turn) = questions.begin() else {
                return Err("Another question is open - answer it first.".into());
            };
            let kind = super::QuestionKind::PmxspanLaunch;
            if questions.declined_lately(kind).is_some() {
                return Err(
                    "Starting PMXSpan was not allowed a moment ago - wait half a minute, or set its path in Settings > Integrations."
                        .into(),
                );
            }
            let shown = path.display().to_string();
            match ask(&pmxspan::launch_question(&path)) {
                CredentialAnswer::Allowed => {
                    db.set_config(pmxspan::APPROVED_PATH_KEY, &shown)
                        .map_err(|e| e.to_string())?;
                    super::audit_or_log(db, "pmxspan.path_approved", None, &shown);
                }
                CredentialAnswer::TooQuick => {
                    return Err("PMXSpan was not started: the question was answered within a second of opening - too fast to be a decision.".into());
                }
                CredentialAnswer::NotAllowed => {
                    questions.record_decline(kind, &shown);
                    super::audit_or_log(db, "pmxspan.path_declined", None, &shown);
                    return Err("PMXSpan was not started.".into());
                }
            }
            (Some(path), "the discovered path")
        }
        pmxspan::Route::Scheme => (None, "the pmxspan:// handler"),
        pmxspan::Route::None => return Err(pmxspan::NOT_FOUND_HINT.into()),
    };
    match &path {
        Some(p) => spawn(p, url).map_err(|e| format!("Could not start PMXSpan: {e}"))?,
        None => open_url(url).map_err(|e| format!("Could not open PMXSpan: {e}"))?,
    }
    let target = path
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "pmxspan://".into());
    super::audit_or_log(
        db,
        "pmxspan.launch",
        None,
        &format!("{what} via {via} ({target})"),
    );
    Ok(serde_json::json!({ "ok": true }))
}

async fn launch(app: AppHandle, url: String, what: String) -> CmdResult<serde_json::Value> {
    super::run_blocking(move || {
        let ask_app = app.clone();
        launch_in(
            &app.state::<AppState>().db,
            &app.state::<super::CredentialQuestions>(),
            &pmxspan::DiscoveryEnv::from_system(),
            &url,
            &what,
            &|prompt| super::ask_native_confirmation(&ask_app, prompt),
            &pmxspan::spawn_with_url,
            &|u| opener::open(u).map_err(|e| std::io::Error::other(e.to_string())),
        )
    })
    .await
}

/// "Manage in PMXSpan" (spec 3.1): opens the server's guest or node page in
/// PMXSpan. The URL is built from the stored origin, never from the page.
#[tauri::command]
pub async fn pmxspan_manage_server(
    app: AppHandle,
    server_id: String,
) -> CmdResult<serde_json::Value> {
    super::require_unlocked(&app.state::<VaultPasswordStore>())?;
    let db = &app.state::<AppState>().db;
    let origin = db
        .get_server_origin(&server_id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| CmdError("This server did not come from PMXSpan.".into()))?;
    let url = handoff::manage_url(&origin)
        .ok_or_else(|| CmdError("This server's PMXSpan origin names no guest or node.".into()))?;
    let what = match origin.vmid {
        Some(v) => format!("manage guest {v} of {}", origin.cluster_id),
        None => format!(
            "manage node {} of {}",
            origin.node.as_deref().unwrap_or(""),
            origin.cluster_id
        ),
    };
    launch(app.clone(), url, what).await
}

/// "Add to PMXSpan..." (spec 3.2): offers the key's PUBLIC `authorized_keys`
/// line (sanitized to one line) and its name to PMXSpan. The private half
/// is never read.
#[tauri::command]
pub async fn pmxspan_add_key(app: AppHandle, key_id: String) -> CmdResult<serde_json::Value> {
    super::require_unlocked(&app.state::<VaultPasswordStore>())?;
    let db = &app.state::<AppState>().db;
    let key = db
        .get_key(&key_id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| CmdError("Key not found.".into()))?;
    let line = crate::crypto::keys::sanitize_public_line(&key.public_key);
    let url = handoff::add_key_url(&line, &key.name);
    if url.len() > handoff::MAX_URL_BYTES {
        return Err("This public key is too long to hand to PMXSpan in a link.".into());
    }
    launch(app.clone(), url, format!("add key {}", key.name)).await
}

/// "Register sshspan:// links on this computer": store the setting and
/// register (or unregister) the scheme now. A failure is a warning: links
/// still work when PMXSpan starts SSHSpan directly.
#[tauri::command]
pub fn deep_link_set_registered(app: AppHandle, on: bool) -> CmdResult<serde_json::Value> {
    let db = &app.state::<AppState>().db;
    db.set_config(
        "setting.deepLinkRegister",
        if on { "true" } else { "false" },
    )
    .map_err(|e| e.to_string())?;
    let warning = apply_deep_link_registration(&app, on).err();
    super::audit_or_log(
        db,
        "settings.deep_link",
        None,
        if on { "registered" } else { "unregistered" },
    );
    Ok(serde_json::json!({ "ok": true, "warning": warning }))
}

/// Register or unregister `sshspan://` with the OS (Linux and Windows; on
/// macOS the bundle's Info.plist declares it at install time).
pub fn apply_deep_link_registration(app: &AppHandle, on: bool) -> Result<(), String> {
    #[cfg(any(windows, target_os = "linux"))]
    {
        use tauri_plugin_deep_link::DeepLinkExt;
        let dl = app.deep_link();
        let result = if on {
            dl.register_all()
        } else {
            dl.unregister("sshspan")
        };
        result.map_err(|e| format!("Could not update the sshspan:// registration: {e}"))
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        let _ = (app, on);
        Ok(())
    }
}

#[cfg(test)]
#[path = "handoff_tests.rs"]
mod tests;
