//! IPC commands for saved SSH servers (the "Connect" feature).

use tauri::{AppHandle, Manager};
use uuid::Uuid;

use super::{CmdError, CmdResult};
use crate::db::{self, ServerRecord};
use crate::putty_sessions::{build_listing, PuttyListing, RawSession, SavedServer};
use crate::AppState;

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

/// Create or update a saved server.
///
/// Saved password (A2-04 / A7-07 / A5-03): on an existing server
/// `savedPassword` null or empty KEEPS the stored sealed password - the dialog
/// can never show it, so an edit that does not retype it used to erase it. A
/// non-empty value replaces it. `clearSavedPassword: true` removes it (and wins
/// over a value sent with it), and a server saved as `publickey` never keeps
/// one.
///
/// A kept password stays with the account it was saved for: an edit that
/// changes the host, the port, the user name or the auth method and brings no
/// new password is refused with [`PASSWORD_FOR_NEW_ACCOUNT`] and writes
/// nothing. It used to keep the password, so a compromised renderer could
/// point a saved server at a host of its own and have Test or Connect send
/// the password there - without a single dialog when that host was already
/// pinned. Edits that leave the account alone (name, colour, category) keep
/// it as before.
///
/// Async, with the work on the blocking pool: a saved password is sealed
/// with Argon2id, which as a synchronous command ran on the main thread and
/// froze the window on every save.
///
/// `{ ok, id, warning }`: `warning` (else null) says what to do when the
/// server's key file is protected by a passphrase, which a connect cannot
/// ask for, or - on Windows - is not on one of this computer's drives. The
/// server is saved all the same.
#[tauri::command]
pub async fn server_save(
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
    clear_saved_password: Option<bool>,
    category_id: Option<String>,
    color: Option<String>,
) -> CmdResult<serde_json::Value> {
    let request = SaveServerRequest {
        id,
        name,
        host,
        port,
        username,
        auth_method,
        key_id,
        pem_path,
        // Wrapped at once: every return below, early ones included, wipes it.
        saved_password: saved_password.map(zeroize::Zeroizing::new),
        clear_saved_password,
        category_id,
        color,
    };
    super::run_blocking(move || {
        server_save_in(
            &app.state::<AppState>().db,
            &app.state::<super::VaultPasswordStore>(),
            &app.state::<super::VaultRotationLock>(),
            request,
        )
    })
    .await
}

/// What [`server_save`] refuses when an edit would send the saved password to
/// another host, port, user name or auth method.
const PASSWORD_FOR_NEW_ACCOUNT: &str = "Enter the password for the new server or account.";

/// Whether `existing` - the server as stored, with the password it was saved
/// with - is still the same account after an edit to `host`, `port`,
/// `username` and `auth_method` (trimmed): the password goes to the same host
/// and port, for the same user, the same way.
fn same_account(
    existing: &ServerRecord,
    host: &str,
    port: u16,
    username: &str,
    auth_method: &str,
) -> bool {
    existing.host.trim() == host
        && existing.port == port
        && existing.username.trim() == username
        && existing.auth_method == auth_method
}

/// The IPC values as one request, so tests exercise the same save operation
/// against an isolated database and password store instead of needing an app.
struct SaveServerRequest {
    id: Option<String>,
    name: String,
    host: String,
    port: Option<u16>,
    username: String,
    auth_method: Option<String>,
    key_id: Option<String>,
    pem_path: Option<String>,
    saved_password: Option<zeroize::Zeroizing<String>>,
    clear_saved_password: Option<bool>,
    category_id: Option<String>,
    color: Option<String>,
}

fn server_save_in(
    db: &db::Database,
    vault: &super::VaultPasswordStore,
    rotation: &super::VaultRotationLock,
    request: SaveServerRequest,
) -> CmdResult<serde_json::Value> {
    server_save_with(db, vault, rotation, request, key_file_warning)
}

/// [`server_save_in`] with `key_warning`, the look at the server's key file
/// ([`key_file_warning`]; a probe in tests). The save holds the rotation
/// guard; the look at the key file does not - on Windows a UNC path opens a
/// network connection, which can stall, and a master-password change waits
/// for the guard.
fn server_save_with(
    db: &db::Database,
    vault: &super::VaultPasswordStore,
    rotation: &super::VaultRotationLock,
    request: SaveServerRequest,
    key_warning: impl Fn(&str) -> Option<&'static str>,
) -> CmdResult<serde_json::Value> {
    let server = {
        // Seals the saved password and rewrites the whole row: take the
        // guard BEFORE reading the master password or any sealed row, and
        // hold it through the write, so a master-password change cannot
        // commit in between.
        let _rotation = rotation.try_shared()?;
        store_server(db, vault, request)?
    };
    let warning = key_file_warning_for(&server, &key_warning);
    Ok(serde_json::json!({ "ok": true, "id": server.id, "warning": warning }))
}

/// A key file a connect cannot use as it is: said at the save, not at the
/// first connect. (A vault key, when one is chosen, is used instead of it.)
fn key_file_warning_for(
    server: &ServerRecord,
    key_warning: &impl Fn(&str) -> Option<&'static str>,
) -> Option<&'static str> {
    server
        .pem_path
        .as_deref()
        .filter(|_| server.auth_method == "publickey" && server.key_id.is_none())
        .and_then(key_warning)
}

/// The save of [`server_save_with`] - checked, sealed, written and audited.
/// The caller holds the rotation guard.
fn store_server(
    db: &db::Database,
    vault: &super::VaultPasswordStore,
    request: SaveServerRequest,
) -> CmdResult<ServerRecord> {
    let vault_pw = vault.get().unwrap_or_default();
    let SaveServerRequest {
        id,
        name,
        host,
        port,
        username,
        auth_method,
        key_id,
        pem_path,
        saved_password,
        clear_saved_password,
        category_id,
        color,
    } = request;
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
    let port = port.unwrap_or(22);
    if port == 0 {
        return Err(CmdError("Port must be between 1 and 65535.".into()));
    }

    let method = auth_method.unwrap_or_else(|| "publickey".to_string());
    if method != "publickey" && method != "password" && method != "keyboard-interactive" {
        return Err(CmdError(format!("Unknown auth method: {method}")).into());
    }
    // publickey requires a key or pem path; password/kbd-interactive require a saved password
    // (the user may choose to leave it blank and type it at connect time, so only enforce
    // the key side).
    if method == "publickey"
        && key_id.is_none()
        && pem_path.as_deref().map(str::trim).unwrap_or("").is_empty()
    {
        return Err(CmdError(
            "Choose a key for publickey auth (or pick a .pem file).".into(),
        ));
    }

    if let Some(cid) = category_id.as_deref() {
        let valid = db
            .list_categories()
            .map_err(|e| e.to_string())?
            .into_iter()
            .any(|c| c.id == cid && c.scope == "host");
        if !valid {
            return Err(CmdError("Server category must be a host category.".into()).into());
        }
    }
    let now = chrono::Utc::now();

    // What happens to the saved password (see `server_save`): dropped, kept
    // (`None` here), or replaced by a value sealed with the vault password.
    let drop_password = method == "publickey" || clear_saved_password == Some(true);
    let replacement: Option<String> = match saved_password.as_deref() {
        Some(p) if !p.is_empty() && !drop_password => Some(
            crate::crypto::vault::seal(&vault_pw, p.as_bytes())
                .map_err(|e| CmdError(e.to_string()))?,
        ),
        _ => None,
    };

    let trimmed_name = name.trim().to_string();
    let trimmed_host = host.trim().to_string();
    let trimmed_user = username.trim().to_string();
    let pem_clean = pem_path
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty());
    let key_clean = key_id
        .map(|k| k.trim().to_string())
        .filter(|k| !k.is_empty());

    let server = match &id {
        Some(existing_id) => {
            // Read, checked and written in ONE transaction: a save racing
            // another writer used to check the row it had read before that
            // writer committed, then write over it.
            let edited = db.modify_server(existing_id, |existing| {
                // The stored password would be kept: only for its own
                // account. (Every writer stores a password together with the
                // account it belongs to, so the row read here pairs them
                // correctly, and the write keeps that pairing.)
                let keeps_password =
                    !drop_password && replacement.is_none() && existing.saved_password.is_some();
                if keeps_password
                    && !same_account(existing, &trimmed_host, port, &trimmed_user, &method)
                {
                    return Err(CmdError(PASSWORD_FOR_NEW_ACCOUNT.into()).into());
                }
                existing.name = trimmed_name;
                existing.host = trimmed_host;
                existing.port = port;
                existing.username = trimmed_user;
                existing.auth_method = method;
                existing.key_id = key_clean;
                existing.pem_path = pem_clean;
                if drop_password {
                    existing.saved_password = None;
                } else if replacement.is_some() {
                    existing.saved_password = replacement;
                }
                existing.category_id = category_id
                    .map(|c| c.trim().to_string())
                    .filter(|c| !c.is_empty());
                existing.color = color;
                existing.updated_at = now;
                Ok(())
            });
            match edited.map_err(CmdError::from)? {
                Some((server, ())) => server,
                None => return Err(CmdError("Server not found.".into())),
            }
        }
        None => {
            let rec = ServerRecord {
                id: Uuid::new_v4().to_string(),
                name: trimmed_name,
                host: trimmed_host,
                port,
                username: trimmed_user,
                auth_method: method,
                key_id: key_clean,
                pem_path: pem_clean,
                saved_password: replacement,
                category_id: category_id
                    .map(|c| c.trim().to_string())
                    .filter(|c| !c.is_empty()),
                color,
                last_connected_at: None,
                created_at: now,
                updated_at: now,
                bitwarden_id: None,
                bitwarden_revision_ts: None,
                bitwarden_updated_at: None,
            };
            db.insert_server(&rec).map_err(|e| e.to_string())?;
            rec
        }
    };

    let _ = db.add_audit(
        "server.save",
        None,
        &format!("{} @ {}:{}", server.name, server.host, server.port),
    );
    Ok(server)
}

/// How much of a key file a save reads to tell whether it is protected by a
/// passphrase: far more than any private key takes.
const KEY_FILE_CHECK_BYTES: u64 = 64 * 1024;

/// The save's warning for the key file at `path`: what to do when it is
/// protected by a passphrase, which a connect cannot ask for
/// ([`crate::ssh_client::PASSPHRASE_PROTECTED_KEY`]). Nothing when it is
/// not, or cannot be read (the connect says why). Only a regular file is
/// read, and only its first [`KEY_FILE_CHECK_BYTES`]. On Windows a path that
/// is not on one of this computer's drives gets
/// [`crate::ssh_client::KEY_FILE_NOT_LOCAL`] instead, without being touched
/// ([`crate::ssh_client::key_path_refusal`]). Elsewhere a UNC or device
/// path (`\\...`, `//...`) is not looked at either. Opening a share hands it
/// an NTLM sign-in and can stall - only to find out whether to warn.
fn key_file_warning(path: &str) -> Option<&'static str> {
    use std::io::Read;
    // On Windows a key file elsewhere than on this computer's drives gets
    // what to do, and is not touched.
    if let Some(why) = crate::ssh_client::key_path_refusal(path) {
        return Some(why);
    }
    let mut start = path.chars();
    let separator = |c: Option<char>| matches!(c, Some('\\' | '/'));
    if separator(start.next()) && separator(start.next()) {
        return None;
    }
    // Looked at before it is opened: opening a named pipe for reading waits
    // for a writer.
    if !std::fs::metadata(path).ok()?.is_file() {
        return None;
    }
    let file = std::fs::File::open(path).ok()?;
    let mut text = String::new();
    file.take(KEY_FILE_CHECK_BYTES)
        .read_to_string(&mut text)
        .ok()?;
    crate::ssh_client::key_needs_passphrase(&text)
        .then_some(crate::ssh_client::PASSPHRASE_PROTECTED_KEY)
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

/// PuTTY's saved sessions, for importing them as servers: each SSH session
/// as the server it would be saved as (the renderer saves the ones the user
/// picks with `server_save`, one at a time), whether a saved server already
/// has its account, and the sessions that cannot be imported, with the
/// reason.
///
/// Refused while the vault is locked: the list is an inventory of hosts,
/// accounts and key paths. Windows only - PuTTY keeps its sessions in the
/// registry - and read on the blocking pool. Key files are reported as
/// paths and never looked at: `server_save` decides whether to warn about
/// one, without touching a path that is not on this computer's drives.
#[tauri::command]
pub async fn putty_list_sessions(app: AppHandle) -> CmdResult<PuttyListing> {
    let local_user = crate::putty_sessions::local_user_name();
    super::run_blocking(move || {
        putty_sessions_in(
            &app.state::<super::VaultPasswordStore>(),
            &app.state::<AppState>().db,
            local_user.as_deref(),
            read_putty_sessions,
        )
    })
    .await
}

/// What [`putty_list_sessions`] answers off Windows.
#[cfg(not(windows))]
const PUTTY_WINDOWS_ONLY: &str =
    "PuTTY's saved sessions are read from the Windows registry, so this works on Windows only.";

/// [`putty_list_sessions`] with the registry reader given. `local_user` is
/// who a session set to log in as the local user logs in as. The lock is
/// checked before `read` runs.
fn putty_sessions_in(
    vault: &super::VaultPasswordStore,
    db: &db::Database,
    local_user: Option<&str>,
    read: impl FnOnce() -> CmdResult<Vec<RawSession>>,
) -> CmdResult<PuttyListing> {
    super::require_unlocked(vault)?;
    let raw = read()?;
    let servers = db.list_servers().map_err(|e| e.to_string())?;
    let saved: Vec<SavedServer<'_>> = servers
        .iter()
        .map(|server| SavedServer {
            host: &server.host,
            port: server.port,
            username: &server.username,
        })
        .collect();
    Ok(build_listing(raw, &saved, local_user))
}

/// What the user is told when PuTTY's sessions key cannot be read (a session
/// that cannot be read is one skipped entry instead). Built on every
/// platform for the tests.
#[cfg(any(windows, test))]
fn putty_read_error(error: std::io::Error) -> CmdError {
    CmdError(format!("Could not read PuTTY's saved sessions: {error}"))
}

/// PuTTY's sessions, from the current user's registry.
#[cfg(windows)]
fn read_putty_sessions() -> CmdResult<Vec<RawSession>> {
    crate::putty_sessions::read_sessions(crate::putty_sessions::SESSIONS_KEY)
        .map_err(putty_read_error)
}

/// Off Windows there is no registry to read them from.
#[cfg(not(windows))]
fn read_putty_sessions() -> CmdResult<Vec<RawSession>> {
    Err(CmdError(PUTTY_WINDOWS_ONLY.into()))
}

#[cfg(test)]
mod ru4_tests {
    use super::*;
    use crate::commands::{VaultPasswordStore, VaultRotationLock};

    struct Fixture {
        db: db::Database,
        vault: VaultPasswordStore,
        rotation: VaultRotationLock,
        path: std::path::PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("sshspan-ru4-server-{}.db", Uuid::new_v4()));
            let db = db::Database::open_at(path.clone()).unwrap();
            let vault = VaultPasswordStore::new();
            vault.set("ru4-fixture-master".into());
            Self {
                db,
                vault,
                rotation: VaultRotationLock::new(),
                path,
            }
        }

        fn save(&self, request: SaveServerRequest) -> CmdResult<serde_json::Value> {
            server_save_in(&self.db, &self.vault, &self.rotation, request)
        }

        fn record(&self, id: &str) -> ServerRecord {
            self.db.get_server(id).unwrap().unwrap()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    fn request(
        id: Option<&str>,
        password: Option<&str>,
        clear: Option<bool>,
        method: &str,
    ) -> SaveServerRequest {
        SaveServerRequest {
            id: id.map(str::to_string),
            name: "Renamed é€😀 ' OR 1=1 --".into(),
            host: "fixture.example".into(),
            port: Some(2222),
            username: "fixture-user".into(),
            auth_method: Some(method.into()),
            key_id: (method == "publickey").then(|| "fixture-key".into()),
            pem_path: None,
            saved_password: password.map(|p| zeroize::Zeroizing::new(p.to_string())),
            clear_saved_password: clear,
            category_id: None,
            color: Some("blue".into()),
        }
    }

    fn saved_id(f: &Fixture) -> String {
        f.save(request(None, Some("fixture-password"), None, "password"))
            .unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string()
    }

    #[test]
    fn ru4_password_none_and_empty_keep_the_same_sealed_value() {
        let f = Fixture::new();
        let id = saved_id(&f);
        let before = f.record(&id);
        for input in [None, Some("")] {
            f.save(request(Some(&id), input, Some(false), "password"))
                .unwrap();
            let after = f.record(&id);
            assert_eq!(
                after.saved_password, before.saved_password,
                "a blank edit must not erase or reseal the password"
            );
            assert_eq!(after.name, "Renamed é€😀 ' OR 1=1 --");
            assert_eq!(after.port, 2222);
        }
    }

    #[test]
    fn ru4_password_explicit_clear_and_publickey_take_precedence_over_replacement() {
        for method in ["password", "keyboard-interactive", "publickey"] {
            let f = Fixture::new();
            let id = saved_id(&f);
            f.save(request(
                Some(&id),
                Some("must-not-be-stored"),
                Some(true),
                method,
            ))
            .unwrap();
            assert_eq!(f.record(&id).saved_password, None);
        }
        let f = Fixture::new();
        let id = saved_id(&f);
        f.save(request(
            Some(&id),
            Some("must-not-be-stored"),
            None,
            "publickey",
        ))
        .unwrap();
        assert_eq!(f.record(&id).saved_password, None);
    }

    #[test]
    fn ru4_password_replacement_is_sealed_and_keyboard_interactive_needs_it_again() {
        let f = Fixture::new();
        let id = saved_id(&f);
        let before = f.record(&id).saved_password;
        f.save(request(
            Some(&id),
            Some("é€😀 new fixture password"),
            None,
            "password",
        ))
        .unwrap();
        let after = f.record(&id).saved_password.unwrap();
        assert_ne!(Some(after.clone()), before);
        assert!(!after.contains("fixture password"));
        assert_eq!(
            crate::crypto::vault::unseal("ru4-fixture-master", &after).unwrap(),
            "é€😀 new fixture password".as_bytes()
        );
        // Another auth method is another account for the saved password: the
        // switch alone is refused and changes nothing; with the password
        // entered again it is saved.
        let err = f
            .save(request(Some(&id), None, None, "keyboard-interactive"))
            .unwrap_err();
        assert_eq!(err.0, PASSWORD_FOR_NEW_ACCOUNT);
        assert_eq!(f.record(&id).auth_method, "password");
        assert_eq!(
            f.record(&id).saved_password.as_deref(),
            Some(after.as_str())
        );
        f.save(request(
            Some(&id),
            Some("é€😀 new fixture password"),
            None,
            "keyboard-interactive",
        ))
        .unwrap();
        assert_eq!(f.record(&id).auth_method, "keyboard-interactive");
    }

    #[test]
    fn ru4_new_servers_do_not_inherit_or_store_publickey_passwords() {
        let f = Fixture::new();
        for (password, clear, method) in [
            (None, None, "password"),
            (Some(""), None, "keyboard-interactive"),
            (Some("discard"), None, "publickey"),
            (Some("discard"), Some(true), "password"),
        ] {
            let id = f.save(request(None, password, clear, method)).unwrap()["id"]
                .as_str()
                .unwrap()
                .to_string();
            assert_eq!(f.record(&id).saved_password, None);
        }
    }

    #[test]
    fn ru4_server_save_respects_rotation_before_reading_or_writing_secrets() {
        let f = Fixture::new();
        let id = saved_id(&f);
        let before = f.record(&id);
        let exclusive = f
            .rotation
            .exclusive_within(std::time::Duration::from_secs(1))
            .unwrap();
        let err = f
            .save(request(Some(&id), Some("replacement"), None, "password"))
            .unwrap_err();
        drop(exclusive);
        assert_eq!(err.0, crate::commands::VAULT_REENCRYPTING);
        assert_eq!(f.record(&id).saved_password, before.saved_password);
        assert_eq!(f.db.list_servers().unwrap().len(), 1);
    }

    #[test]
    fn ru4_server_save_locked_missing_and_invalid_inputs_do_not_write() {
        let f = Fixture::new();
        f.vault.clear();
        assert_eq!(
            f.save(request(None, Some("discard"), None, "password"))
                .unwrap_err()
                .0,
            "Vault is locked."
        );
        f.vault.set("ru4-fixture-master".into());
        assert_eq!(
            f.save(request(Some("missing"), None, None, "password"))
                .unwrap_err()
                .0,
            "Server not found."
        );
        for field in [
            "name",
            "host",
            "username",
            "auth_method",
            "port",
            "category_id",
        ] {
            let mut bad = request(None, None, None, "password");
            match field {
                "name" => bad.name = " ".into(),
                "host" => bad.host = "".into(),
                "username" => bad.username = "\t".into(),
                "auth_method" => bad.auth_method = Some("invalid".into()),
                "port" => bad.port = Some(0),
                "category_id" => bad.category_id = Some("not-a-category".into()),
                _ => unreachable!(),
            }
            assert!(f.save(bad).is_err(), "{field}");
        }
        assert!(f.db.list_servers().unwrap().is_empty());
    }
}

/// A saved password belongs to the account it was saved for: an edit could
/// point a server at another host, port or user name - or another auth
/// method - and keep the password, and the next Test or Connect sent it
/// there.
#[cfg(test)]
mod saved_password_binding_tests {
    use super::*;
    use crate::commands::{VaultPasswordStore, VaultRotationLock};

    const MASTER: &str = "rw-fixture-master";

    struct Fixture {
        db: db::Database,
        vault: VaultPasswordStore,
        rotation: VaultRotationLock,
        path: std::path::PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("sshspan-rw-server-{}.db", Uuid::new_v4()));
            let db = db::Database::open_at(path.clone()).unwrap();
            let vault = VaultPasswordStore::new();
            vault.set(MASTER.into());
            Self {
                db,
                vault,
                rotation: VaultRotationLock::new(),
                path,
            }
        }

        fn save(&self, request: SaveServerRequest) -> CmdResult<serde_json::Value> {
            server_save_in(&self.db, &self.vault, &self.rotation, request)
        }

        fn record(&self, id: &str) -> ServerRecord {
            self.db.get_server(id).unwrap().unwrap()
        }

        fn host_category(&self) -> String {
            let now = chrono::Utc::now();
            let category = db::Category {
                id: Uuid::new_v4().to_string(),
                name: "hosts".into(),
                parent_id: None,
                scope: "host".into(),
                color: None,
                sort_index: 0,
                created_at: now,
                updated_at: now,
            };
            self.db.insert_category(&category).unwrap();
            category.id
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    /// `prod-db` as saved: password auth for `dba@prod-db.example:22`.
    fn prod(id: Option<&str>, password: Option<&str>) -> SaveServerRequest {
        SaveServerRequest {
            id: id.map(str::to_string),
            name: "prod-db".into(),
            host: "prod-db.example".into(),
            port: Some(22),
            username: "dba".into(),
            auth_method: Some("password".into()),
            key_id: None,
            pem_path: None,
            saved_password: password.map(|p| zeroize::Zeroizing::new(p.to_string())),
            clear_saved_password: None,
            category_id: None,
            color: None,
        }
    }

    fn saved_prod(f: &Fixture) -> String {
        f.save(prod(None, Some("the-prod-password"))).unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string()
    }

    fn unsealed(sealed: &str) -> String {
        String::from_utf8(crate::crypto::vault::unseal(MASTER, sealed).unwrap()).unwrap()
    }

    /// Every way to point the saved password elsewhere, each with "keep the
    /// password" spelled both ways.
    fn retargets(id: &str) -> Vec<(&'static str, SaveServerRequest)> {
        let mut out = Vec::new();
        for keep in [None, Some("")] {
            let mut host = prod(Some(id), keep);
            host.host = "attacker.example".into();
            out.push(("host", host));
            let mut port = prod(Some(id), keep);
            port.port = Some(2222);
            out.push(("port", port));
            let mut user = prod(Some(id), keep);
            user.username = "root".into();
            out.push(("username", user));
            let mut method = prod(Some(id), keep);
            method.auth_method = Some("keyboard-interactive".into());
            out.push(("auth method", method));
        }
        out
    }

    #[test]
    fn rw_s1_a_retarget_without_a_new_password_is_refused_and_changes_nothing() {
        let f = Fixture::new();
        let id = saved_prod(&f);
        let before = f.record(&id);
        for (what, request) in retargets(&id) {
            let err = f
                .save(request)
                .expect_err(&format!("a {what} change must not keep the password"));
            assert_eq!(
                err.0, "Enter the password for the new server or account.",
                "{what}"
            );
            let after = f.record(&id);
            assert_eq!(after.host, before.host, "{what}");
            assert_eq!(after.port, before.port, "{what}");
            assert_eq!(after.username, before.username, "{what}");
            assert_eq!(after.auth_method, before.auth_method, "{what}");
            assert_eq!(after.saved_password, before.saved_password, "{what}");
            assert_eq!(
                after.updated_at, before.updated_at,
                "{what}: nothing written"
            );
        }
    }

    #[test]
    fn rw_s1_a_retarget_with_a_new_password_is_saved_with_that_password() {
        let f = Fixture::new();
        let id = saved_prod(&f);
        let mut moved = prod(Some(&id), Some("the-new-password"));
        moved.host = "new-db.example".into();
        moved.username = "admin".into();
        f.save(moved).unwrap();
        let after = f.record(&id);
        assert_eq!(after.host, "new-db.example");
        assert_eq!(after.username, "admin");
        assert_eq!(
            unsealed(after.saved_password.as_deref().unwrap()),
            "the-new-password"
        );
        // A retarget that drops the password is fine too: nothing is kept.
        let mut dropped = prod(Some(&id), None);
        dropped.host = "third.example".into();
        dropped.clear_saved_password = Some(true);
        f.save(dropped).unwrap();
        let after = f.record(&id);
        assert_eq!(after.host, "third.example");
        assert_eq!(after.saved_password, None);
    }

    #[test]
    fn rw_s1_edits_that_keep_the_account_keep_the_password() {
        let f = Fixture::new();
        let id = saved_prod(&f);
        let before = f.record(&id).saved_password;
        let category = f.host_category();
        let mut edit = prod(Some(&id), None);
        edit.name = "prod-db (primary)".into();
        edit.color = Some("red".into());
        edit.category_id = Some(category.clone());
        // Surrounding spaces are not a different host or user.
        edit.host = "  prod-db.example ".into();
        edit.username = " dba".into();
        f.save(edit).unwrap();
        let after = f.record(&id);
        assert_eq!(after.name, "prod-db (primary)");
        assert_eq!(after.color.as_deref(), Some("red"));
        assert_eq!(after.category_id.as_deref(), Some(category.as_str()));
        assert_eq!(
            after.saved_password, before,
            "the same sealed password, not resealed"
        );
    }

    /// Resolve `id` for a connection the way Connect and Test do.
    fn resolved(
        f: &Fixture,
        id: &str,
        override_username: Option<&str>,
    ) -> crate::ssh_client::ResolvedConnection {
        crate::commands::terminal::resolve_connection(
            &f.db,
            &f.vault,
            &f.rotation,
            crate::commands::terminal::ConnectRequest {
                server_id: id.to_string(),
                override_username: override_username.map(str::to_string),
                override_key_id: None,
                prompt_password: None,
            },
        )
        .unwrap()
    }

    #[test]
    fn rw_s1_a_retargeted_server_never_spends_the_old_password() {
        let f = Fixture::new();
        let id = saved_prod(&f);
        // Whatever an edit does, the old password is only ever resolved for
        // the account it was saved for.
        for (what, request) in retargets(&id) {
            let _ = f.save(request);
            let c = resolved(&f, &id, None);
            let same_account = c.server.host == "prod-db.example"
                && c.server.port == 22
                && c.username == "dba"
                && c.auth_method == "password";
            let spends_old = c.password.as_deref().map(String::as_str) == Some("the-prod-password");
            assert!(
                same_account || !spends_old,
                "after a {what} edit the old password would go to {}@{}:{} ({})",
                c.username,
                c.server.host,
                c.server.port,
                c.auth_method
            );
        }
        let connection = resolved(&f, &id, None);
        assert_eq!(connection.server.host, "prod-db.example");
        assert_eq!(
            connection.password.as_deref().map(String::as_str),
            Some("the-prod-password")
        );
        // Connect may not swap the user name under the saved password either:
        // only a password typed at the prompt goes to another account.
        let other_user = resolved(&f, &id, Some("root"));
        assert_eq!(other_user.username, "root");
        assert!(
            other_user.password.is_none(),
            "the saved password is not sent for another user"
        );
        assert_eq!(
            resolved(&f, &id, Some("dba"))
                .password
                .as_deref()
                .map(String::as_str),
            Some("the-prod-password"),
            "the saved user name, spelled out, is the same account"
        );
        // Retargeted with a new password: only that one is ever used.
        let mut moved = prod(Some(&id), Some("the-new-password"));
        moved.host = "new-db.example".into();
        f.save(moved).unwrap();
        let connection = resolved(&f, &id, None);
        assert_eq!(connection.server.host, "new-db.example");
        assert_eq!(
            connection.password.as_deref().map(String::as_str),
            Some("the-new-password")
        );
    }

    /// The save reads the row, checks it and writes it in ONE transaction. A
    /// save racing another writer used to check the row as it was before that
    /// writer committed, then write over it: here a rename, checked against
    /// `prod-db.example`, rewrote the row after another save had moved it to
    /// `new-db.example` - with the old host and the old password.
    #[test]
    fn rw_fix1_a_save_checks_the_row_it_writes() {
        let f = Fixture::new();
        let id = saved_prod(&f);
        let sealed_new = crate::crypto::vault::seal(MASTER, b"the-new-db-password").unwrap();
        let holder = crate::db::test_support::hold_write_bound(
            &f.db,
            vec![(
                "UPDATE servers SET host = ?, saved_password = ? WHERE id = ?".into(),
                vec!["new-db.example".into(), sealed_new.clone(), id.clone()],
            )],
            400,
        );
        let mut rename = prod(Some(&id), None);
        rename.name = "renamed".into();
        let saved = f.save(rename);
        holder.join().unwrap();
        let err = saved.expect_err("the row is another account by the time it is written");
        assert_eq!(err.0, PASSWORD_FOR_NEW_ACCOUNT);
        let after = f.record(&id);
        assert_eq!(after.host, "new-db.example", "the other save's move stands");
        assert_eq!(after.saved_password.as_deref(), Some(sealed_new.as_str()));
        assert_eq!(after.name, "prod-db");
    }

    /// A server whose key file is protected by a passphrase is saved, and the
    /// save says at once what its first connect would refuse it for (A5-26).
    /// A key file without one, a vault key chosen instead of the file, and a
    /// file that is not there say nothing.
    #[test]
    fn fw_r10_saving_a_server_with_a_protected_key_file_says_what_to_do() {
        use crate::crypto::keys::{export_private_key, generate_key_pair, KeyFormat, KeyType};
        let f = Fixture::new();
        let dir = std::env::temp_dir().join(format!("sshspan-fw-r10-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let key = generate_key_pair(KeyType::Ed25519, None, "fw-r10".into()).unwrap();
        let write = |name: &str, passphrase: Option<&str>| {
            let path = dir.join(name);
            let pem = export_private_key(&key, KeyFormat::OpenSsh, passphrase).unwrap();
            std::fs::write(&path, pem).unwrap();
            path.display().to_string()
        };
        let protected = write("protected.pem", Some("fw-r10-passphrase"));
        let plain = write("plain.pem", None);
        let missing = dir.join("missing.pem").display().to_string();
        let with_file = |path: &str, key_id: Option<&str>| SaveServerRequest {
            id: None,
            name: "with a key file".into(),
            host: "keyfile.example".into(),
            port: Some(22),
            username: "ops".into(),
            auth_method: Some("publickey".into()),
            key_id: key_id.map(str::to_string),
            pem_path: Some(path.to_string()),
            saved_password: None,
            clear_saved_password: None,
            category_id: None,
            color: None,
        };
        let out = f.save(with_file(&protected, None)).unwrap();
        assert_eq!(
            out["warning"].as_str(),
            Some(crate::ssh_client::PASSPHRASE_PROTECTED_KEY),
            "{out}"
        );
        let saved = f.record(out["id"].as_str().unwrap());
        assert_eq!(
            saved.pem_path.as_deref(),
            Some(protected.as_str()),
            "saved all the same"
        );
        for (path, key_id) in [
            (plain.as_str(), None),
            (protected.as_str(), Some("a-vault-key")),
            (missing.as_str(), None),
        ] {
            let out = f.save(with_file(path, key_id)).unwrap();
            assert!(out["warning"].is_null(), "{path} {key_id:?}: {out}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A "key file" that is a named pipe: opening one for reading waits for a
    /// writer, so a save that opened it would hold a blocking-pool thread for
    /// good. It is looked at first, and not opened.
    #[cfg(unix)]
    #[test]
    fn fw_r10_a_named_pipe_as_key_file_does_not_stall_the_save() {
        let dir = std::env::temp_dir().join(format!("sshspan-fw-r10-fifo-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let fifo = dir.join("key.pem");
        let made = std::process::Command::new("mkfifo").arg(&fifo).status();
        if !made.is_ok_and(|status| status.success()) {
            eprintln!("mkfifo not available: the named-pipe check is skipped");
            let _ = std::fs::remove_dir_all(&dir);
            return;
        }
        let path = fifo.display().to_string();
        let (done, answer) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = done.send(key_file_warning(&path));
        });
        let warning = answer
            .recv_timeout(std::time::Duration::from_secs(30))
            .expect("the check of a named pipe came back");
        assert_eq!(warning, None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The look at a server's key file ran while the save held the rotation
    /// guard - on Windows a UNC path there opens a network connection, which
    /// can stall, and a master-password change waits for the guard. The look
    /// comes after the guard is dropped: probed by asking, at that moment,
    /// whether a password change could take the lock.
    #[test]
    fn fw_s4_the_key_file_is_looked_at_after_the_rotation_guard() {
        let f = Fixture::new();
        let looked = std::cell::RefCell::new(Vec::new());
        let probe = |path: &str| {
            let free = f.rotation.0.try_write().is_ok();
            looked.borrow_mut().push((path.to_string(), free));
            Some(crate::ssh_client::PASSPHRASE_PROTECTED_KEY)
        };
        let request = SaveServerRequest {
            id: None,
            name: "with a key file".into(),
            host: "keyfile.example".into(),
            port: Some(22),
            username: "ops".into(),
            auth_method: Some("publickey".into()),
            key_id: None,
            pem_path: Some("/keys/id_ed25519".into()),
            saved_password: None,
            clear_saved_password: None,
            category_id: None,
            color: None,
        };
        let out = server_save_with(&f.db, &f.vault, &f.rotation, request, probe).unwrap();
        assert_eq!(
            out["warning"].as_str(),
            Some(crate::ssh_client::PASSPHRASE_PROTECTED_KEY)
        );
        assert_eq!(
            looked.into_inner(),
            vec![("/keys/id_ed25519".to_string(), true)],
            "looked at once, with the rotation guard dropped"
        );
    }

    /// A UNC or device path (`\\server\share\...`, `//...`) is not looked at:
    /// on Windows that is a network connection, with an NTLM sign-in, made
    /// only to decide on a warning. On Unix `//` names the root, so a
    /// protected key file reached that way shows the path is skipped
    /// unopened, not merely unreadable.
    #[cfg(unix)]
    #[test]
    fn fw_s4_a_unc_or_device_key_path_is_not_looked_at() {
        use crate::crypto::keys::{export_private_key, generate_key_pair, KeyFormat, KeyType};
        let dir = std::env::temp_dir().join(format!("sshspan-fw-s4-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let key = generate_key_pair(KeyType::Ed25519, None, "fw-s4".into()).unwrap();
        let protected = dir.join("protected.pem");
        std::fs::write(
            &protected,
            export_private_key(&key, KeyFormat::OpenSsh, Some("fw-s4-passphrase")).unwrap(),
        )
        .unwrap();
        let plain = protected.display().to_string();
        assert_eq!(
            key_file_warning(&plain),
            Some(crate::ssh_client::PASSPHRASE_PROTECTED_KEY)
        );
        for skipped in [
            format!("/{plain}"),
            format!("\\{plain}"),
            r"\\server\share\keys\id_ed25519".to_string(),
            r"\\?\C:\keys\id_ed25519".to_string(),
            r"/\server\share\id_ed25519".to_string(),
        ] {
            assert_eq!(key_file_warning(&skipped), None, "{skipped}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod putty_list_sessions_tests {
    use super::*;
    use crate::commands::{VaultPasswordStore, VaultRotationLock};
    use crate::putty_sessions::RegValue;

    struct Fixture {
        db: db::Database,
        vault: VaultPasswordStore,
        path: std::path::PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("sshspan-putty-list-{}.db", Uuid::new_v4()));
            let db = db::Database::open_at(path.clone()).unwrap();
            let vault = VaultPasswordStore::new();
            vault.set("putty-fixture-master".into());
            Self { db, vault, path }
        }

        /// Save `deploy@prod.example:22` the way the dialog saves a server.
        fn save_prod(&self) {
            let request = SaveServerRequest {
                id: None,
                name: "prod".into(),
                host: "prod.example".into(),
                port: Some(22),
                username: "deploy".into(),
                auth_method: Some("password".into()),
                key_id: None,
                pem_path: None,
                saved_password: None,
                clear_saved_password: None,
                category_id: None,
                color: None,
            };
            server_save_in(&self.db, &self.vault, &VaultRotationLock::new(), request).unwrap();
        }

        fn list(
            &self,
            local_user: Option<&str>,
            read: impl FnOnce() -> CmdResult<Vec<RawSession>>,
        ) -> CmdResult<PuttyListing> {
            putty_sessions_in(&self.vault, &self.db, local_user, read)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    fn session(key_name: &str, values: &[(&str, RegValue)]) -> RawSession {
        RawSession {
            key_name: key_name.into(),
            values: values
                .iter()
                .map(|(name, value)| (name.to_string(), value.clone()))
                .collect(),
            unreadable: None,
        }
    }

    fn host(name: &str) -> (&'static str, RegValue) {
        ("HostName", RegValue::Str(name.into()))
    }

    #[test]
    fn a_locked_vault_is_refused_before_the_registry_is_read() {
        let f = Fixture::new();
        f.vault.clear();
        let ran = std::cell::Cell::new(false);
        let err = f
            .list(None, || {
                ran.set(true);
                Ok(vec![session("s", &[host("h")])])
            })
            .unwrap_err();
        assert_eq!(err.0, "Vault is locked.");
        assert!(
            !ran.get(),
            "the registry was read while the vault was locked"
        );
    }

    #[test]
    fn sessions_whose_account_is_saved_are_marked() {
        let f = Fixture::new();
        f.save_prod();
        let from_env = ("UserNameFromEnvironment", RegValue::Dword(1));
        let listing = f
            .list(Some("deploy"), || {
                Ok(vec![
                    session("prod", &[host("deploy@PROD.example")]),
                    session("prod as root", &[host("root@prod.example")]),
                    session("prod, no user", &[host("prod.example:22")]),
                    session("prod as me", &[host("prod.example"), from_env]),
                    session("other", &[host("deploy@other.example")]),
                    session(
                        "telnet",
                        &[
                            host("prod.example"),
                            ("Protocol", RegValue::Str("telnet".into())),
                        ],
                    ),
                ])
            })
            .unwrap();
        let flags: Vec<(&str, bool)> = listing
            .sessions
            .iter()
            .map(|s| (s.name.as_str(), s.already_saved))
            .collect();
        assert_eq!(
            flags,
            [
                ("other", false),
                ("prod", true),
                ("prod as me", true),
                ("prod as root", false),
                ("prod, no user", true),
            ]
        );
        assert_eq!(listing.skipped.len(), 1);
        assert!(!listing.truncated);
        assert_eq!(f.db.list_servers().unwrap().len(), 1, "nothing is saved");
    }

    /// What the user is told when PuTTY's sessions key cannot be read: the
    /// mapping the Windows reader uses, checked on every platform.
    #[test]
    fn a_registry_that_cannot_be_read_says_what_and_why() {
        let denied = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "access denied");
        assert_eq!(
            putty_read_error(denied).0,
            "Could not read PuTTY's saved sessions: access denied"
        );
        let os = std::io::Error::from_raw_os_error(5);
        let text = os.to_string();
        assert_eq!(
            putty_read_error(os).0,
            format!("Could not read PuTTY's saved sessions: {text}")
        );
        let f = Fixture::new();
        let err = f
            .list(None, || {
                Err(putty_read_error(std::io::Error::other("boom")))
            })
            .unwrap_err();
        assert_eq!(err.0, "Could not read PuTTY's saved sessions: boom");
    }

    #[cfg(not(windows))]
    #[test]
    fn off_windows_the_command_says_it_works_on_windows_only() {
        let f = Fixture::new();
        let err = f.list(None, read_putty_sessions).unwrap_err();
        assert_eq!(
            err.0,
            "PuTTY's saved sessions are read from the Windows registry, so this works on Windows only."
        );
        assert_eq!(err.0, PUTTY_WINDOWS_ONLY);
    }

    /// The real reader, on PuTTY's own key: whatever is saved there (on a
    /// machine without PuTTY, nothing) is listed, and nothing is written.
    #[cfg(windows)]
    #[test]
    fn on_windows_the_command_reads_puttys_key() {
        let f = Fixture::new();
        let listing = f
            .list(None, read_putty_sessions)
            .expect("PuTTY's sessions key could be read");
        for session in &listing.sessions {
            assert!(!session.host.is_empty() && session.port > 0, "{session:?}");
        }
        assert!(listing.skipped.iter().all(|s| !s.reason.is_empty()));
    }
}
