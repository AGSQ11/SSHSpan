//! IPC commands for saved SSH servers (the "Connect" feature).

use tauri::{AppHandle, Manager};
use uuid::Uuid;

use super::{CmdError, CmdResult};
use crate::db::{self, ServerRecord};
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
    clear_saved_password: Option<bool>,
    category_id: Option<String>,
    color: Option<String>,
) -> CmdResult<serde_json::Value> {
    server_save_in(
        &app.state::<AppState>().db,
        &app.state::<super::VaultPasswordStore>(),
        &app.state::<super::VaultRotationLock>(),
        SaveServerRequest {
            id,
            name,
            host,
            port,
            username,
            auth_method,
            key_id,
            pem_path,
            // Wrapped at once: every return below, early ones included,
            // wipes it.
            saved_password: saved_password.map(zeroize::Zeroizing::new),
            clear_saved_password,
            category_id,
            color,
        },
    )
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
    // Seals the saved password and rewrites the whole row: take the guard
    // BEFORE reading the master password or any sealed row, and hold it
    // through the write (RU1 C1).
    let _rotation = rotation.try_shared()?;
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
            let mut existing = db
                .get_server(existing_id)
                .map_err(|e| e.to_string())?
                .ok_or_else(|| CmdError("Server not found.".into()))?;
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
            db.update_server(&existing).map_err(|e| e.to_string())?;
            existing
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
    fn ru4_password_replacement_is_sealed_and_keyboard_interactive_keeps_it() {
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
        f.save(request(Some(&id), None, None, "keyboard-interactive"))
            .unwrap();
        assert_eq!(
            f.record(&id).saved_password.as_deref(),
            Some(after.as_str())
        );
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
