//! Quick connect, the link/bundle offers, origins and PMXSpan launching,
//! against isolated databases - no PMXSpan, no network, no GUI.

use super::*;
use crate::commands::{CredentialAnswer, CredentialQuestions, VaultPasswordStore};
use crate::handoff::state::Proposal;

fn test_db() -> (db::Database, std::path::PathBuf) {
    let path = std::env::temp_dir().join(format!("sshspan-handoff-{}.db", uuid::Uuid::new_v4()));
    (db::Database::open_at(path.clone()).unwrap(), path)
}

fn unlocked() -> VaultPasswordStore {
    let v = VaultPasswordStore::new();
    v.set("handoff-master".into());
    v
}

fn server(id: &str, host: &str, port: u16, user: &str) -> ServerRecord {
    let now = chrono::Utc::now();
    ServerRecord {
        id: id.into(),
        name: format!("srv-{id}"),
        host: host.into(),
        port,
        username: user.into(),
        key_id: None,
        pem_path: None,
        auth_method: "password".into(),
        saved_password: None,
        category_id: None,
        color: None,
        last_connected_at: None,
        created_at: now,
        updated_at: now,
        bitwarden_id: None,
        bitwarden_revision_ts: None,
        bitwarden_updated_at: None,
    }
}

fn origin(vmid: u32) -> Origin {
    Origin {
        kind: "pmxspan".into(),
        cluster_id: "prof-1".into(),
        cluster_name: Some("lab".into()),
        vmid: Some(vmid),
        node: Some("pve1".into()),
        guest_kind: "vm".into(),
    }
}

fn proposal(host: &str, port: u16, keys: Vec<String>) -> Proposal {
    Proposal {
        host: host.into(),
        port,
        user: "debian".into(),
        origin: Some(origin(100)),
        host_keys: keys,
        rotated_at: None,
    }
}

fn quick(host: &str, method: &str) -> QuickConnectRequest {
    QuickConnectRequest {
        host: host.into(),
        port: Some(2222),
        username: "ops".into(),
        auth_method: Some(method.into()),
        key_id: None,
        pem_path: None,
        password: Some(zeroize::Zeroizing::new("typed-pw".into())),
        proposal: None,
    }
}

#[test]
fn a_saved_match_prefers_the_origin_then_host_port_user() {
    let (db, path) = test_db();
    let by_addr = server("a", "10.0.1.5", 22, "debian");
    let by_origin = server("b", "renamed.example", 22, "root");
    db.insert_server(&by_addr).unwrap();
    db.insert_server(&by_origin).unwrap();
    db.set_server_origin("b", Some(&origin(100))).unwrap();
    let servers = db.list_servers().unwrap();
    let origins = db.server_origins().unwrap();
    let m = find_saved_match(
        &servers,
        &origins,
        "10.0.1.5",
        22,
        "debian",
        Some(&origin(100)),
    );
    assert_eq!(m.unwrap().id, "b", "same cluster+vmid wins");
    let m = find_saved_match(
        &servers,
        &origins,
        "10.0.1.5",
        22,
        "debian",
        Some(&origin(101)),
    );
    assert_eq!(m.unwrap().id, "a", "else host:port+user");
    assert!(find_saved_match(&servers, &origins, "10.0.1.5", 2222, "debian", None).is_none());
    assert!(find_saved_match(&servers, &origins, "10.0.1.5", 22, "other", None).is_none());
    let _ = std::fs::remove_file(path);
}

#[test]
fn applying_a_proposal_stores_the_origin_and_proposals_never_a_pin() {
    let (db, path) = test_db();
    db.insert_server(&server("s", "10.0.1.5", 22, "debian"))
        .unwrap();
    let key = crate::handoff::tests::host_key(4);
    let said = apply_proposal(&db, "s", &proposal("10.0.1.5", 22, vec![key.clone()]))
        .unwrap()
        .unwrap();
    assert!(said.contains("PMXSpan lab / 100"), "{said}");
    assert_eq!(db.get_server_origin("s").unwrap(), Some(origin(100)));
    let host = crate::ssh_client::known_host_key("10.0.1.5", 22);
    assert_eq!(
        db.get_proposed_host_keys(&host).unwrap().unwrap().keys,
        vec![key.clone()]
    );
    assert!(
        db.get_known_host(&host).unwrap().is_none(),
        "a proposal is not a pin"
    );
    // A server edited to another address keeps its origin but gets no
    // proposals for an address they were not made for.
    db.insert_server(&server("t", "elsewhere.example", 22, "debian"))
        .unwrap();
    apply_proposal(&db, "t", &proposal("10.0.9.9", 22, vec![key])).unwrap();
    assert!(db
        .get_proposed_host_keys(&crate::ssh_client::known_host_key("10.0.9.9", 22))
        .unwrap()
        .is_none());
    assert!(db.get_server_origin("t").unwrap().is_some());
    assert!(db
        .list_audit(20)
        .unwrap()
        .iter()
        .any(|a| a.action == "server.origin"));
    let _ = std::fs::remove_file(path);
}

#[test]
fn origins_survive_a_backup_round_trip_and_a_server_save() {
    let pw = "handoff-master";
    let (src, src_path) = test_db();
    src.insert_server(&server("s", "10.0.1.5", 22, "debian"))
        .unwrap();
    src.insert_server(&server("plain", "10.0.1.6", 22, "debian"))
        .unwrap();
    src.set_server_origin("s", Some(&origin(100))).unwrap();
    // An ordinary row write (the server dialog's edit, a Bitwarden pull)
    // leaves the origin alone.
    let mut row = src.get_server("s").unwrap().unwrap();
    row.name = "renamed".into();
    src.update_server(&row).unwrap();
    assert_eq!(src.get_server_origin("s").unwrap(), Some(origin(100)));

    let dir = std::env::temp_dir().join(format!("sshspan-origin-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("b.json");
    crate::commands::export_backup_to_path(&src, pw, &file.display().to_string(), &|| Ok(()))
        .unwrap();
    let (dst, dst_path) = test_db();
    let restored = crate::commands::restore_backup_file(&dst, &file, pw, None, &|| Ok(()));
    let _ = std::fs::remove_dir_all(&dir);
    assert!(restored.is_ok(), "{:?}", restored.err());
    assert_eq!(dst.get_server_origin("s").unwrap(), Some(origin(100)));
    assert_eq!(dst.get_server_origin("plain").unwrap(), None);
    let _ = std::fs::remove_file(src_path);
    let _ = std::fs::remove_file(dst_path);
}

#[test]
fn quick_connect_is_checked_like_a_save_and_never_written() {
    let (db, path) = test_db();
    let vault = unlocked();
    let reg = EphemeralRegistry::new();
    for (req, word) in [
        (quick("", "password"), "Host is required"),
        (quick("bad host", "password"), "spaces"),
        (
            QuickConnectRequest {
                username: " ".into(),
                ..quick("h.example", "password")
            },
            "Username",
        ),
        (
            QuickConnectRequest {
                port: Some(0),
                ..quick("h.example", "password")
            },
            "Port",
        ),
        (quick("h.example", "telnet"), "Unknown auth method"),
        (quick("h.example", "publickey"), "Choose a key"),
        (
            QuickConnectRequest {
                key_id: Some("gone".into()),
                ..quick("h.example", "publickey")
            },
            "no longer exists",
        ),
    ] {
        let err = quick_connect_open_in(&db, &vault, &reg, req).unwrap_err();
        assert!(err.0.contains(word), "{word}: {}", err.0);
    }
    let out = quick_connect_open_in(&db, &vault, &reg, quick("h.example", "password")).unwrap();
    let id = out["server"]["id"].as_str().unwrap().to_string();
    assert!(crate::quick_connect::is_ephemeral_id(&id));
    assert_eq!(out["server"]["name"], "ops@h.example", "the tab title");
    assert_eq!(out["server"]["hasSavedPassword"], true);
    assert!(
        db.list_servers().unwrap().is_empty(),
        "nothing written to SQLite"
    );
    // Resolves like a saved server, with the typed password, until forgotten.
    let rotation = crate::commands::VaultRotationLock::new();
    let request = || crate::commands::terminal::ConnectRequest {
        server_id: id.clone(),
        override_username: None,
        override_key_id: None,
        prompt_password: None,
    };
    let resolved =
        crate::commands::terminal::resolve_connection_with(&db, &reg, &vault, &rotation, request())
            .unwrap();
    assert_eq!(resolved.server.host, "h.example");
    assert_eq!(resolved.server.port, 2222);
    assert_eq!(
        resolved.password.as_deref().map(String::as_str),
        Some("typed-pw")
    );
    assert!(reg.remove(&id));
    let err =
        crate::commands::terminal::resolve_connection_with(&db, &reg, &vault, &rotation, request())
            .err()
            .unwrap();
    assert!(err.0.contains("Server not found"), "{}", err.0);
    // Locked: refused.
    vault.clear();
    assert!(quick_connect_open_in(&db, &vault, &reg, quick("h.example", "password")).is_err());
    let _ = std::fs::remove_file(path);
}

#[test]
fn quick_connect_takes_proposals_only_for_their_host_and_port() {
    let (db, path) = test_db();
    let vault = unlocked();
    let reg = EphemeralRegistry::new();
    let key = crate::handoff::tests::host_key(5);
    let with = |host: &str, port: u16| QuickConnectRequest {
        proposal: Some(proposal("10.0.1.5", 22, vec![key.clone()])),
        port: Some(port),
        ..quick(host, "password")
    };
    let same = quick_connect_open_in(&db, &vault, &reg, with("10.0.1.5", 22)).unwrap();
    let id = same["server"]["id"].as_str().unwrap();
    assert_eq!(
        reg.get(id).unwrap().proposal.unwrap().keys,
        vec![key.clone()]
    );
    let other = quick_connect_open_in(&db, &vault, &reg, with("10.0.1.6", 22)).unwrap();
    assert!(reg
        .get(other["server"]["id"].as_str().unwrap())
        .unwrap()
        .proposal
        .is_none());
    let _ = std::fs::remove_file(path);
}

#[test]
fn the_import_listing_marks_saved_rows_problems_and_host_key_status() {
    let (db, path) = test_db();
    let handoff = HandoffState::new();
    let k_pinned = crate::handoff::tests::host_key(1);
    let k_new = crate::handoff::tests::host_key(2);
    db.insert_server(&server("saved", "10.0.1.5", 22, "debian"))
        .unwrap();
    db.add_known_host(
        &crate::ssh_client::known_host_key("10.0.1.5", 22),
        &k_pinned,
        "fp",
    )
    .unwrap();
    db.add_known_host(
        &crate::ssh_client::known_host_key("10.0.1.7", 22),
        &k_pinned,
        "fp",
    )
    .unwrap();
    db.add_known_host(
        &crate::ssh_client::known_host_key("10.0.1.8", 22),
        &k_pinned,
        "fp",
    )
    .unwrap();
    let now = chrono::Utc::now();
    let host = |name: &str, addr: &str, key: Option<&str>, rotated: bool| {
        serde_json::json!({
            "kind": "vm", "vmid": 100 + name.len(), "name": name, "host": addr, "port": 22,
            "user": "debian",
            "host_keys": key.map(|k| vec![serde_json::json!({"type": "ssh-ed25519", "key": k})]).unwrap_or_default(),
            "host_key_rotated_at": if rotated { serde_json::json!(now.to_rfc3339()) } else { serde_json::Value::Null },
            "category": ["Proxmox"]
        })
    };
    let doc = serde_json::json!({
        "format": crate::handoff::BUNDLE_FORMAT, "version": 1, "created_at": now.to_rfc3339(),
        "cluster": {"id": "prof-1", "name": "lab"},
        "hosts": [
            host("a", "10.0.1.5", Some(&k_pinned), false),
            host("bb", "10.0.1.6", Some(&k_new), false),
            host("ccc", "10.0.1.7", Some(&k_new), true),
            host("dddd", "10.0.1.8", Some(&k_new), false),
            host("eeeee", "10.0.1.9", None, false),
            {"kind": "vm", "vmid": 300, "name": "nohost", "user": "debian"},
        ]
    });
    let bundle = crate::handoff::parse_bundle(&serde_json::to_vec(&doc).unwrap(), now).unwrap();
    let out = import_listing(&db, &handoff, &bundle, std::time::Instant::now()).unwrap();
    let rows = out["rows"].as_array().unwrap();
    assert_eq!(rows[0]["alreadySaved"]["id"], "saved");
    assert_eq!(rows[0]["hostKey"]["status"], "unchanged");
    assert_eq!(rows[1]["hostKey"]["status"], "new");
    assert_eq!(rows[1]["alreadySaved"], serde_json::Value::Null);
    assert_eq!(rows[2]["hostKey"]["status"], "rotated");
    assert!(rows[2]["hostKey"]["old"]
        .as_str()
        .unwrap()
        .starts_with("SHA256:"));
    assert_eq!(rows[3]["hostKey"]["status"], "conflict");
    assert_eq!(rows[4]["hostKey"]["status"], "none");
    assert!(rows[5]["problem"]
        .as_str()
        .unwrap()
        .contains("no host address"));
    assert!(
        rows[5].get("token").is_none(),
        "a row that cannot be imported has no token"
    );
    let token = rows[1]["token"].as_str().unwrap();
    let p = handoff.proposal(token, std::time::Instant::now()).unwrap();
    assert_eq!(p.host, "10.0.1.6");
    assert_eq!(p.origin.unwrap().vmid, Some(102));
    handoff.clear_proposals();
    assert!(
        handoff.proposal(token, std::time::Instant::now()).is_none(),
        "a lock drops them"
    );
    let _ = std::fs::remove_file(path);
}

#[test]
fn import_categories_are_created_as_host_paths() {
    let (db, path) = test_db();
    let vault = unlocked();
    let out = category_ensure_host_path_in(&db, &vault, "Proxmox / lab / customers").unwrap();
    let id = out["id"].as_str().unwrap().to_string();
    assert_eq!(db.category_path_string(&id), "Proxmox/lab/customers");
    assert_eq!(db.get_category(&id).unwrap().unwrap().scope, "host");
    let again = category_ensure_host_path_in(&db, &vault, "Proxmox/lab/customers").unwrap();
    assert_eq!(again["id"], id.as_str(), "found, not created twice");
    assert!(category_ensure_host_path_in(&db, &vault, "a/b/c/d/e/f/g/h/i").is_err());
    assert!(category_ensure_host_path_in(&db, &vault, "a\u{7}").is_err());
    vault.clear();
    assert!(category_ensure_host_path_in(&db, &vault, "x").is_err());
    let _ = std::fs::remove_file(path);
}

#[cfg(unix)]
#[test]
fn launching_asks_once_for_a_discovered_path_and_never_without_one() {
    use std::os::unix::fs::PermissionsExt;
    let (db, path) = test_db();
    let root = std::env::temp_dir().join(format!("sshspan-launch-{}", uuid::Uuid::new_v4()));
    let exe = root.join("usr/bin/pmxspan");
    std::fs::create_dir_all(exe.parent().unwrap()).unwrap();
    std::fs::write(&exe, b"#!/bin/sh\n").unwrap();
    std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
    let env = pmxspan::DiscoveryEnv {
        root: root.clone(),
        ..Default::default()
    };
    let questions = CredentialQuestions::new();
    let spawned = std::sync::Mutex::new(Vec::<(std::path::PathBuf, String)>::new());
    let spawn = |p: &std::path::Path, u: &str| {
        spawned
            .lock()
            .unwrap()
            .push((p.to_path_buf(), u.to_string()));
        Ok(())
    };
    let open = |_: &str| -> std::io::Result<()> { panic!("no URL handler is used") };
    let asked = std::sync::Mutex::new(0);
    let url = crate::handoff::guest_url("prof-1", 100);
    // "Don't allow": nothing starts, nothing is remembered.
    let no = |_: &crate::commands::CredentialPrompt| {
        *asked.lock().unwrap() += 1;
        CredentialAnswer::NotAllowed
    };
    assert!(launch_in(&db, &questions, &env, &url, "t", &no, &spawn, &open).is_err());
    assert!(spawned.lock().unwrap().is_empty());
    assert_eq!(db.get_config(pmxspan::APPROVED_PATH_KEY).unwrap(), None);
    // "Allow": started with the URL as its single argument, path remembered.
    let questions = CredentialQuestions::new();
    let yes = |p: &crate::commands::CredentialPrompt| {
        assert!(
            p.message.contains(&exe.display().to_string()),
            "names the exact path"
        );
        *asked.lock().unwrap() += 1;
        CredentialAnswer::Allowed
    };
    launch_in(&db, &questions, &env, &url, "t", &yes, &spawn, &open).unwrap();
    assert_eq!(spawned.lock().unwrap()[0], (exe.clone(), url.clone()));
    // The second launch does not ask.
    let never =
        |_: &crate::commands::CredentialPrompt| -> CredentialAnswer { panic!("asked again") };
    launch_in(&db, &questions, &env, &url, "t", &never, &spawn, &open).unwrap();
    assert_eq!(*asked.lock().unwrap(), 2);
    assert!(db
        .list_audit(20)
        .unwrap()
        .iter()
        .any(|a| a.action == "pmxspan.launch"));
    // Nothing installed and no handler: the hint (the real scheme check may
    // find a handler on a developer machine, so only assert when it does not).
    let empty = pmxspan::DiscoveryEnv {
        root: root.join("none"),
        ..Default::default()
    };
    if !pmxspan::scheme_registered() {
        let err = launch_in(&db, &questions, &empty, &url, "t", &never, &spawn, &open).unwrap_err();
        assert_eq!(err.0, pmxspan::NOT_FOUND_HINT);
    }
    let status = pmxspan_status_in(&db, &empty, || false);
    assert_eq!(status["available"], false);
    assert_eq!(status["hint"], pmxspan::NOT_FOUND_HINT);
    assert_eq!(status["registerLinks"], true, "on by default");
    let _ = std::fs::remove_dir_all(root);
    let _ = std::fs::remove_file(path);
}
