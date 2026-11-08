//! The link and bundle checks of INTEGRATION-SPEC v1: every refusal.

use super::*;
use base64ct::Encoding;
use chrono::{Duration, Utc};

/// A wire-format Ed25519 host key (base64) made of `byte`.
pub(crate) fn host_key(byte: u8) -> String {
    let key = ssh_key::PublicKey::new(
        ssh_key::public::KeyData::Ed25519(ssh_key::public::Ed25519PublicKey([byte; 32])),
        "",
    );
    base64ct::Base64::encode_string(&key.to_bytes().unwrap())
}

fn connect(query: &str) -> Result<ConnectLink, String> {
    match parse_link(&format!("sshspan://connect?{query}"))? {
        Link::Connect(c) => Ok(c),
        other => panic!("not a connect link: {other:?}"),
    }
}

const BASE: &str = "v=1&host=10.0.1.5&port=22&user=debian";

#[test]
fn a_full_connect_link_parses_into_typed_values() {
    let k1 = host_key(1);
    let k2 = host_key(2);
    let url = format!(
        "{BASE}&name=web%2001&source=pmxspan&cluster=prof-1&clustername=lab&kind=vm&vmid=100\
         &node=pve1&pool=customers&hostkey={}&hostkey={}&hostkey_rotated=1762600000&future=ignored",
        percent_encode(&k1),
        percent_encode(&k2)
    );
    let c = connect(&url).unwrap();
    assert_eq!(c.host, "10.0.1.5");
    assert_eq!(c.port, 22);
    assert_eq!(c.user, "debian");
    assert_eq!(c.name, "web 01", "%20 decodes to a space");
    assert_eq!(c.pool.as_deref(), Some("customers"));
    assert_eq!(c.host_keys, vec![k1, k2]);
    assert_eq!(c.host_key_rotated, Some(1_762_600_000));
    let o = c.origin.unwrap();
    assert_eq!(o.cluster_id, "prof-1");
    assert_eq!(o.cluster_name.as_deref(), Some("lab"));
    assert_eq!(o.vmid, Some(100));
    assert_eq!(o.guest_kind, "vm");
    assert!(o.is_valid());
}

#[test]
fn defaults_ipv6_and_case_insensitive_scheme() {
    let c = match parse_link("SSHSpan://connect?v=1&host=2001:db8::1&port=2222&user=root").unwrap()
    {
        Link::Connect(c) => c,
        _ => unreachable!(),
    };
    assert_eq!(c.host, "2001:db8::1");
    assert_eq!(c.name, "2001:db8::1", "name defaults to the host");
    assert!(c.origin.is_none());
    assert!(c.host_keys.is_empty());
}

#[test]
fn plus_is_not_a_space() {
    let c = connect(&format!("{BASE}&name=a+b")).unwrap();
    assert_eq!(c.name, "a+b");
}

#[test]
fn origin_only_for_pmxspan_with_cluster_and_kind() {
    let c = connect(&format!("{BASE}&source=other&cluster=c&kind=vm&vmid=100")).unwrap();
    assert!(c.origin.is_none(), "another source enables no PMXSpan UI");
    let c = connect(&format!("{BASE}&source=pmxspan&kind=vm&vmid=100")).unwrap();
    assert!(c.origin.is_none(), "no cluster");
    let c = connect(&format!(
        "{BASE}&source=pmxspan&cluster=c&kind=node&node=pve1&vmid=100"
    ))
    .unwrap();
    let o = c.origin.unwrap();
    assert_eq!(
        (o.guest_kind.as_str(), o.vmid, o.node.as_deref()),
        ("node", None, Some("pve1"))
    );
}

/// Each refusal, with a word the message must contain.
#[test]
fn every_refusal_names_its_problem() {
    let long = "a".repeat(MAX_URL_BYTES);
    let cases: Vec<(String, &str)> = vec![
        (
            format!("sshspan://connect?{BASE}&x={long}"),
            "longer than 8192",
        ),
        ("https://connect?v=1".into(), "not an sshspan"),
        ("sshspan:connect?v=1".into(), "not an sshspan"),
        (
            "sshspan://connect?host=h&port=22&user=u".into(),
            "no version",
        ),
        (
            "sshspan://connect?v=2&host=h&port=22&user=u&source=pmxspan".into(),
            "newer PMXSpan",
        ),
        (
            "sshspan://connect?v=abc&host=h&port=22&user=u".into(),
            "not supported",
        ),
        (format!("sshspan://launch?{BASE}"), "does not know"),
        ("sshspan://connect?v=1&port=22&user=u".into(), "no host"),
        ("sshspan://connect?v=1&host=h&user=u".into(), "no port"),
        ("sshspan://connect?v=1&host=h&port=22".into(), "no user"),
        (
            format!("sshspan://connect?{BASE}&host=other"),
            "more than once",
        ),
        (
            "sshspan://connect?v=1&host=bad_host&port=22&user=u".into(),
            "DNS name",
        ),
        (
            "sshspan://connect?v=1&host=%5B::1%5D&port=22&user=u".into(),
            "DNS name",
        ),
        (
            "sshspan://connect?v=1&host=-x.example&port=22&user=u".into(),
            "DNS name",
        ),
        (
            "sshspan://connect?v=1&host=999.1.1.1&port=22&user=u".into(),
            "DNS name",
        ),
        (
            "sshspan://connect?v=1&host=h&port=0&user=u".into(),
            "1 to 65535",
        ),
        (
            "sshspan://connect?v=1&host=h&port=65536&user=u".into(),
            "1 to 65535",
        ),
        (
            "sshspan://connect?v=1&host=h&port=%2B22&user=u".into(),
            "1 to 65535",
        ),
        (
            "sshspan://connect?v=1&host=h&port=22&user=a%20b".into(),
            "not allowed",
        ),
        (
            format!(
                "sshspan://connect?v=1&host=h&port=22&user={}",
                "u".repeat(65)
            ),
            "not allowed",
        ),
        (
            format!("sshspan://connect?{BASE}&name={}", "n".repeat(129)),
            "longer than 128",
        ),
        (
            format!("sshspan://connect?{BASE}&name=a%0Ab"),
            "control characters",
        ),
        (
            format!("sshspan://connect?{BASE}&clustername=a%07"),
            "control characters",
        ),
        (
            format!("sshspan://connect?{BASE}&vmid=99"),
            "100 to 999999999",
        ),
        (
            format!("sshspan://connect?{BASE}&vmid=1000000000"),
            "100 to 999999999",
        ),
        (
            format!("sshspan://connect?{BASE}&kind=lxc"),
            "vm, ct or node",
        ),
        (
            format!("sshspan://connect?{BASE}&source=pmxspan&cluster=c&kind=vm"),
            "without its vmid",
        ),
        (
            format!("sshspan://connect?{BASE}&source=pmxspan&cluster=c&kind=node"),
            "without its node",
        ),
        (format!("sshspan://connect?{BASE}&hostkey=%%%"), "%-escape"),
        (
            format!("sshspan://connect?{BASE}&hostkey=!!notbase64"),
            "not valid base64",
        ),
        (
            format!("sshspan://connect?{BASE}&hostkey=AAAA"),
            "not an SSH public key",
        ),
        (
            format!("sshspan://connect?{BASE}&hostkey_rotated=-5"),
            "Unix seconds",
        ),
        (
            format!("sshspan://connect?{BASE}&hostkey_rotated=yesterday"),
            "Unix seconds",
        ),
        (format!("sshspan://connect?{BASE}&name=%FF"), "not UTF-8"),
        ("sshspan://import?v=1&sha256=00".into(), "no bundle"),
        (
            "sshspan://import?v=1&bundle=relative.json&sha256=00".into(),
            "not absolute",
        ),
        (
            format!(
                "sshspan://import?v=1&bundle=%2Ftmp%2Fb.json&sha256={}",
                "0".repeat(63)
            ),
            "64 hexadecimal",
        ),
        (
            format!(
                "sshspan://import?v=1&bundle=%2Ftmp%2Fb.json&sha256={}",
                "g".repeat(64)
            ),
            "64 hexadecimal",
        ),
        (
            "sshspan://import?v=1&bundle=%2Ftmp%2Fb.json".into(),
            "no sha256",
        ),
    ];
    for (url, word) in cases {
        let err = parse_link(&url).expect_err(&url);
        assert!(err.contains(word), "{url}: {err}");
    }
    let keys: String = (0..=MAX_HOST_KEYS as u8)
        .map(|i| format!("&hostkey={}", percent_encode(&host_key(i))))
        .collect();
    let err = parse_link(&format!("sshspan://connect?{BASE}{keys}")).unwrap_err();
    assert!(err.contains("more than 8 host keys"), "{err}");
}

#[test]
fn an_import_link_parses() {
    #[cfg(unix)]
    let (path, encoded) = (
        "/run/user/1000/pmxspan/handoff/ab.json",
        "%2Frun%2Fuser%2F1000%2Fpmxspan%2Fhandoff%2Fab.json",
    );
    #[cfg(windows)]
    let (path, encoded) = ("C:\\Users\\u\\b.json", "C%3A%5CUsers%5Cu%5Cb.json");
    let url = format!(
        "sshspan://import?v=1&source=pmxspan&bundle={encoded}&sha256={}",
        "ab".repeat(32)
    );
    match parse_link(&url).unwrap() {
        Link::Import(i) => {
            assert_eq!(i.bundle, std::path::PathBuf::from(path));
            assert_eq!(i.sha256, [0xab; 32]);
            assert_eq!(i.source.as_deref(), Some("pmxspan"));
        }
        _ => unreachable!(),
    }
}

#[test]
fn pmxspan_urls_are_percent_encoded() {
    assert_eq!(
        guest_url("lab 1/a", 100),
        "pmxspan://guest?v=1&cluster=lab%201%2Fa&vmid=100"
    );
    assert_eq!(
        node_url("c", "pve&1"),
        "pmxspan://node?v=1&cluster=c&node=pve%261"
    );
    let line = "ssh-ed25519 AAAAC3Nza+/= me@host";
    assert_eq!(
        add_key_url(line, "my key"),
        "pmxspan://add-key?v=1&key=ssh-ed25519%20AAAAC3Nza%2B%2F%3D%20me%40host&name=my%20key&source=sshspan"
    );
    // Round trip through the receiving decoder.
    assert_eq!(percent_decode(&percent_encode(line)).unwrap(), line);
    let origin = Origin {
        kind: ORIGIN_PMXSPAN.into(),
        cluster_id: "c".into(),
        cluster_name: None,
        vmid: None,
        node: Some("pve1".into()),
        guest_kind: "node".into(),
    };
    assert_eq!(
        manage_url(&origin).unwrap(),
        "pmxspan://node?v=1&cluster=c&node=pve1"
    );
    let guest = Origin {
        vmid: Some(101),
        guest_kind: "ct".into(),
        node: None,
        ..origin.clone()
    };
    assert_eq!(
        manage_url(&guest).unwrap(),
        "pmxspan://guest?v=1&cluster=c&vmid=101"
    );
    let broken = Origin {
        vmid: None,
        ..guest
    };
    assert!(manage_url(&broken).is_none());
}

#[test]
fn origins_from_a_backup_are_checked() {
    let ok = serde_json::json!({"kind":"pmxspan","clusterId":"c","clusterName":"lab","vmid":100,"node":"pve1","guestKind":"vm"});
    assert!(Origin::from_backup(Some(&ok)).is_some());
    for bad in [
        serde_json::json!({"kind":"other","clusterId":"c","vmid":100,"guestKind":"vm"}),
        serde_json::json!({"kind":"pmxspan","clusterId":"","vmid":100,"guestKind":"vm"}),
        serde_json::json!({"kind":"pmxspan","clusterId":"c","vmid":5,"guestKind":"vm"}),
        serde_json::json!({"kind":"pmxspan","clusterId":"c","guestKind":"vm"}),
        serde_json::json!({"kind":"pmxspan","clusterId":"c\n","vmid":100,"guestKind":"vm"}),
        serde_json::json!({"kind":"pmxspan","clusterId":"c","guestKind":"node"}),
        serde_json::json!("nope"),
    ] {
        assert!(Origin::from_backup(Some(&bad)).is_none(), "{bad}");
    }
    assert!(Origin::from_backup(None).is_none());
}

// ─── bundles ────────────────────────────────────────────────────────────────

fn bundle_json(created: chrono::DateTime<Utc>, hosts: serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "format": BUNDLE_FORMAT,
        "version": 1,
        "created_at": created.to_rfc3339(),
        "pmxspan_version": "0.7.0",
        "cluster": { "id": "prof-1", "name": "lab", "host": "pve.example", "port": 8006 },
        "something_new": { "ignored": true },
        "hosts": hosts,
    }))
    .unwrap()
}

fn good_host() -> serde_json::Value {
    serde_json::json!({
        "kind": "vm", "vmid": 100, "node": "pve1", "name": "web01", "pool": "customers",
        "tags": ["PMXSpan"], "host": "10.0.1.5", "port": 22, "user": "debian",
        "host_keys": [{ "type": "ssh-ed25519", "key": host_key(9), "fetched_at": "2026-11-08T11:59:00Z" }],
        "host_key_rotated_at": null,
        "category": ["Proxmox", "lab", "cust/omers"],
        "unknown_member": 1
    })
}

struct TempDir(std::path::PathBuf);
impl TempDir {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!("sshspan-bundle-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn sha(bytes: &[u8]) -> [u8; 32] {
    sha2::Sha256::digest(bytes).into()
}

#[test]
fn a_valid_bundle_is_read_tolerantly() {
    let dir = TempDir::new();
    let now = Utc::now();
    let mut node = good_host();
    node["kind"] = "node".into();
    node.as_object_mut().unwrap().remove("vmid");
    node.as_object_mut().unwrap().remove("user");
    node["host_keys"] = serde_json::json!([]);
    let bytes = bundle_json(
        now - Duration::minutes(5),
        serde_json::json!([good_host(), node]),
    );
    let path = dir.0.join("b.json");
    std::fs::write(&path, &bytes).unwrap();
    let b = read_bundle(&path, &sha(&bytes), now).unwrap();
    assert_eq!(b.cluster.id, "prof-1");
    assert_eq!(b.cluster.name.as_deref(), Some("lab"));
    assert_eq!(b.hosts.len(), 2);
    let vm = &b.hosts[0];
    assert!(vm.problem.is_none(), "{:?}", vm.problem);
    assert_eq!(vm.host_keys[0].key, host_key(9));
    assert_eq!(vm.host_keys[0].key_type, "ssh-ed25519");
    assert!(vm.host_keys[0].fingerprint.starts_with("SHA256:"));
    assert_eq!(
        vm.category,
        vec!["Proxmox", "lab", "cust-omers"],
        "no / inside a segment"
    );
    let node = &b.hosts[1];
    assert!(node.problem.is_none(), "{:?}", node.problem);
    assert_eq!(node.user, "root", "a node defaults to root");
    assert_eq!(node.vmid, None);
}

#[test]
fn rows_that_cannot_be_imported_say_why() {
    let now = Utc::now();
    let mut no_host = good_host();
    no_host["host"] = "".into();
    let mut bad_user = good_host();
    bad_user["user"] = "a b".into();
    let mut bad_key = good_host();
    bad_key["host_keys"] = serde_json::json!([{ "type": "ssh-rsa", "key": host_key(1) }]);
    let mut bad_port = good_host();
    bad_port["port"] = 70000.into();
    let mut no_vmid = good_host();
    no_vmid.as_object_mut().unwrap().remove("vmid");
    let bytes = bundle_json(
        now,
        serde_json::json!([no_host, bad_user, bad_key, bad_port, no_vmid]),
    );
    let b = parse_bundle(&bytes, now).unwrap();
    let problems: Vec<String> = b
        .hosts
        .iter()
        .map(|h| h.problem.clone().unwrap_or_default())
        .collect();
    assert!(problems[0].contains("no host address"), "{}", problems[0]);
    assert!(
        problems[1].contains("user name is not allowed"),
        "{}",
        problems[1]
    );
    assert!(
        problems[2].contains("says it is ssh-rsa"),
        "{}",
        problems[2]
    );
    assert!(problems[3].contains("port"), "{}", problems[3]);
    assert!(problems[4].contains("no vmid"), "{}", problems[4]);
}

/// Each bundle check, in order, with the word its message names.
#[test]
fn every_bundle_check_refuses_with_its_name() {
    let dir = TempDir::new();
    let now = Utc::now();
    let good = bundle_json(now, serde_json::json!([good_host()]));
    let path = dir.0.join("b.json");
    std::fs::write(&path, &good).unwrap();

    // Absolute path.
    let err = read_bundle(std::path::Path::new("relative/b.json"), &sha(&good), now).unwrap_err();
    assert!(err.contains("not absolute"), "{err}");
    // Missing.
    let err = read_bundle(&dir.0.join("missing.json"), &sha(&good), now).unwrap_err();
    assert!(err.contains("could not be read"), "{err}");
    // A directory is not a regular file.
    let err = read_bundle(&dir.0, &sha(&good), now).unwrap_err();
    assert!(err.contains("not a regular file"), "{err}");
    // A symlink, even to a good bundle.
    #[cfg(unix)]
    {
        let link = dir.0.join("link.json");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        let err = read_bundle(&link, &sha(&good), now).unwrap_err();
        assert!(err.contains("symbolic link"), "{err}");
    }
    // Too big.
    let big = dir.0.join("big.json");
    std::fs::write(&big, vec![b' '; MAX_BUNDLE_BYTES as usize + 1]).unwrap();
    let err = read_bundle(&big, &[0; 32], now).unwrap_err();
    assert!(err.contains("larger than 4 MiB"), "{err}");
    // SHA-256.
    let err = read_bundle(&path, &[0; 32], now).unwrap_err();
    assert!(err.contains("SHA-256"), "{err}");
    // Format, version, age.
    let refuse = |bytes: Vec<u8>, word: &str| {
        let p = dir.0.join(format!("{}.json", uuid::Uuid::new_v4()));
        std::fs::write(&p, &bytes).unwrap();
        let err = read_bundle(&p, &sha(&bytes), now).unwrap_err();
        assert!(err.contains(word), "{word}: {err}");
    };
    let mut doc: serde_json::Value = serde_json::from_slice(&good).unwrap();
    doc["format"] = "other".into();
    refuse(serde_json::to_vec(&doc).unwrap(), "format");
    let mut doc: serde_json::Value = serde_json::from_slice(&good).unwrap();
    doc["version"] = 2.into();
    refuse(serde_json::to_vec(&doc).unwrap(), "newer PMXSpan");
    let mut doc: serde_json::Value = serde_json::from_slice(&good).unwrap();
    doc["version"] = 0.into();
    refuse(serde_json::to_vec(&doc).unwrap(), "version is not 1");
    refuse(
        bundle_json(now - Duration::minutes(61), serde_json::json!([])),
        "60 minutes old",
    );
    refuse(
        bundle_json(now + Duration::minutes(30), serde_json::json!([])),
        "future",
    );
    let mut doc: serde_json::Value = serde_json::from_slice(&good).unwrap();
    doc["created_at"] = "yesterday".into();
    refuse(serde_json::to_vec(&doc).unwrap(), "created_at");
    refuse(b"not json".to_vec(), "not valid JSON");
    refuse(b"[]".to_vec(), "not a JSON object");
    let mut doc: serde_json::Value = serde_json::from_slice(&good).unwrap();
    doc.as_object_mut().unwrap().remove("cluster");
    refuse(serde_json::to_vec(&doc).unwrap(), "no cluster");
    let mut doc: serde_json::Value = serde_json::from_slice(&good).unwrap();
    doc.as_object_mut().unwrap().remove("hosts");
    refuse(serde_json::to_vec(&doc).unwrap(), "no host list");
    // And the good one still reads.
    assert!(read_bundle(&path, &sha(&good), now).is_ok());
}

/// PMXSpan's side (spec Deviations): `"pool": null` for a guest without a
/// pool, node rows without `vmid` and with the "Nodes" category.
#[test]
fn null_pool_and_node_rows_as_pmxspan_writes_them() {
    let now = Utc::now();
    let guest = serde_json::json!({
        "kind": "ct", "vmid": 101, "node": "pve1", "name": "db01", "pool": null,
        "tags": [], "host": "10.0.1.6", "port": 22, "user": "root",
        "host_keys": [], "host_key_rotated_at": null,
        "category": ["Proxmox", "lab", "Containers"]
    });
    let node = serde_json::json!({
        "kind": "node", "node": "pve1", "name": "pve1", "pool": null,
        "host": "10.0.0.11", "port": 22, "host_keys": [], "host_key_rotated_at": null,
        "category": ["Proxmox", "lab", "Nodes"]
    });
    let b = parse_bundle(&bundle_json(now, serde_json::json!([guest, node])), now).unwrap();
    assert!(b.hosts[0].problem.is_none(), "{:?}", b.hosts[0].problem);
    assert_eq!(b.hosts[0].pool, None);
    assert!(b.hosts[1].problem.is_none(), "{:?}", b.hosts[1].problem);
    assert_eq!((b.hosts[1].vmid, b.hosts[1].user.as_str()), (None, "root"));
    assert_eq!(b.hosts[1].category, vec!["Proxmox", "lab", "Nodes"]);
    let origin = b.hosts[1].origin(&b.cluster);
    assert!(origin.is_valid());
    assert_eq!(
        manage_url(&origin).unwrap(),
        "pmxspan://node?v=1&cluster=prof-1&node=pve1"
    );
}
