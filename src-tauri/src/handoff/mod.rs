//! `sshspan://` links from PMXSpan, and the `pmxspan://` links SSHSpan sends
//! back (the shared contract is `INTEGRATION-SPEC.md` v1, sections 1-3 and 7).
//!
//! Everything a link or a bundle file carries is untrusted input from another
//! program: it is parsed and checked here, in Rust, and only typed, validated
//! values ever reach the renderer. Nothing received connects, saves or trusts
//! anything by itself - a link lands in the Quick connect dialog, a bundle in
//! the "Import from PMXSpan" dialog, and host keys from either are PROPOSED
//! pins that the host-key check in `ssh_client` compares against the key the
//! server presents ([`crate::ssh_client::HostKeyProposal`]).
//!
//! - [`parse_link`]: one `sshspan://connect` or `sshspan://import` URL.
//! - [`read_bundle`]: the bulk handoff file an `import` link names.
//! - [`guest_url`], [`node_url`], [`add_key_url`]: the `pmxspan://` URLs,
//!   built and percent-encoded here - the renderer only asks for them.
//! - [`state::HandoffState`]: the link waiting for an unlock and the
//!   proposals a link left for the dialog that shows it.

pub mod state;

#[cfg(test)]
pub(crate) mod tests;

use base64ct::Encoding;
use serde::Serialize;
use sha2::Digest;
use std::path::{Path, PathBuf};

/// The longest URL accepted, in bytes (spec section 1).
pub const MAX_URL_BYTES: usize = 8192;
/// The largest bundle file read, in bytes (spec section 2.2).
pub const MAX_BUNDLE_BYTES: u64 = 4 * 1024 * 1024;
/// How old a bundle may be when it is read (spec section 2.2).
pub const BUNDLE_MAX_AGE_SECS: i64 = 60 * 60;
/// How far in the future a bundle's `created_at` may lie: the two apps run
/// on one computer, so this only absorbs a clock step between the write and
/// the read.
pub const BUNDLE_FUTURE_SKEW_SECS: i64 = 5 * 60;
/// The most host keys one link or bundle row may propose (one per key type;
/// OpenSSH has four).
pub const MAX_HOST_KEYS: usize = 8;
/// The most hosts a bundle row list may hold.
pub const MAX_BUNDLE_HOSTS: usize = 5000;
/// The longest name (in characters) the contract allows.
pub const MAX_NAME_CHARS: usize = 128;
/// The bundle's `format`.
pub const BUNDLE_FORMAT: &str = "pmxspan-sshspan-handoff";
/// The origin kind stored for a server that came from PMXSpan.
pub const ORIGIN_PMXSPAN: &str = "pmxspan";
/// The known-hosts `source` of a pin verified against a PMXSpan proposal.
pub const PIN_SOURCE_PMXSPAN: &str = "imported:pmxspan";

/// Where a server lives in PMXSpan (spec section 2.3): stored in the
/// `servers.origin_*` columns and used to build `pmxspan://guest` /
/// `pmxspan://node`. Every value was checked before it got here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Origin {
    /// Always [`ORIGIN_PMXSPAN`] today.
    pub kind: String,
    pub cluster_id: String,
    pub cluster_name: Option<String>,
    pub vmid: Option<u32>,
    pub node: Option<String>,
    /// `vm`, `ct` or `node`.
    pub guest_kind: String,
}

impl Origin {
    /// Whether every field keeps the contract's rules: what a backup restore
    /// checks before it writes an origin back (a backup is untrusted input).
    pub fn is_valid(&self) -> bool {
        let name_ok = |v: &str| !v.is_empty() && check_name("", v).is_ok();
        self.kind == ORIGIN_PMXSPAN
            && name_ok(&self.cluster_id)
            && self.cluster_name.as_deref().is_none_or(name_ok)
            && self.node.as_deref().is_none_or(name_ok)
            && self.vmid.is_none_or(|v| valid_vmid(v.into()))
            && match self.guest_kind.as_str() {
                "vm" | "ct" => self.vmid.is_some(),
                "node" => self.node.is_some(),
                _ => false,
            }
    }

    /// An origin read from a backup's server entry, when it is valid.
    pub fn from_backup(value: Option<&serde_json::Value>) -> Option<Self> {
        let origin: Self = serde_json::from_value(value?.clone()).ok()?;
        origin.is_valid().then_some(origin)
    }
}

/// A validated `sshspan://connect`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectLink {
    pub host: String,
    pub port: u16,
    pub user: String,
    /// `name`, or the host when the link has none.
    pub name: String,
    pub source: Option<String>,
    /// Only for `source=pmxspan` with a cluster and a guest kind.
    pub origin: Option<Origin>,
    pub pool: Option<String>,
    /// Canonical base64 SSH wire-format host keys, each one parsed.
    pub host_keys: Vec<String>,
    /// Unix seconds; present only after a rebuild changed the key.
    pub host_key_rotated: Option<i64>,
}

/// A validated `sshspan://import`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportLink {
    pub source: Option<String>,
    pub bundle: PathBuf,
    pub sha256: [u8; 32],
}

/// One validated link.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum Link {
    Connect(ConnectLink),
    Import(ImportLink),
}

/// Whether `text` starts like an `sshspan:` URL (scheme case-insensitive):
/// what a command-line argument must look like to be taken as a link.
pub fn looks_like_link(text: &str) -> bool {
    text.len() >= 8 && text.as_bytes()[..8].eq_ignore_ascii_case(b"sshspan:")
}

/// The name of the program that made a link, for messages.
fn peer_name(source: Option<&str>) -> &'static str {
    match source {
        Some(s) if s.eq_ignore_ascii_case(ORIGIN_PMXSPAN) => "PMXSpan",
        _ => "app",
    }
}

/// Parse and validate one `sshspan://` URL. The error is the message the
/// user sees, naming the problem.
pub fn parse_link(url: &str) -> Result<Link, String> {
    if url.len() > MAX_URL_BYTES {
        return Err(format!(
            "The link is longer than {MAX_URL_BYTES} bytes, so it was refused."
        ));
    }
    if !looks_like_link(url) {
        return Err("The link is not an sshspan:// link.".into());
    }
    let rest = &url["sshspan:".len()..];
    let rest = rest
        .strip_prefix("//")
        .ok_or_else(|| "The link is not an sshspan:// link.".to_string())?;
    // A fragment carries nothing the contract defines.
    let rest = rest.split('#').next().unwrap_or("");
    let (action, query) = match rest.find('?') {
        Some(i) => (&rest[..i], &rest[i + 1..]),
        None => (rest, ""),
    };
    let action = action.trim_end_matches('/');
    let params = Params::parse(query)?;
    let source = params.single("source")?;
    if let Some(s) = source.as_deref() {
        check_name("source", s)?;
    }
    match params.single("v")?.as_deref() {
        None => return Err("The link has no version (v=1 is required).".into()),
        Some("1") => {}
        Some(v) => {
            let peer = peer_name(source.as_deref());
            return Err(match v.parse::<u64>() {
                Ok(n) if n > 1 => format!(
                    "This link was made by a newer {peer} (link version {}); update SSHSpan.",
                    v
                ),
                _ => format!(
                    "The link's version \"{}\" is not supported (only v=1 is).",
                    shown(v)
                ),
            });
        }
    }
    if action.eq_ignore_ascii_case("connect") {
        parse_connect(&params, source).map(Link::Connect)
    } else if action.eq_ignore_ascii_case("import") {
        parse_import(&params, source).map(Link::Import)
    } else {
        Err(format!(
            "The link asks for \"{}\", which SSHSpan does not know (connect or import).",
            shown(action)
        ))
    }
}

fn parse_connect(params: &Params, source: Option<String>) -> Result<ConnectLink, String> {
    let host = params
        .single("host")?
        .ok_or_else(|| "The link has no host.".to_string())?;
    check_host(&host)?;
    let port = params
        .single("port")?
        .ok_or_else(|| "The link has no port.".to_string())?;
    let port = parse_port(&port)?;
    let user = params
        .single("user")?
        .ok_or_else(|| "The link has no user.".to_string())?;
    check_user(&user)?;
    let name = match params.single("name")? {
        Some(n) if !n.is_empty() => {
            check_name("name", &n)?;
            n
        }
        _ => host.clone(),
    };
    let pool = optional_name(params, "pool")?;
    let cluster = optional_name(params, "cluster")?;
    let cluster_name = optional_name(params, "clustername")?;
    let node = optional_name(params, "node")?;
    let kind = params.single("kind")?;
    if let Some(k) = kind.as_deref() {
        if !matches!(k, "vm" | "ct" | "node") {
            return Err(format!(
                "The link's kind \"{}\" is not vm, ct or node.",
                shown(k)
            ));
        }
    }
    let vmid = match params.single("vmid")? {
        Some(v) => Some(parse_vmid(&v)?),
        None => None,
    };
    let host_keys = params
        .all("hostkey")
        .iter()
        .map(|k| canonical_host_key(k))
        .collect::<Result<Vec<_>, _>>()?;
    if host_keys.len() > MAX_HOST_KEYS {
        return Err(format!(
            "The link proposes more than {MAX_HOST_KEYS} host keys, so it was refused."
        ));
    }
    let host_key_rotated = match params.single("hostkey_rotated")? {
        Some(t) => Some(parse_unix_seconds(&t)?),
        None => None,
    };
    let from_pmxspan = source
        .as_deref()
        .is_some_and(|s| s.eq_ignore_ascii_case(ORIGIN_PMXSPAN));
    let origin = match (from_pmxspan, cluster, kind) {
        (true, Some(cluster_id), Some(kind)) => {
            match kind.as_str() {
                "vm" | "ct" if vmid.is_none() => {
                    return Err(format!("The link names a {kind} without its vmid."))
                }
                "node" if node.is_none() => {
                    return Err("The link names a node without its node name.".into())
                }
                _ => {}
            }
            Some(Origin {
                kind: ORIGIN_PMXSPAN.into(),
                cluster_id,
                cluster_name,
                vmid: if kind == "node" { None } else { vmid },
                node,
                guest_kind: kind,
            })
        }
        _ => None,
    };
    Ok(ConnectLink {
        host,
        port,
        user,
        name,
        source,
        origin,
        pool,
        host_keys,
        host_key_rotated,
    })
}

fn parse_import(params: &Params, source: Option<String>) -> Result<ImportLink, String> {
    let bundle = params
        .single("bundle")?
        .ok_or_else(|| "The import link names no bundle file.".to_string())?;
    if bundle.chars().any(char::is_control) {
        return Err("The bundle path holds control characters.".into());
    }
    let path = PathBuf::from(&bundle);
    if !path.is_absolute() {
        return Err("The bundle path is not absolute.".into());
    }
    let digest = params
        .single("sha256")?
        .ok_or_else(|| "The import link has no sha256.".to_string())?;
    if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("The import link's sha256 is not 64 hexadecimal digits.".into());
    }
    let mut sha256 = [0u8; 32];
    hex::decode_to_slice(&digest, &mut sha256)
        .map_err(|_| "The import link's sha256 is not 64 hexadecimal digits.".to_string())?;
    Ok(ImportLink {
        source,
        bundle: path,
        sha256,
    })
}

/// The decoded query of a link: name -> every value given for it, in order.
struct Params(Vec<(String, String)>);

impl Params {
    fn parse(query: &str) -> Result<Self, String> {
        let mut out = Vec::new();
        for pair in query.split('&').filter(|p| !p.is_empty()) {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            let key = percent_decode(k)?;
            let value = percent_decode(v)?;
            out.push((key, value));
        }
        Ok(Self(out))
    }

    /// The value of `name`, refused when it is given more than once: two
    /// hosts in one link would leave the reader guessing which one counts.
    fn single(&self, name: &str) -> Result<Option<String>, String> {
        let mut found = self.0.iter().filter(|(k, _)| k == name);
        let first = found.next().map(|(_, v)| v.clone());
        if found.next().is_some() {
            return Err(format!("The link gives \"{name}\" more than once."));
        }
        Ok(first)
    }

    fn all(&self, name: &str) -> Vec<String> {
        self.0
            .iter()
            .filter(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
            .collect()
    }
}

fn optional_name(params: &Params, name: &str) -> Result<Option<String>, String> {
    match params.single(name)? {
        Some(v) if !v.is_empty() => {
            check_name(name, &v)?;
            Ok(Some(v))
        }
        _ => Ok(None),
    }
}

/// Strict percent-decoding of one URL component: `%XX` only (a lone `%` is
/// refused), `+` stays a plus (the contract does not use form encoding), and
/// the result must be UTF-8.
pub fn percent_decode(text: &str) -> Result<String, String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hexpair = bytes
                .get(i + 1..i + 3)
                .and_then(|h| std::str::from_utf8(h).ok())
                .and_then(|h| u8::from_str_radix(h, 16).ok())
                .ok_or_else(|| "The link has a broken %-escape.".to_string())?;
            out.push(hexpair);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| "The link holds text that is not UTF-8.".to_string())
}

/// Percent-encode one value for a `pmxspan://` URL: everything but the RFC
/// 3986 unreserved characters, so a space is `%20` (never `+`).
pub fn percent_encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for b in text.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// A value quoted in a message: control and invisible characters spelled
/// out, and cut at 64 characters.
fn shown(text: &str) -> String {
    let spelled = crate::ssh_client::spell_out(text);
    if spelled.chars().count() > 64 {
        let cut: String = spelled.chars().take(64).collect();
        format!("{cut}...")
    } else {
        spelled
    }
}

/// A DNS name or an IP literal (IPv6 without brackets).
pub fn check_host(host: &str) -> Result<(), String> {
    if valid_host(host) {
        Ok(())
    } else {
        Err(format!(
            "The host \"{}\" is not a DNS name or an IP address.",
            shown(host)
        ))
    }
}

/// [`check_host`] as a predicate.
pub fn valid_host(host: &str) -> bool {
    if host.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    // All-numeric dotted text that is not an IPv4 address (999.1.1.1) is
    // not a name either.
    if host.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    })
}

/// `[A-Za-z0-9._@-]{1,64}`.
pub fn check_user(user: &str) -> Result<(), String> {
    if valid_user(user) {
        Ok(())
    } else {
        Err(format!(
            "The user name \"{}\" is not allowed (1-64 of A-Z a-z 0-9 . _ @ -).",
            shown(user)
        ))
    }
}

/// [`check_user`] as a predicate.
pub fn valid_user(user: &str) -> bool {
    (1..=64).contains(&user.len())
        && user
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'@' | b'-'))
}

/// A display name: at most [`MAX_NAME_CHARS`] characters, none a control
/// character.
pub fn check_name(what: &str, value: &str) -> Result<(), String> {
    if value.chars().count() > MAX_NAME_CHARS {
        return Err(format!(
            "The link's {what} is longer than {MAX_NAME_CHARS} characters."
        ));
    }
    if value.chars().any(char::is_control) {
        return Err(format!("The link's {what} holds control characters."));
    }
    Ok(())
}

fn parse_port(text: &str) -> Result<u16, String> {
    match text.parse::<u32>() {
        Ok(n) if text.bytes().all(|b| b.is_ascii_digit()) && (1..=65535).contains(&n) => {
            Ok(n as u16)
        }
        _ => Err(format!(
            "The port \"{}\" is not a number from 1 to 65535.",
            shown(text)
        )),
    }
}

/// A Proxmox VMID: 100..=999999999.
pub fn valid_vmid(n: u64) -> bool {
    (100..=999_999_999).contains(&n)
}

fn parse_vmid(text: &str) -> Result<u32, String> {
    match text.parse::<u64>() {
        Ok(n) if text.bytes().all(|b| b.is_ascii_digit()) && valid_vmid(n) => Ok(n as u32),
        _ => Err(format!(
            "The vmid \"{}\" is not a number from 100 to 999999999.",
            shown(text)
        )),
    }
}

fn parse_unix_seconds(text: &str) -> Result<i64, String> {
    match text.parse::<i64>() {
        Ok(n) if text.bytes().all(|b| b.is_ascii_digit()) && n > 0 && n < 32_503_680_000 => Ok(n),
        _ => Err(format!(
            "The hostkey_rotated value \"{}\" is not a time in Unix seconds.",
            shown(text)
        )),
    }
}

/// A proposed host key: base64 that decodes to a public key in SSH wire
/// format (parsed by `ssh-key`), returned re-encoded in canonical base64 -
/// the form the known-hosts store and the live comparison use.
pub fn canonical_host_key(b64: &str) -> Result<String, String> {
    let bytes = base64ct::Base64::decode_vec(b64.trim())
        .map_err(|_| "A proposed host key is not valid base64.".to_string())?;
    let key = ssh_key::PublicKey::from_bytes(&bytes)
        .map_err(|_| "A proposed host key is not an SSH public key.".to_string())?;
    let wire = key
        .to_bytes()
        .map_err(|_| "A proposed host key is not an SSH public key.".to_string())?;
    Ok(base64ct::Base64::encode_string(&wire))
}

// ─── bundle files (`sshspan://import`) ─────────────────────────────────────

/// One proposed host key of a bundle row, with its fingerprint for the
/// dialog.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProposedKey {
    pub key_type: String,
    /// Canonical base64 wire format.
    pub key: String,
    pub fingerprint: String,
}

/// One host of a bundle, as SSHSpan would import it - or, with `problem`
/// set, why it cannot be.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BundleHost {
    pub index: usize,
    pub kind: String,
    pub vmid: Option<u32>,
    pub node: Option<String>,
    pub name: String,
    pub pool: Option<String>,
    pub host: String,
    pub port: u16,
    pub user: String,
    pub host_keys: Vec<ProposedKey>,
    /// Unix seconds.
    pub host_key_rotated: Option<i64>,
    /// The suggested category path, top first (no segment holds "/").
    pub category: Vec<String>,
    pub problem: Option<String>,
}

/// The cluster a bundle came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BundleCluster {
    pub id: String,
    pub name: Option<String>,
}

/// A validated bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Bundle {
    pub cluster: BundleCluster,
    pub pmxspan_version: Option<String>,
    pub hosts: Vec<BundleHost>,
}

impl BundleHost {
    /// The origin a server saved from this row stores.
    pub fn origin(&self, cluster: &BundleCluster) -> Origin {
        Origin {
            kind: ORIGIN_PMXSPAN.into(),
            cluster_id: cluster.id.clone(),
            cluster_name: cluster.name.clone(),
            vmid: self.vmid,
            node: self.node.clone(),
            guest_kind: self.kind.clone(),
        }
    }
}

/// Read the bundle an `import` link names, with every check of spec 2.2 in
/// order: absolute path; a regular file that is not a symlink (no-follow
/// open on Unix, and the opened file compared with the path's own entry);
/// at most [`MAX_BUNDLE_BYTES`]; SHA-256 equal to the link's; `format` and
/// `version`; `created_at` within the last hour. The error names the check
/// that failed. `now` is the clock (a test passes its own).
pub fn read_bundle(
    path: &Path,
    sha256: &[u8; 32],
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Bundle, String> {
    let bytes = read_bundle_bytes(path)?;
    let digest = sha2::Sha256::digest(&bytes);
    if digest.as_slice() != sha256 {
        return Err("The bundle's SHA-256 does not match the link, so it was refused.".into());
    }
    parse_bundle(&bytes, now)
}

/// The bytes of the bundle file at `path`: absolute, a regular file, not a
/// symlink, at most [`MAX_BUNDLE_BYTES`].
pub fn read_bundle_bytes(path: &Path) -> Result<Vec<u8>, String> {
    use std::io::Read;
    if !path.is_absolute() {
        return Err("The bundle path is not absolute.".into());
    }
    let entry = std::fs::symlink_metadata(path)
        .map_err(|e| format!("The bundle file could not be read: {e}"))?;
    if entry.file_type().is_symlink() {
        return Err("The bundle file is a symbolic link, so it was refused.".into());
    }
    if !entry.is_file() {
        return Err("The bundle path is not a regular file.".into());
    }
    if entry.len() > MAX_BUNDLE_BYTES {
        return Err("The bundle file is larger than 4 MiB, so it was refused.".into());
    }
    let file = open_no_follow(path).map_err(|e| {
        if is_symlink_refusal(&e) {
            "The bundle file is a symbolic link, so it was refused.".to_string()
        } else {
            format!("The bundle file could not be read: {e}")
        }
    })?;
    let opened = file
        .metadata()
        .map_err(|e| format!("The bundle file could not be read: {e}"))?;
    if !opened.is_file() || !same_file(&entry, &opened) {
        return Err("The bundle file changed while it was opened, so it was refused.".into());
    }
    let mut bytes = Vec::new();
    file.take(MAX_BUNDLE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("The bundle file could not be read: {e}"))?;
    if bytes.len() as u64 > MAX_BUNDLE_BYTES {
        return Err("The bundle file is larger than 4 MiB, so it was refused.".into());
    }
    Ok(bytes)
}

#[cfg(unix)]
fn open_no_follow(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
}

#[cfg(not(unix))]
fn open_no_follow(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::File::open(path)
}

#[cfg(unix)]
fn is_symlink_refusal(e: &std::io::Error) -> bool {
    e.raw_os_error() == Some(libc::ELOOP)
}

#[cfg(not(unix))]
fn is_symlink_refusal(_e: &std::io::Error) -> bool {
    false
}

#[cfg(unix)]
fn same_file(a: &std::fs::Metadata, b: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    a.dev() == b.dev() && a.ino() == b.ino()
}

#[cfg(not(unix))]
fn same_file(a: &std::fs::Metadata, b: &std::fs::Metadata) -> bool {
    a.len() == b.len()
}

/// Parse the bundle JSON v1, tolerant of members it does not know. A host
/// that cannot be imported (no host, a bad user name) becomes a row with a
/// `problem`, not a refusal of the whole bundle.
pub fn parse_bundle(bytes: &[u8], now: chrono::DateTime<chrono::Utc>) -> Result<Bundle, String> {
    let doc: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|e| format!("The bundle file is not valid JSON: {e}"))?;
    let obj = doc
        .as_object()
        .ok_or_else(|| "The bundle file is not a JSON object.".to_string())?;
    if obj.get("format").and_then(|v| v.as_str()) != Some(BUNDLE_FORMAT) {
        return Err(format!(
            "The bundle's format is not \"{BUNDLE_FORMAT}\", so it was refused."
        ));
    }
    match obj.get("version").and_then(|v| v.as_u64()) {
        Some(1) => {}
        Some(n) if n > 1 => {
            return Err(format!(
                "This bundle was made by a newer PMXSpan (version {n}); update SSHSpan."
            ))
        }
        _ => return Err("The bundle's version is not 1, so it was refused.".into()),
    }
    let created = obj
        .get("created_at")
        .and_then(|v| v.as_str())
        .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
        .ok_or_else(|| "The bundle has no readable created_at time.".to_string())?
        .with_timezone(&chrono::Utc);
    let age = now.signed_duration_since(created).num_seconds();
    if age > BUNDLE_MAX_AGE_SECS {
        return Err("The bundle is more than 60 minutes old, so it was refused.".into());
    }
    if age < -BUNDLE_FUTURE_SKEW_SECS {
        return Err("The bundle's created_at lies in the future, so it was refused.".into());
    }
    let cluster = obj
        .get("cluster")
        .and_then(|v| v.as_object())
        .ok_or_else(|| "The bundle names no cluster.".to_string())?;
    let cluster_id = cluster
        .get("id")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "The bundle's cluster has no id.".to_string())?;
    check_name("cluster id", cluster_id)?;
    let cluster_name = cluster
        .get("name")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty() && check_name("cluster name", s).is_ok())
        .map(str::to_string);
    let pmxspan_version = obj
        .get("pmxspan_version")
        .and_then(|v| v.as_str())
        .filter(|s| check_name("version", s).is_ok())
        .map(str::to_string);
    let hosts = obj
        .get("hosts")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "The bundle has no host list.".to_string())?;
    if hosts.len() > MAX_BUNDLE_HOSTS {
        return Err(format!(
            "The bundle lists more than {MAX_BUNDLE_HOSTS} hosts, so it was refused."
        ));
    }
    Ok(Bundle {
        cluster: BundleCluster {
            id: cluster_id.to_string(),
            name: cluster_name,
        },
        pmxspan_version,
        hosts: hosts
            .iter()
            .enumerate()
            .map(|(i, h)| bundle_host(i, h))
            .collect(),
    })
}

/// One `hosts[]` entry as a row.
fn bundle_host(index: usize, value: &serde_json::Value) -> BundleHost {
    let get = |k: &str| value.get(k);
    let text = |k: &str| get(k).and_then(|v| v.as_str()).map(str::to_string);
    let mut problems: Vec<String> = Vec::new();
    let kind = text("kind").unwrap_or_default();
    if !matches!(kind.as_str(), "vm" | "ct" | "node") {
        problems.push("its kind is not vm, ct or node".into());
    }
    let vmid = match get("vmid") {
        Some(serde_json::Value::Number(n)) => match n.as_u64() {
            Some(v) if valid_vmid(v) => Some(v as u32),
            _ => {
                problems.push("its vmid is not from 100 to 999999999".into());
                None
            }
        },
        _ => None,
    };
    if matches!(kind.as_str(), "vm" | "ct") && vmid.is_none() && problems.is_empty() {
        problems.push("it has no vmid".into());
    }
    let clean = |k: &str| -> Option<String> {
        text(k).filter(|s| !s.is_empty() && check_name(k, s).is_ok())
    };
    let node = clean("node");
    if kind == "node" && node.is_none() {
        problems.push("it has no node name".into());
    }
    let pool = clean("pool");
    let host = text("host").unwrap_or_default();
    if host.is_empty() {
        problems.push("it has no host address".into());
    } else if !valid_host(&host) {
        problems.push("its host is not a DNS name or an IP address".into());
    }
    let port = match get("port") {
        None | Some(serde_json::Value::Null) => 22,
        Some(serde_json::Value::Number(n)) => match n.as_u64() {
            Some(p) if (1..=65535).contains(&p) => p as u16,
            _ => {
                problems.push("its port is not from 1 to 65535".into());
                22
            }
        },
        Some(_) => {
            problems.push("its port is not a number".into());
            22
        }
    };
    let user = match text("user").filter(|u| !u.is_empty()) {
        Some(u) => u,
        None if kind == "node" => "root".to_string(),
        None => String::new(),
    };
    if user.is_empty() {
        problems.push("it has no user name".into());
    } else if !valid_user(&user) {
        problems.push("its user name is not allowed (1-64 of A-Z a-z 0-9 . _ @ -)".into());
    }
    let name = match text("name") {
        Some(n) if !n.is_empty() && check_name("name", &n).is_ok() => n,
        Some(n) if !n.is_empty() => {
            problems.push("its name is too long or holds control characters".into());
            host.clone()
        }
        _ => host.clone(),
    };
    let mut host_keys = Vec::new();
    if let Some(keys) = get("host_keys").and_then(|v| v.as_array()) {
        for k in keys.iter().take(MAX_HOST_KEYS + 1) {
            let Some(b64) = k.get("key").and_then(|v| v.as_str()) else {
                problems.push("a host key has no key".into());
                continue;
            };
            match canonical_host_key(b64) {
                Ok(key) => {
                    let key_type = key_type_of(&key);
                    if let Some(claimed) = k.get("type").and_then(|v| v.as_str()) {
                        if claimed != key_type {
                            problems.push(format!(
                                "a host key says it is {} but is {}",
                                shown(claimed),
                                key_type
                            ));
                            continue;
                        }
                    }
                    let fingerprint = crate::ssh_client::hostkey_fingerprint_display(&key);
                    if !host_keys.iter().any(|p: &ProposedKey| p.key == key) {
                        host_keys.push(ProposedKey {
                            key_type,
                            key,
                            fingerprint,
                        });
                    }
                }
                Err(_) => problems.push("a host key is not an SSH public key".into()),
            }
        }
        if keys.len() > MAX_HOST_KEYS {
            problems.push(format!("it proposes more than {MAX_HOST_KEYS} host keys"));
        }
    }
    let host_key_rotated = get("host_key_rotated_at")
        .and_then(|v| v.as_str())
        .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
        .map(|t| t.timestamp());
    let category: Vec<String> = get("category")
        .and_then(|v| v.as_array())
        .map(|parts| {
            parts
                .iter()
                .filter_map(|p| p.as_str())
                .map(|p| p.replace('/', "-").trim().to_string())
                .filter(|p| !p.is_empty() && check_name("category", p).is_ok())
                .take(8)
                .collect()
        })
        .unwrap_or_default();
    BundleHost {
        index,
        kind,
        vmid,
        node,
        name,
        pool,
        host,
        port,
        user,
        host_keys,
        host_key_rotated,
        category,
        problem: (!problems.is_empty()).then(|| {
            let mut text = problems.join("; ");
            if let Some(first) = text.get_mut(0..1) {
                first.make_ascii_uppercase();
            }
            text.push('.');
            text
        }),
    }
}

/// The algorithm name inside a (canonical, already parsed) wire-format key.
pub fn key_type_of(b64: &str) -> String {
    base64ct::Base64::decode_vec(b64)
        .ok()
        .and_then(|bytes| ssh_key::PublicKey::from_bytes(&bytes).ok())
        .map(|k| k.algorithm().as_str().to_string())
        .unwrap_or_default()
}

// ─── pmxspan:// URLs (SSHSpan -> PMXSpan) ──────────────────────────────────

/// `pmxspan://guest?v=1&cluster=<id>&vmid=<n>` (spec 3.1).
pub fn guest_url(cluster_id: &str, vmid: u32) -> String {
    format!(
        "pmxspan://guest?v=1&cluster={}&vmid={vmid}",
        percent_encode(cluster_id)
    )
}

/// `pmxspan://node?v=1&cluster=<id>&node=<name>` (spec 3.1).
pub fn node_url(cluster_id: &str, node: &str) -> String {
    format!(
        "pmxspan://node?v=1&cluster={}&node={}",
        percent_encode(cluster_id),
        percent_encode(node)
    )
}

/// The `pmxspan://` URL that opens `origin` in PMXSpan: the node page for a
/// node, the guest page otherwise. `None` when the origin cannot name one.
pub fn manage_url(origin: &Origin) -> Option<String> {
    if origin.kind != ORIGIN_PMXSPAN {
        return None;
    }
    match (
        origin.guest_kind.as_str(),
        origin.vmid,
        origin.node.as_deref(),
    ) {
        ("node", _, Some(node)) => Some(node_url(&origin.cluster_id, node)),
        ("vm" | "ct", Some(vmid), _) => Some(guest_url(&origin.cluster_id, vmid)),
        _ => None,
    }
}

/// `pmxspan://add-key?v=1&key=<line>&name=<name>&source=sshspan` (spec 3.2).
/// `line` is a public `authorized_keys` line - never anything else.
pub fn add_key_url(line: &str, name: &str) -> String {
    format!(
        "pmxspan://add-key?v=1&key={}&name={}&source=sshspan",
        percent_encode(line),
        percent_encode(name)
    )
}
