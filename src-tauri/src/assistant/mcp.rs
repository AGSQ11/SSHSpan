//! MCP (Model Context Protocol) client - Streamable HTTP transport
//! (2025-11-25), Phase 1: transport + tools + static header auth.
//!
//! All MCP HTTP lives here, in Rust: the renderer never fetches MCP URLs.
//! OAuth (Phase 2) is out of scope; the seams are `resolve_auth_header`
//! (the single place a token source is consulted) and `guarded_client()`
//! (reserved for Phase 2 discovered URLs - the configured origin is
//! deliberately unguarded because self-hosted LAN servers are a
//! first-class use case).
//!
//! Security posture:
//! - Sealed secrets (`crate::crypto::vault::seal`) never cross IPC and are
//!   zeroized after use; env-var auth stores only the variable NAME and is
//!   resolved from the process environment at request time.
//! - Credential ORIGIN BINDING: a stored sealed secret - and an env-var
//!   binding the save does not name again - is dropped whenever the URL,
//!   auth type, or custom header name is edited, so an old credential can
//!   never be replayed at a new origin or under different semantics
//!   (`mcp_save_server` / `plan_auth`). The auth source is mutually
//!   exclusive: a record holds a sealed secret or an env-var name, never
//!   both. Binding a secret or an env var to a place it was not bound to
//!   before needs the user's "Allow" in a NATIVE dialog that names the host
//!   (and the variable); until then the record stays unconfirmed, as a
//!   restored one (`binding_needs_confirmation` / `settle_binding`).
//! - Vault generation: captured before the first await of every flow and
//!   rechecked immediately before EVERY credential-bearing request (via
//!   `ServerContext::checked`), so a lock mid-flow prevents the next
//!   tools/list or tools/call from sending the unsealed header.
//! - 3xx is a hard error (auth headers must never leave the configured
//!   origin; reqwest's `Policy::none()` does NOT error on redirects).
//! - Tools default to disabled; a tool only runs when enabled AND its
//!   definition still hashes to the pinned value the user approved. A
//!   changed definition disables the tool, clears its Auto-approve and is
//!   reported as `definition_changed` until the user re-approves it.
//! - Streamable HTTP only: a legacy HTTP+SSE server gets an explicit
//!   "does not speak MCP Streamable HTTP" error, not a bare status code.
//! - The per-tab access-level gate mirrors `assistant_exec`: enforced in
//!   Rust, independent of which tools the renderer offered the model.
//! - Vault lock tears down every MCP session (HTTP DELETE with
//!   McpSession-Id and the static auth header, 405 ignored per spec, other
//!   refusals audited) and drops session state.
//! - The aggregate enabled-MCP-tool count is capped so the renderer's
//!   built-ins-first 64-total merge can never be broken from the backend.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tauri::{AppHandle, Manager};
use zeroize::Zeroizing;

use crate::commands::{
    audit_or_log, audit_or_warn, capture_vault_generation, require_generation_current,
    vault_password, CmdError, ConfirmCredential, CredentialAnswer, CredentialPrompt, VaultAtSave,
    VaultPasswordStore, VaultRotationLock,
};

pub type CmdResult<T> = Result<T, CmdError>;

/// The transport this client speaks: MCP 2025-11-25 Streamable HTTP.
const PROTOCOL_VERSION_OFFERED: &str = "2025-11-25";
/// Protocol versions accepted back from the server's initialize result.
/// 2024-11-05 (legacy HTTP+SSE) is deliberately absent: this client does
/// not speak it, and a server that only offers it is unsupported.
const SUPPORTED_PROTOCOL_VERSIONS: [&str; 3] = ["2025-11-25", "2025-06-18", "2025-03-26"];

const CALL_TIMEOUT: Duration = Duration::from_secs(60);
/// Hard cap on any MCP HTTP response body (JSON or SSE stream).
const MAX_BODY_BYTES: usize = 2 * 1024 * 1024;
/// Hard cap on the merged (built-in + MCP) tool list the renderer offers the
/// model (must equal `AI_MAX_TOOLS_TOTAL` in src/renderer/assistant.js).
pub const MAX_EXPOSED_TOOLS: usize = 64;
/// Built-in assistant tools the renderer ALWAYS offers first (must equal the
/// number of entries in `AI_TOOL_SPECS` in src/renderer/assistant.js:
/// get_terminal_output, get_session_info, propose_command, type_command,
/// run_command).
pub const BUILTIN_TOOL_COUNT: usize = 5;
/// Slots MCP tools may ever fill: built-ins always win and MCP fills the
/// remainder, so the backend never lets MORE than this many MCP tools be
/// enabled across all servers - enabling beyond it would either break the
/// renderer's 64-total merge or silently displace nothing but lie about it.
pub const MAX_MCP_TOOLS: usize = MAX_EXPOSED_TOOLS - BUILTIN_TOOL_COUNT;
/// Cap on a tool's stored/returned description (chars).
const MAX_DESCRIPTION_CHARS: usize = 1024;
/// Cap on a stored input schema, in canonical-JSON bytes. Schemas are
/// untrusted server text that rides into the model's tool list; an
/// oversized one is not stored (views substitute an empty object schema).
pub const MAX_INPUT_SCHEMA_BYTES: usize = 8 * 1024;

// ─── Validation (pure, unit-tested) ─────────────────────────────────────────

/// Where the URL points: https anywhere, or plain http ONLY for loopback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UrlClass {
    Https,
    /// Plain http to a loopback host - allowed, but the UI must warn.
    LoopbackInsecure,
}

/// Classify a user-entered MCP server URL. https is always allowed; plain
/// http is allowed only when the host is a loopback literal or "localhost"
/// (self-hosted local servers are a first-class use case). Everything else
/// is rejected. No credentials in the URL, ever. Returns the normalized
/// base (scheme + host[:port] + path, no trailing slash) - so a `?query` or
/// `#fragment` is refused rather than silently dropped (A4-23): a token or a
/// route in it would vanish and the server would then fail for no visible
/// reason. The settings form applies the same rule.
pub fn classify_url(raw: &str) -> Result<(String, UrlClass), String> {
    let trimmed = raw.trim();
    let url = url::Url::parse(trimmed).map_err(|_| "Server URL is not a valid URL.".to_string())?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err("Server URL must not contain credentials.".into());
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err("MCP server URLs cannot contain ?query or #fragment parts.".into());
    }
    let (host, is_loopback) = url_host(&url)?;
    let class = match url.scheme() {
        "https" => UrlClass::Https,
        "http" if is_loopback => UrlClass::LoopbackInsecure,
        "http" => {
            return Err(
                "Server URL must use https:// (plain http is only allowed for localhost, 127.x addresses or ::1)."
                    .into(),
            )
        }
        other => return Err(format!("Server URL scheme '{other}' is not supported.")),
    };
    let host_port = match url.port() {
        Some(p) => format!("{host}:{p}"),
        None => host,
    };
    let path = url.path().trim_end_matches('/');
    let base = if path.is_empty() || path == "/" {
        format!("{}://{}", url.scheme(), host_port)
    } else {
        format!("{}://{}{}", url.scheme(), host_port, path)
    };
    Ok((base, class))
}

/// The host of a parsed URL as it is written back into the stored base, and
/// whether plain http to it stays on this machine.
///
/// Loopback is decided on the PARSED host, never on its spelling: only an
/// IPv4 address in 127.0.0.0/8, the IPv6 address ::1 and the name
/// `localhost` qualify. The old string test (`starts_with("127.")`) passed
/// host names such as `127.evil.example`, so the auth header went in
/// cleartext to a machine anyone can name that way.
///
/// The text is the url crate's own serialization: IPv4 canonical (`127.1` is
/// `127.0.0.1`), names lower-cased, and IPv6 literals KEPT in brackets - the
/// base is stored and reused as a URL, and `[::1]:8080` parses as an address
/// and a port where `::1:8080` does not.
fn url_host(url: &url::Url) -> Result<(String, bool), String> {
    use std::net::IpAddr;
    let is_loopback = match url.host() {
        Some(url::Host::Domain(name)) if !name.is_empty() => name.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => IpAddr::V4(ip).is_loopback(),
        Some(url::Host::Ipv6(ip)) => IpAddr::V6(ip).is_loopback(),
        _ => return Err("Server URL has no hostname.".into()),
    };
    let host = url.host_str().unwrap_or_default().to_lowercase();
    Ok((host, is_loopback))
}

/// Header names never valid as a static auth header: they override
/// transport/framework-managed headers (Authorization is reserved for the
/// bearer mode, which formats it itself).
const FORBIDDEN_HEADER_NAMES: [&str; 5] = [
    "host",
    "content-length",
    "mcp-session-id",
    "mcp-protocol-version",
    "authorization",
];

/// True for a valid RFC 7230 token: the only form accepted as a custom
/// header name (and as a server name).
fn is_token(s: &str) -> bool {
    !s.is_empty()
        && s.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(
                    c,
                    '!' | '#'
                        | '$'
                        | '%'
                        | '&'
                        | '\''
                        | '*'
                        | '+'
                        | '-'
                        | '.'
                        | '^'
                        | '_'
                        | '`'
                        | '|'
                        | '~'
                )
        })
}

/// Validate a custom static auth header name per RFC 7230 token syntax and
/// reject headers the transport owns.
pub fn validate_header_name(name: &str) -> Result<(), String> {
    let n = name.trim();
    if n.is_empty() {
        return Err("Auth header name must not be empty.".into());
    }
    if !is_token(n) {
        return Err(
            "Auth header name contains characters that are not valid in an HTTP header.".into(),
        );
    }
    if FORBIDDEN_HEADER_NAMES.contains(&n.to_lowercase().as_str()) {
        return Err(format!(
            "'{n}' is reserved by the MCP transport and cannot be used as the auth header."
        ));
    }
    Ok(())
}

// ─── Tool definition pinning (pure, unit-tested) ────────────────────────────

/// SHA-256 over the CANONICAL JSON (keys sorted recursively, no whitespace)
/// of `{name, title, description, inputSchema, annotations}`.
///
/// Canonical JSON rather than plain concatenation: concatenation is
/// ambiguous at field boundaries, and raw server serialization is
/// key-order-dependent - a server that merely re-orders keys must NOT look
/// like a definition change (false-positive rug-pull), while a real change
/// to any pinned field must. The FULL description feeds the hash; the
/// truncated copy is for display only.
pub fn tool_definition_hash(def: &Value) -> String {
    let mut m = serde_json::Map::new();
    m.insert(
        "name".into(),
        def.get("name").cloned().unwrap_or(Value::Null),
    );
    m.insert(
        "title".into(),
        def.get("title").cloned().unwrap_or(Value::Null),
    );
    m.insert(
        "description".into(),
        def.get("description").cloned().unwrap_or(Value::Null),
    );
    m.insert(
        "inputSchema".into(),
        def.get("inputSchema").cloned().unwrap_or(Value::Null),
    );
    m.insert(
        "annotations".into(),
        def.get("annotations").cloned().unwrap_or(Value::Null),
    );
    let digest = Sha256::digest(canonical_json(&Value::Object(m)));
    hex::encode(digest)
}

/// Serialize to canonical JSON bytes: keys sorted recursively, no
/// whitespace.
fn canonical_json(v: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    write_canonical(v, &mut out);
    out
}

fn write_canonical(v: &Value, out: &mut Vec<u8>) {
    match v {
        Value::Object(map) => {
            // Sort defensively so the hash never depends on serde_json's
            // map ordering (the preserve_order feature flag changes it).
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push(b'{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                serde_json::to_writer(&mut *out, k).unwrap();
                out.push(b':');
                write_canonical(&map[*k], out);
            }
            out.push(b'}');
        }
        Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_canonical(item, out);
            }
            out.push(b']');
        }
        other => serde_json::to_writer(&mut *out, other).unwrap(),
    }
}

/// Truncate a description to the display cap, flagging the cut with a
/// marker so the model knows there is more.
fn truncate_description(desc: &str) -> String {
    if desc.chars().count() <= MAX_DESCRIPTION_CHARS {
        return desc.to_string();
    }
    let cut: String = desc.chars().take(MAX_DESCRIPTION_CHARS).collect();
    format!("{cut} [truncated]")
}

// ─── Tool naming (pure, unit-tested) ────────────────────────────────────────

/// Cap on the renderer-exposed tool name (`mcp__<server>__<tool>`).
const MAX_TOOL_NAME_LEN: usize = 64;

/// Sanitize a server/tool name into the model-facing namespace. MUST stay
/// byte-for-byte identical to `mcpSanitizeName` in src/renderer/mcp.js: only
/// [A-Za-z0-9_] survives (anything else becomes `_`) and runs of underscores
/// collapse to one, so the exposed name can never itself contain "__" and the
/// `mcp__<server>__<tool>` split stays structurally unambiguous. The backend
/// is the authority on collisions precisely because both sides derive the
/// name with this one function.
pub fn sanitize_tool_name_part(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut last_underscore = false;
    for c in s.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c);
            last_underscore = false;
        } else if !last_underscore {
            out.push('_');
            last_underscore = true;
        }
    }
    out
}

/// The renderer-exposed name for a server's tool: `mcp__<server>__<tool>`,
/// both sides sanitized to [A-Za-z0-9_] with collapsed underscore runs. When
/// the full form exceeds 64 chars, the tail is cut and a short deterministic
/// hash suffix is appended so two long names cannot collapse onto each other.
pub fn exposed_tool_name(server: &str, tool: &str) -> String {
    let full = format!(
        "mcp__{}__{}",
        sanitize_tool_name_part(server),
        sanitize_tool_name_part(tool)
    );
    if full.chars().count() <= MAX_TOOL_NAME_LEN {
        return full;
    }
    let cut: String = full.chars().take(MAX_TOOL_NAME_LEN - 9).collect();
    // 8 hex chars of SHA-256 over the UNTRUNCATED name: deterministic and
    // distinct for distinct inputs (a plain counter would let two tools
    // collide after truncation).
    let digest = Sha256::digest(full.as_bytes());
    format!(
        "{}_{:08x}",
        cut,
        u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]])
    )
}

/// The canonical set of model-exposed MCP tool names for a whole registry of
/// servers, rejecting every kind of collision BEFORE anything is exposed:
/// - two tools of ONE server mapping to the same exposed name (e.g. "a b"
///   and "a_b" sanitize identically);
/// - two SERVERS whose names sanitize identically - including two servers
///   with the very same name (the renderer could no longer resolve an
///   exposed name back to one server);
/// - a name colliding with a built-in assistant tool (never allowed, even
///   though the renderer also refuses these).
///
/// Servers are told apart by their id, never by their name (A4-12): two
/// entries that share a name are two servers, not one. `exposed ->
/// (server_id, tool)` is then a well-defined map: one approval can never
/// silently cover another tool.
pub fn build_name_map(
    servers: &[(String, String, Vec<String>)], // (server id, server name, tool names)
) -> Result<HashMap<String, (String, String)>, String> {
    let mut map = HashMap::new();
    // Sanitized prefix -> (id, name) of the server that claimed it.
    let mut prefix_owner: HashMap<String, (String, String)> = HashMap::new();
    for (id, server, tools) in servers {
        // A server with no enabled tools exposes nothing: it cannot create
        // ambiguity, so its name never blocks another server's enables.
        if tools.is_empty() {
            continue;
        }
        let server_san = sanitize_tool_name_part(server);
        match prefix_owner.get(&server_san) {
            Some((prev_id, prev)) if prev_id != id => {
                return Err(if prev == server {
                    format!(
                        "Two MCP servers are both named '{server}'; rename one of them before enabling tools."
                    )
                } else {
                    format!(
                        "MCP server names '{prev}' and '{server}' produce the same model-facing prefix '{server_san}'; rename one of them before enabling tools."
                    )
                });
            }
            Some(_) => {}
            None => {
                prefix_owner.insert(server_san.clone(), (id.clone(), server.clone()));
            }
        }
        let mut tool_seen: HashMap<String, String> = HashMap::new();
        for real in tools {
            let exposed = exposed_tool_name(server, real);
            if BUILTIN_TOOL_NAMES.contains(&exposed.as_str()) {
                return Err(format!(
                    "MCP tool name '{exposed}' collides with a built-in assistant tool; refusing to expose it."
                ));
            }
            match tool_seen.get(&exposed) {
                Some(prev) if prev != real => {
                    return Err(format!(
                        "Tools '{prev}' and '{real}' on MCP server '{server}' produce the same model-facing name '{exposed}'; refusing to expose ambiguous tools."
                    ));
                }
                _ => {
                    tool_seen.insert(exposed.clone(), real.clone());
                }
            }
            match map.get(&exposed) {
                Some((prev_id, prev_tool)) if prev_id != id || prev_tool != real => {
                    return Err(format!(
                        "MCP tools from different servers produce the same model-facing name '{exposed}'; refusing to expose ambiguous tools."
                    ));
                }
                _ => {
                    map.insert(exposed, (id.clone(), real.clone()));
                }
            }
        }
    }
    Ok(map)
}

/// The built-in assistant tool names (src/renderer/assistant.js
/// `AI_TOOL_SPECS`). An MCP tool whose exposed name equals one of these is
/// rejected rather than exposed: the model must never see two definitions
/// behind one name.
pub const BUILTIN_TOOL_NAMES: [&str; 5] = [
    "get_terminal_output",
    "get_session_info",
    "propose_command",
    "type_command",
    "run_command",
];

// ─── Input schema clamping (pure, unit-tested) ─────────────────────────────

/// Extract, validate and bound a tool's `inputSchema` for STORAGE and for the
/// model-facing tool list:
/// - must be a JSON object (a JSON Schema root is an object);
/// - serialized canonically (sorted keys, no whitespace) so the stored bytes
///   are deterministic and bounded by content, not formatting;
/// - rejected (None) when absent, non-object, or above the byte cap. The pin
///   hash keeps hashing the FULL untruncated definition either way.
pub fn clamp_input_schema(def: &Value) -> Option<String> {
    let schema = def.get("inputSchema")?;
    if !schema.is_object() {
        return None;
    }
    let canonical = canonical_json(schema);
    if canonical.len() > MAX_INPUT_SCHEMA_BYTES {
        return None;
    }
    String::from_utf8(canonical).ok()
}

// ─── Auth header resolution ─────────────────────────────────────────────────

/// The static auth header a request should carry, resolved at request time.
/// This is the Phase-2 seam: an OAuth token source slots in here.
fn resolve_auth_header(
    auth_type: &str,
    auth_header_name: Option<&str>,
    sealed_secret: Option<&str>,
    auth_env_var: Option<&str>,
    pw: &Zeroizing<String>,
) -> CmdResult<Option<(String, Zeroizing<String>)>> {
    match auth_type {
        "none" => Ok(None),
        "bearer" => {
            let value = resolve_secret_value(sealed_secret, auth_env_var, pw, "Authorization")?;
            Ok(Some(("Authorization".to_string(), value)))
        }
        "custom_header" => {
            let name = auth_header_name
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| CmdError("Custom header auth requires a header name.".into()))?;
            validate_header_name(name).map_err(CmdError)?;
            let value = resolve_secret_value(sealed_secret, auth_env_var, pw, name)?;
            Ok(Some((name.to_string(), value)))
        }
        other => Err(CmdError(format!("Unknown auth type '{other}'."))),
    }
}

/// Resolve the header VALUE: a stored (sealed) secret, or an environment
/// variable read at request time (only the NAME is stored). The returned
/// value is Zeroizing. Unsealing a secret is an Argon2id derivation: callers
/// run this on the blocking pool.
fn resolve_secret_value(
    sealed_secret: Option<&str>,
    auth_env_var: Option<&str>,
    pw: &Zeroizing<String>,
    header_name: &str,
) -> CmdResult<Zeroizing<String>> {
    if let Some(sealed) = sealed_secret {
        let bytes = crate::commands::unseal_on_pool(pw, sealed)
            .map_err(|e| CmdError(format!("Cannot decrypt the stored MCP auth secret: {e}")))?;
        let value = Zeroizing::new(
            String::from_utf8(bytes)
                .map_err(|_| CmdError("Stored MCP auth secret is not valid UTF-8.".into()))?,
        );
        if value.trim().is_empty() {
            return Err(CmdError("Stored MCP auth secret is empty.".into()));
        }
        return Ok(value);
    }
    if let Some(var) = auth_env_var.map(str::trim).filter(|s| !s.is_empty()) {
        let value = Zeroizing::new(std::env::var(var).map_err(|_| {
            CmdError(format!(
                "Environment variable '{var}' (MCP auth for header '{header_name}') is not set."
            ))
        })?);
        if value.trim().is_empty() {
            return Err(CmdError(format!(
                "Environment variable '{var}' (MCP auth) is set but empty."
            )));
        }
        return Ok(value);
    }
    Err(CmdError(
        "No auth source configured: provide a stored secret or an environment variable name."
            .into(),
    ))
}

// ─── HTTP clients ────────────────────────────────────────────────────────────

/// The UNGUARDED client used for the user-CONFIGURED origin. Deliberately
/// no `guarded_resolver()`: the user-entered URL may be private/LAN (a
/// self-hosted MCP server is a first-class use case) and installing the
/// SSRF filter here would make every LAN server unconnectable. Redirect
/// policy NONE - which does NOT error on a 3xx, reqwest returns it as a
/// normal response - so the explicit 3xx check in `post_jsonrpc` is what
/// actually keeps auth headers from ever leaving the configured origin.
fn origin_client() -> CmdResult<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(CALL_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| CmdError(format!("Cannot build MCP HTTP client: {e}")))
}

/// The GUARDED client, reserved for Phase 2 discovered URLs (e.g. OAuth
/// endpoints learned via WWW-Authenticate). Same transport rules as the
/// origin client plus the SSRF connect-time DNS guard. NOT used for the
/// configured origin - see `origin_client`. Deliberately unused in Phase 1;
/// kept as the Phase-2 seam so discovered-URL handling cannot silently fall
/// back to an unguarded dial.
#[allow(dead_code)]
pub fn guarded_client() -> CmdResult<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(CALL_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .dns_resolver(crate::bitwarden::ssrf::guarded_resolver())
        .build()
        .map_err(|e| CmdError(format!("Cannot build guarded MCP HTTP client: {e}")))
}

// ─── Session + status state (app-managed) ──────────────────────────────────

/// One live MCP session: the negotiated protocol version (echoed back as
/// MCP-Protocol-Version on every later request) and the server-issued
/// session id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpSession {
    pub session_id: Option<String>,
    pub protocol_version: String,
}

/// The settings a session was set up with: the server record's URL and auth
/// configuration at that moment - what [`same_connection`] compares, the
/// secret as sealed. The server knows the session under these settings only,
/// so it is used only for a record that has them, and ended only at this URL
/// with this credential: an edit that lands while a session is being set up
/// must not hand that session - or the old credential - to the new endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ConnectionBinding {
    url: String,
    auth_type: String,
    auth_header_name: Option<String>,
    auth_secret: Option<String>,
    auth_env_var: Option<String>,
}

impl ConnectionBinding {
    fn of(record: &crate::db::McpServerRecord) -> Self {
        Self {
            url: record.url.clone(),
            auth_type: record.auth_type.clone(),
            auth_header_name: record.auth_header_name.clone(),
            auth_secret: record.auth_secret.clone(),
            auth_env_var: record.auth_env_var.clone(),
        }
    }

    /// The auth header these settings send, a stored secret unsealed with
    /// `pw` - an Argon2id derivation, so never on the main thread. `None`
    /// when they send none, the vault is locked (`pw` empty) or the header
    /// cannot be resolved: a teardown then goes out without it. The value is
    /// Zeroizing.
    fn auth_header(&self, pw: &Zeroizing<String>) -> Option<(String, Zeroizing<String>)> {
        if pw.is_empty() {
            return None;
        }
        resolve_auth_header(
            &self.auth_type,
            self.auth_header_name.as_deref(),
            self.auth_secret.as_deref(),
            self.auth_env_var.as_deref(),
            pw,
        )
        .ok()
        .flatten()
    }
}

/// A registered session, the settings it belongs to, and the server's name
/// (for messages about it).
#[derive(Debug, Clone)]
struct LiveSession {
    session: McpSession,
    /// The settings it was set up with. `None` only for a session registered
    /// through [`McpState::set_session`] (a test seam): it counts as
    /// belonging to the server's record as stored.
    binding: Option<ConnectionBinding>,
    server_name: String,
}

impl LiveSession {
    /// Whether a request for `record` may use this session: it was set up
    /// with `record`'s URL and auth settings (or registered without them).
    fn belongs_to(&self, record: &crate::db::McpServerRecord) -> bool {
        self.binding
            .as_ref()
            .is_none_or(|binding| *binding == ConnectionBinding::of(record))
    }

    /// Whether this session is known to be set up with `record`'s URL and
    /// auth settings.
    fn bound_to(&self, record: &crate::db::McpServerRecord) -> bool {
        self.binding
            .as_ref()
            .is_some_and(|binding| *binding == ConnectionBinding::of(record))
    }
}

/// Last-known connect status for one server (status, error, enabled-tool
/// count); absent from the map = "unknown".
type ServerStatus = (String, Option<String>, usize);

/// App-managed in-memory state for MCP: live sessions - each with the
/// settings it was set up with - and last-known connect statuses, keyed by
/// server id - cleared on vault lock ([`teardown_all`]) - and the session
/// teardowns (HTTP DELETEs) still running, so an exit can wait for them
/// ([`McpState::take_teardowns`]).
#[derive(Default)]
pub struct McpState {
    sessions: Mutex<HashMap<String, LiveSession>>,
    statuses: Mutex<HashMap<String, ServerStatus>>,
    teardowns: Mutex<Vec<tauri::async_runtime::JoinHandle<()>>>,
    /// Requests in flight per session id ([`McpState::use_session`]).
    in_use: Mutex<HashMap<String, usize>>,
    /// Ends of replaced sessions that wait for their last request.
    deferred_ends: Mutex<HashMap<String, DeferredEnd>>,
    /// The one copy of the vault password the teardowns share
    /// ([`McpState::shared_password`]).
    password_copy: Mutex<std::sync::Weak<Zeroizing<String>>>,
}

/// The end of a replaced session that is still in use: started when its last
/// request finishes ([`SessionUse`]).
struct DeferredEnd {
    job: TeardownJob,
    db: crate::db::Database,
    client: reqwest::Client,
}

/// One request's use of a registered session ([`McpState::use_session`]).
/// While any is alive, a registration that replaces the session leaves it
/// running and ends it when the last use ends: "Test connection" during a
/// tool call used to end the session the call was waiting on.
pub(crate) struct SessionUse<'a> {
    state: &'a McpState,
    session_id: Option<String>,
}

impl Drop for SessionUse<'_> {
    /// The last use of a replaced session starts its deferred end.
    fn drop(&mut self) {
        let Some(id) = self.session_id.take() else {
            return;
        };
        let deferred = {
            let mut in_use = self.state.in_use.lock().unwrap();
            match in_use.get_mut(&id) {
                Some(count) if *count > 1 => {
                    *count -= 1;
                    None
                }
                _ => {
                    in_use.remove(&id);
                    self.state.deferred_ends.lock().unwrap().remove(&id)
                }
            }
        };
        if let Some(end) = deferred {
            self.state
                .start_teardowns(end.db, end.client, vec![end.job]);
        }
    }
}

/// Most session teardowns pending at once. Each may hold an auth header or
/// share the password copy until it has run; past this many (a "Test
/// connection" loop, a server that never answers), further sessions are not
/// ended but left to expire on their servers.
const MAX_PENDING_TEARDOWNS: usize = 16;

impl McpState {
    pub fn new() -> Self {
        Self::default()
    }
    /// The session registered for `server_id`, whatever settings it belongs
    /// to - for looking at the state. A request takes its session from
    /// [`McpState::session_for`].
    pub fn get_session(&self, server_id: &str) -> Option<McpSession> {
        self.sessions
            .lock()
            .unwrap()
            .get(server_id)
            .map(|live| live.session.clone())
    }
    /// Register `session` for `server_id` WITHOUT the settings it was set up
    /// with: it then counts as belonging to the server's record as stored.
    /// The integration tests' seam - the app registers every session it sets
    /// up through [`McpState::bind_session`].
    #[doc(hidden)]
    pub fn set_session(&self, server_id: &str, session: McpSession) {
        self.insert(
            server_id,
            LiveSession {
                session,
                binding: None,
                server_name: server_id.to_string(),
            },
        );
    }
    /// Register `session`, set up with `record`'s current URL and auth
    /// settings, with no check (the tests' seam; the app registers through
    /// [`McpState::register`]).
    #[cfg(test)]
    pub(crate) fn bind_session(&self, record: &crate::db::McpServerRecord, session: McpSession) {
        self.insert(
            &record.id,
            LiveSession {
                session,
                binding: Some(ConnectionBinding::of(record)),
                server_name: record.name.clone(),
            },
        );
    }

    /// Register `session`, set up with `record`'s current URL and auth
    /// settings - only while `still_current` (the vault-generation check)
    /// passes. Returns the session it replaced, for the caller to end.
    ///
    /// The check runs while the sessions lock is held. A lock bumps the
    /// generation and THEN drains the sessions (`teardown_all`), which needs
    /// that lock: so either the check sees the bump and nothing is
    /// registered, or the drain waits for the registration and takes the
    /// session with it. Checked before the lock was taken, a lock landing in
    /// between left a session registered past it.
    fn register(
        &self,
        record: &crate::db::McpServerRecord,
        session: McpSession,
        still_current: &(dyn Fn() -> CmdResult<()> + Sync),
    ) -> CmdResult<Option<LiveSession>> {
        let mut sessions = self.sessions.lock().unwrap();
        still_current()?;
        Ok(sessions.insert(
            record.id.clone(),
            LiveSession {
                session,
                binding: Some(ConnectionBinding::of(record)),
                server_name: record.name.clone(),
            },
        ))
    }
    fn insert(&self, server_id: &str, live: LiveSession) {
        self.sessions
            .lock()
            .unwrap()
            .insert(server_id.to_string(), live);
    }
    /// The session a request for `record` may use: only one set up with
    /// `record`'s URL and auth settings.
    pub(crate) fn session_for(&self, record: &crate::db::McpServerRecord) -> Option<McpSession> {
        self.live_session(&record.id)
            .filter(|live| live.belongs_to(record))
            .map(|live| live.session)
    }
    fn live_session(&self, server_id: &str) -> Option<LiveSession> {
        self.sessions.lock().unwrap().get(server_id).cloned()
    }
    /// Remove and return the session of `server_id` - only if `take` says so
    /// of the one registered at that moment.
    fn take_session_if(
        &self,
        server_id: &str,
        take: impl FnOnce(&LiveSession) -> bool,
    ) -> Option<LiveSession> {
        let mut sessions = self.sessions.lock().unwrap();
        if sessions.get(server_id).is_some_and(take) {
            sessions.remove(server_id)
        } else {
            None
        }
    }
    fn take_session(&self, server_id: &str) -> Option<LiveSession> {
        self.sessions.lock().unwrap().remove(server_id)
    }
    fn take_sessions(&self) -> Vec<(String, LiveSession)> {
        self.sessions.lock().unwrap().drain().collect()
    }
    /// After a committed master-password change: every live session bound to
    /// a secret the change re-sealed (`before` -> `after`, by server id) is
    /// bound to its new seal. The secret is the same, only sealed with the
    /// new password - without this every session would look set up for other
    /// settings from then on, and be ended at its next use with no
    /// credential (the old seal no longer opens).
    pub(crate) fn follow_resealed_secrets(
        &self,
        before: &HashMap<String, String>,
        after: &HashMap<String, String>,
    ) {
        let mut sessions = self.sessions.lock().unwrap();
        for (server_id, live) in sessions.iter_mut() {
            let (Some(binding), Some(old), Some(new)) = (
                live.binding.as_mut(),
                before.get(server_id),
                after.get(server_id),
            ) else {
                continue;
            };
            if binding.auth_secret.as_deref() == Some(old.as_str()) {
                binding.auth_secret = Some(new.clone());
            }
        }
    }
    pub fn record_status(
        &self,
        server_id: &str,
        status: &str,
        error: Option<String>,
        tool_count: usize,
    ) {
        self.statuses.lock().unwrap().insert(
            server_id.to_string(),
            (status.to_string(), error, tool_count),
        );
    }
    pub fn status_of(&self, server_id: &str) -> String {
        self.statuses
            .lock()
            .unwrap()
            .get(server_id)
            .map(|(s, _, _)| s.clone())
            .unwrap_or_else(|| "unknown".to_string())
    }
    fn clear_statuses(&self) {
        self.statuses.lock().unwrap().clear();
    }
    /// Keep session teardown tasks until they finish, for the exit to wait
    /// for; finished ones are dropped here.
    pub(crate) fn track_teardowns(&self, started: Vec<tauri::async_runtime::JoinHandle<()>>) {
        let mut teardowns = self.teardowns.lock().unwrap();
        teardowns.retain(|handle| !handle.inner().is_finished());
        teardowns.extend(started);
    }
    /// The session teardowns started so far that may still be running (the
    /// lock path's, a stale session's after a URL or auth edit): the exit
    /// waits for them ([`wait_for_teardowns`]) instead of cutting them off.
    pub fn take_teardowns(&self) -> Vec<tauri::async_runtime::JoinHandle<()>> {
        std::mem::take(&mut *self.teardowns.lock().unwrap())
    }

    /// Count a use of `session` by one request until the returned guard
    /// drops ([`SessionUse`]).
    pub(crate) fn use_session(&self, session: Option<&McpSession>) -> SessionUse<'_> {
        let session_id = session.and_then(|s| s.session_id.clone());
        if let Some(id) = &session_id {
            *self.in_use.lock().unwrap().entry(id.clone()).or_insert(0) += 1;
        }
        SessionUse {
            state: self,
            session_id,
        }
    }

    /// End `job` - the teardown of a session a registration replaced - now,
    /// or once the requests still using that session are done
    /// ([`SessionUse`]). The check and the deferral happen under the same
    /// lock as a use's release, so a last use cannot slip in between.
    fn end_replaced(&self, job: TeardownJob, db: crate::db::Database, client: reqwest::Client) {
        let now = {
            let in_use = self.in_use.lock().unwrap();
            if in_use.get(&job.session_id).is_some_and(|n| *n > 0) {
                self.deferred_ends
                    .lock()
                    .unwrap()
                    .insert(job.session_id.clone(), DeferredEnd { job, db, client });
                None
            } else {
                Some((job, db, client))
            }
        };
        if let Some((job, db, client)) = now {
            self.start_teardowns(db, client, vec![job]);
        }
    }

    /// The ends that wait for their last request: started now (a lock does
    /// not wait for them).
    fn start_deferred_ends(&self) {
        let deferred: Vec<DeferredEnd> = self
            .deferred_ends
            .lock()
            .unwrap()
            .drain()
            .map(|(_, end)| end)
            .collect();
        for end in deferred {
            self.start_teardowns(end.db, end.client, vec![end.job]);
        }
    }

    /// Start `jobs` - as many as fit under [`MAX_PENDING_TEARDOWNS`] - and
    /// keep them for the exit to wait for.
    fn start_teardowns(
        &self,
        db: crate::db::Database,
        client: reqwest::Client,
        jobs: Vec<TeardownJob>,
    ) {
        let admitted = self.admit_teardowns(jobs);
        if !admitted.is_empty() {
            self.track_teardowns(spawn_teardown_jobs(db, client, admitted));
        }
    }

    /// A copy of the vault password for teardowns that unseal their
    /// credential - ONE copy, shared, for as long as any of them holds it
    /// (and wiped when the last one lets go). Each replaced session used to
    /// take a copy of its own, and a "Test connection" loop queued one per
    /// replaced session behind the unseal limit, still there after a lock.
    fn shared_password(&self, pw: &Zeroizing<String>) -> std::sync::Arc<Zeroizing<String>> {
        let mut copy = self.password_copy.lock().unwrap();
        if let Some(shared) = copy
            .upgrade()
            .filter(|shared| shared.as_str() == pw.as_str())
        {
            return shared;
        }
        let fresh = std::sync::Arc::new(pw.clone());
        *copy = std::sync::Arc::downgrade(&fresh);
        fresh
    }

    /// The teardowns of `jobs` that fit under [`MAX_PENDING_TEARDOWNS`] next
    /// to the ones still running; the rest are dropped - with any password
    /// copy they held - and their sessions left to expire on their servers.
    fn admit_teardowns(&self, mut jobs: Vec<TeardownJob>) -> Vec<TeardownJob> {
        let running = {
            let mut teardowns = self.teardowns.lock().unwrap();
            teardowns.retain(|handle| !handle.inner().is_finished());
            teardowns.len()
        };
        let room = MAX_PENDING_TEARDOWNS.saturating_sub(running);
        if jobs.len() > room {
            log::warn!(
                "[sshspan-mcp] {} MCP session(s) not ended: {MAX_PENDING_TEARDOWNS} session teardowns are pending already; those sessions expire on their servers",
                jobs.len() - room
            );
            jobs.truncate(room);
        }
        jobs
    }
}

// ─── Transport core ─────────────────────────────────────────────────────────

/// A parsed JSON-RPC response plus what happened while reading the stream.
#[allow(dead_code)] // answered_requests feeds the integration tests' -32601 assertions
pub struct JsonRpcOutcome {
    /// The full JSON-RPC response object (id/jsonrpc/result-or-error).
    pub result: Value,
    /// Server-to-client requests answered with -32601 (never surfaced to
    /// the LLM; counted for audit).
    pub answered_requests: usize,
    /// Whether a tools/list_changed notification was seen (re-fetch tools).
    pub list_changed: bool,
}

/// POST one JSON-RPC message and return the raw response, handling both
/// `application/json` and `text/event-stream` via `read_response`. Pure
/// over an injected `reqwest::Client` so the integration tests drive it.
pub async fn post_jsonrpc(
    client: &reqwest::Client,
    url: &str,
    body: &Value,
    auth: Option<(&str, &Zeroizing<String>)>,
    session: Option<&str>,
    protocol_version: Option<&str>,
) -> CmdResult<reqwest::Response> {
    let mut req = client
        .post(url)
        .header("Accept", "application/json, text/event-stream")
        .header("Content-Type", "application/json")
        .json(body);
    if let Some((name, value)) = auth {
        req = req.header(name, value.as_str());
    }
    if let Some(sid) = session {
        req = req.header("Mcp-Session-Id", sid);
    }
    if let Some(pv) = protocol_version {
        req = req.header("MCP-Protocol-Version", pv);
    }
    let resp = req
        .send()
        .await
        .map_err(|e| CmdError(format!("MCP request failed: {e}")))?;
    // 3xx is a HARD ERROR. Policy::none() means reqwest returns the
    // redirect as a normal response; without this check the caller would
    // try to parse an HTML redirect page, and a future change that followed
    // redirects would send auth headers off-origin. A redirect is never a
    // valid Streamable HTTP reply.
    if resp.status().is_redirection() {
        let loc = resp
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("?")
            .to_string();
        return Err(CmdError(format!(
            "MCP server returned a redirect ({}) to {loc} - redirects are not supported for MCP servers.",
            resp.status().as_u16()
        )));
    }
    Ok(resp)
}

/// Read a response body with the 2 MB cap applied, streaming chunk by
/// chunk so an oversized body aborts instead of buffering first.
async fn read_capped(resp: &mut reqwest::Response) -> CmdResult<String> {
    let mut buf: Vec<u8> = Vec::with_capacity(8 * 1024);
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| CmdError(format!("Error reading MCP response: {e}")))?
    {
        buf.extend_from_slice(&chunk);
        if buf.len() > MAX_BODY_BYTES {
            return Err(CmdError("MCP response exceeds the 2 MB limit.".into()));
        }
    }
    String::from_utf8(buf).map_err(|_| CmdError("MCP response is not valid UTF-8.".into()))
}

/// The error for a server that does not speak Streamable HTTP, the only MCP
/// transport this client implements (A4-22). A legacy HTTP+SSE (2024-11-05)
/// server typically answers the initialize POST with 405 - its SSE endpoint
/// takes GET only - or opens an event stream whose first event is
/// `endpoint`.
fn unsupported_transport(detail: &str) -> CmdError {
    CmdError(format!(
        "This server does not speak MCP Streamable HTTP ({detail}) - SSHSpan supports Streamable HTTP only."
    ))
}

/// One server-sent event: its `event:` name, if any, and its `data:` lines
/// joined with LF.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SseEvent {
    event: Option<String>,
    data: String,
}

/// An incremental `text/event-stream` decoder (A7-50): fed the body chunk by
/// chunk, it hands back each event as soon as its closing blank line has
/// arrived, so a reply can be used while the server keeps the stream open.
/// Lines may end in LF, CRLF or a lone CR, and a chunk may end anywhere -
/// inside a line, between a CR and its LF, or inside a multi-byte UTF-8
/// character (a line is decoded only once complete). Comment lines and
/// unknown fields are skipped, as the SSE format says.
#[derive(Default)]
struct SseDecoder {
    /// Bytes of the line in progress.
    line: Vec<u8>,
    /// The previous byte was a CR, so a LF right after it ends nothing.
    after_cr: bool,
    event: Option<String>,
    data: Vec<String>,
}

impl SseDecoder {
    /// Decode one chunk; returns the events it completed.
    fn push(&mut self, chunk: &[u8]) -> CmdResult<Vec<SseEvent>> {
        let mut events = Vec::new();
        for &byte in chunk {
            if std::mem::take(&mut self.after_cr) && byte == b'\n' {
                continue;
            }
            match byte {
                b'\r' => {
                    self.after_cr = true;
                    self.end_line(&mut events)?;
                }
                b'\n' => self.end_line(&mut events)?,
                _ => self.line.push(byte),
            }
        }
        Ok(events)
    }

    /// The end of the body. A last line without its line break still counts,
    /// and an event the server never closed with a blank line is delivered
    /// too (the whole-body parser this replaces accepted both).
    fn finish(&mut self) -> CmdResult<Vec<SseEvent>> {
        let mut events = Vec::new();
        if !self.line.is_empty() {
            self.end_line(&mut events)?;
        }
        self.dispatch(&mut events);
        Ok(events)
    }

    fn end_line(&mut self, events: &mut Vec<SseEvent>) -> CmdResult<()> {
        let line = String::from_utf8(std::mem::take(&mut self.line))
            .map_err(|_| CmdError("MCP response is not valid UTF-8.".into()))?;
        if line.is_empty() {
            self.dispatch(events);
            return Ok(());
        }
        if line.starts_with(':') {
            return Ok(());
        }
        let (field, value) = match line.split_once(':') {
            Some((field, value)) => (field, value.strip_prefix(' ').unwrap_or(value)),
            None => (line.as_str(), ""),
        };
        match field {
            "data" => self.data.push(value.to_string()),
            "event" => self.event = Some(value.to_string()),
            _ => {}
        }
        Ok(())
    }

    fn dispatch(&mut self, events: &mut Vec<SseEvent>) {
        let event = self.event.take();
        if self.data.is_empty() {
            return;
        }
        events.push(SseEvent {
            event,
            data: std::mem::take(&mut self.data).join("\n"),
        });
    }
}

/// Most server-to-client requests one response may make the client answer.
/// Each -32601 answer is a request carrying the auth header; a server
/// streaming more of them than this is cut off.
const MAX_SERVER_REQUESTS_PER_RESPONSE: usize = 8;

/// Read the JSON-RPC response for `want_id` from an HTTP response, handling
/// both content types:
/// - application/json: the body IS the response.
/// - text/event-stream: decode events AS THEY ARRIVE and return as soon as
///   the response with `want_id` is in - a server may keep the stream open
///   for later notifications (the spec only says it SHOULD close it), and
///   waiting for the end made every such call wait out the 60 s timeout
///   (A7-50). Whatever the server sends after the answer is not read: a
///   tools/list_changed that arrives later is picked up by the next connect
///   or by a later call's stream. The 2 MB cap applies to the bytes read.
///   Server-to-client REQUESTS (id + method) are answered with JSON-RPC
///   error -32601 on the same session and never surfaced - at most
///   [`MAX_SERVER_REQUESTS_PER_RESPONSE`] of them, and only while `guard`
///   (the vault-generation check in production) still passes, because each
///   answer carries the auth header. Notifications (no id) such as
///   notifications/tools/list_changed are noted, not answered. A legacy
///   HTTP+SSE `endpoint` event is the unsupported-transport error.
#[allow(clippy::too_many_arguments)] // the wire context comes piecewise so tests can drive it
pub async fn read_response(
    client: &reqwest::Client,
    url: &str,
    auth: Option<(&str, &Zeroizing<String>)>,
    session: Option<&str>,
    protocol_version: Option<&str>,
    want_id: &Value,
    guard: &(dyn Fn() -> CmdResult<()> + Sync),
    mut resp: reqwest::Response,
) -> CmdResult<JsonRpcOutcome> {
    if !resp.status().is_success() {
        return Err(CmdError(format!(
            "MCP server returned HTTP {}.",
            resp.status().as_u16()
        )));
    }
    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_lowercase();

    if !content_type.starts_with("text/event-stream") {
        let body = read_capped(&mut resp).await?;
        let v: Value = serde_json::from_str(&body)
            .map_err(|_| CmdError("MCP server returned a non-JSON response.".into()))?;
        if v.get("id") != Some(want_id) {
            return Err(CmdError(
                "MCP server answered a different request id than the one sent.".into(),
            ));
        }
        return Ok(JsonRpcOutcome {
            result: v,
            answered_requests: 0,
            list_changed: false,
        });
    }

    let mut decoder = SseDecoder::default();
    let mut bytes_read = 0usize;
    let mut answered = 0usize;
    let mut list_changed = false;
    loop {
        let chunk = resp
            .chunk()
            .await
            .map_err(|e| CmdError(format!("Error reading MCP response: {e}")))?;
        let at_end = chunk.is_none();
        let events = match chunk {
            Some(bytes) => {
                bytes_read += bytes.len();
                if bytes_read > MAX_BODY_BYTES {
                    return Err(CmdError("MCP response exceeds the 2 MB limit.".into()));
                }
                decoder.push(&bytes)?
            }
            None => decoder.finish()?,
        };
        for event in events {
            // A legacy HTTP+SSE server opens with an `endpoint` event naming
            // the URL to POST to - not a JSON-RPC message.
            if event.event.as_deref() == Some("endpoint")
                && serde_json::from_str::<Value>(&event.data).is_err()
            {
                return Err(unsupported_transport(
                    "it opened a legacy HTTP+SSE event stream",
                ));
            }
            let Ok(message) = serde_json::from_str::<Value>(&event.data) else {
                continue;
            };
            match classify_stream_message(&message, want_id) {
                StreamMessage::Answer => {
                    return Ok(JsonRpcOutcome {
                        result: message,
                        answered_requests: answered,
                        list_changed,
                    });
                }
                StreamMessage::ServerRequest => {
                    // Phase 1 supports no client capabilities (empty in
                    // initialize), so nothing is a valid request target:
                    // answer -32601 (method not found) and NEVER pass it to
                    // the LLM. A failure to send the answer is non-fatal -
                    // the main response still counts. The answer carries
                    // the auth header: bounded per response, and not once
                    // the vault has locked.
                    if answered >= MAX_SERVER_REQUESTS_PER_RESPONSE {
                        return Err(CmdError(format!(
                            "MCP server sent more than {MAX_SERVER_REQUESTS_PER_RESPONSE} requests of its own while answering - the request was abandoned."
                        )));
                    }
                    guard()?;
                    let error = json!({
                        "jsonrpc": "2.0",
                        "id": message.get("id").cloned().unwrap_or(Value::Null),
                        "error": { "code": -32601, "message": "Method not found" },
                    });
                    let _ =
                        post_jsonrpc(client, url, &error, auth, session, protocol_version).await;
                    answered += 1;
                }
                StreamMessage::ListChanged => list_changed = true,
                StreamMessage::Ignored => {}
            }
        }
        if at_end {
            return Err(CmdError(
                "MCP server closed the SSE stream without answering the request.".into(),
            ));
        }
    }
}

enum StreamMessage {
    Answer,
    ServerRequest,
    ListChanged,
    Ignored,
}

fn classify_stream_message(event: &Value, want_id: &Value) -> StreamMessage {
    if event.get("id").is_some() && event.get("method").is_some() {
        return StreamMessage::ServerRequest;
    }
    if event.get("method").is_some() {
        // Notification (no id): processed, not answered.
        return if event.get("method").and_then(|m| m.as_str())
            == Some("notifications/tools/list_changed")
        {
            StreamMessage::ListChanged
        } else {
            StreamMessage::Ignored
        };
    }
    if event.get("id") == Some(want_id) {
        return StreamMessage::Answer;
    }
    // A response to some other id: stale duplicate, ignore.
    StreamMessage::Ignored
}

/// Parse a complete SSE body into the JSON `data:` payloads, in order
/// (non-JSON events are skipped) - the same decoder `read_response` runs
/// incrementally.
pub fn parse_sse(body: &str) -> Vec<Value> {
    let mut decoder = SseDecoder::default();
    // A &str is valid UTF-8, so neither call can fail.
    let mut events = decoder.push(body.as_bytes()).unwrap_or_default();
    events.extend(decoder.finish().unwrap_or_default());
    events
        .iter()
        .filter_map(|e| serde_json::from_str(&e.data).ok())
        .collect()
}

/// Extract the `result` or raise the JSON-RPC `error` as a CmdError.
pub fn rpc_result(response: Value) -> CmdResult<Value> {
    if let Some(err) = response.get("error") {
        let code = err.get("code").and_then(|c| c.as_i64()).unwrap_or(0);
        let msg = err
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("unknown error");
        return Err(CmdError(format!(
            "MCP server returned a JSON-RPC error ({code}): {msg}"
        )));
    }
    response
        .get("result")
        .cloned()
        .ok_or_else(|| CmdError("MCP server response has no result.".into()))
}

/// Integration-test exposure of `request_once_unchecked` (which stays
/// private; tests exercise the 404 / re-init flow through this alias).
/// `generation = u64::MAX` and an unlocked vault keep the generation check
/// inert for direct transport-level calls; the guard is a no-op.
#[doc(hidden)]
pub async fn request_once_test(
    ctx: &ServerContext,
    body: &Value,
) -> CmdResult<Option<JsonRpcOutcome>> {
    request_once_unchecked(ctx, body, &|| Ok(())).await
}

// ─── Session lifecycle ──────────────────────────────────────────────────────

/// Everything a connected server needs to make requests, plus the vault
/// generation captured by the owner BEFORE the first await. Every helper
/// that sends a credential-bearing request rechecks the generation first
/// (`ctx.checked`), so a vault lock during any earlier await makes the next
/// request abort instead of sending the unsealed auth header.
pub struct ServerContext {
    pub record: crate::db::McpServerRecord,
    pub url: String,
    pub client: reqwest::Client,
    pub session: Option<McpSession>,
    pub auth: Option<(String, Zeroizing<String>)>,
    pub generation: u64,
}

impl ServerContext {
    /// Abort unless the vault generation captured by the owner is still
    /// current. Called immediately before every credential-bearing request.
    pub fn checked(&self, app: &AppHandle) -> CmdResult<()> {
        require_generation_current(app, self.generation)
    }
}

fn auth_ref(ctx: &ServerContext) -> Option<(&str, &Zeroizing<String>)> {
    ctx.auth.as_ref().map(|(n, v)| (n.as_str(), v))
}

/// Unseal + resolve the auth header for a server record. The caller supplies
/// the vault generation it captured BEFORE its first await so every request
/// made through the context can recheck it.
async fn load_server_context(
    app: &AppHandle,
    record: crate::db::McpServerRecord,
    pw: &Zeroizing<String>,
    generation: u64,
) -> CmdResult<ServerContext> {
    server_context(
        app.state::<McpState>().inner(),
        &app.state::<crate::AppState>().db,
        record,
        pw,
        generation,
    )
    .await
}

/// [`load_server_context`] without the `AppHandle`: the server's URL, a
/// client, a session set up with the record's settings (if one is
/// registered) and its auth header - a stored secret unsealed on the
/// blocking pool. It used to be unsealed inline, an Argon2id derivation on
/// an async worker for every connect and every call.
async fn server_context(
    state: &McpState,
    db: &crate::db::Database,
    record: crate::db::McpServerRecord,
    pw: &Zeroizing<String>,
    generation: u64,
) -> CmdResult<ServerContext> {
    let (url, _class) = classify_url(&record.url).map_err(CmdError)?;
    let auth = {
        let binding = ConnectionBinding::of(&record);
        let pw = pw.clone();
        crate::commands::run_blocking(move || {
            resolve_auth_header(
                &binding.auth_type,
                binding.auth_header_name.as_deref(),
                binding.auth_secret.as_deref(),
                binding.auth_env_var.as_deref(),
                &pw,
            )
        })
        .await?
    };
    let session = usable_session(state, db, &record, pw);
    Ok(ServerContext {
        session,
        url,
        client: origin_client()?,
        record,
        auth,
        generation,
    })
}

/// The registered session a request for `record` may use: only one set up
/// with `record`'s URL and auth settings. It used to be looked up by server
/// id alone, so a session set up with settings an edit had replaced meanwhile
/// (the edit landed while it was being set up) was sent to the NEW endpoint,
/// and the old endpoint never heard of it again.
///
/// A session set up with other settings is not used. If those settings are
/// gone from the stored record too, the session is stale: it is removed and
/// ended in the background at the endpoint it belongs to, with the
/// credential it was set up with (unsealed by the teardown task, from a copy
/// of `pw`). If the stored record still has them, it is the caller's
/// snapshot that is old: the session is left alone.
fn usable_session(
    state: &McpState,
    db: &crate::db::Database,
    record: &crate::db::McpServerRecord,
    pw: &Zeroizing<String>,
) -> Option<McpSession> {
    let live = state.live_session(&record.id)?;
    if live.belongs_to(record) {
        return Some(live.session);
    }
    // Unknown when the record cannot be read: then nothing is ended.
    let stored = db.get_mcp_server(&record.id).ok()?;
    let stale = state.take_session_if(&record.id, |now| {
        now.session == live.session && stored.as_ref().is_none_or(|s| !now.belongs_to(s))
    })?;
    let password = Some(state.shared_password(pw));
    if let (Some(job), Ok(client)) = (session_end(stale, None, password), origin_client()) {
        state.end_replaced(job, db.clone(), client);
    }
    None
}

#[doc(hidden)]
pub async fn initialize_test(ctx: &ServerContext) -> CmdResult<(McpSession, JsonRpcOutcome)> {
    initialize_unchecked(ctx, &|| Ok(())).await
}

/// The initialize request/response, returning the live session. Negotiates
/// the protocol version: offers 2025-11-25, accepts the server's reply if
/// it is in the supported set, and stores THAT version for the
/// MCP-Protocol-Version header on all later requests. Anything else is a
/// hard disconnect - a server speaking an unknown version may have
/// incompatible semantics this client cannot safely guess at. `guard` runs
/// before every further request this exchange sends on its own (the -32601
/// answers in `read_response`); the caller checks it before this request.
async fn initialize_unchecked(
    ctx: &ServerContext,
    guard: &(dyn Fn() -> CmdResult<()> + Sync),
) -> CmdResult<(McpSession, JsonRpcOutcome)> {
    // Production callers check the vault generation immediately before
    // entering this helper and pass the same check as `guard`; test callers
    // use the unchecked transport seam with a no-op guard.
    let id = Value::String(uuid::Uuid::new_v4().to_string());
    let body = json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "initialize",
        "params": {
            // EMPTY capabilities on purpose: this client supports no
            // sampling, roots, or elicitation, so any server-to-client
            // request is answered -32601 (see classify_stream_message).
            "capabilities": {},
            "protocolVersion": PROTOCOL_VERSION_OFFERED,
            "clientInfo": { "name": "SSHSpan", "version": env!("CARGO_PKG_VERSION") },
        },
    });
    let resp = post_jsonrpc(&ctx.client, &ctx.url, &body, auth_ref(ctx), None, None).await?;
    // A legacy HTTP+SSE endpoint takes GET only: 405 on the initialize POST
    // is the old transport, not a broken server.
    if resp.status().as_u16() == 405 {
        return Err(unsupported_transport("HTTP 405"));
    }
    let session_header = resp
        .headers()
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let outcome = read_response(
        &ctx.client,
        &ctx.url,
        auth_ref(ctx),
        None,
        None,
        &id,
        guard,
        resp,
    )
    .await?;
    let result = rpc_result(outcome.result.clone())?;
    let negotiated = result
        .get("protocolVersion")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CmdError("MCP server's initialize result has no protocolVersion.".into()))?;
    if !SUPPORTED_PROTOCOL_VERSIONS.contains(&negotiated) {
        return Err(CmdError(format!(
            "MCP server speaks protocol version '{negotiated}', which this client does not support (supported: {}).",
            SUPPORTED_PROTOCOL_VERSIONS.join(", ")
        )));
    }
    Ok((
        McpSession {
            session_id: session_header,
            protocol_version: negotiated.to_string(),
        },
        outcome,
    ))
}

/// Send `notifications/initialized` after a successful initialize. Like
/// every credential-bearing request, the caller rechecks the vault
/// generation first: a lock that happened during initialize must not let
/// this notification send the unsealed auth header.
async fn send_initialized_unchecked(ctx: &ServerContext, session: &McpSession) -> CmdResult<()> {
    let body = json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
    });
    let resp = post_jsonrpc(
        &ctx.client,
        &ctx.url,
        &body,
        auth_ref(ctx),
        session.session_id.as_deref(),
        Some(&session.protocol_version),
    )
    .await?;
    // 202 Accepted is the expected reply; any success status is fine.
    if !resp.status().is_success() {
        return Err(CmdError(format!(
            "MCP server rejected notifications/initialized with HTTP {}.",
            resp.status().as_u16()
        )));
    }
    Ok(())
}

/// One request attempt. `None` means "session unknown to the server (404)"
/// and the caller re-initializes once and retries. The caller rechecks the
/// vault generation before the request - every post-initialize await is a
/// window in which a lock could have cleared the password store - and
/// `guard` runs before every further request this exchange sends on its own
/// (the -32601 answers in `read_response`).
async fn request_once_unchecked(
    ctx: &ServerContext,
    body: &Value,
    guard: &(dyn Fn() -> CmdResult<()> + Sync),
) -> CmdResult<Option<JsonRpcOutcome>> {
    let session = ctx
        .session
        .as_ref()
        .ok_or_else(|| CmdError("MCP session is not initialized.".into()))?;
    let resp = post_jsonrpc(
        &ctx.client,
        &ctx.url,
        body,
        auth_ref(ctx),
        session.session_id.as_deref(),
        Some(&session.protocol_version),
    )
    .await?;
    if resp.status().as_u16() == 404 {
        // Spec: 404 = session terminated. Signal re-init.
        return Ok(None);
    }
    let outcome = read_response(
        &ctx.client,
        &ctx.url,
        auth_ref(ctx),
        session.session_id.as_deref(),
        Some(&session.protocol_version),
        body.get("id").unwrap_or(&Value::Null),
        guard,
        resp,
    )
    .await?;
    Ok(Some(outcome))
}

/// What setting up, renewing and using a session needs besides the server
/// context: the registry sessions are registered in, the database (the
/// audit row of a teardown that fails), the vault password (to end a session
/// a registration displaced - with ITS credential, which may be another
/// one, [`TeardownAuth::Unseal`]), and the vault-generation check run before
/// every credential-bearing request and when a session is registered.
struct SessionScope<'a> {
    state: &'a McpState,
    db: &'a crate::db::Database,
    password: &'a Zeroizing<String>,
    guard: &'a (dyn Fn() -> CmdResult<()> + Sync),
}

/// Send a request and read its response, handling a 404 for a KNOWN
/// session by re-initializing ONCE and retrying (session expired
/// server-side). Generation is rechecked before initialize, before the
/// initialized notification, and before the retry.
///
/// The server as stored is checked first ([`not_contactable`]): one
/// switched off, edited or removed since `ctx` was set up gets nothing more -
/// the session `ctx` holds is ended where it was set up, and the request
/// fails with why. A session the server lost (404) is forgotten and renewed
/// only through [`establish_session`], which checks the same before its
/// initialize and again once it is answered; and the request asked again on
/// the new session is checked once more first. It used to be renewed, and
/// asked again, whatever had become of the server meanwhile.
async fn request_with_session(
    scope: &SessionScope<'_>,
    ctx: &mut ServerContext,
    body: &Value,
) -> CmdResult<JsonRpcOutcome> {
    (scope.guard)()?;
    if let Some(why) = not_contactable(scope.db, &ctx.record)? {
        end_ctx_session(scope.state, scope.db, ctx);
        ctx.session = None;
        return Err(CmdError(why.into()));
    }
    let first = {
        let _in_use = scope.state.use_session(ctx.session.as_ref());
        request_once_unchecked(ctx, body, scope.guard).await?
    };
    if let Some(outcome) = first {
        return Ok(outcome);
    }
    // 404: forget the lost session (no DELETE: the server dropped it), then
    // re-initialize once and retry the request with the new session.
    // A tools/list_changed announced by that initialize counts as the
    // retried answer's own: a paginated tools/list then starts over from its
    // first page (`fetch_tools`) - the pages read before the renewal may be
    // of the old list. It used to be dropped, and the two lists were mixed.
    forget_lost_session(scope.state, ctx);
    let announced = establish_session(scope, ctx).await?;
    (scope.guard)()?;
    if let Some(why) = not_contactable(scope.db, &ctx.record)? {
        end_ctx_session(scope.state, scope.db, ctx);
        ctx.session = None;
        return Err(CmdError(why.into()));
    }
    let retried = {
        let _in_use = scope.state.use_session(ctx.session.as_ref());
        request_once_unchecked(ctx, body, scope.guard).await?
    };
    let mut outcome =
        retried.ok_or_else(|| CmdError("MCP session could not be re-established.".into()))?;
    outcome.list_changed |= announced;
    Ok(outcome)
}

/// Initialize a new session for `ctx` and register it in the registry,
/// bound to `ctx`'s settings: initialize, then `notifications/initialized`.
/// The vault-generation check runs before each request and when the session
/// is registered ([`McpState::register`]: a lock during initialize must not
/// leave a live session behind) - and before every request the exchange
/// makes on its own. True when the initialize answer announced a
/// tools/list_changed: the server's tool definitions changed since they were
/// last fetched (while SSHSpan was closed, say).
///
/// Nothing is left open on a server: a session the registration replaced -
/// "Test connection" of a connected server, a call that set up a session
/// from an older snapshot of the settings - is ended where it was set up, at
/// its URL with its credential ([`session_end`]; it used to be dropped and
/// left to expire), and only once the requests still using it are done
/// ([`McpState::end_replaced`]: ending it at once broke a tool call waiting
/// on it). When it was set up with this context's settings, the header this
/// context resolved already ends it - no unseal, no password copy. A session
/// the lock refused to register is ended where this context set it up.
///
/// Never for a server switched off, edited or removed since `ctx` was set
/// up ([`not_contactable`]): nothing is sent, and the set-up fails with why.
/// Every set-up and renewal comes here - a connect ("Test connection"), a
/// call, a refresh - and some used to initialize such a server. The same
/// check runs again once the initialize is answered: a server that changed
/// while it was out gets nothing more - the new session is ended where the
/// initialize went, with the credential it carried, and is never
/// registered.
async fn establish_session(scope: &SessionScope<'_>, ctx: &mut ServerContext) -> CmdResult<bool> {
    (scope.guard)()?;
    if let Some(why) = not_contactable(scope.db, &ctx.record)? {
        return Err(CmdError(why.into()));
    }
    let (session, outcome) = initialize_unchecked(ctx, scope.guard).await?;
    let changed_meanwhile = match not_contactable(scope.db, &ctx.record) {
        Ok(None) => None,
        Ok(Some(why)) => Some(CmdError(why.into())),
        Err(e) => Some(e),
    };
    if let Some(refused) = changed_meanwhile {
        ctx.session = Some(session);
        end_unregistered_session(scope, ctx);
        ctx.session = None;
        return Err(refused);
    }
    match scope
        .state
        .register(&ctx.record, session.clone(), scope.guard)
    {
        Ok(Some(replaced)) if replaced.session != session => {
            let job = if replaced.bound_to(&ctx.record) {
                session_end_resolved(replaced, &ctx.url, ctx.auth.clone())
            } else {
                session_end(
                    replaced,
                    None,
                    Some(scope.state.shared_password(scope.password)),
                )
            };
            if let (Some(job), Ok(client)) = (job, origin_client()) {
                scope.state.end_replaced(job, scope.db.clone(), client);
            }
        }
        Ok(_) => {}
        Err(locked) => {
            ctx.session = Some(session);
            end_unregistered_session(scope, ctx);
            ctx.session = None;
            return Err(locked);
        }
    }
    ctx.session = Some(session.clone());
    (scope.guard)()?;
    send_initialized_unchecked(ctx, &session).await?;
    Ok(outcome.list_changed)
}

/// End the session `ctx` holds, which was never registered (a lock refused
/// it, or the server changed while its initialize was out), in the
/// background where `ctx` set it up - at its URL with the credential the
/// initialize carried. It is in no registry, so nothing else would ever end
/// it.
fn end_unregistered_session(scope: &SessionScope<'_>, ctx: &ServerContext) {
    let Some(session) = ctx.session.as_ref() else {
        return;
    };
    let Some(session_id) = session.session_id.clone() else {
        return;
    };
    let job = TeardownJob {
        url: ctx.url.clone(),
        session_id,
        protocol_version: session.protocol_version.clone(),
        auth: TeardownAuth::Resolved(ctx.auth.clone()),
        server_name: ctx.record.name.clone(),
    };
    scope
        .state
        .start_teardowns(scope.db.clone(), ctx.client.clone(), vec![job]);
}

/// What became of one `tools/call` ([`run_tool_call`]).
#[derive(Debug)]
enum CallSent {
    /// The request went out. `approval` is who let it run and `level` the
    /// tab's access level it was checked at, both from the last gate check
    /// before it (for the audit row); `list_changed` whether a
    /// tools/list_changed came with the answer or with the initialize answer
    /// of a session the call set up - whatever became of the call; `called`
    /// is its result, or why there is none (the tool may still have run).
    Sent {
        approval: &'static str,
        level: String,
        list_changed: bool,
        called: CmdResult<Value>,
    },
    /// The gate, checked again right before the request at `level`, refused
    /// it: the reason. Nothing was sent, and a session this call set up was
    /// ended. `list_changed`: a tools/list_changed came with the initialize
    /// answer of a session the call set up on the way.
    Refused {
        reason: String,
        level: String,
        list_changed: bool,
    },
}

/// One check of the call gate right before `tools/call` ([`regate_call`]):
/// the tab's access level it checked, and its verdict - who lets the call
/// run ([`call_gate`]'s label), or why it may not.
#[derive(Debug)]
struct GateCheck {
    level: String,
    verdict: Result<&'static str, String>,
}

/// The network part of [`mcp_call_tool`], without the `AppHandle`: set up a
/// session if there is none, then send `tools/call` - re-initializing once
/// and retrying if the server no longer knows the session (404). The
/// scope's guard is the vault-generation check; `regate` re-reads the server
/// record and the tab's level and runs the call gate again ([`regate_call`]).
///
/// The gate is run again right before every `tools/call` that goes out -
/// after the session set-up and after a re-initialize - not only before the
/// set-up: those round trips can take seconds, and a tool revoked or changed
/// meanwhile (or a tab disarmed from YOLO) was still called. A refusal there
/// is [`CallSent::Refused`]: nothing was sent, and a session this call set up
/// is ended ([`gate_before_call`]). The level that check passed at is the
/// one the call is audited at. The gate also runs before the set-up and
/// before a re-initialize: a server switched off, edited or removed since
/// the command's own check (or while a call was out) gets no initialize - it
/// used to get one, and the refusal came after it.
///
/// A tools/list_changed announced with the answer to an initialize this call
/// sent counts as the call's own: the server's definitions changed since
/// they were fetched - while SSHSpan was closed, say - so the tool list is
/// refreshed after the call (see `finish_tool_call`), which disables a
/// changed tool. It used to be dropped, and a changed tool stayed enabled.
async fn run_tool_call(
    scope: &SessionScope<'_>,
    ctx: &mut ServerContext,
    body: &Value,
    regate: &(dyn Fn() -> GateCheck + Sync),
) -> CmdResult<CallSent> {
    let guard = scope.guard;
    let mut announced = false;
    let set_up = ctx.session.is_none();
    if set_up {
        announced = match set_up_for_call(scope, ctx, regate, false).await? {
            CallSetUp::Ready(changed) => changed,
            CallSetUp::Refused(refused) => return Ok(refused),
        };
    }
    let (mut approval, mut level) = match gate_before_call(scope, ctx, set_up, regate(), announced)
    {
        Ok(passed) => passed,
        Err(refused) => return Ok(refused),
    };
    let first = match guard() {
        Ok(()) => {
            let _in_use = scope.state.use_session(ctx.session.as_ref());
            request_once_unchecked(ctx, body, guard).await
        }
        Err(e) => Err(e),
    };
    let answered = match first {
        Ok(None) => {
            // 404: the session expired before the call ran. Forget it (no
            // DELETE: the server dropped it), set up a new one as far as the
            // gate as stored now lets the call run, check the gate again,
            // retry.
            forget_lost_session(scope.state, ctx);
            match set_up_for_call(scope, ctx, regate, announced).await {
                Ok(CallSetUp::Ready(changed)) => announced |= changed,
                Ok(CallSetUp::Refused(refused)) => return Ok(refused),
                Err(e) => {
                    return Ok(CallSent::Sent {
                        approval,
                        level,
                        list_changed: announced,
                        called: Err(e),
                    })
                }
            }
            (approval, level) = match gate_before_call(scope, ctx, true, regate(), announced) {
                Ok(passed) => passed,
                Err(refused) => return Ok(refused),
            };
            match guard() {
                Ok(()) => {
                    let _in_use = scope.state.use_session(ctx.session.as_ref());
                    request_once_unchecked(ctx, body, guard).await
                }
                Err(e) => Err(e),
            }
        }
        other => other,
    };
    // A list change announced on the way counts whatever becomes of the
    // call: it used to ride inside the call's answer, and was lost with it
    // when the call failed.
    let mut list_changed = announced;
    let called = answered.and_then(|outcome| {
        let outcome =
            outcome.ok_or_else(|| CmdError("MCP session could not be re-established.".into()))?;
        list_changed |= outcome.list_changed;
        guard()?;
        rpc_result(outcome.result)
    });
    Ok(CallSent::Sent {
        approval,
        level,
        list_changed,
        called,
    })
}

/// [`run_tool_call`]'s gate check right before a `tools/call`: who lets the
/// call run and at which level - or the refusal. A refused call ends the
/// session it registered itself (`set_up`): that session was set up for this
/// call, possibly with the very settings an edit just replaced, and was
/// otherwise left registered - the next call sent its id to the new endpoint.
/// `announced`: a tools/list_changed came with that session's set-up - it
/// goes with the refusal (it used to be dropped there). The context forgets
/// the session it ended, so nothing after the refusal sends its id again.
fn gate_before_call(
    scope: &SessionScope<'_>,
    ctx: &mut ServerContext,
    set_up: bool,
    check: GateCheck,
    announced: bool,
) -> Result<(&'static str, String), CallSent> {
    match check.verdict {
        Ok(approval) => Ok((approval, check.level)),
        Err(reason) => {
            if set_up {
                end_ctx_session(scope.state, scope.db, ctx);
                ctx.session = None;
            }
            Err(CallSent::Refused {
                reason,
                level: check.level,
                list_changed: announced,
            })
        }
    }
}

/// How [`set_up_for_call`] ended.
enum CallSetUp {
    /// The session is set up; whether its initialize announced a
    /// tools/list_changed.
    Ready(bool),
    /// The gate refused the call; nothing more was sent.
    Refused(CallSent),
}

/// Set up (or renew) the session a call goes out on - only while the gate
/// as stored now lets the call run: it is checked before the initialize,
/// and again when the set-up fails, so a server switched off, edited or
/// removed while the initialize was out (which [`establish_session`]
/// refuses before registering anything) is a refusal like one after the
/// set-up - audited as such - and not a failed set-up. `announced`: a
/// tools/list_changed came with an earlier set-up of this call. Nothing is
/// set up yet when the gate refuses, so the refusal ends nothing.
async fn set_up_for_call(
    scope: &SessionScope<'_>,
    ctx: &mut ServerContext,
    regate: &(dyn Fn() -> GateCheck + Sync),
    announced: bool,
) -> CmdResult<CallSetUp> {
    if let Err(refused) = gate_before_call(scope, ctx, false, regate(), announced) {
        return Ok(CallSetUp::Refused(refused));
    }
    match establish_session(scope, ctx).await {
        Ok(changed) => Ok(CallSetUp::Ready(changed)),
        Err(failed) => match gate_before_call(scope, ctx, false, regate(), announced) {
            Err(refused) => Ok(CallSetUp::Refused(refused)),
            Ok(_) => Err(failed),
        },
    }
}

/// A call the gate refused right before it went out: nothing ran - but a
/// tools/list_changed announced while its session was set up still means the
/// stored definitions are stale, so they are refreshed (`refresh`; a failure
/// is logged) before the refusal comes back.
async fn after_refused_call<F, Fut>(list_changed: bool, refresh: F)
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = CmdResult<()>>,
{
    if list_changed {
        if let Err(e) = refresh().await {
            log::warn!(
                "[sshspan-mcp] the tool list could not be refreshed after a refused call: {e}"
            );
        }
    }
}

/// The refresh [`after_refused_call`] runs for `mcp_call_tool`: only while
/// the stored record still has the settings `ctx` was set up with and is
/// still switched on (confirmed), and on a session of its own. A gate that
/// refused because the server's URL or auth changed, or because the server
/// was removed, used to get the refresh anyway, on that context: the OLD
/// endpoint got `tools/list` on the session the refusal had just ended - and
/// a real server's 404 then set up a new session for the old settings, which
/// for a removed server lingered until the next lock. Now the refresh waits
/// for the next connect with the new settings. A server switched off
/// meanwhile with the same settings - a "Don't allow" on exactly these, or a
/// restore - gets nothing either: the refresh used to set up a session with
/// it and leave that session registered. With the settings unchanged and the
/// server still on (the tool was revoked, the tab's level dropped), it sets
/// up a session first if the refusal ended the call's.
async fn refresh_after_refusal(
    scope: &SessionScope<'_>,
    ctx: &mut ServerContext,
    record: &crate::db::McpServerRecord,
) -> CmdResult<()> {
    if not_contactable(scope.db, &ctx.record)?.is_some() {
        return Ok(());
    }
    if ctx.session.is_none() {
        establish_session(scope, ctx).await?;
    }
    refresh_tools_after_call(scope, ctx, record).await
}

/// The refresh [`finish_tool_call`] runs for `mcp_call_tool` after a call
/// that went out, when a tools/list_changed came with it: only while the
/// stored record still has the settings `ctx` was set up with and is still
/// switched on ([`not_contactable`]). A server switched off - a "Don't
/// allow", a restore that stored it unconfirmed - or edited or removed while
/// its call was out used to get the refresh anyway, on the call's session
/// (and a new initialize when that answered 404). Now nothing more is sent:
/// the session the call used is ended where it was set up and forgotten, and
/// the next connect with the stored settings refreshes.
async fn refresh_after_sent_call(
    scope: &SessionScope<'_>,
    ctx: &mut ServerContext,
    record: &crate::db::McpServerRecord,
) -> CmdResult<()> {
    if not_contactable(scope.db, &ctx.record)?.is_some() {
        end_ctx_session(scope.state, scope.db, ctx);
        ctx.session = None;
        return Ok(());
    }
    refresh_tools_after_call(scope, ctx, record).await
}

/// The call gate run again on the record as stored NOW, for the call about to
/// go out (`tool` on the server `started_from` was read as, at access
/// `level`, with the user's `approved`). The gate was first checked before
/// the session set-up, which can take seconds: a tool revoked, re-approved
/// with other Auto-approve, changed on the server (refreshed definition) or a
/// tab disarmed from YOLO meanwhile is caught here, with the gate's own
/// messages. A server removed meanwhile, or one whose URL or auth settings
/// changed (the session belongs to the old ones), is refused too.
fn regate_call(
    db: &crate::db::Database,
    started_from: &crate::db::McpServerRecord,
    tool: &str,
    level: &str,
    approved: bool,
) -> GateCheck {
    GateCheck {
        level: level.to_string(),
        verdict: gate_as_stored_now(db, started_from, tool, level, approved),
    }
}

/// [`regate_call`]'s verdict.
fn gate_as_stored_now(
    db: &crate::db::Database,
    started_from: &crate::db::McpServerRecord,
    tool: &str,
    level: &str,
    approved: bool,
) -> Result<&'static str, String> {
    let now = db
        .get_mcp_server(&started_from.id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "MCP server not found.".to_string())?;
    if !same_connection(started_from, &now) {
        return Err(SETTINGS_CHANGED_MEANWHILE.into());
    }
    let entry = now
        .tools
        .iter()
        .find(|t| t.name == tool)
        .ok_or_else(|| format!("Tool '{tool}' not found on this MCP server."))?;
    call_gate(level, approved, now.confirmed, entry)
}

/// Fetch the full tool list with cursor pagination; servers above the
/// global tool cap are rejected outright. A `tools/list_changed`
/// notification observed on ANY page ends pagination immediately and
/// restarts the fetch from scratch, so the returned list is never a mix of
/// pre- and post-change pages.
async fn fetch_tools(scope: &SessionScope<'_>, ctx: &mut ServerContext) -> CmdResult<Vec<Value>> {
    const MAX_FETCH_ATTEMPTS: usize = 3;
    for _ in 0..MAX_FETCH_ATTEMPTS {
        let (tools, list_changed) = fetch_tools_once(scope, ctx).await?;
        if !list_changed {
            if tools.len() > MAX_EXPOSED_TOOLS {
                return Err(CmdError(format!(
                    "MCP server exposes {} tools, above the {}-tool limit.",
                    tools.len(),
                    MAX_EXPOSED_TOOLS
                )));
            }
            return Ok(tools);
        }
        // The tool set changed mid-fetch: pages already accumulated may be
        // stale. Re-fetch from the first page rather than exposing them.
    }
    Err(CmdError(
        "MCP server kept changing its tool list mid-fetch; try again.".into(),
    ))
}

/// Most tools/list pages one pass reads - far beyond what the tool cap needs.
const MAX_TOOL_PAGES: usize = 100;

/// The cursor for the next tools/list page once `pages_read` pages holding
/// `tools_so_far` tools are in, or `None` when the listing is complete (no
/// cursor, or an empty one). A server past the [`MAX_EXPOSED_TOOLS`] cap is
/// refused as soon as it gets there - it would be refused at the end anyway,
/// and reading on only grows memory. A cursor the server already sent (an
/// endless loop - including empty pages that never grow the tool count) or a
/// page beyond [`MAX_TOOL_PAGES`] fails the fetch too: such a server must
/// not hold a connect, and the vault guard it holds, forever. Failing rather
/// than stopping short, because tools missing from a truncated list would be
/// dropped from the stored record by `merge_tools`.
fn next_tools_page(
    seen: &mut std::collections::HashSet<String>,
    pages_read: usize,
    tools_so_far: usize,
    next_cursor: Option<String>,
) -> CmdResult<Option<String>> {
    let next_cursor = next_cursor.filter(|c| !c.is_empty());
    if tools_so_far > MAX_EXPOSED_TOOLS {
        return Err(CmdError(if next_cursor.is_some() {
            format!(
                "MCP server exposes more than {MAX_EXPOSED_TOOLS} tools ({tools_so_far} listed before SSHSpan stopped reading), above the {MAX_EXPOSED_TOOLS}-tool limit."
            )
        } else {
            format!(
                "MCP server exposes {tools_so_far} tools, above the {MAX_EXPOSED_TOOLS}-tool limit."
            )
        }));
    }
    let Some(cursor) = next_cursor else {
        return Ok(None);
    };
    if !seen.insert(cursor.clone()) {
        return Err(CmdError(
            "MCP server repeated a tools/list page cursor, so its tool list never ends.".into(),
        ));
    }
    if pages_read >= MAX_TOOL_PAGES {
        return Err(CmdError(format!(
            "MCP server's tool list ran past {MAX_TOOL_PAGES} pages."
        )));
    }
    Ok(Some(cursor))
}

/// One pagination pass over tools/list. Returns the pages plus whether a
/// tools/list_changed notification was observed along the way.
async fn fetch_tools_once(
    scope: &SessionScope<'_>,
    ctx: &mut ServerContext,
) -> CmdResult<(Vec<Value>, bool)> {
    let mut tools = Vec::new();
    let mut cursor: Option<String> = None;
    let mut seen_cursors = std::collections::HashSet::new();
    let mut pages_read = 0usize;
    loop {
        let id = Value::String(uuid::Uuid::new_v4().to_string());
        let mut params = json!({});
        if let Some(c) = &cursor {
            params["cursor"] = json!(c);
        }
        let body = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/list",
            "params": params,
        });
        let outcome = request_with_session(scope, ctx, &body).await?;
        pages_read += 1;
        let result = rpc_result(outcome.result)?;
        if let Some(arr) = result.get("tools").and_then(|t| t.as_array()) {
            tools.extend(arr.iter().cloned());
        }
        // A list_changed observed on ANY page invalidates the whole pass:
        // stop paginating and let fetch_tools restart from the first page.
        if outcome.list_changed {
            return Ok((tools, true));
        }
        cursor = next_tools_page(
            &mut seen_cursors,
            pages_read,
            tools.len(),
            result
                .get("nextCursor")
                .and_then(|c| c.as_str())
                .map(String::from),
        )?;
        if cursor.is_none() {
            break;
        }
    }
    Ok((tools, false))
}

/// What connect and call refuse for a server that is not confirmed: one
/// restored from a backup, or one whose credential binding the user did not
/// allow in the native dialog (`settle_binding`).
const UNCONFIRMED_SERVER: &str = "This MCP server stays switched off until its URL and credential are confirmed (it came from a backup, or sending its credential was not allowed). Open its settings, check the URL and auth, and save it again.";

/// What a request refuses when the server's URL or auth settings changed
/// since its context was set up.
const SETTINGS_CHANGED_MEANWHILE: &str =
    "This MCP server's URL or auth settings changed meanwhile - test the connection again.";

/// What a request refuses when the server was removed since its context was
/// set up.
const SERVER_REMOVED_MEANWHILE: &str = "This MCP server was removed meanwhile.";

/// The full connect flow: initialize (+initialized), tools/list with
/// pagination, merge + persist. On success the session is registered in
/// the app state and the refreshed record is returned along with the names
/// of tools that were disabled by a definition change (already audited
/// here as `mcp.tool_definition_changed`).
///
/// The vault generation is captured before the first await and rechecked
/// before EVERY credential-bearing request and when the session is
/// registered (the scope's guard), and again before persisting, so a lock
/// mid-connect can neither send the unsealed auth header nor write
/// session/DB state afterward.
///
/// After the network round trips it re-reads the record and writes the
/// whole row back with the fetched tools merged in, in one transaction
/// ([`store_fetched_tools`]). The CALLER holds read access to the
/// `VaultRotationLock` from before it read `record` until this returns:
/// `record`'s secret must not be unsealed with a password that is being
/// replaced.
async fn connect_server(
    app: &AppHandle,
    record: crate::db::McpServerRecord,
) -> CmdResult<(crate::db::McpServerRecord, Vec<String>)> {
    let generation = capture_vault_generation(app)?;
    let pw = vault_password(app)?;
    if pw.is_empty() {
        return Err("Vault is locked.".into());
    }
    if !record.confirmed {
        return Err(CmdError(UNCONFIRMED_SERVER.into()));
    }
    let mut ctx = load_server_context(app, record.clone(), &pw, generation).await?;
    let db = &app.state::<crate::AppState>().db;
    let guard = || require_generation_current(app, generation);
    let scope = SessionScope {
        state: app.state::<McpState>().inner(),
        db,
        password: &pw,
        guard: &guard,
    };
    // A list_changed arriving WITH the initialize answer needs no handling
    // here: the very next step is a fresh tools/list (fetch_tools), so
    // nothing stale is ever exposed from it.
    establish_session(&scope, &mut ctx).await?;
    let tool_defs = fetch_tools(&scope, &mut ctx).await?;
    // Last boundary before persisting: a lock during the fetch must not
    // write session-derived state into the DB.
    require_generation_current(app, generation)?;

    // Re-read the record now, after the round trips, and merge into that
    // (A7-49). The caller's rotation guard still covers read and write.
    store_fetched_tools(db, &record, &tool_defs).inspect_err(|_| {
        // The session belongs to settings that are gone: never reuse it.
        end_ctx_session(scope.state, db, &ctx);
    })
}

/// Remove the session `ctx` set up from `state` - only if it is still the one
/// registered (another request may have set up a newer one meanwhile) - and
/// end it in the background where `ctx` set it up: at `ctx`'s URL with
/// `ctx`'s credential, the pair it belongs to. It used to be removed by
/// server id alone, which could drop a newer session, and was never ended.
fn end_ctx_session(state: &McpState, db: &crate::db::Database, ctx: &ServerContext) {
    let Some(mine) = ctx.session.as_ref() else {
        return;
    };
    let Some(live) = state.take_session_if(&ctx.record.id, |live| live.session == *mine) else {
        return;
    };
    let Some(session_id) = live.session.session_id else {
        return;
    };
    let job = TeardownJob {
        url: ctx.url.clone(),
        session_id,
        protocol_version: live.session.protocol_version,
        auth: TeardownAuth::Resolved(ctx.auth.clone()),
        server_name: ctx.record.name.clone(),
    };
    state.start_teardowns(db.clone(), ctx.client.clone(), vec![job]);
}

/// Store the tools a connect (or a call's refresh) fetched: re-read the
/// record and merge them into it ([`merge_into_stored`]) inside ONE
/// transaction with the write (A7-49). The re-read and the save used to be
/// two statements, so a toggle committed between them was overwritten - a
/// revoked approval came back - and a server removed between them was
/// re-created. Each enabled tool the fetch found changed is audited
/// (`mcp.tool_definition_changed`, after the commit). The caller holds the
/// rotation guard.
fn store_fetched_tools(
    db: &crate::db::Database,
    started_from: &crate::db::McpServerRecord,
    fetched: &[Value],
) -> CmdResult<(crate::db::McpServerRecord, Vec<String>)> {
    let (updated, changed) = db
        .modify_mcp_servers(|all| {
            let stored_now = all.iter().find(|r| r.id == started_from.id).cloned();
            let (updated, changed) = merge_into_stored(started_from, stored_now, fetched)?;
            Ok((
                crate::db::McpWrite::Update(updated.clone()),
                (updated, changed),
            ))
        })
        .map_err(CmdError::from)?;
    for tool in &changed {
        audit_or_log(
            db,
            "mcp.tool_definition_changed",
            Some(&started_from.id),
            &format!("server={} tool={}", started_from.name, tool),
        );
    }
    Ok((updated, changed))
}

/// The record a connect (or a call's tool-list refresh) saves after its
/// network round trips, and the enabled tools whose definition changed. The
/// fetched tools are merged into the record AS STORED NOW - read in the same
/// transaction as the write ([`store_fetched_tools`]) - not into the
/// snapshot the connect started from, so a tool toggled or a name edited
/// during a slow connect is not reverted (A7-49). Nothing is saved when the
/// server was removed meanwhile, or its URL or auth settings changed: the
/// tools came from the old configuration.
fn merge_into_stored(
    started_from: &crate::db::McpServerRecord,
    stored_now: Option<crate::db::McpServerRecord>,
    fetched: &[Value],
) -> CmdResult<(crate::db::McpServerRecord, Vec<String>)> {
    let Some(mut now) = stored_now else {
        return Err(CmdError(SERVER_REMOVED_MEANWHILE.into()));
    };
    if !same_connection(started_from, &now) {
        return Err(CmdError(SETTINGS_CHANGED_MEANWHILE.into()));
    }
    let changed = changed_enabled_tools(&now.tools, fetched);
    now.tools = merge_tools(&now.tools, fetched);
    now.updated_at = chrono::Utc::now();
    Ok((now, changed))
}

/// Whether two snapshots of a server record send the same requests: the
/// same URL and the same auth configuration ([`ConnectionBinding`]).
fn same_connection(a: &crate::db::McpServerRecord, b: &crate::db::McpServerRecord) -> bool {
    ConnectionBinding::of(a) == ConnectionBinding::of(b)
}

/// Why the server `set_up` describes may no longer be contacted with those
/// settings - removed, its URL or auth changed, or switched off (not
/// confirmed: a "Don't allow", a restore) since - or `None` while it may.
/// Checked against the record as stored right before every request that is
/// not a `tools/call`: every initialize, and again once it is answered -
/// before its session is registered and `notifications/initialized` goes out
/// ([`establish_session`]) -, every tools/list page and a page asked again on
/// a renewed session ([`request_with_session`]), and the refreshes after a
/// call ([`refresh_after_refusal`], [`refresh_after_sent_call`]). A
/// `tools/call` is gated the same way and more ([`regate_call`]). So a change
/// that lands while one of these is out is seen before the next of them, and
/// the session involved is ended where it was set up (one whose initialize
/// was out is never registered). Two kinds of request are NOT checked
/// against the stored record: the -32601 answers to requests the server
/// sends inside a response that is still open ([`read_response`]: at most
/// eight, to the same endpoint within the same exchange, checked against the
/// vault generation only - this check is a blocking database read, kept off
/// that path), and session DELETEs, which only ever end a session.
fn not_contactable(
    db: &crate::db::Database,
    set_up: &crate::db::McpServerRecord,
) -> CmdResult<Option<&'static str>> {
    let stored = db
        .get_mcp_server(&set_up.id)
        .map_err(|e| CmdError(e.to_string()))?;
    Ok(match stored {
        None => Some(SERVER_REMOVED_MEANWHILE),
        Some(stored) if !same_connection(set_up, &stored) => Some(SETTINGS_CHANGED_MEANWHILE),
        Some(stored) if !stored.confirmed => Some(UNCONFIRMED_SERVER),
        Some(_) => None,
    })
}

/// The server answered 404: it no longer knows the session `ctx` holds.
/// Forget it - in the registry too, while it is still the one registered -
/// without a DELETE: there is nothing left to end.
fn forget_lost_session(state: &McpState, ctx: &mut ServerContext) {
    if let Some(lost) = ctx.session.take() {
        let _ = state.take_session_if(&ctx.record.id, |live| live.session == lost);
    }
}

/// Whether a stored tool's live definition differs from the one the user
/// approved: it has a pin, and the latest fetched definition no longer
/// hashes to it. `merge_tools` keeps the old pin when a definition changes,
/// so this stays true - and the settings show "definition changed,
/// re-approve" - until the user re-approves the tool (which pins the new
/// definition) or disables it (which drops the pin). The pin and the current
/// hash are both stored, so the flag is as persistent as the record (R6).
/// If the server later reverts to the approved definition the flag clears
/// but the tool stays disabled - it fails closed, and the user enables it
/// again.
pub fn definition_changed(tool: &crate::db::McpToolRecord) -> bool {
    tool.pin_hash.is_some() && tool.pin_hash != tool.current_hash
}

/// Merge freshly-fetched tool definitions into the stored per-tool state.
/// - New tools: disabled, no pin (default-deny).
/// - Known tools: current_hash updated; a tool whose definition no longer
///   matches its pin is DISABLED and loses Auto-approve, and keeps its old
///   pin so [`definition_changed`] reports it (definition rug-pull, A4-05 /
///   A7-29 - the caller audits it via `changed_enabled_tools`). Re-enabling
///   must be a fresh approval of the NEW definition, never the old
///   Auto-approve carried over to it.
/// - Tools the server no longer lists are dropped.
/// - `input_schema` is the clamped canonical JSON of the definition's
///   inputSchema (object-only, byte-capped). The pin hash still hashes the
///   FULL definition, so a schema too big to store still counts as a
///   definition the model must not see unreviewed.
pub fn merge_tools(
    stored: &[crate::db::McpToolRecord],
    fetched: &[Value],
) -> Vec<crate::db::McpToolRecord> {
    fetched
        .iter()
        .filter_map(|def| {
            let name = def.get("name").and_then(|n| n.as_str())?;
            let hash = tool_definition_hash(def);
            let prev = stored.iter().find(|t| t.name == name);
            let (enabled, auto_approve, pin_hash) = match prev {
                Some(p) if p.pin_hash.as_deref() == Some(hash.as_str()) => {
                    (p.enabled, p.auto_approve, p.pin_hash.clone())
                }
                // Definition changed (or never pinned): disabled, without
                // Auto-approve, pending re-approval; the old pin stays.
                Some(p) => (false, false, p.pin_hash.clone()),
                None => (false, false, None),
            };
            Some(crate::db::McpToolRecord {
                name: name.to_string(),
                display_name: def.get("title").and_then(|t| t.as_str()).map(String::from),
                description: truncate_description(
                    def.get("description")
                        .and_then(|d| d.as_str())
                        .unwrap_or(""),
                ),
                enabled,
                auto_approve,
                pin_hash,
                current_hash: Some(hash),
                input_schema: clamp_input_schema(def),
                annotations: def.get("annotations").cloned(),
            })
        })
        .collect()
}

/// Names of tools that were enabled before a fetch and came back with a
/// different definition hash (the rug-pull audit set).
pub fn changed_enabled_tools(
    stored: &[crate::db::McpToolRecord],
    fetched: &[Value],
) -> Vec<String> {
    fetched
        .iter()
        .filter_map(|def| {
            let name = def.get("name").and_then(|n| n.as_str())?;
            let prev = stored.iter().find(|t| t.name == name)?;
            let new_hash = tool_definition_hash(def);
            if prev.enabled && prev.pin_hash.as_deref() != Some(new_hash.as_str()) {
                Some(name.to_string())
            } else {
                None
            }
        })
        .collect()
}

// ─── Teardown on vault lock ─────────────────────────────────────────────────

/// Send the HTTP DELETE that ends a session, with the static auth header
/// attached (the server may require it even for DELETE). The header is
/// resolved first ([`TeardownAuth::resolve`]). Only 405 ("method not
/// allowed" - valid per spec for servers that manage sessions differently) is
/// ignored; a 401 means the session tear-down was refused, and any transport
/// failure is reported - never silently swallowed, and never retried with
/// secrets.
async fn delete_session(
    client: &reqwest::Client,
    url: &str,
    session_id: &str,
    protocol_version: &str,
    auth: Option<(&str, &Zeroizing<String>)>,
    server_label: &str,
) -> Result<(), String> {
    let mut req = client
        .delete(url)
        .header("Mcp-Session-Id", session_id)
        .header("MCP-Protocol-Version", protocol_version)
        .header("Accept", "application/json, text/event-stream");
    if let Some((name, value)) = auth {
        req = req.header(name, value.as_str());
    }
    let resp = req
        .send()
        .await
        .map_err(|e| format!("MCP session teardown for '{server_label}' failed: {e}"))?;
    let status = resp.status();
    if status.as_u16() == 405 {
        // The server does not accept DELETE for sessions - valid per spec.
        return Ok(());
    }
    if !status.is_success() {
        return Err(format!(
            "MCP server '{server_label}' refused session teardown with HTTP {}.",
            status.as_u16()
        ));
    }
    Ok(())
}

/// One pending session teardown: everything the DELETE needs.
struct TeardownJob {
    url: String,
    session_id: String,
    protocol_version: String,
    auth: TeardownAuth,
    server_name: String,
}

/// Where the auth header of a session teardown comes from.
enum TeardownAuth {
    /// Resolved already (`None`: the session's settings send none) - by the
    /// request that set the session up, say.
    Resolved(Option<(String, Zeroizing<String>)>),
    /// Resolved by the teardown itself, on the blocking pool, from the
    /// settings the session was set up with and `password` - a copy of the
    /// vault password taken while it was still there (before a lock cleared
    /// it). A stored secret is an Argon2id derivation to unseal (about 0.75 s
    /// in a release build): it must not run on the thread that ends the
    /// session, which for a lock is the main thread.
    Unseal {
        binding: ConnectionBinding,
        password: Option<std::sync::Arc<Zeroizing<String>>>,
    },
}

/// How many teardowns unseal their credential at once. Each unseal is an
/// Argon2id derivation holding 64 MiB: a lock (or an exit) with many live
/// sessions ran them all at once. Four keeps that bounded while changing
/// nothing for up to four sessions - about what the exit's 2 s budget fits
/// in a release build (about 0.75 s per unseal); past that, the sessions the
/// budget cuts off expire on their servers.
const MAX_PARALLEL_UNSEALS: usize = 4;

/// The permits for [`MAX_PARALLEL_UNSEALS`], shared by every teardown.
fn unseal_permits() -> &'static tokio::sync::Semaphore {
    static PERMITS: std::sync::OnceLock<tokio::sync::Semaphore> = std::sync::OnceLock::new();
    PERMITS.get_or_init(|| tokio::sync::Semaphore::new(MAX_PARALLEL_UNSEALS))
}

/// Unseals running now, and the most seen at once (tests only).
#[cfg(test)]
static UNSEALS_RUNNING: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
static UNSEALS_PEAK: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Counts one unseal while alive (tests only).
#[cfg(test)]
struct UnsealRunning;

#[cfg(test)]
impl UnsealRunning {
    fn enter() -> Self {
        use std::sync::atomic::Ordering::SeqCst;
        let now = UNSEALS_RUNNING.fetch_add(1, SeqCst) + 1;
        UNSEALS_PEAK.fetch_max(now, SeqCst);
        Self
    }
}

#[cfg(test)]
impl Drop for UnsealRunning {
    fn drop(&mut self) {
        UNSEALS_RUNNING.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

impl TeardownAuth {
    /// The header the DELETE carries. Every copy of the password this held
    /// is gone when it returns: the shared copy is released as soon as the
    /// header is resolved - before the DELETE goes out - and is wiped when
    /// the last teardown that shares it has resolved its own.
    async fn resolve(self) -> Option<(String, Zeroizing<String>)> {
        match self {
            Self::Resolved(auth) => auth,
            Self::Unseal {
                binding,
                password: Some(password),
            } => {
                // Waits (without holding a thread) for one of the
                // MAX_PARALLEL_UNSEALS permits; the semaphore is never
                // closed, so `acquire` cannot fail.
                let _permit = unseal_permits().acquire().await.ok();
                crate::commands::spawn_on_pool(move || {
                    #[cfg(test)]
                    let _running = UnsealRunning::enter();
                    let header = binding.auth_header(&password);
                    drop(password);
                    header
                })
                .await
                .ok()
                .flatten()
            }
            // Locked: no secret can be unsealed.
            Self::Unseal { password: None, .. } => None,
        }
    }
}

/// The DELETE that ends `live` where it was set up: at the URL of its
/// settings, with their credential (unsealed by the teardown from
/// `password`) - never at a server record's current settings, which an edit
/// may have pointed at another endpoint since. A session registered without
/// its settings (the integration tests' [`McpState::set_session`]) is ended
/// at `fallback`'s. `None` when there is no session id to end, no settings,
/// or the URL no longer parses.
fn session_end(
    live: LiveSession,
    fallback: Option<&crate::db::McpServerRecord>,
    password: Option<std::sync::Arc<Zeroizing<String>>>,
) -> Option<TeardownJob> {
    let binding = live
        .binding
        .or_else(|| fallback.map(ConnectionBinding::of))?;
    let session_id = live.session.session_id?;
    let (url, _) = classify_url(&binding.url).ok()?;
    // Settings without auth need no password: the copy is not passed on.
    let password = password.filter(|_| binding.auth_type != "none");
    Some(TeardownJob {
        url,
        session_id,
        protocol_version: live.session.protocol_version,
        auth: TeardownAuth::Unseal { binding, password },
        server_name: live.server_name,
    })
}

/// The DELETE that ends `live` - set up with the settings a context in hand
/// has - at that context's `url`, with the `auth` header it resolved
/// already: nothing to unseal, no password copy. `None` when there is no
/// session id to end.
fn session_end_resolved(
    live: LiveSession,
    url: &str,
    auth: Option<(String, Zeroizing<String>)>,
) -> Option<TeardownJob> {
    Some(TeardownJob {
        url: url.to_string(),
        session_id: live.session.session_id?,
        protocol_version: live.session.protocol_version,
        auth: TeardownAuth::Resolved(auth),
        server_name: live.server_name,
    })
}

/// Tear down every live MCP session. Called from `lock_vault_internal`
/// AFTER the generation bump but BEFORE the password store clears. The lock
/// path itself never waits for a server or for a secret: the in-memory
/// session map is drained at once (no new request can use a session), a copy
/// of the vault password is taken while it is still there, and each session
/// is ended by a task of its own on the Tauri async runtime
/// ([`end_sessions`]).
pub fn teardown_all(app: &AppHandle) {
    let state = app.state::<McpState>();
    let sessions = state.take_sessions();
    state.clear_statuses();
    // Replaced sessions still waiting for their last request: a lock ends
    // them now (their requests abort at their next generation check).
    state.start_deferred_ends();
    // The shared copy of the password, taken BEFORE the lock clears the
    // store.
    let password = vault_password(app)
        .ok()
        .filter(|pw| !pw.is_empty())
        .map(|pw| state.shared_password(&pw));
    end_sessions(
        state.inner(),
        app.state::<crate::AppState>().db.clone(),
        password,
        sessions,
    );
}

/// End `sessions` - one teardown task each ([`spawn_teardown_jobs`]), kept in
/// `state` until it finishes so an exit can wait for it - each where it was
/// set up ([`session_end`]), its header resolved by its own task from
/// `password` ([`TeardownAuth::Unseal`]). Returns at once.
///
/// The lock path used to unseal every live session's secret before it
/// returned - one Argon2id derivation per session, on the main thread for
/// the Lock button, the tray's Lock and the exit - so two connected servers
/// froze the window for about 1.5 s, and an exit spent that before its 2 s
/// wait for the DELETEs even began. Each session also used to be ended at
/// its record's CURRENT settings, which an edit may have pointed at another
/// endpoint since.
fn end_sessions(
    state: &McpState,
    db: crate::db::Database,
    password: Option<std::sync::Arc<Zeroizing<String>>>,
    sessions: Vec<(String, LiveSession)>,
) {
    let Ok(client) = origin_client() else {
        return;
    };
    let jobs: Vec<TeardownJob> = sessions
        .into_iter()
        .filter_map(|(server_id, live)| {
            // Only a session registered without its settings needs the
            // record (a test seam); the app binds every session it sets up.
            let fallback = match live.binding {
                Some(_) => None,
                None => db.get_mcp_server(&server_id).ok().flatten(),
            };
            session_end(live, fallback.as_ref(), password.clone())
        })
        .collect();
    // This copy goes now; the teardowns hold theirs until resolved.
    drop(password);
    state.start_teardowns(db, client, jobs);
}

/// End one session: resolve its header, then send the DELETE.
async fn run_teardown(client: &reqwest::Client, job: TeardownJob) -> Result<(), String> {
    let TeardownJob {
        url,
        session_id,
        protocol_version,
        auth,
        server_name,
    } = job;
    let auth = auth.resolve().await;
    delete_session(
        client,
        &url,
        &session_id,
        &protocol_version,
        auth.as_ref().map(|(n, v)| (n.as_str(), v)),
        &server_name,
    )
    .await
}

/// Start each session teardown as its own task on the Tauri runtime and hand
/// back the handles. One task per session: a hung server neither delays the
/// other DELETEs nor holds an exit beyond its budget (they used to run one
/// after another in a single detached task, so one hung server kept the rest
/// from ever being sent). A refused or failed DELETE (other than 405) is
/// audited - a refused teardown must not disappear silently.
fn spawn_teardown_jobs(
    db: crate::db::Database,
    client: reqwest::Client,
    jobs: Vec<TeardownJob>,
) -> Vec<tauri::async_runtime::JoinHandle<()>> {
    jobs.into_iter()
        .map(|job| {
            let (db, client) = (db.clone(), client.clone());
            tauri::async_runtime::spawn(async move {
                if let Err(e) = run_teardown(&client, job).await {
                    audit_or_log(&db, "mcp.session_teardown_failed", None, &e);
                }
            })
        })
        .collect()
}

/// Wait for session teardown tasks ([`McpState::take_teardowns`]), `budget`
/// in total at most - the exit waits here and must never hang on a server.
/// True when all of them finished in time; the rest are left to run until
/// the process ends.
pub async fn wait_for_teardowns(
    handles: Vec<tauri::async_runtime::JoinHandle<()>>,
    budget: Duration,
) -> bool {
    tokio::time::timeout(budget, async {
        for handle in handles {
            // A task that panicked is finished too.
            let _ = handle.await;
        }
    })
    .await
    .is_ok()
}

// ─── Result shaping (pure, unit-tested) ─────────────────────────────────────

/// Shape a tools/call result into the single string the renderer wraps:
/// - text content passes through (blocks joined by newlines);
/// - structuredContent is serialized as JSON text;
/// - an embedded resource with a text field passes through as text;
/// - image/audio/other binary becomes a type-specific placeholder;
/// - isError is surfaced to the caller separately.
pub fn shape_tool_result(result: &Value) -> (String, bool) {
    let is_error = result
        .get("isError")
        .and_then(|e| e.as_bool())
        .unwrap_or(false);
    let mut parts: Vec<String> = Vec::new();
    if let Some(content) = result.get("content").and_then(|c| c.as_array()) {
        for block in content {
            match block.get("type").and_then(|t| t.as_str()) {
                Some("text") => {
                    if let Some(t) = block.get("text").and_then(|t| t.as_str()) {
                        parts.push(t.to_string());
                    }
                }
                Some("resource") => {
                    let resource = block.get("resource");
                    if let Some(text) = resource
                        .and_then(|r| r.get("text"))
                        .and_then(|t| t.as_str())
                    {
                        parts.push(text.to_string());
                    } else {
                        parts.push("[binary resource omitted]".to_string());
                    }
                }
                Some("image") => parts.push("[image omitted]".to_string()),
                Some("audio") => parts.push("[audio omitted]".to_string()),
                _ => parts.push("[binary resource omitted]".to_string()),
            }
        }
    }
    if let Some(sc) = result.get("structuredContent") {
        if !sc.is_null() {
            parts.push(sc.to_string());
        }
    }
    (parts.join("\n"), is_error)
}

/// SHA-256 hex of the arguments JSON (for the audit log - the arguments
/// themselves are never audited).
fn arguments_fingerprint(arguments_json: &str) -> String {
    hex::encode(Sha256::digest(arguments_json.as_bytes()))
}

// ─── Commands ───────────────────────────────────────────────────────────────

/// The safe substitute schema when a tool has no stored input schema (the
/// server sent none, a non-object, or one above the byte cap): an object
/// with no properties, as canonical JSON text. The renderer's schema
/// validation requires an object, so this keeps the model tool list
/// buildable for every stored tool.
fn empty_object_schema() -> String {
    "{\"type\":\"object\"}".to_string()
}

fn tool_view(server_name: &str, tool: &crate::db::McpToolRecord) -> Value {
    json!({
        "name": tool.name,
        "display_name": tool.display_name,
        "description": tool.description,
        "enabled": tool.enabled,
        "auto_approve": tool.auto_approve,
        "pinned": tool.pin_hash.is_some(),
        // The server changed this tool after the user approved it: show the
        // re-approve notice (R6). Cleared by re-approving or disabling it.
        "definition_changed": definition_changed(tool),
        // The definition this view shows; enabling sends it back as
        // `expected_hash`, so only the reviewed definition is approved.
        "definition_hash": tool.current_hash,
        // Bounded, object-only schema; never absent so renderer validation
        // cannot break on any stored tool.
        // Renderer-facing JSON follows MCP's camelCase schema field name.
        "inputSchema": tool.input_schema.clone().unwrap_or_else(empty_object_schema),
        // The canonical model-facing name, computed with the SAME function
        // the enable gate uses - the renderer derives it identically.
        "exposed_name": exposed_tool_name(server_name, &tool.name),
        "annotations": tool.annotations,
    })
}

#[tauri::command]
pub fn mcp_list_servers(app: AppHandle) -> CmdResult<Value> {
    let db = &app.state::<crate::AppState>().db;
    let state = app.state::<McpState>();
    let records = db.list_mcp_servers().map_err(|e| e.to_string())?;
    // Listing NEVER fails on over-cap or collision state - the settings UI
    // must stay usable to FIX such state. The exposure gates live in
    // mcp_set_tool_state (enable-time collision check + aggregate cap), and
    // the renderer's built-ins-first merge only fills leftover slots, so
    // neither an over-cap nor an ambiguous registry can break the model's
    // tool list.
    let servers: Vec<Value> = records
        .iter()
        .map(|r| {
            server_view(
                r,
                state.status_of(&r.id),
                state.session_for(r).map(|s| s.protocol_version),
            )
        })
        .collect();
    Ok(Value::Array(servers))
}

/// One row of `mcp_list_servers`: everything the edit form needs to
/// round-trip a server's settings (A4-07 / A7-30) - the custom header name,
/// the environment variable's NAME (never its value) and whether a sealed
/// secret is stored (never the secret) - plus the protocol version the live
/// session negotiated (`null` when not connected).
fn server_view(
    r: &crate::db::McpServerRecord,
    status: String,
    protocol_version: Option<String>,
) -> Value {
    let insecure = matches!(classify_url(&r.url), Ok((_, UrlClass::LoopbackInsecure)));
    let enabled = r.tools.iter().filter(|t| t.enabled).count();
    json!({
        "id": r.id,
        "name": r.name,
        "url": r.url,
        "auth_type": r.auth_type,
        "auth_header_name": r.auth_header_name,
        "auth_env_var": r.auth_env_var,
        "has_secret": r.auth_secret.is_some(),
        "protocol_version": protocol_version,
        "confirmed": r.confirmed,
        "loopback_insecure": insecure,
        "status": status,
        "tool_count": enabled,
        "tools": r.tools.iter().map(|t| tool_view(&r.name, t)).collect::<Vec<_>>(),
    })
}

/// The enable-time collision check: given the FULL registry with the
/// candidate enable already applied, run the name/collision authority over
/// the enabled tools. `Some(err)` means enabling must be refused - the
/// model-facing name set would be ambiguous (two tools behind one name
/// means one approval could cover the other). Pure over records.
pub fn enable_collision_error(records: &[crate::db::McpServerRecord]) -> Option<String> {
    let registry: Vec<(String, String, Vec<String>)> = records
        .iter()
        .filter(|r| r.tools.iter().any(|t| t.enabled))
        .map(|r| {
            (
                r.id.clone(),
                r.name.clone(),
                r.tools
                    .iter()
                    .filter(|t| t.enabled)
                    .map(|t| t.name.clone())
                    .collect(),
            )
        })
        .collect();
    build_name_map(&registry).err()
}

/// Save (add or edit) an MCP server. Async, with the work on the blocking
/// pool (A5-12): a new secret is sealed with Argon2id, and as a synchronous
/// command that ran on the main thread and froze the window; the
/// transactional write may also wait for another connection's write. When
/// the URL or the auth settings changed, the live session is dropped once
/// the save has committed, and ended at the OLD endpoint with the OLD
/// credential in the background ([`session_end`]).
///
/// A save that binds a credential to a place it was not bound to before is
/// stored switched off (`confirmed: false`) and then asked about in a native
/// dialog, on the blocking pool ([`settle_binding`]); the answer says whether
/// the server is `confirmed` and, when it is not, why (`warning`).
#[tauri::command(rename_all = "snake_case")]
pub async fn mcp_save_server(
    app: AppHandle,
    id: Option<String>,
    name: String,
    url: String,
    auth_type: String,
    auth_header_name: Option<String>,
    auth_secret: Option<String>,
    auth_env_var: Option<String>,
) -> CmdResult<Value> {
    // The vault as the save finds it: an "Allow" given after a lock (the
    // question can stay open for as long as the user likes) counts for
    // nothing.
    let generation = capture_vault_generation(&app)?;
    let worker = app.clone();
    let mut saved = crate::commands::run_blocking(move || {
        // Seals the auth secret and rewrites the whole record: not while a
        // master-password change is re-encrypting the vault.
        let _rotation = crate::commands::rotation_shared(&worker)?;
        save_server(
            &worker.state::<crate::AppState>().db,
            worker.state::<McpState>().inner(),
            worker.state::<VaultPasswordStore>().inner(),
            SaveServerArgs {
                id,
                name,
                url,
                auth_type,
                auth_header_name,
                auth_secret,
                auth_env_var,
            },
        )
    })
    .await?;
    if let Some(job) = saved.teardown.take() {
        // Best effort and not awaited: the save is done, and the old server
        // may well be the unreachable one the user is moving away from. A
        // failure is audited (`mcp.session_teardown_failed`); an exit waits
        // for it like for the lock path's teardowns. Started before the
        // question below, which can stay open for as long as the user likes.
        match origin_client() {
            Ok(client) => {
                let db = app.state::<crate::AppState>().db.clone();
                app.state::<McpState>()
                    .start_teardowns(db, client, vec![job]);
            }
            Err(e) => log::warn!("[sshspan-mcp] could not end a stale MCP session: {e}"),
        }
    }
    if let Some(pending) = saved.pending.take() {
        let worker = app.clone();
        let outcome = crate::commands::run_blocking(move || {
            let at_save = VaultAtSave {
                vault: worker.state::<VaultPasswordStore>().inner(),
                generations: worker.state::<crate::commands::VaultGeneration>().inner(),
                generation,
            };
            Ok(settle_binding(
                &worker.state::<crate::AppState>().db,
                worker.state::<VaultRotationLock>().inner(),
                worker
                    .state::<crate::commands::CredentialQuestions>()
                    .inner(),
                &at_save,
                pending,
                &|prompt| crate::commands::ask_native_confirmation(&worker, prompt),
            ))
        })
        .await?;
        apply_outcome(&mut saved.view, outcome);
    }
    Ok(saved.view)
}

/// What [`save_server`] did: the command's answer, the teardown of the live
/// session the save made stale, and the credential binding the user still
/// has to allow.
struct SavedServer {
    view: Value,
    teardown: Option<TeardownJob>,
    pending: Option<PendingBinding>,
}

/// A record [`save_server`] stored UNCONFIRMED because it binds a credential
/// to a place it was not bound to before, and the question to ask about it
/// ([`settle_binding`]).
#[derive(Debug)]
struct PendingBinding {
    id: String,
    /// The settings the user is asked about: confirmed only while the record
    /// still has exactly these.
    binding: ConnectionBinding,
    prompt: CredentialPrompt,
    /// Where it sends what, for the audit row: no secret, no value.
    detail: String,
    host: String,
}

/// How the question about a [`PendingBinding`] ended.
#[derive(Debug, PartialEq, Eq)]
struct BindingOutcome {
    confirmed: bool,
    warning: Option<String>,
}

/// Whether saving `record` over `previous` (the record as stored, `None`
/// for a new server) binds a credential to a place it was not bound to
/// before - which the user must allow in a native dialog before anything is
/// sent ([`settle_binding`]). A secret or a variable whose value the
/// renderer cannot see would otherwise go to any https address a renderer
/// names: the save used to mark every record confirmed.
///
/// Asked: a new server with a secret or a variable; a record that sends a
/// credential where it sent none, or one that was not confirmed (restored
/// from a backup, or not allowed); another address keeping a variable; a
/// variable that was not the one sent there before. Not asked: no auth, a
/// rename, the same variable again, a new secret for the address already
/// confirmed (its value is the one just typed, for the same place).
fn binding_needs_confirmation(
    previous: Option<&crate::db::McpServerRecord>,
    record: &crate::db::McpServerRecord,
) -> bool {
    let sends_credential = |r: &crate::db::McpServerRecord| {
        r.auth_type != "none" && (r.auth_secret.is_some() || r.auth_env_var.is_some())
    };
    if !sends_credential(record) {
        return false;
    }
    let Some(previous) = previous.filter(|p| p.confirmed && sends_credential(p)) else {
        return true;
    };
    if previous.url != record.url {
        return true;
    }
    match &record.auth_env_var {
        Some(var) => previous.auth_env_var.as_ref() != Some(var),
        None => false,
    }
}

/// The question for `record`, which binds a credential to a new place
/// ([`binding_needs_confirmation`]): what is sent - the value of the named
/// environment variable, or the secret saved for the server - to which host,
/// in which header, and the full address. The audit detail names the same,
/// never a value.
fn pending_binding(record: &crate::db::McpServerRecord) -> PendingBinding {
    // Every value is checked when it is saved; quoted cleaned and capped all
    // the same ([`crate::commands::dialog_text`]).
    let quote = |text: &str, max: usize| crate::commands::dialog_text(text, max);
    let host = url::Url::parse(&record.url)
        .map(|u| crate::commands::host_label(&u))
        .unwrap_or_else(|_| record.url.clone());
    let host = quote(&host, 120);
    let header = match (
        record.auth_type.as_str(),
        record.auth_header_name.as_deref(),
    ) {
        ("custom_header", Some(name)) => format!("the {} header", quote(name, 128)),
        _ => "an Authorization header".to_string(),
    };
    let (what, sends) = match &record.auth_env_var {
        Some(var) => (
            format!("the value of the environment variable {}", quote(var, 128)),
            format!("env:{}", quote(var, 128)),
        ),
        None => (
            "the secret saved for this MCP server".to_string(),
            "secret".to_string(),
        ),
    };
    let name = quote(&record.name, 128);
    PendingBinding {
        id: record.id.clone(),
        binding: ConnectionBinding::of(record),
        prompt: CredentialPrompt {
            title: "SSHSpan - Send a credential?".to_string(),
            message: format!(
                "SSHSpan will send {what} to {host} as {header}. Allow?\n\n\
                 MCP server: {name}\nAddress: {}",
                quote(&record.url, 200)
            ),
        },
        detail: format!("server={name} host={host} sends={sends}"),
        host,
    }
}

/// What a confirmation says when the server was removed while the dialog
/// was open.
const SERVER_GONE_WHILE_ASKED: &str = "The server was removed while you were deciding.";

/// What a confirmation says when the server's address or credential changed
/// while the dialog was open: the answer was about other settings.
const BINDING_MOVED_WHILE_ASKED: &str = "The server was saved, but its address or credential changed while you were deciding, so it stays switched off. Save it again to confirm it.";

/// What a save that would ask says while another credential question is
/// still open ([`crate::commands::CredentialQuestions`]).
const BINDING_QUESTION_OPEN: &str = "The server was saved but stays switched off, because another question about sending a credential was still open. Answer it, then save this server again.";

/// What a confirmation says when the vault was locked while the dialog was
/// open: an answer given to a locked vault counts for nothing.
const LOCKED_WHILE_ASKED: &str = "The server was saved but stays switched off, because the vault was locked while you were deciding. Unlock it and save the server again.";

/// What a confirmation says when it could not be written.
const BINDING_NOT_STORED: &str = "The server was saved but stays switched off, because confirming it could not be stored. Save it again to be asked again.";

/// What a save says while the last question about sending a credential, to
/// `host`, was answered "Don't allow" or "Cancel" less than
/// [`crate::commands::CREDENTIAL_DECLINE_BACKOFF`] ago, whatever server or
/// address is saved now: nothing is asked.
fn binding_declined_lately(host: &str) -> String {
    format!(
        "The server was saved but stays switched off, because sending a credential to {host} was declined a moment ago. Wait 30 seconds, then save it again."
    )
}

/// Ask about `pending` - in production the native dialog, on the blocking
/// pool - and, when allowed, confirm the record ([`confirm_binding`]). A
/// "no", or an "Allow" sooner than a second after the question opened,
/// leaves it saved but switched off (connect and call refuse it, as for a
/// restored record) until a later save is allowed, and switches it off again
/// if an earlier "Allow" confirmed these settings meanwhile
/// ([`decline_binding`]).
/// Both answers are audited (`mcp.credential_allowed` /
/// `mcp.credential_declined`) with the host and what is sent, never a value.
///
/// One question at a time (`questions`): while another one is open, this
/// save is not asked about and stays off. The turn lasts until the answer
/// is written, so answers are written in the order the questions were asked.
fn settle_binding(
    db: &crate::db::Database,
    rotation: &VaultRotationLock,
    questions: &crate::commands::CredentialQuestions,
    at_save: &VaultAtSave<'_>,
    pending: PendingBinding,
    ask: ConfirmCredential<'_>,
) -> BindingOutcome {
    let Some(_turn) = questions.begin() else {
        return BindingOutcome {
            confirmed: false,
            warning: Some(BINDING_QUESTION_OPEN.into()),
        };
    };
    // After "Don't allow" or "Cancel", no credential question is asked for
    // 30 seconds ([`crate::commands::CREDENTIAL_DECLINE_BACKOFF`]), whatever
    // server or address it names; the answer names the host declined.
    let kind = crate::commands::QuestionKind::McpCredential;
    if let Some(declined) = questions.declined_lately(kind) {
        return BindingOutcome {
            confirmed: false,
            warning: Some(binding_declined_lately(&declined)),
        };
    }
    let answer = ask(&pending.prompt);
    if answer == CredentialAnswer::NotAllowed {
        questions.record_decline(kind, &pending.host);
    }
    if answer != CredentialAnswer::Allowed {
        decline_binding(db, rotation, &pending);
        let detail = match answer {
            CredentialAnswer::TooQuick => format!("{} answered=too-quickly", pending.detail),
            _ => pending.detail.clone(),
        };
        audit_or_log(db, "mcp.credential_declined", Some(&pending.id), &detail);
        let warning = match answer {
            CredentialAnswer::TooQuick => format!(
                "The server was saved but stays switched off, because the question about sending its credential to {} was answered within a second of opening - too fast to be a decision. Save it again to be asked again.",
                pending.host
            ),
            _ => format!(
                "The server was saved but stays switched off, because sending its credential to {} was not allowed. Save it again to be asked again.",
                pending.host
            ),
        };
        return BindingOutcome {
            confirmed: false,
            warning: Some(warning),
        };
    }
    match confirm_binding(db, rotation, at_save, &pending) {
        Ok(()) => {
            audit_or_log(
                db,
                "mcp.credential_allowed",
                Some(&pending.id),
                &pending.detail,
            );
            BindingOutcome {
                confirmed: true,
                warning: None,
            }
        }
        Err(warning) => BindingOutcome {
            confirmed: false,
            warning: Some(warning),
        },
    }
}

/// Mark the record of `pending` confirmed - only while it still has exactly
/// the settings the user allowed, compared and written in one transaction -
/// only while the vault is still unlocked in the generation of the save (an
/// "Allow" given to a locked vault counts for nothing), and not while a
/// master-password change runs (the write replaces the whole record). Why it
/// was not confirmed comes back as the warning to show - in plain words: a
/// database error is logged, not shown.
fn confirm_binding(
    db: &crate::db::Database,
    rotation: &VaultRotationLock,
    at_save: &VaultAtSave<'_>,
    pending: &PendingBinding,
) -> Result<(), String> {
    let _rotation = rotation.try_shared().map_err(|_| {
        "The server was saved but stays switched off, because the vault was being re-encrypted. Save it again when that has finished.".to_string()
    })?;
    if !at_save.unchanged() {
        return Err(LOCKED_WHILE_ASKED.into());
    }
    db.modify_mcp_servers(|all| {
        // Again inside the transaction: a lock that landed meanwhile.
        if !at_save.unchanged() {
            return Err(CmdError(LOCKED_WHILE_ASKED.into()).into());
        }
        let mut record = all
            .iter()
            .find(|r| r.id == pending.id)
            .cloned()
            .ok_or_else(|| CmdError(SERVER_GONE_WHILE_ASKED.into()))?;
        if ConnectionBinding::of(&record) != pending.binding {
            return Err(CmdError(BINDING_MOVED_WHILE_ASKED.into()).into());
        }
        record.confirmed = true;
        Ok((crate::db::McpWrite::Update(record), ()))
    })
    .map_err(|e| {
        let text = e.to_string();
        if [
            SERVER_GONE_WHILE_ASKED,
            BINDING_MOVED_WHILE_ASKED,
            LOCKED_WHILE_ASKED,
        ]
        .contains(&text.as_str())
        {
            text
        } else {
            log::warn!("[sshspan-mcp] could not store a credential confirmation: {text}");
            BINDING_NOT_STORED.to_string()
        }
    })
}

/// [`decline_binding`]'s transaction when there is nothing to switch off.
const NOTHING_TO_SWITCH_OFF: &str = "nothing to switch off";

/// A "no" to `pending` - or an "Allow" too soon after the question opened:
/// the record stays switched off, and is switched off again if an earlier
/// "Allow" confirmed these very settings after this save had stored them.
/// The questions are answered one at a time and in order, so the later "no"
/// stands. Settings saved since are left alone - they are not confirmed
/// until their own question allows them. Nothing is written while a
/// master-password change runs (the write replaces the whole record), and a
/// failure is logged: the save stored the record switched off already.
fn decline_binding(
    db: &crate::db::Database,
    rotation: &VaultRotationLock,
    pending: &PendingBinding,
) {
    let Ok(_rotation) = rotation.try_shared() else {
        log::warn!(
            "[sshspan-mcp] a declined credential binding was not written: the vault is being re-encrypted"
        );
        return;
    };
    let switched = db.modify_mcp_servers(|all| {
        let mut record = all
            .iter()
            .find(|r| r.id == pending.id && r.confirmed)
            .filter(|r| ConnectionBinding::of(r) == pending.binding)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!(NOTHING_TO_SWITCH_OFF))?;
        record.confirmed = false;
        Ok((crate::db::McpWrite::Update(record), ()))
    });
    if let Err(e) = switched {
        if e.to_string() != NOTHING_TO_SWITCH_OFF {
            log::warn!("[sshspan-mcp] could not store a declined credential binding: {e}");
        }
    }
}

/// The save's answer with the outcome of its question: `confirmed`, and its
/// warning after any the save already had.
fn apply_outcome(view: &mut Value, outcome: BindingOutcome) {
    view["confirmed"] = json!(outcome.confirmed);
    if let Some(note) = outcome.warning {
        let joined = match view["warning"].as_str() {
            Some(earlier) => format!("{earlier} {note}"),
            None => note,
        };
        view["warning"] = json!(joined);
    }
}

/// The arguments of [`mcp_save_server`]. For `auth_header_name`,
/// `auth_secret` and `auth_env_var`, absent (or null) keeps what is stored,
/// an empty string clears it, and anything else replaces it (see
/// [`plan_auth`]).
struct SaveServerArgs {
    id: Option<String>,
    name: String,
    url: String,
    auth_type: String,
    auth_header_name: Option<String>,
    auth_secret: Option<String>,
    auth_env_var: Option<String>,
}

/// How an optional text argument of `mcp_save_server` reads.
#[derive(Debug, Clone, PartialEq, Eq)]
enum TextArg {
    /// Absent or null: keep what is stored.
    Absent,
    /// An empty string: clear it.
    Clear,
    Set(String),
}

impl TextArg {
    fn from_arg(value: Option<&str>) -> Self {
        match value.map(str::trim) {
            None => Self::Absent,
            Some("") => Self::Clear,
            Some(v) => Self::Set(v.to_string()),
        }
    }
}

/// The `auth_secret` argument, read like a [`TextArg`] but without holding
/// on to the plaintext.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SecretArg {
    Absent,
    Clear,
    New,
}

impl SecretArg {
    fn from_arg(value: Option<&str>) -> Self {
        match value.map(str::trim) {
            None => Self::Absent,
            Some("") => Self::Clear,
            Some(_) => Self::New,
        }
    }
}

/// What a save does with the record's sealed secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SecretPlan {
    Keep,
    Drop,
    /// Seal the newly entered secret.
    Seal,
}

/// The auth fields a save leaves on the record.
#[derive(Debug, PartialEq, Eq)]
struct AuthPlan {
    header_name: Option<String>,
    secret: SecretPlan,
    env_var: Option<String>,
}

/// Decide the auth fields `mcp_save_server` stores, from the stored record
/// (`None` for a new server) and the arguments (A4-07 / A7-30). Pure, so the
/// rules are unit-testable:
/// - An absent header name or env-var name keeps the stored one, so an edit
///   that does not touch auth (a rename) keeps it; an empty string clears
///   it. A header name exists only for custom_header (bearer formats
///   Authorization itself); auth "none" clears every source.
/// - Credential ORIGIN BINDING: a credential set up for one origin under one
///   auth semantic never silently survives a change of either. When the
///   URL, the auth type or the custom header name changes, the stored sealed
///   secret is dropped, and so is an env-var binding the save does not name
///   again - its value would otherwise be sent to the new origin unasked.
/// - The source stays exclusive: a new secret replaces an env-var binding,
///   a newly named env var replaces a stored secret.
/// - bearer and custom_header must end up with a source: a server saved
///   without one used to fail only at its first connect.
fn plan_auth(
    stored: Option<&crate::db::McpServerRecord>,
    url: &str,
    auth_type: &str,
    header: TextArg,
    secret: SecretArg,
    env: TextArg,
) -> Result<AuthPlan, String> {
    if auth_type == "none" {
        if matches!(header, TextArg::Set(_))
            || secret == SecretArg::New
            || matches!(env, TextArg::Set(_))
        {
            return Err("Auth type 'none' cannot carry a header, secret or env var.".into());
        }
        return Ok(AuthPlan {
            header_name: None,
            secret: SecretPlan::Drop,
            env_var: None,
        });
    }
    let header_name = if auth_type == "custom_header" {
        let name = match header {
            TextArg::Absent => stored.and_then(|r| r.auth_header_name.clone()),
            TextArg::Clear => None,
            TextArg::Set(name) => Some(name),
        }
        .ok_or_else(|| "Custom header auth requires a header name.".to_string())?;
        validate_header_name(&name)?;
        Some(name)
    } else {
        None
    };
    let rebound = stored.is_some_and(|r| {
        r.url != url
            || r.auth_type != auth_type
            || (auth_type == "custom_header" && r.auth_header_name != header_name)
    });
    let kept_env = || {
        stored
            .filter(|_| !rebound)
            .and_then(|r| r.auth_env_var.clone())
    };
    let kept_secret = if rebound {
        SecretPlan::Drop
    } else {
        SecretPlan::Keep
    };
    let (secret, env_var) = match (secret, env) {
        (SecretArg::New, _) => (SecretPlan::Seal, None),
        (_, TextArg::Set(var)) => (SecretPlan::Drop, Some(var)),
        (SecretArg::Clear, TextArg::Absent) => (SecretPlan::Drop, kept_env()),
        (SecretArg::Clear, TextArg::Clear) => (SecretPlan::Drop, None),
        (SecretArg::Absent, TextArg::Clear) => (kept_secret, None),
        (SecretArg::Absent, TextArg::Absent) => (kept_secret, kept_env()),
    };
    let has_secret = match secret {
        SecretPlan::Seal => true,
        SecretPlan::Keep => stored.is_some_and(|r| r.auth_secret.is_some()),
        SecretPlan::Drop => false,
    };
    if !has_secret && env_var.is_none() {
        let had_source =
            stored.is_some_and(|r| r.auth_secret.is_some() || r.auth_env_var.is_some());
        return Err(if rebound && had_source {
            "Changing the URL or the auth settings discards the stored secret or environment variable - enter it again for the new settings."
                .to_string()
        } else {
            let kind = if auth_type == "bearer" {
                "Bearer"
            } else {
                "Custom header"
            };
            format!("{kind} auth needs a secret or an environment variable name.")
        });
    }
    Ok(AuthPlan {
        header_name,
        secret,
        env_var,
    })
}

/// The other stored server whose name gives the same model-facing tool
/// prefix as `name`, compared case-insensitively (A4-12): two such servers
/// could not be told apart on an Approve card or by the model.
fn name_collision<'a>(
    records: &'a [crate::db::McpServerRecord],
    self_id: Option<&str>,
    name: &str,
) -> Option<&'a crate::db::McpServerRecord> {
    let prefix = sanitize_tool_name_part(name).to_ascii_lowercase();
    records.iter().find(|r| {
        Some(r.id.as_str()) != self_id
            && sanitize_tool_name_part(&r.name).to_ascii_lowercase() == prefix
    })
}

/// [`mcp_save_server`] without the `AppHandle`, so its rules run against a
/// real database in tests. The caller holds the rotation guard.
///
/// The record is read, checked (auth plan, name collisions) and written in
/// ONE transaction ([`crate::db::Database::modify_mcp_servers`], A7-49): a
/// tool toggled while the save ran is kept, and a server removed meanwhile is
/// not re-created. A new secret is sealed BEFORE that transaction (Argon2id
/// must not run while the write lock is held).
///
/// When the save changes the URL or the auth settings, the server's live
/// session belongs to the old ones. It is dropped once the save has
/// committed - it used to be dropped inside the transaction, so a write that
/// then failed left the old settings in place without their session, which
/// was never ended - and the DELETE that ends it at the old endpoint, with
/// the old credential, comes back as `teardown`. A session set
/// up with the NEW settings in the meantime is kept. Until it is dropped, no
/// request for the new settings uses the old session ([`usable_session`]). A
/// failed audit row after the commit is a `warning`, not an error.
fn save_server(
    db: &crate::db::Database,
    state: &McpState,
    vault: &VaultPasswordStore,
    args: SaveServerArgs,
) -> CmdResult<SavedServer> {
    let SaveServerArgs {
        id,
        name,
        url,
        auth_type,
        auth_header_name,
        auth_secret,
        auth_env_var,
    } = args;
    // The secret's plaintext is wiped when this frame ends.
    let auth_secret = auth_secret.map(Zeroizing::new);
    let pw = vault.get().unwrap_or_default();
    if pw.is_empty() {
        return Err("Vault is locked.".into());
    }
    let fields = check_save_fields(&name, &url, &auth_type)?;
    let existing_id = id.filter(|s| !s.is_empty());
    let header_arg = TextArg::from_arg(auth_header_name.as_deref());
    let secret_arg = SecretArg::from_arg(auth_secret.as_deref().map(String::as_str));
    let env_arg = TextArg::from_arg(auth_env_var.as_deref());
    if let TextArg::Set(var) = &env_arg {
        check_env_var_name(var).map_err(CmdError)?;
    }
    let sealed_secret = match secret_arg {
        SecretArg::New => {
            let secret = auth_secret.as_deref().map_or("", |s| s.trim());
            // Argon2id: `mcp_save_server` runs this on the blocking pool.
            Some(crate::commands::seal_on_pool(&pw, secret.as_bytes()).map_err(|e| e.to_string())?)
        }
        SecretArg::Absent | SecretArg::Clear => None,
    };

    let (record, previous) = db
        .modify_mcp_servers(|all| {
            let stored = match existing_id.as_deref() {
                Some(existing) => Some(
                    all.iter()
                        .find(|r| r.id == existing)
                        .cloned()
                        .ok_or_else(|| CmdError("MCP server not found.".into()))?,
                ),
                None => None,
            };
            let plan = plan_auth(
                stored.as_ref(),
                &fields.url,
                &fields.auth_type,
                header_arg,
                secret_arg,
                env_arg,
            )
            .map_err(CmdError)?;
            // The variable's name is shown in the native question: checked
            // whatever its source - typed now, or kept from storage (a
            // restored backup, an older version).
            if let Some(var) = &plan.env_var {
                check_env_var_name(var).map_err(CmdError)?;
            }
            if let Some(other) = name_collision(all, existing_id.as_deref(), &fields.name) {
                return Err(CmdError(format!(
                    "An MCP server named '{}' already exists and '{}' would share its model-facing tool names - choose a different name.",
                    other.name, fields.name
                ))
                .into());
            }
            let record = saved_record(stored.as_ref(), fields, plan, sealed_secret);
            let write = if stored.is_some() {
                crate::db::McpWrite::Update(record.clone())
            } else {
                crate::db::McpWrite::Insert(record.clone())
            };
            Ok((write, (record, stored)))
        })
        .map_err(CmdError::from)?;

    // Committed: a session the new settings made stale is dropped now.
    let teardown = previous
        .as_ref()
        .filter(|old| !same_connection(old, &record))
        .and_then(|old| {
            let stale = state.take_session_if(&old.id, |live| !live.bound_to(&record))?;
            session_end(stale, Some(old), Some(state.shared_password(&pw)))
        });
    let action = if previous.is_some() {
        "mcp.server_updated"
    } else {
        "mcp.server_added"
    };
    let warning = audit_or_warn(
        db,
        action,
        Some(&record.id),
        &record.name,
        "The server was saved, but its audit row could not be written",
    );
    // Stored unconfirmed: the user is asked next (`settle_binding`).
    let pending = (!record.confirmed).then(|| pending_binding(&record));
    Ok(SavedServer {
        view: json!({ "ok": true, "id": record.id, "warning": warning, "confirmed": record.confirmed }),
        teardown,
        pending,
    })
}

/// An environment variable name a save binds: it is shown in the native
/// confirmation dialog ([`pending_binding`]), so it may hold only visible
/// ASCII characters - no line break, space, invisible or text-direction
/// character that could rewrite the question - and no `=`, which no variable
/// name contains; 128 at most.
fn check_env_var_name(name: &str) -> Result<(), String> {
    let plain = !name.is_empty()
        && name.len() <= 128
        && name.chars().all(|c| c.is_ascii_graphic() && c != '=');
    if plain {
        Ok(())
    } else {
        Err("The environment variable name must be 1 to 128 visible ASCII characters, without spaces or '='.".into())
    }
}

/// The name, URL and auth type a save writes, checked: the trimmed name, the
/// normalized URL and the trimmed auth type.
struct SaveFields {
    name: String,
    url: String,
    auth_type: String,
}

/// Check the name, URL and auth type of a save ([`save_server`]).
fn check_save_fields(name: &str, url: &str, auth_type: &str) -> CmdResult<SaveFields> {
    let name = name.trim().to_string();
    // The rule is RFC 7230 token syntax (`is_token`), so say exactly that.
    if !is_token(&name) {
        return Err(
            "Server name must be non-empty and use only letters, digits and ! # $ % & ' * + - . ^ _ ` | ~ (no spaces)."
                .into(),
        );
    }
    let (url, _class) = classify_url(url)?;
    let auth_type = auth_type.trim().to_string();
    if !matches!(auth_type.as_str(), "none" | "bearer" | "custom_header") {
        return Err("Auth type must be 'none', 'bearer' or 'custom_header'.".into());
    }
    Ok(SaveFields {
        name,
        url,
        auth_type,
    })
}

/// The record a save writes: `stored` (a new one for an add) with the checked
/// `fields` and the auth `plan` applied, a new secret already sealed. Saving
/// from the UI confirms the URL and the auth settings - unless the save binds
/// a credential to a place it was not bound to before
/// ([`binding_needs_confirmation`]): then the record is stored unconfirmed
/// and the user is asked in a native dialog. A renderer's save is no
/// stronger than a restored entry, which also becomes connectable only
/// through here.
fn saved_record(
    stored: Option<&crate::db::McpServerRecord>,
    fields: SaveFields,
    plan: AuthPlan,
    sealed_secret: Option<String>,
) -> crate::db::McpServerRecord {
    let now = chrono::Utc::now();
    let mut record = stored
        .cloned()
        .unwrap_or_else(|| crate::db::McpServerRecord {
            id: uuid::Uuid::new_v4().to_string(),
            name: String::new(),
            url: String::new(),
            auth_type: String::new(),
            auth_header_name: None,
            auth_secret: None,
            auth_env_var: None,
            confirmed: false,
            tools: Vec::new(),
            created_at: now,
            updated_at: now,
        });
    record.name = fields.name;
    record.url = fields.url;
    record.auth_type = fields.auth_type;
    record.auth_header_name = plan.header_name;
    record.auth_secret = match plan.secret {
        SecretPlan::Keep => record.auth_secret.take(),
        SecretPlan::Drop => None,
        SecretPlan::Seal => sealed_secret,
    };
    record.auth_env_var = plan.env_var;
    record.confirmed = !binding_needs_confirmation(stored, &record);
    // Belt-and-suspenders on the exclusive-source invariant.
    debug_assert!(
        record.auth_secret.is_none() || record.auth_env_var.is_none(),
        "a stored secret and an env-var binding must never coexist"
    );
    record.updated_at = now;
    record
}

#[tauri::command]
pub async fn mcp_remove_server(app: AppHandle, id: String) -> CmdResult<Value> {
    // Not while a master-password change is re-encrypting the vault:
    // the change re-seals this record's secret in place.
    let _rotation = crate::commands::rotation_shared(&app)?;
    remove_server(
        &app.state::<crate::AppState>().db,
        app.state::<McpState>().inner(),
        app.state::<VaultPasswordStore>().inner(),
        &id,
        REMOVE_TEARDOWN_TIMEOUT,
    )
    .await
}

/// How long removing a server waits for its session DELETE.
pub const REMOVE_TEARDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// [`mcp_remove_server`] without the `AppHandle`, so the integration tests
/// can drive it against a mock server. The caller holds the rotation guard.
///
/// The live session is torn down first, best effort: the DELETE carries the
/// static auth header (resolved while the vault is unlocked) and gets
/// `teardown_timeout`. A refused, failed or timed-out teardown is audited
/// (`mcp.session_teardown_failed`) and returned as `warning`, and the entry
/// is removed all the same - the usual reason to remove a server is that it
/// is gone, and it used to take a 60 s wait and a second click (A4-27 /
/// A7-51). Refused while the vault is locked (A6-08).
#[doc(hidden)]
pub async fn remove_server(
    db: &crate::db::Database,
    state: &McpState,
    vault: &VaultPasswordStore,
    id: &str,
    teardown_timeout: Duration,
) -> CmdResult<Value> {
    if !vault.is_set() {
        return Err("Vault is locked.".into());
    }
    let record = db
        .get_mcp_server(id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| CmdError("MCP server not found.".into()))?;
    let mut warning = None;
    // Ended where it was set up ([`session_end`]): for a session set up with
    // settings an edit has replaced since, not at the record's current URL.
    let password = vault.get().map(std::sync::Arc::new);
    let ending = state
        .take_session(id)
        .and_then(|live| session_end(live, Some(&record), password));
    if let Some(job) = ending {
        let failure = match origin_client() {
            Err(e) => Some(e.0),
            Ok(client) => {
                // Resolved BEFORE the record (and its sealed secret) is
                // deleted, and outside the DELETE's time limit; the value is
                // Zeroizing.
                let auth = job.auth.resolve().await;
                let teardown = delete_session(
                    &client,
                    &job.url,
                    &job.session_id,
                    &job.protocol_version,
                    auth.as_ref().map(|(n, v)| (n.as_str(), v)),
                    &job.server_name,
                );
                match tokio::time::timeout(teardown_timeout, teardown).await {
                    Ok(Ok(())) => None,
                    Ok(Err(e)) => Some(e),
                    Err(_) => Some(format!(
                        "MCP session teardown for '{}' timed out after {} s.",
                        record.name,
                        teardown_timeout.as_secs()
                    )),
                }
            }
        };
        if let Some(e) = failure {
            audit_or_log(db, "mcp.session_teardown_failed", Some(id), &e);
            warning = Some(e);
        }
    }
    db.delete_mcp_server(id).map_err(|e| e.to_string())?;
    // The server is gone: a failed audit row is a warning, not an error.
    if let Some(note) = audit_or_warn(
        db,
        "mcp.server_removed",
        Some(id),
        &record.name,
        "The server was removed, but its audit row could not be written",
    ) {
        warning = Some(match warning {
            Some(teardown) => format!("{teardown} {note}"),
            None => note,
        });
    }
    Ok(json!({ "ok": true, "warning": warning }))
}

#[tauri::command]
pub async fn mcp_test_connection(app: AppHandle, id: String) -> CmdResult<Value> {
    // Before the record is read, held until connect_server has written it
    // back: a master-password change must not commit in between.
    let _rotation = crate::commands::rotation_shared(&app)?;
    let db = &app.state::<crate::AppState>().db;
    let record = db
        .get_mcp_server(&id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| CmdError("MCP server not found.".into()))?;
    let state = app.state::<McpState>();
    let (updated, changed) = connect_server(&app, record)
        .await
        .inspect_err(|e| state.record_status(&id, "error", Some(e.0.clone()), 0))?;
    state.record_status(&id, "connected", None, updated.tools.len());
    Ok(json!({
        "ok": true,
        "tools": updated.tools.iter().map(|t| tool_view(&updated.name, t)).collect::<Vec<_>>(),
        // Enabled tools this connect found changed - now disabled, awaiting
        // re-approval (A7-29); each tool's `definition_changed` says the same.
        "changed": changed,
    }))
}

/// Enable, disable or set Auto-approve on one tool ([`set_tool_state`]).
/// Async, with the work on the blocking pool: its transaction
/// takes the write lock and may wait for another connection's write, which
/// a synchronous command did on the main thread.
#[tauri::command(rename_all = "snake_case")]
pub async fn mcp_set_tool_state(
    app: AppHandle,
    id: String,
    tool: String,
    enabled: bool,
    auto_approve: bool,
    expected_hash: Option<String>,
) -> CmdResult<Value> {
    crate::commands::run_blocking(move || {
        // Rewrites the whole record: not while a master-password change
        // could re-seal its secret in between.
        let _rotation = crate::commands::rotation_shared(&app)?;
        set_tool_state(
            &app.state::<crate::AppState>().db,
            app.state::<VaultPasswordStore>().inner(),
            &id,
            &tool,
            enabled,
            auto_approve,
            expected_hash.as_deref(),
        )
    })
    .await
}

/// What enabling a tool says when the definition the user reviewed is no
/// longer the one stored (see [`set_tool_state`]).
const DEFINITION_MOVED: &str = "This tool's definition changed - review it and approve again.";

/// What enabling a tool says when the request does not name the definition
/// the user reviewed (see [`set_tool_state`]).
const DEFINITION_NOT_NAMED: &str = "This approval does not say which tool definition you reviewed - reload the MCP server's tools, review the tool and approve it again.";

/// [`mcp_set_tool_state`] without the `AppHandle`, so its gates run against a
/// real database in tests. The caller holds the rotation guard.
///
/// Enabling is a compare-and-swap on the definition: `expected_hash` is the
/// `definition_hash` of the tool view the user approved, it is required for
/// every enable (a first approval as much as a re-approval), and the enable
/// is refused unless it is still the stored current hash - otherwise a
/// refresh that replaced the definition while the settings panel showed the
/// old one would let a click (with Auto-approve ticked) approve a definition
/// the user never saw. Disabling needs no hash.
///
/// The check and the write are ONE transaction
/// ([`crate::db::Database::modify_mcp_servers`]): the hash is compared with
/// the record as stored at the moment of the write, so a refresh that commits
/// a new definition while the toggle runs makes the enable fail - a lost race
/// never approves anything. The record used to be read, then
/// written back whole as a separate statement: such a refresh was overwritten
/// and its definition approved unseen, and a server removed meanwhile came
/// back. A failed `mcp.tool_approved` audit row after the commit is a
/// `warning` next to `ok: true`, never an error for an approval that is
/// stored.
fn set_tool_state(
    db: &crate::db::Database,
    vault: &VaultPasswordStore,
    id: &str,
    tool: &str,
    enabled: bool,
    auto_approve: bool,
    expected_hash: Option<&str>,
) -> CmdResult<Value> {
    // Approving or revoking a tool is a policy change: not while the vault
    // is locked (A6-08).
    if !vault.is_set() {
        return Err("Vault is locked.".into());
    }
    db.modify_mcp_servers(|all| {
        let mut record = all
            .iter()
            .find(|r| r.id == id)
            .cloned()
            .ok_or_else(|| CmdError("MCP server not found.".into()))?;
        apply_tool_state(&mut record, tool, enabled, auto_approve, expected_hash)?;
        if enabled {
            let registry: Vec<crate::db::McpServerRecord> = all
                .iter()
                .map(|r| {
                    if r.id == id {
                        record.clone()
                    } else {
                        r.clone()
                    }
                })
                .collect();
            check_enabled_registry(&registry, tool)?;
        }
        Ok((crate::db::McpWrite::Update(record), ()))
    })
    .map_err(CmdError::from)?;
    let warning = if enabled {
        audit_or_warn(
            db,
            "mcp.tool_approved",
            Some(id),
            &format!("tool={tool}"),
            "The tool was approved, but its audit row could not be written",
        )
    } else {
        None
    };
    Ok(json!({ "ok": true, "warning": warning }))
}

/// One toggle of `tool` on `record`: the definition compare-and-swap of an
/// enable (see [`set_tool_state`]), the pin, and Auto-approve exactly as
/// passed.
fn apply_tool_state(
    record: &mut crate::db::McpServerRecord,
    tool: &str,
    enabled: bool,
    auto_approve: bool,
    expected_hash: Option<&str>,
) -> CmdResult<()> {
    let entry = record
        .tools
        .iter_mut()
        .find(|t| t.name == tool)
        .ok_or_else(|| CmdError(format!("Tool '{tool}' not found on this MCP server.")))?;
    if enabled {
        // Enabling (re-)pins the CURRENT definition hash: that is the
        // definition the user is approving - which also clears a pending
        // "definition changed" notice (`definition_changed`).
        let Some(hash) = entry.current_hash.clone() else {
            return Err(CmdError(
                "Tool definition unknown - connect to the server first.".into(),
            ));
        };
        let Some(expected) = expected_hash else {
            return Err(DEFINITION_NOT_NAMED.into());
        };
        if expected != hash {
            return Err(DEFINITION_MOVED.into());
        }
        entry.pin_hash = Some(hash);
    } else {
        // Disabling clears the pin: re-enabling re-approves the
        // then-current definition, not a stale one.
        entry.pin_hash = None;
    }
    entry.enabled = enabled;
    // Exactly as passed (masked by `enabled`): a re-approval never inherits
    // an Auto-approve granted to an older definition.
    entry.auto_approve = auto_approve && enabled;
    record.updated_at = chrono::Utc::now();
    Ok(())
}

/// Whether the whole registry, with an enable of `tool` applied, may be
/// exposed - checked inside the enable's transaction, so two concurrent
/// toggles can never both pass an individually stale check:
/// - collision authority, BEFORE any exposure: an ambiguous model-facing
///   name set is refused outright - one approval must never silently cover
///   another tool;
/// - aggregate cap: the renderer offers [`BUILTIN_TOOL_COUNT`] built-in
///   tools first and fills the remaining slots with MCP tools, so more than
///   [`MAX_MCP_TOOLS`] enabled MCP tools could never all be exposed and
///   would silently drop the overflow - refused instead.
fn check_enabled_registry(registry: &[crate::db::McpServerRecord], tool: &str) -> CmdResult<()> {
    if let Some(err) = enable_collision_error(registry) {
        return Err(CmdError(err));
    }
    let enabled_total = registry
        .iter()
        .flat_map(|r| &r.tools)
        .filter(|t| t.enabled)
        .count();
    if enabled_total > MAX_MCP_TOOLS {
        return Err(CmdError(format!(
            "Enabling '{tool}' would expose {enabled_total} MCP tools across all servers; the assistant keeps {BUILTIN_TOOL_COUNT} built-in tools and the model-facing list is capped at {MAX_EXPOSED_TOOLS}. Disable another tool first."
        )));
    }
    Ok(())
}

#[tauri::command]
pub async fn mcp_call_tool(
    app: AppHandle,
    tab_id: String,
    id: String,
    tool: String,
    arguments_json: String,
    approved: bool,
) -> CmdResult<Value> {
    // THE GATE ([`call_gate`]) is enforced here, in Rust, independent of
    // what the renderer offered the model: the per-tab access level, the
    // user's approval (`approved` - the renderer attests the clicked card),
    // the confirmed entry, the enabled tool and its unchanged definition.
    let level = app
        .state::<crate::assistant::AssistantLevels>()
        .get(&tab_id);
    let db = &app.state::<crate::AppState>().db;
    let record = db
        .get_mcp_server(&id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| CmdError("MCP server not found.".into()))?;
    let entry = record
        .tools
        .iter()
        .find(|t| t.name == tool)
        .ok_or_else(|| CmdError(format!("Tool '{tool}' not found on this MCP server.")))?;

    let args_value: Value = serde_json::from_str(&arguments_json)
        .map_err(|_| CmdError("Tool arguments are not valid JSON.".into()))?;
    let fingerprint = arguments_fingerprint(&arguments_json);

    let denied = |level: &str, reason: &str| {
        audit_or_log(
            db,
            "mcp.tool_call",
            Some(&id),
            &format!(
                "server={} tool={} args_sha256={} level={} outcome=denied reason={}",
                record.name, tool, fingerprint, level, reason
            ),
        );
    };
    if let Err(reason) = call_gate(&level, approved, record.confirmed, entry) {
        denied(&level, &reason);
        return Err(CmdError(reason));
    }

    // A tools/list_changed refresh after the call rewrites the whole record:
    // a master-password change must not commit in between.
    let _rotation = crate::commands::rotation_shared(&app)?;
    // Execute. The generation pattern guards the awaits: every
    // credential-bearing request below rechecks the generation first (via
    // ServerContext::checked / require_generation_current), so a lock during
    // the call must not send the auth secret or register state afterward.
    let generation = capture_vault_generation(&app)?;
    let pw = vault_password(&app)?;
    if pw.is_empty() {
        return Err("Vault is locked.".into());
    }
    let mut ctx = load_server_context(&app, record.clone(), &pw, generation).await?;
    let rpc_id = Value::String(uuid::Uuid::new_v4().to_string());
    let body = json!({
        "jsonrpc": "2.0",
        "id": rpc_id,
        "method": "tools/call",
        "params": {
            "name": tool,
            "arguments": args_value,
        },
    });
    // The gate again, on the record as stored and the tab's level as set
    // right before the request goes out (the session set-up can take
    // seconds).
    let level_now = || {
        app.state::<crate::assistant::AssistantLevels>()
            .get(&tab_id)
    };
    let regate = || regate_call(db, &record, &tool, &level_now(), approved);
    let guard = || require_generation_current(&app, generation);
    let scope = SessionScope {
        state: app.state::<McpState>().inner(),
        db,
        password: &pw,
        guard: &guard,
    };
    let sent = run_tool_call(&scope, &mut ctx, &body, &regate).await?;
    // From here on the call may reach the server, so every outcome is
    // audited (see finish_tool_call) - at the level the gate checked right
    // before the request, not whatever the tab is set to once it answers.
    let (approval, level_sent, list_changed, called) = match sent {
        CallSent::Refused {
            reason,
            level,
            list_changed,
        } => {
            denied(&level, &reason);
            after_refused_call(list_changed, || {
                refresh_after_refusal(&scope, &mut ctx, &record)
            })
            .await;
            return Err(CmdError(reason));
        }
        CallSent::Sent {
            approval,
            level,
            list_changed,
            called,
        } => (approval, level, list_changed, called),
    };
    let audit = CallAudit {
        server_id: &id,
        server_name: &record.name,
        tool: &tool,
        args_sha256: &fingerprint,
        level: &level_sent,
        approval,
    };
    finish_tool_call(db, &audit, list_changed, called, || {
        refresh_after_sent_call(&scope, &mut ctx, &record)
    })
    .await
}

/// THE GATE for one MCP tool call (R6), pure over the stored tool so every
/// rule is unit-testable. Enforced here, independent of what the renderer
/// offered the model:
///   1. the server entry is confirmed;
///   2. at read/draft the user's approval of the card (`approved`) is
///      required - a tool's Auto-approve applies only from execute up;
///   3. the tool is enabled;
///   4. at execute, the card's approval or the tool's own Auto-approve; YOLO
///      needs neither;
///   5. the tool has an approved definition and still matches it.
///
/// Returns who let the call run, for the audit row: "approved" (the card),
/// "auto" (Auto-approve) or "yolo".
fn call_gate(
    level: &str,
    approved: bool,
    confirmed: bool,
    entry: &crate::db::McpToolRecord,
) -> Result<&'static str, String> {
    let tool = &entry.name;
    if !confirmed {
        return Err(UNCONFIRMED_SERVER.into());
    }
    if matches!(level, "read" | "draft") && !approved {
        return Err(format!(
            "AI access level is '{level}' - tool calls need your approval."
        ));
    }
    if !entry.enabled {
        return Err(format!(
            "Tool '{tool}' is not enabled - enable it in the MCP server settings."
        ));
    }
    if !entry.auto_approve && !approved && level != "yolo" {
        return Err(format!(
            "Tool '{tool}' requires approval before it can run."
        ));
    }
    if entry.pin_hash.is_none() {
        return Err(format!(
            "Tool '{tool}' has no approved definition - enable it again in the MCP server settings."
        ));
    }
    if definition_changed(entry) {
        return Err(format!(
            "Tool '{tool}' changed on the server since it was approved - re-approve it in the MCP settings."
        ));
    }
    Ok(if approved {
        "approved"
    } else if entry.auto_approve {
        "auto"
    } else {
        "yolo"
    })
}

/// What an `mcp.tool_call` audit row records about a call that passed the
/// gate. The arguments themselves are never audited, only their SHA-256.
struct CallAudit<'a> {
    server_id: &'a str,
    server_name: &'a str,
    tool: &'a str,
    args_sha256: &'a str,
    level: &'a str,
    /// Who let the call run: "approved" (the user's card), "auto" (the
    /// tool's own Auto-approve) or "yolo".
    approval: &'static str,
}

impl CallAudit<'_> {
    /// `result`: "ok", "error" (the tool reported isError) or "failed" (no
    /// usable answer - the call may or may not have run).
    fn write(&self, db: &crate::db::Database, result: &str) -> anyhow::Result<()> {
        db.add_audit(
            "mcp.tool_call",
            Some(self.server_id),
            &format!(
                "server={} tool={} args_sha256={} level={} outcome={} result={}",
                self.server_name, self.tool, self.args_sha256, self.level, self.approval, result
            ),
        )
    }
}

/// The tail of [`mcp_call_tool`] once the request has gone out: `called` is
/// the tools/call result, `list_changed` whether a tools/list_changed came
/// with it or with a session set-up on the way - after a failed call too -
/// and `refresh` re-fetches and re-pins the server's tools.
///
/// Every outcome writes the `mcp.tool_call` audit row - a call that failed
/// may still have run on the server. And once the tool HAS run, nothing
/// after it turns the call into an error: a failed refresh (or audit write)
/// comes back as `warning` next to the result, because the model, told
/// "error", would retry a side effect that already happened.
async fn finish_tool_call<F, Fut>(
    db: &crate::db::Database,
    audit: &CallAudit<'_>,
    list_changed: bool,
    called: CmdResult<Value>,
    refresh: F,
) -> CmdResult<Value>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = CmdResult<()>>,
{
    let result = match called {
        Ok(result) => result,
        Err(e) => {
            if let Err(audit_err) = audit.write(db, "failed") {
                log::warn!("[sshspan-mcp] could not audit a failed MCP tool call: {audit_err}");
            }
            // The server said its tools changed: refresh even though the
            // call failed, so the next call is gated against the new
            // definitions (a changed tool is disabled). The call's own error
            // is what comes back; a failed refresh is logged.
            if list_changed {
                if let Err(refresh_err) = refresh().await {
                    log::warn!(
                        "[sshspan-mcp] the tool list could not be refreshed after a failed call: {refresh_err}"
                    );
                }
            }
            return Err(e);
        }
    };
    let mut warnings: Vec<String> = Vec::new();
    // Re-pin so the NEXT call is gated against the fresh definitions.
    if list_changed {
        if let Err(e) = refresh().await {
            warnings.push(format!(
                "The tool ran, but refreshing this server's tool list afterwards failed: {e}"
            ));
        }
    }
    let (content, is_error) = shape_tool_result(&result);
    if let Err(e) = audit.write(db, if is_error { "error" } else { "ok" }) {
        log::warn!("[sshspan-mcp] could not audit an MCP tool call: {e}");
        warnings.push(format!(
            "The tool ran, but its audit row could not be written: {e}"
        ));
    }
    let warning = (!warnings.is_empty()).then(|| warnings.join(" "));
    Ok(json!({ "ok": true, "content": content, "is_error": is_error, "warning": warning }))
}

/// A tools/list_changed that arrived with a call (or with a mid-call
/// re-initialize): re-fetch and re-run pinning so the NEXT call is already
/// gated against fresh definitions. The caller holds the rotation guard.
async fn refresh_tools_after_call(
    scope: &SessionScope<'_>,
    ctx: &mut ServerContext,
    record: &crate::db::McpServerRecord,
) -> CmdResult<()> {
    let refreshed = fetch_tools(scope, ctx).await?;
    (scope.guard)()?;
    store_fetched_tools(scope.db, record, &refreshed)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── tools/list pagination is bounded ─────────────

    /// A server that keeps handing out cursors - empty pages included, which
    /// never trip the tool-count check - must end the fetch with an error: on
    /// a repeated cursor at once, otherwise after MAX_TOOL_PAGES pages.
    #[test]
    fn tools_list_pagination_stops_on_a_repeated_cursor_and_at_the_page_cap() {
        let mut seen = std::collections::HashSet::new();
        assert_eq!(next_tools_page(&mut seen, 1, 0, None).unwrap(), None);
        assert_eq!(
            next_tools_page(&mut seen, 1, 0, Some("c1".into())).unwrap(),
            Some("c1".into())
        );
        assert_eq!(
            next_tools_page(&mut seen, 2, 0, Some("c2".into())).unwrap(),
            Some("c2".into())
        );
        let looped = next_tools_page(&mut seen, 3, 0, Some("c1".into())).unwrap_err();
        assert!(looped.0.contains("repeated"), "{}", looped.0);

        let mut fresh = std::collections::HashSet::new();
        assert!(next_tools_page(&mut fresh, MAX_TOOL_PAGES - 1, 0, Some("a".into())).is_ok());
        let capped = next_tools_page(&mut fresh, MAX_TOOL_PAGES, 0, Some("b".into())).unwrap_err();
        assert!(capped.0.contains("pages"), "{}", capped.0);
    }

    // ── URL classification ──────────────────────────────────────────────

    #[test]
    fn https_urls_are_accepted_everywhere() {
        let (base, class) = classify_url("https://mcp.example.com/route").unwrap();
        assert_eq!(base, "https://mcp.example.com/route");
        assert_eq!(class, UrlClass::Https);
        // Trailing slash normalized away.
        let (base, _) = classify_url("https://mcp.example.com/").unwrap();
        assert_eq!(base, "https://mcp.example.com");
    }

    #[test]
    fn http_is_allowed_only_for_loopback() {
        for ok in [
            "http://localhost:3000",
            "http://127.0.0.1:8080",
            "http://127.5.4.3",
            "http://[::1]:9000",
        ] {
            let (_, class) = classify_url(ok).unwrap();
            assert_eq!(class, UrlClass::LoopbackInsecure, "{ok}");
        }
        for bad in [
            "http://mcp.example.com",
            "http://192.168.1.5:3000",
            "http://10.0.0.2",
        ] {
            let err = classify_url(bad).unwrap_err();
            assert!(err.contains("https"), "{bad}: {err}");
        }
    }

    #[test]
    fn url_must_not_carry_credentials_or_bogus_schemes() {
        assert!(classify_url("https://user:pw@mcp.example.com").is_err());
        assert!(classify_url("ftp://mcp.example.com").is_err());
        assert!(classify_url("not a url").is_err());
    }

    #[test]
    fn http_loopback_is_decided_on_the_parsed_address_not_a_name_prefix() {
        // Host NAMES that only look like loopback: plain http to them would
        // send the auth header in cleartext to whoever owns the name.
        for bad in [
            "http://127.evil.example/mcp",
            "http://127.0.0.1.nip.io/mcp",
            "http://127.0.0.1.evil.example:8080",
            "http://localhost.evil.example/mcp",
            // IPv4-mapped is not the loopback interface by std's definition.
            "http://[::ffff:127.0.0.1]/mcp",
        ] {
            let err = classify_url(bad).unwrap_err();
            assert!(err.contains("https"), "{bad} must be refused: {err}");
        }
        // Real loopback, however it is spelled, still passes; the url crate
        // canonicalizes `127.1` to `127.0.0.1`.
        for (ok, base) in [
            ("http://127.1/mcp", "http://127.0.0.1/mcp"),
            ("http://[::1]/mcp", "http://[::1]/mcp"),
            ("http://127.255.0.9:3000", "http://127.255.0.9:3000"),
            ("http://LOCALHOST:3000/mcp", "http://localhost:3000/mcp"),
        ] {
            let (got, class) = classify_url(ok).unwrap_or_else(|e| panic!("{ok}: {e}"));
            assert_eq!(class, UrlClass::LoopbackInsecure, "{ok}");
            assert_eq!(got, base, "{ok}");
        }
    }

    #[test]
    fn ipv6_literals_keep_their_brackets_in_the_stored_base() {
        for (raw, want, want_class) in [
            (
                "http://[::1]:8080/mcp",
                "http://[::1]:8080/mcp",
                UrlClass::LoopbackInsecure,
            ),
            (
                "https://[2001:db8::1]/mcp",
                "https://[2001:db8::1]/mcp",
                UrlClass::Https,
            ),
        ] {
            let (base, class) = classify_url(raw).unwrap();
            assert_eq!(base, want, "{raw}");
            assert_eq!(class, want_class, "{raw}");
            // Round trip: the stored base is a URL for the same address and
            // classifies to itself.
            let reparsed = url::Url::parse(&base).expect("the stored base must parse");
            assert_eq!(
                reparsed.host(),
                url::Url::parse(raw).unwrap().host(),
                "{raw}"
            );
            assert_eq!(classify_url(&base).unwrap().0, base, "{raw}");
        }
    }

    // ── Header name validation ──────────────────────────────────────────

    #[test]
    fn header_name_accepts_valid_tokens() {
        for good in ["X-Api-Key", "x-custom-auth", "A.b-c_d", "X!#$&'*+^`|~1"] {
            assert!(validate_header_name(good).is_ok(), "{good}");
        }
    }

    #[test]
    fn header_name_rejects_reserved_and_invalid() {
        for bad in [
            "Host",
            "host",
            "Content-Length",
            "content-length",
            "Mcp-Session-Id",
            "MCP-Protocol-Version",
            "Authorization",
            "Bad Name",
            "Bad:Name",
            "",
            "  ",
            "Hö̈st",
            "X()[]",
        ] {
            assert!(validate_header_name(bad).is_err(), "{bad}");
        }
    }

    // ── Tool naming ─────────────────────────────────────────────────────

    #[test]
    fn tool_names_are_sanitized_into_the_mcp_namespace() {
        assert_eq!(
            exposed_tool_name("github", "create issue"),
            "mcp__github__create_issue"
        );
        assert_eq!(exposed_tool_name("a", "b"), "mcp__a__b");
    }

    #[test]
    fn sanitization_matches_the_renderer_collapsing_underscore_runs() {
        // Mirrors mcpSanitizeName in src/renderer/mcp.js: non-[A-Za-z0-9_]
        // becomes '_' and runs collapse to one; '-' does NOT survive (the
        // backend is the authority, the renderer must match it).
        assert_eq!(sanitize_tool_name_part("my-server"), "my_server");
        assert_eq!(sanitize_tool_name_part("a  b--c"), "a_b_c");
        assert_eq!(sanitize_tool_name_part("__x__"), "_x_");
        assert_eq!(sanitize_tool_name_part("höst/tool"), "h_st_tool");
        // The exposed name can never contain "__" inside a part, so the
        // mcp__<server>__<tool> split stays unambiguous.
        assert!(!sanitize_tool_name_part("a b").contains("__"));
    }

    #[test]
    fn long_tool_names_get_a_hash_suffix_not_a_collision() {
        let long_a = "x".repeat(80);
        let long_b = "y".repeat(80);
        let name_a = exposed_tool_name("srv", &long_a);
        let name_b = exposed_tool_name("srv", &long_b);
        assert!(name_a.chars().count() <= MAX_TOOL_NAME_LEN);
        assert_ne!(name_a, name_b, "distinct inputs must not collide");
        assert_eq!(name_a, exposed_tool_name("srv", &long_a));
    }

    /// One registry entry for `build_name_map`: (server id, name, tools).
    fn entry(id: &str, name: &str, tools: &[&str]) -> (String, String, Vec<String>) {
        (
            id.into(),
            name.into(),
            tools.iter().map(|t| (*t).to_string()).collect(),
        )
    }

    #[test]
    fn name_map_rejects_collisions_within_and_across_servers() {
        // Within one server: "a b" and "a_b" sanitize identically.
        let err = build_name_map(&[entry("s1", "srv", &["a b", "a_b"])])
            .expect_err("same-server collision must be rejected");
        assert!(err.contains("same model-facing name"), "{err}");
        assert!(build_name_map(&[entry("s1", "srv", &["a b", "c"])]).is_ok());
        // Across servers: two servers with names that sanitize identically.
        let err = build_name_map(&[
            entry("s1", "my srv", &["t1"]),
            entry("s2", "my_srv", &["t2"]),
        ])
        .expect_err("server-name collision must be rejected");
        assert!(err.contains("same model-facing prefix"), "{err}");
        // Two servers with the SAME name are two servers (keyed by id), not
        // one: refused as well.
        let err = build_name_map(&[entry("s1", "srv", &["t"]), entry("s2", "srv", &["t"])])
            .expect_err("equal names on two servers must be rejected");
        assert!(err.contains("both named 'srv'"), "{err}");
        // The exposed name maps back to the server's id.
        let map = build_name_map(&[entry("s1", "srv", &["t"])]).unwrap();
        assert_eq!(map["mcp__srv__t"], ("s1".to_string(), "t".to_string()));
        // Built-in names are structurally out of reach (every exposed name
        // starts with "mcp__"); the belt-and-suspenders check must not
        // false-positive on a tool that merely shares a suffix.
        assert!(build_name_map(&[entry("s1", "mcp", &["run_command"])]).is_ok());
        // The identical tool name on two DIFFERENT (distinctly named)
        // servers produces two distinct exposed names and is fine.
        assert!(build_name_map(&[
            entry("s1", "alpha", &["search"]),
            entry("s2", "beta", &["search"])
        ])
        .is_ok());
    }

    // ── Pin hash ────────────────────────────────────────────────────────

    #[test]
    fn pin_hash_is_key_order_independent() {
        let a = json!({
            "name": "t", "title": "T", "description": "does things",
            "inputSchema": {"type": "object", "properties": {"x": {"type": "string"}}},
            "annotations": {"readOnlyHint": true},
        });
        // Same content, different key order everywhere.
        let b = json!({
            "annotations": {"readOnlyHint": true},
            "inputSchema": {"properties": {"x": {"type": "string"}}, "type": "object"},
            "description": "does things",
            "title": "T",
            "name": "t",
        });
        assert_eq!(tool_definition_hash(&a), tool_definition_hash(&b));
    }

    #[test]
    fn pin_hash_changes_when_a_field_changes() {
        let base = json!({
            "name": "t", "title": "T", "description": "does things",
            "inputSchema": {"type": "object"}, "annotations": null,
        });
        for field in ["description", "name", "title", "inputSchema", "annotations"] {
            let mut changed = base.clone();
            changed[field] = json!("changed");
            assert_ne!(
                tool_definition_hash(&base),
                tool_definition_hash(&changed),
                "changing {field} must change the hash"
            );
        }
    }

    #[test]
    fn pin_hash_uses_the_full_description() {
        let a = json!({ "name": "t", "description": "short" });
        let b = json!({ "name": "t", "description": "short but longer" });
        assert_ne!(tool_definition_hash(&a), tool_definition_hash(&b));
    }

    #[test]
    fn field_boundary_concatenation_ambiguity_is_avoided() {
        // Concatenating name+description would hash these two identically;
        // canonical JSON must not.
        let a = json!({ "name": "ab", "description": "c" });
        let b = json!({ "name": "a", "description": "bc" });
        assert_ne!(tool_definition_hash(&a), tool_definition_hash(&b));
    }

    // ── SSE parsing + response shaping ──────────────────────────────────

    #[test]
    fn sse_events_are_parsed_in_order() {
        let body = "event: message\ndata: {\"a\":1}\n\ndata: {\"b\":2}\n\n: keepalive\n\ndata: not json\n\n";
        let events = parse_sse(body);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0]["a"], 1);
        assert_eq!(events[1]["b"], 2);
        // Multi-line data fields are joined with newlines before parsing,
        // and CRLF endings work.
        let multi = "data: {\"c\":\r\ndata: 3}\r\n\r\n";
        assert_eq!(parse_sse(multi)[0]["c"], 3);
    }

    #[test]
    fn tool_result_shaping_covers_all_content_kinds() {
        let result = json!({
            "content": [
                { "type": "text", "text": "hello" },
                { "type": "image", "data": "AAAA", "mimeType": "image/png" },
                { "type": "audio", "data": "AAAA", "mimeType": "audio/wav" },
                { "type": "resource", "resource": { "uri": "file:///x", "text": "file text", "mimeType": "text/plain" } },
                { "type": "resource", "resource": { "uri": "file:///y", "blob": "AAAA", "mimeType": "application/pdf" } },
                { "type": "video", "data": "AAAA" },
            ],
            "structuredContent": { "rows": 1 },
            "isError": false,
        });
        let (content, is_error) = shape_tool_result(&result);
        assert!(!is_error);
        let lines: Vec<&str> = content.split('\n').collect();
        assert_eq!(lines[0], "hello");
        assert!(lines.contains(&"[image omitted]"));
        assert!(lines.contains(&"[audio omitted]"));
        assert!(lines.contains(&"file text"));
        assert!(lines.contains(&"[binary resource omitted]"));
        assert!(content.contains("\"rows\":1"));
    }

    #[test]
    fn tool_result_surfaces_is_error() {
        let result = json!({
            "content": [{ "type": "text", "text": "boom" }],
            "isError": true,
        });
        let (content, is_error) = shape_tool_result(&result);
        assert!(is_error);
        assert_eq!(content, "boom");
    }

    // ── Protocol version negotiation ────────────────────────────────────

    #[test]
    fn supported_protocol_versions_are_the_three_known_ones() {
        assert_eq!(PROTOCOL_VERSION_OFFERED, "2025-11-25");
        for v in ["2025-11-25", "2025-06-18", "2025-03-26"] {
            assert!(SUPPORTED_PROTOCOL_VERSIONS.contains(&v), "{v}");
        }
        // Legacy HTTP+SSE and unknown futures are both unsupported.
        assert!(!SUPPORTED_PROTOCOL_VERSIONS.contains(&"2024-11-05"));
        assert!(!SUPPORTED_PROTOCOL_VERSIONS.contains(&"1999-01-01"));
    }

    // ── Env var resolution ──────────────────────────────────────────────

    fn env_auth(var: &str) -> CmdResult<Zeroizing<String>> {
        resolve_secret_value(None, Some(var), &Zeroizing::new(String::new()), "X-Test")
    }

    #[test]
    fn env_var_resolves_at_request_time_and_errors_when_unset() {
        let var = "SSHSPAN_MCP_TEST_VAR";
        std::env::remove_var(var);
        let err = env_auth(var).unwrap_err();
        assert!(
            err.0.contains(var),
            "the error must name the variable: {err}"
        );
        assert!(err.0.contains("not set"));
        std::env::set_var(var, "token-123");
        assert_eq!(env_auth(var).unwrap().as_str(), "token-123");
        std::env::remove_var(var);
        // And again after removal - resolution is per-request, never cached.
        assert!(env_auth(var).is_err());
    }

    // ── Tool merge / rug-pull ───────────────────────────────────────────

    fn stored_tool(name: &str, desc: &str, enabled: bool, pin: bool) -> crate::db::McpToolRecord {
        crate::db::McpToolRecord {
            name: name.into(),
            display_name: None,
            description: desc.into(),
            enabled,
            auto_approve: false,
            pin_hash: pin
                .then(|| tool_definition_hash(&json!({ "name": name, "description": desc }))),
            current_hash: Some(tool_definition_hash(
                &json!({ "name": name, "description": desc }),
            )),
            input_schema: None,
            annotations: None,
        }
    }

    #[test]
    fn merge_preserves_pins_and_disables_changed_tools() {
        let stored = vec![
            stored_tool("same", "unchanged", true, true),
            stored_tool("rug", "old description", true, true),
            stored_tool("gone", "will disappear", true, true),
        ];
        let fetched = vec![
            json!({ "name": "same", "description": "unchanged" }),
            json!({ "name": "rug", "description": "NEW malicious description" }),
            json!({ "name": "new", "description": "brand new tool" }),
        ];
        let changed = changed_enabled_tools(&stored, &fetched);
        assert_eq!(changed, vec!["rug".to_string()]);

        let merged = merge_tools(&stored, &fetched);
        let same = merged.iter().find(|t| t.name == "same").unwrap();
        assert!(same.enabled);
        assert!(same.pin_hash.is_some());
        let rug = merged.iter().find(|t| t.name == "rug").unwrap();
        assert!(!rug.enabled, "a changed definition must disable the tool");
        let new = merged.iter().find(|t| t.name == "new").unwrap();
        assert!(!new.enabled, "new tools arrive disabled");
        assert!(new.pin_hash.is_none());
        assert!(merged.iter().all(|t| t.name != "gone"));
    }

    #[test]
    fn long_descriptions_are_truncated_with_a_marker() {
        let long = "x".repeat(MAX_DESCRIPTION_CHARS + 50);
        let merged = merge_tools(&[], &[json!({ "name": "t", "description": long })]);
        assert!(merged[0].description.contains("[truncated]"));
        assert!(merged[0].description.chars().count() <= MAX_DESCRIPTION_CHARS + 15);
        // The hash is over the FULL description: the truncated display copy
        // does not feed the pin.
        let full_hash = tool_definition_hash(&json!({ "name": "t", "description": long }));
        assert_eq!(merged[0].current_hash.as_deref(), Some(full_hash.as_str()));
    }

    // ── Input schema storage ───────────────────────────────────

    #[test]
    fn input_schema_is_stored_canonically_and_bounded() {
        let schema = json!({
            "type": "object",
            "properties": {
                "cmd": { "type": "string", "description": "what to run" },
            },
            "required": ["cmd"],
        });
        let def = json!({ "name": "t", "description": "d", "inputSchema": schema });
        assert_eq!(
            clamp_input_schema(&def).as_deref(),
            Some(
                r#"{"properties":{"cmd":{"description":"what to run","type":"string"}},"required":["cmd"],"type":"object"}"#
            )
        );
        // merge_tools stores the same clamped value.
        let merged = merge_tools(&[], &[def.clone()]);
        assert_eq!(
            merged[0].input_schema.as_deref(),
            clamp_input_schema(&def).as_deref()
        );
        // The PIN still hashes the full definition (schema included).
        assert_eq!(
            merged[0].current_hash.as_deref(),
            Some(tool_definition_hash(&def).as_str())
        );
    }

    #[test]
    fn input_schema_rejects_missing_non_object_and_oversized() {
        // Missing entirely.
        assert_eq!(clamp_input_schema(&json!({ "name": "t" })), None);
        // Non-object schemas (arrays, strings, booleans).
        for bad in [json!([]), json!("object"), json!(true), json!(42)] {
            let def = json!({ "name": "t", "inputSchema": bad });
            assert_eq!(clamp_input_schema(&def), None, "{bad}");
        }
        // Above the byte cap: not stored (the renderer substitutes an empty
        // object schema), but the pin hash still covers the full schema.
        let huge = json!({ "type": "object", "properties": {
            "blob": { "type": "string", "description": "x".repeat(MAX_INPUT_SCHEMA_BYTES) },
        }});
        let def = json!({ "name": "t", "inputSchema": huge });
        assert_eq!(clamp_input_schema(&def), None);
        let merged = merge_tools(&[], &[def.clone()]);
        assert_eq!(merged[0].input_schema, None);
        assert_eq!(
            merged[0].current_hash.as_deref(),
            Some(tool_definition_hash(&def).as_str())
        );
    }

    // ── Tool-cap constants stay aligned with the renderer ───────────────

    #[test]
    fn mcp_capacity_leaves_room_for_every_builtin_tool() {
        // Must equal AI_MAX_TOOLS_TOTAL (64) in src/renderer/assistant.js.
        assert_eq!(MAX_EXPOSED_TOOLS, 64);
        // Must equal the number of entries in AI_TOOL_SPECS there.
        assert_eq!(BUILTIN_TOOL_NAMES.len(), BUILTIN_TOOL_COUNT);
        // MCP can therefore fill every slot the built-ins leave: the
        // backend cap cannot make the renderer's merge fail.
        assert_eq!(MAX_MCP_TOOLS, MAX_EXPOSED_TOOLS - BUILTIN_TOOL_COUNT);
    }

    // ── Static credential origin binding ───────────────────────

    /// The pure decision core of mcp_save_server's binding rule: whether the
    /// STORED secret must be dropped when saving `new` over `old`.
    fn keep_stored_secret(
        old: &crate::db::McpServerRecord,
        new_url: &str,
        new_auth_type: &str,
        new_header_name: Option<&str>,
    ) -> bool {
        let origin_changed = old.url != new_url;
        let semantics_changed =
            old.auth_type != new_auth_type || old.auth_header_name.as_deref() != new_header_name;
        !(origin_changed || semantics_changed)
    }

    fn binding_record(
        url: &str,
        auth_type: &str,
        header: Option<&str>,
    ) -> crate::db::McpServerRecord {
        crate::db::McpServerRecord {
            id: "x".into(),
            name: "srv".into(),
            url: url.into(),
            auth_type: auth_type.into(),
            auth_header_name: header.map(String::from),
            auth_secret: Some("sealed-old".into()),
            auth_env_var: None,
            confirmed: true,
            tools: Vec::new(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn editing_url_auth_type_or_header_drops_the_stored_secret() {
        let old = binding_record("https://a.example.com/mcp", "bearer", None);
        // Same config: the secret may be kept (blank field in the UI).
        assert!(keep_stored_secret(
            &old,
            "https://a.example.com/mcp",
            "bearer",
            None
        ));
        // URL change (even just the port): never reuse the old secret at a
        // new origin.
        assert!(!keep_stored_secret(
            &old,
            "https://a.example.com:8443/mcp",
            "bearer",
            None
        ));
        assert!(!keep_stored_secret(
            &old,
            "https://b.example.com/mcp",
            "bearer",
            None
        ));
        // Auth semantic change: bearer -> custom_header, or a different
        // header name under custom_header (the old value would be sent as a
        // different header - different meaning).
        assert!(!keep_stored_secret(
            &old,
            "https://a.example.com/mcp",
            "custom_header",
            Some("X-Api-Key")
        ));
        let custom = binding_record("https://a.example.com/mcp", "custom_header", Some("X-Key"));
        assert!(keep_stored_secret(
            &custom,
            "https://a.example.com/mcp",
            "custom_header",
            Some("X-Key")
        ));
        assert!(!keep_stored_secret(
            &custom,
            "https://a.example.com/mcp",
            "custom_header",
            Some("X-Other")
        ));
    }

    #[test]
    fn auth_source_selection_is_mutually_exclusive_in_saved_records() {
        // The save path enforces it structurally; this pins the invariant a
        // record must never break, including records that round-trip the DB.
        let mut r = binding_record("https://a.example.com", "bearer", None);
        // Model the env-var branch of mcp_save_server: selecting an env source
        // clears the old sealed value before persisting the record.
        r.auth_secret = None;
        r.auth_env_var = Some("TOKEN".into());
        assert!(r.auth_secret.is_none() || r.auth_env_var.is_none());
        // Selecting none clears both sources.
        r.auth_type = "none".into();
        r.auth_env_var = None;
        assert!(r.auth_secret.is_none() && r.auth_env_var.is_none());
    }

    // ── 3xx detection ───────────────────────────────────────────────────

    #[tokio::test]
    async fn redirects_are_a_hard_error_not_a_followed_response() {
        use std::io::{Read as _, Write as _};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            if let Ok((mut sock, _)) = listener.accept() {
                // Drain the request head (and any body) before replying.
                let mut sink = [0u8; 4096];
                let _ = sock.read(&mut sink);
                let _ = sock.write_all(
                    b"HTTP/1.1 302 Found\r\nLocation: https://evil.example.com/harvest\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                );
            }
        });
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let err = post_jsonrpc(
            &client,
            &format!("http://{addr}/mcp"),
            &json!({"jsonrpc":"2.0","id":1,"method":"ping"}),
            Some(("Authorization", &Zeroizing::new("secret".into()))),
            None,
            None,
        )
        .await
        .unwrap_err();
        assert!(err.0.contains("redirect"), "{err}");
        assert!(err.0.contains("evil.example.com"));
        let _ = handle.join();
    }

    // ── Backup/restore inertness (db round-trip) ─────────────────────────

    #[test]
    fn backup_restored_entries_come_back_inert() {
        let db = crate::db::Database::open_at(
            std::env::temp_dir().join(format!("sshspan-mcp-inert-{}.sqlite", uuid::Uuid::new_v4())),
        )
        .unwrap();
        // A "malicious backup" entry: confirmed=true, tools enabled with
        // pins and auto-approve - everything restore must neutralize.
        let payload = json!({
            "mcpServers": [{
                "id": "stolen",
                "name": "evil",
                "url": "https://attacker.example/mcp",
                "auth_type": "bearer",
                "auth_header_name": null,
                "auth_secret": "sealed-blob",
                "auth_env_var": "LEAKED_VAR",
                "confirmed": true,
                "tools": [{
                    "name": "steal", "display_name": null, "description": "d",
                    "enabled": true, "auto_approve": true,
                    "pin_hash": "abc", "current_hash": "abc",
                    "annotations": null,
                }],
                "created_at": "2026-01-01T00:00:00Z",
                "updated_at": "2026-01-01T00:00:00Z",
            }],
        });
        let counts = db.restore_backup(&payload).unwrap();
        assert_eq!(counts["mcpServers"], 1);
        let restored = db.get_mcp_server("stolen").unwrap().unwrap();
        assert!(!restored.confirmed, "restored entries must be unconfirmed");
        assert_eq!(restored.tools.len(), 1);
        assert!(!restored.tools[0].enabled);
        assert!(!restored.tools[0].auto_approve);
        assert!(restored.tools[0].pin_hash.is_none());
        // The sealed secret itself survives (re-sealable at restore time) -
        // inertness comes from the confirmed flag, not from data loss.
        assert!(restored.auth_secret.is_some());
    }

    // ── Delayed vault lock ─────────────────────────────────────

    /// The generation guard `ServerContext::checked` consults (via
    /// `require_generation_current`): a lock that happens BETWEEN two
    /// credential-bearing requests must revoke the guard for the second
    /// one - the exact race the initialize → tools/list sequence has.
    #[test]
    fn delayed_vault_lock_between_requests_revokes_the_guard() {
        use crate::commands::VaultGeneration;

        let gen = VaultGeneration::new();
        let captured = gen.current();
        // Request 1 (e.g. initialize): guard passes.
        assert!(
            gen.is_current(captured, true),
            "the guard must pass while unlocked and unchanged"
        );
        // The vault locks between the requests: lock_vault_internal bumps
        // the generation BEFORE clearing the password store, so there is a
        // window where the vault is still unlocked but the generation is
        // stale - the guard must ALREADY fail there, so the next POST never
        // carries the unsealed header.
        gen.bump();
        assert!(
            !gen.is_current(captured, true),
            "a bumped generation must abort the next request even while the \
             password store still holds a value"
        );
        // The store cleared afterwards: still (and again) refused.
        assert!(!gen.is_current(captured, false));
        // A later re-unlock does NOT resurrect the captured generation: a
        // pending operation from the previous unlock session must not send
        // secrets into the new one.
        assert!(!gen.is_current(captured, true));
        // A fresh capture after the re-unlock is valid again.
        let fresh = gen.current();
        assert!(gen.is_current(fresh, true));
    }

    // ── Enable-time collision gate ─────────────────────────────

    fn record_with_tools(
        id: &str,
        name: &str,
        tools: &[(&str, bool)],
    ) -> crate::db::McpServerRecord {
        crate::db::McpServerRecord {
            id: id.into(),
            name: name.into(),
            url: "https://mcp.example.com".into(),
            auth_type: "none".into(),
            auth_header_name: None,
            auth_secret: None,
            auth_env_var: None,
            confirmed: true,
            tools: tools
                .iter()
                .map(|(n, enabled)| crate::db::McpToolRecord {
                    name: (*n).into(),
                    display_name: None,
                    description: String::new(),
                    enabled: *enabled,
                    auto_approve: false,
                    pin_hash: None,
                    current_hash: None,
                    input_schema: None,
                    annotations: None,
                })
                .collect(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn enable_collision_error_rejects_ambiguous_registries() {
        // Registry where two tools of one server sanitize to one name.
        let records = vec![record_with_tools(
            "s1",
            "srv",
            &[("a b", true), ("a_b", true)],
        )];
        let err = enable_collision_error(&records).expect("must be rejected");
        assert!(err.contains("same model-facing name"), "{err}");
        // Enabling on one server while ANOTHER server's enabled tool set
        // produces the same exposed name is refused too.
        let records = vec![
            record_with_tools("s1", "alpha", &[("search", true)]),
            record_with_tools("s2", "beta", &[("search", false)]),
        ];
        assert!(enable_collision_error(&records).is_none());
        // A server whose name collides but has NO enabled tools blocks
        // nothing (it exposes nothing).
        let records = vec![
            record_with_tools("s1", "my srv", &[("t", true)]),
            record_with_tools("s2", "my_srv", &[]),
        ];
        assert!(enable_collision_error(&records).is_none());
        // Once both collide AND both expose, it is refused.
        let records = vec![
            record_with_tools("s1", "my srv", &[("t", true)]),
            record_with_tools("s2", "my_srv", &[("t", true)]),
        ];
        let err = enable_collision_error(&records).expect("must be rejected");
        assert!(err.contains("same model-facing prefix"), "{err}");
        // Empty registry: fine.
        assert!(enable_collision_error(&[]).is_none());
    }

    /// Same tool name on two DIFFERENTLY named servers produces distinct
    /// exposed names and must be accepted.
    #[test]
    fn same_tool_on_two_servers_is_not_a_collision() {
        let records = vec![
            record_with_tools("s1", "alpha", &[("search", true)]),
            record_with_tools("s2", "beta", &[("search", true)]),
        ];
        assert_eq!(exposed_tool_name("alpha", "search"), "mcp__alpha__search");
        assert_eq!(exposed_tool_name("beta", "search"), "mcp__beta__search");
        assert!(enable_collision_error(&records).is_none());
    }

    // ── Helpers: a test database, an unlocked vault, saved servers ──────

    fn temp_db() -> crate::db::Database {
        crate::db::Database::open_at(
            std::env::temp_dir().join(format!("sshspan-mcp-ru2-{}.sqlite", uuid::Uuid::new_v4())),
        )
        .unwrap()
    }

    fn unlocked_vault() -> VaultPasswordStore {
        let vault = VaultPasswordStore::new();
        vault.set("test-master-pw".into());
        vault
    }

    /// A stored tool pinned to `def` (the state approval writes).
    fn tool_pinned_to(def: &Value, enabled: bool) -> crate::db::McpToolRecord {
        let mut tool = merge_tools(&[], std::slice::from_ref(def)).remove(0);
        tool.enabled = enabled;
        tool.pin_hash = tool.current_hash.clone();
        tool
    }

    fn save_args(id: Option<&str>, name: &str, url: &str, auth_type: &str) -> SaveServerArgs {
        SaveServerArgs {
            id: id.map(String::from),
            name: name.into(),
            url: url.into(),
            auth_type: auth_type.into(),
            auth_header_name: None,
            auth_secret: None,
            auth_env_var: None,
        }
    }

    fn saved_id(out: Value) -> String {
        out["id"].as_str().expect("save returns the id").to_string()
    }

    /// What `mcp_save_server` does, without the app: the save, then - when it
    /// bound a credential to a new place - the question, answered by `ask`.
    /// (The command also starts the stale session's teardown in between.)
    fn save_and_settle(
        db: &crate::db::Database,
        state: &McpState,
        vault: &VaultPasswordStore,
        rotation: &VaultRotationLock,
        args: SaveServerArgs,
        ask: ConfirmCredential<'_>,
    ) -> CmdResult<SavedServer> {
        let questions = crate::commands::CredentialQuestions::new();
        let generations = crate::commands::VaultGeneration::new();
        save_and_settle_with(
            db,
            state,
            vault,
            rotation,
            &questions,
            &generations,
            args,
            ask,
        )
    }

    /// [`save_and_settle`] with the app's one-question-at-a-time gate and
    /// vault generation given.
    #[allow(clippy::too_many_arguments)]
    fn save_and_settle_with(
        db: &crate::db::Database,
        state: &McpState,
        vault: &VaultPasswordStore,
        rotation: &VaultRotationLock,
        questions: &crate::commands::CredentialQuestions,
        generations: &crate::commands::VaultGeneration,
        args: SaveServerArgs,
        ask: ConfirmCredential<'_>,
    ) -> CmdResult<SavedServer> {
        let generation = generations.current();
        // On the pool like the command runs it (a typed secret is sealed).
        let mut saved = crate::commands::as_if_on_pool(|| save_server(db, state, vault, args))?;
        if let Some(pending) = saved.pending.take() {
            let at_save = VaultAtSave {
                vault,
                generations,
                generation,
            };
            let outcome = settle_binding(db, rotation, questions, &at_save, pending, ask);
            apply_outcome(&mut saved.view, outcome);
        }
        Ok(saved)
    }

    /// `mcp_save_server` with no live sessions, the user allowing whatever it
    /// asks, returning the command's answer.
    fn save(
        db: &crate::db::Database,
        vault: &VaultPasswordStore,
        args: SaveServerArgs,
    ) -> CmdResult<Value> {
        save_and_settle(
            db,
            &McpState::new(),
            vault,
            &VaultRotationLock::new(),
            args,
            &|_| CredentialAnswer::Allowed,
        )
        .map(|saved| saved.view)
    }

    // ── Rug-pull guard the UI can show (R6: A4-05, A7-29, A8-15) ────────

    #[test]
    fn a_changed_definition_is_disabled_loses_auto_approve_and_is_flagged() {
        let mut rug = stored_tool("rug", "old description", true, true);
        rug.auto_approve = true;
        let stored = vec![rug, stored_tool("same", "unchanged", true, true)];
        let fetched = vec![
            json!({ "name": "rug", "description": "NEW malicious description" }),
            json!({ "name": "same", "description": "unchanged" }),
            json!({ "name": "new", "description": "brand new tool" }),
        ];
        let merged = merge_tools(&stored, &fetched);
        let rug = merged.iter().find(|t| t.name == "rug").unwrap();
        assert!(!rug.enabled);
        assert!(
            !rug.auto_approve,
            "a changed definition must not keep the old Auto-approve"
        );
        assert_eq!(
            rug.pin_hash, stored[0].pin_hash,
            "the old pin is kept, so the change stays detectable"
        );
        assert_eq!(tool_view("srv", rug)["definition_changed"], true);
        for name in ["same", "new"] {
            let t = merged.iter().find(|t| t.name == name).unwrap();
            assert_eq!(tool_view("srv", t)["definition_changed"], false, "{name}");
        }
    }

    #[test]
    fn re_enabling_a_changed_tool_pins_the_new_definition_and_clears_the_flag() {
        let db = temp_db();
        // A rug-pulled tool as a connect leaves it: disabled, old pin kept.
        let old = json!({ "name": "rug", "description": "old" });
        let new = json!({ "name": "rug", "description": "new" });
        let mut record = record_with_tools("s1", "srv", &[]);
        let mut tool = tool_pinned_to(&old, false);
        tool.current_hash = Some(tool_definition_hash(&new));
        record.tools = vec![tool];
        db.save_mcp_server(&record).unwrap();
        assert_eq!(
            tool_view("srv", &record.tools[0])["definition_changed"],
            true
        );

        let shown = tool_definition_hash(&new);
        set_tool_state(
            &db,
            &unlocked_vault(),
            "s1",
            "rug",
            true,
            false,
            Some(&shown),
        )
        .unwrap();
        let t = db.get_mcp_server("s1").unwrap().unwrap().tools.remove(0);
        assert!(
            t.enabled && !t.auto_approve,
            "Auto-approve is stored only as passed"
        );
        assert_eq!(
            t.pin_hash, t.current_hash,
            "re-approval pins the definition the user sees now"
        );
        assert_eq!(tool_view("srv", &t)["definition_changed"], false);
    }

    // ── Lock gates (A6-08) ──────────────────────────────────────────────

    #[test]
    fn tool_toggles_are_refused_while_the_vault_is_locked() {
        let db = temp_db();
        let mut record = record_with_tools("s1", "srv", &[("t", false)]);
        record.tools[0].current_hash = Some("h".into());
        db.save_mcp_server(&record).unwrap();
        let err = set_tool_state(
            &db,
            &VaultPasswordStore::new(),
            "s1",
            "t",
            true,
            false,
            Some("h"),
        )
        .unwrap_err();
        assert_eq!(err.0, "Vault is locked.");
        assert!(!db.get_mcp_server("s1").unwrap().unwrap().tools[0].enabled);
        set_tool_state(&db, &unlocked_vault(), "s1", "t", true, false, Some("h")).unwrap();
    }

    // ── Approval bound to the reviewed definition ─────

    /// A stored server `s1` with tool `t` whose stored definition moved from
    /// `old` to `new`; `pinned_old` says whether the user had approved `old`.
    fn tool_whose_definition_moved(
        db: &crate::db::Database,
        old: &Value,
        new: &Value,
        pinned_old: bool,
    ) {
        let mut record = record_with_tools("s1", "srv", &[]);
        let mut tool = tool_pinned_to(old, false);
        if !pinned_old {
            tool.pin_hash = None;
        }
        tool.current_hash = Some(tool_definition_hash(new));
        record.tools = vec![tool];
        db.save_mcp_server(&record).unwrap();
    }

    fn stored_tool_t(db: &crate::db::Database) -> crate::db::McpToolRecord {
        db.get_mcp_server("s1").unwrap().unwrap().tools.remove(0)
    }

    const REAPPROVE: &str = "This tool's definition changed - review it and approve again.";

    /// A check-then-use race: a refresh replaced (and flagged) a tool's
    /// definition while the settings panel still showed the old one. Enabling
    /// it, Auto-approve ticked or not, must not approve the definition the
    /// user never saw.
    #[test]
    fn enabling_with_a_stale_definition_hash_is_refused() {
        let db = temp_db();
        let vault = unlocked_vault();
        let old = json!({ "name": "t", "description": "old" });
        let new = json!({ "name": "t", "description": "new" });
        tool_whose_definition_moved(&db, &old, &new, true);
        let shown = tool_definition_hash(&old);
        let err = set_tool_state(&db, &vault, "s1", "t", true, true, Some(&shown)).unwrap_err();
        assert_eq!(err.0, REAPPROVE);
        let t = stored_tool_t(&db);
        assert!(!t.enabled && !t.auto_approve, "nothing was approved");
        assert!(definition_changed(&t), "the notice stays up");
        // The same check binds a first approval: the panel showed `old`, the
        // server meanwhile serves `new`.
        let db = temp_db();
        tool_whose_definition_moved(&db, &old, &new, false);
        let err = set_tool_state(&db, &vault, "s1", "t", true, false, Some(&shown)).unwrap_err();
        assert_eq!(err.0, REAPPROVE);
        assert!(!stored_tool_t(&db).enabled);
    }

    /// Every enable names the definition the user reviewed:
    /// without `expected_hash` it is refused - a first approval as much as a
    /// re-approval - and the message sends the user to reload and review.
    #[test]
    fn enabling_without_a_definition_hash_is_refused() {
        let db = temp_db();
        let vault = unlocked_vault();
        let def = json!({ "name": "t", "description": "d" });
        // Never approved and unchanged: still needs the hash.
        tool_whose_definition_moved(&db, &def, &def, false);
        let err = set_tool_state(&db, &vault, "s1", "t", true, false, None).unwrap_err();
        assert!(
            err.0.contains("reload") && err.0.contains("review"),
            "{}",
            err.0
        );
        assert!(!stored_tool_t(&db).enabled);
        // A flagged tool likewise, Auto-approve or not.
        let db = temp_db();
        let new = json!({ "name": "t", "description": "new" });
        tool_whose_definition_moved(&db, &def, &new, true);
        let err = set_tool_state(&db, &vault, "s1", "t", true, true, None).unwrap_err();
        assert!(
            err.0.contains("reload") && err.0.contains("review"),
            "{}",
            err.0
        );
        let t = stored_tool_t(&db);
        assert!(!t.enabled && !t.auto_approve, "nothing was approved");
        assert!(definition_changed(&t), "the notice stays up");
    }

    #[test]
    fn enabling_with_the_shown_definition_hash_pins_it_and_clears_the_flag() {
        let db = temp_db();
        let vault = unlocked_vault();
        let old = json!({ "name": "t", "description": "old" });
        let new = json!({ "name": "t", "description": "new" });
        tool_whose_definition_moved(&db, &old, &new, true);
        let shown = tool_definition_hash(&new);
        set_tool_state(&db, &vault, "s1", "t", true, true, Some(&shown)).unwrap();
        let t = stored_tool_t(&db);
        assert!(t.enabled && t.auto_approve);
        assert_eq!(t.pin_hash.as_deref(), Some(shown.as_str()));
        assert!(!definition_changed(&t));
    }

    #[test]
    fn disabling_a_tool_needs_no_definition_hash() {
        let db = temp_db();
        let vault = unlocked_vault();
        let old = json!({ "name": "t", "description": "old" });
        let new = json!({ "name": "t", "description": "new" });
        tool_whose_definition_moved(&db, &old, &new, true);
        set_tool_state(&db, &vault, "s1", "t", false, false, None).unwrap();
        set_tool_state(&db, &vault, "s1", "t", false, true, Some("stale")).unwrap();
        let t = stored_tool_t(&db);
        assert!(!t.enabled && !t.auto_approve && t.pin_hash.is_none());
    }

    /// The over-cap error tells the truth about whether the listing was
    /// complete.
    #[test]
    fn the_tool_cap_error_says_whether_the_listing_was_complete() {
        let mut seen = std::collections::HashSet::new();
        let complete = next_tools_page(&mut seen, 1, 70, None).unwrap_err();
        assert_eq!(
            complete.0,
            "MCP server exposes 70 tools, above the 64-tool limit."
        );
        let complete = next_tools_page(&mut seen, 1, 70, Some(String::new())).unwrap_err();
        assert!(!complete.0.contains("stopped reading"), "{}", complete.0);
        let partial = next_tools_page(&mut seen, 1, 70, Some("more".into())).unwrap_err();
        assert!(
            partial.0.contains("more than 64") && partial.0.contains("stopped reading"),
            "{}",
            partial.0
        );
    }

    /// The server-name rule is described as it is checked: RFC 7230 token
    /// characters, not only letters, digits, - and _.
    #[test]
    fn the_server_name_rule_is_described_as_it_is_checked() {
        let db = temp_db();
        let vault = unlocked_vault();
        let err = save(
            &db,
            &vault,
            save_args(None, "my server", "https://a.example.com", "none"),
        )
        .unwrap_err();
        assert_eq!(
            err.0,
            "Server name must be non-empty and use only letters, digits and ! # $ % & ' * + - . ^ _ ` | ~ (no spaces)."
        );
        // Characters the message lists are accepted.
        save(
            &db,
            &vault,
            save_args(None, "a.b~c!", "https://a.example.com", "none"),
        )
        .unwrap();
    }

    #[test]
    fn the_tool_view_carries_the_definition_hash_to_send_back() {
        let def = json!({ "name": "t", "description": "d" });
        let tool = tool_pinned_to(&def, true);
        let view = tool_view("srv", &tool);
        assert_eq!(view["definition_hash"], tool_definition_hash(&def).as_str());
    }

    // ── Settings round-trip (A4-07, A7-30, A4-12) ───────────────────────

    #[test]
    fn the_server_list_round_trips_auth_settings_without_the_secret() {
        let mut r = record_with_tools("s1", "srv", &[]);
        r.auth_type = "custom_header".into();
        r.auth_header_name = Some("X-Api-Key".into());
        r.auth_secret = Some("SEALED-BLOB".into());
        let v = server_view(&r, "connected".into(), Some("2025-06-18".into()));
        assert_eq!(v["auth_header_name"], "X-Api-Key");
        assert_eq!(v["has_secret"], true);
        assert_eq!(v["auth_env_var"], Value::Null);
        assert_eq!(v["protocol_version"], "2025-06-18");
        assert!(
            !v.to_string().contains("SEALED-BLOB"),
            "the sealed secret never crosses IPC"
        );
        let mut e = record_with_tools("s2", "env", &[]);
        e.auth_type = "bearer".into();
        e.auth_env_var = Some("GITHUB_TOKEN".into());
        let v = server_view(&e, "unknown".into(), None);
        assert_eq!(v["auth_env_var"], "GITHUB_TOKEN");
        assert_eq!(v["has_secret"], false);
        assert_eq!(v["protocol_version"], Value::Null);
    }

    #[test]
    fn an_absent_env_var_keeps_the_stored_binding() {
        let db = temp_db();
        let vault = unlocked_vault();
        let mut args = save_args(None, "gh", "https://mcp.example.com/mcp", "bearer");
        args.auth_env_var = Some("GITHUB_TOKEN".into());
        let id = saved_id(save(&db, &vault, args).unwrap());
        // Rename only: the form sends no env var (absent) - the binding stays.
        save(
            &db,
            &vault,
            save_args(Some(&id), "github", "https://mcp.example.com/mcp", "bearer"),
        )
        .unwrap();
        let r = db.get_mcp_server(&id).unwrap().unwrap();
        assert_eq!(r.name, "github");
        assert_eq!(r.auth_env_var.as_deref(), Some("GITHUB_TOKEN"));
        // An explicit empty string clears it - and a bearer server left with
        // no auth source is refused.
        let mut clear = save_args(Some(&id), "github", "https://mcp.example.com/mcp", "bearer");
        clear.auth_env_var = Some(String::new());
        let err = save(&db, &vault, clear).unwrap_err();
        assert!(err.0.contains("environment variable"), "{}", err.0);
        // Switching to auth "none" drops it legitimately.
        save(
            &db,
            &vault,
            save_args(Some(&id), "github", "https://mcp.example.com/mcp", "none"),
        )
        .unwrap();
        assert_eq!(db.get_mcp_server(&id).unwrap().unwrap().auth_env_var, None);
    }

    #[test]
    fn an_absent_header_name_keeps_the_stored_custom_header() {
        let db = temp_db();
        let vault = unlocked_vault();
        let mut args = save_args(None, "kb", "https://kb.example.com/mcp", "custom_header");
        args.auth_header_name = Some("X-Api-Key".into());
        args.auth_env_var = Some("KB_TOKEN".into());
        let id = saved_id(save(&db, &vault, args).unwrap());
        save(
            &db,
            &vault,
            save_args(
                Some(&id),
                "kb2",
                "https://kb.example.com/mcp",
                "custom_header",
            ),
        )
        .unwrap();
        let r = db.get_mcp_server(&id).unwrap().unwrap();
        assert_eq!(r.auth_header_name.as_deref(), Some("X-Api-Key"));
        assert_eq!(r.auth_env_var.as_deref(), Some("KB_TOKEN"));
    }

    #[test]
    fn a_bearer_or_custom_header_server_needs_an_auth_source() {
        let db = temp_db();
        let vault = unlocked_vault();
        let err = save(
            &db,
            &vault,
            save_args(None, "a", "https://a.example.com", "bearer"),
        )
        .unwrap_err();
        assert!(
            err.0.contains("secret or an environment variable"),
            "{}",
            err.0
        );
        let mut custom = save_args(None, "b", "https://b.example.com", "custom_header");
        custom.auth_header_name = Some("X-Key".into());
        assert!(save(&db, &vault, custom).is_err());
        assert!(
            db.list_mcp_servers().unwrap().is_empty(),
            "nothing was saved"
        );
        // A URL change discards the stored credential binding; with nothing
        // new entered the save is refused and changes nothing.
        let mut env = save_args(None, "c", "https://c.example.com", "bearer");
        env.auth_env_var = Some("TOKEN".into());
        let id = saved_id(save(&db, &vault, env).unwrap());
        let err = save(
            &db,
            &vault,
            save_args(Some(&id), "c", "https://elsewhere.example.com", "bearer"),
        )
        .unwrap_err();
        assert!(err.0.contains("discards"), "{}", err.0);
        assert_eq!(
            db.get_mcp_server(&id).unwrap().unwrap().url,
            "https://c.example.com"
        );
    }

    #[test]
    fn server_names_that_collide_as_tool_prefixes_are_refused() {
        let db = temp_db();
        let vault = unlocked_vault();
        let id = saved_id(
            save(
                &db,
                &vault,
                save_args(None, "my-srv", "https://a.example.com", "none"),
            )
            .unwrap(),
        );
        for clash in ["my_srv", "My.Srv", "MY-SRV"] {
            let err = save(
                &db,
                &vault,
                save_args(None, clash, "https://b.example.com", "none"),
            )
            .unwrap_err();
            assert!(err.0.contains("my-srv"), "{clash}: {}", err.0);
        }
        // The same server re-saved under its own name is fine, and so is a
        // distinct name.
        save(
            &db,
            &vault,
            save_args(Some(&id), "my-srv", "https://a.example.com", "none"),
        )
        .unwrap();
        save(
            &db,
            &vault,
            save_args(None, "other", "https://b.example.com", "none"),
        )
        .unwrap();
    }

    #[test]
    fn two_servers_with_the_same_name_cannot_both_expose_tools() {
        let records = vec![
            record_with_tools("s1", "srv", &[("t", true)]),
            record_with_tools("s2", "srv", &[("t", true)]),
        ];
        let err = enable_collision_error(&records).expect("equal names must not alias");
        assert!(err.contains("srv"), "{err}");
        // Different tools behind one name are just as ambiguous: the Approve
        // card and the model cannot tell the two servers apart.
        let records = vec![
            record_with_tools("s1", "srv", &[("a", true)]),
            record_with_tools("s2", "srv", &[("b", true)]),
        ];
        assert!(enable_collision_error(&records).is_some());
    }

    // ── A connect does not revert concurrent edits (A7-49) ──────────────

    #[test]
    fn a_connect_keeps_toggles_and_edits_made_while_it_ran() {
        let def = json!({ "name": "t", "description": "d" });
        let mut at_start = record_with_tools("s1", "srv", &[]);
        at_start.tools = vec![tool_pinned_to(&def, true)];
        // While the connect was on the network the user disabled the tool
        // and renamed the server.
        let mut now = at_start.clone();
        now.name = "renamed".into();
        now.tools[0].enabled = false;
        now.tools[0].pin_hash = None;
        let (saved, changed) =
            merge_into_stored(&at_start, Some(now), std::slice::from_ref(&def)).unwrap();
        assert!(
            !saved.tools[0].enabled,
            "a tool disabled meanwhile stays disabled"
        );
        assert_eq!(saved.name, "renamed");
        assert!(changed.is_empty());
        // Removed meanwhile, or re-pointed at another URL: nothing is saved.
        assert!(merge_into_stored(&at_start, None, std::slice::from_ref(&def)).is_err());
        let mut moved = at_start.clone();
        moved.url = "https://other.example.com".into();
        assert!(merge_into_stored(&at_start, Some(moved), &[def]).is_err());
    }

    // ── tools/list bounds: an empty cursor ends it, the cap stops it ────

    #[test]
    fn an_empty_cursor_ends_the_list_and_the_tool_cap_stops_reading() {
        let mut seen = std::collections::HashSet::new();
        assert_eq!(
            next_tools_page(&mut seen, 1, 3, Some(String::new())).unwrap(),
            None
        );
        let err =
            next_tools_page(&mut seen, 1, MAX_EXPOSED_TOOLS + 1, Some("more".into())).unwrap_err();
        assert!(err.0.contains(&MAX_EXPOSED_TOOLS.to_string()), "{}", err.0);
        assert!(next_tools_page(&mut seen, 1, MAX_EXPOSED_TOOLS, Some("more".into())).is_ok());
    }

    // ── The call gate (R6) and the call's audit trail ──────

    #[test]
    fn the_call_gate_needs_approval_below_execute_and_names_who_approved() {
        let mut t = tool_pinned_to(&json!({ "name": "t", "description": "d" }), true);
        // Read/Draft: only the user's approval (the card) lets a call through,
        // even for an Auto-approve tool.
        t.auto_approve = true;
        assert!(call_gate("read", false, true, &t).is_err());
        assert_eq!(call_gate("draft", true, true, &t), Ok("approved"));
        // Execute: the card, or the tool's own Auto-approve.
        assert_eq!(call_gate("execute", false, true, &t), Ok("auto"));
        t.auto_approve = false;
        assert!(call_gate("execute", false, true, &t).is_err());
        assert_eq!(call_gate("execute", true, true, &t), Ok("approved"));
        // YOLO runs without either - and the audit row says so.
        assert_eq!(call_gate("yolo", false, true, &t), Ok("yolo"));
        // Never: an unconfirmed server, a disabled tool, a changed or a
        // never-approved definition.
        assert!(call_gate("yolo", true, false, &t).is_err());
        let mut off = t.clone();
        off.enabled = false;
        assert!(call_gate("yolo", true, true, &off).is_err());
        let mut changed = t.clone();
        changed.current_hash = Some("another definition".into());
        assert!(call_gate("yolo", true, true, &changed).is_err());
        let mut unpinned = t.clone();
        unpinned.pin_hash = None;
        assert!(call_gate("yolo", true, true, &unpinned).is_err());
    }

    fn sample_audit() -> CallAudit<'static> {
        CallAudit {
            server_id: "s1",
            server_name: "srv",
            tool: "t",
            args_sha256: "abc",
            level: "execute",
            approval: "approved",
        }
    }

    fn tool_call_rows(db: &crate::db::Database) -> Vec<String> {
        db.list_audit(50)
            .unwrap()
            .into_iter()
            .filter(|r| r.action == "mcp.tool_call")
            .map(|r| r.details)
            .collect()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_tool_that_ran_is_reported_and_audited_even_if_the_refresh_fails() {
        let db = temp_db();
        let result = json!({ "content": [{ "type": "text", "text": "done" }] });
        let out = finish_tool_call(&db, &sample_audit(), true, Ok(result), || async {
            Err(CmdError("tools/list failed".into()))
        })
        .await
        .expect("the tool ran - its result must reach the model");
        assert_eq!(out["content"], "done");
        assert!(
            out["warning"]
                .as_str()
                .unwrap_or_default()
                .contains("tools/list failed"),
            "{out}"
        );
        let rows = tool_call_rows(&db);
        assert!(rows.iter().any(|d| d.contains("result=ok")), "{rows:?}");
    }

    // ── Incremental SSE decoding (A7-50) ────────────────────────────────

    fn decode_all(chunks: &[&[u8]]) -> Vec<SseEvent> {
        let mut decoder = SseDecoder::default();
        let mut out = Vec::new();
        for chunk in chunks {
            out.extend(decoder.push(chunk).unwrap());
        }
        out.extend(decoder.finish().unwrap());
        out
    }

    #[test]
    fn sse_events_decode_the_same_across_any_chunk_boundary() {
        // CRLF, LF and lone-CR line ends, a comment, a multi-line data field
        // and a multi-byte character.
        let body = "event: message\r\ndata: {\"a\":\r\ndata: 1}\r\n\r\n: keep-alive\n\nevent: endpoint\rdata: /messages?x=\u{e9}\r\r";
        let whole = decode_all(&[body.as_bytes()]);
        assert_eq!(
            whole,
            vec![
                SseEvent {
                    event: Some("message".into()),
                    data: "{\"a\":\n1}".into(),
                },
                SseEvent {
                    event: Some("endpoint".into()),
                    data: "/messages?x=\u{e9}".into(),
                },
            ]
        );
        // Split at every byte - inside a CRLF pair and inside the é too.
        let bytes = body.as_bytes();
        for split in 1..bytes.len() {
            assert_eq!(
                decode_all(&[&bytes[..split], &bytes[split..]]),
                whole,
                "split at {split}"
            );
        }
        let one_by_one: Vec<&[u8]> = bytes.chunks(1).collect();
        assert_eq!(decode_all(&one_by_one), whole);
    }

    #[test]
    fn an_unterminated_last_event_still_counts_and_bad_utf8_is_an_error() {
        assert_eq!(
            decode_all(&[b"data: {\"x\":1}"]),
            vec![SseEvent {
                event: None,
                data: "{\"x\":1}".into(),
            }]
        );
        let mut decoder = SseDecoder::default();
        assert!(decoder.push(b"data: \xff\xfe\n").is_err());
    }

    // ── Saving: which auth source survives (pure rules) ─────────────────

    #[test]
    fn saving_keeps_or_drops_the_auth_source_by_the_documented_rules() {
        let mut stored = record_with_tools("s1", "srv", &[]);
        stored.url = "https://a.example.com".into();
        stored.auth_type = "custom_header".into();
        stored.auth_header_name = Some("X-Key".into());
        stored.auth_secret = Some("sealed".into());
        let url = "https://a.example.com";
        let plan = |header: TextArg, secret: SecretArg, env: TextArg| {
            plan_auth(Some(&stored), url, "custom_header", header, secret, env)
        };
        // Nothing about auth touched: the header and the secret stay.
        assert_eq!(
            plan(TextArg::Absent, SecretArg::Absent, TextArg::Absent),
            Ok(AuthPlan {
                header_name: Some("X-Key".into()),
                secret: SecretPlan::Keep,
                env_var: None,
            })
        );
        // Another header name changes what the secret means: it must be
        // entered again - and with a new secret the save goes through.
        let other = || TextArg::Set("X-Other".into());
        assert!(plan(other(), SecretArg::Absent, TextArg::Absent)
            .unwrap_err()
            .contains("discards"));
        assert_eq!(
            plan(other(), SecretArg::New, TextArg::Absent)
                .unwrap()
                .secret,
            SecretPlan::Seal
        );
        // A named env var replaces the stored secret.
        assert_eq!(
            plan(
                TextArg::Absent,
                SecretArg::Absent,
                TextArg::Set("TOKEN".into())
            ),
            Ok(AuthPlan {
                header_name: Some("X-Key".into()),
                secret: SecretPlan::Drop,
                env_var: Some("TOKEN".into()),
            })
        );
        // Auth "none" carries nothing and keeps nothing.
        assert!(plan_auth(
            Some(&stored),
            url,
            "none",
            TextArg::Absent,
            SecretArg::New,
            TextArg::Absent
        )
        .is_err());
        assert_eq!(
            plan_auth(
                Some(&stored),
                url,
                "none",
                TextArg::Clear,
                SecretArg::Clear,
                TextArg::Absent
            ),
            Ok(AuthPlan {
                header_name: None,
                secret: SecretPlan::Drop,
                env_var: None,
            })
        );
    }

    // ── Helpers: concurrent writers, sessions, teardown sinks ───────────

    /// Change the stored record `id` on ANOTHER connection - write `change`
    /// over it, or delete it when `None` - inside `BEGIN IMMEDIATE`, and hold
    /// that write open for `ms` milliseconds before committing: a concurrent
    /// toggle, refresh or removal caught mid-commit. Returns once the write
    /// lock is held.
    fn hold_mcp_change(
        db: &crate::db::Database,
        id: &str,
        change: Option<&crate::db::McpServerRecord>,
        ms: u64,
    ) -> std::thread::JoinHandle<()> {
        let statement = match change {
            Some(record) => (
                "UPDATE mcp_servers SET value = ? WHERE key = ?".to_string(),
                vec![serde_json::to_string(record).unwrap(), id.to_string()],
            ),
            None => (
                "DELETE FROM mcp_servers WHERE key = ?".to_string(),
                vec![id.to_string()],
            ),
        };
        crate::db::test_support::hold_write_bound(db, vec![statement], ms)
    }

    /// How long a test waits for a teardown that unseals a stored secret
    /// first: one Argon2id derivation takes several seconds in a debug build
    /// while the whole suite runs in parallel, and went past 30 s on a
    /// machine also running a coverage build and other test suites. It only
    /// bounds a failure: a passing test waits as long as the unseal takes.
    const UNSEALING_TEARDOWN_WAIT: Duration = Duration::from_secs(120);

    /// How long a test waits for a teardown, a request or a set-up that
    /// unseals nothing - generous, for a machine saturated by other builds
    /// and suites; it only bounds a failure.
    const LOADED_MACHINE_WAIT: Duration = Duration::from_secs(60);

    /// A live session with id `id`.
    fn session(id: &str) -> McpSession {
        McpSession {
            session_id: Some(id.into()),
            protocol_version: "2025-06-18".into(),
        }
    }

    use crate::assistant::test_support::refuse_audit_rows;

    /// A local HTTP endpoint that hands each request head to the returned
    /// receiver and answers 200 after `delay`.
    fn http_sink(delay: Duration) -> (String, std::sync::mpsc::Receiver<String>) {
        use std::io::{Read as _, Write as _};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/mcp", listener.local_addr().unwrap());
        let (seen, requests) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut sock) = stream else { return };
                let seen = seen.clone();
                std::thread::spawn(move || {
                    let mut buf = [0u8; 8192];
                    let n = sock.read(&mut buf).unwrap_or(0);
                    let _ = seen.send(String::from_utf8_lossy(&buf[..n]).into_owned());
                    std::thread::sleep(delay);
                    let _ = sock.write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    );
                });
            }
        });
        (url, requests)
    }

    fn teardown_job(url: &str, session_id: &str) -> TeardownJob {
        TeardownJob {
            url: url.into(),
            session_id: session_id.into(),
            protocol_version: "2025-06-18".into(),
            auth: TeardownAuth::Resolved(None),
            server_name: format!("srv-{session_id}"),
        }
    }

    /// `s1` with one tool `t`, approved (enabled, pinned to `def`).
    fn approved_server(db: &crate::db::Database, def: &Value) -> crate::db::McpServerRecord {
        let mut record = record_with_tools("s1", "srv", &[]);
        record.tools = vec![tool_pinned_to(def, true)];
        db.save_mcp_server(&record).unwrap();
        record
    }

    // ── MCP URLs: no silently dropped query or fragment (A4-23) ─────────

    #[test]
    fn mcp_urls_with_a_query_or_fragment_are_refused() {
        for bad in [
            "https://mcp.example.com/mcp?key=abc",
            "https://mcp.example.com/mcp#section",
            "https://mcp.example.com/mcp?",
            "http://localhost:3000/?route=a",
        ] {
            assert_eq!(
                classify_url(bad).unwrap_err(),
                "MCP server URLs cannot contain ?query or #fragment parts.",
                "{bad}"
            );
        }
        let db = temp_db();
        let err = save(
            &db,
            &unlocked_vault(),
            save_args(None, "q", "https://mcp.example.com/mcp?token=1", "none"),
        )
        .unwrap_err();
        assert!(err.0.contains("?query"), "{}", err.0);
        assert!(db.list_mcp_servers().unwrap().is_empty(), "nothing saved");
        // A path is still kept, and an encoded ? in it is part of the path.
        assert_eq!(
            classify_url("https://mcp.example.com/a%3Fb").unwrap().0,
            "https://mcp.example.com/a%3Fb"
        );
    }

    // ── Read-modify-write of MCP records is one transaction (A7-49) ─────

    /// The enable read the record, then wrote it whole. A
    /// refresh committing a new definition in between was overwritten, and
    /// the stale record went in enabled - the new definition approved
    /// without review.
    #[test]
    fn an_enable_racing_a_definition_change_never_approves_the_new_definition() {
        let db = temp_db();
        let old = json!({ "name": "t", "description": "old" });
        let new = json!({ "name": "t", "description": "new" });
        tool_whose_definition_moved(&db, &old, &old, false);
        let mut refreshed = db.get_mcp_server("s1").unwrap().unwrap();
        refreshed.tools = merge_tools(&refreshed.tools, std::slice::from_ref(&new));
        let holder = hold_mcp_change(&db, "s1", Some(&refreshed), 300);
        let shown = tool_definition_hash(&old);
        let result = set_tool_state(&db, &unlocked_vault(), "s1", "t", true, true, Some(&shown));
        holder.join().unwrap();
        let t = stored_tool_t(&db);
        assert!(
            !t.enabled && !t.auto_approve,
            "the definition changed under the click: nothing may be approved ({t:?})"
        );
        assert_eq!(
            t.current_hash.as_deref(),
            Some(tool_definition_hash(&new).as_str()),
            "the refresh is not lost"
        );
        assert_eq!(result.unwrap_err().0, REAPPROVE);
    }

    /// A toggle that read the record before a removal committed wrote it
    /// back with an upsert - the removed server (and its sealed secret) came
    /// back.
    #[test]
    fn a_tool_toggle_racing_a_removal_does_not_bring_the_server_back() {
        let db = temp_db();
        approved_server(&db, &json!({ "name": "t", "description": "d" }));
        let holder = hold_mcp_change(&db, "s1", None, 300);
        let result = set_tool_state(&db, &unlocked_vault(), "s1", "t", false, false, None);
        holder.join().unwrap();
        assert!(
            db.get_mcp_server("s1").unwrap().is_none(),
            "a removed server stays removed"
        );
        assert_eq!(result.unwrap_err().0, "MCP server not found.");
    }

    /// A save (here a rename) wrote back the whole record it had read: a
    /// tool revoked while it ran came back enabled.
    #[test]
    fn a_save_keeps_a_tool_revoke_that_committed_while_it_ran() {
        let db = temp_db();
        let record = approved_server(&db, &json!({ "name": "t", "description": "d" }));
        let mut revoked = record.clone();
        revoked.tools[0].enabled = false;
        revoked.tools[0].pin_hash = None;
        let holder = hold_mcp_change(&db, "s1", Some(&revoked), 300);
        let result = save(
            &db,
            &unlocked_vault(),
            save_args(Some("s1"), "renamed", "https://mcp.example.com", "none"),
        );
        holder.join().unwrap();
        result.unwrap();
        let stored = db.get_mcp_server("s1").unwrap().unwrap();
        assert_eq!(stored.name, "renamed");
        assert!(
            !stored.tools[0].enabled && stored.tools[0].pin_hash.is_none(),
            "the revoke made meanwhile stays: {:?}",
            stored.tools[0]
        );
    }

    /// The connect (and a call's refresh) re-read the record and saved it as
    /// two statements: a revoke committing in between was overwritten.
    #[test]
    fn a_connect_keeps_a_revoke_that_committed_while_it_stored_the_tools() {
        let db = temp_db();
        let def = json!({ "name": "t", "description": "d" });
        let started_from = approved_server(&db, &def);
        let mut revoked = started_from.clone();
        revoked.tools[0].enabled = false;
        revoked.tools[0].pin_hash = None;
        let holder = hold_mcp_change(&db, "s1", Some(&revoked), 300);
        let stored = store_fetched_tools(&db, &started_from, std::slice::from_ref(&def));
        holder.join().unwrap();
        stored.unwrap();
        let t = stored_tool_t(&db);
        assert!(!t.enabled && t.pin_hash.is_none(), "{t:?}");
    }

    // ── An approval that committed is not reported as failed ──────

    #[test]
    fn an_approval_whose_audit_row_fails_is_reported_as_done_with_a_warning() {
        let db = temp_db();
        let def = json!({ "name": "t", "description": "d" });
        tool_whose_definition_moved(&db, &def, &def, false);
        refuse_audit_rows(&db);
        let shown = tool_definition_hash(&def);
        let out = set_tool_state(&db, &unlocked_vault(), "s1", "t", true, false, Some(&shown))
            .expect("the approval is stored - the call must not report a failure");
        assert_eq!(out["ok"], true);
        let warning = out["warning"].as_str().unwrap_or_default();
        assert!(warning.contains("audit"), "{out}");
        assert!(stored_tool_t(&db).enabled);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_save_or_removal_whose_audit_row_fails_still_reports_success() {
        let db = temp_db();
        let vault = unlocked_vault();
        refuse_audit_rows(&db);
        let saved = save(
            &db,
            &vault,
            save_args(None, "srv", "https://mcp.example.com", "none"),
        )
        .expect("the server is saved - the call must not report a failure");
        assert!(
            saved["warning"]
                .as_str()
                .unwrap_or_default()
                .contains("audit"),
            "{saved}"
        );
        let id = saved_id(saved);
        assert!(db.get_mcp_server(&id).unwrap().is_some());
        let removed = remove_server(&db, &McpState::new(), &vault, &id, REMOVE_TEARDOWN_TIMEOUT)
            .await
            .expect("the server is removed - the call must not report a failure");
        assert!(
            removed["warning"]
                .as_str()
                .unwrap_or_default()
                .contains("audit"),
            "{removed}"
        );
        assert!(db.get_mcp_server(&id).unwrap().is_none());
    }

    // ── A URL or auth edit ends the old session ──────────

    #[tokio::test(flavor = "multi_thread")]
    async fn saving_a_new_url_or_auth_ends_the_old_session_at_the_old_endpoint() {
        let db = temp_db();
        let vault = unlocked_vault();
        let state = McpState::new();
        let (old_url, requests) = http_sink(Duration::ZERO);
        let mut args = save_args(None, "srv", &old_url, "bearer");
        args.auth_secret = Some("old-token".into());
        let id = saved_id(
            crate::commands::as_if_on_pool(|| save_server(&db, &state, &vault, args))
                .unwrap()
                .view,
        );
        state.bind_session(&db.get_mcp_server(&id).unwrap().unwrap(), session("sess-1"));
        let mut moved = save_args(Some(&id), "srv", "https://new.example.com/mcp", "bearer");
        moved.auth_secret = Some("new-token".into());
        let saved =
            crate::commands::as_if_on_pool(|| save_server(&db, &state, &vault, moved)).unwrap();
        assert!(
            state.get_session(&id).is_none(),
            "the next call negotiates against the new endpoint"
        );
        let job = saved.teardown.expect("the old session is torn down");
        assert_eq!(job.url, old_url);
        assert_eq!(job.session_id, "sess-1");
        // The teardown unseals the old credential itself.
        let handles = spawn_teardown_jobs(db.clone(), client_for_tests(), vec![job]);
        assert!(wait_for_teardowns(handles, UNSEALING_TEARDOWN_WAIT).await);
        let head = requests
            .recv_timeout(Duration::from_secs(5))
            .expect("the DELETE reached the old endpoint")
            .to_lowercase();
        assert!(head.starts_with("delete "), "{head}");
        assert!(head.contains("mcp-session-id: sess-1"), "{head}");
        assert!(
            head.contains("authorization: old-token"),
            "the old credential goes to the old origin only: {head}"
        );
        assert!(!head.contains("new-token"), "{head}");
    }

    #[test]
    fn a_rename_keeps_the_live_session() {
        let db = temp_db();
        let vault = unlocked_vault();
        let state = McpState::new();
        let id = saved_id(
            save(
                &db,
                &vault,
                save_args(None, "srv", "https://a.example.com", "none"),
            )
            .unwrap(),
        );
        state.bind_session(&db.get_mcp_server(&id).unwrap().unwrap(), session("sess-1"));
        let saved = save_server(
            &db,
            &state,
            &vault,
            save_args(Some(&id), "renamed", "https://a.example.com", "none"),
        )
        .unwrap();
        assert!(saved.teardown.is_none());
        assert!(state.get_session(&id).is_some());
        // The session still belongs to the renamed record: the next request
        // uses it.
        let renamed = db.get_mcp_server(&id).unwrap().unwrap();
        assert!(state.session_for(&renamed).is_some());
    }

    /// The tests' MCP client: like `origin_client`, with a time limit of its
    /// own (the app's is CALL_TIMEOUT), so a request that stalls fails.
    fn client_for_tests() -> reqwest::Client {
        reqwest::Client::builder()
            .timeout(LOADED_MACHINE_WAIT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap()
    }

    // ── The exit waits for the session teardowns, within a budget ───────

    /// The lock path started the DELETEs and returned nothing to wait for,
    /// so an exit could cut them off. Every teardown now runs as its own
    /// task: a hung server neither delays the others nor holds the exit
    /// past the budget. (The hung server answers after 120 s; every upper
    /// bound here is half that, wide enough for a loaded machine.)
    #[tokio::test(flavor = "multi_thread")]
    async fn the_exit_wait_covers_every_teardown_and_ends_at_its_budget() {
        let db = temp_db();
        let (hung_url, hung_requests) = http_sink(Duration::from_secs(120));
        let (slow_url, slow_requests) = http_sink(Duration::from_millis(300));
        let handles = spawn_teardown_jobs(
            db.clone(),
            client_for_tests(),
            vec![teardown_job(&hung_url, "a"), teardown_job(&slow_url, "b")],
        );
        let started = std::time::Instant::now();
        let all_done = wait_for_teardowns(handles, Duration::from_millis(1500)).await;
        let waited = started.elapsed();
        assert!(!all_done, "the hung teardown is not done");
        assert!(
            waited >= Duration::from_millis(1400) && waited < LOADED_MACHINE_WAIT,
            "the wait ends at its budget, not with the hung DELETE: {waited:?}"
        );
        let (hung_sent, slow_sent) = tokio::task::spawn_blocking(move || {
            (
                hung_requests.recv_timeout(LOADED_MACHINE_WAIT).is_ok(),
                slow_requests.recv_timeout(LOADED_MACHINE_WAIT).is_ok(),
            )
        })
        .await
        .unwrap();
        assert!(hung_sent, "the hung DELETE was sent");
        assert!(
            slow_sent,
            "the other DELETE did not wait behind the hung one"
        );
        // Without a hung server the wait ends as soon as the DELETEs answer.
        let (url, requests) = http_sink(Duration::from_millis(300));
        let handles = spawn_teardown_jobs(
            db.clone(),
            client_for_tests(),
            vec![teardown_job(&url, "c"), teardown_job(&url, "d")],
        );
        let started = std::time::Instant::now();
        assert!(wait_for_teardowns(handles, LOADED_MACHINE_WAIT).await);
        let waited = started.elapsed();
        assert!(
            waited >= Duration::from_millis(250) && waited < LOADED_MACHINE_WAIT,
            "it waited for the answers, not for its budget: {waited:?}"
        );
        assert_eq!(requests.try_iter().count(), 2);
    }

    // ── The call gate is checked again right before tools/call ──────────

    /// A local MCP server for the call path: it reports the JSON-RPC method
    /// of every request (a session DELETE as `DELETE <session id>`), holds
    /// each `initialize` until the test releases it (so the test can change
    /// the stored record while the session is being set up), answers
    /// `notifications/initialized` with 202 and `tools/call` as [`Script`]
    /// says, and a DELETE with 200.
    struct ScriptedMcp {
        url: String,
        methods: std::sync::mpsc::Receiver<String>,
        release_initialize: std::sync::mpsc::Sender<()>,
    }

    /// How [`scripted_mcp_with`] answers.
    #[derive(Default, Clone, Copy)]
    struct Script {
        /// `tools/call` is answered 404 the first time (an expired session).
        expire_first_call: bool,
        /// `tools/call` is answered after this long.
        call_delay: Duration,
        /// `initialize` is answered as an event stream that first announces a
        /// tools/list_changed.
        announce_list_changed: bool,
        /// `tools/call` is answered HTTP 500 (the call fails).
        fail_call: bool,
        /// `tools/list` lists `t1` with the cursor `p2`, and `t2` on page
        /// `p2`. It is reported as `tools/list` or `tools/list p2`.
        tools_pages: bool,
        /// The first `tools/list` for page `p2` is answered 404 (the session
        /// expired mid-listing).
        expire_page_two_once: bool,
        /// Each `initialize` sets up a session of its own (`sess-1`,
        /// `sess-2`, ... instead of `sess-new` every time), and every request
        /// but a DELETE is reported with the session it carried:
        /// `<method> @<session>` (`@-` without one).
        numbered_sessions: bool,
        /// The request reported as this (`tools/call`, `tools/list p2`) is
        /// answered only after a release of its own on `release_initialize`
        /// (releases are taken in the order the waiting requests arrived), so
        /// a test can change the server while that request is out.
        hold: Option<&'static str>,
        /// `initialize` is answered HTTP 500 at once (no release needed).
        fail_initialize: bool,
    }

    /// The password a test's [`SessionScope`] carries: only a teardown that
    /// unseals a stored secret uses it.
    fn test_password() -> Zeroizing<String> {
        Zeroizing::new("test-master-pw".to_string())
    }

    fn test_scope<'a>(
        state: &'a McpState,
        db: &'a crate::db::Database,
        password: &'a Zeroizing<String>,
        guard: &'a (dyn Fn() -> CmdResult<()> + Sync),
    ) -> SessionScope<'a> {
        SessionScope {
            state,
            db,
            password,
            guard,
        }
    }

    fn scripted_mcp(expire_first_call: bool) -> ScriptedMcp {
        scripted_mcp_with(Script {
            expire_first_call,
            ..Script::default()
        })
    }

    fn scripted_mcp_with(script: Script) -> ScriptedMcp {
        use std::io::{Read as _, Write as _};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/mcp", listener.local_addr().unwrap());
        let (seen, methods) = std::sync::mpsc::channel::<String>();
        let (release_initialize, released) = std::sync::mpsc::channel::<()>();
        let released = std::sync::Arc::new(Mutex::new(released));
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let page_two = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let inits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut sock) = stream else { return };
                let (seen, released, calls, page_two, inits) = (
                    seen.clone(),
                    released.clone(),
                    calls.clone(),
                    page_two.clone(),
                    inits.clone(),
                );
                std::thread::spawn(move || {
                    // The request head, then a Content-Length body.
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 8192];
                    let (head_end, length, head) = loop {
                        let n = sock.read(&mut chunk).unwrap_or(0);
                        if n == 0 {
                            return;
                        }
                        buf.extend_from_slice(&chunk[..n]);
                        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            let head = String::from_utf8_lossy(&buf[..end]).to_lowercase();
                            let length = head
                                .lines()
                                .find_map(|l| l.strip_prefix("content-length:"))
                                .and_then(|v| v.trim().parse::<usize>().ok())
                                .unwrap_or(0);
                            break (end + 4, length, head);
                        }
                    };
                    if head.starts_with("delete ") {
                        let header = |name: &str| {
                            head.lines()
                                .find_map(|l| l.strip_prefix(name))
                                .map(|v| v.trim().to_string())
                        };
                        let session = header("mcp-session-id:").unwrap_or_default();
                        // The credential the DELETE carries, if any
                        // (lowercased, like the whole head).
                        let auth = header("authorization:")
                            .map(|v| format!(" auth={v}"))
                            .unwrap_or_default();
                        let _ = seen.send(format!("DELETE {session}{auth}"));
                        let _ = sock.write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        );
                        return;
                    }
                    while buf.len() < head_end + length {
                        let n = sock.read(&mut chunk).unwrap_or(0);
                        if n == 0 {
                            break;
                        }
                        buf.extend_from_slice(&chunk[..n]);
                    }
                    let request: Value =
                        serde_json::from_slice(&buf[head_end..]).unwrap_or(Value::Null);
                    let method = request["method"].as_str().unwrap_or_default().to_string();
                    let cursor = request["params"]["cursor"].as_str().map(String::from);
                    let report = match &cursor {
                        Some(cursor) if method == "tools/list" => format!("{method} {cursor}"),
                        _ => method.clone(),
                    };
                    let held = script.hold == Some(report.as_str());
                    let _ = seen.send(if script.numbered_sessions {
                        let carried = head
                            .lines()
                            .find_map(|l| l.strip_prefix("mcp-session-id:"))
                            .map_or("-".to_string(), |v| v.trim().to_string());
                        format!("{report} @{carried}")
                    } else {
                        report
                    });
                    if held {
                        let _ = released.lock().unwrap().recv_timeout(LOADED_MACHINE_WAIT);
                    }
                    let json_reply = |body: Value, extra: &str| {
                        let body = body.to_string();
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{extra}\
                             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        )
                    };
                    let status_reply = |code: u16| {
                        format!(
                            "HTTP/1.1 {code} X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        )
                    };
                    let reply = match method.as_str() {
                        "initialize" if script.fail_initialize => status_reply(500),
                        "initialize" => {
                            let _ = released.lock().unwrap().recv_timeout(LOADED_MACHINE_WAIT);
                            let session = if script.numbered_sessions {
                                let n = inits.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                                format!("sess-{n}")
                            } else {
                                "sess-new".to_string()
                            };
                            let answer = json!({ "jsonrpc": "2.0", "id": request["id"],
                                "result": { "protocolVersion": "2025-06-18", "capabilities": {} } });
                            if script.announce_list_changed {
                                let changed = json!({ "jsonrpc": "2.0",
                                    "method": "notifications/tools/list_changed" });
                                let body = format!(
                                    "event: message\ndata: {changed}\n\nevent: message\ndata: {answer}\n\n"
                                );
                                format!(
                                    "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\
                                     Mcp-Session-Id: {session}\r\nContent-Length: {}\r\n\
                                     Connection: close\r\n\r\n{body}",
                                    body.len()
                                )
                            } else {
                                json_reply(answer, &format!("Mcp-Session-Id: {session}\r\n"))
                            }
                        }
                        "notifications/initialized" => status_reply(202),
                        "tools/list" if script.tools_pages => {
                            let tool = |name: &str| {
                                json!({ "name": name, "description": "d",
                                        "inputSchema": { "type": "object" } })
                            };
                            match cursor.as_deref() {
                                Some("p2")
                                    if script.expire_page_two_once
                                        && page_two
                                            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                                            == 0 =>
                                {
                                    status_reply(404)
                                }
                                Some("p2") => json_reply(
                                    json!({ "jsonrpc": "2.0", "id": request["id"],
                                            "result": { "tools": [tool("t2")] } }),
                                    "",
                                ),
                                _ => json_reply(
                                    json!({ "jsonrpc": "2.0", "id": request["id"],
                                            "result": { "tools": [tool("t1")],
                                                        "nextCursor": "p2" } }),
                                    "",
                                ),
                            }
                        }
                        "tools/call" if script.fail_call => status_reply(500),
                        "tools/call"
                            if script.expire_first_call
                                && calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 =>
                        {
                            status_reply(404)
                        }
                        "tools/call" => {
                            std::thread::sleep(script.call_delay);
                            json_reply(
                                json!({ "jsonrpc": "2.0", "id": request["id"], "result": {
                                    "content": [{ "type": "text", "text": "ran" }] } }),
                                "",
                            )
                        }
                        _ => status_reply(400),
                    };
                    let _ = sock.write_all(reply.as_bytes());
                });
            }
        });
        ScriptedMcp {
            url,
            methods,
            release_initialize,
        }
    }

    /// `s1` with tool `t` approved, pointing at `url`; the context a call
    /// starts from (no generation check: `u64::MAX` marks a test context).
    fn call_fixture(
        db: &crate::db::Database,
        url: &str,
        session: Option<McpSession>,
    ) -> (crate::db::McpServerRecord, ServerContext) {
        let mut record = record_with_tools("s1", "srv", &[]);
        record.url = url.into();
        record.tools = vec![tool_pinned_to(
            &json!({ "name": "t", "description": "d" }),
            true,
        )];
        db.save_mcp_server(&record).unwrap();
        let ctx = ServerContext {
            record: record.clone(),
            url: url.into(),
            client: client_for_tests(),
            session,
            auth: None,
            generation: u64::MAX,
        };
        (record, ctx)
    }

    fn tool_call_body() -> Value {
        json!({ "jsonrpc": "2.0", "id": "call-1", "method": "tools/call",
                "params": { "name": "t", "arguments": {} } })
    }

    /// `fut`, or a failure saying `what` did not finish within
    /// [`LOADED_MACHINE_WAIT`]: a stall fails the test instead of hanging the
    /// whole run (round 6).
    async fn bounded<F: std::future::Future>(what: &str, fut: F) -> F::Output {
        tokio::time::timeout(LOADED_MACHINE_WAIT, fut)
            .await
            .unwrap_or_else(|_| panic!("{what} did not finish within {LOADED_MACHINE_WAIT:?}"))
    }

    /// Wait (without blocking the runtime) until the server has seen `method`.
    async fn wait_for_method(server: &ScriptedMcp, method: &str) {
        let deadline = std::time::Instant::now() + LOADED_MACHINE_WAIT;
        loop {
            if server.methods.try_iter().any(|m| m == method) {
                return;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "{method} never arrived"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    /// The gate was checked before the session set-up only: a tool revoked
    /// while `initialize` was in flight was still called.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_tool_revoked_while_the_session_is_set_up_is_never_called() {
        let db = temp_db();
        let server = scripted_mcp(false);
        let (record, mut ctx) = call_fixture(&db, &server.url, None);
        let state = McpState::new();
        // Approved on the card at Execute: the gate passes when the call starts.
        let regate = || regate_call(&db, &record, "t", "execute", true);
        let body = tool_call_body();
        let unchecked = || -> CmdResult<()> { Ok(()) };
        let pw = test_password();
        let scope = test_scope(&state, &db, &pw, &unchecked);
        let call = run_tool_call(&scope, &mut ctx, &body, &regate);
        let revoke = async {
            wait_for_method(&server, "initialize").await;
            set_tool_state(&db, &unlocked_vault(), "s1", "t", false, false, None).unwrap();
            server.release_initialize.send(()).unwrap();
        };
        let (sent, ()) = bounded("the request and the change racing it", async {
            tokio::join!(call, revoke)
        })
        .await;
        let later: Vec<String> = server.methods.try_iter().collect();
        assert!(
            !later.iter().any(|m| m == "tools/call"),
            "a revoked tool must not be called: {later:?}"
        );
        match sent {
            Ok(CallSent::Refused { reason, level, .. }) => {
                assert!(reason.contains("not enabled"), "{reason}");
                assert_eq!(level, "execute");
            }
            other => panic!("refused before the call: {other:?}"),
        }
    }

    /// The same for the re-initialize after a 404 (the session had expired):
    /// a definition the server changed meanwhile is not called on the retry.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_tool_changed_while_an_expired_session_is_renewed_is_not_called_again() {
        let db = temp_db();
        let server = scripted_mcp(true);
        let (record, mut ctx) = call_fixture(&db, &server.url, Some(session("sess-old")));
        let state = McpState::new();
        let regate = || regate_call(&db, &record, "t", "yolo", false);
        let body = tool_call_body();
        let unchecked = || -> CmdResult<()> { Ok(()) };
        let pw = test_password();
        let scope = test_scope(&state, &db, &pw, &unchecked);
        let call = run_tool_call(&scope, &mut ctx, &body, &regate);
        let change = async {
            wait_for_method(&server, "initialize").await;
            let mut changed = db.get_mcp_server("s1").unwrap().unwrap();
            changed.tools[0].current_hash = Some("a definition nobody approved".into());
            db.save_mcp_server(&changed).unwrap();
            server.release_initialize.send(()).unwrap();
        };
        let (sent, ()) = bounded("the request and the change racing it", async {
            tokio::join!(call, change)
        })
        .await;
        let later: Vec<String> = server.methods.try_iter().collect();
        assert!(
            !later.iter().any(|m| m == "tools/call"),
            "only the expired call went out: {later:?}"
        );
        match sent {
            Ok(CallSent::Refused { reason, .. }) => {
                assert!(reason.contains("changed on the server"), "{reason}")
            }
            other => panic!("refused before the retry: {other:?}"),
        }
    }

    /// Unchanged state: the call goes out once and its answer comes back, with
    /// the label of who let it run.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_unchanged_tool_is_called_after_the_session_is_set_up() {
        let db = temp_db();
        let server = scripted_mcp(false);
        let (record, mut ctx) = call_fixture(&db, &server.url, None);
        let state = McpState::new();
        server.release_initialize.send(()).unwrap();
        let regate = || regate_call(&db, &record, "t", "execute", true);
        let unchecked = || -> CmdResult<()> { Ok(()) };
        let pw = test_password();
        let scope = test_scope(&state, &db, &pw, &unchecked);
        let sent = bounded(
            "the call",
            run_tool_call(&scope, &mut ctx, &tool_call_body(), &regate),
        )
        .await
        .unwrap();
        match sent {
            CallSent::Sent {
                approval,
                level,
                list_changed: false,
                called: Ok(result),
            } => {
                assert_eq!((approval, level.as_str()), ("approved", "execute"));
                assert_eq!(shape_tool_result(&result).0, "ran");
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(
            state
                .get_session("s1")
                .and_then(|s| s.session_id)
                .as_deref(),
            Some("sess-new")
        );
        let seen: Vec<String> = server.methods.try_iter().collect();
        assert_eq!(
            seen,
            ["initialize", "notifications/initialized", "tools/call"]
        );
    }

    /// What the exit waits for: every teardown task still running - the lock
    /// path's and a stale session's - kept in McpState; finished ones are
    /// dropped, and each is handed out once.
    #[tokio::test(flavor = "multi_thread")]
    async fn running_teardowns_are_kept_for_the_exit_and_finished_ones_dropped() {
        let state = McpState::new();
        let finished = tauri::async_runtime::spawn(async {});
        while !finished.inner().is_finished() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        state.track_teardowns(vec![finished]);
        let running = tauri::async_runtime::spawn(async {
            tokio::time::sleep(Duration::from_secs(30)).await;
        });
        state.track_teardowns(vec![running]);
        let pending = state.take_teardowns();
        assert_eq!(pending.len(), 1, "the finished teardown was dropped");
        assert!(state.take_teardowns().is_empty(), "handed out once");
        assert!(!wait_for_teardowns(pending, Duration::from_millis(100)).await);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_failed_call_is_still_audited() {
        let db = temp_db();
        let err = finish_tool_call(
            &db,
            &sample_audit(),
            false,
            Err(CmdError("MCP request failed: timed out".into())),
            || async { Ok(()) },
        )
        .await
        .unwrap_err();
        assert!(err.0.contains("timed out"));
        let rows = tool_call_rows(&db);
        assert!(rows.iter().any(|d| d.contains("result=failed")), "{rows:?}");
    }

    // ── A session belongs to the settings it was set up with

    /// A URL edit that landed while a call set up its session
    /// left that session - the OLD endpoint's - registered for the server
    /// after the re-check refused the call; the next call sent its id to the
    /// NEW endpoint, and it was never ended. A refused call ends the session
    /// it set up, at the endpoint the session belongs to.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_call_refused_after_an_edit_ends_the_session_it_set_up_at_the_old_endpoint() {
        let db = temp_db();
        let server = scripted_mcp(false);
        let (record, mut ctx) = call_fixture(&db, &server.url, None);
        let state = McpState::new();
        let regate = || regate_call(&db, &record, "t", "execute", true);
        let body = tool_call_body();
        let unchecked = || -> CmdResult<()> { Ok(()) };
        let pw = test_password();
        let scope = test_scope(&state, &db, &pw, &unchecked);
        let call = run_tool_call(&scope, &mut ctx, &body, &regate);
        let edit = async {
            wait_for_method(&server, "initialize").await;
            let saved = save_server(
                &db,
                &state,
                &unlocked_vault(),
                save_args(Some("s1"), "srv", "https://new.example.com/mcp", "none"),
            )
            .unwrap();
            assert!(
                saved.teardown.is_none(),
                "no session existed when the save ran"
            );
            server.release_initialize.send(()).unwrap();
        };
        let (sent, ()) = bounded("the request and the change racing it", async {
            tokio::join!(call, edit)
        })
        .await;
        match sent {
            Ok(CallSent::Refused { reason, .. }) => {
                assert!(reason.contains("URL or auth settings changed"), "{reason}")
            }
            other => panic!("{other:?}"),
        }
        assert!(
            state.get_session("s1").is_none(),
            "the old endpoint's session is not left for the next call"
        );
        assert!(wait_for_teardowns(state.take_teardowns(), LOADED_MACHINE_WAIT).await);
        let seen: Vec<String> = server.methods.try_iter().collect();
        assert!(
            seen.iter().any(|m| m == "DELETE sess-new"),
            "ended at the old endpoint: {seen:?}"
        );
    }

    /// The next request took a server's session by server id alone, so a
    /// session set up with settings the server no longer has (an edit raced
    /// its set-up) went to the new endpoint. A request uses only a session
    /// set up with its own settings; a stale one is ended where it belongs,
    /// with its own credential.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_session_set_up_with_other_settings_is_never_used_and_is_ended_where_it_belongs() {
        let db = temp_db();
        let vault = unlocked_vault();
        let state = McpState::new();
        let (old_url, old_requests) = http_sink(Duration::ZERO);
        let mut args = save_args(None, "srv", &old_url, "bearer");
        args.auth_secret = Some("old-token".into());
        let id = saved_id(save(&db, &vault, args).unwrap());
        let old = db.get_mcp_server(&id).unwrap().unwrap();
        // The edit commits first; the session set up with the old settings
        // registers after it.
        let mut moved = save_args(Some(&id), "srv", "https://new.example.com/mcp", "bearer");
        moved.auth_secret = Some("new-token".into());
        save(&db, &vault, moved).unwrap();
        state.bind_session(&old, session("sess-old"));
        let new = db.get_mcp_server(&id).unwrap().unwrap();
        let pw = vault.get().unwrap();
        assert!(
            usable_session(&state, &db, &new, &pw).is_none(),
            "never used for the new settings"
        );
        assert!(state.get_session(&id).is_none(), "and not left registered");
        assert!(wait_for_teardowns(state.take_teardowns(), UNSEALING_TEARDOWN_WAIT).await);
        let head = old_requests
            .recv_timeout(Duration::from_secs(5))
            .expect("ended at the old endpoint")
            .to_lowercase();
        assert!(head.starts_with("delete "), "{head}");
        assert!(head.contains("mcp-session-id: sess-old"), "{head}");
        assert!(
            head.contains("authorization: old-token"),
            "with the old credential: {head}"
        );
        // A session of the stored settings is used. A request that still
        // holds an OLDER snapshot neither uses it nor ends it.
        state.bind_session(&new, session("sess-new"));
        assert_eq!(
            usable_session(&state, &db, &new, &pw).and_then(|s| s.session_id),
            Some("sess-new".to_string())
        );
        assert!(usable_session(&state, &db, &old, &pw).is_none());
        assert_eq!(
            state.get_session(&id).and_then(|s| s.session_id),
            Some("sess-new".to_string())
        );
    }

    /// The settings of `s1`: first `old_url` with bearer `old-token`, then -
    /// after a session was set up with those - `new_url` with `new-token`.
    fn server_moved_after_set_up(
        db: &crate::db::Database,
        vault: &VaultPasswordStore,
        state: &McpState,
        old_url: &str,
        new_url: &str,
    ) -> String {
        let mut args = save_args(None, "srv", old_url, "bearer");
        args.auth_secret = Some("old-token".into());
        let id = saved_id(save(db, vault, args).unwrap());
        state.bind_session(
            &db.get_mcp_server(&id).unwrap().unwrap(),
            session("sess-old"),
        );
        let mut moved = save_args(Some(&id), "srv", new_url, "bearer");
        moved.auth_secret = Some("new-token".into());
        save(db, vault, moved).unwrap();
        id
    }

    /// Removing a server ended its session at the record's CURRENT URL with
    /// its current credential - for a session set up with older settings the
    /// wrong endpoint, which never knew it.
    #[tokio::test(flavor = "multi_thread")]
    async fn removing_a_server_ends_its_session_where_it_was_set_up() {
        let db = temp_db();
        let vault = unlocked_vault();
        let state = McpState::new();
        let (old_url, old_requests) = http_sink(Duration::ZERO);
        let (new_url, new_requests) = http_sink(Duration::ZERO);
        let id = server_moved_after_set_up(&db, &vault, &state, &old_url, &new_url);
        // The DELETE's limit, wide for a loaded machine: a DELETE that timed
        // out would come back as a warning.
        let out = remove_server(&db, &state, &vault, &id, LOADED_MACHINE_WAIT)
            .await
            .unwrap();
        assert!(out["warning"].is_null(), "{out}");
        let head = old_requests
            .recv_timeout(Duration::from_secs(5))
            .expect("ended at the old endpoint")
            .to_lowercase();
        assert!(head.contains("mcp-session-id: sess-old"), "{head}");
        assert!(head.contains("authorization: old-token"), "{head}");
        assert!(
            new_requests.try_recv().is_err(),
            "the new endpoint never knew the session"
        );
    }

    /// The same for the lock: each session went to its record's current URL.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_lock_ends_each_session_where_it_was_set_up() {
        let db = temp_db();
        let vault = unlocked_vault();
        let state = McpState::new();
        let (old_url, old_requests) = http_sink(Duration::ZERO);
        let (new_url, new_requests) = http_sink(Duration::ZERO);
        server_moved_after_set_up(&db, &vault, &state, &old_url, &new_url);
        let password = vault.get().map(std::sync::Arc::new);
        end_sessions(&state, db.clone(), password, state.take_sessions());
        assert!(wait_for_teardowns(state.take_teardowns(), UNSEALING_TEARDOWN_WAIT).await);
        let head = old_requests
            .recv_timeout(Duration::from_secs(5))
            .expect("ended at the old endpoint")
            .to_lowercase();
        assert!(head.contains("mcp-session-id: sess-old"), "{head}");
        assert!(head.contains("authorization: old-token"), "{head}");
        assert!(new_requests.try_recv().is_err());
    }

    /// A connect whose settings changed meanwhile removed the server's
    /// session by server id alone - possibly a newer one another request had
    /// set up - and never ended the one it had set up itself.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_failed_connect_ends_only_the_session_it_set_up() {
        let db = temp_db();
        let (url, requests) = http_sink(Duration::ZERO);
        let state = McpState::new();
        let (record, mut ctx) = call_fixture(&db, &url, Some(session("sess-mine")));
        ctx.auth = Some(("Authorization".into(), Zeroizing::new("tok".into())));
        // Another request registered a newer session meanwhile: it stays.
        state.bind_session(&record, session("sess-newer"));
        end_ctx_session(&state, &db, &ctx);
        assert_eq!(
            state.get_session("s1").and_then(|s| s.session_id),
            Some("sess-newer".to_string())
        );
        assert!(wait_for_teardowns(state.take_teardowns(), LOADED_MACHINE_WAIT).await);
        assert!(requests.try_recv().is_err(), "nothing was ended");
        // Its own session is removed, and ended where it was set up, with
        // its credential.
        state.bind_session(&record, session("sess-mine"));
        end_ctx_session(&state, &db, &ctx);
        assert!(state.get_session("s1").is_none());
        assert!(wait_for_teardowns(state.take_teardowns(), LOADED_MACHINE_WAIT).await);
        let head = requests
            .recv_timeout(Duration::from_secs(5))
            .expect("the session was ended")
            .to_lowercase();
        assert!(head.contains("mcp-session-id: sess-mine"), "{head}");
        assert!(head.contains("authorization: tok"), "{head}");
    }

    /// The lock unsealed every live session's secret before it returned - an
    /// Argon2id derivation each (about 0.75 s in a release build), on the
    /// main thread - so Lock froze the window, and an exit spent that time
    /// before its 2 s wait began. Each teardown task now unseals its own, on
    /// a copy of the password that goes as soon as the header is resolved.
    /// The test holds every unseal permit while the lock runs, so no unseal
    /// can start before it returns (it used to compare the lock's time with
    /// one unseal's, which a loaded machine could upset).
    #[tokio::test(flavor = "multi_thread")]
    async fn the_lock_returns_before_any_secret_is_unsealed_and_lets_go_of_its_password_copy() {
        let db = temp_db();
        let vault = unlocked_vault();
        let state = std::sync::Arc::new(McpState::new());
        // The DELETE is still unanswered when the sink reports it.
        let (url, requests) = http_sink(Duration::from_secs(2));
        let mut args = save_args(None, "srv", &url, "bearer");
        args.auth_secret = Some("the-token".into());
        let id = saved_id(save(&db, &vault, args).unwrap());
        let record = db.get_mcp_server(&id).unwrap().unwrap();
        state.bind_session(&record, session("sess-1"));
        let password = std::sync::Arc::new(vault.get().unwrap());
        let copy = std::sync::Arc::downgrade(&password);
        let no_unseal_can_start = unseal_permits()
            .acquire_many(MAX_PARALLEL_UNSEALS as u32)
            .await
            .unwrap();
        let (lock_state, lock_db) = (state.clone(), db.clone());
        let lock = tokio::task::spawn_blocking(move || {
            end_sessions(
                &lock_state,
                lock_db,
                Some(password),
                lock_state.take_sessions(),
            )
        });
        let returned = tokio::time::timeout(LOADED_MACHINE_WAIT, lock).await;
        let header_pending = copy.upgrade().is_some();
        drop(no_unseal_can_start);
        assert!(
            matches!(returned, Ok(Ok(()))),
            "the lock returned while no unseal could run"
        );
        assert!(
            header_pending,
            "the lock left the header to its teardown, which still holds the password copy"
        );
        let head =
            tokio::task::spawn_blocking(move || requests.recv_timeout(UNSEALING_TEARDOWN_WAIT))
                .await
                .unwrap()
                .expect("the DELETE went out")
                .to_lowercase();
        assert!(head.contains("mcp-session-id: sess-1"), "{head}");
        assert!(
            head.contains("authorization: the-token"),
            "with its credential: {head}"
        );
        assert!(
            copy.upgrade().is_none(),
            "the password copy is gone once the header is resolved"
        );
        assert!(wait_for_teardowns(state.take_teardowns(), LOADED_MACHINE_WAIT).await);
    }

    /// The tool-call audit row took the tab's level read AFTER the call
    /// answered: a YOLO call that ended after a switch to Read (or a lock)
    /// was logged as `level=read outcome=yolo`. It is the level the gate
    /// checked right before the request.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_call_is_audited_at_the_level_the_gate_checked_before_it() {
        let db = temp_db();
        let server = scripted_mcp_with(Script {
            call_delay: Duration::from_millis(300),
            ..Script::default()
        });
        let (record, mut ctx) = call_fixture(&db, &server.url, None);
        let state = McpState::new();
        server.release_initialize.send(()).unwrap();
        let tab_level = Mutex::new("yolo".to_string());
        let regate = || {
            let level = tab_level.lock().unwrap().clone();
            regate_call(&db, &record, "t", &level, false)
        };
        let body = tool_call_body();
        let unchecked = || -> CmdResult<()> { Ok(()) };
        let pw = test_password();
        let scope = test_scope(&state, &db, &pw, &unchecked);
        let call = run_tool_call(&scope, &mut ctx, &body, &regate);
        let switch = async {
            wait_for_method(&server, "tools/call").await;
            *tab_level.lock().unwrap() = "read".into();
        };
        let (sent, ()) = bounded("the request and the change racing it", async {
            tokio::join!(call, switch)
        })
        .await;
        match sent {
            Ok(CallSent::Sent {
                approval,
                level,
                called: Ok(_),
                ..
            }) => assert_eq!((approval, level.as_str()), ("yolo", "yolo")),
            other => panic!("{other:?}"),
        }
    }

    /// A tools/list_changed that came with the initialize
    /// answer was dropped on the call path, so a definition change announced
    /// while SSHSpan was closed was never acted on - no refresh after the
    /// call, the changed tool still enabled. It counts as the call's own now,
    /// on the first set-up and on a renewal after a 404 alike.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_list_change_announced_with_the_initialize_answer_brings_the_refresh() {
        for expired in [false, true] {
            let db = temp_db();
            let server = scripted_mcp_with(Script {
                announce_list_changed: true,
                expire_first_call: expired,
                ..Script::default()
            });
            let existing = expired.then(|| session("sess-old"));
            let (record, mut ctx) = call_fixture(&db, &server.url, existing);
            let state = McpState::new();
            server.release_initialize.send(()).unwrap();
            let regate = || regate_call(&db, &record, "t", "execute", true);
            let unchecked = || -> CmdResult<()> { Ok(()) };
            let pw = test_password();
            let scope = test_scope(&state, &db, &pw, &unchecked);
            let sent = bounded(
                "the call",
                run_tool_call(&scope, &mut ctx, &tool_call_body(), &regate),
            )
            .await
            .unwrap();
            assert!(
                matches!(
                    sent,
                    CallSent::Sent {
                        list_changed: true,
                        called: Ok(_),
                        ..
                    }
                ),
                "expired session: {expired}, {sent:?}"
            );
        }
    }

    /// A save dropped the live session INSIDE its
    /// transaction. When the write then failed, the old settings stayed - and
    /// their session was gone, and never ended. It is dropped only once the
    /// save has committed.
    #[test]
    fn a_save_that_does_not_commit_keeps_the_live_session() {
        let db = temp_db();
        let vault = unlocked_vault();
        let state = McpState::new();
        let id = saved_id(
            save(
                &db,
                &vault,
                save_args(None, "srv", "https://a.example.com/mcp", "none"),
            )
            .unwrap(),
        );
        state.bind_session(&db.get_mcp_server(&id).unwrap().unwrap(), session("sess-1"));
        crate::db::test_support::execute(
            &db,
            "CREATE TRIGGER refuse_mcp_update BEFORE UPDATE ON mcp_servers \
             BEGIN SELECT RAISE(ABORT, 'refused by the test'); END",
        );
        let result = save_server(
            &db,
            &state,
            &vault,
            save_args(Some(&id), "srv", "https://b.example.com/mcp", "none"),
        );
        assert!(result.is_err(), "the refused write fails the save");
        assert_eq!(
            db.get_mcp_server(&id).unwrap().unwrap().url,
            "https://a.example.com/mcp"
        );
        assert_eq!(
            state.get_session(&id).and_then(|s| s.session_id),
            Some("sess-1".to_string()),
            "the session of the settings that stayed is kept"
        );
    }

    // ── A credential goes to a new place only when the user allows it in a
    //    native dialog ────────────────────────────────────────────────────

    /// Answers every question with `answer` (true: "Allow") and keeps the
    /// questions asked.
    struct Asked {
        answer: CredentialAnswer,
        prompts: Mutex<Vec<CredentialPrompt>>,
    }

    impl Asked {
        fn new(allow: bool) -> Self {
            Self::answering(if allow {
                CredentialAnswer::Allowed
            } else {
                CredentialAnswer::NotAllowed
            })
        }

        fn answering(answer: CredentialAnswer) -> Self {
            Self {
                answer,
                prompts: Mutex::new(Vec::new()),
            }
        }

        fn ask(&self) -> impl Fn(&CredentialPrompt) -> CredentialAnswer + '_ {
            move |prompt| {
                self.prompts.lock().unwrap().push(prompt.clone());
                self.answer
            }
        }

        fn messages(&self) -> Vec<String> {
            self.prompts
                .lock()
                .unwrap()
                .iter()
                .map(|p| p.message.clone())
                .collect()
        }
    }

    fn audit_rows(db: &crate::db::Database, action: &str) -> Vec<String> {
        db.list_audit(50)
            .unwrap()
            .into_iter()
            .filter(|r| r.action == action)
            .map(|r| r.details)
            .collect()
    }

    /// The attack: a renderer saved a server that sends the value of
    /// AWS_SECRET_ACCESS_KEY to a host of its choosing and got it marked
    /// confirmed. The record now stays switched off - connect and call
    /// refuse it, as for a restored one - until the user allows it in the
    /// native dialog that names the variable and the host.
    #[test]
    fn rw_s2_a_new_server_with_an_env_var_stays_off_until_the_native_question_allows_it() {
        let db = temp_db();
        let vault = unlocked_vault();
        let state = McpState::new();
        let rotation = VaultRotationLock::new();
        let args = || {
            let mut args = save_args(None, "aws", "https://mcp.example.com/mcp", "bearer");
            args.auth_env_var = Some("AWS_SECRET_ACCESS_KEY".into());
            args
        };
        let declined = Asked::new(false);
        let saved =
            save_and_settle(&db, &state, &vault, &rotation, args(), &declined.ask()).unwrap();
        let asked = declined.messages();
        assert_eq!(asked.len(), 1, "asked once: {asked:?}");
        assert!(
            asked[0].starts_with(
                "SSHSpan will send the value of the environment variable AWS_SECRET_ACCESS_KEY \
                 to mcp.example.com as an Authorization header. Allow?"
            ),
            "{}",
            asked[0]
        );
        assert!(
            asked[0].contains("https://mcp.example.com/mcp"),
            "{}",
            asked[0]
        );
        assert_eq!(saved.view["ok"], true);
        assert_eq!(saved.view["confirmed"], false);
        let warning = saved.view["warning"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        assert!(
            warning.contains("mcp.example.com") && warning.contains("Save it again"),
            "{warning}"
        );
        let id = saved_id(saved.view);
        let stored = db.get_mcp_server(&id).unwrap().unwrap();
        assert!(!stored.confirmed, "inert until the user allows it");
        let tool = tool_pinned_to(&json!({ "name": "t", "description": "d" }), true);
        assert!(call_gate("yolo", true, stored.confirmed, &tool).is_err());
        assert_eq!(
            audit_rows(&db, "mcp.credential_declined"),
            vec!["server=aws host=mcp.example.com sends=env:AWS_SECRET_ACCESS_KEY".to_string()]
        );
        // Saved again and allowed: confirmed.
        let allowed = Asked::new(true);
        let mut again = args();
        again.id = Some(id.clone());
        let saved = save_and_settle(&db, &state, &vault, &rotation, again, &allowed.ask()).unwrap();
        assert_eq!(allowed.messages().len(), 1);
        assert_eq!(saved.view["confirmed"], true);
        assert_eq!(saved.view["warning"], Value::Null);
        assert!(db.get_mcp_server(&id).unwrap().unwrap().confirmed);
        assert_eq!(audit_rows(&db, "mcp.credential_allowed").len(), 1);
    }

    /// Which saves are asked about: those that bind a secret or a variable to
    /// a place it was not bound to (a new server, another address, another
    /// variable, a credential where there was none) - not a rename, the same
    /// variable again, or a new token for the same place.
    #[test]
    fn rw_s2_only_a_credential_bound_to_a_new_place_is_asked_about() {
        let db = temp_db();
        let vault = unlocked_vault();
        let state = McpState::new();
        let rotation = VaultRotationLock::new();
        let asked = Asked::new(true);
        let ask = asked.ask();
        let step = |args: SaveServerArgs| -> (Value, usize) {
            let before = asked.messages().len();
            let saved = save_and_settle(&db, &state, &vault, &rotation, args, &ask).unwrap();
            (saved.view, asked.messages().len() - before)
        };
        let a = "https://a.example.com/mcp";
        let (out, n) = step(save_args(None, "srv", a, "none"));
        assert_eq!((n, out["confirmed"].clone()), (0, json!(true)), "no auth");
        let id = saved_id(out);
        let with = |url: &str, secret: Option<&str>, var: Option<&str>| {
            let mut args = save_args(Some(&id), "srv", url, "bearer");
            args.auth_secret = secret.map(String::from);
            args.auth_env_var = var.map(String::from);
            args
        };
        assert_eq!(
            step(with(a, Some("tok-1"), None)).1,
            1,
            "a credential where there was none"
        );
        assert_eq!(
            step(with(a, Some("tok-2"), None)).1,
            0,
            "a new token for the same place"
        );
        let (out, n) = step(with(a, None, None));
        assert_eq!(
            (n, out["confirmed"].clone()),
            (0, json!(true)),
            "the secret kept"
        );
        let mut renamed = with(a, None, None);
        renamed.name = "srv2".into();
        assert_eq!(step(renamed).1, 0, "a rename");
        assert_eq!(
            step(with(a, None, Some("TOKEN_X"))).1,
            1,
            "a variable instead of the secret"
        );
        assert_eq!(
            step(with(a, None, Some("TOKEN_X"))).1,
            0,
            "the same variable again"
        );
        assert_eq!(
            step(with(a, None, Some("TOKEN_Y"))).1,
            1,
            "another variable"
        );
        assert_eq!(
            step(with("https://b.example.com/mcp", None, Some("TOKEN_Y"))).1,
            1,
            "the variable kept for another address"
        );
        let mut custom = save_args(
            None,
            "other",
            "https://c.example.com:8443/mcp",
            "custom_header",
        );
        custom.auth_header_name = Some("X-Api-Key".into());
        custom.auth_secret = Some("k".into());
        let (_, n) = step(custom);
        assert_eq!(n, 1, "a new server with a secret");
        let last = asked.messages().pop().unwrap();
        assert!(
            last.starts_with(
                "SSHSpan will send the secret saved for this MCP server to c.example.com:8443 \
                 as the X-Api-Key header. Allow?"
            ),
            "{last}"
        );
    }

    /// A restored (or declined) record stays unconfirmed until a save is
    /// allowed: saving it unchanged asks again, and a "no" keeps it off.
    #[test]
    fn rw_s2_a_restored_server_is_asked_about_when_it_is_saved_again() {
        let db = temp_db();
        let vault = unlocked_vault();
        let state = McpState::new();
        let rotation = VaultRotationLock::new();
        let mut restored = record_with_tools("r1", "restored", &[]);
        restored.auth_type = "bearer".into();
        restored.auth_env_var = Some("GITHUB_TOKEN".into());
        restored.confirmed = false;
        db.save_mcp_server(&restored).unwrap();
        let declined = Asked::new(false);
        let saved = save_and_settle(
            &db,
            &state,
            &vault,
            &rotation,
            save_args(Some("r1"), "restored", "https://mcp.example.com", "bearer"),
            &declined.ask(),
        )
        .unwrap();
        assert_eq!(declined.messages().len(), 1);
        assert_eq!(saved.view["confirmed"], false);
        assert!(!db.get_mcp_server("r1").unwrap().unwrap().confirmed);
        // With no auth there is nothing to send: confirmed without a question.
        let quiet = Asked::new(false);
        let saved = save_and_settle(
            &db,
            &state,
            &vault,
            &rotation,
            save_args(Some("r1"), "restored", "https://mcp.example.com", "none"),
            &quiet.ask(),
        )
        .unwrap();
        assert!(quiet.messages().is_empty());
        assert_eq!(saved.view["confirmed"], true);
    }

    /// The "Allow" confirms only the settings it asked about: a save that
    /// lands while the dialog is open (another address, another variable)
    /// leaves the record off.
    #[test]
    fn rw_s2_an_allowed_binding_is_confirmed_only_as_it_was_shown() {
        let db = temp_db();
        let vault = unlocked_vault();
        let state = McpState::new();
        let rotation = VaultRotationLock::new();
        let mut first = save_args(None, "srv", "https://a.example.com/mcp", "bearer");
        first.auth_env_var = Some("TOKEN_A".into());
        let id = std::sync::OnceLock::<String>::new();
        let asked = std::sync::atomic::AtomicUsize::new(0);
        let edit_meanwhile = |_: &CredentialPrompt| {
            if asked.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                let stored = db.list_mcp_servers().unwrap().remove(0);
                let _ = id.set(stored.id.clone());
                let mut moved = save_args(
                    Some(&stored.id),
                    "srv",
                    "https://evil.example.com/mcp",
                    "bearer",
                );
                moved.auth_env_var = Some("TOKEN_A".into());
                save_server(&db, &state, &vault, moved).unwrap();
            }
            CredentialAnswer::Allowed
        };
        let saved =
            save_and_settle(&db, &state, &vault, &rotation, first, &edit_meanwhile).unwrap();
        assert_eq!(saved.view["confirmed"], false);
        let warning = saved.view["warning"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        assert!(
            warning.contains("changed while you were deciding"),
            "{warning}"
        );
        let stored = db.get_mcp_server(id.get().unwrap()).unwrap().unwrap();
        assert_eq!(stored.url, "https://evil.example.com/mcp");
        assert!(!stored.confirmed, "the address nobody allowed stays off");
    }

    /// The variable's name is shown in the dialog: it may not carry line
    /// breaks, invisible or text-direction characters, '=' or spaces that
    /// could rewrite the question.
    #[test]
    fn rw_s2_an_env_var_name_cannot_rewrite_the_question() {
        let db = temp_db();
        let vault = unlocked_vault();
        for bad in [
            "TOKEN\n\nThis request was checked by SSHSpan",
            "TOKEN\u{202e}NEKOT",
            "TOKEN\u{200b}",
            "MY=VAR",
            "MY VAR",
            "T\u{00e9}",
        ] {
            let mut args = save_args(None, "srv", "https://a.example.com/mcp", "bearer");
            args.auth_env_var = Some(bad.into());
            let err = save(&db, &vault, args).expect_err(bad);
            assert!(
                err.0.contains("environment variable name"),
                "{bad:?}: {}",
                err.0
            );
        }
        assert!(db.list_mcp_servers().unwrap().is_empty());
        let mut fine = save_args(None, "srv", "https://a.example.com/mcp", "bearer");
        fine.auth_env_var = Some("ProgramFiles(x86)".into());
        save(&db, &vault, fine).unwrap();
    }

    // ── Sessions: list changes, locks and replaced sessions ───────────────

    /// A tools/list_changed announced with the initialize answer of a
    /// session the call set up was folded into the call's answer - and lost
    /// when the call itself failed, so a changed tool stayed enabled.
    #[tokio::test(flavor = "multi_thread")]
    async fn rw_r1_a_list_change_announced_with_the_set_up_survives_a_failed_call() {
        let db = temp_db();
        let server = scripted_mcp_with(Script {
            announce_list_changed: true,
            fail_call: true,
            ..Script::default()
        });
        let (record, mut ctx) = call_fixture(&db, &server.url, None);
        let state = McpState::new();
        server.release_initialize.send(()).unwrap();
        let regate = || regate_call(&db, &record, "t", "execute", true);
        let unchecked = || -> CmdResult<()> { Ok(()) };
        let pw = test_password();
        let scope = test_scope(&state, &db, &pw, &unchecked);
        let sent = bounded(
            "the call",
            run_tool_call(&scope, &mut ctx, &tool_call_body(), &regate),
        )
        .await
        .unwrap();
        match sent {
            CallSent::Sent {
                list_changed: true,
                called: Err(_),
                ..
            } => {}
            other => panic!("the announced change must not be lost: {other:?}"),
        }
    }

    /// And a failed call still refreshes the tool list it was told
    /// changed, so the next call is gated against the new definitions.
    #[tokio::test(flavor = "multi_thread")]
    async fn rw_r1_a_failed_call_still_refreshes_a_tool_list_announced_as_changed() {
        let db = temp_db();
        let refreshed = std::sync::atomic::AtomicUsize::new(0);
        let refresh = || async {
            refreshed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        };
        let err = finish_tool_call(
            &db,
            &sample_audit(),
            true,
            Err(CmdError("MCP request failed: timed out".into())),
            refresh,
        )
        .await
        .unwrap_err();
        assert!(
            err.0.contains("timed out"),
            "the call's own error comes back"
        );
        assert_eq!(refreshed.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(tool_call_rows(&db)
            .iter()
            .any(|d| d.contains("result=failed")));
        // Nothing announced: no refresh.
        finish_tool_call(
            &db,
            &sample_audit(),
            false,
            Err(CmdError("MCP request failed: timed out".into())),
            refresh,
        )
        .await
        .unwrap_err();
        assert_eq!(refreshed.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    /// A session that expires in the middle of a paginated tools/list is
    /// renewed - and when the renewal's initialize announces a list change,
    /// the pages read so far may be of the old list: the listing starts over
    /// from its first page instead of mixing the two.
    #[tokio::test(flavor = "multi_thread")]
    async fn rw_r1_a_session_renewed_mid_listing_restarts_the_listing_from_its_first_page() {
        let db = temp_db();
        let server = scripted_mcp_with(Script {
            announce_list_changed: true,
            tools_pages: true,
            expire_page_two_once: true,
            ..Script::default()
        });
        let (_record, mut ctx) = call_fixture(&db, &server.url, Some(session("sess-old")));
        let state = McpState::new();
        server.release_initialize.send(()).unwrap();
        let unchecked = || -> CmdResult<()> { Ok(()) };
        let pw = test_password();
        let scope = test_scope(&state, &db, &pw, &unchecked);
        let tools = bounded("the listing", fetch_tools(&scope, &mut ctx))
            .await
            .unwrap();
        let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
        assert_eq!(names, ["t1", "t2"]);
        let listings: Vec<String> = server
            .methods
            .try_iter()
            .filter(|m| m.starts_with("tools/list"))
            .collect();
        assert_eq!(
            listings,
            [
                "tools/list",
                "tools/list p2",
                "tools/list p2",
                "tools/list",
                "tools/list p2"
            ],
            "after the renewal the listing starts over at page 1"
        );
    }

    /// A lock landing between the generation check and the registration
    /// left a session registered past the lock (its drain had already run).
    /// The check now runs under the sessions lock: the lock's drain waits for
    /// the registration and takes the session with it.
    #[test]
    fn rw_r2_a_lock_between_the_check_and_the_registration_leaves_no_session() {
        use std::sync::atomic::{AtomicBool, Ordering::SeqCst};
        let state = McpState::new();
        let record = record_with_tools("s1", "srv", &[]);
        let checked = AtomicBool::new(false);
        let locked = AtomicBool::new(false);
        let drained = std::thread::scope(|threads| {
            // The lock, as `lock_vault_internal` runs it: the generation
            // first, then the MCP drain.
            let lock = threads.spawn(|| {
                while !checked.load(SeqCst) {
                    std::thread::sleep(Duration::from_millis(1));
                }
                locked.store(true, SeqCst);
                state.take_sessions()
            });
            let guard = || -> CmdResult<()> {
                if locked.load(SeqCst) {
                    return Err(CmdError(
                        "Vault was locked while the operation was in progress.".into(),
                    ));
                }
                // The check passes - and the lock lands right after it.
                checked.store(true, SeqCst);
                std::thread::sleep(Duration::from_millis(200));
                Ok(())
            };
            let _ = state.register(&record, session("sess-1"), &guard);
            lock.join().unwrap()
        });
        assert!(
            state.get_session("s1").is_none(),
            "no session outlives the lock"
        );
        assert_eq!(
            drained
                .iter()
                .map(|(id, _)| id.as_str())
                .collect::<Vec<_>>(),
            ["s1"],
            "the lock took (and ends) the session"
        );
    }

    /// Registering a session replaced the one registered - Test
    /// connection of a connected server, a call from a stale snapshot - and
    /// never ended it. The replaced session is ended where it was set up.
    #[tokio::test(flavor = "multi_thread")]
    async fn rw_r3_a_session_a_registration_replaces_is_ended_where_it_was_set_up() {
        let db = temp_db();
        let server = scripted_mcp(false);
        let (record, mut ctx) = call_fixture(&db, &server.url, None);
        let state = McpState::new();
        // A connected server tested again: same settings.
        state.bind_session(&record, session("sess-old"));
        server.release_initialize.send(()).unwrap();
        let unchecked = || -> CmdResult<()> { Ok(()) };
        let pw = test_password();
        let scope = test_scope(&state, &db, &pw, &unchecked);
        bounded("the set-up", establish_session(&scope, &mut ctx))
            .await
            .unwrap();
        assert!(wait_for_teardowns(state.take_teardowns(), LOADED_MACHINE_WAIT).await);
        let seen: Vec<String> = server.methods.try_iter().collect();
        assert!(
            seen.iter().any(|m| m == "DELETE sess-old"),
            "the replaced session was ended: {seen:?}"
        );

        // A call from a stale snapshot displaces the session of the NEW
        // settings: it is ended at the new URL, with the new credential.
        let (new_url, new_requests) = http_sink(Duration::ZERO);
        let mut newer = record.clone();
        newer.url = new_url;
        newer.auth_type = "bearer".into();
        newer.auth_secret = Some(crate::crypto::vault::seal(&pw, b"new-token").unwrap());
        state.bind_session(&newer, session("sess-newer"));
        let server = scripted_mcp(false);
        let (_, mut stale_ctx) = call_fixture(&db, &server.url, None);
        server.release_initialize.send(()).unwrap();
        bounded("the set-up", establish_session(&scope, &mut stale_ctx))
            .await
            .unwrap();
        assert!(wait_for_teardowns(state.take_teardowns(), UNSEALING_TEARDOWN_WAIT).await);
        let head = new_requests
            .recv_timeout(Duration::from_secs(5))
            .expect("ended at the new endpoint")
            .to_lowercase();
        assert!(head.starts_with("delete "), "{head}");
        assert!(head.contains("mcp-session-id: sess-newer"), "{head}");
        assert!(head.contains("authorization: new-token"), "{head}");
    }

    /// Every teardown unseals its own credential (an Argon2id
    /// derivation, 64 MiB each): a lock with many live sessions ran them all
    /// at once. At most MAX_PARALLEL_UNSEALS run together now - no change up
    /// to that many sessions, which is what fits the exit's 2 s budget.
    #[tokio::test(flavor = "multi_thread")]
    async fn rw_r4_a_lock_unseals_at_most_four_secrets_at_once() {
        let db = temp_db();
        let vault = unlocked_vault();
        let state = McpState::new();
        let (url, requests) = http_sink(Duration::ZERO);
        let pw = vault.get().unwrap();
        let sealed = crate::crypto::vault::seal(&pw, b"token").unwrap();
        for n in 0..6 {
            let mut record = record_with_tools(&format!("s{n}"), &format!("srv{n}"), &[]);
            record.url = url.clone();
            record.auth_type = "bearer".into();
            record.auth_secret = Some(sealed.clone());
            db.save_mcp_server(&record).unwrap();
            state.bind_session(&record, session(&format!("sess-{n}")));
        }
        UNSEALS_PEAK.store(0, std::sync::atomic::Ordering::SeqCst);
        end_sessions(
            &state,
            db.clone(),
            Some(std::sync::Arc::new(pw)),
            state.take_sessions(),
        );
        // Two rounds of unseals: four, then two.
        assert!(wait_for_teardowns(state.take_teardowns(), 2 * UNSEALING_TEARDOWN_WAIT).await);
        assert_eq!(requests.try_iter().count(), 6, "every session was ended");
        let peak = UNSEALS_PEAK.load(std::sync::atomic::Ordering::SeqCst);
        assert!(
            peak <= MAX_PARALLEL_UNSEALS,
            "{peak} unseals ran at once (at most {MAX_PARALLEL_UNSEALS})"
        );
    }

    // ── Credential questions: one at a time, never after a lock, the last
    //    answer stands ────────────────────────────────────────────────────

    /// The arguments of a save that binds AWS_SECRET_ACCESS_KEY to a new
    /// server - one that is asked about.
    fn env_var_save() -> SaveServerArgs {
        let mut args = save_args(None, "aws", "https://mcp.example.com/mcp", "bearer");
        args.auth_env_var = Some("AWS_SECRET_ACCESS_KEY".into());
        args
    }

    /// While another credential question is open, a save that would ask is
    /// not asked about - two questions could be answered by one keystroke -
    /// and its server stays switched off.
    #[test]
    fn rw_fix1_a_save_is_not_asked_about_while_another_question_is_open() {
        let db = temp_db();
        let vault = unlocked_vault();
        let state = McpState::new();
        let rotation = VaultRotationLock::new();
        let questions = crate::commands::CredentialQuestions::new();
        let generations = crate::commands::VaultGeneration::new();
        let open = questions.begin().expect("no question is open yet");
        let asked = Asked::new(true);
        let saved = save_and_settle_with(
            &db,
            &state,
            &vault,
            &rotation,
            &questions,
            &generations,
            env_var_save(),
            &asked.ask(),
        )
        .unwrap();
        assert!(
            asked.messages().is_empty(),
            "not asked while another question is open"
        );
        assert_eq!(saved.view["confirmed"], false);
        let warning = saved.view["warning"].as_str().unwrap_or_default();
        assert!(warning.contains("another question"), "{warning}");
        drop(open);
        let id = saved_id(saved.view);
        assert!(!db.get_mcp_server(&id).unwrap().unwrap().confirmed);
    }

    /// The question can stay open for as long as the user likes: an "Allow"
    /// clicked after the vault was locked - even after it was unlocked again
    /// - confirms nothing.
    #[test]
    fn rw_fix1_an_allow_given_after_a_lock_confirms_nothing() {
        let db = temp_db();
        let vault = unlocked_vault();
        let state = McpState::new();
        let rotation = VaultRotationLock::new();
        let questions = crate::commands::CredentialQuestions::new();
        let generations = crate::commands::VaultGeneration::new();
        let lock_then_allow = |_: &CredentialPrompt| {
            generations.bump();
            vault.clear();
            vault.set("test-master-pw".into());
            CredentialAnswer::Allowed
        };
        let saved = save_and_settle_with(
            &db,
            &state,
            &vault,
            &rotation,
            &questions,
            &generations,
            env_var_save(),
            &lock_then_allow,
        )
        .unwrap();
        assert_eq!(saved.view["confirmed"], false);
        let warning = saved.view["warning"].as_str().unwrap_or_default();
        assert!(warning.contains("locked"), "{warning}");
        let id = saved_id(saved.view);
        assert!(!db.get_mcp_server(&id).unwrap().unwrap().confirmed);
        assert!(audit_rows(&db, "mcp.credential_allowed").is_empty());
    }

    /// Two saves of the same settings: the first one's "Allow" is written
    /// after the second save stored the server switched off again. The
    /// second question's "Don't allow" must leave it off - an earlier "Allow"
    /// never undoes a later "no".
    #[test]
    fn rw_fix1_a_later_dont_allow_is_never_undone_by_an_earlier_allow() {
        let db = temp_db();
        let vault = unlocked_vault();
        let state = McpState::new();
        let rotation = VaultRotationLock::new();
        let questions = crate::commands::CredentialQuestions::new();
        let generations = crate::commands::VaultGeneration::new();
        let first = save_server(&db, &state, &vault, env_var_save()).unwrap();
        let first_question = first.pending.expect("asked about");
        let id = saved_id(first.view);
        let mut again = env_var_save();
        again.id = Some(id.clone());
        let second = save_server(&db, &state, &vault, again).unwrap();
        let second_question = second.pending.expect("asked about again");
        let at_save = VaultAtSave {
            vault: &vault,
            generations: &generations,
            generation: generations.current(),
        };
        let allowed = settle_binding(
            &db,
            &rotation,
            &questions,
            &at_save,
            first_question,
            &|_| CredentialAnswer::Allowed,
        );
        assert!(allowed.confirmed);
        let declined = settle_binding(
            &db,
            &rotation,
            &questions,
            &at_save,
            second_question,
            &|_| CredentialAnswer::NotAllowed,
        );
        assert!(!declined.confirmed);
        assert!(
            !db.get_mcp_server(&id).unwrap().unwrap().confirmed,
            "the later Don't allow stands"
        );
    }

    /// A credential answered "Don't allow" or "Cancel" for an address is not
    /// asked about again for 30 seconds - a renderer could ask again and
    /// again until a tired user gave in. The save is stored switched off and
    /// says why; after 30 seconds the question is asked again.
    #[test]
    fn fw_s1_a_declined_credential_is_not_asked_again_for_30_seconds() {
        let db = temp_db();
        let vault = unlocked_vault();
        let state = McpState::new();
        let rotation = VaultRotationLock::new();
        let clock = crate::commands::TestClock::new();
        let questions = clock.questions();
        let generations = crate::commands::VaultGeneration::new();
        let asked = std::cell::Cell::new(0);
        let counter = &asked;
        let answer = |reply: CredentialAnswer| {
            move |_: &CredentialPrompt| {
                counter.set(counter.get() + 1);
                reply
            }
        };
        let declined = answer(CredentialAnswer::NotAllowed);
        let first = save_and_settle_with(
            &db,
            &state,
            &vault,
            &rotation,
            &questions,
            &generations,
            env_var_save(),
            &declined,
        )
        .unwrap();
        assert_eq!(asked.get(), 1);
        assert_eq!(first.view["confirmed"], false);
        let id = saved_id(first.view);
        let again = || {
            let mut save = env_var_save();
            save.id = Some(id.clone());
            save
        };
        let allow = answer(CredentialAnswer::Allowed);
        let second = save_and_settle_with(
            &db,
            &state,
            &vault,
            &rotation,
            &questions,
            &generations,
            again(),
            &allow,
        )
        .unwrap();
        assert_eq!(asked.get(), 1, "not asked again within 30 seconds");
        assert_eq!(second.view["confirmed"], false);
        assert_eq!(
            second.view["warning"].as_str(),
            Some(
                "The server was saved but stays switched off, because sending a credential to \
                 mcp.example.com was declined a moment ago. Wait 30 seconds, then save it again."
            )
        );
        assert!(!db.get_mcp_server(&id).unwrap().unwrap().confirmed);
        clock.advance(crate::commands::CREDENTIAL_DECLINE_BACKOFF);
        let third = save_and_settle_with(
            &db,
            &state,
            &vault,
            &rotation,
            &questions,
            &generations,
            again(),
            &allow,
        )
        .unwrap();
        assert_eq!(asked.get(), 2, "asked again after 30 seconds");
        assert_eq!(third.view["confirmed"], true);
        assert!(db.get_mcp_server(&id).unwrap().unwrap().confirmed);
    }

    /// Keyed by the host, the 30 seconds after a "no" let a renderer ask at
    /// once about the next made-up host (a1.x, a2.x, ...) - an MCP address
    /// needs no DNS - so the back-off never engaged. After a "no", no
    /// credential question is asked for 30 seconds, whatever the server or
    /// the address, and the answer names the host declined. A "no" to another
    /// kind of question holds nothing back here.
    #[test]
    fn fw_u2_a_declined_credential_holds_back_every_mcp_question() {
        use crate::commands::QuestionKind;
        let db = temp_db();
        let vault = unlocked_vault();
        let state = McpState::new();
        let rotation = VaultRotationLock::new();
        let clock = crate::commands::TestClock::new();
        let questions = clock.questions();
        let generations = crate::commands::VaultGeneration::new();
        let asked = std::cell::Cell::new(0);
        let counter = &asked;
        let answer = |reply: CredentialAnswer| {
            move |_: &CredentialPrompt| {
                counter.set(counter.get() + 1);
                reply
            }
        };
        questions.record_decline(QuestionKind::AssistantKeyMove, "llm.example.com");
        questions.record_decline(QuestionKind::BitwardenDestination, "vault.example.com");
        let declined = answer(CredentialAnswer::NotAllowed);
        let first = save_and_settle_with(
            &db,
            &state,
            &vault,
            &rotation,
            &questions,
            &generations,
            env_var_save(),
            &declined,
        )
        .unwrap();
        assert_eq!(
            asked.get(),
            1,
            "asked, though the other kinds were declined"
        );
        let id = saved_id(first.view);
        // The same server at another address, or a new server (a name of its
        // own) at a made-up one.
        let at = |id: Option<&str>, name: &str, url: &str| {
            let mut save = env_var_save();
            save.id = id.map(String::from);
            save.name = name.into();
            save.url = url.into();
            save
        };
        let held_back = "The server was saved but stays switched off, because sending a \
             credential to mcp.example.com was declined a moment ago. Wait 30 seconds, then \
             save it again.";
        let allow = answer(CredentialAnswer::Allowed);
        for (server, name, url) in [
            (Some(id.as_str()), "aws", "https://mcp.example.com/mcp2"),
            (Some(id.as_str()), "aws", "https://other.example.net/mcp"),
            (None, "a1", "https://a1.attacker.example/mcp"),
            (None, "a2", "https://a2.attacker.example/mcp"),
        ] {
            let saved = save_and_settle_with(
                &db,
                &state,
                &vault,
                &rotation,
                &questions,
                &generations,
                at(server, name, url),
                &allow,
            )
            .unwrap();
            assert_eq!(asked.get(), 1, "{url}: held back");
            assert_eq!(saved.view["confirmed"], false, "{url}");
            assert_eq!(saved.view["warning"].as_str(), Some(held_back), "{url}");
        }
        // 30 seconds after the "no": asked again, whatever the address.
        clock.advance(crate::commands::CREDENTIAL_DECLINE_BACKOFF);
        let later = save_and_settle_with(
            &db,
            &state,
            &vault,
            &rotation,
            &questions,
            &generations,
            at(None, "a3", "https://a3.attacker.example/mcp"),
            &allow,
        )
        .unwrap();
        assert_eq!(asked.get(), 2, "asked again after 30 seconds");
        assert_eq!(later.view["confirmed"], true);
    }

    /// An "Allow" within a second of the question opening counts as "Don't
    /// allow", and the warning says why.
    #[test]
    fn rw_fix1_a_quick_allow_keeps_the_server_off_and_says_why() {
        let db = temp_db();
        let vault = unlocked_vault();
        let quick = Asked::answering(CredentialAnswer::TooQuick);
        let saved = save_and_settle(
            &db,
            &McpState::new(),
            &vault,
            &VaultRotationLock::new(),
            env_var_save(),
            &quick.ask(),
        )
        .unwrap();
        assert_eq!(saved.view["confirmed"], false);
        let warning = saved.view["warning"].as_str().unwrap_or_default();
        assert!(warning.contains("within a second"), "{warning}");
        assert_eq!(
            audit_rows(&db, "mcp.credential_declined"),
            vec![
                "server=aws host=mcp.example.com sends=env:AWS_SECRET_ACCESS_KEY answered=too-quickly"
                    .to_string()
            ]
        );
    }

    /// A variable name kept from storage - a restored backup, an older
    /// version - is shown in the question like a typed one: it is checked
    /// like a typed one.
    #[test]
    fn rw_fix1_a_kept_env_var_name_is_checked_too() {
        let db = temp_db();
        let vault = unlocked_vault();
        let mut restored = record_with_tools("r1", "restored", &[]);
        restored.auth_type = "bearer".into();
        restored.auth_env_var = Some("TOKEN\n\nThis request was checked by SSHSpan".into());
        restored.confirmed = false;
        db.save_mcp_server(&restored).unwrap();
        let asked = Asked::new(true);
        let err = save_and_settle(
            &db,
            &McpState::new(),
            &vault,
            &VaultRotationLock::new(),
            save_args(Some("r1"), "restored", "https://mcp.example.com", "bearer"),
            &asked.ask(),
        )
        .map(|saved| saved.view)
        .expect_err("a kept name is checked too");
        assert!(err.0.contains("environment variable name"), "{}", err.0);
        assert!(asked.messages().is_empty(), "nothing was asked");
        assert!(!db.get_mcp_server("r1").unwrap().unwrap().confirmed);
    }

    /// A confirmation the database refuses is reported in plain words - the
    /// raw database error is not shown to the user.
    #[test]
    fn rw_fix1_a_confirmation_that_cannot_be_stored_says_so_plainly() {
        let db = temp_db();
        let vault = unlocked_vault();
        let state = McpState::new();
        let saved = save_server(&db, &state, &vault, env_var_save()).unwrap();
        let pending = saved.pending.expect("asked about");
        crate::db::test_support::execute(
            &db,
            "CREATE TRIGGER refuse_mcp_updates BEFORE UPDATE ON mcp_servers \
             BEGIN SELECT RAISE(ABORT, 'disk detail /var/lib/secret-path'); END",
        );
        let generations = crate::commands::VaultGeneration::new();
        let at_save = VaultAtSave {
            vault: &vault,
            generations: &generations,
            generation: generations.current(),
        };
        let outcome = settle_binding(
            &db,
            &VaultRotationLock::new(),
            &crate::commands::CredentialQuestions::new(),
            &at_save,
            pending,
            &|_| CredentialAnswer::Allowed,
        );
        assert!(!outcome.confirmed);
        assert_eq!(outcome.warning.as_deref(), Some(BINDING_NOT_STORED));
    }

    // ── Calls, replaced sessions and teardowns ──────────────────────────────

    /// A tools/list_changed announced with the set-up of a session goes with
    /// a refusal too - the gate refused the call after the set-up - and the
    /// refusal path refreshes the list it was told changed.
    #[tokio::test(flavor = "multi_thread")]
    async fn rw_fix1_a_refused_call_keeps_a_list_change_announced_at_set_up() {
        let db = temp_db();
        let server = scripted_mcp_with(Script {
            announce_list_changed: true,
            ..Script::default()
        });
        let (record, mut ctx) = call_fixture(&db, &server.url, None);
        let state = McpState::new();
        let regate = || regate_call(&db, &record, "t", "execute", true);
        let body = tool_call_body();
        let unchecked = || -> CmdResult<()> { Ok(()) };
        let pw = test_password();
        let scope = test_scope(&state, &db, &pw, &unchecked);
        let call = run_tool_call(&scope, &mut ctx, &body, &regate);
        let revoke = async {
            wait_for_method(&server, "initialize").await;
            set_tool_state(&db, &unlocked_vault(), "s1", "t", false, false, None).unwrap();
            server.release_initialize.send(()).unwrap();
        };
        let (sent, ()) = bounded("the request and the change racing it", async {
            tokio::join!(call, revoke)
        })
        .await;
        match sent {
            Ok(CallSent::Refused {
                list_changed: true, ..
            }) => {}
            other => panic!("the announced change goes with the refusal: {other:?}"),
        }
        let refreshed = std::sync::atomic::AtomicUsize::new(0);
        let refresh = || async {
            refreshed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        };
        after_refused_call(true, refresh).await;
        after_refused_call(false, refresh).await;
        assert_eq!(refreshed.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    /// "Test connection" while a tool call is waiting on the registered
    /// session: the new session replaces it, but it is ended only once the
    /// call is done with it - ending it at once broke the call (its retry).
    #[tokio::test(flavor = "multi_thread")]
    async fn rw_fix1_a_replaced_session_in_use_is_ended_once_its_requests_finish() {
        let db = temp_db();
        let server = scripted_mcp(false);
        let (record, mut ctx) = call_fixture(&db, &server.url, None);
        let state = McpState::new();
        state.bind_session(&record, session("sess-old"));
        let in_flight = state.use_session(Some(&session("sess-old")));
        server.release_initialize.send(()).unwrap();
        let unchecked = || -> CmdResult<()> { Ok(()) };
        let pw = test_password();
        let scope = test_scope(&state, &db, &pw, &unchecked);
        bounded("the set-up", establish_session(&scope, &mut ctx))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(wait_for_teardowns(state.take_teardowns(), LOADED_MACHINE_WAIT).await);
        let seen: Vec<String> = server.methods.try_iter().collect();
        assert!(
            !seen.iter().any(|m| m.starts_with("DELETE sess-old")),
            "not ended while a request still uses it: {seen:?}"
        );
        drop(in_flight);
        assert!(wait_for_teardowns(state.take_teardowns(), LOADED_MACHINE_WAIT).await);
        let seen: Vec<String> = server.methods.try_iter().collect();
        assert!(
            seen.iter().any(|m| m == "DELETE sess-old"),
            "ended once its last request finished: {seen:?}"
        );
    }

    /// A session replaced by one set up with the same settings ("Test
    /// connection" of a connected server) is ended with the header already
    /// in memory: no unseal, no password copy. Here the stored secret does
    /// not even open with the password the teardown would have used.
    #[tokio::test(flavor = "multi_thread")]
    async fn rw_fix1_a_session_replaced_with_the_same_settings_is_ended_with_the_header_in_memory()
    {
        let db = temp_db();
        let server = scripted_mcp(false);
        let (mut record, mut ctx) = call_fixture(&db, &server.url, None);
        record.auth_type = "bearer".into();
        record.auth_secret = Some(crate::crypto::vault::seal("another-password", b"x").unwrap());
        db.save_mcp_server(&record).unwrap();
        ctx.record = record.clone();
        ctx.auth = Some((
            "Authorization".into(),
            Zeroizing::new("live-token".to_string()),
        ));
        let state = McpState::new();
        state.bind_session(&record, session("sess-old"));
        server.release_initialize.send(()).unwrap();
        let unchecked = || -> CmdResult<()> { Ok(()) };
        let pw = test_password();
        let scope = test_scope(&state, &db, &pw, &unchecked);
        bounded("the set-up", establish_session(&scope, &mut ctx))
            .await
            .unwrap();
        assert!(wait_for_teardowns(state.take_teardowns(), UNSEALING_TEARDOWN_WAIT).await);
        let seen: Vec<String> = server.methods.try_iter().collect();
        assert!(
            seen.iter().any(|m| m == "DELETE sess-old auth=live-token"),
            "ended with the header in memory: {seen:?}"
        );
    }

    /// Teardowns that unseal their credential share ONE copy of the vault
    /// password, wiped once none holds it; and the teardowns waiting at once
    /// are capped - a "Test connection" loop used to queue one password copy
    /// per replaced session.
    #[tokio::test(flavor = "multi_thread")]
    async fn rw_fix1_teardowns_share_one_password_copy_and_wait_in_a_capped_queue() {
        let state = McpState::new();
        let pw = test_password();
        let first = state.shared_password(&pw);
        let second = state.shared_password(&pw);
        assert!(std::sync::Arc::ptr_eq(&first, &second), "one copy, shared");
        drop((first, second));
        let gone = std::sync::Arc::downgrade(&state.shared_password(&pw));
        assert!(gone.upgrade().is_none(), "wiped once nobody holds it");
        // The running teardowns are still waiting for their answer when the
        // new ones are admitted, however slow the machine.
        let (url, _requests) = http_sink(Duration::from_secs(120));
        let running = spawn_teardown_jobs(
            temp_db(),
            client_for_tests(),
            (0..MAX_PENDING_TEARDOWNS - 2)
                .map(|n| teardown_job(&url, &format!("r{n}")))
                .collect(),
        );
        state.track_teardowns(running);
        let admitted = state.admit_teardowns(
            (0..5)
                .map(|n| teardown_job(&url, &format!("n{n}")))
                .collect(),
        );
        assert_eq!(admitted.len(), 2, "only what fits under the cap");
    }

    /// A connect or a call resolves a stored secret on the blocking pool -
    /// an Argon2id derivation it used to run on an async worker.
    #[tokio::test(flavor = "multi_thread")]
    async fn rw_fix1_a_stored_mcp_secret_is_unsealed_on_the_blocking_pool() {
        let db = temp_db();
        let state = McpState::new();
        let pw = test_password();
        let mut record = record_with_tools("s1", "srv", &[]);
        record.auth_type = "bearer".into();
        record.auth_secret = Some(crate::crypto::vault::seal(&pw, b"the-token").unwrap());
        let ctx = server_context(&state, &db, record, &pw, 0).await.unwrap();
        let (name, value) = ctx.auth.expect("the header is resolved");
        assert_eq!(
            (name.as_str(), value.as_str()),
            ("Authorization", "the-token")
        );
    }

    // ── The refresh after a refused call ─────────────────────────────────

    /// A server that announces a list change when a session is set up,
    /// lists tools `t1` and `t2`, numbers its sessions and reports the session
    /// every request carried.
    fn announcing_server() -> ScriptedMcp {
        scripted_mcp_with(Script {
            announce_list_changed: true,
            tools_pages: true,
            numbered_sessions: true,
            ..Script::default()
        })
    }

    /// The gate refused the call because the server's URL changed - or the
    /// server was removed - while its session was set up. The refresh used
    /// to run anyway, on that context: the OLD endpoint got `tools/list` on
    /// the very session the refusal had just ended. Nothing more goes there
    /// now, and the context forgets the ended session. (Since round 5 the
    /// change is caught once the initialize is answered, before that session
    /// is registered - so the list change its answer announced goes with it,
    /// and the refusal no longer carries it.)
    #[tokio::test(flavor = "multi_thread")]
    async fn rw_fix2_a_call_refused_for_new_settings_sends_nothing_more_to_the_old_endpoint() {
        for removed in [false, true] {
            let db = temp_db();
            let server = announcing_server();
            let (record, mut ctx) = call_fixture(&db, &server.url, None);
            let state = McpState::new();
            let regate = || regate_call(&db, &record, "t", "execute", true);
            let body = tool_call_body();
            let unchecked = || -> CmdResult<()> { Ok(()) };
            let pw = test_password();
            let scope = test_scope(&state, &db, &pw, &unchecked);
            let call = run_tool_call(&scope, &mut ctx, &body, &regate);
            let change = async {
                wait_for_method(&server, "initialize @-").await;
                if removed {
                    db.delete_mcp_server("s1").unwrap();
                } else {
                    save_server(
                        &db,
                        &state,
                        &unlocked_vault(),
                        save_args(Some("s1"), "srv", "https://new.example.com/mcp", "none"),
                    )
                    .unwrap();
                }
                server.release_initialize.send(()).unwrap();
            };
            let (sent, ()) = bounded("the request and the change racing it", async {
                tokio::join!(call, change)
            })
            .await;
            match sent {
                Ok(CallSent::Refused { .. }) => {}
                other => panic!("removed={removed}: refused after the set-up: {other:?}"),
            }
            assert!(
                ctx.session.is_none(),
                "removed={removed}: the refusal ended the session it set up - and forgot it"
            );
            bounded(
                "the refresh after the refusal",
                refresh_after_refusal(&scope, &mut ctx, &record),
            )
            .await
            .unwrap();
            assert!(wait_for_teardowns(state.take_teardowns(), LOADED_MACHINE_WAIT).await);
            let later: Vec<String> = server.methods.try_iter().collect();
            assert!(
                !later
                    .iter()
                    .any(|m| m.starts_with("tools/list") || m.starts_with("initialize")),
                "removed={removed}: nothing more to the old endpoint: {later:?}"
            );
        }
    }

    /// Refused for another reason (the tool was revoked) with the settings
    /// unchanged, the refresh still runs - on a session of its own: the one
    /// the call set up was ended by the refusal and is never used again.
    #[tokio::test(flavor = "multi_thread")]
    async fn rw_fix2_a_refused_call_refreshes_on_a_session_of_its_own() {
        let db = temp_db();
        let server = announcing_server();
        let (record, mut ctx) = call_fixture(&db, &server.url, None);
        let state = McpState::new();
        let regate = || regate_call(&db, &record, "t", "execute", true);
        let body = tool_call_body();
        let unchecked = || -> CmdResult<()> { Ok(()) };
        let pw = test_password();
        let scope = test_scope(&state, &db, &pw, &unchecked);
        let call = run_tool_call(&scope, &mut ctx, &body, &regate);
        let revoke = async {
            wait_for_method(&server, "initialize @-").await;
            set_tool_state(&db, &unlocked_vault(), "s1", "t", false, false, None).unwrap();
            server.release_initialize.send(()).unwrap();
        };
        let (sent, ()) = bounded("the request and the change racing it", async {
            tokio::join!(call, revoke)
        })
        .await;
        match sent {
            Ok(CallSent::Refused {
                list_changed: true, ..
            }) => {}
            other => panic!("refused after the set-up: {other:?}"),
        }
        assert!(ctx.session.is_none(), "the ended session is forgotten");
        // The refresh's own set-up.
        server.release_initialize.send(()).unwrap();
        bounded(
            "the refresh after the refusal",
            refresh_after_refusal(&scope, &mut ctx, &record),
        )
        .await
        .unwrap();
        assert!(wait_for_teardowns(state.take_teardowns(), LOADED_MACHINE_WAIT).await);
        let later: Vec<String> = server.methods.try_iter().collect();
        assert!(
            later.iter().any(|m| m == "tools/list @sess-2"),
            "listed on a session of its own: {later:?}"
        );
        assert!(
            !later
                .iter()
                .any(|m| m.starts_with("tools/list") && m.ends_with("@sess-1")),
            "never on the ended one: {later:?}"
        );
        let stored = db.get_mcp_server("s1").unwrap().unwrap();
        assert!(
            stored.tools.iter().any(|t| t.name == "t1"),
            "the list was refreshed"
        );
    }

    /// The server was switched off while the call's session was set up - a
    /// "Don't allow" on exactly these settings, or a restore that brings it
    /// back with the same URL and credential, switched off. The gate refused
    /// the call, but the refresh checked only that the URL and credential
    /// were unchanged: it set up a session of its own, sent `initialize` and
    /// `tools/list` to the switched-off server and left that session
    /// registered. Nothing more goes there now. (Since round 5 the refusal
    /// comes before the call's session is registered, without the list
    /// change its initialize announced - see the round-2 test above.)
    #[tokio::test(flavor = "multi_thread")]
    async fn rw_fix3_a_call_refused_on_a_switched_off_server_refreshes_nothing() {
        for restored in [false, true] {
            let db = temp_db();
            let server = announcing_server();
            let (record, mut ctx) = call_fixture(&db, &server.url, None);
            let state = McpState::new();
            let regate = || regate_call(&db, &record, "t", "execute", true);
            let body = tool_call_body();
            let unchecked = || -> CmdResult<()> { Ok(()) };
            let pw = test_password();
            let scope = test_scope(&state, &db, &pw, &unchecked);
            let call = run_tool_call(&scope, &mut ctx, &body, &regate);
            let switch_off = async {
                wait_for_method(&server, "initialize @-").await;
                let stored = db.get_mcp_server("s1").unwrap().unwrap();
                if restored {
                    let mut switched_off = stored;
                    switched_off.confirmed = false;
                    db.save_mcp_server(&switched_off).unwrap();
                } else {
                    decline_binding(&db, &VaultRotationLock::new(), &pending_binding(&stored));
                }
                server.release_initialize.send(()).unwrap();
            };
            let (sent, ()) = bounded("the request and the change racing it", async {
                tokio::join!(call, switch_off)
            })
            .await;
            match sent {
                Ok(CallSent::Refused { ref reason, .. }) if reason == UNCONFIRMED_SERVER => {}
                other => panic!("restored={restored}: refused as switched off: {other:?}"),
            }
            assert!(
                ctx.session.is_none(),
                "restored={restored}: the ended session is forgotten"
            );
            // What a refresh's own set-up would be answered with.
            server.release_initialize.send(()).unwrap();
            bounded(
                "the refresh after the refusal",
                refresh_after_refusal(&scope, &mut ctx, &record),
            )
            .await
            .unwrap();
            assert!(wait_for_teardowns(state.take_teardowns(), LOADED_MACHINE_WAIT).await);
            let later: Vec<String> = server.methods.try_iter().collect();
            assert!(
                !later
                    .iter()
                    .any(|m| m.starts_with("initialize") || m.starts_with("tools/list")),
                "restored={restored}: nothing more to the switched-off server: {later:?}"
            );
            assert!(
                state.get_session("s1").is_none(),
                "restored={restored}: no session is left registered"
            );
            assert!(
                !db.get_mcp_server("s1").unwrap().unwrap().confirmed,
                "restored={restored}: still switched off"
            );
        }
    }

    // ── Nothing more for a server switched off, edited or removed ────────

    /// What happens to server `s1` behind a request's back.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Meanwhile {
        /// "Don't allow" on exactly its settings.
        Declined,
        /// A restore stores it with the same URL and credential, switched off.
        Restored,
        /// Its URL is edited.
        Edited,
        /// It is removed.
        Removed,
    }

    impl Meanwhile {
        fn apply(self, db: &crate::db::Database, state: &McpState) {
            let stored = db.get_mcp_server("s1").unwrap().unwrap();
            match self {
                Self::Declined => {
                    decline_binding(db, &VaultRotationLock::new(), &pending_binding(&stored))
                }
                Self::Restored => {
                    let mut switched_off = stored;
                    switched_off.confirmed = false;
                    db.save_mcp_server(&switched_off).unwrap();
                }
                Self::Edited => {
                    save_server(
                        db,
                        state,
                        &unlocked_vault(),
                        save_args(Some("s1"), "srv", "https://new.example.com/mcp", "none"),
                    )
                    .unwrap();
                }
                Self::Removed => {
                    db.delete_mcp_server("s1").unwrap();
                }
            }
        }

        /// What a request that is not a tools/call refuses with.
        fn refusal(self) -> &'static str {
            match self {
                Self::Declined | Self::Restored => UNCONFIRMED_SERVER,
                Self::Edited => SETTINGS_CHANGED_MEANWHILE,
                Self::Removed => SERVER_REMOVED_MEANWHILE,
            }
        }

        /// What the call gate refuses with ([`regate_call`]).
        fn gate_refusal(self) -> &'static str {
            match self {
                Self::Removed => "MCP server not found.",
                other => other.refusal(),
            }
        }

        /// [`Self::apply`] as the app does it: the save of an edit also
        /// ends the session it took from the registry (`mcp_save_server`
        /// starts that teardown).
        fn apply_in_app(self, db: &crate::db::Database, state: &McpState) {
            if self != Self::Edited {
                self.apply(db, state);
                return;
            }
            let saved = save_server(
                db,
                state,
                &unlocked_vault(),
                save_args(Some("s1"), "srv", "https://new.example.com/mcp", "none"),
            )
            .unwrap();
            if let Some(job) = saved.teardown {
                state.start_teardowns(db.clone(), client_for_tests(), vec![job]);
            }
        }
    }

    /// Every way server `s1` changes behind a request's back.
    const EVERY_CHANGE: [Meanwhile; 4] = [
        Meanwhile::Declined,
        Meanwhile::Restored,
        Meanwhile::Edited,
        Meanwhile::Removed,
    ];

    /// The server was switched off ("Don't allow", a restore) or edited
    /// while a call it answered was out. The refresh its announced list
    /// change asks for used to run anyway, on the call's session (with a new
    /// initialize if that answered 404). Nothing more goes there now: the
    /// session the call used is ended where it was set up, and none stays
    /// registered.
    #[tokio::test(flavor = "multi_thread")]
    async fn rw_fix4_a_call_answered_after_its_server_was_switched_off_or_edited_refreshes_nothing()
    {
        for meanwhile in [Meanwhile::Declined, Meanwhile::Restored, Meanwhile::Edited] {
            let db = temp_db();
            let server = scripted_mcp_with(Script {
                announce_list_changed: true,
                tools_pages: true,
                numbered_sessions: true,
                hold: Some("tools/call"),
                ..Script::default()
            });
            let (record, mut ctx) = call_fixture(&db, &server.url, None);
            let state = McpState::new();
            let regate = || regate_call(&db, &record, "t", "execute", true);
            let body = tool_call_body();
            let unchecked = || -> CmdResult<()> { Ok(()) };
            let pw = test_password();
            let scope = test_scope(&state, &db, &pw, &unchecked);
            // The call's own set-up.
            server.release_initialize.send(()).unwrap();
            let call = run_tool_call(&scope, &mut ctx, &body, &regate);
            let change = async {
                wait_for_method(&server, "tools/call @sess-1").await;
                meanwhile.apply(&db, &state);
                // The call's answer.
                server.release_initialize.send(()).unwrap();
            };
            let (sent, ()) = bounded("the request and the change racing it", async {
                tokio::join!(call, change)
            })
            .await;
            match sent {
                Ok(CallSent::Sent {
                    list_changed: true,
                    called: Ok(_),
                    ..
                }) => {}
                other => panic!("{meanwhile:?}: the call went out and was answered: {other:?}"),
            }
            // What a refresh's new set-up would be answered with.
            server.release_initialize.send(()).unwrap();
            bounded(
                "the refresh after the call",
                refresh_after_sent_call(&scope, &mut ctx, &record),
            )
            .await
            .unwrap();
            assert!(wait_for_teardowns(state.take_teardowns(), LOADED_MACHINE_WAIT).await);
            let later: Vec<String> = server.methods.try_iter().collect();
            assert!(
                !later
                    .iter()
                    .any(|m| m.starts_with("initialize") || m.starts_with("tools/list")),
                "{meanwhile:?}: nothing more to the server: {later:?}"
            );
            assert!(
                state.get_session("s1").is_none(),
                "{meanwhile:?}: no session is left registered"
            );
            assert!(ctx.session.is_none(), "{meanwhile:?}: and none is kept");
            if meanwhile != Meanwhile::Edited {
                // (An edit ends it itself: the save takes it.)
                assert!(
                    later.iter().any(|m| m == "DELETE sess-1"),
                    "{meanwhile:?}: ended where it was set up: {later:?}"
                );
            }
        }
    }

    /// A session the server lost in the middle of a tools/list (404) was
    /// set up again with a new initialize, whatever had become of the server
    /// while the page was out. A server switched off, edited or removed gets
    /// no new session now: the listing fails with why, the lost session is
    /// forgotten, and none is registered.
    #[tokio::test(flavor = "multi_thread")]
    async fn rw_fix4_a_session_lost_mid_listing_is_not_renewed_for_a_server_switched_off_edited_or_removed(
    ) {
        for meanwhile in [
            Meanwhile::Declined,
            Meanwhile::Restored,
            Meanwhile::Edited,
            Meanwhile::Removed,
        ] {
            let db = temp_db();
            let server = scripted_mcp_with(Script {
                tools_pages: true,
                expire_page_two_once: true,
                numbered_sessions: true,
                hold: Some("tools/list p2"),
                ..Script::default()
            });
            let (record, mut ctx) = call_fixture(&db, &server.url, Some(session("sess-old")));
            let state = McpState::new();
            state.bind_session(&record, session("sess-old"));
            let unchecked = || -> CmdResult<()> { Ok(()) };
            let pw = test_password();
            let scope = test_scope(&state, &db, &pw, &unchecked);
            let listing = fetch_tools(&scope, &mut ctx);
            let change = async {
                wait_for_method(&server, "tools/list p2 @sess-old").await;
                meanwhile.apply(&db, &state);
                // Page two's answer (404), then what a new set-up would get.
                server.release_initialize.send(()).unwrap();
                server.release_initialize.send(()).unwrap();
            };
            let (listed, ()) = bounded("the request and the change racing it", async {
                tokio::join!(listing, change)
            })
            .await;
            let err = listed.expect_err("no listing without a session");
            assert_eq!(err.0, meanwhile.refusal(), "{meanwhile:?}");
            let later: Vec<String> = server.methods.try_iter().collect();
            assert!(
                !later.iter().any(|m| m.starts_with("initialize")),
                "{meanwhile:?}: no new session: {later:?}"
            );
            assert!(
                state.get_session("s1").is_none(),
                "{meanwhile:?}: none is registered"
            );
            assert!(
                ctx.session.is_none(),
                "{meanwhile:?}: the lost one is forgotten"
            );
        }
    }

    /// The same for a tools/call whose session the server had lost (404):
    /// the new initialize went out before the gate was checked again. The
    /// gate as stored now decides first: refused, nothing more is sent.
    #[tokio::test(flavor = "multi_thread")]
    async fn rw_fix4_a_lost_call_session_is_not_renewed_for_a_server_switched_off_or_edited() {
        for meanwhile in [Meanwhile::Declined, Meanwhile::Restored, Meanwhile::Edited] {
            let db = temp_db();
            let server = scripted_mcp_with(Script {
                expire_first_call: true,
                numbered_sessions: true,
                ..Script::default()
            });
            let (record, mut ctx) = call_fixture(&db, &server.url, Some(session("sess-old")));
            let state = McpState::new();
            state.bind_session(&record, session("sess-old"));
            // The gate passes the first tools/call; the change lands while
            // that call is out.
            let first = std::sync::atomic::AtomicBool::new(true);
            let regate = || {
                let check = regate_call(&db, &record, "t", "execute", true);
                if first.swap(false, std::sync::atomic::Ordering::SeqCst) {
                    meanwhile.apply(&db, &state);
                }
                check
            };
            let unchecked = || -> CmdResult<()> { Ok(()) };
            let pw = test_password();
            let scope = test_scope(&state, &db, &pw, &unchecked);
            // What a new set-up would be answered with.
            server.release_initialize.send(()).unwrap();
            let sent = bounded(
                "the call",
                run_tool_call(&scope, &mut ctx, &tool_call_body(), &regate),
            )
            .await;
            let expected = match meanwhile {
                Meanwhile::Edited => SETTINGS_CHANGED_MEANWHILE,
                _ => UNCONFIRMED_SERVER,
            };
            match sent {
                Ok(CallSent::Refused { reason, .. }) => {
                    assert_eq!(reason, expected, "{meanwhile:?}")
                }
                other => panic!("{meanwhile:?}: refused before a new session: {other:?}"),
            }
            let seen: Vec<String> = server.methods.try_iter().collect();
            assert_eq!(
                seen,
                ["tools/call @sess-old"],
                "{meanwhile:?}: nothing after the lost call"
            );
            assert!(
                state.get_session("s1").is_none(),
                "{meanwhile:?}: the lost session is not kept"
            );
        }
    }

    /// A call that has to set up its session: the server was switched off
    /// or edited after the command checked the gate (while the context
    /// unsealed the secret, say). The initialize went out before the gate
    /// was checked again; now nothing is sent at all.
    #[tokio::test(flavor = "multi_thread")]
    async fn rw_fix4_a_call_sets_up_no_session_with_a_server_switched_off_or_edited() {
        for meanwhile in [Meanwhile::Declined, Meanwhile::Restored, Meanwhile::Edited] {
            let db = temp_db();
            let server = scripted_mcp_with(Script {
                numbered_sessions: true,
                ..Script::default()
            });
            let (record, mut ctx) = call_fixture(&db, &server.url, None);
            let state = McpState::new();
            meanwhile.apply(&db, &state);
            let regate = || regate_call(&db, &record, "t", "execute", true);
            let unchecked = || -> CmdResult<()> { Ok(()) };
            let pw = test_password();
            let scope = test_scope(&state, &db, &pw, &unchecked);
            // What a set-up would be answered with.
            server.release_initialize.send(()).unwrap();
            let sent = bounded(
                "the call",
                run_tool_call(&scope, &mut ctx, &tool_call_body(), &regate),
            )
            .await;
            let expected = match meanwhile {
                Meanwhile::Edited => SETTINGS_CHANGED_MEANWHILE,
                _ => UNCONFIRMED_SERVER,
            };
            match sent {
                Ok(CallSent::Refused {
                    reason,
                    list_changed: false,
                    ..
                }) => assert_eq!(reason, expected, "{meanwhile:?}"),
                other => panic!("{meanwhile:?}: refused before any request: {other:?}"),
            }
            assert!(wait_for_teardowns(state.take_teardowns(), LOADED_MACHINE_WAIT).await);
            let seen: Vec<String> = server.methods.try_iter().collect();
            assert!(seen.is_empty(), "{meanwhile:?}: nothing was sent: {seen:?}");
            assert!(state.get_session("s1").is_none(), "{meanwhile:?}");
        }
    }

    /// Every set-up of a session checks the server as stored first - also a
    /// connect ("Test connection") or a refresh, whose context was loaded
    /// before the server was switched off, edited or removed: no initialize
    /// goes out, and the set-up fails with why.
    #[tokio::test(flavor = "multi_thread")]
    async fn rw_fix4_no_session_is_set_up_with_a_server_switched_off_edited_or_removed() {
        for meanwhile in [
            Meanwhile::Declined,
            Meanwhile::Restored,
            Meanwhile::Edited,
            Meanwhile::Removed,
        ] {
            let db = temp_db();
            let server = scripted_mcp_with(Script {
                numbered_sessions: true,
                ..Script::default()
            });
            let (_record, mut ctx) = call_fixture(&db, &server.url, None);
            let state = McpState::new();
            meanwhile.apply(&db, &state);
            let unchecked = || -> CmdResult<()> { Ok(()) };
            let pw = test_password();
            let scope = test_scope(&state, &db, &pw, &unchecked);
            // What a set-up would be answered with.
            server.release_initialize.send(()).unwrap();
            let err = bounded("the set-up", establish_session(&scope, &mut ctx))
                .await
                .expect_err("no set-up");
            assert_eq!(err.0, meanwhile.refusal(), "{meanwhile:?}");
            assert!(wait_for_teardowns(state.take_teardowns(), LOADED_MACHINE_WAIT).await);
            let seen: Vec<String> = server.methods.try_iter().collect();
            assert!(seen.is_empty(), "{meanwhile:?}: nothing was sent: {seen:?}");
            assert!(state.get_session("s1").is_none(), "{meanwhile:?}");
            assert!(ctx.session.is_none(), "{meanwhile:?}");
        }
    }

    // ── The check also after the initialize, and before every page ──────

    /// A listing already running when the server is switched off, edited or
    /// removed asks for no further page: the session it ran on is ended
    /// where it was set up, and the listing fails with why. (The check before
    /// every page had no test of its own.)
    #[tokio::test(flavor = "multi_thread")]
    async fn rw_fix5_a_listing_asks_for_no_further_page_once_its_server_changed() {
        for meanwhile in EVERY_CHANGE {
            let db = temp_db();
            let server = scripted_mcp_with(Script {
                tools_pages: true,
                numbered_sessions: true,
                hold: Some("tools/list"),
                ..Script::default()
            });
            let (record, mut ctx) = call_fixture(&db, &server.url, Some(session("sess-old")));
            let state = McpState::new();
            state.bind_session(&record, session("sess-old"));
            let unchecked = || -> CmdResult<()> { Ok(()) };
            let pw = test_password();
            let scope = test_scope(&state, &db, &pw, &unchecked);
            let listing = fetch_tools(&scope, &mut ctx);
            let change = async {
                wait_for_method(&server, "tools/list @sess-old").await;
                meanwhile.apply_in_app(&db, &state);
                // Page one's answer.
                server.release_initialize.send(()).unwrap();
            };
            let (listed, ()) = bounded("the request and the change racing it", async {
                tokio::join!(listing, change)
            })
            .await;
            let err = listed.expect_err("the listing stops");
            assert_eq!(err.0, meanwhile.refusal(), "{meanwhile:?}");
            assert!(wait_for_teardowns(state.take_teardowns(), LOADED_MACHINE_WAIT).await);
            let later: Vec<String> = server.methods.try_iter().collect();
            assert!(
                later.iter().any(|m| m == "DELETE sess-old"),
                "{meanwhile:?}: ended where it was set up: {later:?}"
            );
            assert!(
                !later.iter().any(|m| m == "tools/list p2 @sess-old"),
                "{meanwhile:?}: no further page: {later:?}"
            );
            assert!(state.get_session("s1").is_none(), "{meanwhile:?}");
            assert!(ctx.session.is_none(), "{meanwhile:?}");
        }
    }

    /// The server is switched off, edited or removed while the initialize of
    /// a set-up is out. The set-up registered the new session anyway and
    /// sent `notifications/initialized` on it; now it is refused before the
    /// session is ever registered, and that session is ended at the endpoint
    /// the initialize went to, with its credential - nothing new is
    /// contacted.
    #[tokio::test(flavor = "multi_thread")]
    async fn rw_fix5_a_server_changed_while_its_initialize_was_out_gets_no_session() {
        for meanwhile in EVERY_CHANGE {
            let db = temp_db();
            let server = scripted_mcp_with(Script {
                numbered_sessions: true,
                ..Script::default()
            });
            let (_record, mut ctx) = call_fixture(&db, &server.url, None);
            let state = McpState::new();
            let unchecked = || -> CmdResult<()> { Ok(()) };
            let pw = test_password();
            let scope = test_scope(&state, &db, &pw, &unchecked);
            let set_up = establish_session(&scope, &mut ctx);
            let change = async {
                wait_for_method(&server, "initialize @-").await;
                meanwhile.apply_in_app(&db, &state);
                server.release_initialize.send(()).unwrap();
            };
            let (set_up, ()) = bounded("the request and the change racing it", async {
                tokio::join!(set_up, change)
            })
            .await;
            let err = set_up.expect_err("refused once the initialize is answered");
            assert_eq!(err.0, meanwhile.refusal(), "{meanwhile:?}");
            assert!(wait_for_teardowns(state.take_teardowns(), LOADED_MACHINE_WAIT).await);
            let later: Vec<String> = server.methods.try_iter().collect();
            assert!(
                later.iter().any(|m| m == "DELETE sess-1"),
                "{meanwhile:?}: the new session was ended: {later:?}"
            );
            assert!(
                !later
                    .iter()
                    .any(|m| m.starts_with("notifications/initialized")),
                "{meanwhile:?}: nothing more was sent on it: {later:?}"
            );
            assert!(
                state.get_session("s1").is_none(),
                "{meanwhile:?}: never registered"
            );
            assert!(ctx.session.is_none(), "{meanwhile:?}");
        }
    }

    /// A page asked again after its session was renewed (the server had lost
    /// it: 404) was the one request sent after a set-up without looking at
    /// the server once more. Here the change lands after the renewal's
    /// initialize was answered, while its `notifications/initialized` is out
    /// (the set-up's own check is behind it): the page is not asked again,
    /// the new session is ended where it was set up, nothing is registered.
    #[tokio::test(flavor = "multi_thread")]
    async fn rw_fix5_a_page_is_not_asked_again_on_a_renewed_session_once_its_server_changed() {
        for meanwhile in EVERY_CHANGE {
            let db = temp_db();
            let server = scripted_mcp_with(Script {
                tools_pages: true,
                expire_page_two_once: true,
                numbered_sessions: true,
                hold: Some("notifications/initialized"),
                ..Script::default()
            });
            let (record, mut ctx) = call_fixture(&db, &server.url, Some(session("sess-old")));
            let state = McpState::new();
            state.bind_session(&record, session("sess-old"));
            let unchecked = || -> CmdResult<()> { Ok(()) };
            let pw = test_password();
            let scope = test_scope(&state, &db, &pw, &unchecked);
            // The renewal's initialize.
            server.release_initialize.send(()).unwrap();
            let listing = fetch_tools(&scope, &mut ctx);
            let change = async {
                wait_for_method(&server, "notifications/initialized @sess-1").await;
                meanwhile.apply_in_app(&db, &state);
                server.release_initialize.send(()).unwrap();
            };
            let (listed, ()) = bounded("the request and the change racing it", async {
                tokio::join!(listing, change)
            })
            .await;
            let err = listed.expect_err("the page is not asked again");
            assert_eq!(err.0, meanwhile.refusal(), "{meanwhile:?}");
            assert!(wait_for_teardowns(state.take_teardowns(), LOADED_MACHINE_WAIT).await);
            let later: Vec<String> = server.methods.try_iter().collect();
            assert!(
                !later.iter().any(|m| m == "tools/list p2 @sess-1"),
                "{meanwhile:?}: {later:?}"
            );
            assert!(
                later.iter().any(|m| m == "DELETE sess-1"),
                "{meanwhile:?}: ended where it was set up: {later:?}"
            );
            assert!(state.get_session("s1").is_none(), "{meanwhile:?}");
            assert!(ctx.session.is_none(), "{meanwhile:?}");
        }
    }

    /// The code reviewer's probe: the change lands while the renewal's
    /// initialize is out. It got `notifications/initialized` and the page
    /// again on the new session, which stayed registered. Two checks stop it
    /// now - the set-up's own, after the initialize, and the one before the
    /// page is asked again; each is pinned by a test of its own above.
    #[tokio::test(flavor = "multi_thread")]
    async fn rw_fix5_a_session_is_not_renewed_when_its_server_changes_during_the_renewal() {
        for meanwhile in EVERY_CHANGE {
            let db = temp_db();
            let server = scripted_mcp_with(Script {
                tools_pages: true,
                expire_page_two_once: true,
                numbered_sessions: true,
                ..Script::default()
            });
            let (record, mut ctx) = call_fixture(&db, &server.url, Some(session("sess-old")));
            let state = McpState::new();
            state.bind_session(&record, session("sess-old"));
            let unchecked = || -> CmdResult<()> { Ok(()) };
            let pw = test_password();
            let scope = test_scope(&state, &db, &pw, &unchecked);
            let listing = fetch_tools(&scope, &mut ctx);
            let change = async {
                wait_for_method(&server, "initialize @-").await;
                meanwhile.apply_in_app(&db, &state);
                server.release_initialize.send(()).unwrap();
            };
            let (listed, ()) = bounded("the request and the change racing it", async {
                tokio::join!(listing, change)
            })
            .await;
            let err = listed.expect_err("no listing on a renewed session");
            assert_eq!(err.0, meanwhile.refusal(), "{meanwhile:?}");
            assert!(wait_for_teardowns(state.take_teardowns(), LOADED_MACHINE_WAIT).await);
            let later: Vec<String> = server.methods.try_iter().collect();
            assert!(
                !later.iter().any(|m| m == "tools/list p2 @sess-1"),
                "{meanwhile:?}: {later:?}"
            );
            assert!(
                state.get_session("s1").is_none(),
                "{meanwhile:?}: nothing is registered"
            );
            assert!(ctx.session.is_none(), "{meanwhile:?}");
        }
    }

    /// A call whose server changes while the initialize of its set-up - or
    /// of the renewal after a 404 - is out. The set-up now refuses before the
    /// new session is registered; the call is then refused by the gate (and
    /// audited as a refusal, as when the change came after the set-up), the
    /// new session is ended where it was set up, and nothing more is sent.
    #[tokio::test(flavor = "multi_thread")]
    async fn rw_fix5_a_call_whose_server_changes_during_its_set_up_is_refused() {
        for meanwhile in EVERY_CHANGE {
            for renewal in [false, true] {
                let db = temp_db();
                let server = scripted_mcp_with(Script {
                    expire_first_call: renewal,
                    numbered_sessions: true,
                    ..Script::default()
                });
                let existing = renewal.then(|| session("sess-old"));
                let (record, mut ctx) = call_fixture(&db, &server.url, existing);
                let state = McpState::new();
                if renewal {
                    state.bind_session(&record, session("sess-old"));
                }
                let regate = || regate_call(&db, &record, "t", "execute", true);
                let body = tool_call_body();
                let unchecked = || -> CmdResult<()> { Ok(()) };
                let pw = test_password();
                let scope = test_scope(&state, &db, &pw, &unchecked);
                let call = run_tool_call(&scope, &mut ctx, &body, &regate);
                let change = async {
                    wait_for_method(&server, "initialize @-").await;
                    meanwhile.apply_in_app(&db, &state);
                    server.release_initialize.send(()).unwrap();
                };
                let (sent, ()) = bounded("the request and the change racing it", async {
                    tokio::join!(call, change)
                })
                .await;
                match sent {
                    Ok(CallSent::Refused { reason, .. }) => {
                        assert_eq!(reason, meanwhile.gate_refusal(), "{meanwhile:?} {renewal}")
                    }
                    other => panic!("{meanwhile:?} renewal={renewal}: refused: {other:?}"),
                }
                assert!(wait_for_teardowns(state.take_teardowns(), LOADED_MACHINE_WAIT).await);
                let later: Vec<String> = server.methods.try_iter().collect();
                assert!(
                    later.iter().any(|m| m == "DELETE sess-1"),
                    "{meanwhile:?} renewal={renewal}: the new session was ended: {later:?}"
                );
                assert!(
                    !later
                        .iter()
                        .any(|m| m.starts_with("notifications/initialized")
                            || m.starts_with("tools/call")),
                    "{meanwhile:?} renewal={renewal}: nothing more: {later:?}"
                );
                assert!(
                    state.get_session("s1").is_none(),
                    "{meanwhile:?} renewal={renewal}: nothing is registered"
                );
            }
        }
    }

    /// The other side of [`set_up_for_call`]: a set-up that fails for any
    /// other reason - the server answers the initialize with HTTP 500, or
    /// nothing listens at its address - stays a failure. A first set-up
    /// returns the error; a renewal after a 404 is a call that went out and
    /// failed, audited as failed. (Turning every failed set-up into a refusal
    /// passed every test before this one.)
    ///
    /// What pins "no 'denied' row" here is the result type each case is
    /// matched against: of the results of `run_tool_call`, the command
    /// (`mcp_call_tool`) writes that row for `Refused` only, and nothing at
    /// this level writes one - an assertion on the audit rows could not fail
    /// here.
    #[tokio::test(flavor = "multi_thread")]
    async fn rw_fix6_a_set_up_that_fails_for_another_reason_stays_a_failure() {
        let unchecked = || -> CmdResult<()> { Ok(()) };
        let pw = test_password();
        let body = tool_call_body();
        // A first set-up, answered HTTP 500.
        let db = temp_db();
        let server = scripted_mcp_with(Script {
            fail_initialize: true,
            numbered_sessions: true,
            ..Script::default()
        });
        let (record, mut ctx) = call_fixture(&db, &server.url, None);
        let state = McpState::new();
        let regate = || regate_call(&db, &record, "t", "execute", true);
        let scope = test_scope(&state, &db, &pw, &unchecked);
        match bounded("the call", run_tool_call(&scope, &mut ctx, &body, &regate)).await {
            // An error, not a refusal.
            Err(e) => assert!(e.0.contains("HTTP 500"), "{}", e.0),
            other => panic!("a failed first set-up is an error: {other:?}"),
        }
        assert!(state.get_session("s1").is_none());
        // A renewal after a 404, answered HTTP 500: the call went out.
        let db = temp_db();
        let server = scripted_mcp_with(Script {
            expire_first_call: true,
            fail_initialize: true,
            numbered_sessions: true,
            ..Script::default()
        });
        let (record, mut ctx) = call_fixture(&db, &server.url, Some(session("sess-old")));
        let state = McpState::new();
        state.bind_session(&record, session("sess-old"));
        let regate = || regate_call(&db, &record, "t", "execute", true);
        let scope = test_scope(&state, &db, &pw, &unchecked);
        let called =
            match bounded("the call", run_tool_call(&scope, &mut ctx, &body, &regate)).await {
                Ok(CallSent::Sent {
                    called: Err(e),
                    list_changed,
                    ..
                }) => {
                    assert!(e.0.contains("HTTP 500"), "{}", e.0);
                    finish_tool_call(&db, &sample_audit(), list_changed, Err(e), || async {
                        Ok(())
                    })
                    .await
                }
                other => panic!("a failed renewal is a failed call: {other:?}"),
            };
        assert!(called.is_err());
        let rows = tool_call_rows(&db);
        assert!(
            rows.iter().any(|d| d.contains("result=failed")),
            "audited as failed: {rows:?}"
        );
        // Nothing listens at the address.
        let db = temp_db();
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/mcp", closed.local_addr().unwrap());
        drop(closed);
        let (record, mut ctx) = call_fixture(&db, &url, None);
        let state = McpState::new();
        let regate = || regate_call(&db, &record, "t", "execute", true);
        let scope = test_scope(&state, &db, &pw, &unchecked);
        match bounded("the call", run_tool_call(&scope, &mut ctx, &body, &regate)).await {
            Err(e) => assert!(e.0.starts_with("MCP request failed"), "{}", e.0),
            other => panic!("an unreachable server is an error: {other:?}"),
        }
    }
}
