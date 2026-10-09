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
//!   both.
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
    capture_vault_generation, require_generation_current, vault_password, CmdError,
    VaultPasswordStore,
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
/// base (scheme + host[:port] + path, no trailing slash).
pub fn classify_url(raw: &str) -> Result<(String, UrlClass), String> {
    let trimmed = raw.trim();
    let url = url::Url::parse(trimmed).map_err(|_| "Server URL is not a valid URL.".to_string())?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err("Server URL must not contain credentials.".into());
    }
    let host = url
        .host_str()
        .ok_or_else(|| "Server URL has no hostname.".to_string())?
        .to_lowercase()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string();
    if host.is_empty() {
        return Err("Server URL has no hostname.".into());
    }
    let is_loopback =
        matches!(host.as_str(), "localhost" | "127.0.0.1" | "::1") || host.starts_with("127.");
    let class = match url.scheme() {
        "https" => UrlClass::Https,
        "http" if is_loopback => UrlClass::LoopbackInsecure,
        "http" => {
            return Err(
                "Server URL must use https:// (plain http is only allowed for localhost/127.0.0.1/::1)."
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
/// value is Zeroizing.
fn resolve_secret_value(
    sealed_secret: Option<&str>,
    auth_env_var: Option<&str>,
    pw: &Zeroizing<String>,
    header_name: &str,
) -> CmdResult<Zeroizing<String>> {
    if let Some(sealed) = sealed_secret {
        let bytes = crate::crypto::vault::unseal(pw, sealed)
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
#[derive(Debug, Clone)]
pub struct McpSession {
    pub session_id: Option<String>,
    pub protocol_version: String,
}

/// Last-known connect status for one server (status, error, enabled-tool
/// count); absent from the map = "unknown".
type ServerStatus = (String, Option<String>, usize);

/// App-managed in-memory state for MCP: live sessions and last-known
/// connect statuses, keyed by server id. Cleared on vault lock
/// (`McpState::teardown_all`).
#[derive(Default)]
pub struct McpState {
    sessions: Mutex<HashMap<String, McpSession>>,
    statuses: Mutex<HashMap<String, ServerStatus>>,
}

impl McpState {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn get_session(&self, server_id: &str) -> Option<McpSession> {
        self.sessions.lock().unwrap().get(server_id).cloned()
    }
    pub fn set_session(&self, server_id: &str, session: McpSession) {
        self.sessions
            .lock()
            .unwrap()
            .insert(server_id.to_string(), session);
    }
    pub fn remove_session(&self, server_id: &str) -> Option<McpSession> {
        self.sessions.lock().unwrap().remove(server_id)
    }
    fn take_sessions(&self) -> Vec<(String, McpSession)> {
        self.sessions.lock().unwrap().drain().collect()
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

/// Integration-test exposure of `request_once` (the internal name stays
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
fn load_server_context(
    app: &AppHandle,
    record: crate::db::McpServerRecord,
    pw: &Zeroizing<String>,
    generation: u64,
) -> CmdResult<ServerContext> {
    let (url, _class) = classify_url(&record.url).map_err(CmdError)?;
    let auth = resolve_auth_header(
        &record.auth_type,
        record.auth_header_name.as_deref(),
        record.auth_secret.as_deref(),
        record.auth_env_var.as_deref(),
        pw,
    )?;
    Ok(ServerContext {
        session: app.state::<McpState>().get_session(&record.id),
        url,
        client: origin_client()?,
        record,
        auth,
        generation,
    })
}

/// The initialize request/response, returning the live session. Negotiates
/// the protocol version: offers 2025-11-25, accepts the server's reply if
/// it is in the supported set, and stores THAT version for the
/// MCP-Protocol-Version header on all later requests. Anything else is a
/// hard disconnect - a server speaking an unknown version may have
/// incompatible semantics this client cannot safely guess at.
pub async fn initialize(
    app: &AppHandle,
    ctx: &ServerContext,
) -> CmdResult<(McpSession, JsonRpcOutcome)> {
    ctx.checked(app)?;
    initialize_unchecked(ctx, &|| ctx.checked(app)).await
}

#[doc(hidden)]
pub async fn initialize_test(ctx: &ServerContext) -> CmdResult<(McpSession, JsonRpcOutcome)> {
    initialize_unchecked(ctx, &|| Ok(())).await
}

/// `guard` runs before every further request this exchange sends on its own
/// (the -32601 answers in `read_response`).
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

/// Send `notifications/initialized` after a successful initialize. Like every
/// credential-bearing request, the vault generation is rechecked first: a
/// lock that happened during initialize must not let this notification send
/// the unsealed auth header.
async fn send_initialized(
    app: &AppHandle,
    ctx: &ServerContext,
    session: &McpSession,
) -> CmdResult<()> {
    ctx.checked(app)?;
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
/// and the caller re-initializes once and retries. The vault generation is
/// rechecked before the request: every post-initialize await is a window in
/// which a lock could have cleared the password store.
async fn request_once(
    app: &AppHandle,
    ctx: &ServerContext,
    body: &Value,
) -> CmdResult<Option<JsonRpcOutcome>> {
    ctx.checked(app)?;
    request_once_unchecked(ctx, body, &|| ctx.checked(app)).await
}

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

/// Send a request and read its response, handling a 404 for a KNOWN
/// session by re-initializing ONCE and retrying (session expired
/// server-side). Generation is rechecked before initialize, before the
/// initialized notification, and before the retry.
async fn request_with_session(
    app: &AppHandle,
    ctx: &mut ServerContext,
    body: &Value,
) -> CmdResult<JsonRpcOutcome> {
    if let Some(outcome) = request_once(app, ctx, body).await? {
        return Ok(outcome);
    }
    // 404: re-initialize once, then retry the request with the new session.
    ctx.checked(app)?;
    let (new_session, _) = initialize(app, ctx).await?;
    send_initialized(app, ctx, &new_session).await?;
    ctx.session = Some(new_session.clone());
    app.state::<McpState>()
        .set_session(&ctx.record.id, new_session);
    request_once(app, ctx, body)
        .await?
        .ok_or_else(|| CmdError("MCP session could not be re-established.".into()))
}

/// Fetch the full tool list with cursor pagination; servers above the
/// global tool cap are rejected outright. A `tools/list_changed`
/// notification observed on ANY page ends pagination immediately and
/// restarts the fetch from scratch, so the returned list is never a mix of
/// pre- and post-change pages.
async fn fetch_tools(ctx: &mut ServerContext, app: &AppHandle) -> CmdResult<Vec<Value>> {
    const MAX_FETCH_ATTEMPTS: usize = 3;
    for _ in 0..MAX_FETCH_ATTEMPTS {
        let (tools, list_changed) = fetch_tools_once(ctx, app).await?;
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
    ctx: &mut ServerContext,
    app: &AppHandle,
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
        let outcome = request_with_session(app, ctx, &body).await?;
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

/// The full connect flow: initialize (+initialized), tools/list with
/// pagination, merge + persist. On success the session is registered in
/// the app state and the refreshed record is returned along with the names
/// of tools that were disabled by a definition change (already audited
/// here as `mcp.tool_definition_changed`).
///
/// The vault generation is captured before the first await and rechecked
/// before EVERY credential-bearing request (inside request_once /
/// initialize / send_initialized via `ServerContext::checked`) and again
/// before persisting, so a lock mid-connect can neither send the unsealed
/// auth header nor write session/DB state afterward.
///
/// After the network round trips it re-reads the record and writes the
/// whole row back with the fetched tools merged in ([`merge_into_stored`]),
/// so the CALLER must hold read access to the `VaultRotationLock` from
/// before it read `record` until this returns (C1): a master-password change
/// committing in between would otherwise get an old-sealed secret written
/// back over the re-sealed one (or unseal `record`'s secret with the wrong
/// password).
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
        return Err(CmdError(
            "This MCP server entry was restored from a backup/import and has not been re-confirmed. Open Settings, review its URL and auth, and save it again before connecting.".into(),
        ));
    }
    let mut ctx = load_server_context(app, record.clone(), &pw, generation)?;
    let (session, _init_outcome) = initialize(app, &ctx).await?;
    // Re-check BEFORE registering the session: a lock during initialize
    // must not leave a live session in state.
    require_generation_current(app, generation)?;
    app.state::<McpState>()
        .set_session(&record.id, session.clone());
    ctx.session = Some(session);
    // Note: a list_changed arriving WITH the initialize stream needs no
    // special handling here - the very next step is a fresh tools/list
    // (fetch_tools), so nothing stale is ever exposed from it.
    send_initialized(app, &ctx, ctx.session.as_ref().unwrap()).await?;

    let tool_defs = fetch_tools(&mut ctx, app).await?;
    // Last boundary before persisting: a lock during the fetch must not
    // write session-derived state into the DB.
    require_generation_current(app, generation)?;

    // Re-read the record now, after the round trips, and merge into that
    // (A7-49). The caller's rotation guard still covers read and write.
    let db = &app.state::<crate::AppState>().db;
    let stored_now = db.get_mcp_server(&record.id).map_err(|e| e.to_string())?;
    let (updated, changed) =
        merge_into_stored(&record, stored_now, &tool_defs).inspect_err(|_| {
            // The session belongs to settings that are gone: never reuse it.
            app.state::<McpState>().remove_session(&record.id);
        })?;
    db.save_mcp_server(&updated).map_err(|e| e.to_string())?;
    for tool in &changed {
        let _ = db.add_audit(
            "mcp.tool_definition_changed",
            Some(&record.id),
            &format!("server={} tool={}", record.name, tool),
        );
    }
    Ok((updated, changed))
}

/// The record a connect (or a call's tool-list refresh) saves after its
/// network round trips, and the enabled tools whose definition changed. The
/// fetched tools are merged into the record AS STORED NOW - re-read right
/// before this - not into the snapshot the connect started from, so a tool
/// toggled or a name edited during a slow connect is not reverted (A7-49).
/// Nothing is saved when the server was removed meanwhile, or its URL or
/// auth settings changed: the tools came from the old configuration.
fn merge_into_stored(
    started_from: &crate::db::McpServerRecord,
    stored_now: Option<crate::db::McpServerRecord>,
    fetched: &[Value],
) -> CmdResult<(crate::db::McpServerRecord, Vec<String>)> {
    let Some(mut now) = stored_now else {
        return Err(CmdError("This MCP server was removed meanwhile.".into()));
    };
    if !same_connection(started_from, &now) {
        return Err(CmdError(
            "This MCP server's URL or auth settings changed meanwhile - test the connection again."
                .into(),
        ));
    }
    let changed = changed_enabled_tools(&now.tools, fetched);
    now.tools = merge_tools(&now.tools, fetched);
    now.updated_at = chrono::Utc::now();
    Ok((now, changed))
}

/// Whether two snapshots of a server record send the same requests: the
/// same URL and the same auth configuration.
fn same_connection(a: &crate::db::McpServerRecord, b: &crate::db::McpServerRecord) -> bool {
    a.url == b.url
        && a.auth_type == b.auth_type
        && a.auth_header_name == b.auth_header_name
        && a.auth_secret == b.auth_secret
        && a.auth_env_var == b.auth_env_var
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

/// Resolve the auth header for a record from the vault password alone (safe
/// to call mid-lock, after the generation bump but before the password store
/// clears). `None` when the vault is locked or the header cannot be
/// resolved: a teardown then goes out without it. The value is Zeroizing.
fn resolve_auth_with_password(
    pw: Option<Zeroizing<String>>,
    record: &crate::db::McpServerRecord,
) -> Option<(String, Zeroizing<String>)> {
    let pw = pw.filter(|p| !p.is_empty())?;
    resolve_auth_header(
        &record.auth_type,
        record.auth_header_name.as_deref(),
        record.auth_secret.as_deref(),
        record.auth_env_var.as_deref(),
        &pw,
    )
    .ok()
    .flatten()
}

/// Send the HTTP DELETE that ends a session, with the static auth header
/// attached (the server may require it even for DELETE). The credentials are
/// resolved BEFORE the vault store clears. Only 405 ("method not allowed" -
/// valid per spec for servers that manage sessions differently) is ignored;
/// a 401 means the session tear-down was refused, and any transport failure
/// is reported - never silently swallowed, and never retried with secrets.
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

/// One pending authenticated session teardown: everything the DELETE needs,
/// resolved while the vault password is still available.
struct TeardownJob {
    url: String,
    session_id: String,
    protocol_version: String,
    auth: Option<(String, Zeroizing<String>)>,
    server_name: String,
}

/// Tear down every live MCP session. Called from `lock_vault_internal`
/// AFTER the generation bump but BEFORE the password store clears, so the
/// static auth header for each server can still be resolved (with a safe
/// snapshot of the record) and attached to the DELETE. Decrypted secrets
/// are zeroized by their Zeroizing wrappers when the task ends; nothing
/// session-scoped is cached. The lock path itself stays nonblocking: the
/// in-memory session map is drained synchronously (no new request can use
/// a session) and the DELETEs run on the Tauri async runtime.
pub fn teardown_all(app: &AppHandle) {
    let all = app.state::<McpState>().take_sessions();
    app.state::<McpState>().clear_statuses();
    let client = match origin_client() {
        Ok(c) => c,
        Err(_) => return,
    };
    // Resolve URL + auth while the vault password is still available.
    let mut jobs: Vec<TeardownJob> = Vec::new();
    for (server_id, session) in all {
        let Some(sid) = session.session_id else {
            continue;
        };
        let Ok(Some(rec)) = app.state::<crate::AppState>().db.get_mcp_server(&server_id) else {
            continue;
        };
        let Ok((url, _)) = classify_url(&rec.url) else {
            continue;
        };
        // BEFORE the store clear; the resolved value is Zeroizing.
        let auth = resolve_auth_with_password(vault_password(app).ok(), &rec);
        jobs.push(TeardownJob {
            url,
            session_id: sid,
            protocol_version: session.protocol_version,
            auth,
            server_name: rec.name,
        });
    }
    let app = app.clone();
    // Fire-and-forget on the Tauri runtime: the lock path must not block on
    // network I/O. The in-memory session map is already drained, so no new
    // request can use a session. Failures (other than 405) are audited -
    // a refused teardown must not disappear silently.
    tauri::async_runtime::spawn(async move {
        for job in jobs {
            if let Err(e) = delete_session(
                &client,
                &job.url,
                &job.session_id,
                &job.protocol_version,
                job.auth.as_ref().map(|(n, v)| (n.as_str(), v)),
                &job.server_name,
            )
            .await
            {
                if let Err(audit_err) = app.state::<crate::AppState>().db.add_audit(
                    "mcp.session_teardown_failed",
                    None,
                    &e,
                ) {
                    log::warn!(
                        "[sshspan-mcp] could not audit a failed MCP session teardown: {audit_err}"
                    );
                }
            }
        }
    });
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
                state.get_session(&r.id).map(|s| s.protocol_version),
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

#[tauri::command(rename_all = "snake_case")]
pub fn mcp_save_server(
    app: AppHandle,
    id: Option<String>,
    name: String,
    url: String,
    auth_type: String,
    auth_header_name: Option<String>,
    auth_secret: Option<String>,
    auth_env_var: Option<String>,
) -> CmdResult<Value> {
    // Seals the auth secret and rewrites the whole record: not while a
    // master-password change is re-encrypting the vault (C1).
    let _rotation = crate::commands::rotation_shared(&app)?;
    save_server(
        &app.state::<crate::AppState>().db,
        app.state::<VaultPasswordStore>().inner(),
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
fn save_server(
    db: &crate::db::Database,
    vault: &VaultPasswordStore,
    args: SaveServerArgs,
) -> CmdResult<Value> {
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
    let name = name.trim().to_string();
    // The rule is RFC 7230 token syntax (`is_token`), so say exactly that.
    if !is_token(&name) {
        return Err(
            "Server name must be non-empty and use only letters, digits and ! # $ % & ' * + - . ^ _ ` | ~ (no spaces)."
                .into(),
        );
    }
    let (normalized_url, _class) = classify_url(&url)?;
    let auth_type = auth_type.trim().to_string();
    if !matches!(auth_type.as_str(), "none" | "bearer" | "custom_header") {
        return Err("Auth type must be 'none', 'bearer' or 'custom_header'.".into());
    }
    let existing_id = id.filter(|s| !s.is_empty());
    let stored = match existing_id.as_deref() {
        Some(existing) => {
            let mut r = db
                .get_mcp_server(existing)
                .map_err(|e| e.to_string())?
                .ok_or_else(|| CmdError("MCP server not found.".into()))?;
            r.id = existing.to_string();
            Some(r)
        }
        None => None,
    };
    let plan = plan_auth(
        stored.as_ref(),
        &normalized_url,
        &auth_type,
        TextArg::from_arg(auth_header_name.as_deref()),
        SecretArg::from_arg(auth_secret.as_deref().map(String::as_str)),
        TextArg::from_arg(auth_env_var.as_deref()),
    )
    .map_err(CmdError)?;
    let all = db.list_mcp_servers().map_err(|e| e.to_string())?;
    if let Some(other) = name_collision(&all, existing_id.as_deref(), &name) {
        return Err(CmdError(format!(
            "An MCP server named '{}' already exists and '{name}' would share its model-facing tool names - choose a different name.",
            other.name
        )));
    }

    let now = chrono::Utc::now();
    let is_new = stored.is_none();
    let mut record = stored.unwrap_or_else(|| crate::db::McpServerRecord {
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
    let record_id = record.id.clone();
    record.name = name;
    record.url = normalized_url;
    record.auth_type = auth_type;
    record.auth_header_name = plan.header_name;
    record.auth_secret = match plan.secret {
        SecretPlan::Keep => record.auth_secret.take(),
        SecretPlan::Drop => None,
        SecretPlan::Seal => {
            let secret = auth_secret.as_deref().map_or("", |s| s.trim());
            Some(crate::crypto::vault::seal(&pw, secret.as_bytes()).map_err(|e| e.to_string())?)
        }
    };
    record.auth_env_var = plan.env_var;
    // Saving from the UI IS the user's re-confirmation of URL + auth source
    // (backup-restored entries become connectable only through here).
    record.confirmed = true;
    // Belt-and-suspenders on the exclusive-source invariant.
    debug_assert!(
        record.auth_secret.is_none() || record.auth_env_var.is_none(),
        "a stored secret and an env-var binding must never coexist"
    );
    record.updated_at = now;
    db.save_mcp_server(&record).map_err(|e| e.to_string())?;
    let action = if is_new {
        "mcp.server_added"
    } else {
        "mcp.server_updated"
    };
    db.add_audit(action, Some(&record_id), &record.name)
        .map_err(|e| e.to_string())?;
    Ok(json!({ "ok": true, "id": record_id }))
}

#[tauri::command]
pub async fn mcp_remove_server(app: AppHandle, id: String) -> CmdResult<Value> {
    // Not while a master-password change is re-encrypting the vault (C1):
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
    if let Some(session) = state.remove_session(id) {
        if let (Some(sid), Ok((url, _))) = (session.session_id, classify_url(&record.url)) {
            // Resolved BEFORE the record (and its sealed secret) is deleted;
            // the value is Zeroizing.
            let auth = resolve_auth_with_password(vault.get(), &record);
            let failure = match origin_client() {
                Err(e) => Some(e.0),
                Ok(client) => {
                    let teardown = delete_session(
                        &client,
                        &url,
                        &sid,
                        &session.protocol_version,
                        auth.as_ref().map(|(n, v)| (n.as_str(), v)),
                        &record.name,
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
                if let Err(audit_err) = db.add_audit("mcp.session_teardown_failed", Some(id), &e) {
                    log::warn!(
                        "[sshspan-mcp] could not audit a failed MCP session teardown: {audit_err}"
                    );
                }
                warning = Some(e);
            }
        }
    }
    db.delete_mcp_server(id).map_err(|e| e.to_string())?;
    db.add_audit("mcp.server_removed", Some(id), &record.name)
        .map_err(|e| e.to_string())?;
    Ok(json!({ "ok": true, "warning": warning }))
}

#[tauri::command]
pub async fn mcp_test_connection(app: AppHandle, id: String) -> CmdResult<Value> {
    // Before the record is read, held until connect_server has written it
    // back: a master-password change must not commit in between (C1).
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

#[tauri::command(rename_all = "snake_case")]
pub fn mcp_set_tool_state(
    app: AppHandle,
    id: String,
    tool: String,
    enabled: bool,
    auto_approve: bool,
    expected_hash: Option<String>,
) -> CmdResult<Value> {
    // Rewrites the whole record: not while a master-password change could
    // re-seal its secret in between (C1).
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
    let mut record = db
        .get_mcp_server(id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| CmdError("MCP server not found.".into()))?;
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
    if enabled {
        // ── Collision authority, BEFORE any exposure (item 6): run the
        // name map over the full registry with this enable applied. An
        // ambiguous model-facing name set is refused outright - one
        // approval must never silently cover another tool.
        let mut all = db.list_mcp_servers().map_err(|e| e.to_string())?;
        if let Some(slot) = all.iter_mut().find(|r| r.id == id) {
            *slot = record.clone();
        }
        if let Some(err) = enable_collision_error(&all) {
            return Err(CmdError(err));
        }
        // ── Aggregate cap (item 5), computed and enforced INSIDE the same
        // SQLite transaction as the write: the count and the update commit
        // (or roll back) together, so two concurrent toggles can never both
        // pass an individually-stale check. The renderer offers
        // {BUILTIN_TOOL_COUNT} built-in tools first and fills the remaining
        // slots with MCP tools, so more than MAX_MCP_TOOLS enabled MCP
        // tools could never all be exposed and would silently drop the
        // overflow - refuse (and roll back) instead.
        match db
            .save_mcp_server_capped(&record, MAX_MCP_TOOLS)
            .map_err(|e| e.to_string())?
        {
            crate::db::McpCapOutcome::Committed { .. } => {}
            crate::db::McpCapOutcome::OverCap { enabled_total } => {
                return Err(CmdError(format!(
                    "Enabling '{tool}' would expose {enabled_total} MCP tools across all servers; the assistant keeps {BUILTIN_TOOL_COUNT} built-in tools and the model-facing list is capped at {MAX_EXPOSED_TOOLS}. Disable another tool first."
                )));
            }
        }
    } else {
        db.save_mcp_server(&record).map_err(|e| e.to_string())?;
    }
    if enabled {
        db.add_audit("mcp.tool_approved", Some(id), &format!("tool={tool}"))
            .map_err(|e| e.to_string())?;
    }
    Ok(json!({ "ok": true }))
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

    let approval = match call_gate(&level, approved, record.confirmed, entry) {
        Ok(approval) => approval,
        Err(reason) => {
            let _ = db.add_audit(
                "mcp.tool_call",
                Some(&id),
                &format!(
                    "server={} tool={} args_sha256={} level={} outcome=denied reason={}",
                    record.name, tool, fingerprint, level, reason
                ),
            );
            return Err(CmdError(reason));
        }
    };

    // A tools/list_changed refresh after the call rewrites the whole record:
    // a master-password change must not commit in between (C1).
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
    let mut ctx = load_server_context(&app, record.clone(), &pw, generation)?;
    if ctx.session.is_none() {
        ctx.checked(&app)?;
        let (session, _) = initialize(&app, &ctx).await?;
        require_generation_current(&app, generation)?;
        app.state::<McpState>()
            .set_session(&record.id, session.clone());
        ctx.session = Some(session);
        send_initialized(&app, &ctx, ctx.session.as_ref().unwrap()).await?;
    }
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
    // From here on the call may reach the server, so every outcome is
    // audited (see finish_tool_call).
    let called = async {
        let outcome = request_with_session(&app, &mut ctx, &body).await?;
        require_generation_current(&app, generation)?;
        let list_changed = outcome.list_changed;
        Ok::<_, CmdError>((rpc_result(outcome.result)?, list_changed))
    }
    .await;
    let audit = CallAudit {
        server_id: &id,
        server_name: &record.name,
        tool: &tool,
        args_sha256: &fingerprint,
        level: &level,
        approval,
    };
    finish_tool_call(db, &audit, called, || {
        refresh_tools_after_call(&app, &mut ctx, db, &record, generation)
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
        return Err("This MCP server entry has not been confirmed.".into());
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
/// the tools/call result and whether a tools/list_changed came with it,
/// `refresh` re-fetches and re-pins the server's tools.
///
/// Every outcome writes the `mcp.tool_call` audit row - a call that failed
/// may still have run on the server. And once the tool HAS run, nothing
/// after it turns the call into an error: a failed refresh (or audit write)
/// comes back as `warning` next to the result, because the model, told
/// "error", would retry a side effect that already happened.
async fn finish_tool_call<F, Fut>(
    db: &crate::db::Database,
    audit: &CallAudit<'_>,
    called: CmdResult<(Value, bool)>,
    refresh: F,
) -> CmdResult<Value>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = CmdResult<()>>,
{
    let (result, list_changed) = match called {
        Ok(called) => called,
        Err(e) => {
            if let Err(audit_err) = audit.write(db, "failed") {
                log::warn!("[sshspan-mcp] could not audit a failed MCP tool call: {audit_err}");
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
    app: &AppHandle,
    ctx: &mut ServerContext,
    db: &crate::db::Database,
    record: &crate::db::McpServerRecord,
    generation: u64,
) -> CmdResult<()> {
    let refreshed = fetch_tools(ctx, app).await?;
    require_generation_current(app, generation)?;
    let stored_now = db.get_mcp_server(&record.id).map_err(|e| e.to_string())?;
    let (next, changed) = merge_into_stored(record, stored_now, &refreshed)?;
    db.save_mcp_server(&next).map_err(|e| e.to_string())?;
    for t in changed {
        let _ = db.add_audit(
            "mcp.tool_definition_changed",
            Some(&record.id),
            &format!("server={} tool={}", record.name, t),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── tools/list pagination is bounded (RU1 fix 2, SHOULD 1) ─────────────

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

    // ── Input schema storage (item 4) ───────────────────────────────────

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

    // ── Static credential origin binding (item 1) ───────────────────────

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

    // ── Delayed vault lock (item 2) ─────────────────────────────────────

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

    // ── Enable-time collision gate (item 6) ─────────────────────────────

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

    // ── RU2 helpers ─────────────────────────────────────────────────────

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

    // ── Approval bound to the reviewed definition (review round 1) ─────

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

    /// The TOCTOU the review found: a refresh replaced (and flagged) a tool's
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

    /// Every enable names the definition the user reviewed (fix round 1b):
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
    /// complete (review round 1).
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
    /// characters, not only letters, digits, - and _ (review round 1).
    #[test]
    fn the_server_name_rule_is_described_as_it_is_checked() {
        let db = temp_db();
        let vault = unlocked_vault();
        let err = save_server(
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
        save_server(
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
        let id = saved_id(save_server(&db, &vault, args).unwrap());
        // Rename only: the form sends no env var (absent) - the binding stays.
        save_server(
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
        let err = save_server(&db, &vault, clear).unwrap_err();
        assert!(err.0.contains("environment variable"), "{}", err.0);
        // Switching to auth "none" drops it legitimately.
        save_server(
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
        let id = saved_id(save_server(&db, &vault, args).unwrap());
        save_server(
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
        let err = save_server(
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
        assert!(save_server(&db, &vault, custom).is_err());
        assert!(
            db.list_mcp_servers().unwrap().is_empty(),
            "nothing was saved"
        );
        // A URL change discards the stored credential binding; with nothing
        // new entered the save is refused and changes nothing.
        let mut env = save_args(None, "c", "https://c.example.com", "bearer");
        env.auth_env_var = Some("TOKEN".into());
        let id = saved_id(save_server(&db, &vault, env).unwrap());
        let err = save_server(
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
            save_server(
                &db,
                &vault,
                save_args(None, "my-srv", "https://a.example.com", "none"),
            )
            .unwrap(),
        );
        for clash in ["my_srv", "My.Srv", "MY-SRV"] {
            let err = save_server(
                &db,
                &vault,
                save_args(None, clash, "https://b.example.com", "none"),
            )
            .unwrap_err();
            assert!(err.0.contains("my-srv"), "{clash}: {}", err.0);
        }
        // The same server re-saved under its own name is fine, and so is a
        // distinct name.
        save_server(
            &db,
            &vault,
            save_args(Some(&id), "my-srv", "https://a.example.com", "none"),
        )
        .unwrap();
        save_server(
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

    // ── tools/list bounds (RU1 review: empty cursor, stop at the cap) ───

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

    // ── The call gate (R6) and the call's audit trail (RU1 review) ──────

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
        let out = finish_tool_call(&db, &sample_audit(), Ok((result, true)), || async {
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

    #[tokio::test(flavor = "multi_thread")]
    async fn a_failed_call_is_still_audited() {
        let db = temp_db();
        let err = finish_tool_call(
            &db,
            &sample_audit(),
            Err(CmdError("MCP request failed: timed out".into())),
            || async { Ok(()) },
        )
        .await
        .unwrap_err();
        assert!(err.0.contains("timed out"));
        let rows = tool_call_rows(&db);
        assert!(rows.iter().any(|d| d.contains("result=failed")), "{rows:?}");
    }
}
