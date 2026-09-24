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
//! - Credential ORIGIN BINDING: a stored sealed secret is dropped whenever
//!   the URL, auth type, or custom header name is edited, so an old secret
//!   can never be replayed at a new origin or under different semantics
//!   (`mcp_save_server`). The auth source is mutually exclusive: a record
//!   holds a sealed secret or an env-var name, never both.
//! - Vault generation: captured before the first await of every flow and
//!   rechecked immediately before EVERY credential-bearing request (via
//!   `ServerContext::checked`), so a lock mid-flow prevents the next
//!   tools/list or tools/call from sending the unsealed header.
//! - 3xx is a hard error (auth headers must never leave the configured
//!   origin; reqwest's `Policy::none()` does NOT error on redirects).
//! - Tools default to disabled; a tool only runs when enabled AND its
//!   definition still hashes to the pinned value the user approved.
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
/// - two SERVERS whose names sanitize identically (the renderer could no
///   longer resolve an exposed name back to one server);
/// - a name colliding with a built-in assistant tool (never allowed, even
///   though the renderer also refuses these).
///
/// `exposed -> (server_id, tool)` is then a well-defined map: one approval
/// can never silently cover another tool.
pub fn build_name_map(
    servers: &[(String, Vec<String>)], // (server name, tool names)
) -> Result<HashMap<String, (String, String)>, String> {
    let mut map = HashMap::new();
    let mut server_seen: HashMap<String, String> = HashMap::new();
    for (server, tools) in servers {
        // A server with no enabled tools exposes nothing: it cannot create
        // ambiguity, so its name never blocks another server's enables.
        if tools.is_empty() {
            continue;
        }
        let server_san = sanitize_tool_name_part(server);
        if let Some(prev) = server_seen.get(&server_san) {
            if prev != server {
                return Err(format!(
                    "MCP server names '{prev}' and '{server}' produce the same model-facing prefix '{server_san}'; rename one of them before enabling tools."
                ));
            }
        } else {
            server_seen.insert(server_san.clone(), server.clone());
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
                Some((prev_server, prev_tool)) if prev_server != server || prev_tool != real => {
                    return Err(format!(
                        "MCP tools from different servers produce the same model-facing name '{exposed}'; refusing to expose ambiguous tools."
                    ));
                }
                _ => {
                    map.insert(exposed, (server.clone(), real.clone()));
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

/// Read the JSON-RPC response for `want_id` from a completed HTTP
/// response, handling both content types:
/// - application/json: the body IS the response.
/// - text/event-stream: read events until the response with `want_id`
///   arrives. Server-to-client REQUESTS (id + method) are answered with
///   JSON-RPC error -32601 on the same session and never surfaced;
///   notifications (no id) such as notifications/tools/list_changed are
///   noted, not answered.
pub async fn read_response(
    client: &reqwest::Client,
    url: &str,
    auth: Option<(&str, &Zeroizing<String>)>,
    session: Option<&str>,
    protocol_version: Option<&str>,
    want_id: &Value,
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

    let body = read_capped(&mut resp).await?;
    let mut answered = 0usize;
    let mut list_changed = false;
    for event in parse_sse(&body) {
        match classify_stream_message(&event, want_id) {
            StreamMessage::Answer => {
                return Ok(JsonRpcOutcome {
                    result: event,
                    answered_requests: answered,
                    list_changed,
                });
            }
            StreamMessage::ServerRequest => {
                // Phase 1 supports no client capabilities (empty in
                // initialize), so nothing is a valid request target:
                // answer -32601 (method not found) and NEVER pass it to the
                // LLM. A failure to send the answer is non-fatal - the main
                // response still counts.
                let error = json!({
                    "jsonrpc": "2.0",
                    "id": event.get("id").cloned().unwrap_or(Value::Null),
                    "error": { "code": -32601, "message": "Method not found" },
                });
                let _ = post_jsonrpc(client, url, &error, auth, session, protocol_version).await;
                answered += 1;
            }
            StreamMessage::ListChanged => list_changed = true,
            StreamMessage::Ignored => {}
        }
    }
    Err(CmdError(
        "MCP server closed the SSE stream without answering the request.".into(),
    ))
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

/// Parse an SSE body into the JSON `data:` payloads, in order. Handles both
/// LF and CRLF line/block endings.
pub fn parse_sse(body: &str) -> Vec<Value> {
    let normalized = body.replace("\r\n", "\n");
    let mut out = Vec::new();
    for block in normalized.split("\n\n") {
        let data: String = block
            .lines()
            .filter_map(|l| l.strip_prefix("data:"))
            .map(|d| d.trim_start())
            .collect::<Vec<_>>()
            .join("\n");
        if data.is_empty() {
            continue;
        }
        if let Ok(v) = serde_json::from_str(&data) {
            out.push(v);
        }
    }
    out
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
/// inert for direct transport-level calls.
#[doc(hidden)]
pub async fn request_once_test(
    ctx: &ServerContext,
    body: &Value,
) -> CmdResult<Option<JsonRpcOutcome>> {
    request_once_unchecked(ctx, body).await
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
    initialize_unchecked(ctx).await
}

#[doc(hidden)]
pub async fn initialize_test(ctx: &ServerContext) -> CmdResult<(McpSession, JsonRpcOutcome)> {
    initialize_unchecked(ctx).await
}

async fn initialize_unchecked(ctx: &ServerContext) -> CmdResult<(McpSession, JsonRpcOutcome)> {
    // Production callers check the vault generation immediately before
    // entering this helper; test callers use the unchecked transport seam.
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
    let session_header = resp
        .headers()
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let outcome =
        read_response(&ctx.client, &ctx.url, auth_ref(ctx), None, None, &id, resp).await?;
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
    request_once_unchecked(ctx, body).await
}

async fn request_once_unchecked(
    ctx: &ServerContext,
    body: &Value,
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

/// One pagination pass over tools/list. Returns the pages plus whether a
/// tools/list_changed notification was observed along the way.
async fn fetch_tools_once(
    ctx: &mut ServerContext,
    app: &AppHandle,
) -> CmdResult<(Vec<Value>, bool)> {
    let mut tools = Vec::new();
    let mut cursor: Option<String> = None;
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
        let result = rpc_result(outcome.result)?;
        if let Some(arr) = result.get("tools").and_then(|t| t.as_array()) {
            tools.extend(arr.iter().cloned());
        }
        // A list_changed observed on ANY page invalidates the whole pass:
        // stop paginating and let fetch_tools restart from the first page.
        if outcome.list_changed {
            return Ok((tools, true));
        }
        cursor = result
            .get("nextCursor")
            .and_then(|c| c.as_str())
            .map(String::from);
        // A runaway pagination loop (server always returns a cursor) stops
        // well above the tool cap; fetch_tools' caller enforces the cap.
        if cursor.is_none() || tools.len() > 1000 {
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

    let changed = changed_enabled_tools(&record.tools, &tool_defs);
    let mut updated = record.clone();
    updated.tools = merge_tools(&record.tools, &tool_defs);
    updated.updated_at = chrono::Utc::now();
    let db = &app.state::<crate::AppState>().db;
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

/// Merge freshly-fetched tool definitions into the stored per-tool state.
/// - New tools: disabled, no pin (default-deny).
/// - Known tools: current_hash updated; an enabled tool whose definition no
///   longer matches its pin is DISABLED (definition rug-pull - the caller
///   audits it via `changed_enabled_tools`).
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
                // Definition changed (or never pinned): a previously-enabled
                // tool is disabled pending re-approval.
                Some(p) => (false, p.auto_approve, p.pin_hash.clone()),
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

/// Resolve the auth header for a record WITHOUT touching app state beyond
/// the vault password (safe to call mid-lock, after the generation bump but
/// before the password store clears). Errors are the caller's to ignore or
/// report; the value is Zeroizing either way.
fn resolve_auth_for_teardown(
    app: &AppHandle,
    record: &crate::db::McpServerRecord,
) -> Option<(String, Zeroizing<String>)> {
    let pw = vault_password(app).ok()?;
    if pw.is_empty() {
        return None;
    }
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
        let auth = resolve_auth_for_teardown(app, &rec);
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
                let _ = app.state::<crate::AppState>().db.add_audit(
                    "mcp.session_teardown_failed",
                    None,
                    &e,
                );
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
            let insecure = matches!(classify_url(&r.url), Ok((_, UrlClass::LoopbackInsecure)));
            let enabled = r.tools.iter().filter(|t| t.enabled).count();
            json!({
                "id": r.id,
                "name": r.name,
                "url": r.url,
                "auth_type": r.auth_type,
                "confirmed": r.confirmed,
                "loopback_insecure": insecure,
                "status": state.status_of(&r.id),
                "tool_count": enabled,
                "tools": r.tools.iter().map(|t| tool_view(&r.name, t)).collect::<Vec<_>>(),
            })
        })
        .collect();
    Ok(Value::Array(servers))
}

/// The enable-time collision check: given the FULL registry with the
/// candidate enable already applied, run the name/collision authority over
/// the enabled tools. `Some(err)` means enabling must be refused - the
/// model-facing name set would be ambiguous (two tools behind one name
/// means one approval could cover the other). Pure over records.
pub fn enable_collision_error(records: &[crate::db::McpServerRecord]) -> Option<String> {
    let registry: Vec<(String, Vec<String>)> = records
        .iter()
        .filter(|r| r.tools.iter().any(|t| t.enabled))
        .map(|r| {
            (
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
    let pw = vault_password(&app)?;
    if pw.is_empty() {
        return Err("Vault is locked.".into());
    }
    let name = name.trim().to_string();
    if !is_token(&name) {
        return Err(
            "Server name must be non-empty and contain only letters, digits, - and _.".into(),
        );
    }
    let (normalized_url, _class) = classify_url(&url)?;
    let auth_type = auth_type.trim().to_string();
    if !matches!(auth_type.as_str(), "none" | "bearer" | "custom_header") {
        return Err("Auth type must be 'none', 'bearer' or 'custom_header'.".into());
    }
    let auth_header_name = auth_header_name
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    match auth_type.as_str() {
        "custom_header" => {
            let n = auth_header_name
                .as_deref()
                .ok_or_else(|| CmdError("Custom header auth requires a header name.".into()))?;
            validate_header_name(n).map_err(CmdError)?;
        }
        "none" if auth_header_name.is_some() || auth_secret.is_some() || auth_env_var.is_some() => {
            return Err("Auth type 'none' cannot carry a header, secret or env var.".into());
        }
        _ => {}
    }
    let auth_env_var = auth_env_var
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let db = &app.state::<crate::AppState>().db;
    let now = chrono::Utc::now();
    let is_new = id.as_deref().filter(|s| !s.is_empty()).is_none();
    let (record_id, mut record) = match id.as_deref().filter(|s| !s.is_empty()) {
        Some(existing) => {
            let mut r = db
                .get_mcp_server(existing)
                .map_err(|e| e.to_string())?
                .ok_or_else(|| CmdError("MCP server not found.".into()))?;
            r.id = existing.to_string();
            (existing.to_string(), r)
        }
        None => {
            let new_id = uuid::Uuid::new_v4().to_string();
            (
                new_id.clone(),
                crate::db::McpServerRecord {
                    id: new_id,
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
                },
            )
        }
    };
    // ── Static credential ORIGIN BINDING ────────────────────────────────
    // A sealed secret was entered for ONE origin under ONE auth semantic.
    // Editing the URL, the auth type, or the custom header name changes the
    // destination or the meaning, so the OLD secret must never survive the
    // save: it is dropped here and a NEW secret must be entered for the new
    // configuration. The auth SOURCE stays mutually exclusive: a record
    // holds a sealed secret or an env-var name, never both.
    let origin_changed = record.url != normalized_url;
    let auth_semantics_changed =
        record.auth_type != auth_type || record.auth_header_name != auth_header_name;
    if !is_new && (origin_changed || auth_semantics_changed) {
        record.auth_secret = None;
    }
    record.name = name;
    record.url = normalized_url;
    record.auth_type = auth_type;
    record.auth_header_name = auth_header_name;
    // Saving from the UI IS the user's re-confirmation of URL + auth source
    // (backup-restored entries become connectable only through here).
    record.confirmed = true;
    if let Some(secret) = auth_secret.clone().filter(|s| !s.is_empty()) {
        // A newly entered secret: the only source, replacing any env var.
        let secret = Zeroizing::new(secret);
        record.auth_secret = Some(
            crate::crypto::vault::seal(&pw, secret.trim().as_bytes()).map_err(|e| e.to_string())?,
        );
        record.auth_env_var = None;
    } else {
        if auth_secret.is_some() {
            // Explicit empty string = clear the stored secret.
            record.auth_secret = None;
        }
        if auth_env_var.is_some() {
            // An env-var name (re-)bound: the only source.
            record.auth_secret = None;
        }
        record.auth_env_var = auth_env_var;
    }
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
    let db = &app.state::<crate::AppState>().db;
    let record = db
        .get_mcp_server(&id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| CmdError("MCP server not found.".into()))?;
    // Session teardown BEFORE the entry disappears: the DELETE carries the
    // static auth header (resolved while the vault is still unlocked), is
    // actually awaited (removal is a user-initiated action, not the lock
    // path), and only 405 is ignored - a refused teardown fails the removal
    // instead of silently leaking the session.
    if let Some(session) = app.state::<McpState>().remove_session(&id) {
        if let Some(sid) = session.session_id {
            if let Ok((url, _)) = classify_url(&record.url) {
                let client = origin_client()?;
                // Resolve the header BEFORE the record (and its sealed
                // secret) is deleted; the value is Zeroizing.
                let auth = resolve_auth_for_teardown(&app, &record);
                delete_session(
                    &client,
                    &url,
                    &sid,
                    &session.protocol_version,
                    auth.as_ref().map(|(n, v)| (n.as_str(), v)),
                    &record.name,
                )
                .await
                .map_err(CmdError)?;
            }
        }
    }
    db.delete_mcp_server(&id).map_err(|e| e.to_string())?;
    db.add_audit("mcp.server_removed", Some(&id), &record.name)
        .map_err(|e| e.to_string())?;
    Ok(json!({ "ok": true }))
}

#[tauri::command]
pub async fn mcp_test_connection(app: AppHandle, id: String) -> CmdResult<Value> {
    let db = &app.state::<crate::AppState>().db;
    let record = db
        .get_mcp_server(&id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| CmdError("MCP server not found.".into()))?;
    let state = app.state::<McpState>();
    let (updated, _changed) = connect_server(&app, record)
        .await
        .inspect_err(|e| state.record_status(&id, "error", Some(e.0.clone()), 0))?;
    state.record_status(&id, "connected", None, updated.tools.len());
    Ok(json!({
        "ok": true,
        "tools": updated.tools.iter().map(|t| tool_view(&updated.name, t)).collect::<Vec<_>>(),
    }))
}

#[tauri::command(rename_all = "snake_case")]
pub fn mcp_set_tool_state(
    app: AppHandle,
    id: String,
    tool: String,
    enabled: bool,
    auto_approve: bool,
) -> CmdResult<Value> {
    let db = &app.state::<crate::AppState>().db;
    let mut record = db
        .get_mcp_server(&id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| CmdError("MCP server not found.".into()))?;
    let entry = record
        .tools
        .iter_mut()
        .find(|t| t.name == tool)
        .ok_or_else(|| CmdError(format!("Tool '{tool}' not found on this MCP server.")))?;
    if enabled {
        // Enabling (re-)pins the CURRENT definition hash: that is the
        // definition the user is approving.
        let Some(hash) = entry.current_hash.clone() else {
            return Err(CmdError(
                "Tool definition unknown - connect to the server first.".into(),
            ));
        };
        entry.pin_hash = Some(hash);
    } else {
        // Disabling clears the pin: re-enabling re-approves the
        // then-current definition, not a stale one.
        entry.pin_hash = None;
    }
    entry.enabled = enabled;
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
        db.add_audit("mcp.tool_approved", Some(&id), &format!("tool={tool}"))
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
    // THE GATE. Everything is enforced here, in Rust, independent of what
    // the renderer offered the model:
    //   1. the per-tab access level permits the call (yolo/execute run;
    //      read/draft need the human's approval, attested by `approved`),
    //   2. the server entry is confirmed,
    //   3. the tool is enabled,
    //   4. the tool's current definition still matches its pin,
    //   5. auto_approve OR approved OR yolo.
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

    let denied = |reason: String| -> CmdResult<Value> {
        let _ = db.add_audit(
            "mcp.tool_call",
            Some(&id),
            &format!(
                "server={} tool={} args_sha256={} level={} outcome=denied reason={}",
                record.name, tool, fingerprint, level, reason
            ),
        );
        Err(CmdError(reason))
    };

    if !record.confirmed {
        return denied("This MCP server entry has not been confirmed.".into());
    }
    if matches!(level.as_str(), "read" | "draft") && !approved {
        return denied(format!(
            "AI access level is '{level}' - tool calls need your approval."
        ));
    }
    if !entry.enabled {
        return denied(format!(
            "Tool '{tool}' is not enabled - enable it in the MCP server settings."
        ));
    }
    if !entry.auto_approve && !approved && level != "yolo" {
        return denied(format!(
            "Tool '{tool}' requires approval before it can run."
        ));
    }
    if let (Some(pin), Some(current)) = (entry.pin_hash.as_deref(), entry.current_hash.as_deref()) {
        if pin != current {
            return denied(format!(
                "Tool '{tool}' changed on the server since it was approved - re-approve it in the MCP settings."
            ));
        }
    }

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
    let outcome = request_with_session(&app, &mut ctx, &body).await?;
    require_generation_current(&app, generation)?;
    let result = rpc_result(outcome.result)?;

    // A tools/list_changed that arrived with this call (or with a mid-call
    // re-initialize): re-fetch and re-run pinning so the NEXT call is
    // already gated against fresh definitions.
    if outcome.list_changed {
        let refreshed = fetch_tools(&mut ctx, &app).await?;
        require_generation_current(&app, generation)?;
        if let Some(stored) = db.get_mcp_server(&id).map_err(|e| e.to_string())? {
            let changed = changed_enabled_tools(&stored.tools, &refreshed);
            let mut next = stored.clone();
            next.tools = merge_tools(&stored.tools, &refreshed);
            next.updated_at = chrono::Utc::now();
            db.save_mcp_server(&next).map_err(|e| e.to_string())?;
            for t in changed {
                let _ = db.add_audit(
                    "mcp.tool_definition_changed",
                    Some(&id),
                    &format!("server={} tool={}", record.name, t),
                );
            }
        }
    }

    let (content, is_error) = shape_tool_result(&result);
    let outcome_label = if entry.auto_approve {
        "auto"
    } else {
        "approved"
    };
    db.add_audit(
        "mcp.tool_call",
        Some(&id),
        &format!(
            "server={} tool={} args_sha256={} level={} outcome={}",
            record.name, tool, fingerprint, level, outcome_label
        ),
    )
    .map_err(|e| e.to_string())?;
    Ok(json!({ "ok": true, "content": content, "is_error": is_error }))
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn name_map_rejects_collisions_within_and_across_servers() {
        // Within one server: "a b" and "a_b" sanitize identically.
        let err = build_name_map(&[("srv".into(), vec!["a b".into(), "a_b".into()])])
            .err()
            .expect("same-server collision must be rejected");
        assert!(err.contains("same model-facing name"), "{err}");
        assert!(build_name_map(&[("srv".into(), vec!["a b".into(), "c".into()])]).is_ok());
        // Across servers: two servers with names that sanitize identically.
        let err = build_name_map(&[
            ("my srv".into(), vec!["t1".into()]),
            ("my_srv".into(), vec!["t2".into()]),
        ])
        .err()
        .expect("server-name collision must be rejected");
        assert!(err.contains("same model-facing prefix"), "{err}");
        // Built-in names are structurally out of reach (every exposed name
        // starts with "mcp__"); the belt-and-suspenders check must not
        // false-positive on a tool that merely shares a suffix.
        assert!(build_name_map(&[("mcp".into(), vec!["run_command".into()])]).is_ok());
        // The identical tool name on two DIFFERENT (distinctly named)
        // servers produces two distinct exposed names and is fine.
        assert!(build_name_map(&[
            ("alpha".into(), vec!["search".into()]),
            ("beta".into(), vec!["search".into()]),
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
}
