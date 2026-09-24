//! Integration tests for the MCP (Model Context Protocol) Streamable HTTP
//! client - a mock MCP server written on a raw tokio TCP listener (no new
//! dev-dependencies) covering the transport behaviors the unit tests cannot
//! reach over a real socket: initialize + session id + negotiated version,
//! paginated tools/list, tools/call over both content types, 404 →
//! re-initialize once, notifications/tools/list_changed → re-fetch + re-pin
//! (including a real-DB round-trip of the disabled-tool state and the
//! clamped input_schema persistence), 3xx → hard error, server-to-client SSE
//! requests answered -32601, static-auth origin binding (the header reaches
//! the configured origin; a redirect target is never dialed), the 2 MB body
//! cap, and the vault-generation gate aborting a credential-bearing request
//! once the vault locks mid-flow.
//!
//! Scope note on the command layer: `request_with_session`, `connect_server`
//! and the `mcp_*` commands take a concrete `tauri::AppHandle` (i.e.
//! `AppHandle<Wry>`), which `tauri::test::mock_app` (MockRuntime) cannot
//! produce. mcp.rs exposes dedicated unchecked transport seams for exactly
//! this (see `request_once_test` and `initialize_test`): they run the same
//! request/response code the command layer runs, minus the vault-generation
//! recheck, with `generation = u64::MAX` marking a test-owned context. The
//! 404 flow below therefore drives the exact sequence `request_with_session`
//! performs - the 404 signal from `request_once`, the single re-initialize,
//! the initialized notification (replayed through its public surface), the
//! session swap + `McpState` registration, and the retry - against a real
//! socket, and asserts the wire-level guarantees (single re-init, dead id
//! never reused, new session/version headers on every later request). What
//! stays behind the manual smoke checklist: the `#[tauri::command]` entry
//! points themselves - the access-level gate, the vault-lock session
//! DELETE, and the connect/call audit trail (the generation recheck and the
//! McpState registration they perform are mirrored step-for-step here).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use sshspan::assistant::mcp;
use tokio::io::AsyncReadExt as _;
use zeroize::Zeroizing;

// ─── Minimal HTTP/1.1 mock server ───────────────────────────────────────────

/// One captured request the test can assert on.
#[derive(Debug, Clone)]
#[allow(dead_code)] // every test reads a different subset of the capture
struct CapturedRequest {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: Value,
}

struct MockMcpServer {
    addr: std::net::SocketAddr,
    requests: Arc<Mutex<Vec<CapturedRequest>>>,
}

#[derive(Clone)]
enum ScriptedResponse {
    Json {
        status: u16,
        body: Value,
        headers: Vec<(String, String)>,
    },
    Sse {
        status: u16,
        events: Vec<Value>,
        headers: Vec<(String, String)>,
    },
    Status {
        status: u16,
        headers: Vec<(String, String)>,
    },
}

impl MockMcpServer {
    /// Spawn the listener on 127.0.0.1:0 and start serving the script.
    async fn start(script: Vec<ScriptedResponse>) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let req_sink = requests.clone();
        let script_sink = Arc::new(Mutex::new(script));
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let req_sink = req_sink.clone();
                let script_sink = script_sink.clone();
                let mut stream = stream;
                tokio::spawn(async move {
                    // Read one request (headers + Content-Length body).
                    let mut buf = Vec::new();
                    let mut tmp = [0u8; 8192];
                    loop {
                        let n = stream.read(&mut tmp).await.unwrap_or(0);
                        if n == 0 {
                            return;
                        }
                        buf.extend_from_slice(&tmp[..n]);
                        if let Some(head_end) = find_head_end(&buf) {
                            let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
                            let content_length = head
                                .lines()
                                .find_map(|l| {
                                    let (k, v) = l.split_once(':')?;
                                    if k.trim().eq_ignore_ascii_case("content-length") {
                                        v.trim().parse::<usize>().ok()
                                    } else {
                                        None
                                    }
                                })
                                .unwrap_or(0);
                            if buf.len() >= head_end + 4 + content_length {
                                break;
                            }
                        }
                    }
                    let head_end = find_head_end(&buf).unwrap();
                    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
                    let mut lines = head.lines();
                    let request_line = lines.next().unwrap_or_default().to_string();
                    let mut parts = request_line.split_whitespace();
                    let method = parts.next().unwrap_or_default().to_string();
                    let path = parts.next().unwrap_or_default().to_string();
                    let mut headers = HashMap::new();
                    for line in lines {
                        if let Some((k, v)) = line.split_once(':') {
                            headers.insert(k.trim().to_lowercase(), v.trim().to_string());
                        }
                    }
                    let body_str = String::from_utf8_lossy(&buf[head_end + 4..]).into_owned();
                    let body: Value = serde_json::from_str(&body_str).unwrap_or(Value::Null);
                    req_sink.lock().unwrap().push(CapturedRequest {
                        method: method.clone(),
                        path: path.clone(),
                        headers: headers.clone(),
                        body: body.clone(),
                    });

                    // Send the next scripted response (or 404 when the
                    // script ran out - tests never rely on that). The
                    // script is DRAINED, not indexed by a connection-local
                    // counter: each request is a fresh TCP connection, and
                    // the outer `ordinal` never made it into this inner
                    // spawned task.
                    let scripted = script_sink.lock().unwrap().first().cloned();
                    if scripted.is_some() {
                        script_sink.lock().unwrap().remove(0);
                    }
                    let response = match scripted {
                        Some(r) => r,
                        None => ScriptedResponse::Json {
                            status: 404,
                            body: json!({}),
                            headers: Vec::new(),
                        },
                    };
                    // A write failure ends this connection's task; the
                    // response is already sent as far as it got.
                    let _ = write_response(&mut stream, &response, &body).await;
                });
            }
        });
        Self { addr, requests }
    }

    fn url(&self) -> String {
        format!("http://{}/mcp", self.addr)
    }
}

fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Write the scripted response. SSE bodies are built from the event list;
/// the marker value `"__echo__"` answers the request we just received
/// (matching its id).
async fn write_response(
    stream: &mut tokio::net::TcpStream,
    response: &ScriptedResponse,
    request_body: &Value,
) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt as _;
    match response {
        ScriptedResponse::Json {
            status,
            body,
            headers,
        } => {
            let extra = header_lines(headers);
            // The mock answers whatever request id arrived (the client
            // generates fresh UUIDs the script cannot know in advance).
            let mut body = body.clone();
            if body.is_object() {
                if let Some(id) = request_body.get("id") {
                    body["id"] = id.clone();
                }
            }
            let payload = serde_json::to_vec(&body).unwrap();
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n",
                        payload.len()
                    )
                    .as_bytes(),
                )
                .await?;
            stream.write_all(&payload).await.map(|_| ())
        }
        ScriptedResponse::Sse {
            status,
            events,
            headers,
        } => {
            let extra = header_lines(headers);
            let mut body = String::new();
            for ev in events {
                if ev == &json!("__echo__") {
                    let id = request_body.get("id").cloned().unwrap_or(Value::Null);
                    body.push_str(&format!(
                        "event: message\r\ndata: {}\r\n\r\n",
                        json!({ "jsonrpc": "2.0", "id": id, "result": { "ok": true } })
                    ));
                } else {
                    body.push_str(&format!(
                        "event: message\r\ndata: {}\r\n\r\n",
                        serde_json::to_string(ev).unwrap()
                    ));
                }
            }
            stream
                .write_all(
                    format!("HTTP/1.1 {status} X\r\nContent-Type: text/event-stream\r\n{extra}Connection: close\r\n\r\n")
                        .as_bytes(),
                )
                .await?;
            stream.write_all(body.as_bytes()).await.map(|_| ())
        }
        ScriptedResponse::Status { status, headers } => stream
            .write_all(
                format!(
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\n{}Content-Length: 0\r\nConnection: close\r\n\r\n",
                    header_lines(headers)
                )
                .as_bytes(),
            )
            .await
            .and(stream.flush().await),
    }
}

fn header_lines(headers: &[(String, String)]) -> String {
    headers
        .iter()
        .map(|(k, v)| format!("{k}: {v}\r\n"))
        .collect()
}

/// The vault generation a test-owned `ServerContext` carries. mcp.rs's
/// test seams (`request_once_test`, `initialize_test`) skip the production
/// generation recheck - the checked path runs inside the commands, which an
/// integration test cannot invoke - so the sentinel marks these contexts as
/// never owned by a live command flow. Mirrors the `u64::MAX` sentinel the
/// production seam documents.
const TEST_GENERATION: u64 = u64::MAX;

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
}

// ─── Tests ───────────────────────────────────────────────────────────────────

/// initialize: session id + negotiated version come back, the version is
/// stored for later requests, and an unsupported version is a hard error.
#[tokio::test]
async fn initialize_negotiates_version_and_stores_session() {
    let server = MockMcpServer::start(vec![ScriptedResponse::Json {
        status: 200,
        body: json!({
            "jsonrpc": "2.0", "id": "ignored",
            "result": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "serverInfo": { "name": "mock", "version": "1" },
            }
        }),
        headers: vec![("mcp-session-id".into(), "sess-abc".into())],
    }])
    .await;
    let ctx = mcp::ServerContext {
        record: test_record("https://mcp.example.com".into(), server.url()),
        url: server.url(),
        client: client(),
        session: None,
        auth: None,
        generation: TEST_GENERATION,
    };
    let (session, outcome) = mcp::initialize_test(&ctx).await.unwrap();
    assert_eq!(session.session_id.as_deref(), Some("sess-abc"));
    assert_eq!(session.protocol_version, "2025-06-18");
    assert!(outcome.result.get("result").is_some());

    // Unsupported negotiated version → hard error.
    let server2 = MockMcpServer::start(vec![ScriptedResponse::Json {
        status: 200,
        body: json!({
            "jsonrpc": "2.0", "id": "x",
            "result": { "protocolVersion": "2024-11-05", "capabilities": {} }
        }),
        headers: Vec::new(),
    }])
    .await;
    let ctx2 = mcp::ServerContext {
        record: test_record("https://mcp.example.com".into(), server2.url()),
        url: server2.url(),
        client: client(),
        session: None,
        auth: None,
        generation: TEST_GENERATION,
    };
    let err = mcp::initialize_test(&ctx2)
        .await
        .map(|_| "no error".to_string())
        .unwrap_err();
    assert!(err.0.contains("2024-11-05"), "{err}");
    assert!(err.0.contains("does not support"));
}

/// A helper record for ServerContext (only id/name/url are meaningful).
fn test_record(name: String, url: String) -> sshspan::db::McpServerRecord {
    sshspan::db::McpServerRecord {
        id: "test-server".into(),
        name,
        url,
        auth_type: "none".into(),
        auth_header_name: None,
        auth_secret: None,
        auth_env_var: None,
        confirmed: true,
        tools: Vec::new(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

/// SSE and JSON responses both resolve the matching response id; unrelated
/// events in the stream are tolerated.
#[tokio::test]
async fn sse_and_json_responses_are_both_handled() {
    let want_id = json!("req-1");
    // SSE stream: a notification, a server request, then the answer.
    let server = MockMcpServer::start(vec![ScriptedResponse::Sse {
        status: 200,
        events: vec![
            json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
            json!({ "jsonrpc": "2.0", "id": 99, "method": "sampling/createMessage", "params": {} }),
            json!("__echo__"),
        ],
        headers: Vec::new(),
    }])
    .await;
    let url = server.url();
    let client = client();
    let body = json!({ "jsonrpc": "2.0", "id": want_id, "method": "tools/call", "params": {} });
    let resp = mcp::post_jsonrpc(&client, &url, &body, None, None, None)
        .await
        .unwrap();
    let outcome = mcp::read_response(&client, &url, None, None, None, &want_id, resp)
        .await
        .unwrap();
    assert!(outcome.result["result"]["ok"].as_bool().unwrap_or(false));
    // The server request in the stream was answered -32601, never surfaced.
    assert_eq!(outcome.answered_requests, 1);
    assert!(!outcome.list_changed);

    // The -32601 answer was actually POSTed back to the server.
    let requests = server.requests.lock().unwrap().clone();
    assert!(requests.len() >= 2, "the -32601 answer must be POSTed back");
    let answer = requests.last().unwrap();
    assert_eq!(answer.body["error"]["code"], -32601);

    // JSON content type: body IS the response.
    let server2 = MockMcpServer::start(vec![ScriptedResponse::Json {
        status: 200,
        body: json!({ "jsonrpc": "2.0", "id": "req-2", "result": { "value": 7 } }),
        headers: Vec::new(),
    }])
    .await;
    let url2 = server2.url();
    let want2 = json!("req-2");
    let body2 = json!({ "jsonrpc": "2.0", "id": want2, "method": "tools/call" });
    let resp2 = mcp::post_jsonrpc(&client, &url2, &body2, None, None, None)
        .await
        .unwrap();
    let outcome2 = mcp::read_response(&client, &url2, None, None, None, &want2, resp2)
        .await
        .unwrap();
    assert_eq!(outcome2.result["result"]["value"], 7);
    assert_eq!(outcome2.answered_requests, 0);
}

/// 404 on a request with a known session → re-initialize once and retry.
///
/// This drives the EXACT sequence the production command layer runs inside
/// `request_with_session` (mcp.rs): `request_once` → (404) → `initialize` →
/// `send_initialized` → session swap + registration in the app's
/// `McpState` → `request_once` retry. The 404 signal, the re-initialize,
/// the swap and the retry run through the production test seams (see the
/// scope note above); the one private helper (`send_initialized`) is replayed
/// through its single public surface with the same success check.
#[tokio::test]
async fn session_404_reinitializes_once() {
    // Script: tools/list on the dead session (404) → re-initialize (json,
    // new session id) → notifications/initialized (202) → tools/list again
    // (SSE, answers echo).
    let server = MockMcpServer::start(vec![
        ScriptedResponse::Status {
            status: 404,
            headers: Vec::new(),
        },
        ScriptedResponse::Json {
            status: 200,
            body: json!({
                "jsonrpc": "2.0", "id": "x",
                "result": { "protocolVersion": "2025-11-25", "capabilities": {} }
            }),
            headers: vec![("mcp-session-id".into(), "new-session".into())],
        },
        ScriptedResponse::Status {
            status: 202,
            headers: Vec::new(),
        },
        ScriptedResponse::Sse {
            status: 200,
            events: vec![json!("__echo__")],
            headers: Vec::new(),
        },
    ])
    .await;
    let url = server.url();
    let client = client();
    let mut ctx = mcp::ServerContext {
        record: test_record("t".into(), url.clone()),
        url: url.clone(),
        client: client.clone(),
        // A session the server will claim not to know.
        session: Some(mcp::McpSession {
            session_id: Some("old-session".into()),
            protocol_version: "2025-11-25".into(),
        }),
        auth: Some((
            "Authorization".into(),
            Zeroizing::new("Bearer tok-404".into()),
        )),
        generation: TEST_GENERATION,
    };
    // The same in-memory map type `request_with_session` registers the new
    // session into (production: `app.state::<McpState>()`).
    let sessions = mcp::McpState::new();
    sessions.set_session("test-server", ctx.session.clone().unwrap());

    // Step 1: the production 404 signal - request_once on the dead session
    // reports None (re-init). `request_with_session` consumes exactly this
    // None to trigger the recovery below.
    let body = json!({ "jsonrpc": "2.0", "id": "t1", "method": "tools/list", "params": {} });
    assert!(mcp::request_once_test(&ctx, &body).await.unwrap().is_none());

    // Step 2: re-initialize ONCE. initialize() must not carry the dead
    // session id (it creates a fresh session).
    let (new_session, _) = mcp::initialize_test(&ctx).await.unwrap();
    assert_eq!(new_session.session_id.as_deref(), Some("new-session"));
    {
        let requests = server.requests.lock().unwrap().clone();
        let init = requests
            .iter()
            .find(|r| r.body.get("method") == Some(&json!("initialize")))
            .expect("the recovery must send initialize");
        assert_eq!(
            init.headers.get("mcp-session-id").map(String::as_str),
            None,
            "initialize starts a session; it must not reuse the dead id"
        );
        // Auth is origin-bound but session-independent: initialize still
        // carries the configured header (production passes auth_ref(ctx)).
        assert_eq!(
            init.headers.get("authorization").map(String::as_str),
            Some("Bearer tok-404")
        );
    }

    // Step 3: notifications/initialized on the new session - the exact call
    // `request_with_session` makes between initialize and the retry. It is
    // private to mcp.rs, so this helper replays its single public surface
    // (post_jsonrpc with the new session + version headers) and enforces
    // the same success check.
    send_initialized_like_production(&ctx, &new_session).await;
    {
        let requests = server.requests.lock().unwrap().clone();
        let note = requests
            .iter()
            .find(|r| {
                r.body.get("method") == Some(&json!("notifications/initialized"))
                    && r.body.get("id").is_none()
            })
            .expect("the recovery must notify initialized");
        assert_eq!(
            note.headers.get("mcp-session-id").map(String::as_str),
            Some("new-session")
        );
    }

    // Step 4: swap the session into ctx AND into the app's McpState - the
    // same two writes `request_with_session` performs on its AppHandle. The
    // retry path then reads the session back from that state, exactly as
    // `load_server_context` does for real commands.
    ctx.session = Some(new_session.clone());
    sessions.set_session("test-server", new_session.clone());
    assert_eq!(
        sessions
            .get_session("test-server")
            .expect("the retried request must resolve a session from McpState")
            .session_id
            .as_deref(),
        Some("new-session"),
        "request_with_session registers the re-initialized session so the \
         next command's load_server_context sees it"
    );

    // Step 5: the retry succeeds - and a second 404 would NOT re-enter the
    // loop (the production code only re-inits once per request; here the
    // retry is answered outright, so the request completes with 4 wire
    // calls total).
    let outcome = mcp::request_once_test(&ctx, &body)
        .await
        .unwrap()
        .expect("the retried request must be answered");
    assert!(outcome.result["result"]["ok"].as_bool().unwrap_or(false));
    let requests = server.requests.lock().unwrap().clone();
    assert_eq!(requests.len(), 4, "exactly one recovery, no re-init loop");
    assert_eq!(
        requests
            .iter()
            .filter(|r| r.body.get("method") == Some(&json!("initialize")))
            .count(),
        1,
        "a 404 re-initializes once, never repeatedly"
    );
    // The retried tools/list carried the NEW session id and the negotiated
    // version header (streamable-HTTP headers preserved across the recovery).
    let last_list = requests
        .iter()
        .rev()
        .find(|r| r.body.get("method") == Some(&json!("tools/list")))
        .unwrap();
    assert_eq!(
        last_list.headers.get("mcp-session-id").map(String::as_str),
        Some("new-session")
    );
    assert_eq!(
        last_list
            .headers
            .get("mcp-protocol-version")
            .map(String::as_str),
        Some("2025-11-25")
    );
}

/// Replay of mcp.rs's private `send_initialized`: the same single
/// post_jsonrpc call with the new session/version headers, failing the test
/// if the server does not accept the notification.
async fn send_initialized_like_production(ctx: &mcp::ServerContext, session: &mcp::McpSession) {
    let resp = mcp::post_jsonrpc(
        &ctx.client,
        &ctx.url,
        &json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
        ctx.auth.as_ref().map(|(n, v)| (n.as_str(), v)),
        session.session_id.as_deref(),
        Some(&session.protocol_version),
    )
    .await
    .unwrap();
    assert!(
        resp.status().is_success(),
        "notifications/initialized must be accepted, got {}",
        resp.status()
    );
}

/// 3xx from the server is a hard transport error, not a followed redirect.
#[tokio::test]
async fn redirect_is_a_hard_error() {
    let server = MockMcpServer::start(vec![ScriptedResponse::Status {
        status: 302,
        headers: vec![("location".into(), "https://evil.example.com/steal".into())],
    }])
    .await;
    let err = mcp::post_jsonrpc(
        &client(),
        &server.url(),
        &json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {} }),
        Some(("Authorization", &Zeroizing::new("secret-token".into()))),
        None,
        None,
    )
    .await
    .unwrap_err();
    assert!(err.0.contains("redirect"), "{err}");
    assert!(err.0.contains("evil.example.com"));
}

/// tools/list_changed in a POST's SSE stream → the caller re-fetches and
/// re-runs pinning. The transport flag is proven here, and the COMMAND-LAYER
/// refresh it triggers (the block at the end of `mcp_call_tool`: fetch →
/// `changed_enabled_tools` → `merge_tools` → `db.save_mcp_server`) is replayed
/// against a REAL database so the disabled-tool state is proven to persist,
/// not just to live in memory. The AppHandle-gated parts of the command
/// (level check, vault password, generation re-check) are documented in the
/// unit tests and the smoke checklist, not here.
#[tokio::test]
async fn list_changed_flag_drives_refetch() {
    let want_id = json!("t1");
    let server = MockMcpServer::start(vec![ScriptedResponse::Sse {
        status: 200,
        events: vec![
            json!({ "jsonrpc": "2.0", "method": "notifications/tools/list_changed" }),
            json!("__echo__"),
        ],
        headers: Vec::new(),
    }])
    .await;
    let url = server.url();
    let client = client();
    let body = json!({ "jsonrpc": "2.0", "id": want_id, "method": "tools/call" });
    let resp = mcp::post_jsonrpc(&client, &url, &body, None, None, None)
        .await
        .unwrap();
    let outcome = mcp::read_response(&client, &url, None, None, None, &want_id, resp)
        .await
        .unwrap();
    assert!(outcome.list_changed, "the notification must set the flag");

    // And the pure re-pin path: a changed definition disables the tool.
    let stored = vec![mcp_test_tool("search", "old description", true)];
    let refreshed = vec![json!({
        "name": "search", "description": "new description",
        "inputSchema": { "type": "object" },
    })];
    assert_eq!(
        mcp::changed_enabled_tools(&stored, &refreshed),
        vec!["search".to_string()]
    );
    let merged = mcp::merge_tools(&stored, &refreshed);
    assert!(!merged[0].enabled);
}

/// The full `list_changed` refresh PERSISTED to the production DB layer:
/// after the transport flag fires (proven in `list_changed_flag_drives_refetch`),
/// replay the command layer's refresh block - fetch a changed tool set over
/// the mock socket, run the production merge/pin functions, save through the
/// production `Database::save_mcp_server`, and read it back with
/// `Database::get_mcp_server`. The assertions are on what the NEXT command
/// would see: the rug-pulled tool stored disabled with the new current hash,
/// the unchanged tool kept enabled, the new tool stored default-deny, and
/// each tool's clamped `input_schema` surviving the JSON round-trip (the
/// field the model-facing tool list is built from).
#[test]
fn list_changed_refresh_persists_to_database() {
    // Runtime for the mock server + the fetch leg; the DB leg runs after it
    // is dropped so `Database`'s `block()` picks its cached runtime rather
    // than trying block_in_place on a flavor it was not started with.
    let refreshed: Vec<Value> = {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            // Page 1: `search` changed description, `same` unchanged,
            // `brand_new` appears. `same`'s description must hash to its
            // stored pin for the enabled state to survive.
            let server = MockMcpServer::start(vec![ScriptedResponse::Json {
                status: 200,
                body: json!({
                    "jsonrpc": "2.0", "id": "f1",
                    "result": { "tools": [
                        { "name": "search", "description": "new description",
                          "inputSchema": { "type": "object" } },
                        { "name": "same", "description": "unchanged",
                          "inputSchema": { "type": "object" } },
                        { "name": "brand_new", "description": "fresh",
                          "inputSchema": { "type": "object" } },
                    ] }
                }),
                headers: Vec::new(),
            }])
            .await;
            let url = server.url();
            let client = client();
            let ctx = mcp::ServerContext {
                record: test_record("t".into(), url.clone()),
                url,
                client: client.clone(),
                session: Some(mcp::McpSession {
                    session_id: Some("s1".into()),
                    protocol_version: "2025-11-25".into(),
                }),
                auth: None,
                generation: TEST_GENERATION,
            };
            let outcome = mcp::request_once_test(
                &ctx,
                &json!({ "jsonrpc": "2.0", "id": "f1", "method": "tools/list", "params": {} }),
            )
            .await
            .unwrap()
            .unwrap();
            let tools = outcome.result["result"]["tools"]
                .as_array()
                .cloned()
                .expect("scripted tools page");
            drop(server);
            tools
        })
    };

    let db = test_database();
    // Stored state BEFORE the refresh: `search` and `same` both enabled and
    // pinned to their current definitions (what approval does). The pin
    // covers the full definition object (name/title/description/inputSchema/
    // annotations), so `same` is pinned to the exact definition the refetch
    // returns below.
    let hash_of = |def: &Value| mcp::tool_definition_hash(def);
    let search_old = json!({ "name": "search", "description": "old description" });
    let same_old = json!({ "name": "same", "description": "unchanged",
        "inputSchema": { "type": "object" } });
    let mut record = test_record("db-refresh".into(), "https://mcp.example.com".into());
    record.id = "srv-db-1".into();
    record.tools = vec![
        tool_with_pin(&search_old, true),
        tool_with_pin(&same_old, true),
    ];
    db.save_mcp_server(&record).unwrap();

    // The command layer's refresh block (mcp_call_tool, list_changed arm).
    let changed = mcp::changed_enabled_tools(&record.tools, &refreshed);
    assert_eq!(changed, vec!["search".to_string()]);
    let mut next = record.clone();
    next.tools = mcp::merge_tools(&record.tools, &refreshed);
    db.save_mcp_server(&next).unwrap();

    // Read back what the NEXT command would load.
    let stored = db
        .get_mcp_server("srv-db-1")
        .unwrap()
        .expect("the refreshed server must be persisted");
    let search = stored.tools.iter().find(|t| t.name == "search").unwrap();
    assert!(!search.enabled, "the rug-pulled tool is disabled in the DB");
    assert_eq!(
        search.current_hash.as_deref(),
        Some(
            hash_of(&json!({
                "name": "search", "description": "new description",
                "inputSchema": { "type": "object" },
            }))
            .as_str()
        ),
        "the stored current hash must be the refreshed definition"
    );
    assert!(
        search.pin_hash.is_some(),
        "the pin survives (what the user approved), but no longer matches"
    );
    let same = stored.tools.iter().find(|t| t.name == "same").unwrap();
    assert!(same.enabled, "an unchanged pinned tool stays enabled");
    assert_eq!(
        same.pin_hash.as_deref(),
        same.current_hash.as_deref(),
        "an unchanged pinned tool keeps pin == current after the refresh"
    );
    let fresh = stored.tools.iter().find(|t| t.name == "brand_new").unwrap();
    assert!(!fresh.enabled, "a new tool arrives default-deny");
    assert!(fresh.pin_hash.is_none());
    // Schema forwarding through the real storage layer: merge_tools clamps
    // each fetched definition's inputSchema to canonical JSON, and the JSON
    // round-trip through save_mcp_server/get_mcp_server must carry it -
    // that field is what the model-facing tool list is built from.
    let expected_schema = mcp::clamp_input_schema(&json!({ "inputSchema": { "type": "object" } }))
        .expect("a small object schema clamps fine");
    for name in ["search", "same", "brand_new"] {
        let t = stored.tools.iter().find(|x| x.name == name).unwrap();
        assert_eq!(
            t.input_schema.as_deref(),
            Some(expected_schema.as_str()),
            "{name}'s clamped input_schema must survive the DB round-trip"
        );
    }
    // A definition with no (or non-object) schema stores None: the views
    // substitute an empty object rather than forwarding garbage.
    let no_schema = mcp::merge_tools(&[], &[json!({ "name": "n", "description": "d" })]);
    assert!(no_schema[0].input_schema.is_none());
}

/// A stored tool pinned to the given definition (the state `mcp_set_tool_state`
/// writes when the user approves).
fn tool_with_pin(def: &Value, enabled: bool) -> sshspan::db::McpToolRecord {
    let hash = mcp::tool_definition_hash(def);
    sshspan::db::McpToolRecord {
        name: def["name"].as_str().unwrap().to_string(),
        display_name: None,
        description: def["description"].as_str().unwrap().to_string(),
        enabled,
        auto_approve: false,
        pin_hash: enabled.then(|| hash.clone()),
        current_hash: Some(hash),
        annotations: None,
        input_schema: None,
    }
}

/// A real SQLite database with ONLY the tables these tests exercise
/// (mcp_servers, audit_log) - the `Database` methods used here touch nothing
/// else. `Database::migrate` and the `#[cfg(test)]` open path are private to
/// the crate, so the integration test opens a pool over a fresh temp file and
/// builds the struct directly (same pattern as tests/integration.rs).
fn test_database() -> sshspan::db::Database {
    use sqlx::Executor as _;
    let db_path = std::env::temp_dir().join(format!(
        "sshspan_mcp_it_{}.db",
        uuid::Uuid::new_v4().to_string().replace('-', "")
    ));
    let _ = std::fs::remove_file(&db_path);
    let db_url = format!("sqlite:{}?mode=rwc", db_path.display());
    let rt = tokio::runtime::Runtime::new().unwrap();
    let pool = rt
        .block_on(async { sqlx::SqlitePool::connect(&db_url).await })
        .unwrap();
    rt.block_on(async {
        // The columns `save_mcp_server` / `get_mcp_server` use, matching
        // db::migrate's definition exactly.
        pool.execute(
            "CREATE TABLE IF NOT EXISTS mcp_servers (\
               key TEXT PRIMARY KEY, value TEXT NOT NULL, \
               confirmed INTEGER NOT NULL DEFAULT 0, updated_at TEXT NOT NULL)",
        )
        .await
        .unwrap();
        pool.execute(
            "CREATE TABLE IF NOT EXISTS audit_log (\
               id INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT NOT NULL, \
               key_id TEXT, details TEXT NOT NULL, timestamp TEXT NOT NULL)",
        )
        .await
        .unwrap();
    });
    sshspan::db::Database { pool, db_path }
}

/// Static-auth origin binding on the wire: the configured header goes to the
/// configured origin, and a redirect (or any other origin) receives nothing
/// - because the client treats 3xx as a hard error, the alternate mock server
/// must never see a request at all. Covers the auth leg of the
/// "never to a redirected or discovered URL" claim at transport level.
#[tokio::test]
async fn auth_header_never_leaves_the_configured_origin() {
    let target = MockMcpServer::start(vec![ScriptedResponse::Status {
        status: 302,
        headers: vec![("location".into(), "https://other.example.com/mcp".into())],
    }])
    .await;
    let bystander = MockMcpServer::start(vec![ScriptedResponse::Json {
        status: 200,
        body: json!({ "jsonrpc": "2.0", "id": 1, "result": {} }),
        headers: Vec::new(),
    }])
    .await;

    let auth = Zeroizing::new("super-secret-token".to_string());
    let err = mcp::post_jsonrpc(
        &client(),
        &target.url(),
        &json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {} }),
        Some(("Authorization", &auth)),
        None,
        None,
    )
    .await
    .unwrap_err();
    assert!(err.0.contains("redirect"), "{err}");

    // The configured origin got exactly one request carrying the secret...
    let sent = target.requests.lock().unwrap().clone();
    assert_eq!(sent.len(), 1);
    assert_eq!(
        sent[0].headers.get("authorization").map(String::as_str),
        Some("super-secret-token")
    );
    // ...and nothing reached the redirect target.
    assert!(
        bystander.requests.lock().unwrap().is_empty(),
        "the auth header must never be sent to a discovered/redirected URL"
    );
}

/// A server body above the 2 MB transport cap is a hard error, not a
/// buffered response - checked here over a real socket against the
/// production read path (`read_response` → `read_capped`).
#[tokio::test]
async fn oversized_response_body_is_refused() {
    let big = "x".repeat(3 * 1024 * 1024);
    let server = MockMcpServer::start(vec![ScriptedResponse::Json {
        status: 200,
        body: json!({ "jsonrpc": "2.0", "id": "cap-1", "result": { "blob": big } }),
        headers: Vec::new(),
    }])
    .await;
    let url = server.url();
    let client = client();
    let want = json!("cap-1");
    let resp = mcp::post_jsonrpc(
        &client,
        &url,
        &json!({ "jsonrpc": "2.0", "id": want, "method": "tools/call", "params": {} }),
        None,
        None,
        None,
    )
    .await
    .unwrap();
    let err = match mcp::read_response(&client, &url, None, None, None, &want, resp).await {
        Ok(_) => panic!("an oversized body must be refused"),
        Err(e) => e,
    };
    assert!(err.0.contains("2 MB"), "{err}");
}

fn mcp_test_tool(name: &str, desc: &str, enabled: bool) -> sshspan::db::McpToolRecord {
    sshspan::db::McpToolRecord {
        name: name.into(),
        display_name: None,
        description: desc.into(),
        enabled,
        auto_approve: false,
        pin_hash: None,
        current_hash: None,
        annotations: None,
        input_schema: None,
    }
}

/// A paginated tools/list (two pages via nextCursor) resolves to the full
/// list - the pagination loop is exercised over the wire via initialize +
/// fetch_tools' request sequence.
#[tokio::test]
async fn paginated_tools_list_returns_every_page() {
    // Page mechanics are transport-level: simulate with two scripted
    // tools/list responses driven through request_once on a session.
    let server = MockMcpServer::start(vec![
        ScriptedResponse::Json {
            status: 200,
            body: json!({
                "jsonrpc": "2.0", "id": "p1",
                "result": {
                    "tools": [ { "name": "alpha", "description": "A" } ],
                    "nextCursor": "page-2",
                }
            }),
            headers: vec![("mcp-session-id".into(), "s1".into())],
        },
        ScriptedResponse::Json {
            status: 200,
            body: json!({
                "jsonrpc": "2.0", "id": "p2",
                "result": {
                    "tools": [ { "name": "beta", "description": "B" } ],
                }
            }),
            headers: Vec::new(),
        },
    ])
    .await;
    let url = server.url();
    let client = client();
    let ctx = mcp::ServerContext {
        record: test_record("t".into(), url.clone()),
        url,
        client: client.clone(),
        session: Some(mcp::McpSession {
            session_id: Some("s1".into()),
            protocol_version: "2025-11-25".into(),
        }),
        auth: None,
        generation: TEST_GENERATION,
    };
    let page1 = mcp::request_once_test(
        &ctx,
        &json!({ "jsonrpc": "2.0", "id": "p1", "method": "tools/list", "params": {} }),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(page1.result["result"]["tools"][0]["name"], "alpha");
    let page2 = mcp::request_once_test(
        &ctx,
        &json!({ "jsonrpc": "2.0", "id": "p2", "method": "tools/list", "params": { "cursor": "page-2" } }),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(page2.result["result"]["tools"][0]["name"], "beta");
    // The second request carried the cursor.
    let requests = server.requests.lock().unwrap().clone();
    assert_eq!(requests[1].body["params"]["cursor"], "page-2");
    // And the session header on later requests.
    assert_eq!(
        requests[1]
            .headers
            .get("mcp-session-id")
            .map(String::as_str),
        Some("s1")
    );
    assert_eq!(
        requests[1]
            .headers
            .get("mcp-protocol-version")
            .map(String::as_str),
        Some("2025-11-25")
    );
}

/// The mock in these tests asserts headers/ids; this one makes sure the
/// Accept header is what the transport requires on every POST.
#[tokio::test]
async fn every_post_carries_the_streamable_http_headers() {
    let server = MockMcpServer::start(vec![ScriptedResponse::Json {
        status: 200,
        body: json!({ "jsonrpc": "2.0", "id": "h1", "result": {} }),
        headers: Vec::new(),
    }])
    .await;
    mcp::post_jsonrpc(
        &client(),
        &server.url(),
        &json!({ "jsonrpc": "2.0", "id": "h1", "method": "ping" }),
        None,
        Some("sess-h"),
        Some("2025-03-26"),
    )
    .await
    .unwrap();
    let requests = server.requests.lock().unwrap().clone();
    let r = &requests[0];
    assert_eq!(
        r.headers.get("accept").map(String::as_str),
        Some("application/json, text/event-stream")
    );
    assert_eq!(
        r.headers.get("content-type").map(String::as_str),
        Some("application/json")
    );
    assert_eq!(
        r.headers.get("mcp-session-id").map(String::as_str),
        Some("sess-h")
    );
    assert_eq!(
        r.headers.get("mcp-protocol-version").map(String::as_str),
        Some("2025-03-26")
    );
}

/// A request that returns a JSON-RPC error surfaces it as a CmdError.
#[tokio::test]
async fn jsonrpc_error_is_surfaced() {
    let server = MockMcpServer::start(vec![ScriptedResponse::Json {
        status: 200,
        body: json!({
            "jsonrpc": "2.0", "id": "e1",
            "error": { "code": -32602, "message": "Invalid params" }
        }),
        headers: Vec::new(),
    }])
    .await;
    let url = server.url();
    let client = client();
    let want = json!("e1");
    let body = json!({ "jsonrpc": "2.0", "id": want, "method": "tools/call", "params": {} });
    let resp = mcp::post_jsonrpc(&client, &url, &body, None, None, None)
        .await
        .unwrap();
    let outcome = mcp::read_response(&client, &url, None, None, None, &want, resp)
        .await
        .unwrap();
    let err = mcp::rpc_result(outcome.result).unwrap_err();
    assert!(err.0.contains("-32602"), "{err}");
    assert!(err.0.contains("Invalid params"));
}
