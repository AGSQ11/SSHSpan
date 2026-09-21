//! AI assistant: provider proxy, sealed API-key storage, and the per-tab
//! access-level gate for AI-initiated terminal execution.
//!
//! The agent/tool loop lives in the renderer (src/renderer/assistant.js) -
//! the conversation context it needs (terminal scrollback, server info) is
//! renderer-side, so the backend stays a non-streaming proxy plus policy gate:
//! it owns the sealed API key, all provider HTTPS traffic, the access level,
//! and the only path that lets an AI-issued command reach an SSH channel.
//!
//! Access levels: "read" (advise only), "draft" (may type into the prompt,
//! never submits), "execute" (runs commands, renderer confirms each), "yolo"
//! (runs without asking). The renderer exposes tools to the model according to
//! the level; `assistant_exec` re-checks the level here before writing to the
//! session, so a confused or prompt-injected model cannot escalate itself by
//! emitting tool calls the UI never offered.
//!
//! Known boundary: the renderer can still call `terminal_send` directly (user
//! typing needs it), so this gate constrains the AI's sanctioned path, not a
//! compromised webview - which is outside the threat model (release builds
//! ship without devtools).

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};
use zeroize::Zeroizing;

use crate::commands::{vault_password, CmdError};

type CmdResult<T> = Result<T, CmdError>;

const OPENAI_DEFAULT_BASE: &str = "https://api.openai.com/v1";
const ANTHROPIC_DEFAULT_BASE: &str = "https://api.anthropic.com";
const ANTHROPIC_VERSION: &str = "2023-06-01";

/// Provider calls get one budget end to end. Non-streaming responses from a
/// loaded local server (Ollama on CPU) can legitimately take a minute; two
/// minutes is long enough for that and short enough that a wedged connection
/// does not park a command slot forever.
const CHAT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);
const TEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

// ─── Access levels ──────────────────────────────────────────────────────────

/// Per-tab AI access levels, in memory only: they reset on app restart and
/// are cleared on vault lock (see commands::lock_vault_internal). Persisting
/// "yolo" across a restart would arm it without the user re-confirming.
pub struct AssistantLevels(std::sync::Mutex<HashMap<String, String>>);

impl AssistantLevels {
    pub fn new() -> Self {
        Self(std::sync::Mutex::new(HashMap::new()))
    }
    pub fn set(&self, tab_id: &str, level: &str) {
        self.0
            .lock()
            .unwrap()
            .insert(tab_id.to_string(), level.to_string());
    }
    pub fn get(&self, tab_id: &str) -> String {
        self.0
            .lock()
            .unwrap()
            .get(tab_id)
            .cloned()
            .unwrap_or_else(|| "read".to_string())
    }
    pub fn clear(&self) {
        self.0.lock().unwrap().clear();
    }
}

fn valid_level(level: &str) -> bool {
    matches!(level, "read" | "draft" | "execute" | "yolo")
}

/// The gate: may an AI-issued command be executed at this level? Pure so the
/// decision is unit-testable without AppState.
fn level_permits_exec(level: &str) -> bool {
    matches!(level, "execute" | "yolo")
}

// ─── Config commands ────────────────────────────────────────────────────────

#[tauri::command]
pub fn assistant_get_config(app: AppHandle) -> CmdResult<serde_json::Value> {
    let config = app
        .state::<crate::AppState>()
        .db
        .load_assistant_config()
        .map_err(|e| e.to_string())?;
    Ok(serde_json::json!({
        "provider": config.provider,
        "base_url": config.base_url,
        "model": config.model,
        // The sealed key never crosses the IPC boundary; the renderer only
        // needs to know whether one is stored.
        "has_api_key": config.api_key.is_some(),
    }))
}

#[tauri::command]
pub fn assistant_save_config(
    app: AppHandle,
    provider: String,
    base_url: Option<String>,
    model: String,
    api_key: Option<String>,
    // Explicit removal signal: null/empty api_key alone means "keep the
    // stored key" (so a save from a form that blanks the password field for
    // privacy does not silently destroy it), which otherwise made a stored
    // key impossible to remove.
    clear_api_key: Option<bool>,
) -> CmdResult<serde_json::Value> {
    let pw = vault_password(&app)?;
    if pw.is_empty() {
        return Err("Vault is locked.".into());
    }
    let provider = provider.trim().to_string();
    if provider != "openai" && provider != "anthropic" {
        return Err("Provider must be 'openai' or 'anthropic'.".into());
    }
    let model = model.trim().to_string();
    if model.is_empty() {
        return Err("Model is required.".into());
    }
    // Blank base URL = provider default; stored as None so a changed default
    // reaches existing configs. Deliberately no SSRF guard (unlike
    // Bitwarden): user-configured localhost/LAN inference servers (Ollama,
    // LM Studio) are a first-class use case for this feature.
    let base_url = base_url
        .map(|s| s.trim().trim_end_matches('/').to_string())
        .filter(|s| !s.is_empty());
    if let Some(u) = &base_url {
        if !u.starts_with("https://") && !u.starts_with("http://") {
            return Err("Base URL must start with https:// (or http:// for local servers).".into());
        }
    }

    let db = &app.state::<crate::AppState>().db;
    let mut config = db.load_assistant_config().map_err(|e| e.to_string())?;
    config.provider = Some(provider);
    config.base_url = base_url;
    config.model = Some(model);
    if let Some(key) = api_key.filter(|s| !s.trim().is_empty()) {
        // Wrap immediately: the plaintext key must be wiped from this frame
        // once sealed, not left as freed heap (secret-wiping hardening).
        let key = Zeroizing::new(key);
        config.api_key = Some(
            crate::crypto::vault::seal(&pw, key.trim().as_bytes()).map_err(|e| e.to_string())?,
        );
    } else if clear_api_key.unwrap_or(false) {
        // save_assistant_config's None => DELETE removes the sealed row.
        config.api_key = None;
    }
    db.save_assistant_config(&config)
        .map_err(|e| e.to_string())?;
    db.add_audit("assistant.config", None, "saved")
        .map_err(|e| e.to_string())?;
    Ok(serde_json::json!({ "ok": true }))
}

// ─── Provider plumbing ──────────────────────────────────────────────────────

struct ResolvedProvider {
    provider: String,
    base_url: String,
    model: String,
    api_key: Zeroizing<String>,
}

fn load_provider(app: &AppHandle) -> CmdResult<ResolvedProvider> {
    let pw = vault_password(app)?;
    if pw.is_empty() {
        return Err("Vault is locked.".into());
    }
    let config = app
        .state::<crate::AppState>()
        .db
        .load_assistant_config()
        .map_err(|e| e.to_string())?;
    let provider = config.provider.ok_or_else(|| {
        "AI assistant is not configured - open Settings > AI assistant.".to_string()
    })?;
    let sealed = config
        .api_key
        .ok_or_else(|| "No API key stored - save one in Settings > AI assistant.".to_string())?;
    let key_bytes = crate::crypto::vault::unseal(&pw, &sealed).map_err(|e| e.to_string())?;
    let api_key = Zeroizing::new(
        String::from_utf8(key_bytes)
            .map_err(|_| "Stored API key is not valid UTF-8.".to_string())?,
    );
    let base_url = config.base_url.unwrap_or_else(|| {
        if provider == "anthropic" {
            ANTHROPIC_DEFAULT_BASE.to_string()
        } else {
            OPENAI_DEFAULT_BASE.to_string()
        }
    });
    let model = config
        .model
        .ok_or_else(|| "No model configured.".to_string())?;
    Ok(ResolvedProvider {
        provider,
        base_url,
        model,
        api_key,
    })
}

fn http_client(timeout: std::time::Duration) -> CmdResult<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(timeout)
        .build()
        .map_err(|e| CmdError(e.to_string()))
}

/// Turn a provider error response into an actionable message. Reads the body
/// once; status classes the user can act on (auth, wrong URL, rate limit)
/// come first.
async fn provider_error(resp: reqwest::Response) -> CmdError {
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    let snippet: String = body.chars().take(300).collect();
    let msg = match status.as_u16() {
        401 | 403 => "API key rejected (check the key and provider).".to_string(),
        404 => "Provider returned 404 - check the base URL and model name.".to_string(),
        429 => format!("Rate limited by the provider (429). {snippet}"),
        s if s >= 500 => format!("Provider server error ({s}). {snippet}"),
        s => format!("Provider error ({s}). {snippet}"),
    };
    CmdError(msg)
}

// ─── Normalized wire contract (mirrors src/renderer/assistant.js) ──────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    id: String,
    name: String,
    arguments_json: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "role", rename_all = "lowercase")]
pub enum ChatMessage {
    System {
        content: String,
    },
    User {
        content: String,
    },
    Assistant {
        content: Option<String>,
        tool_calls: Option<Vec<ToolCall>>,
    },
    Tool {
        tool_call_id: String,
        name: String,
        content: String,
    },
}

#[derive(Debug, Clone, Deserialize)]
pub struct ToolSpec {
    name: String,
    description: String,
    /// JSON Schema for the tool's parameters, as a JSON string. A string (not
    /// a parsed value) keeps the renderer's schema verbatim - the renderer
    /// authors it and the provider validates it, the backend only forwards.
    parameters_json: String,
}

// ─── [OI]-compatible shaping ───────────────────────────────────────────────

fn openai_body(
    model: &str,
    messages: &[ChatMessage],
    tools: &[ToolSpec],
    max_tokens: u32,
) -> CmdResult<serde_json::Value> {
    let mut wire_msgs = Vec::with_capacity(messages.len());
    for m in messages {
        let v = match m {
            ChatMessage::System { content } => serde_json::json!({
                "role": "system", "content": content,
            }),
            ChatMessage::User { content } => serde_json::json!({
                "role": "user", "content": content,
            }),
            ChatMessage::Assistant {
                content,
                tool_calls,
            } => {
                let calls: Vec<serde_json::Value> = tool_calls
                    .clone()
                    .unwrap_or_default()
                    .iter()
                    .map(|c| {
                        serde_json::json!({
                            "id": c.id,
                            "type": "function",
                            "function": { "name": c.name, "arguments": c.arguments_json },
                        })
                    })
                    .collect();
                if calls.is_empty() {
                    serde_json::json!({ "role": "assistant", "content": content })
                } else {
                    // [OI] rejects an assistant message whose tool_calls are
                    // not followed by matching tool results; the renderer's
                    // loop guarantees the pairing.
                    serde_json::json!({
                        "role": "assistant", "content": content, "tool_calls": calls,
                    })
                }
            }
            ChatMessage::Tool {
                tool_call_id,
                content,
                ..
            } => serde_json::json!({
                "role": "tool", "tool_call_id": tool_call_id, "content": content,
            }),
        };
        wire_msgs.push(v);
    }

    let mut body = serde_json::json!({
        "model": model,
        "messages": wire_msgs,
        "max_tokens": max_tokens,
    });
    if !tools.is_empty() {
        let mut wire_tools = Vec::with_capacity(tools.len());
        for t in tools {
            let params: serde_json::Value =
                serde_json::from_str(&t.parameters_json).map_err(|e| {
                    CmdError(format!(
                        "tool '{}' has invalid parameters_json: {e}",
                        t.name
                    ))
                })?;
            wire_tools.push(serde_json::json!({
                "type": "function",
                "function": {
                    "name": t.name,
                    "description": t.description,
                    "parameters": params,
                },
            }));
        }
        body["tools"] = serde_json::Value::Array(wire_tools);
    }
    Ok(body)
}

fn parse_openai_response(body: &serde_json::Value) -> CmdResult<serde_json::Value> {
    let msg = body
        .get("choices")
        .and_then(|c| c.get(0))
        .and_then(|c| c.get("message"))
        .ok_or_else(|| CmdError("Provider returned no choices[0].message.".into()))?;
    let text = msg
        .get("content")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let mut calls = Vec::new();
    if let Some(arr) = msg.get("tool_calls").and_then(|t| t.as_array()) {
        for c in arr {
            let id = c.get("id").and_then(|v| v.as_str()).unwrap_or_default();
            let name = c
                .get("function")
                .and_then(|f| f.get("name"))
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            let args = c
                .get("function")
                .and_then(|f| f.get("arguments"))
                .and_then(|v| v.as_str())
                .unwrap_or("{}");
            if !name.is_empty() {
                calls.push(serde_json::json!({
                    "id": if id.is_empty() { uuid::Uuid::new_v4().to_string() } else { id.to_string() },
                    "name": name,
                    "arguments_json": args,
                }));
            }
        }
    }
    Ok(serde_json::json!({ "text": text, "tool_calls": calls }))
}

// ─── Anthropic shaping ──────────────────────────────────────────────────────

fn anthropic_body(
    model: &str,
    messages: &[ChatMessage],
    tools: &[ToolSpec],
    max_tokens: u32,
) -> CmdResult<serde_json::Value> {
    let mut system_parts: Vec<String> = Vec::new();
    let mut wire_msgs: Vec<serde_json::Value> = Vec::new();
    for m in messages {
        match m {
            // Anthropic takes system as a top-level field, not a message.
            ChatMessage::System { content } => system_parts.push(content.clone()),
            ChatMessage::User { content } => wire_msgs.push(serde_json::json!({
                "role": "user", "content": content,
            })),
            ChatMessage::Assistant {
                content,
                tool_calls,
            } => {
                let mut blocks: Vec<serde_json::Value> = Vec::new();
                if let Some(t) = content.as_ref().filter(|t| !t.is_empty()) {
                    blocks.push(serde_json::json!({ "type": "text", "text": t }));
                }
                for c in tool_calls.clone().unwrap_or_default() {
                    let input: serde_json::Value =
                        serde_json::from_str(&c.arguments_json).unwrap_or(serde_json::json!({}));
                    blocks.push(serde_json::json!({
                        "type": "tool_use", "id": c.id, "name": c.name, "input": input,
                    }));
                }
                wire_msgs.push(serde_json::json!({ "role": "assistant", "content": blocks }));
            }
            ChatMessage::Tool {
                tool_call_id,
                content,
                ..
            } => {
                // Anthropic carries tool results as tool_result blocks inside
                // a user turn. Consecutive tool results must share one user
                // message - the API rejects adjacent same-role messages - so
                // merge into the previous user message when it is one.
                let block = serde_json::json!({
                    "type": "tool_result", "tool_use_id": tool_call_id, "content": content,
                });
                let merged = match wire_msgs.last_mut() {
                    Some(serde_json::Value::Object(prev))
                        if prev.get("role").and_then(|r| r.as_str()) == Some("user")
                            && prev
                                .get("content")
                                .and_then(|c| c.as_array())
                                .map(|a| {
                                    a.iter().any(|b| {
                                        b.get("type").and_then(|t| t.as_str())
                                            == Some("tool_result")
                                    })
                                })
                                .unwrap_or(false) =>
                    {
                        prev.get_mut("content")
                            .and_then(|c| c.as_array_mut())
                            .map(|a| a.push(block.clone()));
                        true
                    }
                    _ => false,
                };
                if !merged {
                    wire_msgs.push(serde_json::json!({
                        "role": "user", "content": [block],
                    }));
                }
            }
        }
    }
    // Anthropic rejects an empty conversation; a tools-only history is not a
    // valid request either way, so fail loudly instead of sending garbage.
    if wire_msgs.is_empty() {
        return Err("Anthropic request needs at least one non-system message.".into());
    }

    let mut body = serde_json::json!({
        "model": model,
        "messages": wire_msgs,
        "max_tokens": max_tokens,
    });
    if !system_parts.is_empty() {
        body["system"] = serde_json::Value::String(system_parts.join("\n\n"));
    }
    if !tools.is_empty() {
        let mut wire_tools = Vec::with_capacity(tools.len());
        for t in tools {
            let schema: serde_json::Value =
                serde_json::from_str(&t.parameters_json).map_err(|e| {
                    CmdError(format!(
                        "tool '{}' has invalid parameters_json: {e}",
                        t.name
                    ))
                })?;
            wire_tools.push(serde_json::json!({
                "name": t.name,
                "description": t.description,
                "input_schema": schema,
            }));
        }
        body["tools"] = serde_json::Value::Array(wire_tools);
    }
    Ok(body)
}

fn parse_anthropic_response(body: &serde_json::Value) -> CmdResult<serde_json::Value> {
    let content = body
        .get("content")
        .and_then(|c| c.as_array())
        .ok_or_else(|| CmdError("Anthropic response has no content blocks.".into()))?;
    let mut texts: Vec<String> = Vec::new();
    let mut calls = Vec::new();
    for b in content {
        match b.get("type").and_then(|t| t.as_str()) {
            Some("text") => {
                if let Some(t) = b.get("text").and_then(|v| v.as_str()) {
                    texts.push(t.to_string());
                }
            }
            Some("tool_use") => {
                let name = b.get("name").and_then(|v| v.as_str()).unwrap_or_default();
                if !name.is_empty() {
                    calls.push(serde_json::json!({
                        "id": b.get("id").and_then(|v| v.as_str()).unwrap_or_default(),
                        "name": name,
                        "arguments_json": serde_json::to_string(
                            b.get("input").unwrap_or(&serde_json::json!({})),
                        )
                        .unwrap_or_else(|_| "{}".to_string()),
                    }));
                }
            }
            _ => {}
        }
    }
    let text = if texts.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::Value::String(texts.join(""))
    };
    Ok(serde_json::json!({ "text": text, "tool_calls": calls }))
}

// ─── Chat / test commands ───────────────────────────────────────────────────

#[tauri::command]
pub async fn assistant_chat(
    app: AppHandle,
    messages: Vec<ChatMessage>,
    tools: Vec<ToolSpec>,
    max_tokens: Option<u32>,
) -> CmdResult<serde_json::Value> {
    let p = load_provider(&app)?;
    let max_tokens = max_tokens.unwrap_or(2048);
    let client = http_client(CHAT_TIMEOUT)?;

    let resp = if p.provider == "anthropic" {
        let body = anthropic_body(&p.model, &messages, &tools, max_tokens)?;
        client
            .post(format!("{}/v1/messages", p.base_url))
            .header("x-api-key", p.api_key.as_str())
            .header("anthropic-version", ANTHROPIC_VERSION)
            .json(&body)
            .send()
            .await
            .map_err(|e| CmdError(format!("Provider request failed: {e}")))?
    } else {
        let body = openai_body(&p.model, &messages, &tools, max_tokens)?;
        client
            .post(format!("{}/chat/completions", p.base_url))
            .bearer_auth(p.api_key.as_str())
            .json(&body)
            .send()
            .await
            .map_err(|e| CmdError(format!("Provider request failed: {e}")))?
    };

    if !resp.status().is_success() {
        return Err(provider_error(resp).await);
    }
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| CmdError(format!("Provider returned a non-JSON response: {e}")))?;
    if p.provider == "anthropic" {
        parse_anthropic_response(&body)
    } else {
        parse_openai_response(&body)
    }
}

#[tauri::command]
pub async fn assistant_test_connection(app: AppHandle) -> CmdResult<serde_json::Value> {
    let p = load_provider(&app)?;
    let client = http_client(TEST_TIMEOUT)?;

    let resp = if p.provider == "anthropic" {
        // Anthropic has no cheap authenticated GET; a 1-token messages call
        // is the smallest real check and validates base URL, key, and model.
        let body = serde_json::json!({
            "model": p.model,
            "max_tokens": 1,
            "messages": [{ "role": "user", "content": "ping" }],
        });
        client
            .post(format!("{}/v1/messages", p.base_url))
            .header("x-api-key", p.api_key.as_str())
            .header("anthropic-version", ANTHROPIC_VERSION)
            .json(&body)
            .send()
            .await
            .map_err(|e| CmdError(format!("Connection failed: {e}")))?
    } else {
        client
            .get(format!("{}/models", p.base_url))
            .bearer_auth(p.api_key.as_str())
            .send()
            .await
            .map_err(|e| CmdError(format!("Connection failed: {e}")))?
    };

    if !resp.status().is_success() {
        return Err(provider_error(resp).await);
    }
    Ok(serde_json::json!({
        "ok": true,
        "detail": format!("Connected to {} (model: {}).", p.base_url, p.model),
    }))
}

// ─── Level + execution gate ─────────────────────────────────────────────────

#[tauri::command]
pub fn assistant_set_level(
    app: AppHandle,
    tab_id: String,
    level: String,
) -> CmdResult<serde_json::Value> {
    if !valid_level(&level) {
        return Err(format!("Unknown access level '{level}'.").into());
    }
    app.state::<AssistantLevels>().set(&tab_id, &level);
    Ok(serde_json::json!({ "ok": true }))
}

#[tauri::command]
pub fn assistant_get_level(app: AppHandle, tab_id: String) -> CmdResult<serde_json::Value> {
    let level = app.state::<AssistantLevels>().get(&tab_id);
    Ok(serde_json::json!({ "level": level }))
}

#[tauri::command]
pub fn assistant_exec(
    app: AppHandle,
    session_id: String,
    tab_id: String,
    command: String,
) -> CmdResult<serde_json::Value> {
    let level = app.state::<AssistantLevels>().get(&tab_id);
    if !level_permits_exec(&level) {
        return Err(format!(
            "AI access level is '{level}' - raise it in the assistant panel to let the assistant run commands."
        )
        .into());
    }
    let db = &app.state::<crate::AppState>().db;
    let snippet: String = command.chars().take(200).collect();
    db.add_audit(
        "assistant.exec",
        None,
        &format!("tab={tab_id} level={level} cmd={snippet}"),
    )
    .map_err(|e| e.to_string())?;

    // Same path as terminal_send: the renderer's confirmed AI command is just
    // bytes on the session's stdin, Enter included.
    let registry = app
        .state::<std::sync::Arc<crate::ssh_client::SessionRegistry>>()
        .inner()
        .clone();
    let mut bytes = command.into_bytes();
    bytes.push(b'\r');
    crate::ssh_client::session_send(&registry, &session_id, bytes).map_err(CmdError::from)?;
    Ok(serde_json::json!({ "ok": true }))
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn tools() -> Vec<ToolSpec> {
        vec![ToolSpec {
            name: "run_command".into(),
            description: "Run a shell command.".into(),
            parameters_json: r#"{"type":"object","properties":{"command":{"type":"string"}},"required":["command"]}"#.into(),
        }]
    }

    fn history() -> Vec<ChatMessage> {
        vec![
            ChatMessage::System {
                content: "You help administer servers.".into(),
            },
            ChatMessage::User {
                content: "check disk".into(),
            },
            ChatMessage::Assistant {
                content: None,
                tool_calls: Some(vec![ToolCall {
                    id: "call_1".into(),
                    name: "get_terminal_output".into(),
                    arguments_json: "{}".into(),
                }]),
            },
            ChatMessage::Tool {
                tool_call_id: "call_1".into(),
                name: "get_terminal_output".into(),
                content: "user@host:~$".into(),
            },
            ChatMessage::Assistant {
                content: Some("Disk is fine.".into()),
                tool_calls: None,
            },
        ]
    }

    #[test]
    fn openai_shapes_all_message_kinds() {
        let body = openai_body("gpt-4o-mini", &history(), &tools(), 1024).unwrap();
        assert_eq!(body["model"], "gpt-4o-mini");
        let msgs = body["messages"].as_array().unwrap();
        assert_eq!(msgs[0]["role"], "system");
        assert_eq!(
            msgs[2]["tool_calls"][0]["function"]["name"],
            "get_terminal_output"
        );
        // Arguments cross the wire as the string the renderer supplied.
        assert_eq!(msgs[2]["tool_calls"][0]["function"]["arguments"], "{}");
        assert_eq!(msgs[3]["role"], "tool");
        assert_eq!(msgs[3]["tool_call_id"], "call_1");
        // Assistant message without tool calls must not carry an empty array.
        assert!(msgs[4].get("tool_calls").is_none());
        assert_eq!(
            body["tools"][0]["function"]["parameters"]["properties"]["command"]["type"],
            "string"
        );
    }

    #[test]
    fn openai_omits_tools_when_empty() {
        let body = openai_body("m", &history(), &[], 1024).unwrap();
        assert!(body.get("tools").is_none());
    }

    #[test]
    fn openai_rejects_bad_schema_json() {
        let bad = vec![ToolSpec {
            name: "x".into(),
            description: "x".into(),
            parameters_json: "{not json".into(),
        }];
        assert!(openai_body("m", &history(), &bad, 1024).is_err());
    }

    #[test]
    fn openai_parses_text_toolcalls_and_mixed() {
        let text_only = serde_json::json!({
            "choices": [{ "message": { "role": "assistant", "content": "hi" } }]
        });
        let r = parse_openai_response(&text_only).unwrap();
        assert_eq!(r["text"], "hi");
        assert_eq!(r["tool_calls"].as_array().unwrap().len(), 0);

        // [OI] returns null content when the model only calls tools.
        let calls_only = serde_json::json!({
            "choices": [{ "message": {
                "role": "assistant", "content": null,
                "tool_calls": [{
                    "id": "call_9", "type": "function",
                    "function": { "name": "run_command", "arguments": "{\"command\":\"ls\"}" }
                }]
            }}]
        });
        let r = parse_openai_response(&calls_only).unwrap();
        assert!(r["text"].is_null());
        assert_eq!(r["tool_calls"][0]["name"], "run_command");
        assert_eq!(r["tool_calls"][0]["arguments_json"], "{\"command\":\"ls\"}");

        let no_choices = serde_json::json!({ "choices": [] });
        assert!(parse_openai_response(&no_choices).is_err());
    }

    #[test]
    fn anthropic_hoists_system_and_shapes_tools() {
        let body = anthropic_body("claude-sonnet-4-5", &history(), &tools(), 1024).unwrap();
        assert_eq!(body["system"], "You help administer servers.");
        assert!(body["messages"]
            .as_array()
            .unwrap()
            .iter()
            .all(|m| m["role"] != "system"));
        assert_eq!(body["tools"][0]["input_schema"]["type"], "object");
        let msgs = body["messages"].as_array().unwrap();
        // user, assistant(text absent, tool_use), user(tool_result), assistant(text)
        assert_eq!(msgs[1]["role"], "assistant");
        assert_eq!(msgs[1]["content"][0]["type"], "tool_use");
        assert_eq!(msgs[1]["content"][0]["input"], serde_json::json!({}));
        assert_eq!(msgs[2]["role"], "user");
        assert_eq!(msgs[2]["content"][0]["type"], "tool_result");
        assert_eq!(msgs[2]["content"][0]["tool_use_id"], "call_1");
    }

    #[test]
    fn anthropic_merges_consecutive_tool_results() {
        let msgs = vec![
            ChatMessage::User {
                content: "go".into(),
            },
            ChatMessage::Assistant {
                content: None,
                tool_calls: Some(vec![
                    ToolCall {
                        id: "a".into(),
                        name: "t1".into(),
                        arguments_json: "{}".into(),
                    },
                    ToolCall {
                        id: "b".into(),
                        name: "t2".into(),
                        arguments_json: "{}".into(),
                    },
                ]),
            },
            ChatMessage::Tool {
                tool_call_id: "a".into(),
                name: "t1".into(),
                content: "one".into(),
            },
            ChatMessage::Tool {
                tool_call_id: "b".into(),
                name: "t2".into(),
                content: "two".into(),
            },
        ];
        let body = anthropic_body("m", &msgs, &[], 1024).unwrap();
        let wire = body["messages"].as_array().unwrap();
        // Adjacent same-role messages are an API error; both results must sit
        // in ONE following user message.
        assert_eq!(wire.len(), 3);
        assert_eq!(wire[2]["content"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn untrusted_block_in_user_message_shapes_for_both_providers() {
        // The prompt-injection hardening delivers the terminal snapshot inside
        // a single user message (nonce-wrapped, closing tag stripped). Both
        // providers must shape that list into a valid request - critically,
        // Anthropic must NOT split it into adjacent same-role messages.
        let nonce = "1234567890123456";
        let snapshot = format!(
            "<terminal_output_{nonce} trust=\"untrusted\">\n$ df -h\nFilesystem  Size\n</terminal_output_{nonce}>"
        );
        let user_content = format!("summarize the screen\n\n{snapshot}");
        let msgs = vec![
            ChatMessage::System {
                content: "rules".into(),
            },
            ChatMessage::User {
                content: user_content.clone(),
            },
        ];

        // [OI]: system stays in-band, user content passes through verbatim.
        let oi = openai_body("m", &msgs, &[], 1024).unwrap();
        let oi_msgs = oi["messages"].as_array().unwrap();
        assert_eq!(oi_msgs[0]["role"], "system");
        assert_eq!(oi_msgs[1]["role"], "user");
        assert_eq!(
            oi_msgs[1]["content"],
            serde_json::Value::String(user_content.clone())
        );
        assert!(oi_msgs[1]["content"]
            .as_str()
            .unwrap()
            .contains(&format!("terminal_output_{nonce}")));

        // Anthropic: system hoisted, exactly one user message (no adjacent
        // same-role split), and the untrusted block survives inside it.
        let an = anthropic_body("m", &msgs, &[], 1024).unwrap();
        assert_eq!(an["system"], "rules");
        let an_msgs = an["messages"].as_array().unwrap();
        assert_eq!(an_msgs.len(), 1, "must be exactly one non-system message");
        assert_eq!(an_msgs[0]["role"], "user");
        let an_text = an_msgs[0]["content"].as_str().unwrap();
        assert!(an_text.contains(&format!("terminal_output_{nonce}")));
        assert!(an_text.contains("summarize the screen"));
    }

    #[test]
    fn anthropic_rejects_system_only_conversation() {
        let msgs = vec![ChatMessage::System {
            content: "s".into(),
        }];
        assert!(anthropic_body("m", &msgs, &[], 1024).is_err());
    }

    #[test]
    fn anthropic_parses_text_and_tool_use() {
        let body = serde_json::json!({
            "content": [
                { "type": "text", "text": "Let me check. " },
                { "type": "tool_use", "id": "tu_1", "name": "run_command",
                  "input": { "command": "df -h" } },
                { "type": "text", "text": "Running it." }
            ]
        });
        let r = parse_anthropic_response(&body).unwrap();
        assert_eq!(r["text"], "Let me check. Running it.");
        assert_eq!(r["tool_calls"][0]["id"], "tu_1");
        assert_eq!(
            r["tool_calls"][0]["arguments_json"],
            "{\"command\":\"df -h\"}"
        );

        let no_content = serde_json::json!({ "id": "msg_1" });
        assert!(parse_anthropic_response(&no_content).is_err());
    }

    #[test]
    fn level_gate_allows_only_execute_and_yolo() {
        assert!(!level_permits_exec("read"));
        assert!(!level_permits_exec("draft"));
        assert!(level_permits_exec("execute"));
        assert!(level_permits_exec("yolo"));
        assert!(!level_permits_exec(""));
        assert!(!level_permits_exec("admin"));
    }

    #[test]
    fn levels_default_to_read_and_roundtrip() {
        let levels = AssistantLevels::new();
        assert_eq!(levels.get("tab1"), "read");
        levels.set("tab1", "yolo");
        assert_eq!(levels.get("tab1"), "yolo");
        levels.clear();
        assert_eq!(levels.get("tab1"), "read");
    }

    #[test]
    fn unknown_level_strings_are_rejected() {
        for bad in ["YOLO", "write", "", "read-only"] {
            assert!(!valid_level(bad), "{bad} must not validate");
        }
        for good in ["read", "draft", "execute", "yolo"] {
            assert!(valid_level(good));
        }
    }

    #[test]
    fn sealed_key_roundtrip() {
        let pw = Zeroizing::new("vault-master".to_string());
        let sealed = crate::crypto::vault::seal(&pw, b"sk-test-123").unwrap();
        let back = crate::crypto::vault::unseal(&pw, &sealed).unwrap();
        assert_eq!(back, b"sk-test-123");
    }
}
