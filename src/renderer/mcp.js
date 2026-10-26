/**
 * mcp.js - MCP (Model Context Protocol) server support, renderer side.
 *
 * Two jobs:
 *   1. Agent-loop integration. mcp_list_servers is mirrored into a module
 *      registry; only tools the user explicitly enabled AND that are still
 *      pinned (the server has not changed their definition since) are offered
 *      to the model. They are appended AFTER assistant.js's built-in tools and
 *      only fill the remaining slots up to 64 - built-ins always win. MCP
 *      results are third-party output, so assistant.js wraps every one in the
 *      turn's nonce untrusted block before it enters the conversation.
 *   2. The Settings -> AI assistant -> MCP servers section: server list with
 *      status, add/edit form with per-auth-type value source, test connection,
 *      and a per-tool approval list (Enable / Auto-approve toggles). Every
 *      approval names the definition the user reviewed (`expected_hash` =
 *      the shown `definition_hash`), so a definition that changed meanwhile
 *      is refused by the backend and shown again, never approved unseen.
 *
 * SECURITY: names, URLs, descriptions and annotations come from MCP servers -
 * fully untrusted. Every one of them is rendered with textContent /
 * createElement, never innerHTML. A tool's name and display name are also
 * spelled out where this file and assistant.js show them (spellOut, app.js;
 * mcpNameInText), and so is the server's own name, which a backup restores
 * unchecked, so a direction override or a zero-width character cannot make
 * one tool or server read as another; the model, the backend and the stored
 * record get them as they are. Annotations may be SHOWN in the approval card
 * but never bypass it; only the user-set auto_approve flag does that.
 *
 * Loaded by app.js right after assistant.js; bridges through window.*.
 */

'use strict';

// Hard cap on the merged (built-in + MCP) tool list lives in assistant.js
// (AI_MAX_TOOLS_TOTAL); the merge there takes the built-ins unfiltered and
// gives mcpGetTools() only the leftover slots, so MCP never displaces them.
const MCP_DESC_LIMIT = 1024;

// Model-facing tool names are the backend's `exposed_name` (mcpExposedName
// below): sanitized server and tool parts, capped at 64 characters with a
// hash suffix - computed once, in Rust, by the function its gates use.

// ─── registry ───────────────────────────────────────────────────────────────

// What mcp_list_servers last returned (array of server objects straight from
// the backend - treat every field in it as untrusted data).
let mcpServers = [];
let mcpAvailable = true; // false once the backend command is found missing
let mcpRefreshSeq = 0;   // only the newest list request may replace the registry

const mcpCall = (cmd, args) => (window.call || call)(cmd, args);

// An error becomes text through app.js's errText (it loads first).

/// Tauri's own answer for a command that is not registered (tauri 2.11.5,
/// src/webview/mod.rs, on_message: `Command {command} not found`). Only THAT means "this
/// backend has no MCP support": a corrupt record ("missing field ...") or a
/// database error ("no such table") used to match a broad regex and turned
/// MCP off for the session with a wrong explanation (A4-25).
function mcpIsUnknownCommand(msg) {
  return /^Command mcp_[a-z_]+ not found$/i.test(String(msg).trim());
}

// Pull the registry from the backend. Missing command (old backend) degrades
// to a one-time notice; other errors surface but keep the previous snapshot.
async function mcpRefresh() {
  if (!mcpAvailable) return null;
  const seq = ++mcpRefreshSeq;
  try {
    const list = await mcpCall('mcp_list_servers');
    // An older request answering last must not overwrite a fresher list
    // (a toggle's reload racing the panel's refresh).
    if (seq === mcpRefreshSeq) mcpServers = Array.isArray(list) ? list : [];
    return mcpServers;
  } catch (e) {
    if (mcpIsUnknownCommand(errText(e))) {
      mcpAvailable = false; // old backend without MCP: degrade, stop asking
      mcpServers = [];
      return null;
    }
    throw e;
  }
}

function mcpServerById(id) {
  return mcpServers.find(sv => sv && sv.id === id) || null;
}

// ─── agent-loop bridge ──────────────────────────────────────────────────────

/// The model-facing name of a tool: the backend's `exposed_name`, computed by
/// the same function its enable gate uses (64-character cap plus a hash
/// suffix - A4-11 / A8-20). A tool without one is not offered at all.
function mcpExposedName(t) {
  const n = t && t.exposed_name;
  return typeof n === 'string' && n.startsWith('mcp__') && n.length <= 64 ? n : null;
}

// Model-facing tool specs for every enabled+pinned MCP tool, in a stable
// order (registry order, tool order within a server). Same shape as
// assistant.js's AI_TOOL_SPECS entries so the backend forwards them
// unchanged. The server's own description is NOT forwarded (it is untrusted
// text): the model gets the server name, the tool name and its title, capped
// at MCP_DESC_LIMIT, plus the input schema.
function mcpGetTools() {
  const out = [];
  if (!mcpAvailable) return out;
  // Belt-and-suspenders on top of assistant.js's built-ins-first merge: even
  // though the merge can never displace a built-in, also refuse any MCP tool
  // whose sanitized name would collide with a built-in's exact name.
  const builtins = typeof window.aiBuiltinToolNames === 'function'
    ? window.aiBuiltinToolNames() : [];
  const seen = {};
  for (const sv of mcpServers) {
    if (!sv || !Array.isArray(sv.tools)) continue;
    for (const t of sv.tools) {
      if (!t || !t.enabled || !t.pinned || t.definition_changed) continue;
      const name = mcpExposedName(t);
      // Refuse built-in collisions and duplicates (two servers whose names
      // sanitize identically): the first one wins, the model never sees an
      // ambiguous tool name.
      if (!name || builtins.indexOf(name) !== -1 || seen[name]) continue;
      seen[name] = true;
      const rawDesc = t.display_name && t.display_name !== t.name
        ? t.display_name + ' (MCP server "' + sv.name + '", tool "' + t.name + '")'
        : 'MCP server "' + sv.name + '", tool "' + t.name + '"';
      const desc = rawDesc.length > MCP_DESC_LIMIT
        ? rawDesc.slice(0, MCP_DESC_LIMIT) : rawDesc;
      const parameters_json = mcpValidateToolSchema(t, sv.name, t.name);
      out.push({ name, description: desc, parameters_json });
    }
  }
  return out;
}

function mcpIsMcpTool(name) {
  return typeof name === 'string' && name.startsWith('mcp__');
}

// Reverse the model-facing name back to {serverId, toolName}. It is compared
// in full against every offered tool's exposed_name - a name the model merely
// MADE UP starting with "mcp__" maps to nothing and is rejected, so it cannot
// select a server or tool it was never shown.
function mcpResolveTool(name) {
  for (const sv of mcpServers) {
    if (!sv || !Array.isArray(sv.tools)) continue;
    for (const t of sv.tools) {
      if (!t || !t.enabled || !t.pinned || t.definition_changed) continue;
      if (name === mcpExposedName(t)) {
        return { serverId: sv.id, serverName: sv.name, toolName: t.name,
                 autoApprove: !!t.auto_approve, annotations: t.annotations || null };
      }
    }
  }
  return null;
}

// Look up the CURRENT state of an MCP tool (assistant.js consults this for the
// auto-approve bypass, so a mid-turn settings change takes effect immediately).
function mcpToolInfo(name) {
  return mcpResolveTool(name);
}

// Invoke an MCP tool on the backend. approved: true ONLY when the user
// clicked Approve on this call's card (R6) - Auto-approve and YOLO pass
// false, and the backend's gate decides (it names the source in the audit
// row: approved / auto / yolo). Returns {content, isError, warning}; all
// three are server-supplied text for the caller to render with textContent
// and to wrap as untrusted before the model sees them.
async function mcpCallTool(tabId, name, args, approved) {
  const r = mcpResolveTool(name);
  if (!r) throw new Error('unknown MCP tool: ' + name);
  const res = await mcpCall('mcp_call_tool', {
    tabId,
    id: r.serverId,
    tool: r.toolName,
    argumentsJson: JSON.stringify(args == null ? {} : args),
    approved: approved === true,
  });
  return {
    content: res && res.content != null ? String(res.content) : '',
    isError: !!(res && res.is_error),
    warning: res && res.warning ? String(res.warning) : null,
  };
}

/// A name an MCP server chose inside a sentence of plain text (an error, the
/// status strip, a toast, a question): a tool's, or the server's own, which
/// is checked when it is saved but not when it is restored from a backup.
/// Spelled out (spellOut, app.js), then kept to itself between FIRST STRONG
/// ISOLATE and POP DIRECTIONAL ISOLATE, as bdiOf keeps a name in a line of
/// the page, so it cannot read as another name or turn the words around it.
function mcpNameInText(name) {
  return '\u2068' + spellOut(name) + '\u2069';
}

// Validate that a tool schema coming from the backend is usable JSON and not
// empty. Returns the schema as a JSON string; throws a visible error if
// missing/invalid. The error is shown, never sent to the model: it names the
// tool and its server spelled out (mcpNameInText), and a parse error, which
// can quote the schema, is spelled out too.
function mcpValidateToolSchema(t, serverName, toolName) {
  const which = 'MCP tool "' + mcpNameInText(toolName) + '" from server "' + mcpNameInText(serverName) + '"';
  const raw = t && typeof t === 'object' ? t.inputSchema : undefined;
  if (raw == null) {
    throw new Error(which + ' has no inputSchema.');
  }
  let parsed;
  if (typeof raw === 'string') {
    try {
      parsed = JSON.parse(raw);
    } catch (e) {
      throw new Error(which + ' has invalid inputSchema: ' + errSpelled(e));
    }
  } else if (typeof raw === 'object') {
    parsed = raw;
  } else {
    throw new Error(which + ' has a non-object inputSchema.');
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error(which + ' has a non-object inputSchema.');
  }
  return typeof raw === 'string' ? raw : JSON.stringify(raw);
}

// ─── settings: server list ──────────────────────────────────────────────────

function mcpListHost() { return document.getElementById('mcpServerList'); }
function mcpFormHost() { return document.getElementById('mcpFormHost'); }

const MCP_STATUS_TEXT = { connected: 'Connected', error: 'Error', unknown: 'Not connected' };

// A server the backend keeps switched off until the user confirms it (A4-07):
// one restored from a backup, and one whose credential the user did not allow
// to be sent in SSHSpan's own native question. Connect and call are refused
// meanwhile. What its row says:
const MCP_NOT_CONFIRMED_CREDENTIAL = 'Not confirmed - SSHSpan will not send this credential until you allow it.';
const MCP_NOT_CONFIRMED_ADDRESS = 'Not confirmed - SSHSpan will not connect to this server until you open Edit, check its address and save it.';
// A save answered "not confirmed" without saying why.
const MCP_SAVED_NOT_CONFIRMED = 'Saved, but not confirmed - SSHSpan will not send its credential until you allow it.';

/// Does `sv` send a credential - a stored secret or an environment variable?
function mcpSendsCredential(sv) {
  return !!sv && (sv.auth_type || 'none') !== 'none' && (!!sv.has_secret || !!sv.auth_env_var);
}

// The dot is colour; the text next to it says the same in words (A4-24).
function mcpStatusDot(status) {
  const dot = document.createElement('span');
  dot.className = 'server-dot mcp-dot ' + (status === 'connected' ? 'live' : status === 'error' ? 'err' : '');
  const label = MCP_STATUS_TEXT[status] || MCP_STATUS_TEXT.unknown;
  dot.title = label;
  dot.setAttribute('role', 'img');
  dot.setAttribute('aria-label', 'Status: ' + label);
  return dot;
}

// Servers with an operation in flight (Test, Remove): one at a time per
// server, and the row's buttons stay disabled until it ends - a double click
// used to start a second 60-second test or a second removal (A4-12).
const mcpBusyServers = new Set();
// The last Test failure per server id. mcp_list_servers reports a status
// but not the error, so the message the Test returned is kept here and shown
// beside the row until the next successful Test (A4-15).
const mcpLastErrors = new Map();

function mcpRowEl(id) {
  const host = mcpListHost();
  return host ? [...host.querySelectorAll('.mcp-server-row')].find((r) => r.dataset.id === String(id)) || null : null;
}

function mcpPaintRowBusy(id) {
  const row = mcpRowEl(id);
  if (!row) return;
  const on = mcpBusyServers.has(id);
  row.setAttribute('aria-busy', on ? 'true' : 'false');
  // One reason among others (setDisabledFor): the end of a run does not
  // re-enable a button the vault lock disabled meanwhile.
  for (const b of row.querySelectorAll('.mcp-server-actions button')) setDisabledFor(b, 'busy', on);
}

/// Run `fn` as the one operation of server `id`; a second call while it runs
/// is ignored.
async function mcpRowAction(id, fn) {
  if (mcpBusyServers.has(id)) return undefined;
  mcpBusyServers.add(id);
  mcpPaintRowBusy(id);
  try {
    return await fn();
  } finally {
    mcpBusyServers.delete(id);
    mcpPaintRowBusy(id);
  }
}

/// The MCP section's status strip: notices that must outlive a reload (a
/// removal's teardown warning, a definition that changed under a click).
function mcpSetStatus(text, kind) {
  const strip = mcpF('mcpStatus');
  if (!strip) return;
  strip.className = 'status-strip' + (kind ? ' ' + kind : '');
  strip.textContent = text;
}

function mcpEnabledCount(sv) {
  return Array.isArray(sv.tools) ? sv.tools.filter((t) => t && t.enabled).length : 0;
}

// One row per server: status, name, url, enabled/total tools, protocol, the
// last Test error, whether it is confirmed, and the actions (allow sending,
// edit, review tools, test, remove). Every string from the server goes
// through textContent.
function mcpServerRow(sv) {
  const row = document.createElement('div');
  row.className = 'mcp-server-row';
  row.dataset.id = String(sv.id == null ? '' : sv.id);

  const head = document.createElement('div');
  head.className = 'mcp-server-head';
  head.appendChild(mcpStatusDot(sv.status));
  const status = document.createElement('span');
  status.className = 'mcp-status-text';
  status.textContent = MCP_STATUS_TEXT[sv.status] || MCP_STATUS_TEXT.unknown;
  head.appendChild(status);
  const name = document.createElement('span');
  name.className = 'mcp-server-name';
  // Spelled out: a backup restores the name unchecked (mcpNameInText).
  name.textContent = spellOut(sv.name || '(unnamed)');
  head.appendChild(name);
  const url = document.createElement('span');
  url.className = 'mcp-server-url mono';
  url.textContent = sv.url || '';
  url.title = sv.url || '';
  head.appendChild(url);
  // Only `confirmed: true` is confirmed - the same rule as a save's answer
  // (mcpSaveOutcome): a record that says nothing of it fails closed.
  const unconfirmed = sv.confirmed !== true;
  const asksToSend = unconfirmed && mcpSendsCredential(sv);
  if (unconfirmed) {
    // Seen at a glance; the sentence below the head says it in full, so the
    // badge is not read out twice.
    const badge = document.createElement('span');
    badge.className = 'mcp-badge';
    badge.textContent = 'Not confirmed';
    badge.setAttribute('aria-hidden', 'true');
    head.appendChild(badge);
  }
  const total = Array.isArray(sv.tools) ? sv.tools.length : 0;
  const count = document.createElement('span');
  count.className = 'mcp-server-count';
  count.textContent = mcpEnabledCount(sv) + '/' + total + ' tools enabled';
  head.appendChild(count);
  row.appendChild(head);

  let unconfirmedNote = null;
  if (unconfirmed) {
    unconfirmedNote = document.createElement('div');
    unconfirmedNote.className = 'mcp-unconfirmed';
    unconfirmedNote.id = 'mcpUnconfirmed-' + row.dataset.id.replace(/[^\w-]/g, '_');
    unconfirmedNote.textContent = asksToSend ? MCP_NOT_CONFIRMED_CREDENTIAL : MCP_NOT_CONFIRMED_ADDRESS;
    row.appendChild(unconfirmedNote);
  }

  if (sv.protocol_version) {
    const meta = document.createElement('div');
    meta.className = 'mcp-server-meta';
    meta.textContent = 'MCP protocol ' + sv.protocol_version;
    row.appendChild(meta);
  }

  const lastError = mcpLastErrors.get(sv.id);
  if (lastError) {
    const err = document.createElement('div');
    err.className = 'mcp-server-error';
    err.textContent = 'Last test failed: ' + lastError;
    row.appendChild(err);
  }

  if (sv.loopback_insecure) {
    const warn = document.createElement('div');
    warn.className = 'mcp-loopback-warn';
    warn.textContent = 'Plain HTTP on a loopback address - traffic to this server is not encrypted or authenticated.';
    row.appendChild(warn);
  }

  const actions = document.createElement('div');
  actions.className = 'mcp-server-actions';
  const mkBtn = (label, cls, handler) => {
    const b = document.createElement('button');
    b.type = 'button';
    b.className = cls;
    b.textContent = label;
    b.addEventListener('click', handler);
    actions.appendChild(b);
    return b;
  };
  if (asksToSend) {
    // Asked again by the backend, in its own dialog (it saves to the vault,
    // so not while it is locked).
    const allow = mkBtn('Allow sending...', 'ghost-btn', () => mcpAllowSending(sv));
    allow.setAttribute('aria-describedby', unconfirmedNote.id);
    lockGate(allow, 'settings');
  }
  mkBtn('Edit', 'ghost-btn', () => mcpOpenForm(sv));
  // The stored tools and their approvals, without reconnecting (A4-15).
  mkBtn('Review tools', 'ghost-btn', () => mcpShowToolsFor(sv.id));
  // Connecting unseals the credential and removing rewrites the vault: both
  // wait for an unlocked vault (the backend refuses anyway).
  lockGate(mkBtn('Test connection', 'ghost-btn', () => mcpTestConnection(sv.id)), 'settings');
  lockGate(mkBtn('Remove', 'danger-btn', () => mcpRemoveServer(sv)), 'settings');
  row.appendChild(actions);
  if (mcpBusyServers.has(sv.id)) {
    row.setAttribute('aria-busy', 'true');
    for (const b of actions.querySelectorAll('button')) setDisabledFor(b, 'busy', true);
  }
  return row;
}

async function mcpRemoveServer(sv) {
  if (mcpBusyServers.has(sv.id)) return;
  // The app's own dialog: the native confirm() is not usable here (see
  // confirmModal in app.js), and Cancel / Escape must really mean no.
  const ok = await confirmModal('Remove MCP server', 'Remove MCP server "' + mcpNameInText(sv.name || '') + '"?', 'Remove');
  if (!ok) return;
  await mcpRowAction(sv.id, async () => {
    try {
      const r = await mcpCall('mcp_remove_server', { id: sv.id });
      mcpLastErrors.delete(sv.id);
      if (mcpToolsShownFor === sv.id) mcpToolsShownFor = null;
      await mcpLoadSettings();
      // The entry is gone either way; what went wrong around it - a failed
      // session teardown (A4-27), an audit row that could not be written,
      // or both - is said as the backend says it, as text, where it stays
      // readable. Spelled out: a teardown that timed out names the server.
      if (r && r.warning) {
        const said = 'MCP server removed. ' + spellOut(r.warning);
        mcpSetStatus(said, 'warn');
        toast(said, 'warn');
      } else {
        toast('MCP server removed.', 'ok');
      }
    } catch (e) {
      toast(errText(e), 'err');
    }
  });
}

function mcpRenderList() {
  const host = mcpListHost();
  if (!host) return;
  host.textContent = '';
  if (!mcpServers.length) {
    const empty = document.createElement('p');
    empty.className = 'hint';
    empty.textContent = 'No MCP servers configured yet.';
    host.appendChild(empty);
    return;
  }
  for (const sv of mcpServers) host.appendChild(mcpServerRow(sv));
}

// ─── settings: add / edit form ──────────────────────────────────────────────

let mcpEditing = null; // server object being edited, or null when adding

function mcpF(id) { return document.getElementById(id); }

function mcpAuthKind() { const e = mcpF('mcpAuthType'); return e ? e.value : 'none'; }
function mcpSecretKind() { const e = mcpF('mcpSecretSource'); return e ? e.value : 'stored'; }

function mcpShowIf(id, on) { const e = mcpF(id); if (e) e.hidden = !on; }

// bearer / custom_header show a value-source picker: a sealed stored secret
// (password field, blank keeps the stored one) or the NAME of an environment
// variable the backend should read.
function mcpSyncAuthRows() {
  const kind = mcpAuthKind();
  const secret = mcpSecretKind();
  const withSecret = kind === 'bearer' || kind === 'custom_header';
  mcpShowIf('mcpSecretSourceRow', withSecret);
  mcpShowIf('mcpHeaderRow', kind === 'custom_header');
  mcpShowIf('mcpSecretRow', withSecret && secret === 'stored');
  mcpShowIf('mcpEnvRow', withSecret && secret === 'env');
  const env = mcpF('mcpAuthEnvVar');
  if (env) env.placeholder = kind === 'custom_header' ? 'e.g. MY_SERVICE_TOKEN' : 'e.g. GITHUB_MCP_TOKEN';
  mcpUrlCheck();
}

/// The MCP rule, mirrored from the backend's classify_url (assistant/mcp.rs):
/// plain http only to localhost, ::1 or 127.x - NOT the provider base URL's
/// broader local/private-network rule. Like the backend's url_host it is
/// decided on the PARSED host (A4-23): an IPv4 address in 127.0.0.0/8 (the
/// URL parser writes 127.1 as 127.0.0.1), the IPv6 address ::1 or the name
/// localhost - never a name that only starts like one ("127.example.com",
/// "localhost.example.com").
function mcpIsLoopbackHost(hostname) {
  const h = String(hostname || '').toLowerCase().replace(/^\[|\]$/g, '');
  return h === 'localhost' || h === '::1' || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(h);
}

// Plain-http loopback gets a visible warning; plain-http anywhere else is
// refused in the UI before it ever reaches the backend (which also enforces).
function mcpIsLoopbackUrl(u) {
  let p;
  try { p = new URL(u); } catch (e) { return false; }
  return p.protocol === 'http:' && mcpIsLoopbackHost(p.hostname);
}

/// Why `raw` cannot be saved as an MCP server URL, or '' if it can.
function mcpUrlProblem(raw) {
  let p;
  try { p = new URL(raw); } catch (e) { return 'Not a valid URL.'; }
  if (p.protocol !== 'http:' && p.protocol !== 'https:') return 'Only http:// and https:// URLs are supported.';
  if (p.username || p.password) return 'Server URL must not contain credentials.';
  // The backend keeps scheme, host, port and path only; a query (often a
  // token or a route) or a fragment would vanish silently (A4-23).
  if (/[?#]/.test(raw)) {
    return 'MCP server URLs cannot carry a ?query or #fragment - SSHSpan would connect without it. Remove everything from the ? or # on; put a token in the auth settings below.';
  }
  if (p.protocol === 'http:' && !mcpIsLoopbackHost(p.hostname)) {
    return 'Plain http:// is only allowed for localhost, 127.x or ::1 - use https:// for anything else.';
  }
  return '';
}

/// The URL as the backend stores it (classify_url: scheme://host[:port]path,
/// no trailing slash), to tell a real change from a re-typed equal URL.
function mcpNormalizedUrl(raw) {
  let p;
  try { p = new URL(String(raw || '').trim()); } catch (e) { return String(raw || '').trim(); }
  const host = p.hostname.toLowerCase().replace(/^\[|\]$/g, '');
  const path = p.pathname.replace(/\/+$/, '');
  return p.protocol + '//' + host + (p.port ? ':' + p.port : '') + (path === '/' ? '' : path);
}

function mcpUrlCheck() {
  const input = mcpF('mcpUrl');
  const warn = mcpF('mcpUrlWarn');
  const err = mcpF('mcpUrlError');
  const save = mcpF('mcpSaveBtn');
  const raw = input ? input.value.trim() : '';
  const problem = raw ? mcpUrlProblem(raw) : '';
  if (warn) warn.hidden = !raw || !!problem || !mcpIsLoopbackUrl(raw);
  if (err) { err.textContent = problem; err.hidden = !problem; }
  if (input) input.setAttribute('aria-invalid', problem ? 'true' : 'false');
  // One reason among others: a Save that is running stays disabled.
  if (save) setDisabledFor(save, 'url', !!problem);
  mcpRebindCheck();
}

/// Would this edit drop the server's stored credential? The backend binds a
/// stored secret to the URL, auth type and header name it was entered for
/// (A4-07): changing any of them discards it unless a new one is entered.
function mcpRebound() {
  const sv = mcpEditing;
  if (!sv) return false;
  const kind = mcpAuthKind();
  const header = (mcpF('mcpHeaderName') || {}).value || '';
  return mcpNormalizedUrl((mcpF('mcpUrl') || {}).value) !== String(sv.url || '')
    || kind !== (sv.auth_type || 'none')
    || (kind === 'custom_header' && header.trim() !== String(sv.auth_header_name || ''));
}

/// Say before Save what an edit does to the stored credential, and keep the
/// "a secret is stored" hint true.
function mcpRebindCheck() {
  const sv = mcpEditing;
  const warn = mcpF('mcpRebindWarn');
  const hint = mcpF('mcpSecretHint');
  const secretInput = mcpF('mcpAuthSecret');
  const kind = mcpAuthKind();
  const withSecret = kind === 'bearer' || kind === 'custom_header';
  const rebound = mcpRebound();
  const keepsSecret = !!(sv && sv.has_secret) && !rebound && withSecret;
  if (hint) hint.textContent = keepsSecret ? 'A secret is stored - leave this blank to keep it.' : '';
  if (secretInput) secretInput.placeholder = keepsSecret ? 'Leave blank to keep the stored secret' : 'Enter the token';
  let text = '';
  if (sv && rebound && withSecret) {
    if (sv.has_secret) {
      text = 'Changing the URL or the auth settings discards the stored secret - enter it again below before saving.';
    } else if (sv.auth_env_var && mcpSecretKind() === 'env') {
      text = 'Changing the URL or the auth settings sends the token from environment variable '
        + sv.auth_env_var + ' to the new settings - change the variable name if that is not intended.';
    }
  } else if (mcpEnvVarStays()) {
    text = 'No secret entered: the environment variable ' + sv.auth_env_var
      + ' stays in effect. Type a secret to replace it with a stored one.';
  }
  if (warn) { warn.textContent = text; warn.hidden = !text; }
}

function mcpOpenForm(sv) {
  const host = mcpFormHost();
  if (!host) return;
  mcpEditing = sv || null;
  const set = (id, v) => { const e = mcpF(id); if (e) e.value = v == null ? '' : v; };
  set('mcpName', sv ? sv.name : '');
  set('mcpUrl', sv ? sv.url : '');
  set('mcpAuthType', sv ? (sv.auth_type || 'none') : 'none');
  set('mcpSecretSource', 'stored');
  // The stored settings round-trip (A4-07): the header NAME and the
  // environment variable NAME come back from mcp_list_servers; a sealed
  // secret never does (has_secret only says there is one).
  set('mcpHeaderName', sv && sv.auth_header_name ? sv.auth_header_name : '');
  set('mcpAuthSecret', '');
  set('mcpAuthEnvVar', '');
  // Which secret source the server actually uses: a stored env-var name means
  // "environment variable"; anything else reads back as the default "stored".
  if (sv && sv.auth_env_var) {
    set('mcpSecretSource', 'env');
    set('mcpAuthEnvVar', sv.auth_env_var);
  }
  const title = mcpF('mcpFormTitle');
  if (title) title.textContent = sv ? 'Edit MCP server' : 'Add MCP server';
  host.hidden = false;
  mcpSyncAuthRows();
  const name = mcpF('mcpName');
  if (name) name.focus();
}

function mcpCloseForm() {
  const host = mcpFormHost();
  if (host) host.hidden = true;
  mcpEditing = null;
  mcpRebindCheck();
}

/// An env-var server switched to "Stored secret" with no secret typed and no
/// URL/auth change: plan_auth keeps an absent source, so the variable stays
/// in effect - the form says so rather than refusing (A4-07).
function mcpEnvVarStays() {
  const sv = mcpEditing;
  const kind = mcpAuthKind();
  const secretInput = mcpF('mcpAuthSecret');
  return !!(sv && sv.auth_env_var && (kind === 'bearer' || kind === 'custom_header')
    && mcpSecretKind() === 'stored' && !(secretInput && secretInput.value.trim()) && !mcpRebound());
}

/// What is wrong with the auth part of the form, or '' - the same rules the
/// backend applies (plan_auth in src-tauri/src/assistant/mcp.rs; the
/// messages are its own), said before anything is sent.
function mcpAuthProblem(kind, source, header, secret, envVar) {
  if (kind === 'custom_header' && !header) return 'Custom header auth requires a header name.';
  if (kind !== 'bearer' && kind !== 'custom_header') return '';
  if (source === 'env') return envVar ? '' : 'Enter the name of the environment variable that holds the token.';
  if (secret) return '';
  const sv = mcpEditing;
  if (sv && sv.has_secret && !mcpRebound()) return '';
  if (mcpEnvVarStays()) return '';
  if (sv && mcpRebound() && (sv.has_secret || sv.auth_env_var)) {
    return 'Changing the URL or the auth settings discards the stored secret or environment variable - enter it again for the new settings.';
  }
  return (kind === 'bearer' ? 'Bearer' : 'Custom header') + ' auth needs a secret or an environment variable name.';
}

async function mcpSaveServer() {
  const btn = mcpF('mcpSaveBtn');
  // withBusy: a second click (or call) while the save runs is ignored - a
  // double click used to create two servers (A4-12).
  return withBusy(btn, 'Saving...', async () => {
    const val = (id) => { const e = mcpF(id); return e ? e.value.trim() : ''; };
    const name = val('mcpName');
    const url = val('mcpUrl');
    if (!name) { toast('Give the server a name.', 'err'); return; }
    if (!url) { toast('Give the server a URL.', 'err'); return; }
    mcpUrlCheck();
    const urlProblem = mcpUrlProblem(url);
    if (urlProblem) { toast(urlProblem, 'err'); return; }
    const kind = mcpAuthKind();
    const source = mcpSecretKind();
    const withSecret = kind === 'bearer' || kind === 'custom_header';
    const secretInput = mcpF('mcpAuthSecret');
    const secretValue = secretInput ? secretInput.value.trim() : '';
    const authProblem = mcpAuthProblem(kind, source, val('mcpHeaderName'), secretValue, val('mcpAuthEnvVar'));
    if (authProblem) { toast(authProblem, 'err'); return; }
    const keptEnv = mcpEnvVarStays() ? mcpEditing.auth_env_var : null;
    try {
      // null keeps what is stored; a value replaces it (mcp_save_server).
      const r = await mcpSendSave({
        id: mcpEditing ? mcpEditing.id : null,
        name,
        url,
        authType: kind,
        headerName: kind === 'custom_header' ? val('mcpHeaderName') : null,
        secret: withSecret && source === 'stored' && secretValue ? secretValue : null,
        envVar: withSecret && source === 'env' ? val('mcpAuthEnvVar') : null,
      });
      const { warning, notConfirmed } = mcpSaveOutcome(r);
      if (secretInput) secretInput.value = '';
      mcpCloseForm();
      await mcpLoadSettings();
      // Saved, but switched off (its credential was not allowed) or with a
      // failure after the save (its audit row): said as the backend says it,
      // without undoing the save.
      const kept = keptEnv ? 'Saved. No secret was entered, so the environment variable ' + keptEnv + ' stays in effect.' : '';
      const why = warning || (notConfirmed ? MCP_SAVED_NOT_CONFIRMED : '');
      if (why) {
        mcpSetStatus(kept ? kept + ' ' + why : why, 'warn');
        toast(why, 'warn');
      } else if (kept) {
        mcpSetStatus(kept);
        toast('MCP server saved - the environment variable ' + keptEnv + ' stays in effect.', 'ok');
      } else {
        toast('MCP server saved.', 'ok');
      }
    } catch (e) {
      // Spelled out: a refusal can quote another server's name, which a
      // backup restores unchecked.
      toast(errSpelled(e), 'err');
    }
  });
}

/// The one mcp_save_server request: the form's Save and a row's "Allow
/// sending..." both send it. The payload always names the three auth fields
/// (null keeps what is stored, a value replaces it, '' clears it -
/// scripts/check-mcp-contract.js reads this literal). A save that binds a
/// credential to a place it was not confirmed for is asked about by the
/// backend, in a native dialog the page can neither show nor answer, before
/// it answers { ok, id, warning, confirmed } (A4-07).
function mcpSendSave(s) {
  const payload = {
    id: s.id,
    name: s.name,
    url: s.url,
    auth_type: s.authType,
    auth_header_name: s.headerName,
    auth_secret: s.secret,
    auth_env_var: s.envVar,
  };
  return mcpCall('mcp_save_server', payload);
}

/// What a save's answer says beyond "saved": the backend's `warning`, and
/// whether the server stays switched off. Only `confirmed: true` is a
/// confirmation - an answer without it is not one (fail closed), so neither
/// the form's Save nor "Allow sending..." says the credential may go.
function mcpSaveOutcome(r) {
  return {
    warning: r && r.warning ? String(r.warning) : '',
    notConfirmed: !r || r.confirmed !== true,
  };
}

/// "Allow sending..." on a server that is not confirmed: its stored settings
/// are saved again unchanged - nothing typed, so its credential stays - and
/// the backend asks its native question again. The row is busy until that is
/// answered; then the backend's answer is said as it is.
async function mcpAllowSending(sv) {
  // As the notices name it (mcpNameInText); the save sends sv.name as it is.
  const name = mcpNameInText(sv.name || '');
  await mcpRowAction(sv.id, async () => {
    mcpSetStatus('Waiting for your answer: SSHSpan asks in its own dialog whether it may send the credential of "'
      + name + '".', 'info');
    let r;
    try {
      r = await mcpSendSave({ id: sv.id, name: sv.name, url: sv.url, authType: sv.auth_type, headerName: null, secret: null, envVar: null });
    } catch (e) {
      // Spelled out, as the form's refusals are (mcpSaveServer).
      const msg = errSpelled(e);
      mcpSetStatus(msg, 'err');
      toast(msg, 'err');
      return;
    }
    await mcpLoadSettings();
    const { warning, notConfirmed } = mcpSaveOutcome(r);
    if (notConfirmed || warning) {
      const why = warning || MCP_SAVED_NOT_CONFIRMED;
      mcpSetStatus(why, 'warn');
      toast(why, 'warn');
      return;
    }
    toast('MCP server "' + name + '" is confirmed - SSHSpan may send its credential now.', 'ok');
  });
}

// ─── settings: test connection + tool approval list ─────────────────────────

async function mcpTestConnection(id) {
  return mcpRowAction(id, async () => {
    try {
      const r = await mcpCall('mcp_test_connection', { id });
      mcpLastErrors.delete(id);
      const tools = (r && r.tools) || [];
      toast('MCP: ' + tools.length + ' tool' + (tools.length === 1 ? '' : 's') + ' returned.', 'ok');
      // Refresh first so the list reflects the pin state the test just set,
      // then show this server's tools (enabled defaults to off - new and
      // re-appeared definitions stay dark until the user approves them).
      await mcpLoadSettings();
      mcpShowToolsFor(id);
      const changed = Array.isArray(r && r.changed) ? r.changed : [];
      if (changed.length) {
        mcpSetStatus('These tools changed on the server and were turned off until you review them again: '
          + changed.map(mcpNameInText).join(', ') + '.', 'err');
      }
    } catch (e) {
      const msg = errText(e);
      // Shown beside the row (the list has the status, not the reason) and
      // the row is redrawn from the backend, which now says "error".
      mcpLastErrors.set(id, msg);
      toast(msg, 'err');
      try { await mcpLoadSettings(); } catch (e2) { mcpRenderList(); }
    }
  });
}

// Human labels for the MCP annotation hints. The values come from the server,
// so they are only ever rendered, never trusted for any decision.
function mcpAnnotationLabels(ann) {
  if (!ann || typeof ann !== 'object') return [];
  const out = [];
  if (ann.readOnlyHint === true) out.push('read-only');
  if (ann.destructiveHint === true) out.push('destructive');
  if (ann.idempotentHint === true) out.push('idempotent');
  if (ann.openWorldHint === true) out.push('open-world');
  return out;
}

// Tools with an approval request in flight ("<server id>\n<tool>").
const mcpToolBusy = new Set();

/// The backend's two refusals of an approval that does not match the stored
/// definition (mcp_set_tool_state compare-and-swap): a missing expected_hash
/// or one that is not the current definition any more - DEFINITION_MOVED and
/// DEFINITION_NOT_NAMED in src-tauri/src/assistant/mcp.rs (set_tool_state).
function mcpIsDefinitionRefusal(msg) {
  return /definition changed - review it and approve again|does not say which tool definition you reviewed/i.test(String(msg));
}

/// Change one tool's approval. Every enable - the Enable toggle and both
/// Auto-approve directions - names the definition this row SHOWS
/// (`expected_hash`), so the backend refuses it if the server changed the
/// tool meanwhile; the refusal reloads the list and shows the new definition
/// for a fresh review instead of retrying (no silent re-approval). After any
/// answer the list is reloaded, so pins and Auto-approve stay in step with
/// what the backend enforces (A4-08).
async function mcpSetToolState(serverId, t, enabled, autoApprove) {
  const key = serverId + '\n' + t.name;
  if (mcpToolBusy.has(key)) return;
  mcpToolBusy.add(key);
  const args = { id: serverId, tool: t.name, enabled, auto_approve: enabled && autoApprove };
  if (enabled) args.expected_hash = t.definition_hash == null ? null : String(t.definition_hash);
  let refusal = null;
  let warning = '';
  try {
    const r = await mcpCall('mcp_set_tool_state', args);
    // Done, but its audit row could not be written: said as it is.
    warning = r && r.warning ? String(r.warning) : '';
  } catch (e) {
    // Spelled out: a refusal can quote the tool ("Tool '...' not found").
    refusal = errSpelled(e);
  } finally {
    mcpToolBusy.delete(key); // before the redraw, or its toggles stay disabled
  }
  await mcpLoadSettings();
  if (warning) {
    mcpSetStatus(warning, 'warn');
    toast(warning, 'warn');
  }
  if (refusal === null) return;
  if (mcpIsDefinitionRefusal(refusal)) {
    mcpSetStatus('Tool "' + mcpNameInText(t.name) + '" was not approved: ' + refusal
      + ' Its current definition is shown below - review it, then enable it again.', 'err');
  } else {
    toast(refusal, 'err');
  }
}

// One tool row in the approval list: name (untrusted), annotations as plain
// labels, the (untrusted) description and input schema - the definition the
// user approves - and Enable / Auto-approve toggles. Toggling calls
// mcp_set_tool_state immediately; Auto-approve only exists for an enabled tool.
function mcpToolRow(serverId, t) {
  const changed = !!t.definition_changed;
  const row = document.createElement('div');
  row.className = 'mcp-tool-row' + (changed ? ' changed' : '');

  const head = document.createElement('div');
  head.className = 'mcp-tool-head';
  const name = document.createElement('code');
  name.className = 'mcp-tool-name';
  // Both names are the server's: spelled out, and each kept to itself when
  // they share the line, so this tool cannot read as another.
  if (t.display_name && t.display_name !== t.name) {
    name.append(bdiOf(spellOut(t.display_name)), ' (', bdiOf(spellOut(t.name)), ')');
  } else {
    name.textContent = spellOut(t.name);
  }
  head.appendChild(name);
  for (const label of mcpAnnotationLabels(t.annotations)) {
    const chip = document.createElement('span');
    chip.className = 'mcp-ann-chip' + (label === 'destructive' ? ' destructive' : '');
    chip.textContent = label;
    head.appendChild(chip);
  }
  row.appendChild(head);

  if (t.description) {
    const d = document.createElement('div');
    d.className = 'mcp-tool-desc';
    d.textContent = t.description;
    row.appendChild(d);
  }

  const schema = document.createElement('pre');
  schema.className = 'mcp-tool-schema';
  let schemaText = t.inputSchema;
  if (typeof schemaText === 'string') {
    try { schemaText = JSON.stringify(JSON.parse(schemaText), null, 2); } catch (e) { /* show as sent */ }
  } else {
    try { schemaText = JSON.stringify(schemaText == null ? {} : schemaText, null, 2); } catch (e) { schemaText = String(schemaText); }
  }
  schema.textContent = 'Input schema: ' + schemaText;
  row.appendChild(schema);

  if (changed) {
    // The server changed this tool after it was approved: the backend turned
    // it off and dropped its Auto-approve (R6). The text above is the NEW
    // definition; enabling approves exactly that one.
    const w = document.createElement('div');
    w.className = 'mcp-tool-changed';
    w.textContent = 'Definition changed - re-approve: review the new definition above, then turn Enable on to approve it.';
    row.appendChild(w);
  }

  const toggles = document.createElement('div');
  toggles.className = 'mcp-tool-toggles';

  const mkToggle = (id, label, checked, onFlip) => {
    const wrap = document.createElement('label');
    wrap.className = 'toggle-chip';
    wrap.htmlFor = id;
    const input = document.createElement('input');
    input.type = 'checkbox';
    input.id = id;
    input.checked = !!checked;
    input.addEventListener('change', () => onFlip(input.checked));
    wrap.appendChild(input);
    const box = document.createElement('span');
    box.className = 'toggle-box';
    wrap.appendChild(box);
    const text = document.createElement('span');
    text.textContent = label;
    wrap.appendChild(text);
    toggles.appendChild(wrap);
    return input;
  };

  const busy = mcpToolBusy.has(serverId + '\n' + t.name);
  // Enabling is a fresh approval of the definition shown: never with an
  // Auto-approve granted earlier (A4-05) - that is a second, explicit click.
  // The row is redrawn from the reloaded list when the request ends; until
  // then its toggles take no second click.
  const lock = () => { setDisabledFor(enableInput, 'busy', true); setDisabledFor(autoInput, 'busy', true); };
  const enableInput = mkToggle(
    'mcp_en_' + serverId + '_' + t.name, 'Enable', t.enabled,
    (on) => { lock(); mcpSetToolState(serverId, t, on, false); });

  const autoInput = mkToggle(
    'mcp_aa_' + serverId + '_' + t.name, 'Auto-approve', t.enabled && t.auto_approve,
    (on) => {
      if (!enableInput.checked) { toast('Enable the tool first.', 'warn'); autoInput.checked = false; return; }
      lock();
      mcpSetToolState(serverId, t, true, on);
    });
  autoInput.title = t.enabled ? 'Run this tool at Execute without a card (never at Read or Draft)' : 'Enable the tool first';
  if (changed) enableInput.title = 'Approve the changed definition shown above';
  setDisabledFor(autoInput, 'off', !t.enabled);
  if (busy) { setDisabledFor(enableInput, 'busy', true); setDisabledFor(autoInput, 'busy', true); }
  // Approvals are vault writes: not while it is locked (fail closed).
  lockGate(enableInput, 'settings');
  lockGate(autoInput, 'settings');

  row.appendChild(toggles);
  return row;
}

// Render the tool approval list for one server, or the prompt to test.
function mcpRenderToolsFor(id) {
  const host = mcpF('mcpToolsHost');
  if (!host) return;
  host.textContent = '';
  const sv = mcpServerById(id);
  if (!sv) return;
  if (!Array.isArray(sv.tools) || !sv.tools.length) {
    const p = document.createElement('p');
    p.className = 'hint';
    p.textContent = 'No tools known yet - run Test connection to list what this server offers.';
    host.appendChild(p);
    return;
  }
  const title = document.createElement('div');
  title.className = 'mcp-tools-title';
  // The server's name spelled out and kept to itself (mcpNameInText).
  title.append('Tools from "', bdiOf(spellOut(sv.name || '')), '" (' + mcpEnabledCount(sv) + '/' + sv.tools.length
    + ' enabled) - review each before enabling:');
  host.appendChild(title);
  for (const t of sv.tools) host.appendChild(mcpToolRow(sv.id, t));
}

function mcpShowToolsFor(id) { mcpToolsShownFor = id; mcpRenderToolsFor(id); }
function mcpRenderTools() { if (mcpToolsShownFor != null) mcpRenderToolsFor(mcpToolsShownFor); }

// ─── settings: load + wiring ────────────────────────────────────────────────

let mcpToolsShownFor = null;

const MCP_STATUS_DEFAULT = 'MCP tools are offered to the assistant only when enabled below, stay behind the access level, and (outside YOLO) behind per-call approval.';

// Reload the registry and redraw the list AND the shown tools from it, so no
// row keeps acting on an older snapshot (A4-15).
async function mcpLoadSettings() {
  let failed = null;
  try {
    await mcpRefresh();
  } catch (e) {
    failed = errText(e);
    toast(failed, 'err');
  }
  if (!mcpAvailable) {
    mcpSetStatus('This build of the backend has no MCP support - update SSHSpan to configure MCP servers.');
    mcpRenderList();
    return;
  }
  mcpSetStatus(failed ? 'Could not load the MCP servers: ' + failed : MCP_STATUS_DEFAULT, failed ? 'err' : '');
  mcpRenderList();
  mcpRenderTools();
}

function mcpWire() {
  const on = (id, ev, fn) => { const e = mcpF(id); if (e) e.addEventListener(ev, fn); };
  on('mcpAddBtn', 'click', () => mcpOpenForm(null));
  on('mcpCancelBtn', 'click', mcpCloseForm);
  on('mcpSaveBtn', 'click', mcpSaveServer);
  on('mcpUrl', 'input', mcpUrlCheck);
  on('mcpAuthType', 'change', mcpSyncAuthRows);
  on('mcpSecretSource', 'change', mcpSyncAuthRows);
  on('mcpHeaderName', 'input', mcpRebindCheck);
  on('mcpAuthSecret', 'input', mcpRebindCheck);
  // Adding and saving servers write the vault: not while it is locked.
  lockGate(mcpF('mcpAddBtn'), 'settings');
  lockGate(mcpF('mcpSaveBtn'), 'settings');
  // Load the server list whenever the assistant settings section becomes
  // visible - from its nav item, the palette or assistantOpenSettings alike
  // (showSettingsSection only toggles `hidden`, A4-25).
  const section = document.querySelector('.settings-section[data-section="assistant"]');
  if (section) {
    new MutationObserver(() => { if (!section.hidden) mcpLoadSettings(); })
      .observe(section, { attributes: true, attributeFilter: ['hidden'] });
  }
}

window.mcpGetTools = mcpGetTools;
window.mcpIsMcpTool = mcpIsMcpTool;
window.mcpCallTool = mcpCallTool;
window.mcpToolInfo = mcpToolInfo;
window.mcpRefresh = mcpRefresh;
window.mcpLoadSettings = mcpLoadSettings;

window.__SSHPAN_MCP_JS__ = true;

if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', mcpWire);
else mcpWire();
