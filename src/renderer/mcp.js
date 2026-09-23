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
 *      and a per-tool approval list (Enable / Auto-approve toggles).
 *
 * SECURITY: names, URLs, descriptions and annotations come from MCP servers -
 * fully untrusted. Every one of them is rendered with textContent /
 * createElement, never innerHTML. Annotations may be SHOWN in the approval
 * card but never bypass it; only the user-set auto_approve flag does that.
 *
 * Loaded by app.js right after assistant.js; bridges through window.*.
 */

'use strict';

// Hard cap on the merged (built-in + MCP) tool list lives in assistant.js
// (AI_MAX_TOOLS_TOTAL); the merge there takes the built-ins unfiltered and
// gives mcpGetTools() only the leftover slots, so MCP never displaces them.
const MCP_DESC_LIMIT = 1024;

// Sanitize a server/tool name for the model-facing tool name. Only
// [A-Za-z0-9_] survives, and runs of underscores collapse to one - so the
// model-facing name can never itself contain "__", and the
// mcp__<server>__<tool> split is structurally unambiguous: a name the model
// saw always maps back to exactly the {server, tool} pair it was built from.
function mcpSanitizeName(s) {
  return String(s == null ? '' : s).replace(/[^A-Za-z0-9_]+/g, '_').replace(/_+/g, '_');
}

// ─── registry ───────────────────────────────────────────────────────────────

// What mcp_list_servers last returned (array of server objects straight from
// the backend - treat every field in it as untrusted data).
let mcpServers = [];
let mcpAvailable = true; // false once the backend command is found missing

const mcpCall = (cmd, args) => (window.call || call)(cmd, args);

// Pull the registry from the backend. Missing command (old backend) degrades
// to a one-time notice; other errors surface but keep the previous snapshot.
async function mcpRefresh() {
  if (!mcpAvailable) return null;
  try {
    const list = await mcpCall('mcp_list_servers');
    mcpServers = Array.isArray(list) ? list : [];
    return mcpServers;
  } catch (e) {
    const msg = (e && (e.message || e.error)) || String(e);
    if (/not a valid|unknown|no such|not found|missing/i.test(msg)) {
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

// Model-facing tool specs for every enabled+pinned MCP tool, in a stable
// order (registry order, tool order within a server). Same shape as
// assistant.js's AI_TOOL_SPECS entries so the backend forwards them
// unchanged. Description is truncated hard: descriptions are untrusted
// server text and would otherwise ride into the model's tool list.
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
      if (!t || !t.enabled || !t.pinned) continue;
      const name = 'mcp__' + mcpSanitizeName(sv.name) + '__' + mcpSanitizeName(t.name);
      // Refuse built-in collisions and sanitized-name duplicates (two servers
      // with names that sanitize identically): the first one wins, the model
      // never sees an ambiguous tool name.
      if (builtins.indexOf(name) !== -1 || seen[name]) continue;
      seen[name] = true;
      const rawDesc = t.display_name && t.display_name !== t.name
        ? t.display_name + ' (MCP server "' + sv.name + '", tool "' + t.name + '")'
        : 'MCP server "' + sv.name + '", tool "' + t.name + '"';
      const desc = rawDesc.length > MCP_DESC_LIMIT
        ? rawDesc.slice(0, MCP_DESC_LIMIT) : rawDesc;
      out.push({ name, description: desc, parameters_json: t.parameters_json || '{}' });
    }
  }
  return out;
}

function mcpIsMcpTool(name) {
  return typeof name === 'string' && name.startsWith('mcp__');
}

// Reverse the sanitized model-facing name back to {serverId, toolName}. Every
// registered tool's sanitized name is computed and compared in full - a name
// the model merely MADE UP starting with "mcp__" maps to nothing and is
// rejected, so it cannot select a server or tool it was never shown.
function mcpResolveTool(name) {
  for (const sv of mcpServers) {
    if (!sv || !Array.isArray(sv.tools)) continue;
    for (const t of sv.tools) {
      if (!t || !t.enabled || !t.pinned) continue;
      if (name === 'mcp__' + mcpSanitizeName(sv.name) + '__' + mcpSanitizeName(t.name)) {
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

// Invoke an MCP tool on the backend. approved: true means the user approved
// the card (or the level is yolo / the tool is auto_approve) - the backend
// still re-checks the level server-side and owns the audit log.
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
  if (res && res.is_error) throw new Error(String(res.content == null ? 'MCP tool error' : res.content));
  return res ? String(res.content == null ? '' : res.content) : '';
}

// ─── settings: server list ──────────────────────────────────────────────────

function mcpListHost() { return document.getElementById('mcpServerList'); }
function mcpFormHost() { return document.getElementById('mcpFormHost'); }

function mcpStatusDot(status) {
  const dot = document.createElement('span');
  dot.className = 'server-dot mcp-dot ' + (status === 'connected' ? 'live' : status === 'error' ? 'err' : '');
  dot.title = status || 'unknown';
  return dot;
}

// One row per server: status dot, name, url, tool count, and the actions
// (edit, test, remove). Every string from the server goes through textContent.
function mcpServerRow(sv) {
  const row = document.createElement('div');
  row.className = 'mcp-server-row';
  row.dataset.id = String(sv.id == null ? '' : sv.id);

  const head = document.createElement('div');
  head.className = 'mcp-server-head';
  head.appendChild(mcpStatusDot(sv.status));
  const name = document.createElement('span');
  name.className = 'mcp-server-name';
  name.textContent = sv.name || '(unnamed)';
  head.appendChild(name);
  const url = document.createElement('span');
  url.className = 'mcp-server-url mono';
  url.textContent = sv.url || '';
  head.appendChild(url);
  const count = document.createElement('span');
  count.className = 'mcp-server-count';
  count.textContent = (sv.tool_count != null ? sv.tool_count : (sv.tools ? sv.tools.length : 0)) + ' tools';
  head.appendChild(count);
  row.appendChild(head);

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
  mkBtn('Edit', 'ghost-btn', () => mcpOpenForm(sv));
  mkBtn('Test connection', 'ghost-btn', () => mcpTestConnection(sv.id));
  mkBtn('Remove', 'danger-btn', async () => {
    b: {
      if (!window.confirm('Remove MCP server "' + (sv.name || '') + '"?')) break b;
      try {
        await mcpCall('mcp_remove_server', { id: sv.id });
        await mcpLoadSettings();
        mcpRenderTools();
        toast('MCP server removed.', 'ok');
      } catch (e) {
        toast((e && (e.message || e.error)) || String(e), 'err');
      }
    }
  });
  row.appendChild(actions);
  return row;
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

// bearer / custom-header show a value-source picker: a sealed stored secret
// (password field, blank keeps the stored one) or the NAME of an environment
// variable the backend should read.
function mcpSyncAuthRows() {
  const kind = mcpAuthKind();
  const secret = mcpSecretKind();
  const withSecret = kind === 'bearer' || kind === 'custom';
  mcpShowIf('mcpSecretSourceRow', withSecret);
  mcpShowIf('mcpHeaderRow', kind === 'custom');
  mcpShowIf('mcpSecretRow', withSecret && secret === 'stored');
  mcpShowIf('mcpEnvRow', withSecret && secret === 'env');
  const env = mcpF('mcpAuthEnvVar');
  if (env) env.placeholder = kind === 'custom' ? 'e.g. MY_SERVICE_TOKEN' : 'e.g. GITHUB_MCP_TOKEN';
  mcpUrlCheck();
}

// Plain-http loopback gets a visible warning; plain-http anywhere else is
// refused in the UI before it ever reaches the backend (which also enforces).
function mcpIsLoopbackUrl(u) {
  let p;
  try { p = new URL(u); } catch (e) { return false; }
  const h = (p.hostname || '').toLowerCase();
  return p.protocol === 'http:'
    && (h === 'localhost' || h === '127.0.0.1' || h === '::1' || h === '[::1]' || h.endsWith('.localhost'));
}

function mcpUrlCheck() {
  const input = mcpF('mcpUrl');
  const warn = mcpF('mcpUrlWarn');
  const err = mcpF('mcpUrlError');
  const save = mcpF('mcpSaveBtn');
  if (warn) warn.hidden = true;
  if (err) { err.hidden = true; err.textContent = ''; }
  if (save) save.disabled = false;
  if (!input || !input.value.trim()) return;
  let p;
  try { p = new URL(input.value.trim()); } catch (e) {
    if (err) { err.textContent = 'Not a valid URL.'; err.hidden = false; }
    if (save) save.disabled = true;
    return;
  }
  if (p.protocol !== 'http:' && p.protocol !== 'https:') {
    if (err) { err.textContent = 'Only http:// and https:// URLs are supported.'; err.hidden = false; }
    if (save) save.disabled = true;
    return;
  }
  if (p.protocol === 'http:' && !mcpIsLoopbackUrl(input.value.trim())) {
    if (err) {
      err.textContent = 'Plain http:// is only allowed on loopback addresses (localhost / 127.0.0.1 / ::1) - use https:// for anything else.';
      err.hidden = false;
    }
    if (save) save.disabled = true;
  } else if (p.protocol === 'http:') {
    if (warn) warn.hidden = false;
  }
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
  set('mcpHeaderName', '');
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
  const hint = mcpF('mcpSecretHint');
  if (hint) hint.textContent = sv ? 'Stored secret: leave blank to keep the current one.' : '';
  host.hidden = false;
  mcpSyncAuthRows();
  const name = mcpF('mcpName');
  if (name) name.focus();
}

function mcpCloseForm() {
  const host = mcpFormHost();
  if (host) host.hidden = true;
  mcpEditing = null;
}

async function mcpSaveServer() {
  const val = (id) => { const e = mcpF(id); return e ? e.value.trim() : ''; };
  const name = val('mcpName');
  const url = val('mcpUrl');
  if (!name) { toast('Give the server a name.', 'err'); return; }
  if (!url) { toast('Give the server a URL.', 'err'); return; }
  mcpUrlCheck();
  const errEl = mcpF('mcpUrlError');
  if (errEl && !errEl.hidden) { toast(errEl.textContent, 'err'); return; }
  const kind = mcpAuthKind();
  const secret = mcpSecretKind();
  const payload = {
    id: mcpEditing ? mcpEditing.id : null,
    name,
    url,
    auth_type: kind,
    auth_header_name: kind === 'custom' ? (val('mcpHeaderName') || null) : null,
    auth_secret: (kind === 'bearer' || kind === 'custom') && secret === 'stored'
      ? (val('mcpAuthSecret') || null) : null,
    auth_env_var: (kind === 'bearer' || kind === 'custom') && secret === 'env'
      ? (val('mcpAuthEnvVar') || null) : null,
  };
  try {
    await mcpCall('mcp_save_server', payload);
    mcpCloseForm();
    await mcpLoadSettings();
    mcpRenderTools();
    toast('MCP server saved.', 'ok');
  } catch (e) {
    toast((e && (e.message || e.error)) || String(e), 'err');
  }
}

// ─── settings: test connection + tool approval list ─────────────────────────

async function mcpTestConnection(id) {
  try {
    const r = await mcpCall('mcp_test_connection', { id });
    const tools = (r && r.tools) || [];
    toast('MCP: ' + tools.length + ' tool' + (tools.length === 1 ? '' : 's') + ' returned.', 'ok');
    // Refresh first so the list reflects the pin state the test just set,
    // then show this server's tools (enabled defaults to off - new and
    // re-appeared definitions stay dark until the user approves them).
    await mcpLoadSettings();
    mcpShowToolsFor(id);
  } catch (e) {
    toast((e && (e.message || e.error)) || String(e), 'err');
  }
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

// One tool row in the approval list: name (untrusted), annotations as plain
// labels, the (untrusted) description, and Enable / Auto-approve toggles.
// Toggling Enable calls mcp_set_tool_state immediately; Auto-approve only
// persists when the tool is enabled.
function mcpToolRow(serverId, t) {
  const row = document.createElement('div');
  row.className = 'mcp-tool-row' + (t.enabled && !t.pinned ? ' changed' : '');
  const needsReapprove = t.enabled && !t.pinned;

  const head = document.createElement('div');
  head.className = 'mcp-tool-head';
  const name = document.createElement('code');
  name.className = 'mcp-tool-name';
  name.textContent = t.display_name || t.name;
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

  if (needsReapprove) {
    const w = document.createElement('div');
    w.className = 'mcp-tool-changed';
    w.textContent = 'Definition changed - re-approve (toggle Enable off and on) to use this tool again.';
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

  const setToolState = async (enabled, autoApprove) => {
    try {
      await mcpCall('mcp_set_tool_state', { id: serverId, tool: t.name, enabled, auto_approve: autoApprove });
      t.enabled = enabled;
      t.auto_approve = enabled ? autoApprove : false;
    } catch (e) {
      toast((e && (e.message || e.error)) || String(e), 'err');
      await mcpLoadSettings();
      mcpRenderTools();
    }
  };

  const enableInput = mkToggle(
    'mcp_en_' + serverId + '_' + t.name, 'Enable', t.enabled && !needsReapprove,
    (on) => setToolState(on, on ? t.auto_approve : false));

  const autoInput = mkToggle(
    'mcp_aa_' + serverId + '_' + t.name, 'Auto-approve', t.auto_approve && t.enabled && !needsReapprove,
    (on) => {
      if (!enableInput.checked) { toast('Enable the tool first.', 'warn'); autoInput.checked = false; return; }
      setToolState(true, on);
    });
  autoInput.disabled = !t.enabled || needsReapprove;
  if (needsReapprove) enableInput.title = 'Definition changed - turn off and on again to re-approve';

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
  title.textContent = 'Tools from "' + (sv.name || '') + '" - review each before enabling:';
  host.appendChild(title);
  for (const t of sv.tools) host.appendChild(mcpToolRow(sv.id, t));
}

function mcpShowToolsFor(id) { mcpToolsShownFor = id; mcpRenderToolsFor(id); }
function mcpRenderTools() { if (mcpToolsShownFor != null) mcpRenderToolsFor(mcpToolsShownFor); }

// ─── settings: load + wiring ────────────────────────────────────────────────

let mcpToolsShownFor = null;

async function mcpLoadSettings() {
  try {
    await mcpRefresh();
  } catch (e) {
    toast((e && (e.message || e.error)) || String(e), 'err');
  }
  if (!mcpAvailable) {
    const strip = mcpF('mcpStatus');
    if (strip) {
      strip.className = 'status-strip';
      strip.textContent = 'This build of the backend has no MCP support - update SSHSpan to configure MCP servers.';
    }
    mcpRenderList();
    return;
  }
  const strip = mcpF('mcpStatus');
  if (strip) {
    strip.className = 'status-strip';
    strip.textContent = 'MCP tools are offered to the assistant only when enabled below, stay behind the access level, and (outside YOLO) behind per-call approval.';
  }
  mcpRenderList();
}

function mcpWire() {
  const on = (id, ev, fn) => { const e = mcpF(id); if (e) e.addEventListener(ev, fn); };
  on('mcpAddBtn', 'click', () => mcpOpenForm(null));
  on('mcpCancelBtn', 'click', mcpCloseForm);
  on('mcpSaveBtn', 'click', mcpSaveServer);
  on('mcpUrl', 'input', mcpUrlCheck);
  on('mcpAuthType', 'change', mcpSyncAuthRows);
  on('mcpSecretSource', 'change', mcpSyncAuthRows);
  // Load the server list when the assistant settings section is opened -
  // a second listener on the same nav buttons aiLoadConfig already uses.
  for (const b of document.querySelectorAll('.settings-nav-item[data-section="assistant"]')) {
    b.addEventListener('click', () => mcpLoadSettings());
  }
}

window.mcpGetTools = mcpGetTools;
window.mcpIsMcpTool = mcpIsMcpTool;
window.mcpCallTool = mcpCallTool;
window.mcpToolInfo = mcpToolInfo;
window.mcpRefresh = mcpRefresh;

window.__SSHPAN_MCP_JS__ = true;

if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', mcpWire);
else mcpWire();
