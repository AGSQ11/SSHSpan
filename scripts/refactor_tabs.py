# -*- coding: utf-8 -*-
"""app.js multi-tab refactor: replace single-session connect flow with tabs."""
import io, re

P = 'src/renderer/app.js'
s = io.open(P, encoding='utf-8').read()

# ── 1. state: sessions map ──
s = s.replace(
    """  // connect / saved servers
  servers: [],
  connectSelectedId: null,
  connectAuthMethod: 'publickey',
  _pendingConnectServer: null,
  _pendingConnectKey: null,
};""",
    """  // connect / saved servers
  servers: [],
  connectSelectedId: null,
  connectAuthMethod: 'publickey',
  _pendingConnectServer: null,
  _pendingConnectKey: null,
  // multi-tab SSH sessions
  sessions: new Map(),   // tabId -> {tabId, sessionId, serverId, serverName, host, port, mode, sftpReady, sftpPath, ended}
  activeTabId: null,
};""")

# ── 2. replace connectToServer + disconnectActive + onTerminalClosed block ──
old_block_start = s.find('async function connectToServer(srv, opts = {}) {')
old_block_end = s.find('// ─── tiny escaper used by context menus')
assert old_block_start != -1 and old_block_end != -1 and old_block_end > old_block_start

new_block = '''function newTabId() {
  return 'tab-' + Date.now().toString(36) + Math.floor(Math.random() * 1e4);
}

/// Open a NEW session tab for a server (always a new tab — never replaces).
async function openSessionTab(srv, opts = {}) {
  if (typeof window.terminalConnectInTab !== 'function') {
    toast('terminal.js is missing — Connect cannot run.', 'err');
    return;
  }
  switchView('connect');
  const tabId = newTabId();
  const tab = {
    tabId,
    sessionId: null,
    serverId: srv.id,
    serverName: srv.name || srv.host,
    host: srv.host,
    port: srv.port || 22,
    mode: 'ssh',
    sftpReady: false,
    sftpPath: '/',
    ended: false,
  };
  state.sessions.set(tabId, tab);
  window.createTabTerminal(tabId);
  state.activeTabId = tabId;
  window.showTabTerminal(tabId);
  renderTermTabs();
  updateTerminalHead();
  el('termDisconnectBtn').hidden = true;
  el('termReconnectBtn').hidden = true;
  terminalSetStatus(`Connecting to ${srv.host}:${srv.port}…`);

  let pw = null;
  if (srv.authMethod !== 'publickey' && !srv.hasSavedPassword) {
    pw = await new Promise(resolve => askConnectPassword(srv, resolve));
    if (pw === null || pw === undefined) {
      terminalSetStatus('Cancelled.');
      closeSessionTab(tabId, { skipConfirm: true });
      return;
    }
  }

  try {
    const sessionId = await window.terminalConnectInTab(tabId, srv, { ...opts, promptPassword: pw });
    tab.sessionId = sessionId;
    renderTermTabs();
    updateTerminalHead();
    terminalSetStatus(`Connected to ${srv.host}:${srv.port} — streaming`);
  } catch (e) {
    tab.ended = true;
    renderTermTabs();
    updateTerminalHead();
    terminalSetStatus(`Failed: ${e.message || e}`);
    toast(e.message || String(e), 'err');
  }
}

/// Disconnect the active tab's live session (tab stays with [connection closed]).
async function disconnectActiveTab() {
  const tab = state.sessions.get(state.activeTabId);
  if (!tab || !window.tabSessionLive(tab.tabId)) return;
  try { await call('terminal_disconnect', { sessionId: tab.sessionId }); } catch (e) {}
  // The close-detection poll fires onSessionClosed, which finalizes tab state.
}

/// Reconnect the active tab: new session in the SAME tab (keeps scrollback).
async function reconnectActiveTab() {
  const tab = state.sessions.get(state.activeTabId);
  if (!tab) return;
  const srv = state.servers.find(s => s.id === tab.serverId);
  if (!srv) { toast('Server no longer exists.', 'err'); return; }
  let pw = null;
  if (srv.authMethod !== 'publickey' && !srv.hasSavedPassword) {
    pw = await new Promise(resolve => askConnectPassword(srv, resolve));
    if (pw === null || pw === undefined) return;
  }
  terminalSetStatus(`Reconnecting to ${srv.host}:${srv.port}…`);
  el('termDisconnectBtn').hidden = true;
  el('termReconnectBtn').hidden = true;
  try {
    const sessionId = await window.terminalConnectInTab(tab.tabId, srv, { promptPassword: pw });
    tab.sessionId = sessionId;
    tab.ended = false;
    renderTermTabs();
    updateTerminalHead();
    terminalSetStatus(`Connected to ${srv.host}:${srv.port} — streaming`);
  } catch (e) {
    renderTermTabs();
    updateTerminalHead();
    terminalSetStatus(`Failed: ${e.message || e}`);
    toast(e.message || String(e), 'err');
  }
}

/// Close a tab: disconnect if live, dispose terminal, forget the session.
function closeSessionTab(tabId, { skipConfirm = false } = {}) {
  const tab = state.sessions.get(tabId);
  if (!tab) return;
  const live = window.tabSessionLive(tabId);
  if (live && !skipConfirm && !confirm(`Close the session to ${tab.serverName}?`)) return;
  if (live) call('terminal_disconnect', { sessionId: tab.sessionId }).catch(() => {});
  if (tab.sftpReady) call('sftp_close', { sessionId: tab.sessionId || '' }).catch(() => {});
  window.destroyTabTerminal(tabId);
  state.sessions.delete(tabId);
  if (state.activeTabId === tabId) {
    state.activeTabId = state.sessions.keys().next().value || null;
    if (state.activeTabId) {
      const nt = state.sessions.get(state.activeTabId);
      if (nt && nt.mode === 'sftp') window.showSftpForTab(state.activeTabId);
      else window.showTabTerminal(state.activeTabId);
    } else {
      const sbody = document.getElementById('sftpBody');
      if (sbody) sbody.classList.remove('visible');
      const body = document.getElementById('terminalBody');
      if (body) body.style.display = 'flex';
    }
  }
  renderTermTabs();
  updateTerminalHead();
}

/// Activate a tab (click on its chip).
function activateSessionTab(tabId) {
  state.activeTabId = tabId;
  const tab = state.sessions.get(tabId);
  if (tab && tab.mode === 'sftp') window.showSftpForTab(tabId);
  else window.showTabTerminal(tabId);
  renderTermTabs();
  updateTerminalHead();
}

/// Tab strip: chips for each session + the persistent "+" button.
function renderTermTabs() {
  const strip = el('termTabs');
  if (!strip) return;
  strip.querySelectorAll('.term-tab').forEach(n => n.remove());
  const addBtn = el('termTabAdd');
  for (const [tabId, tab] of state.sessions) {
    const chip = document.createElement('div');
    chip.className = 'term-tab' + (tabId === state.activeTabId ? ' active' : '') + (tab.ended ? ' ended' : '');
    const dot = document.createElement('span');
    dot.className = 'term-tab-dot' + (window.tabSessionLive(tabId) ? ' live' : '');
    const name = document.createElement('span');
    name.className = 'term-tab-name';
    name.textContent = tab.serverName;
    name.title = `${tab.serverName} (${tab.host}:${tab.port})`;
    const close = document.createElement('span');
    close.className = 'term-tab-close';
    close.textContent = '×';
    close.title = 'Close session';
    close.addEventListener('click', (ev) => { ev.stopPropagation(); closeSessionTab(tabId); });
    chip.appendChild(dot);
    chip.appendChild(name);
    chip.appendChild(close);
    chip.addEventListener('click', () => activateSessionTab(tabId));
    strip.insertBefore(chip, addBtn);
  }
}

/// Head title + buttons follow the active tab, or the selected server.
function updateTerminalHead() {
  const tab = state.sessions.get(state.activeTabId);
  const srv = currentSelectedServer();
  el('termTestBtn').hidden = !srv;
  if (tab) {
    el('termTitle').textContent = tab.serverName;
    el('termBadge').textContent = `${tab.host}:${tab.port}`;
    el('termBadge').hidden = false;
    const live = window.tabSessionLive(tab.tabId);
    el('termDisconnectBtn').hidden = !live;
    el('termReconnectBtn').hidden = live;
    el('termModeBtn').hidden = !live;
    el('termModeLabel').textContent = tab.mode === 'sftp' ? 'SSH' : 'SFTP';
  } else if (srv) {
    el('termTitle').textContent = srv.name;
    el('termBadge').textContent = `${srv.host}:${srv.port}`;
    el('termBadge').hidden = false;
    el('termDisconnectBtn').hidden = true;
    el('termReconnectBtn').hidden = false;
    el('termModeBtn').hidden = true;
  } else {
    el('termTitle').textContent = 'No connection';
    el('termBadge').hidden = true;
    el('termDisconnectBtn').hidden = true;
    el('termReconnectBtn').hidden = true;
    el('termModeBtn').hidden = true;
  }
}

/// Called by terminal.js when a tab's SSH session ends (server side or drop).
function onSessionClosed(tabId) {
  const tab = state.sessions.get(tabId);
  if (!tab) return;
  tab.ended = true;
  if (tab.sftpReady) {
    call('sftp_close', { sessionId: tab.sessionId || '' }).catch(() => {});
    tab.sftpReady = false;
    if (tab.mode === 'sftp' && tabId === state.activeTabId) {
      window.showSshForTab(tabId);
      tab.mode = 'ssh';
    }
  }
  tab.sessionId = null;
  if (tabId === state.activeTabId) terminalSetStatus('Connection closed.');
  renderTermTabs();
  updateTerminalHead();
}
window.onSessionClosed = onSessionClosed;

// ─── tiny escaper used by context menus'''
s = s[:old_block_start] + new_block + s[old_block_end:]

# ── 3. clearConnectView: close all tabs ──
s = s.replace(
    """  state._pendingConnectServer = null;
  state._pendingConnectKey = null;
}""",
    """  state._pendingConnectServer = null;
  state._pendingConnectKey = null;
  // Close every session tab.
  for (const tabId of [...state.sessions.keys()]) {
    const tab = state.sessions.get(tabId);
    if (tab && window.tabSessionLive(tabId)) {
      call('terminal_disconnect', { sessionId: tab.sessionId }).catch(() => {});
    }
    if (tab && tab.sftpReady) call('sftp_close', { sessionId: tab.sessionId || '' }).catch(() => {});
    window.destroyTabTerminal(tabId);
    state.sessions.delete(tabId);
  }
  state.activeTabId = null;
  const sbody = document.getElementById('sftpBody');
  if (sbody) sbody.classList.remove('visible');
  const tbody = document.getElementById('terminalBody');
  if (tbody) tbody.style.display = 'flex';
  renderTermTabs();
}""")

# ── 4. selectServer: simplify (head handled by updateTerminalHead) ──
old_sel = s.find('function selectServer(id) {')
assert old_sel != -1
old_sel_end = s.find('function openServerContextMenu')
assert old_sel_end != -1
new_sel = '''function selectServer(id) {
  state.connectSelectedId = id;
  renderServerList();
  updateTerminalHead();
}

'''
s = s[:old_sel] + new_sel + s[old_sel_end:]

# ── 5. call sites: connectToServer -> openSessionTab ──
s = s.replace("if (srv) connectToServer(srv);", "if (srv) openSessionTab(srv);")
s = s.replace("row.addEventListener('dblclick', () => connectToServer(s));",
              "row.addEventListener('dblclick', () => openSessionTab(s));")
s = s.replace("mk('Connect', 'plug-zap', () => connectToServer(srv));",
              "mk('Connect', 'plug-zap', () => openSessionTab(srv));")
s = s.replace("""      state._pendingConnectKey = key.id;
      selectServer(s.id);
      connectToServer(s, { overrideKeyId: key.id });""",
              """      state._pendingConnectKey = key.id;
      selectServer(s.id);
      openSessionTab(s, { overrideKeyId: key.id });""")

# ── 6. toggleTermMax: fitActiveTerminal ──
s = s.replace("""  // Let the layout settle, then refit + push the new PTY size.
  setTimeout(() => {
    if (typeof fitTerminalNow === 'function') fitTerminalNow();
  }, 80);
  setTimeout(() => {
    if (typeof fitTerminalNow === 'function') fitTerminalNow();
  }, 250);""",
"""  // Let the layout settle, then refit + push the new PTY size.
  setTimeout(() => { if (typeof fitActiveTerminal === 'function') fitActiveTerminal(); }, 80);
  setTimeout(() => { if (typeof fitActiveTerminal === 'function') fitActiveTerminal(); }, 250);""")

# ── 7. wiring: buttons ──
s = s.replace("el('termDisconnectBtn').addEventListener('click', disconnectActive);",
              "el('termDisconnectBtn').addEventListener('click', disconnectActiveTab);")
s = s.replace("""  el('termReconnectBtn').addEventListener('click', () => {
    const srv = currentSelectedServer();
    if (srv) connectToServer(srv);
  });""",
"""  el('termReconnectBtn').addEventListener('click', reconnectActiveTab);
  el('termModeBtn').addEventListener('click', () => {
    if (typeof window.toggleSshSftpMode === 'function') window.toggleSshSftpMode();
  });
  el('termTabAdd').addEventListener('click', () => {
    if (document.getElementById('app').classList.contains('term-max')) toggleTermMax();
    el('serverSearch').focus();
  });""")

# ── 8. residual single-session references in clearConnectView/init ──
s = s.replace("if (typeof terminalReset === 'function') terminalReset('Vault is locked.');",
              "if (typeof window.terminalResetActive === 'function') window.terminalResetActive();")

# any leftover direct references?
io.open(P, 'w', encoding='utf-8', newline='\n').write(s)
print('app.js refactored')
leftovers = [i+1 for i, line in enumerate(s.split('\n')) if re.search(r'connectSessionId|connectServerId|disconnectActive\(\)|onTerminalClosed', line)]
print('leftover refs:', leftovers)
