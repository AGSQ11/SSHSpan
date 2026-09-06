/**
 * sftp.js — SFTP file-browser panel for Connect tabs.
 * ---------------------------------------------------------------------------
 * Per-tab panel: remote listing with breadcrumb, drag-and-drop upload from
 * the OS file manager (Tauri onDragDropEvent — real file paths), download,
 * open-with-system-editor (temp download + watch + auto re-upload), rename,
 * delete, and "Send to" another connected SFTP tab (download → temp → upload,
 * never a direct server-to-server pipe).
 *
 * Loaded dynamically by app.js after terminal.js.
 */

'use strict';

const sftpCore = window.__TAURI__.core;
const sftpWindow = window.__TAURI__.window;

async function sftpCall(cmd, args) {
  return await sftpCore.invoke(cmd, args);
}

/// Switch the active tab between SSH (terminal) and SFTP (file panel).
async function toggleSshSftpMode() {
  const tab = state.sessions.get(state.activeTabId);
  if (!tab) return;
  if (!window.tabSessionLive(tab.tabId)) {
    toast('Connect first — SFTP runs over the live session.', 'err');
    return;
  }
  if (tab.mode === 'sftp') {
    tab.mode = 'ssh';
    showSshForTab(tab.tabId);
  } else {
    try {
      if (!tab.sftpReady) {
        const r = await sftpCall('sftp_open', { sessionId: tab.sessionId });
        tab.sftpReady = true;
        tab.sftpPath = r.cwd || '/';
      }
      tab.mode = 'sftp';
      showSftpForTab(tab.tabId);
      await refreshSftpPanel(tab.tabId);
    } catch (e) {
      toast(e.message || String(e), 'err');
    }
  }
  updateTerminalHead();
}

/// Pane visibility for a tab: SFTP panel vs terminal body.
function showSftpForTab(tabId) {
  const body = document.getElementById('terminalBody');
  const sbody = document.getElementById('sftpBody');
  if (body) body.style.display = 'none';
  if (sbody) {
    sbody.classList.add('visible');
    for (const child of sbody.children) child.style.display = 'none';
    let panel = document.getElementById('sftpPanel-' + tabId);
    if (!panel) {
      panel = buildSftpPanel(tabId);
      sbody.appendChild(panel);
    }
    panel.style.display = 'block';
  }
  const label = document.getElementById('termModeLabel');
  if (label) label.textContent = 'SSH';
  const rec = window.tabRecord ? window.tabRecord(tabId) : null;
  if (rec && rec.hostEl) rec.hostEl.style.display = 'none';
}

function showSshForTab(tabId) {
  const sbody = document.getElementById('sftpBody');
  if (sbody) sbody.classList.remove('visible');
  const body = document.getElementById('terminalBody');
  if (body) body.style.display = 'flex';
  window.showTabTerminal(tabId);
  const label = document.getElementById('termModeLabel');
  if (label) label.textContent = 'SFTP';
}

function buildSftpPanel(tabId) {
  const panel = document.createElement('div');
  panel.className = 'sftp-panel';
  panel.id = 'sftpPanel-' + tabId;
  panel.style.display = 'none';

  const toolbar = document.createElement('div');
  toolbar.className = 'sftp-toolbar';
  const upBtn = document.createElement('button');
  upBtn.className = 'ghost-btn';
  upBtn.title = 'Parent directory';
  upBtn.innerHTML = `${ico('arrow-up')}<span>Up</span>`;
  upBtn.addEventListener('click', () => sftpNavigateUp(tabId));
  const refreshBtn = document.createElement('button');
  refreshBtn.className = 'ghost-btn';
  refreshBtn.title = 'Refresh';
  refreshBtn.innerHTML = `${ico('refresh-cw')}<span>Refresh</span>`;
  refreshBtn.addEventListener('click', () => refreshSftpPanel(tabId));
  const mkdirBtn = document.createElement('button');
  mkdirBtn.className = 'ghost-btn';
  mkdirBtn.title = 'New folder';
  mkdirBtn.innerHTML = `${ico('folder-plus')}<span>New folder</span>`;
  mkdirBtn.addEventListener('click', () => sftpMkdirPrompt(tabId));
  const pathBox = document.createElement('input');
  pathBox.className = 'sftp-path';
  pathBox.readOnly = true;
  toolbar.appendChild(upBtn);
  toolbar.appendChild(refreshBtn);
  toolbar.appendChild(mkdirBtn);
  toolbar.appendChild(pathBox);

  const table = document.createElement('table');
  table.className = 'sftp-table';
  const tbody = document.createElement('tbody');
  tbody.id = 'sftpTbody-' + tabId;
  table.appendChild(tbody);

  const hint = document.createElement('div');
  hint.className = 'sftp-drop-hint';
  hint.textContent = '⬇ Drag files here from your file manager to upload';

  panel.appendChild(toolbar);
  panel.appendChild(table);
  panel.appendChild(hint);

  wireSftpDrop(panel, tabId, hint);
  return panel;
}

function sftpTab(tabId) { return state.sessions.get(tabId) || null; }

function sftpJoin(dir, name) {
  return dir.endsWith('/') ? dir + name : dir + '/' + name;
}

function sftpParent(dir) {
  if (dir === '/' || !dir) return '/';
  const trimmed = dir.endsWith('/') ? dir.slice(0, -1) : dir;
  const idx = trimmed.lastIndexOf('/');
  return idx <= 0 ? '/' : trimmed.slice(0, idx);
}

async function refreshSftpPanel(tabId) {
  const tab = sftpTab(tabId);
  if (!tab) return;
  const tbody = document.getElementById('sftpTbody-' + tabId);
  const pathBox = document.querySelector('#sftpPanel-' + tabId + ' .sftp-path');
  if (!tbody) return;
  tbody.innerHTML = '';
  try {
    const r = await sftpCall('sftp_list_dir', { sessionId: tab.sessionId, path: tab.sftpPath });
    tab.sftpPath = r.path || tab.sftpPath;
    if (pathBox) pathBox.value = tab.sftpPath;
    for (const entry of r.entries || []) {
      const tr = document.createElement('tr');
      tr.dataset.isdir = entry.isDir ? '1' : '0';
      const tdName = document.createElement('td');
      tdName.textContent = (entry.isDir ? '📁 ' : '📄 ') + entry.name;
      const tdSize = document.createElement('td');
      tdSize.textContent = entry.isDir ? '—' : formatSftpSize(entry.size);
      const tdMod = document.createElement('td');
      tdMod.textContent = entry.modifiedMs ? fmtTime(new Date(entry.modifiedMs).toISOString()) : '—';
      tr.appendChild(tdName); tr.appendChild(tdSize); tr.appendChild(tdMod);

      tr.className = entry.isDir ? 'sftp-entry sftp-dir' : 'sftp-entry sftp-file';
      tr.tabIndex = 0;
      tr.setAttribute('role', 'button');
      tr.title = entry.isDir ? 'Double-click to open folder' : 'Double-click to download file';
      tr.addEventListener('click', () => {
        for (const row of tbody.querySelectorAll('.sftp-entry.selected')) row.classList.remove('selected');
        tr.classList.add('selected');
      });
      tr.addEventListener('dblclick', () => {
        if (entry.isDir) {
          tab.sftpPath = sftpJoin(tab.sftpPath, entry.name);
          refreshSftpPanel(tabId);
        } else {
          sftpDownloadTo(tabId, sftpJoin(tab.sftpPath, entry.name), entry.name);
        }
      });
      tr.addEventListener('keydown', (ev) => {
        if (ev.key === 'Enter') tr.dispatchEvent(new MouseEvent('dblclick'));
        else if (ev.key === 'ContextMenu' || (ev.shiftKey && ev.key === 'F10')) {
          ev.preventDefault();
          const rect = tr.getBoundingClientRect();
          openSftpFileMenu(rect.left + 12, rect.top + 12, tabId, entry);
        }
      });
      tr.addEventListener('contextmenu', (ev) => {
        ev.preventDefault();
        openSftpFileMenu(ev.clientX, ev.clientY, tabId, entry);
      });
      tbody.appendChild(tr);
    }
  } catch (e) {
    toast(e.message || String(e), 'err');
  }
}

function formatSftpSize(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  if (bytes < 1024 * 1024 * 1024) return (bytes / 1024 / 1024).toFixed(1) + ' MB';
  return (bytes / 1024 / 1024 / 1024).toFixed(2) + ' GB';
}

function sftpNavigateUp(tabId) {
  const tab = sftpTab(tabId);
  if (!tab) return;
  tab.sftpPath = sftpParent(tab.sftpPath);
  refreshSftpPanel(tabId);
}

async function sftpMkdirPrompt(tabId) {
  const tab = sftpTab(tabId);
  if (!tab) return;
  promptModal('New folder', `Create a folder in ${tab.sftpPath}:`, 'new-folder', async (name) => {
    if (!name) return;
    try {
      await sftpCall('sftp_mkdir', { sessionId: tab.sessionId, path: sftpJoin(tab.sftpPath, name) });
      await refreshSftpPanel(tabId);
    } catch (e) { toast(e.message || String(e), 'err'); }
  });
}

/// Right-click menu for a remote file/dir.
function openSftpFileMenu(x, y, tabId, entry) {
  closeKeyConnectMenu();
  const tab = sftpTab(tabId);
  if (!tab) return;
  const fullPath = sftpJoin(tab.sftpPath, entry.name);
  const menu = document.createElement('div');
  menu.className = 'ctx-menu';
  menu.id = 'keyConnectMenu';
  const mk = (label, icon, fn) => {
    const b = document.createElement('button');
    b.className = 'ctx-item';
    b.innerHTML = `${ico(icon)}<span>${escapeHtml(label)}</span>`;
    b.addEventListener('click', () => { closeKeyConnectMenu(); fn(); });
    menu.appendChild(b);
    return b;
  };

  mk('Download…', 'download', () => sftpDownloadTo(tabId, fullPath, entry.name));
  if (!entry.isDir) {
    mk('Open with system app', 'pencil', () => sftpOpenForEdit(tabId, fullPath, entry.name));
    mk('Rename…', 'pencil', async () => {
      promptModal('Rename', 'New name:', entry.name, async (newName) => {
        if (!newName || newName === entry.name) return;
        try {
          await sftpCall('sftp_rename', { sessionId: tab.sessionId, from: fullPath, to: sftpJoin(tab.sftpPath, newName) });
          await refreshSftpPanel(tabId);
        } catch (e) { toast(e.message || String(e), 'err'); }
      });
    });
  }
  mk('Delete', 'trash-2', async () => {
    if (!confirm(`Delete "${fullPath}"?`)) return;
    try {
      await sftpCall('sftp_remove', { sessionId: tab.sessionId, path: fullPath, isDir: entry.isDir });
      await refreshSftpPanel(tabId);
    } catch (e) { toast(e.message || String(e), 'err'); }
  });

  // Send to → other connected SFTP tabs (download → temp → upload).
  const others = [...state.sessions.values()].filter(t =>
    t.tabId !== tabId && window.tabSessionLive(t.tabId) && t.sftpReady);
  if (others.length > 0 && !entry.isDir) {
    const sep = document.createElement('div');
    sep.className = 'ctx-sep';
    menu.appendChild(sep);
    const sendLabel = document.createElement('div');
    sendLabel.className = 'ctx-item';
    sendLabel.style.cursor = 'default';
    sendLabel.style.opacity = '0.6';
    sendLabel.innerHTML = `${ico('send')}<span>Send to…</span>`;
    menu.appendChild(sendLabel);
    for (const other of others) {
      const b = document.createElement('button');
      b.className = 'ctx-item';
      b.style.paddingLeft = '26px';
      b.innerHTML = `${ico('server')}<span>${escapeHtml(other.serverName)}</span>`;
      b.addEventListener('click', async () => {
        closeKeyConnectMenu();
        await sftpSendTo(tabId, fullPath, other);
      });
      menu.appendChild(b);
    }
  }

  menu.style.left = x + 'px';
  menu.style.top = y + 'px';
  document.body.appendChild(menu);
  const onAway = (ev) => {
    if (ev.target.closest && ev.target.closest('#keyConnectMenu')) return;
    closeKeyConnectMenu();
  };
  setTimeout(() => document.addEventListener('mousedown', onAway, { once: true }), 0);
}

async function sftpDownloadTo(tabId, fullPath, name) {
  const tab = sftpTab(tabId);
  if (!tab) return;
  try {
    const pick = await call('system_pick_save_path', { title: 'Save remote file', defaultName: name });
    if (pick.canceled) return;
    await sftpCall('sftp_download', { sessionId: tab.sessionId, remote: fullPath, local: pick.path });
    toast('Downloaded to ' + pick.path, 'ok');
  } catch (e) { toast(e.message || String(e), 'err'); }
}

/// Download to a temp file, open with the OS default app, and keep watching:
/// every local save is re-uploaded to the server automatically.
async function sftpOpenForEdit(tabId, fullPath, name) {
  const tab = sftpTab(tabId);
  if (!tab) return;
  try {
    const r = await sftpCall('sftp_open_for_edit', { sessionId: tab.sessionId, remote: fullPath });
    await call('system_open_external', { url: r.localPath });
    toast(`Editing ${name} — saves upload automatically.`, 'info');
  } catch (e) { toast(e.message || String(e), 'err'); }
}

/// OS-mediated transfer: download from the source tab to a temp file, then
/// upload that file to the target tab's current directory.
async function sftpSendTo(fromTabId, fullPath, targetTab) {
  try {
    const name = fullPath.split('/').filter(Boolean).pop() || 'file';
    terminalSetStatus(`Sending ${name} to ${targetTab.serverName}…`);
    const tmp = window.__TAURI__.path
      ? '' : ''; // placeholder; temp dir resolved Rust-side below
    const r = await sftpCall('sftp_download', {
      sessionId: state.sessions.get(fromTabId)?.sessionId,
      remote: fullPath,
      local: await sftpTempPath(name),
    });
    await sftpCall('sftp_upload', {
      sessionId: targetTab.sessionId,
      local: r.local,
      remote: sftpJoin(targetTab.sftpPath || '/', name),
    });
    terminalSetStatus(`Sent ${name} to ${targetTab.serverName}.`);
    toast(`Sent ${name} to ${targetTab.serverName}.`, 'ok');
  } catch (e) { toast(e.message || String(e), 'err'); }
}

// The Rust edit-temp dir doubles as the transfer staging area.
async function sftpTempPath(name) {
  const r = await call('sftp_stage_path', { name });
  return r.path;
}

/// Native drag-and-drop upload: Tauri onDragDropEvent gives real file paths.
let sftpDropWired = false;
function wireSftpDrop(panel, tabId, hint) {
  if (sftpDropWired) return;
  sftpDropWired = true;
  const win = sftpWindow && sftpWindow.getCurrentWindow ? sftpWindow.getCurrentWindow() : null;
  if (!win || !win.onDragDropEvent) return;
  win.onDragDropEvent(async (event) => {
    const tab = state.sessions.get(state.activeTabId);
    if (!tab || tab.mode !== 'sftp') return;
    if (event.payload.type === 'enter' || event.payload.type === 'over') {
      hint.classList.add('dragover');
    } else if (event.payload.type === 'leave') {
      hint.classList.remove('dragover');
    } else if (event.payload.type === 'drop') {
      hint.classList.remove('dragover');
      const paths = event.payload.paths || [];
      let done = 0;
      for (const p of paths) {
        const name = p.split(/[\\/]/).filter(Boolean).pop() || ('file-' + done);
        try {
          await sftpCall('sftp_upload', {
            sessionId: tab.sessionId,
            local: p,
            remote: sftpJoin(tab.sftpPath, name),
          });
          done += 1;
        } catch (e) { toast(e.message || String(e), 'err'); }
      }
      if (done) {
        toast(`Uploaded ${done} file(s).`, 'ok');
        await refreshSftpPanel(tab.tabId);
      }
    }
  });
}

window.toggleSshSftpMode = toggleSshSftpMode;
window.refreshSftpPanel = refreshSftpPanel;
window.showSshForTab = showSshForTab;
window.showSftpForTab = showSftpForTab;