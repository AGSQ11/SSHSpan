/**
 * sftp.js — SFTP file-browser panel for Connect tabs (FileZilla-parity pass).
 * ---------------------------------------------------------------------------
 * Per-tab panel: remote listing with sortable columns, multi-select,
 * hidden-file toggle, per-server bookmarks, recursive search, chmod dialog,
 * statvfs free-space display, activity log, dual-pane local view, and a
 * global background transfer queue with progress.
 *
 * Loaded dynamically by app.js after terminal.js.
 */

'use strict';

const sftpCore = window.__TAURI__.core;
const sftpWindow = window.__TAURI__.window;
const sftpListen = window.__TAURI__.event.listen;

async function sftpCall(cmd, args) {
  return await sftpCore.invoke(cmd, args);
}

// ─── per-tab state helpers ──────────────────────────────────────────────────

function sftpTab(tabId) {
  return state.sessions.get(tabId) || null;
}

function sftpJoin(dir, name) {
  return dir.endsWith('/') ? dir + name : dir + '/' + name;
}

function sftpParent(dir) {
  if (dir === '/' || !dir) return '/';
  const trimmed = dir.endsWith('/') ? dir.slice(0, -1) : dir;
  const idx = trimmed.lastIndexOf('/');
  return idx <= 0 ? '/' : trimmed.slice(0, idx);
}

/// Ensure the tab record has all the SFTP fields this module uses.
function sftpTabState(tab) {
  if (!tab.sftpSelected) tab.sftpSelected = new Set();
  if (!tab.sortKey) tab.sortKey = 'name';
  if (tab.sortDesc === undefined) tab.sortDesc = false;
  if (!tab.log) tab.log = [];
  if (!tab.showHidden) tab.showHidden = state.settings?.sftpShowHidden === '1';
  if (tab.dualPane === undefined) tab.dualPane = state.sftpDualPane === true;
  if (!tab.localPath) tab.localPath = '';
  if (tab.sftpPreserveTs === undefined) tab.sftpPreserveTs = state.settings?.sftpPreserveTs === '1';
  return tab;
}

function sftpLog(tabId, line) {
  const tab = sftpTab(tabId);
  if (!tab) return;
  sftpTabState(tab);
  const ts = new Date().toTimeString().slice(0, 8);
  tab.log.push(`[${ts}] ${line}`);
  if (tab.log.length > 200) tab.log.splice(0, tab.log.length - 200);
  const logEl = document.getElementById('sftpLog-' + tabId);
  if (logEl) {
    logEl.textContent = tab.log.join('\n');
    logEl.scrollTop = logEl.scrollHeight;
  }
}

// ─── mode switching ─────────────────────────────────────────────────────────

async function toggleSshSftpMode() {
  const tab = sftpTab(state.activeTabId);
  if (!tab) return;
  if (!window.tabSessionLive(tab.tabId)) {
    toast('Connect first — SFTP runs over the live session.', 'err');
    return;
  }
  if (tab.mode === 'sftp') {
    tab.mode = 'ssh';
    if (state.activeTabId === tab.tabId) {
      if (typeof window.activateSessionSurface === 'function') window.activateSessionSurface(tab.tabId);
      else showSshForTab(tab.tabId);
    }
  } else {
    try {
      if (!tab.sftpReady) {
        const r = await sftpCall('sftp_open', { sessionId: tab.sessionId });
        tab.sftpReady = true;
        tab.sftpPath = r.cwd || '/';
        sftpLog(tab.tabId, `SFTP opened at ${tab.sftpPath}`);
        sftpCall('sftp_keepalive_start', { sessionId: tab.sessionId }).catch(() => {});
        wireQueueEvents();
      }
      tab.mode = 'sftp';
      if (state.activeTabId === tab.tabId) {
        if (typeof window.activateSessionSurface === 'function') window.activateSessionSurface(tab.tabId);
        else showSftpForTab(tab.tabId);
      }
      await refreshSftpPanel(tab.tabId);
    } catch (e) {
      toast(e.message || String(e), 'err');
    }
  }
  updateTerminalHead();
}

function showSftpForTab(tabId) {
  const body = document.getElementById('terminalBody');
  const sbody = document.getElementById('sftpBody');
  if (body) body.style.display = 'none';
  if (sbody) {
    sbody.classList.add('visible');
    for (const child of sbody.children) {
      child.style.display = child.id === 'sftpQueuePanel' ? 'flex' : 'none';
    }
    let panel = document.getElementById('sftpPanel-' + tabId);
    if (!panel) {
      panel = buildSftpPanel(tabId);
      sbody.appendChild(panel);
    }
    panel.style.display = 'flex';
  }
  let queuePanel = document.getElementById('sftpQueuePanel');
  if (!queuePanel && sbody) {
    queuePanel = buildQueuePanel();
    sbody.appendChild(queuePanel);
  }
  if (queuePanel) queuePanel.style.display = 'flex';
  const label = document.getElementById('termModeLabel');
  if (label) label.textContent = 'SSH';
  const rec = window.tabRecord ? window.tabRecord(tabId) : null;
  if (rec && rec.hostEl) rec.hostEl.style.display = 'none';
}

function showSshForTab(tabId) {
  const rec = window.tabRecord ? window.tabRecord(tabId) : null;
  const sbody = document.getElementById('sftpBody');
  if (sbody) {
    sbody.classList.remove('visible');
    for (const child of sbody.children) child.style.display = 'none';
  }
  const body = document.getElementById('terminalBody');
  if (body) body.style.display = 'flex';
  if (rec && rec.hostEl) rec.hostEl.style.display = 'block';
  if (typeof window.showTabTerminal === 'function') window.showTabTerminal(tabId);
  const label = document.getElementById('termModeLabel');
  if (label) label.textContent = 'SFTP';
}

// ─── panel construction ─────────────────────────────────────────────────────

function buildSftpPanel(tabId) {
  const panel = document.createElement('div');
  panel.className = 'sftp-panel';
  panel.id = 'sftpPanel-' + tabId;
  panel.style.display = 'none';

  // ── toolbar ──
  const toolbar = document.createElement('div');
  toolbar.className = 'sftp-toolbar';
  const mkBtn = (icon, title, fn, label) => {
    const b = document.createElement('button');
    b.className = 'ghost-btn';
    b.title = title;
    b.innerHTML = `${ico(icon)}${label ? `<span>${label}</span>` : ''}`;
    b.addEventListener('click', fn);
    return b;
  };

  const upBtn = mkBtn('arrow-up', 'Parent directory', () => sftpNavigateUp(tabId), 'Up');
  const refreshBtn = mkBtn('refresh-cw', 'Refresh', () => refreshSftpPanel(tabId), 'Refresh');
  const mkdirBtn = mkBtn('folder-plus', 'New folder', () => sftpMkdirPrompt(tabId), 'Folder');
  const newFileBtn = mkBtn('file-text', 'New empty file', () => sftpTouchPrompt(tabId), 'File');
  const bookmarkBtn = mkBtn('star', 'Bookmarks', (ev) => openBookmarkMenu(ev, tabId));
  const searchBtn = mkBtn('search', 'Search recursively (in current tree)', () => toggleSearchBar(tabId));
  const hiddenBtn = mkBtn('eye', 'Show/hide dotfiles', () => {
    const tab = sftpTabState(sftpTab(tabId));
    tab.showHidden = !tab.showHidden;
    hiddenBtn.classList.toggle('active', tab.showHidden);
    refreshSftpPanel(tabId, { keepScroll: true });
  });
  const dualBtn = mkBtn('folder-open', 'Toggle local pane', () => toggleDualPane(tabId));
  const logBtn = mkBtn('history', 'Activity log', () => {
    const log = document.getElementById('sftpLog-' + tabId);
    if (log) log.hidden = !log.hidden;
  });

  const pathBox = document.createElement('input');
  pathBox.className = 'sftp-path';
  pathBox.readOnly = true;
  pathBox.title = 'Click to copy path';

  const fsInfo = document.createElement('span');
  fsInfo.className = 'sftp-fsinfo';
  fsInfo.id = 'sftpFsInfo-' + tabId;

  toolbar.appendChild(upBtn);
  toolbar.appendChild(refreshBtn);
  toolbar.appendChild(mkdirBtn);
  toolbar.appendChild(newFileBtn);
  toolbar.appendChild(bookmarkBtn);
  toolbar.appendChild(searchBtn);
  toolbar.appendChild(hiddenBtn);
  toolbar.appendChild(dualBtn);
  toolbar.appendChild(logBtn);
  toolbar.appendChild(pathBox);
  toolbar.appendChild(fsInfo);

  // ── search bar (hidden until toggled) ──
  const searchBar = document.createElement('div');
  searchBar.className = 'sftp-searchbar';
  searchBar.id = 'sftpSearchBar-' + tabId;
  searchBar.hidden = true;
  const searchInput = document.createElement('input');
  searchInput.type = 'text';
  searchInput.placeholder = 'Find in this directory tree…';
  searchInput.id = 'sftpSearchInput-' + tabId;
  const searchResults = document.createElement('div');
  searchResults.className = 'sftp-searchresults';
  searchResults.id = 'sftpSearchResults-' + tabId;
  const searchStatus = document.createElement('span');
  searchStatus.className = 'sftp-searchstatus';
  searchStatus.id = 'sftpSearchStatus-' + tabId;
  searchBar.appendChild(searchInput);
  searchBar.appendChild(searchStatus);
  searchBar.appendChild(searchResults);

  searchInput.addEventListener('keydown', (ev) => {
    if (ev.key === 'Enter') {
      ev.preventDefault();
      runSearch(tabId, searchInput.value.trim());
    } else if (ev.key === 'Escape') {
      searchBar.hidden = true;
    }
  });

  // ── remote listing ──
  const remotePane = document.createElement('div');
  remotePane.className = 'sftp-pane sftp-remote';
  const table = document.createElement('table');
  table.className = 'sftp-table';
  const thead = document.createElement('thead');
  thead.innerHTML = `
    <tr>
      <th data-sort="name">Name</th>
      <th data-sort="size">Size</th>
      <th data-sort="modified">Modified</th>
    </tr>`;
  thead.addEventListener('click', (ev) => {
    const th = ev.target.closest('th[data-sort]');
    if (!th) return;
    const tab = sftpTabState(sftpTab(tabId));
    const key = th.dataset.sort;
    if (tab.sortKey === key) tab.sortDesc = !tab.sortDesc;
    else { tab.sortKey = key; tab.sortDesc = false; }
    renderEntries(tabId); // re-sort cached entries without refetch
  });
  const tbody = document.createElement('tbody');
  tbody.id = 'sftpTbody-' + tabId;
  table.appendChild(thead);
  table.appendChild(tbody);
  remotePane.appendChild(table);

  // Empty-area click clears selection.
  tbody.addEventListener('click', (ev) => {
    if (ev.target === tbody) clearSelection(tabId);
  });

  // ── local pane (dual mode) ──
  const localPane = document.createElement('div');
  localPane.className = 'sftp-pane sftp-local';
  localPane.id = 'sftpLocalPane-' + tabId;
  localPane.hidden = true;
  const localToolbar = document.createElement('div');
  localToolbar.className = 'sftp-toolbar';
  const localUp = mkBtn('arrow-up', 'Parent directory', () => localNavigateUp(tabId), 'Up');
  const localHome = mkBtn('folder', 'Home', () => {
    const tab = sftpTab(tabId);
    tab.localPath = '';
    refreshLocalPane(tabId);
  }, 'Home');
  const localPath = document.createElement('input');
  localPath.className = 'sftp-path';
  localPath.readOnly = true;
  localPath.id = 'sftpLocalPath-' + tabId;
  localToolbar.appendChild(localUp);
  localToolbar.appendChild(localHome);
  localToolbar.appendChild(localPath);
  const localTable = document.createElement('table');
  localTable.className = 'sftp-table';
  const localHead = document.createElement('thead');
  localHead.innerHTML = `<tr><th>Name</th><th>Size</th><th>Modified</th></tr>`;
  const localBody = document.createElement('tbody');
  localBody.id = 'sftpLocalTbody-' + tabId;
  localTable.appendChild(localHead);
  localTable.appendChild(localBody);
  localPane.appendChild(localToolbar);
  localPane.appendChild(localTable);

  // ── splitter (drag to resize) ──
  const splitter = document.createElement('div');
  splitter.className = 'sftp-splitter';
  splitter.id = 'sftpSplitter-' + tabId;
  let dragState = null;
  splitter.addEventListener('mousedown', (ev) => {
    dragState = { startX: ev.clientX, startW: remotePane.getBoundingClientRect().width };
    ev.preventDefault();
  });
  document.addEventListener('mousemove', (ev) => {
    if (!dragState) return;
    const panelRect = panel.getBoundingClientRect();
    const pct = ((dragState.startW + ev.clientX - dragState.startX) / panelRect.width) * 100;
    panel.style.setProperty('--local-pct', `${Math.min(70, Math.max(20, pct)).toFixed(1)}%`);
  });
  document.addEventListener('mouseup', () => { dragState = null; });

  // ── activity log (hidden until toggled) ──
  const log = document.createElement('pre');
  log.className = 'sftp-log';
  log.id = 'sftpLog-' + tabId;
  log.hidden = true;

  // ── drop hint ──
  const hint = document.createElement('div');
  hint.className = 'sftp-drop-hint';
  hint.textContent = '⬇ Drag files here from your file manager to upload';

  const panes = document.createElement('div');
  panes.className = 'sftp-panes';
  panes.appendChild(localPane);
  panes.appendChild(splitter);
  panes.appendChild(remotePane);

  panel.appendChild(toolbar);
  panel.appendChild(searchBar);
  panel.appendChild(panes);
  panel.appendChild(log);
  panel.appendChild(hint);

  wireSftpDrop(panel, tabId, hint);
  wireSftpPaneDnd(tabId);
  ensureSftpPreserveTsToggle(tabId);
  return panel;
}

// ─── preserve-timestamps toggle (FileZilla: "Preserve timestamps of
// transferred files") ────────────────────────────────────────────────────────

/// Idempotent: append the toggle next to the hidden-files button if absent
/// (never restructure the toolbar — G owns that block; this appends only).
function ensureSftpPreserveTsToggle(tabId) {
  const panel = document.getElementById('sftpPanel-' + tabId);
  if (!panel || document.getElementById('sftpPreserveTsBtn-' + tabId)) return;
  const toolbar = panel.querySelector('.sftp-toolbar');
  const hiddenBtn = [...toolbar.querySelectorAll('button')].find(b => b.title === 'Show/hide dotfiles');
  if (!toolbar) return;
  const tab = sftpTabState(sftpTab(tabId));
  const btn = document.createElement('button');
  btn.className = 'ghost-btn';
  btn.id = 'sftpPreserveTsBtn-' + tabId;
  btn.title = 'Preserve timestamps of transferred files';
  btn.innerHTML = ico('history');
  btn.classList.toggle('active', !!tab.sftpPreserveTs);
  btn.addEventListener('click', () => window.sftpPreserveTsToggle(tabId));
  toolbar.insertBefore(btn, hiddenBtn ? hiddenBtn.nextSibling : null);
}

/// Toggle per-tab preserve-timestamps; persists the global default setting.
function sftpPreserveTsToggle(tabId) {
  const tab = sftpTabState(sftpTab(tabId));
  if (!tab) return;
  tab.sftpPreserveTs = !tab.sftpPreserveTs;
  const btn = document.getElementById('sftpPreserveTsBtn-' + tabId);
  if (btn) btn.classList.toggle('active', tab.sftpPreserveTs);
  state.settings = state.settings || {};
  state.settings.sftpPreserveTs = tab.sftpPreserveTs ? '1' : '0';
  call('settings_set', { key: 'sftpPreserveTs', value: tab.sftpPreserveTs ? '1' : '0' }).catch(() => {});
  sftpLog(tabId, `preserve timestamps ${tab.sftpPreserveTs ? 'ON' : 'OFF'}`);
}
window.sftpPreserveTsToggle = sftpPreserveTsToggle;

// ─── entry rendering (remote) ───────────────────────────────────────────────

function clearSelection(tabId) {
  const tab = sftpTab(tabId);
  if (!tab) return;
  sftpTabState(tab);
  tab.sftpSelected.clear();
  const tbody = document.getElementById('sftpTbody-' + tabId);
  if (tbody) for (const r of tbody.querySelectorAll('.sftp-entry.selected')) r.classList.remove('selected');
}

function toggleRowSelected(tr, on) {
  tr.classList.toggle('selected', on);
}

async function refreshSftpPanel(tabId, opts = {}) {
  const tab = sftpTab(tabId);
  if (!tab) return;
  sftpTabState(tab);
  const tbody = document.getElementById('sftpTbody-' + tabId);
  const pathBox = document.querySelector('#sftpPanel-' + tabId + ' .sftp-path');
  if (!tbody) return;
  try {
    const r = await sftpCall('sftp_list_dir', { sessionId: tab.sessionId, path: tab.sftpPath });
    tab.sftpPath = r.path || tab.sftpPath;
    tab._entries = r.entries || [];
    if (pathBox) pathBox.value = tab.sftpPath;
    pathBox.onclick = () => { copyText(tab.sftpPath).then(ok => ok && toast('Path copied.', 'ok')); };
    renderEntries(tabId);
    if (tab.dualPane) refreshLocalPane(tabId);
    updateFsInfo(tabId);
  } catch (e) {
    toast(e.message || String(e), 'err');
  }
}

function renderEntries(tabId) {
  const tab = sftpTab(tabId);
  if (!tab || !tab._entries) return;
  const tbody = document.getElementById('sftpTbody-' + tabId);
  if (!tbody) return;
  const thead = tbody.parentElement.querySelector('thead');
  if (thead) {
    for (const th of thead.querySelectorAll('th[data-sort]')) {
      th.classList.toggle('sorted', th.dataset.sort === tab.sortKey);
      th.classList.toggle('desc', th.dataset.sort === tab.sortKey && tab.sortDesc);
    }
  }
  tab.sftpSelected = tab.sftpSelected || new Set();
  // Keep only selections still present.
  const names = new Set(tab._entries.map(e => e.name));
  for (const n of [...tab.sftpSelected]) if (!names.has(n)) tab.sftpSelected.delete(n);

  let entries = tab._entries.filter(e => tab.showHidden || !e.name.startsWith('.'));
  const dir = tab.sftpPath;
  const key = tab.sortKey, desc = tab.sortDesc;
  entries.sort((a, b) => {
    if (a.isDir !== b.isDir) return a.isDir ? -1 : 1; // dirs always first
    let c = 0;
    if (key === 'size') c = (a.size || 0) - (b.size || 0);
    else if (key === 'modified') c = (a.modifiedMs || 0) - (b.modifiedMs || 0);
    else c = a.name.toLowerCase().localeCompare(b.name.toLowerCase());
    return desc ? -c : c;
  });

  tbody.innerHTML = '';
  let lastClicked = null;
  for (const entry of entries) {
    const tr = document.createElement('tr');
    tr.dataset.isdir = entry.isDir ? '1' : '0';
    tr.dataset.name = entry.name;
    const tdName = document.createElement('td');
    tdName.textContent = (entry.isDir ? '📁 ' : '📄 ') + entry.name;
    const tdSize = document.createElement('td');
    tdSize.textContent = entry.isDir ? '—' : formatSftpSize(entry.size);
    const tdMod = document.createElement('td');
    tdMod.textContent = entry.modifiedMs ? fmtTime(new Date(entry.modifiedMs).toISOString()) : '—';
    tr.appendChild(tdName); tr.appendChild(tdSize); tr.appendChild(tdMod);

    tr.className = entry.isDir ? 'sftp-entry sftp-dir' : 'sftp-entry sftp-file';
    tr.tabIndex = 0;
    tr.title = entry.isDir ? 'Double-click to open folder' : 'Double-click to download';
    if (tab.sftpSelected.has(entry.name)) tr.classList.add('selected');

    // Draggable to the local pane (download) or another remote dir (move).
    tr.draggable = true;
    tr.addEventListener('dragstart', (ev) => {
      const payload = {
        tabId,
        path: sftpJoin(tab.sftpPath, entry.name),
        name: entry.name,
        isDir: !!entry.isDir,
      };
      ev.dataTransfer.setData('text/sftp-remote', JSON.stringify(payload));
      ev.dataTransfer.effectAllowed = 'copyMove';
    });

    tr.addEventListener('click', (ev) => {
      if (ev.ctrlKey || ev.metaKey) {
        if (tab.sftpSelected.has(entry.name)) { tab.sftpSelected.delete(entry.name); toggleRowSelected(tr, false); }
        else { tab.sftpSelected.add(entry.name); toggleRowSelected(tr, true); }
        lastClicked = entry.name;
      } else if (ev.shiftKey && lastClicked) {
        // Range select from lastClicked to this entry.
        const names = entries.map(e => e.name);
        const i0 = names.indexOf(lastClicked), i1 = names.indexOf(entry.name);
        if (i0 >= 0 && i1 >= 0) {
          for (let i = Math.min(i0, i1); i <= Math.max(i0, i1); i++) tab.sftpSelected.add(names[i]);
          for (const row of tbody.querySelectorAll('.sftp-entry')) {
            toggleRowSelected(row, tab.sftpSelected.has(row.dataset.name));
          }
        }
      } else {
        tab.sftpSelected.clear();
        for (const row of tbody.querySelectorAll('.sftp-entry.selected')) row.classList.remove('selected');
        tab.sftpSelected.add(entry.name);
        toggleRowSelected(tr, true);
        lastClicked = entry.name;
      }
    });
    tr.addEventListener('dblclick', () => {
      if (entry.isDir) {
        tab.sftpPath = sftpJoin(tab.sftpPath, entry.name);
        refreshSftpPanel(tabId);
      } else {
        // Queue the download to the last-used local dir (or temp dir).
        queueDownloads(tabId, [sftpJoin(tab.sftpPath, entry.name)]);
      }
    });
    tr.addEventListener('keydown', (ev) => {
      if (ev.key === 'Enter') tr.dispatchEvent(new MouseEvent('dblclick', { bubbles: true }));
      else if (ev.key === 'ContextMenu' || (ev.shiftKey && ev.key === 'F10')) {
        ev.preventDefault();
        const rect = tr.getBoundingClientRect();
        openSftpFileMenu(rect.left + 12, rect.top + 12, tabId, entry);
      }
    });
    tr.addEventListener('contextmenu', (ev) => {
      ev.preventDefault();
      if (!tab.sftpSelected.has(entry.name)) {
        tab.sftpSelected.clear();
        for (const row of tbody.querySelectorAll('.sftp-entry.selected')) row.classList.remove('selected');
        tab.sftpSelected.add(entry.name);
        toggleRowSelected(tr, true);
      }
      openSftpFileMenu(ev.clientX, ev.clientY, tabId, entry);
    });
    tbody.appendChild(tr);
  }
}

// Ctrl+A within the panel selects all rows.
document.addEventListener('keydown', (ev) => {
  if (!(ev.ctrlKey || ev.metaKey) || ev.key.toLowerCase() !== 'a') return;
  const active = sftpTab(state.activeTabId);
  if (!active || active.mode !== 'sftp') return;
  const panel = document.getElementById('sftpPanel-' + active.tabId);
  if (!panel) return;
  const tbody = document.getElementById('sftpTbody-' + active.tabId);
  if (!tbody) return;
  ev.preventDefault();
  sftpTabState(active);
  active.sftpSelected.clear();
  for (const row of tbody.querySelectorAll('.sftp-entry')) {
    if (!row.dataset.name.startsWith('.') || active.showHidden) {
      active.sftpSelected.add(row.dataset.name);
      toggleRowSelected(row, true);
    }
  }
});

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
      sftpLog(tabId, `mkdir ${name}`);
      await refreshSftpPanel(tabId);
    } catch (e) { toast(e.message || String(e), 'err'); }
  });
}

async function sftpTouchPrompt(tabId) {
  const tab = sftpTab(tabId);
  if (!tab) return;
  promptModal('New file', `Create an empty file in ${tab.sftpPath}:`, 'new-file.txt', async (name) => {
    if (!name) return;
    try {
      await sftpCall('sftp_touch', { sessionId: tab.sessionId, path: sftpJoin(tab.sftpPath, name) });
      sftpLog(tabId, `touch ${name}`);
      await refreshSftpPanel(tabId);
    } catch (e) { toast(e.message || String(e), 'err'); }
  });
}

// ─── statvfs display ────────────────────────────────────────────────────────

async function updateFsInfo(tabId) {
  const tab = sftpTab(tabId);
  const el = document.getElementById('sftpFsInfo-' + tabId);
  if (!tab || !el) return;
  try {
    const r = await sftpCall('sftp_fs_info', { sessionId: tab.sessionId, path: tab.sftpPath });
    if (r && r.supported) {
      const free = formatSftpSize(r.freeBytes || 0);
      const total = formatSftpSize(r.totalBytes || 0);
      el.textContent = `— ${free} free of ${total}${r.readOnly ? ' (read-only)' : ''}`;
    } else {
      el.textContent = '';
    }
  } catch { el.textContent = ''; }
}

// ─── context menu ───────────────────────────────────────────────────────────

/// Right-click menu for a remote file/dir (selection-aware).
function openSftpFileMenu(x, y, tabId, entry) {
  closeKeyConnectMenu();
  const tab = sftpTabState(sftpTab(tabId));
  if (!tab) return;
  const selected = [...tab.sftpSelected];
  const multi = selected.length > 1;
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

  const selectedPaths = selected.map(n => sftpJoin(tab.sftpPath, n));

  mk(multi ? `Download ${selected.length} items` : 'Download', 'download', () =>
    queueDownloads(tabId, selectedPaths.length ? selectedPaths : [fullPath]));
  if (!multi && !entry.isDir) {
    mk('Download as…', 'download', () => sftpDownloadTo(tabId, fullPath, entry.name));
    mk('Open with system app', 'pencil', () => sftpOpenForEdit(tabId, fullPath, entry.name));
  }
  mk('File permissions…', 'settings', () => openChmodDialog(tabId, multi ? selectedPaths : [fullPath], entry));
  mk(multi ? `Rename… (${selected[0]} +${selected.length - 1})` : 'Rename…', 'pencil', async () => {
    if (multi) { toast('Rename applies to a single item — select one.', 'info'); return; }
    promptModal('Rename', 'New name:', entry.name, async (newName) => {
      if (!newName || newName === entry.name) return;
      try {
        await sftpCall('sftp_rename', { sessionId: tab.sessionId, from: fullPath, to: sftpJoin(tab.sftpPath, newName) });
        sftpLog(tabId, `rename ${entry.name} → ${newName}`);
        await refreshSftpPanel(tabId);
      } catch (e) { toast(e.message || String(e), 'err'); }
    });
  });
  mk(multi ? `Delete ${selected.length} items` : 'Delete', 'trash-2', async () => {
    const paths = selectedPaths.length ? selectedPaths : [fullPath];
    if (!confirm(`Delete ${paths.length === 1 ? `"${paths[0]}"` : paths.length + ' items'}?`)) return;
    let ok = 0, fail = 0;
    for (const p of paths) {
      const name = p.split('/').filter(Boolean).pop();
      const isDir = (tab._entries || []).find(e => e.name === name)?.isDir ?? false;
      try {
        await sftpCall('sftp_remove', { sessionId: tab.sessionId, path: p, isDir });
        ok++;
      } catch { fail++; }
    }
    sftpLog(tabId, `delete ${ok} item(s)${fail ? `, ${fail} failed` : ''}`);
    if (fail) toast(`${ok} deleted, ${fail} failed.`, 'err');
    await refreshSftpPanel(tabId);
  });
  mk('Copy path', 'copy', () => copyText(fullPath).then(ok => ok && toast('Path copied.', 'ok')));
  mk('Copy URL (sftp://)', 'copy', () => {
    const url = `sftp://${tab.host || 'host'}:${tab.port || 22}${fullPath}`;
    copyText(url).then(ok => ok && toast('URL copied.', 'ok'));
  });
  mk('Select all', 'check-circle', () => {
    for (const row of document.querySelectorAll(`#sftpTbody-${tabId} .sftp-entry`)) {
      if (!row.dataset.name.startsWith('.') || tab.showHidden) {
        tab.sftpSelected.add(row.dataset.name);
        toggleRowSelected(row, true);
      }
    }
  });

  // Send to → other connected SFTP tabs (download → temp → upload).
  const others = [...state.sessions.values()].filter(t =>
    t.tabId !== tabId && window.tabSessionLive(t.tabId) && t.sftpReady);
  if (others.length > 0 && !multi) {
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

// ─── chmod dialog ───────────────────────────────────────────────────────────

function openChmodDialog(tabId, paths, entry) {
  const tab = sftpTab(tabId);
  if (!tab || !paths.length) return;
  const modal = document.getElementById('chmodModal');
  if (!modal) { toast('chmod dialog missing from page.', 'err'); return; }
  const title = document.getElementById('chmodTitle');
  title.textContent = paths.length === 1
    ? `Permissions — ${paths[0].split('/').filter(Boolean).pop()}`
    : `Permissions — ${paths.length} items`;

  const boxes = {}; // rwx × owner/group/other
  for (const who of ['owner', 'group', 'other']) {
    for (const bit of ['r', 'w', 'x']) {
      boxes[who + bit] = document.getElementById('chmod-' + who + '-' + bit);
    }
  }
  const octal = document.getElementById('chmodOctal');
  const recurse = document.getElementById('chmodRecurse');
  const applyTo = document.getElementById('chmodApplyTo');
  const applyBtn = document.getElementById('chmodApplyBtn');
  const cancelBtn = document.getElementById('chmodCancelBtn');

  const toOctal = () => {
    let s = '';
    for (const who of ['owner', 'group', 'other']) {
      let n = 0;
      if (boxes[who + 'r'].checked) n += 4;
      if (boxes[who + 'w'].checked) n += 2;
      if (boxes[who + 'x'].checked) n += 1;
      s += n;
    }
    return s;
  };
  const fromOctal = (mode) => {
    const str = (mode & 0o777).toString(8).padStart(3, '0');
    const bits = [['owner', 0], ['group', 1], ['other', 2]];
    for (const [who, i] of bits) {
      const n = parseInt(str[i], 10);
      boxes[who + 'r'].checked = !!(n & 4);
      boxes[who + 'w'].checked = !!(n & 2);
      boxes[who + 'x'].checked = !!(n & 1);
    }
    octal.value = str;
  };
  for (const cb of Object.values(boxes)) {
    cb.onchange = () => { octal.value = toOctal(); };
  }
  octal.oninput = () => {
    if (/^[0-7]{3}$/.test(octal.value)) fromOctal(parseInt(octal.value, 8));
  };

  // Prefill from the first path (stat).
  (async () => {
    try {
      const r = await sftpCall('sftp_get_permissions', { sessionId: tab.sessionId, path: paths[0] });
      if (r && r.mode != null) fromOctal(r.mode);
      else fromOctal(0o644);
    } catch { fromOctal(0o644); }
  })();

  const close = () => { modal.hidden = true; };
  cancelBtn.onclick = close;
  modal.onclick = (ev) => { if (ev.target === modal) close(); };

  applyBtn.onclick = async () => {
    const mode = parseInt(toOctal(), 8);
    if (Number.isNaN(mode)) { toast('Invalid permission value.', 'err'); return; }
    let changed = 0, fail = 0;
    for (const p of paths) {
      try {
        const r = await sftpCall('sftp_chmod', {
          sessionId: tab.sessionId, path: p, mode,
          recursive: recurse.checked, applyTo: applyTo.value,
        });
        changed += r.changed || 1;
      } catch { fail++; }
    }
    sftpLog(tabId, `chmod ${toOctal()} on ${paths.length} path(s) — ${changed} changed${fail ? `, ${fail} failed` : ''}`);
    toast(fail ? `${changed} updated, ${fail} failed.` : `Permissions set (${toOctal()}).`, fail ? 'err' : 'ok');
    close();
    refreshSftpPanel(tabId);
  };

  modal.hidden = false;
  octal.focus();
}

// ─── search ─────────────────────────────────────────────────────────────────

let searchUnlisten = null;

function toggleSearchBar(tabId) {
  const bar = document.getElementById('sftpSearchBar-' + tabId);
  if (!bar) return;
  bar.hidden = !bar.hidden;
  if (!bar.hidden) document.getElementById('sftpSearchInput-' + tabId).focus();
}

async function runSearch(tabId, query) {
  if (!query) return;
  const tab = sftpTab(tabId);
  if (!tab) return;
  const results = document.getElementById('sftpSearchResults-' + tabId);
  const status = document.getElementById('sftpSearchStatus-' + tabId);
  if (!results || !status) return;
  results.innerHTML = '';
  status.textContent = 'Searching…';
  sftpLog(tabId, `search "${query}" under ${tab.sftpPath}`);
  let count = 0;

  if (searchUnlisten) { searchUnlisten(); searchUnlisten = null; }
  searchUnlisten = await sftpListen('sftp-search', (ev) => {
    const p = ev.payload;
    if (p.sessionId !== tab.sessionId) return;
    if (p.done) {
      status.textContent = `${p.matched} match(es)${p.capped ? ' (capped at 500)' : ''} · ${p.scanned} scanned`;
      return;
    }
    count++;
    if (count > 50) return; // render only first 50
    const item = document.createElement('div');
    item.className = 'sftp-searchitem';
    item.textContent = (p.isDir ? '📁 ' : '📄 ') + p.path;
    item.title = 'Navigate to containing folder';
    item.addEventListener('click', () => {
      const parent = p.path.slice(0, p.path.lastIndexOf('/')) || '/';
      tab.sftpPath = parent;
      refreshSftpPanel(tabId);
      toggleSearchBar(tabId);
    });
    results.appendChild(item);
  });

  try {
    await sftpCall('sftp_search', {
      sessionId: tab.sessionId, rootPath: tab.sftpPath, query,
    });
  } catch (e) {
    status.textContent = 'Search failed: ' + (e.message || e);
  }
}

// ─── bookmarks ──────────────────────────────────────────────────────────────

async function openBookmarkMenu(ev, tabId) {
  const tab = sftpTab(tabId);
  if (!tab) return;
  const r = await sftpCall('sftp_bookmarks_list', { serverId: tab.serverId });
  const bookmarks = r.bookmarks || [];

  closeKeyConnectMenu();
  const menu = document.createElement('div');
  menu.className = 'ctx-menu';
  menu.id = 'keyConnectMenu';

  if (!bookmarks.length) {
    const empty = document.createElement('div');
    empty.className = 'ctx-item';
    empty.style.cursor = 'default';
    empty.style.opacity = '0.6';
    empty.textContent = 'No bookmarks yet';
    menu.appendChild(empty);
  }
  for (const b of bookmarks) {
    const item = document.createElement('button');
    item.className = 'ctx-item';
    item.innerHTML = `${ico('star')}<span>${escapeHtml(b.name)}</span>`;
    item.addEventListener('click', () => {
      closeKeyConnectMenu();
      tab.sftpPath = b.remotePath;
      if (b.localPath) tab.localPath = b.localPath;
      refreshSftpPanel(tabId);
    });
    item.addEventListener('contextmenu', async (e) => {
      e.preventDefault();
      const updated = bookmarks.filter(x => x !== b);
      await sftpCall('sftp_bookmarks_save', { serverId: tab.serverId, bookmarks: updated });
      toast('Bookmark removed.', 'ok');
      closeKeyConnectMenu();
    });
    menu.appendChild(item);
  }
  const sep = document.createElement('div');
  sep.className = 'ctx-sep';
  menu.appendChild(sep);
  const addBtn = document.createElement('button');
  addBtn.className = 'ctx-item';
  addBtn.innerHTML = `${ico('plus')}<span>Bookmark this directory…</span>`;
  addBtn.addEventListener('click', () => {
    closeKeyConnectMenu();
    promptModal('Bookmark', `Name for ${tab.sftpPath}:`, tab.sftpPath.split('/').filter(Boolean).pop() || 'root', async (name) => {
      if (!name) return;
      const list = await sftpCall('sftp_bookmarks_list', { serverId: tab.serverId });
      const updated = [...(list.bookmarks || []), {
        name, remotePath: tab.sftpPath, localPath: tab.dualPane ? tab.localPath : null,
      }];
      await sftpCall('sftp_bookmarks_save', { serverId: tab.serverId, bookmarks: updated });
      sftpLog(tabId, `bookmark "${name}" → ${tab.sftpPath}`);
      toast('Bookmark saved.', 'ok');
    });
  });
  menu.appendChild(addBtn);

  const rect = ev.currentTarget.getBoundingClientRect();
  menu.style.left = rect.left + 'px';
  menu.style.top = (rect.bottom + 4) + 'px';
  document.body.appendChild(menu);
  const onAway = (e2) => {
    if (e2.target.closest && e2.target.closest('#keyConnectMenu')) return;
    closeKeyConnectMenu();
  };
  setTimeout(() => document.addEventListener('mousedown', onAway, { once: true }), 0);
}

// ─── local pane (dual mode) ─────────────────────────────────────────────────

function toggleDualPane(tabId) {
  const tab = sftpTabState(sftpTab(tabId));
  if (!tab) return;
  tab.dualPane = !tab.dualPane;
  const panel = document.getElementById('sftpPanel-' + tabId);
  if (panel) panel.classList.toggle('dual', tab.dualPane);
  const localPane = document.getElementById('sftpLocalPane-' + tabId);
  const splitter = document.getElementById('sftpSplitter-' + tabId);
  if (localPane && splitter) {
    localPane.hidden = !tab.dualPane;
    splitter.hidden = !tab.dualPane;
  }
  if (tab.dualPane) refreshLocalPane(tabId);
  // Persist the preference globally.
  state.sftpDualPane = tab.dualPane;
  call('settings_set', { key: 'sftpDualPane', value: tab.dualPane ? '1' : '0' }).catch(() => {});
}

async function refreshLocalPane(tabId) {
  const tab = sftpTab(tabId);
  if (!tab) return;
  const tbody = document.getElementById('sftpLocalTbody-' + tabId);
  const pathEl = document.getElementById('sftpLocalPath-' + tabId);
  if (!tbody) return;
  try {
    const r = await sftpCall('sftp_local_list', { path: tab.localPath || '' });
    tab.localPath = r.path || tab.localPath;
    tab._localHome = r.home;
    if (pathEl) pathEl.value = tab.localPath;
    tbody.innerHTML = '';
    for (const entry of r.entries || []) {
      const tr = document.createElement('tr');
      tr.className = entry.isDir ? 'sftp-entry sftp-dir' : 'sftp-entry sftp-file';
      tr.dataset.isdir = entry.isDir ? '1' : '0';
      const tdName = document.createElement('td');
      tdName.textContent = (entry.isDir ? '📁 ' : '📄 ') + entry.name;
      const tdSize = document.createElement('td');
      tdSize.textContent = entry.isDir ? '—' : formatSftpSize(entry.size);
      const tdMod = document.createElement('td');
      tdMod.textContent = entry.modifiedMs ? fmtTime(new Date(entry.modifiedMs).toISOString()) : '—';
      tr.appendChild(tdName); tr.appendChild(tdSize); tr.appendChild(tdMod);
      tr.addEventListener('dblclick', () => {
        if (entry.isDir) {
          const sep = tab.localPath.endsWith('\\') || tab.localPath.endsWith('/') ? '' : '/';
          tab.localPath = tab.localPath + sep + entry.name;
          refreshLocalPane(tabId);
        } else {
          // Upload this local file to the current remote dir via the queue.
          queueUploads(tabId, [{ local: joinLocal(tab.localPath, entry.name), remote: sftpJoin(tab.sftpPath, entry.name) }]);
        }
      });
      // Draggable to the remote pane (upload) or a remote dir row (upload into).
      tr.draggable = true;
      tr.addEventListener('dragstart', (ev) => {
        ev.dataTransfer.setData('text/sftp-local', JSON.stringify({
          tabId, path: joinLocal(tab.localPath, entry.name), name: entry.name, isDir: !!entry.isDir,
        }));
        ev.dataTransfer.effectAllowed = 'copy';
      });
      tbody.appendChild(tr);
    }
  } catch (e) {
    toast(e.message || String(e), 'err');
  }
}

function joinLocal(dir, name) {
  const sep = dir.includes('\\') && !dir.includes('/') ? '\\' : '/';
  return dir.endsWith(sep) ? dir + name : dir + sep + name;
}

function localNavigateUp(tabId) {
  const tab = sftpTab(tabId);
  if (!tab || !tab.localPath) return;
  const sep = tab.localPath.includes('\\') && !tab.localPath.includes('/') ? '\\' : '/';
  const parts = tab.localPath.split(sep).filter(Boolean);
  parts.pop();
  if (!parts.length) { tab.localPath = ''; refreshLocalPane(tabId); return; }
  let up = parts.join(sep);
  if (sep === '/') up = '/' + up;
  tab.localPath = up;
  refreshLocalPane(tabId);
}

// ─── downloads / uploads via the queue ──────────────────────────────────────

/// Download remote paths into an EXPLICIT local dir (drag onto a folder),
/// bypassing queueDownloads' local-pane-cwd default. Falls back to it when
/// the local pane hasn't loaded a path yet.
async function queueDownloadsInto(tabId, remotePaths, dir) {
  const tab = sftpTab(tabId);
  if (!tab) return;
  sftpTabState(tab);
  if (!tab.dualPane) toggleDualPane(tabId);
  const target = dir || tab.localPath;
  if (!target) {
    queueDownloads(tabId, remotePaths);
    return;
  }
  try {
    const r = await sftpCall('sftp_queue_add', {
      sessionId: tab.sessionId,
      direction: 'download',
      items: remotePaths.map(p => ({ remote: p })),
      destDir: target,
      preserveTs: !!tab.sftpPreserveTs,
    });
    sftpLog(tabId, `queued ${r.added} download(s) → ${target}`);
    if (r.added > 0) toast(`${r.added} download(s) → ${target}`, 'ok');
  } catch (e) { toast(e.message || String(e), 'err'); }
}

async function queueDownloads(tabId, remotePaths) {
  const tab = sftpTab(tabId);
  if (!tab) return;
  // Plain "Download" lands in the local pane's current directory. If the
  // local pane isn't open, open it so the destination is always visible —
  // never a hidden temp folder. Explicit placement stays on "Download as…".
  sftpTabState(tab);
  if (!tab.dualPane) toggleDualPane(tabId);
  if (!tab.localPath) {
    // Local listing hasn't loaded yet (toggle just opened it) — wait briefly.
    await new Promise(r => setTimeout(r, 600));
  }
  const dir = tab.localPath || null;
  if (!dir) {
    toast('Local pane is still loading — try again in a moment.', 'err');
    return;
  }
  try {
    const r = await sftpCall('sftp_queue_add', {
      sessionId: tab.sessionId,
      direction: 'download',
      items: remotePaths.map(p => ({ remote: p })),
      destDir: dir,
      preserveTs: !!tab.sftpPreserveTs,
    });
    sftpLog(tabId, `queued ${r.added} download(s) → ${dir}`);
    if (r.added > 0) toast(`${r.added} download(s) → ${dir}`, 'ok');
  } catch (e) { toast(e.message || String(e), 'err'); }
}

async function queueUploads(tabId, pairs) {
  const tab = sftpTab(tabId);
  if (!tab) return;
  try {
    const r = await sftpCall('sftp_queue_add', {
      sessionId: tab.sessionId,
      direction: 'upload',
      items: pairs,
      preserveTs: !!tab.sftpPreserveTs,
    });
    sftpLog(tabId, `queued ${r.added} upload(s)`);
    if (r.added > 0) toast(`${r.added} upload(s) queued.`, 'ok');
  } catch (e) { toast(e.message || String(e), 'err'); }
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

async function sftpOpenForEdit(tabId, fullPath, name) {
  const tab = sftpTab(tabId);
  if (!tab) return;
  try {
    const r = await sftpCall('sftp_open_for_edit', { sessionId: tab.sessionId, remote: fullPath });
    await call('system_open_external', { url: r.localPath });
    sftpLog(tabId, `editing ${name} (auto-sync on save)`);
    toast(`Editing ${name} — saves upload automatically.`, 'info');
  } catch (e) { toast(e.message || String(e), 'err'); }
}

// Server-to-server "Send to": enqueues a queue job that downloads from the
// source and uploads to the target on fresh SFTP channels (the interactive
// browse sessions are never used — some servers fail reads on the
// long-lived channel). Progress shows in the transfer queue panel.
async function sftpSendTo(fromTabId, fullPath, targetTab) {
  try {
    const name = fullPath.split('/').filter(Boolean).pop() || 'file';
    terminalSetStatus(`Sending ${name} to ${targetTab.serverName}…`);
    await sftpCall('sftp_server_copy', {
      fromSessionId: state.sessions.get(fromTabId)?.sessionId,
      remote: fullPath,
      targetSessionId: targetTab.sessionId,
      targetDir: targetTab.sftpPath || '/',
    });
    terminalSetStatus(`Sent ${name} to ${targetTab.serverName}.`);
    toast(`Sending ${name} to ${targetTab.serverName} — see Transfers.`, 'ok');
  } catch (e) { toast(e.message || String(e), 'err'); }
}

// ─── transfer queue panel ───────────────────────────────────────────────────

const queueJobs = new Map(); // id -> job
let queueUnlisten = null;
let queueTab = 'queued'; // which tab is visible: queued | failed | done

function wireQueueEvents() {
  if (queueUnlisten) return;
  sftpListen('sftp-queue', (ev) => {
    for (const j of ev.payload.jobs || []) {
      queueJobs.set(j.id, j);
      // Mirror failures into the active tab's log + status strip.
      if (j.state === 'failed' && !j._logged) {
        j._logged = true;
        const tab = [...state.sessions.values()].find(t => t.sessionId === j.sessionId);
        if (tab) sftpLog(tab.tabId, `transfer failed: ${j.remotePath || j.localPath} — ${j.error || 'error'}`);
      }
    }
    renderQueuePanel();
  }).then(un => { queueUnlisten = un; });
}

function buildQueuePanel() {
  const panel = document.createElement('div');
  panel.className = 'sftp-queuepanel';
  panel.id = 'sftpQueuePanel';
  panel.style.display = 'none';

  const head = document.createElement('div');
  head.className = 'sftp-queuehead';
  const title = document.createElement('span');
  title.className = 'sftp-queuetitle';
  title.textContent = 'Transfers';
  const summary = document.createElement('span');
  summary.className = 'sftp-queuesummary';
  summary.id = 'sftpQueueSummary';
  const tabs = document.createElement('div');
  tabs.className = 'sftp-queuetabs';
  for (const t of ['queued', 'failed', 'done']) {
    const b = document.createElement('button');
    b.className = 'sftp-queuetab';
    b.dataset.tab = t;
    b.textContent = t[0].toUpperCase() + t.slice(1);
    b.addEventListener('click', () => {
      queueTab = t;
      renderQueuePanel();
    });
    tabs.appendChild(b);
  }
  const clearBtn = document.createElement('button');
  clearBtn.className = 'ghost-btn';
  clearBtn.textContent = 'Clear finished';
  clearBtn.addEventListener('click', async () => {
    await call('sftp_queue_clear_finished');
    for (const [id, j] of [...queueJobs]) {
      if (['done', 'failed', 'cancelled'].includes(j.state)) queueJobs.delete(id);
    }
    renderQueuePanel();
  });
  head.appendChild(title);
  head.appendChild(summary);
  head.appendChild(tabs);
  head.appendChild(clearBtn);

  const list = document.createElement('div');
  list.className = 'sftp-queuelist';
  list.id = 'sftpQueueList';

  panel.appendChild(head);
  panel.appendChild(list);
  return panel;
}

function renderQueuePanel() {
  const list = document.getElementById('sftpQueueList');
  const summary = document.getElementById('sftpQueueSummary');
  if (!list || !summary) return;
  const tabsEl = document.querySelector('.sftp-queuetabs');
  if (tabsEl) {
    for (const b of tabsEl.querySelectorAll('.sftp-queuetab')) {
      b.classList.toggle('active', b.dataset.tab === queueTab);
    }
  }

  const jobs = [...queueJobs.values()];
  const active = jobs.filter(j => j.state === 'active');
  const queued = jobs.filter(j => j.state === 'queued');
  const failed = jobs.filter(j => j.state === 'failed');
  const done = jobs.filter(j => j.state === 'done');

  const aggSpeed = active.reduce((s, j) => s + (j.speed || 0), 0);
  summary.textContent = active.length
    ? `${active.length} active · ${(aggSpeed / 1024).toFixed(1)} KB/s`
    : queued.length ? `${queued.length} queued` : (failed.length ? `${failed.length} failed` : '');

  const shown = queueTab === 'queued'
    ? [...active, ...queued]
    : queueTab === 'failed' ? failed : done;

  list.innerHTML = '';
  for (const j of shown.slice(-100).reverse()) {
    const row = document.createElement('div');
    row.className = 'sftp-queueitem';
    const name = j.kind === 'upload'
      ? (j.remotePath || '').split('/').filter(Boolean).pop()
      : (j.remotePath || '').split('/').filter(Boolean).pop();
    const dirLabel = j.kind === 'upload' ? '↑' : j.kind === 'serverCopy' ? '⇄' : '↓';
    // serverCopy: bytesDone is overall (download half + upload half), so the
    // progress bar maps 0..2×size onto 0..100%.
    const totalUnits = j.kind === 'serverCopy' ? (j.size || 0) * 2 : (j.size || 0);
    const pct = totalUnits > 0
      ? Math.min(100, (j.bytesDone / totalUnits) * 100)
      : (j.state === 'done' ? 100 : 0);
    const shownDone = j.kind === 'serverCopy'
      ? Math.min(j.bytesDone || 0, j.size || 0)
      : (j.bytesDone || 0);

    const info = document.createElement('div');
    info.className = 'sftp-queueinfo';
    const route = j.kind === 'serverCopy' && j.targetServerName
      ? `${escapeHtml(j.serverName || '')} → ${escapeHtml(j.targetServerName)}`
      : escapeHtml(j.serverName || '');
    info.innerHTML = `<span class="sftp-queuename">${escapeHtml(dirLabel + ' ' + (name || '?'))}</span>
      <span class="sftp-queuesub">${route} · ${formatSftpSize(shownDone || 0)}${j.size ? ' / ' + formatSftpSize(j.size) : ''}${j.speed ? ' · ' + (j.speed / 1024).toFixed(1) + ' KB/s' : ''}${j.error ? ' · ' + escapeHtml(j.error) : ''}</span>`;
    const bar = document.createElement('div');
    bar.className = 'sftp-queuebar';
    const fill = document.createElement('div');
    fill.className = 'sftp-queuefill' + (j.state === 'failed' ? ' failed' : j.state === 'done' ? ' done' : '');
    fill.style.width = pct + '%';
    bar.appendChild(fill);
    row.appendChild(info);
    row.appendChild(bar);

    const actions = document.createElement('div');
    actions.className = 'sftp-queueactions';
    if (j.state === 'active' || j.state === 'queued') {
      const cancel = document.createElement('button');
      cancel.className = 'icon-btn';
      cancel.title = 'Cancel';
      cancel.innerHTML = ico('x');
      cancel.addEventListener('click', () => call('sftp_queue_cancel', { jobId: j.id }));
      actions.appendChild(cancel);
    }
    if (j.state === 'failed' || j.state === 'cancelled') {
      const retry = document.createElement('button');
      retry.className = 'icon-btn';
      retry.title = 'Retry';
      retry.innerHTML = ico('refresh-cw');
      retry.addEventListener('click', () => call('sftp_queue_retry', { jobId: j.id }));
      actions.appendChild(retry);
    }
    row.appendChild(actions);
    list.appendChild(row);
  }
  // Ask backend for authoritative state on first render.
  if (!queueJobs.size) call('sftp_queue_list').catch(() => {});
}

// Refresh remote listing when a job for this session finishes.
let lastDoneCount = 0;
setInterval(() => {
  const done = [...queueJobs.values()].filter(j => j.state === 'done').length;
  if (done > lastDoneCount) {
    const tab = sftpTab(state.activeTabId);
    if (tab && tab.mode === 'sftp' && tab.sftpReady) refreshSftpPanel(tab.tabId);
  }
  lastDoneCount = done;
}, 1500);

// ─── OS drag-and-drop upload ────────────────────────────────────────────────

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
      const tab = state.sessions.get(state.activeTabId);
      if (!tab || tab.mode !== 'sftp') return;
      const paths = event.payload.paths || [];
      if (!paths.length) return;
      // Target the hovered pane: over a remote DIRECTORY row the upload goes
      // INTO that folder; over the remote pane generally it goes to the
      // remote cwd. Over the local pane an OS drop can only mean an upload to
      // the remote cwd (the local pane can't receive OS files meaningfully).
      let remoteDir = tab.sftpPath;
      const pos = event.payload.position; // window coords (physical px)
      if (pos && typeof document.elementFromPoint === 'function') {
        const dpr = window.devicePixelRatio || 1;
        const el = document.elementFromPoint(pos.x / dpr, pos.y / dpr);
        const row = el && el.closest ? el.closest('tr.sftp-entry') : null;
        const panel = el && el.closest ? el.closest('.sftp-panel') : null;
        if (panel && panel.id === 'sftpPanel-' + tab.tabId &&
            row && row.dataset.isdir === '1' &&
            el.closest('.sftp-remote')) {
          remoteDir = sftpJoin(tab.sftpPath, row.dataset.name);
        }
      }
      const pairs = paths.map(p => {
        const name = p.split(/[\\/]/).filter(Boolean).pop() || 'file';
        return { local: p, remote: sftpJoin(remoteDir, name) };
      });
      queueUploads(tab.tabId, pairs);
    }
  });
}

// ─── two-pane drag & drop (FileZilla parity) ─────────────────────────────────

// Affordance styles injected once (styles.css is shared; keep this scoped and
// idempotent so parallel edits to the stylesheet don't collide).
function ensureSftpDndStyles() {
  if (document.getElementById('sftpDndStyles')) return;
  const style = document.createElement('style');
  style.id = 'sftpDndStyles';
  style.textContent = `
    .sftp-pane.drag-over { outline: 2px dashed var(--accent); outline-offset: -4px; background: var(--accent-weak); }
    .sftp-entry.drop-target td { background: var(--accent-weak) !important; box-shadow: inset 3px 0 var(--accent); }`;
  document.head.appendChild(style);
}
ensureSftpDndStyles();

const SFTP_DND_TYPES = ['text/sftp-local', 'text/sftp-remote'];

function sftpDndPayload(ev) {
  for (const type of SFTP_DND_TYPES) {
    if (ev.dataTransfer.types.includes(type)) {
      try {
        const raw = ev.dataTransfer.getData(type);
        if (!raw) return null;
        const data = JSON.parse(raw);
        return { type, data };
      } catch { return null; } // malformed payload — ignore the gesture
    }
  }
  return null;
}

function clearSftpDropHighlights(panel) {
  if (!panel) return;
  for (const el of panel.querySelectorAll('.drop-target')) el.classList.remove('drop-target');
  for (const el of panel.querySelectorAll('.drag-over')) el.classList.remove('drag-over');
}

/// Highlight the element under a drag: a DIRECTORY row wins (drop-into-folder),
/// otherwise the pane itself (drop-into-cwd).
function highlightSftpDropTarget(ev) {
  const panel = ev.target.closest ? ev.target.closest('.sftp-panel') : null;
  const root = panel || document.getElementById('sftpBody') || document;
  // Clear previous highlights anywhere in the active panel.
  for (const el of root.querySelectorAll('.drop-target')) el.classList.remove('drop-target');
  for (const el of root.querySelectorAll('.drag-over')) el.classList.remove('drag-over');
  const row = ev.target.closest ? ev.target.closest('tr.sftp-entry') : null;
  if (row && row.dataset.isdir === '1') {
    row.classList.add('drop-target');
    return row;
  }
  const pane = ev.target.closest ? ev.target.closest('.sftp-pane') : null;
  if (pane) pane.classList.add('drag-over');
  return null;
}

/// Local row double-click already uploads; this handles the local tbody as a
/// DROP TARGET for text/sftp-remote (remote → local download). Event
/// delegation on the tbody, added once per panel via wireSftpPaneDnd.
function wireSftpPaneDnd(tabId) {
  const localBody = document.getElementById('sftpLocalTbody-' + tabId);
  const remoteBody = document.getElementById('sftpTbody-' + tabId);
  if (localBody && !localBody._sftpDndWired) {
    localBody._sftpDndWired = true;
    localBody.addEventListener('dragover', (ev) => {
      if (!ev.dataTransfer.types.includes('text/sftp-remote')) return;
      ev.preventDefault();
      ev.dataTransfer.dropEffect = 'copy';
      highlightSftpDropTarget(ev);
    });
    localBody.addEventListener('drop', async (ev) => {
      const payload = sftpDndPayload(ev);
      if (!payload || payload.type !== 'text/sftp-remote') return;
      ev.preventDefault();
      ev.stopPropagation(); // don't double-fire the pane-level handler
      clearSftpDropHighlights(ev.target.closest('.sftp-panel'));
      const { data } = payload;
      const tab = sftpTab(tabId);
      if (!tab || tab.mode !== 'sftp') return;
      // Over a local DIRECTORY row → download into that dir; else pane cwd.
      const row = ev.target.closest('tr.sftp-entry');
      if (row && row.dataset.isdir === '1' && tab.localPath) {
        const dir = joinLocal(tab.localPath, row.dataset.name);
        queueDownloadsInto(tabId, [data.path], dir);
      } else {
        queueDownloads(tabId, [data.path]);
      }
    });
  }
  if (remoteBody && !remoteBody._sftpDndWired) {
    remoteBody._sftpDndWired = true;
    remoteBody.addEventListener('dragover', (ev) => {
      if (!SFTP_DND_TYPES.some(t => ev.dataTransfer.types.includes(t))) return;
      ev.preventDefault();
      ev.dataTransfer.dropEffect = ev.dataTransfer.types.includes('text/sftp-remote')
        ? 'move' : 'copy';
      highlightSftpDropTarget(ev);
    });
    remoteBody.addEventListener('drop', async (ev) => {
      const payload = sftpDndPayload(ev);
      if (!payload) return;
      ev.preventDefault();
      ev.stopPropagation();
      clearSftpDropHighlights(ev.target.closest('.sftp-panel'));
      const tab = sftpTab(tabId);
      if (!tab || tab.mode !== 'sftp') return;
      const row = ev.target.closest('tr.sftp-entry');
      const overDir = row && row.dataset.isdir === '1' ? row.dataset.name : null;
      if (payload.type === 'text/sftp-local') {
        // local → remote: upload into the hovered dir, else the remote cwd.
        const target = overDir ? sftpJoin(tab.sftpPath, overDir) : tab.sftpPath;
        queueUploads(tabId, [{ local: payload.data.path, remote: sftpJoin(target, payload.data.name) }]);
      } else if (payload.type === 'text/sftp-remote') {
        // remote → remote: MOVE via rename when dropped on a different dir.
        if (!overDir) return; // same-dir drop is a no-op
        const from = payload.data.path;
        const to = sftpJoin(sftpJoin(tab.sftpPath, overDir), payload.data.name);
        if (from === to) return;
        if (!confirm(`Move "${payload.data.name}" to "${sftpJoin(tab.sftpPath, overDir)}"?`)) return;
        try {
          await sftpCall('sftp_rename', { sessionId: tab.sessionId, from, to });
          sftpLog(tabId, `move ${payload.data.name} → ${to}`);
          await refreshSftpPanel(tabId);
        } catch (e) { toast(e.message || String(e), 'err'); }
      }
    });
  }
}

// Document-level dragover: prevent default for our custom types. The tbody
// delegations own the row/pane affordances; this just keeps the drop allowed
// over pane chrome and empty tbody areas.
document.addEventListener('dragover', (ev) => {
  if (SFTP_DND_TYPES.some(t => ev.dataTransfer.types.includes(t))) {
    ev.preventDefault();
  }
});
document.addEventListener('drop', (ev) => {
  const payload = sftpDndPayload(ev);
  if (!payload) return;
  ev.preventDefault();
  const tab = sftpTab(state.activeTabId);
  if (!tab || tab.mode !== 'sftp') return;
  clearSftpDropHighlights(document.getElementById('sftpPanel-' + tab.tabId));
  // Only handle drops NOT on a directory row (those were consumed by the
  // tbody delegation with stopPropagation; this is the belt-and-braces path
  // for drops over pane chrome / empty tbody areas).
  const row = ev.target.closest ? ev.target.closest('tr.sftp-entry') : null;
  if (row && row.dataset.isdir === '1') return;
  if (payload.type === 'text/sftp-local') {
    // Local → remote pane cwd (upload). If the drop was over the LOCAL pane,
    // a local→local move is not supported — treat as no-op.
    if (ev.target.closest && ev.target.closest('.sftp-local')) return;
    queueUploads(tab.tabId, [{ local: payload.data.path, remote: sftpJoin(tab.sftpPath, payload.data.name) }]);
  } else if (payload.type === 'text/sftp-remote') {
    // Remote → local pane cwd (download). Over the remote pane itself the
    // row handler already managed it; a bare pane drop is a no-op.
    if (ev.target.closest && ev.target.closest('.sftp-remote')) return;
    if (!ev.target.closest || !ev.target.closest('.sftp-local')) return;
    queueDownloads(tab.tabId, [payload.data.path]);
  }
});

// Dragleave cleanup: clear stale highlights when a drag exits the pane.
document.addEventListener('dragleave', (ev) => {
  if (!SFTP_DND_TYPES.some(t => ev.dataTransfer.types.includes(t))) return;
  const pane = ev.target.closest ? ev.target.closest('.sftp-pane') : null;
  if (pane && !pane.contains(ev.relatedTarget)) {
    pane.classList.remove('drag-over');
    for (const el of pane.querySelectorAll('.drop-target')) el.classList.remove('drop-target');
  }
});


// ─── exports ────────────────────────────────────────────────────────────────

window.toggleSshSftpMode = toggleSshSftpMode;
window.refreshSftpPanel = refreshSftpPanel;
window.showSshForTab = showSshForTab;
window.showSftpForTab = showSftpForTab;
window.sftpQueueDownloads = queueDownloads;
