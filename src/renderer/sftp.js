/**
 * sftp.js - SFTP file-browser panel for Connect tabs (FileZilla-parity pass).
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

// `settings_get` returns a fixed allowlist of keys plus every `sftpLocalDir:`
// row read by prefix, so a per-server default round-trips through the same
// config table as every other setting and arrives in `state.settings` like
// the rest. Read it from there rather than keeping a second copy anywhere.
function sftpSettingGet(key, fallback) {
  const v = state.settings && state.settings[key];
  return v === undefined || v === null ? fallback : v;
}

/// Namespaced settings key for a server's remembered local-pane directory
/// (Task 6). Prefixed so it can't collide with any flat setting name, and
/// keyed by the server's stable id (not its display name, which can repeat
/// or be edited) or session id (which changes every connection).
function sftpLocalDirKey(serverId) {
  return 'sftpLocalDir:' + (serverId || 'unknown');
}

/// Ensure the tab record has all the SFTP fields this module uses.
function sftpTabState(tab) {
  if (!tab.sftpSelected) tab.sftpSelected = new Set();
  if (!tab.sortKey) tab.sortKey = 'name';
  if (tab.sortDesc === undefined) tab.sortDesc = false;
  if (!tab.log) tab.log = [];
  if (!tab.showHidden) tab.showHidden = state.settings?.sftpShowHidden === '1';
  if (tab.dualPane === undefined) tab.dualPane = state.sftpDualPane === true;
  // Per-server default local directory, if the user has set one (Task 6);
  // falls back to '' (the OS home directory, sftp_local_list's own default)
  // exactly like before this existed.
  if (!tab.localPath) tab.localPath = sftpSettingGet(sftpLocalDirKey(tab.serverId), '');
  if (tab.sftpPreserveTs === undefined) tab.sftpPreserveTs = state.settings?.sftpPreserveTs === '1';
  // Permissions/Owner columns default ON; toggleable per the toolbar button
  // (they widen the table noticeably, so narrow windows may prefer them off -
  // the table wrapper also scrolls horizontally regardless, see styles.css).
  if (tab.showOwnerCols === undefined) tab.showOwnerCols = state.settings?.sftpShowOwnerCols !== '0';
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
    toast('Connect first - SFTP runs over the live session.', 'err');
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

  // ── toolbar (every button carries a short label; the row wraps, never clips) ──
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
  const mkPathCopy = (getter) => {
    const b = document.createElement('button');
    b.className = 'icon-btn sftp-pathcopy';
    b.title = 'Copy path';
    b.innerHTML = ico('copy');
    b.addEventListener('click', () => {
      const p = getter();
      if (p) copyText(p).then(ok => ok && toast('Path copied.', 'ok'));
    });
    return b;
  };

  const upBtn = mkBtn('arrow-up', 'Parent directory', () => sftpNavigateUp(tabId), 'Up');
  const refreshBtn = mkBtn('refresh-cw', 'Refresh', () => refreshSftpPanel(tabId, { forceFresh: true }), 'Refresh');
  const mkdirBtn = mkBtn('folder-plus', 'New folder', () => sftpMkdirPrompt(tabId), 'Folder');
  const newFileBtn = mkBtn('file-text', 'New empty file', () => sftpTouchPrompt(tabId), 'File');
  const bookmarkBtn = mkBtn('star', 'Bookmarks', (ev) => openBookmarkMenu(ev, tabId), 'Bookmarks');
  const searchBtn = mkBtn('search', 'Search recursively (in current tree)', () => toggleSearchBar(tabId), 'Search');
  const hiddenBtn = mkBtn('eye', 'Show/hide dotfiles', () => {
    const tab = sftpTabState(sftpTab(tabId));
    tab.showHidden = !tab.showHidden;
    hiddenBtn.classList.toggle('active', tab.showHidden);
    // Client-side re-filter only: sftp_list_dir already returned the hidden
    // entries (the server doesn't filter them), so this never needs a
    // network round trip - just re-run the existing cached listing.
    renderEntries(tabId);
    if (typeof sftpCmpAfterRefresh === 'function') sftpCmpAfterRefresh(tabId);
  }, 'Hidden');
  const dualBtn = mkBtn('folder-open', 'Toggle local pane', () => toggleDualPane(tabId), 'Dual');
  const colsBtn = mkBtn('settings', 'Show/hide permissions & owner columns', () => {
    const tab = sftpTabState(sftpTab(tabId));
    tab.showOwnerCols = !tab.showOwnerCols;
    colsBtn.classList.toggle('active', tab.showOwnerCols);
    panel.classList.toggle('show-owner-cols', tab.showOwnerCols);
    state.settings = state.settings || {};
    state.settings.sftpShowOwnerCols = tab.showOwnerCols ? '1' : '0';
    call('settings_set', { key: 'sftpShowOwnerCols', value: tab.showOwnerCols ? '1' : '0' }).catch(() => {});
  }, 'Columns');
  const logBtn = mkBtn('history', 'Activity log', () => {
    const log = document.getElementById('sftpLog-' + tabId);
    if (log) log.hidden = !log.hidden;
  }, 'Log');
  {
    const t = sftpTabState(sftpTab(tabId));
    if (t && t.showHidden) hiddenBtn.classList.add('active');
    if (t && t.showOwnerCols) colsBtn.classList.add('active');
  }
  panel.classList.toggle('show-owner-cols', !!(sftpTab(tabId) && sftpTab(tabId).showOwnerCols));

  toolbar.appendChild(upBtn);
  toolbar.appendChild(refreshBtn);
  toolbar.appendChild(mkdirBtn);
  toolbar.appendChild(newFileBtn);
  toolbar.appendChild(bookmarkBtn);
  toolbar.appendChild(searchBtn);
  toolbar.appendChild(hiddenBtn);
  toolbar.appendChild(colsBtn);
  toolbar.appendChild(dualBtn);
  toolbar.appendChild(logBtn);

  // ── search bar (hidden until toggled) ──
  const searchBar = document.createElement('div');
  searchBar.className = 'sftp-searchbar';
  searchBar.id = 'sftpSearchBar-' + tabId;
  searchBar.hidden = true;
  const searchInput = document.createElement('input');
  searchInput.type = 'text';
  searchInput.placeholder = 'Find in this directory tree...';
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

  // ── remote site: slim header (label + editable path + copy) + listing ──
  const remotePane = document.createElement('div');
  remotePane.className = 'sftp-pane sftp-remote';
  const remoteHead = document.createElement('div');
  remoteHead.className = 'sftp-panehead';
  const remoteTitle = document.createElement('span');
  remoteTitle.className = 'sftp-panetitle';
  remoteTitle.textContent = 'Remote site';
  const pathBox = document.createElement('input');
  pathBox.className = 'sftp-path';
  pathBox.id = 'sftpPath-' + tabId;
  pathBox.placeholder = '/remote/path - Enter to navigate';
  pathBox.spellcheck = false;
  pathBox.autocomplete = 'off';
  pathBox.addEventListener('keydown', (ev) => {
    if (ev.key === 'Enter') { ev.preventDefault(); sftpUiNavigateRemote(tabId, pathBox.value.trim()); }
    else if (ev.key === 'Escape') { pathBox.value = sftpTab(tabId)?.sftpPath || ''; pathBox.blur(); }
  });
  pathBox.addEventListener('focus', () => pathBox.select());
  const remoteCopy = mkPathCopy(() => sftpTab(tabId)?.sftpPath || '');
  remoteHead.appendChild(remoteTitle);
  remoteHead.appendChild(pathBox);
  remoteHead.appendChild(remoteCopy);

  const table = document.createElement('table');
  table.className = 'sftp-table';
  const thead = document.createElement('thead');
  thead.innerHTML = `
    <tr>
      <th data-sort="name">Name</th>
      <th data-sort="size">Size</th>
      <th data-sort="modified">Modified</th>
      <th data-sort="permissions" class="col-extra">Permissions</th>
      <th data-sort="owner" class="col-extra">Owner</th>
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
  const tableWrap = document.createElement('div');
  tableWrap.className = 'sftp-tablewrap';
  tableWrap.appendChild(table);
  remotePane.appendChild(remoteHead);
  remotePane.appendChild(tableWrap);

  // Quick-find indicator (Task 8): hidden until the user types with a row
  // focused; positioned over the pane (not the scrolling tablewrap) so it
  // stays put regardless of scroll/virtualization state.
  const quickFind = document.createElement('div');
  quickFind.className = 'sftp-quickfind';
  quickFind.id = 'sftpQuickFind-' + tabId;
  quickFind.hidden = true;
  remotePane.appendChild(quickFind);

  // All row interaction (click/dblclick/keydown/contextmenu/dragstart,
  // including the empty-area click-clears-selection case) is delegated once
  // here rather than attached per-row - see sftpWireTbodyDelegation.
  sftpWireTbodyDelegation(tabId);

  // ── local pane (dual mode): slim header with editable path + listing ──
  const localPane = document.createElement('div');
  localPane.className = 'sftp-pane sftp-local';
  localPane.id = 'sftpLocalPane-' + tabId;
  localPane.hidden = true;
  const localHead = document.createElement('div');
  localHead.className = 'sftp-panehead';
  const localTitle = document.createElement('span');
  localTitle.className = 'sftp-panetitle';
  localTitle.textContent = 'Local site';
  const localUp = mkBtn('arrow-up', 'Parent directory', () => localNavigateUp(tabId), 'Up');
  const localHome = mkBtn('folder', 'Home', () => {
    const tab = sftpTab(tabId);
    tab.localPath = '';
    refreshLocalPane(tabId);
  }, 'Home');
  const localPath = document.createElement('input');
  localPath.className = 'sftp-path';
  localPath.id = 'sftpLocalPath-' + tabId;
  localPath.placeholder = 'Local path - Enter to navigate';
  localPath.spellcheck = false;
  localPath.autocomplete = 'off';
  localPath.addEventListener('keydown', (ev) => {
    if (ev.key === 'Enter') { ev.preventDefault(); sftpUiNavigateLocal(tabId, localPath.value.trim()); }
    else if (ev.key === 'Escape') { localPath.value = sftpTab(tabId)?.localPath || ''; localPath.blur(); }
  });
  localPath.addEventListener('focus', () => localPath.select());
  const localCopy = mkPathCopy(() => sftpTab(tabId)?.localPath || '');
  // Task 6: remember the local pane's current directory as this server's
  // default so future SFTP sessions with it open here instead of home.
  const localSetDefault = mkBtn('star', 'Set as default local directory for this server', () => sftpSetLocalDirDefault(tabId), null);
  localHead.appendChild(localTitle);
  localHead.appendChild(localUp);
  localHead.appendChild(localHome);
  localHead.appendChild(localPath);
  localHead.appendChild(localCopy);
  localHead.appendChild(localSetDefault);
  const localTable = document.createElement('table');
  localTable.className = 'sftp-table';
  const localThead = document.createElement('thead');
  localThead.innerHTML = `<tr><th>Name</th><th>Size</th><th>Modified</th><th class="col-extra">Permissions</th><th class="col-extra">Owner</th></tr>`;
  const localBody = document.createElement('tbody');
  localBody.id = 'sftpLocalTbody-' + tabId;
  localTable.appendChild(localThead);
  localTable.appendChild(localBody);
  const localWrap = document.createElement('div');
  localWrap.className = 'sftp-tablewrap';
  localWrap.appendChild(localTable);
  localPane.appendChild(localHead);
  localPane.appendChild(localWrap);
  // Local pane has no sort/selection UI (never did) - just the two
  // delegated listeners it already had per-row (dblclick, dragstart).
  sftpWireLocalTbodyDelegation(tabId);

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

  const panes = document.createElement('div');
  panes.className = 'sftp-panes';
  panes.appendChild(localPane);
  panes.appendChild(splitter);
  panes.appendChild(remotePane);

  // ── drop overlay ──
  // Hidden by default; appears only while a drag hovers the panel (wireSftpDrop
  // toggles the .dragover class). No permanent strip - the panes keep full height.
  const panesWrap = document.createElement('div');
  panesWrap.className = 'sftp-paneswrap';
  const hint = document.createElement('div');
  hint.className = 'sftp-drop-hint';
  hint.textContent = 'Drop files to upload to the current remote directory';
  panesWrap.appendChild(panes);
  panesWrap.appendChild(hint);

  // ── status bar ──
  const statusBar = document.createElement('div');
  statusBar.className = 'sftp-statusbar';
  statusBar.id = 'sftpStatusBar-' + tabId;
  const statLeft = document.createElement('span');
  statLeft.className = 'sftp-status-left';
  statLeft.id = 'sftpStatusLeft-' + tabId;
  const statFs = document.createElement('span');
  statFs.className = 'sftp-fsinfo';
  statFs.id = 'sftpFsInfo-' + tabId; // relocated here from the toolbar; id kept for updateFsInfo
  statusBar.appendChild(statLeft);
  statusBar.appendChild(statFs);

  panel.appendChild(toolbar);
  panel.appendChild(searchBar);
  panel.appendChild(panesWrap);
  panel.appendChild(log);
  panel.appendChild(statusBar);

  wireSftpDrop(panel, tabId, hint);
  wireSftpPaneDnd(tabId);
  ensureSftpPreserveTsToggle(tabId);
  return panel;
}

// ─── preserve-timestamps toggle (FileZilla: "Preserve timestamps of
// transferred files") ────────────────────────────────────────────────────────

/// Idempotent: append the toggle next to the hidden-files button if absent
/// (never restructure the toolbar - G owns that block; this appends only).
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

// ─── UI helpers: entry icons, editable path bars, status bar ─────────────────

/// Lucide folder/file icon span for listing rows (replaces 📁/📄 emoji).
/// `isLink` overlays a small corner badge (CSS ::after, see .sftp-eicon.is-link
/// in styles.css) - SSH_FXP_READDIR/lstat already told us it's a symlink, so
/// the badge is free; what it points AT is resolved lazily on interaction,
/// never here (see sftpResolveSymlink / sftpActivateEntry).
function sftpEntryIcon(isDir, isLink) {
  const span = document.createElement('span');
  span.className = 'sftp-eicon' + (isDir ? ' is-dir' : '') + (isLink ? ' is-link' : '');
  span.innerHTML = ico(isDir ? 'folder' : 'file-text');
  return span;
}

/// Validate a remote path candidate: '/'-prefixed, no empty segments.
function sftpUiNormalizeRemotePath(input) {
  if (!input || !input.startsWith('/')) return null;
  const parts = input.split('/').filter(Boolean);
  const rebuilt = '/' + parts.join('/');
  return { path: rebuilt === '/' ? '/' : rebuilt, parts };
}

/// Enter in the remote path box: navigate; on failure toast and revert.
async function sftpUiNavigateRemote(tabId, input) {
  const tab = sftpTab(tabId);
  const box = document.getElementById('sftpPath-' + tabId);
  if (!tab || !box) return;
  const norm = sftpUiNormalizeRemotePath(input);
  if (!norm) {
    toast('Remote paths must start with /', 'err');
    box.value = tab.sftpPath || '/';
    return;
  }
  if (norm.path === tab.sftpPath) { box.value = tab.sftpPath; return; }
  const prev = tab.sftpPath;
  tab.sftpPath = norm.path;
  try {
    // Cache-aware: a short-TTL hit skips the round trip entirely (Task 6).
    const cached = sftpCacheGet(tab, norm.path);
    let entries, canonicalPath;
    if (cached) {
      entries = cached.entries;
      canonicalPath = cached.path;
    } else {
      const r = await sftpCall('sftp_list_dir', { sessionId: tab.sessionId, path: norm.path });
      entries = r.entries || [];
      canonicalPath = r.path || norm.path;
      sftpCacheSet(tab, norm.path, entries, canonicalPath);
    }
    tab.sftpPath = canonicalPath;
    sftpSetEntries(tab, entries);
    tab._quickFind = ''; // navigating away drops an in-progress quick-find
    box.value = tab.sftpPath;
    renderEntries(tabId);
    if (tab.dualPane) refreshLocalPane(tabId);
    updateFsInfo(tabId);
  } catch (e) {
    tab.sftpPath = prev;
    box.value = prev;
    toast(e.message || String(e), 'err');
  }
}

/// Enter in the local path box: navigate; on failure toast and revert.
async function sftpUiNavigateLocal(tabId, input) {
  const tab = sftpTab(tabId);
  const box = document.getElementById('sftpLocalPath-' + tabId);
  if (!tab || !box || !input) return;
  if (input === tab.localPath) { box.value = tab.localPath; return; }
  const prev = tab.localPath;
  tab.localPath = input;
  try {
    await sftpUiLocalLoad(tabId); // adopts the canonical path + renders
  } catch (e) {
    tab.localPath = prev;
    box.value = prev || '';
    toast(e.message || String(e), 'err');
  }
}

/// Recompute the status-bar text (counts / selection / local count) for a tab.
function sftpUpdateStatusBar(tabId) {
  const tab = sftpTab(tabId);
  const el = document.getElementById('sftpStatusLeft-' + tabId);
  if (!tab || !el) return;
  sftpTabState(tab);
  // Hidden-filtered count (quick-find intentionally excluded - its own
  // indicator shows "matched of shown"; this line is "how big is this dir").
  const total = tab._sortedEntries
    ? tab._sortedEntries.length
    : (tab._entries || []).filter(e => tab.showHidden || !e.name.startsWith('.')).length;
  // O(1) lookups (Task 5) - was entries.find() per selected item, O(n) each,
  // so select-all on a 10k-entry directory was ~10^8 string comparisons.
  const map = tab._entryMap || new Map((tab._entries || []).map(e => [e.name, e]));
  const sel = tab.sftpSelected ? [...tab.sftpSelected] : [];
  let text;
  if (sel.length) {
    let size = 0, unknown = false;
    for (const n of sel) {
      const ent = map.get(n);
      if (!ent) continue;
      if (ent.isDir || ent.size == null) unknown = true;
      else size += ent.size;
    }
    const sizeStr = unknown && size ? `${formatSftpSize(size)}+` : formatSftpSize(size);
    text = `${total} item${total === 1 ? '' : 's'} · ${sel.length} selected · ${sizeStr}`;
  } else {
    text = `${total} item${total === 1 ? '' : 's'}`;
  }
  if (tab.dualPane) {
    // _localEntries is the cached local-entry ARRAY (see sftpUiLocalLoad).
    const localTotal = (tab._localEntries || []).length;
    if (localTotal) text += ` · local: ${localTotal} item${localTotal === 1 ? '' : 's'}`;
  }
  el.textContent = text;
}

// ─── entry rendering (remote) ───────────────────────────────────────────────

function clearSelection(tabId) {
  const tab = sftpTab(tabId);
  if (!tab) return;
  sftpTabState(tab);
  tab.sftpSelected.clear();
  const tbody = document.getElementById('sftpTbody-' + tabId);
  if (tbody) for (const r of tbody.querySelectorAll('.sftp-entry.selected')) r.classList.remove('selected');
  sftpUpdateStatusBar(tabId);
}

function toggleRowSelected(tr, on) {
  tr.classList.toggle('selected', on);
}

// ─── directory listing cache (Task 6) ───────────────────────────────────────
//
// Short-TTL, per-tab, per-path cache so back/forward navigation (Up, a
// bookmark, synchronized browsing, a search-result click) doesn't re-pay a
// full SSH_FXP_READDIR round trip when the directory was just seen. Never
// trusted past a mutation: mkdir/touch/rename/delete/chmod all force a fresh
// read of the directory they touched (refreshSftpPanel's forceFresh option -
// see openSftpFileMenu, sftpMkdirPrompt, sftpTouchPrompt, sftpRenamePrompt,
// openChmodDialog); a cross-directory move (drag a remote row onto another
// remote directory) additionally invalidates the drop target explicitly,
// since that directory isn't the one being refreshed. The queue-completion
// listener below drops a tab's whole cache whenever a transfer finishes for
// it, and the session-disconnect hook further down drops it on disconnect so
// a later reconnect can never surface a listing read under the old session.
// The explicit Refresh toolbar button always passes forceFresh too. A stale
// listing after a delete is worse than a slow one - when in doubt, invalidate.

const SFTP_DIR_CACHE_TTL_MS = 12000;

function sftpCacheGet(tab, path) {
  const hit = tab._dirCache && tab._dirCache.get(path);
  if (!hit) return null;
  if (Date.now() - hit.ts > SFTP_DIR_CACHE_TTL_MS) { tab._dirCache.delete(path); return null; }
  return hit;
}

function sftpCacheSet(tab, path, entries, canonicalPath) {
  if (!tab._dirCache) tab._dirCache = new Map();
  tab._dirCache.set(path, { entries, path: canonicalPath, ts: Date.now() });
}

function sftpCacheInvalidate(tab, path) {
  if (tab && tab._dirCache) tab._dirCache.delete(path);
}

function sftpCacheInvalidateAll(tab) {
  if (tab && tab._dirCache) tab._dirCache.clear();
}

/// Replace a tab's full entry list and rebuild the name→entry index used for
/// O(1) lookups elsewhere (status bar totals/sizes - Task 5 - row activation,
/// the context menu, drag payloads) instead of re-scanning the array per
/// lookup.
function sftpSetEntries(tab, entries) {
  tab._entries = entries || [];
  tab._entryMap = new Map(tab._entries.map(e => [e.name, e]));
}

// A finished transfer (upload/download/server-copy) landing in a directory
// makes any cached listing of it stale. Rather than track exactly which
// directory each job's destination was, drop the WHOLE per-tab cache for
// every session id a finished job touches (its own sessionId, and -
// for a "Send to" server copy - targetSessionId too). Cheap (a Map.clear())
// and errs toward freshness. This registers its OWN 'sftp-queue' listener,
// independent of the transfer-queue panel's (wireQueueEvents) - Tauri
// supports multiple listeners per event, so this never has to touch that
// code. sftpCacheInvalidatedJobIds dedupes so a job resent across repeated
// snapshot broadcasts doesn't re-clear the cache indefinitely.
const sftpCacheInvalidatedJobIds = new Set();
function sftpWireQueueCacheInvalidation() {
  sftpListen('sftp-queue', (ev) => {
    for (const j of ev.payload.jobs || []) {
      if (j.state !== 'done' || sftpCacheInvalidatedJobIds.has(j.id)) continue;
      if (sftpCacheInvalidatedJobIds.size > 5000) sftpCacheInvalidatedJobIds.clear();
      sftpCacheInvalidatedJobIds.add(j.id);
      for (const t of state.sessions.values()) {
        if (t.sessionId === j.sessionId || t.sessionId === j.targetSessionId) sftpCacheInvalidateAll(t);
      }
    }
  }).catch(() => {});
}
sftpWireQueueCacheInvalidation();

// ─── cache disposal on disconnect (Task 6) ──────────────────────────────────
//
// onSessionClosed (defined in app.js, invoked by terminal.js when a session
// drops - server-side hangup or the Disconnect button) keeps the SAME tab
// object alive so Reconnect can reuse it; only tab.sftpReady/tab.sessionId
// reset. Left alone, tab._dirCache would survive the disconnect intact, and
// a reconnect (a new sessionId - possibly even a different account/keypair
// against the same host) could then serve a listing read under the OLD
// session. sftp.js loads after app.js assigns window.onSessionClosed (see
// the module doc comment at the top of this file), so wrapping it here -
// rather than editing app.js, which is off-limits - always captures the
// real handler first and still runs it.
//
// An outright tab CLOSE needs no equivalent hook: closeSessionTab and
// clearConnectView (both in app.js) delete the tab from state.sessions
// outright, and _dirCache lives only on that now-unreferenced tab object,
// so it is dropped for free once the object is garbage collected - nothing
// else in this file indexes the cache by tabId independently of the tab.
const sftpPrevOnSessionClosed = window.onSessionClosed;
window.onSessionClosed = function sftpOnSessionClosedWithCacheDrop(tabId) {
  const tab = sftpTab(tabId);
  if (tab) sftpCacheInvalidateAll(tab);
  if (typeof sftpPrevOnSessionClosed === 'function') sftpPrevOnSessionClosed(tabId);
};

async function refreshSftpPanel(tabId, opts = {}) {
  const tab = sftpTab(tabId);
  if (!tab) return;
  sftpTabState(tab);
  const tbody = document.getElementById('sftpTbody-' + tabId);
  if (!tbody) return;
  const path = tab.sftpPath;
  try {
    const cached = !opts.forceFresh && sftpCacheGet(tab, path);
    let entries, canonicalPath;
    if (cached) {
      entries = cached.entries;
      canonicalPath = cached.path;
    } else {
      const r = await sftpCall('sftp_list_dir', { sessionId: tab.sessionId, path });
      entries = r.entries || [];
      canonicalPath = r.path || path;
      sftpCacheSet(tab, path, entries, canonicalPath);
    }
    tab.sftpPath = canonicalPath;
    sftpSetEntries(tab, entries);
    tab._quickFind = ''; // a fresh listing drops an in-progress quick-find
    const pathBox = document.getElementById('sftpPath-' + tabId);
    if (pathBox && document.activeElement !== pathBox) pathBox.value = tab.sftpPath;
    renderEntries(tabId);
    if (tab.dualPane) refreshLocalPane(tabId);
    if (typeof sftpCmpAfterRefresh === 'function') sftpCmpAfterRefresh(tabId);
    if (typeof sftpCmpEnsureButtons === 'function') sftpCmpEnsureButtons(tabId);
    updateFsInfo(tabId);
  } catch (e) {
    toast(e.message || String(e), 'err');
  }
}

/// Hidden-filtered + sorted view of a tab's full entry list. Stashed on
/// tab._sortedEntries (the status bar's "total" count is read off it) so
/// quick-find (Task 8) can filter on top of it per keystroke without
/// re-sorting the whole directory every time.
function sftpComputeSortedEntries(tab) {
  const entries = (tab._entries || []).filter(e => tab.showHidden || !e.name.startsWith('.'));
  const key = tab.sortKey, desc = tab.sortDesc;
  entries.sort((a, b) => {
    if (a.isDir !== b.isDir) return a.isDir ? -1 : 1; // dirs always first
    let c = 0;
    if (key === 'size') c = (a.size || 0) - (b.size || 0);
    else if (key === 'modified') c = (a.modifiedMs || 0) - (b.modifiedMs || 0);
    else if (key === 'permissions') c = (a.permissions ?? -1) - (b.permissions ?? -1);
    else if (key === 'owner') {
      const au = a.uid ?? -1, ag = a.gid ?? -1, bu = b.uid ?? -1, bg = b.gid ?? -1;
      c = au - bu || ag - bg;
    } else c = a.name.toLowerCase().localeCompare(b.name.toLowerCase());
    return desc ? -c : c;
  });
  tab._sortedEntries = entries;
  return entries;
}

/// Type-to-filter (Task 8): a plain substring match layered on top of the
/// sorted list above. Deliberately separate from the recursive server-side
/// search bar (runSearch) - this only ever filters the CURRENT listing.
function sftpApplyQuickFind(tab, sorted) {
  const q = (tab._quickFind || '').toLowerCase();
  if (!q) return sorted;
  return sorted.filter(e => e.name.toLowerCase().includes(q));
}

function sftpUpdateQuickFindIndicator(tabId, totalShown, matched) {
  const box = document.getElementById('sftpQuickFind-' + tabId);
  const tab = sftpTab(tabId);
  if (!box || !tab) return;
  const q = tab._quickFind || '';
  if (!q) { box.hidden = true; return; }
  box.hidden = false;
  box.textContent = `Filter: "${q}" - ${matched} of ${totalShown}`;
}

/// Sync .selected onto whatever rows are CURRENTLY mounted. With windowing
/// (Task 4) that may be fewer than the full selection - rows outside the
/// window pick up the class from tab.sftpSelected the next time they're
/// built (sftpBuildRemoteRow checks it), so nothing is lost, just deferred.
function sftpRefreshSelectionClasses(tabId) {
  const tab = sftpTab(tabId);
  const tbody = document.getElementById('sftpTbody-' + tabId);
  if (!tab || !tbody) return;
  for (const row of tbody.querySelectorAll('tr.sftp-entry')) {
    toggleRowSelected(row, tab.sftpSelected.has(row.dataset.name));
  }
}

/// Re-focus the row the user was on after a re-render tears down and rebuilds
/// the DOM (rows are replaced wholesale, never patched in place - see
/// sftpRenderRows). Without this, removing a focused row drops focus to
/// <body>, and every handler above - being delegated to the tbody - would
/// stop receiving keystrokes after a single keypress. While quick-find is
/// active this doubles as "jump to the first match" (classic type-ahead).
function sftpRestoreRowFocus(tabId, tbody, visible) {
  const tab = sftpTab(tabId);
  if (!tab) return;
  const targetName = tab._quickFind ? (visible[0] && visible[0].name) : tab._focusedName;
  if (!targetName) return;
  const row = tbody.querySelector(`tr[data-name="${CSS.escape(targetName)}"]`);
  if (!row) return;
  tab._focusedName = targetName;
  row.focus({ preventScroll: !tab._quickFind });
  if (tab._quickFind) row.scrollIntoView({ block: 'nearest' });
}

/// Size cell for one row. Files: formatted byte count. Directories: a muted
/// placeholder until "Calculate size" (Task 9, context menu) has run for
/// this row - then a spinner while sftp_dir_size is in flight, then the
/// result (a "+"-suffixed floor, with an explanatory tooltip, when the walk
/// hit its cap rather than presenting a wrong exact total).
function sftpFillSizeCell(td, entry) {
  if (!entry.isDir) {
    td.className = '';
    td.title = '';
    td.textContent = formatSftpSize(entry.size);
    return;
  }
  const sz = entry._dirSize;
  if (sz && sz.state === 'pending') {
    td.className = 'sftp-dirsize';
    td.textContent = '';
    const sp = document.createElement('span');
    sp.className = 'sftp-spinner';
    td.appendChild(sp);
    td.title = 'Calculating size...';
  } else if (sz && sz.state === 'done') {
    td.className = 'sftp-dirsize sftp-dirsize-done';
    td.textContent = sz.truncated ? `${formatSftpSize(sz.bytes)}+` : formatSftpSize(sz.bytes);
    td.title = sz.truncated
      ? `Stopped at the walk's cap (50,000 entries / 120s) - actual size is at least this much. ${sz.files} file(s), ${sz.dirs} folder(s) scanned.`
      : `${sz.files} file(s), ${sz.dirs} folder(s)`;
  } else if (sz && sz.state === 'error') {
    td.className = 'sftp-dirsize';
    td.textContent = 'Error';
    td.title = sz.error || 'Could not calculate size.';
  } else {
    td.className = 'sftp-dirsize';
    td.textContent = '-';
    td.title = 'Directory - right-click -> Calculate size';
  }
}

/// Build one remote-pane <tr>. No per-row listeners live here - every
/// interaction is delegated to the tbody once (sftpWireTbodyDelegation); this
/// only sets the classes/dataset those delegated handlers key off of.
function sftpBuildRemoteRow(tab, entry) {
  const tr = document.createElement('tr');
  tr.dataset.isdir = entry.isDir ? '1' : '0';
  tr.dataset.islink = entry.isLink ? '1' : '0';
  tr.dataset.name = entry.name;
  tr.className = entry.isDir ? 'sftp-entry sftp-dir' : 'sftp-entry sftp-file';
  tr.tabIndex = 0;
  tr.draggable = true;
  tr.title = entry.isLink
    ? 'Symlink - double-click to resolve and open'
    : entry.isDir ? 'Double-click to open folder' : 'Double-click to download';
  if (tab.sftpSelected.has(entry.name)) tr.classList.add('selected');

  const tdName = document.createElement('td');
  tdName.className = 'sftp-tdname';
  tdName.appendChild(sftpEntryIcon(entry.isDir, entry.isLink));
  tdName.appendChild(document.createTextNode(entry.name));

  const tdSize = document.createElement('td');
  sftpFillSizeCell(tdSize, entry);

  const tdMod = document.createElement('td');
  tdMod.textContent = entry.modifiedMs ? fmtTime(new Date(entry.modifiedMs).toISOString()) : '-';

  const tdPerm = document.createElement('td');
  tdPerm.className = 'sftp-permcell col-extra';
  tdPerm.textContent = formatMode(entry.permissions);
  if (entry.permissions != null) tdPerm.title = '0' + (entry.permissions & 0o7777).toString(8);

  const tdOwner = document.createElement('td');
  tdOwner.className = 'sftp-ownercell col-extra';
  tdOwner.textContent = (entry.uid == null && entry.gid == null) ? '—' : `${entry.uid ?? '?'}:${entry.gid ?? '?'}`;

  tr.appendChild(tdName); tr.appendChild(tdSize); tr.appendChild(tdMod);
  tr.appendChild(tdPerm); tr.appendChild(tdOwner);
  return tr;
}

// ─── windowed rendering (Task 4) ────────────────────────────────────────────
//
// Below the threshold, just render every row - simplest, and correct for the
// overwhelming common case (per-task guidance: don't virtualize what doesn't
// need it). Above it, keep only the scrolled window of rows (plus a buffer)
// mounted, framed by up to two spacer <tr>s that hold the scrollbar's total
// height. Row height is measured off the first real row actually rendered
// (font/zoom-dependent) rather than assumed, with a fallback constant for the
// very first paint. No absolute positioning, no library - just two spacers.

const SFTP_VIRTUALIZE_THRESHOLD = 300;
const SFTP_ROW_BUFFER = 8;
const SFTP_DEFAULT_ROW_H = 31;

/// Render `entries` into `tbody`. `buildRowFn(entry)` builds one <tr>;
/// `colCount` sizes the spacer rows' single spanning <td>.
function sftpRenderRows(tbody, entries, buildRowFn, colCount) {
  const wrap = tbody.closest('.sftp-tablewrap');
  if (entries.length <= SFTP_VIRTUALIZE_THRESHOLD) {
    sftpTeardownWindow(tbody);
    tbody.innerHTML = '';
    const frag = document.createDocumentFragment();
    for (const e of entries) frag.appendChild(buildRowFn(e));
    tbody.appendChild(frag);
    return;
  }
  let win = tbody._sftpWin;
  if (!win) {
    win = tbody._sftpWin = { rowH: SFTP_DEFAULT_ROW_H, measured: false };
    win.onScroll = () => sftpReflowWindow(tbody);
    if (wrap) wrap.addEventListener('scroll', win.onScroll);
    if (wrap && typeof ResizeObserver !== 'undefined') {
      win.ro = new ResizeObserver(() => sftpReflowWindow(tbody));
      win.ro.observe(wrap);
    }
  }
  win.entries = entries;
  win.buildRowFn = buildRowFn;
  win.colCount = colCount;
  win.lastRange = null; // force a full rebuild of the visible slice
  sftpReflowWindow(tbody);
}

function sftpTeardownWindow(tbody) {
  const win = tbody._sftpWin;
  if (!win) return;
  const wrap = tbody.closest('.sftp-tablewrap');
  if (wrap && win.onScroll) wrap.removeEventListener('scroll', win.onScroll);
  if (win.ro) win.ro.disconnect();
  tbody._sftpWin = null;
}

function sftpMakeSpacerRow(heightPx, colCount) {
  const tr = document.createElement('tr');
  tr.className = 'sftp-winspacer';
  tr.style.height = heightPx + 'px';
  const td = document.createElement('td');
  td.colSpan = colCount || 1;
  tr.appendChild(td);
  return tr;
}

function sftpReflowWindow(tbody) {
  const win = tbody._sftpWin;
  const wrap = tbody.closest('.sftp-tablewrap');
  if (!win || !wrap) return;
  const entries = win.entries;
  const total = entries.length;
  const viewportH = wrap.clientHeight || 400;
  let start = Math.floor(wrap.scrollTop / win.rowH) - SFTP_ROW_BUFFER;
  let end = Math.ceil((wrap.scrollTop + viewportH) / win.rowH) + SFTP_ROW_BUFFER;
  start = Math.max(0, start);
  end = Math.min(total, Math.max(start, end));
  if (win.lastRange && win.lastRange.start === start && win.lastRange.end === end) return;
  win.lastRange = { start, end };

  tbody.innerHTML = '';
  const topH = start * win.rowH;
  const bottomH = (total - end) * win.rowH;
  if (topH > 0) tbody.appendChild(sftpMakeSpacerRow(topH, win.colCount));
  const frag = document.createDocumentFragment();
  for (let i = start; i < end; i++) frag.appendChild(win.buildRowFn(entries[i]));
  tbody.appendChild(frag);
  if (!win.measured) {
    const first = tbody.querySelector('tr.sftp-entry');
    if (first) {
      const h = first.getBoundingClientRect().height;
      if (h > 4) { win.rowH = h; win.measured = true; }
    }
  }
  if (bottomH > 0) tbody.appendChild(sftpMakeSpacerRow(bottomH, win.colCount));
}

function renderEntries(tabId) {
  const tab = sftpTab(tabId);
  if (!tab || !tab._entries) return;
  const tbody = document.getElementById('sftpTbody-' + tabId);
  if (!tbody) return;
  sftpWireTbodyDelegation(tabId); // idempotent - the panel already wires this once
  const thead = tbody.parentElement.querySelector('thead');
  if (thead) {
    for (const th of thead.querySelectorAll('th[data-sort]')) {
      th.classList.toggle('sorted', th.dataset.sort === tab.sortKey);
      th.classList.toggle('desc', th.dataset.sort === tab.sortKey && tab.sortDesc);
    }
  }
  tab.sftpSelected = tab.sftpSelected || new Set();
  // Keep only selections still present (against the FULL entry list, not
  // just what's hidden-filtered/quick-found/currently mounted).
  for (const n of [...tab.sftpSelected]) if (!tab._entryMap || !tab._entryMap.has(n)) tab.sftpSelected.delete(n);

  const sorted = sftpComputeSortedEntries(tab);
  const visible = sftpApplyQuickFind(tab, sorted);
  tab._visibleEntries = visible; // authoritative "all rows" for select-all/shift-range, not just what's mounted
  tab._lastClicked = null; // shift-click anchor doesn't survive a re-render (sort/filter/hidden/quick-find change)

  sftpUpdateQuickFindIndicator(tabId, sorted.length, visible.length);
  sftpRenderRows(tbody, visible, (e) => sftpBuildRemoteRow(tab, e), 5);
  sftpRestoreRowFocus(tabId, tbody, visible);
  sftpUpdateStatusBar(tabId);
}

// ─── delegated row interaction (Task 3) ─────────────────────────────────────
//
// One listener per event type, attached ONCE to the tbody, instead of five
// per row - a 20,000-entry directory used to mean ~100,000 live listeners.
// Rows carry only data-* attributes; every handler below looks the actual
// entry up by name (tab._entryMap, O(1)) rather than trusting anything wider
// parsed back off the DOM.

function sftpWireTbodyDelegation(tabId) {
  const tbody = document.getElementById('sftpTbody-' + tabId);
  if (!tbody || tbody._sftpDelegated) return;
  tbody._sftpDelegated = true;

  // Tracks which row is logically focused so sftpRestoreRowFocus can put
  // focus back after a re-render replaces the DOM out from under it.
  tbody.addEventListener('focusin', (ev) => {
    const tr = ev.target.closest('tr.sftp-entry');
    if (!tr) return;
    const tab = sftpTab(tabId);
    if (tab) tab._focusedName = tr.dataset.name;
  });

  tbody.addEventListener('click', (ev) => {
    if (ev.target === tbody) { clearSelection(tabId); return; } // empty-area click
    const tr = ev.target.closest('tr.sftp-entry');
    if (!tr) return;
    const tab = sftpTab(tabId);
    const entry = tab && tab._entryMap && tab._entryMap.get(tr.dataset.name);
    if (!tab || !entry) return;
    const visible = tab._visibleEntries || [];
    if (ev.ctrlKey || ev.metaKey) {
      if (tab.sftpSelected.has(entry.name)) tab.sftpSelected.delete(entry.name);
      else tab.sftpSelected.add(entry.name);
      tab._lastClicked = entry.name;
    } else if (ev.shiftKey && tab._lastClicked) {
      // Range select from the anchor to this entry, over the FULL visible
      // list (Task 4) - not just whatever happens to be mounted right now.
      const names = visible.map(e => e.name);
      const i0 = names.indexOf(tab._lastClicked), i1 = names.indexOf(entry.name);
      if (i0 >= 0 && i1 >= 0) {
        for (let i = Math.min(i0, i1); i <= Math.max(i0, i1); i++) tab.sftpSelected.add(names[i]);
      }
    } else {
      tab.sftpSelected.clear();
      tab.sftpSelected.add(entry.name);
      tab._lastClicked = entry.name;
    }
    tab._focusedName = entry.name;
    sftpRefreshSelectionClasses(tabId);
    sftpUpdateStatusBar(tabId);
  });

  tbody.addEventListener('dblclick', (ev) => {
    const tr = ev.target.closest('tr.sftp-entry');
    if (!tr) return;
    const tab = sftpTab(tabId);
    const entry = tab && tab._entryMap && tab._entryMap.get(tr.dataset.name);
    if (entry) sftpActivateEntry(tabId, entry);
  });

  tbody.addEventListener('contextmenu', (ev) => {
    const tr = ev.target.closest('tr.sftp-entry');
    if (!tr) return;
    ev.preventDefault();
    const tab = sftpTab(tabId);
    const entry = tab && tab._entryMap && tab._entryMap.get(tr.dataset.name);
    if (!tab || !entry) return;
    if (!tab.sftpSelected.has(entry.name)) {
      tab.sftpSelected.clear();
      tab.sftpSelected.add(entry.name);
      sftpRefreshSelectionClasses(tabId);
    }
    openSftpFileMenu(ev.clientX, ev.clientY, tabId, entry);
  });

  // Draggable to the local pane (download) or another remote dir (move).
  tbody.addEventListener('dragstart', (ev) => {
    const tr = ev.target.closest('tr.sftp-entry');
    if (!tr) return;
    const tab = sftpTab(tabId);
    const entry = tab && tab._entryMap && tab._entryMap.get(tr.dataset.name);
    if (!tab || !entry) return;
    ev.dataTransfer.setData('text/sftp-remote', JSON.stringify({
      tabId, path: sftpJoin(tab.sftpPath, entry.name), name: entry.name, isDir: !!entry.isDir,
    }));
    ev.dataTransfer.effectAllowed = 'copyMove';
  });

  tbody.addEventListener('keydown', (ev) => {
    const tab = sftpTab(tabId);
    if (!tab) return;
    const tr = ev.target.closest('tr.sftp-entry');

    if (ev.key === 'Enter' && tr) {
      const entry = tab._entryMap && tab._entryMap.get(tr.dataset.name);
      if (entry) sftpActivateEntry(tabId, entry);
      return;
    }
    if (ev.key === 'F2' && tr) {
      ev.preventDefault();
      const entry = tab._entryMap && tab._entryMap.get(tr.dataset.name);
      if (entry) sftpRenamePrompt(tabId, entry); // same code path as the context menu's Rename
      return;
    }
    if ((ev.key === 'ContextMenu' || (ev.shiftKey && ev.key === 'F10')) && tr) {
      ev.preventDefault();
      const entry = tab._entryMap && tab._entryMap.get(tr.dataset.name);
      if (entry) {
        if (!tab.sftpSelected.has(entry.name)) {
          tab.sftpSelected.clear();
          tab.sftpSelected.add(entry.name);
          sftpRefreshSelectionClasses(tabId);
        }
        const rect = tr.getBoundingClientRect();
        openSftpFileMenu(rect.left + 12, rect.top + 12, tabId, entry);
      }
      return;
    }
    if (ev.key === 'Escape') {
      if (tab._quickFind) { ev.preventDefault(); tab._quickFind = ''; renderEntries(tabId); }
      return;
    }
    // Type-to-filter (Task 8): a single printable character with no modifier
    // starts/extends the quick-find. Starting a fresh session (was empty)
    // scrolls to the top first so the first match is guaranteed mounted for
    // sftpRestoreRowFocus to jump to.
    if (ev.key && ev.key.length === 1 && !ev.ctrlKey && !ev.metaKey && !ev.altKey) {
      ev.preventDefault();
      if (!tab._quickFind) {
        const wrap = tbody.closest('.sftp-tablewrap');
        if (wrap) wrap.scrollTop = 0;
      }
      tab._quickFind = (tab._quickFind || '') + ev.key;
      renderEntries(tabId);
    }
  });
}

/// Activate a row (Enter / double-click): navigate into a directory, download
/// a file, or - for a symlink - resolve it FIRST (lazily, on demand; never
/// during listing render, see sftpEntryIcon's doc comment) and then do
/// whichever of those two the target turns out to be. A dangling link toasts
/// and does nothing else (Task 1).
function sftpActivateEntry(tabId, entry) {
  const tab = sftpTab(tabId);
  if (!tab) return;
  const full = sftpJoin(tab.sftpPath, entry.name);
  if (entry.isLink) {
    sftpResolveSymlink(tabId, full).then(r => {
      if (!r || r.ok === false) {
        toast(`Could not resolve "${entry.name}": ${(r && r.error) || 'unknown error'}`, 'err');
        return;
      }
      sftpMarkLinkRow(tabId, entry.name, !!r.broken);
      if (r.broken) {
        toast(`"${entry.name}" is a broken symlink - its target doesn't exist.`, 'warn');
        return;
      }
      if (r.isDir) {
        if (typeof sftpSyncRemoteNav === 'function' && sftpSyncRemoteNav(tabId, entry.name)) return;
        tab.sftpPath = full;
        refreshSftpPanel(tabId);
      } else {
        queueDownloads(tabId, [full]);
      }
    });
    return;
  }
  if (entry.isDir) {
    if (typeof sftpSyncRemoteNav === 'function' && sftpSyncRemoteNav(tabId, entry.name)) return;
    tab.sftpPath = full;
    refreshSftpPanel(tabId);
  } else {
    // Queue the download to the last-used local dir (or temp dir).
    queueDownloads(tabId, [full]);
  }
}

/// Resolve a symlink's target (sftp_resolve_link), on demand, once - cached
/// per path so re-activating the same link never re-pays the round trip.
/// NEVER called while rendering a listing (that would cost one round trip
/// per link in a link-heavy directory) - only from user interaction. A
/// broken link comes back as `{ok:true, broken:true}` from the backend, not
/// as a thrown error.
function sftpResolveSymlink(tabId, fullPath) {
  const tab = sftpTab(tabId);
  if (!tab) return Promise.resolve(null);
  if (!tab._linkCache) tab._linkCache = new Map();
  if (tab._linkCache.has(fullPath)) return Promise.resolve(tab._linkCache.get(fullPath));
  if (!tab._linkPending) tab._linkPending = new Map();
  if (tab._linkPending.has(fullPath)) return tab._linkPending.get(fullPath);
  const p = sftpCall('sftp_resolve_link', { sessionId: tab.sessionId, path: fullPath })
    .then(r => { tab._linkCache.set(fullPath, r); return r; })
    .catch(e => ({ ok: false, error: e.message || String(e) }))
    .finally(() => { tab._linkPending.delete(fullPath); });
  tab._linkPending.set(fullPath, p);
  return p;
}

/// Reflect a resolved symlink's broken/ok state on its icon badge, if the row
/// happens to still be mounted (windowing may have scrolled it away by now).
function sftpMarkLinkRow(tabId, name, broken) {
  const tr = document.querySelector(`#sftpTbody-${tabId} tr[data-name="${CSS.escape(name)}"]`);
  const icon = tr && tr.querySelector('.sftp-eicon.is-link');
  if (icon) icon.classList.toggle('broken', !!broken);
}

// Ctrl+A within the panel selects all rows - the full filtered list (Task 4:
// hidden-file toggling and quick-find already narrowed tab._visibleEntries),
// not just whatever the windowed renderer currently has mounted.
document.addEventListener('keydown', (ev) => {
  if (!(ev.ctrlKey || ev.metaKey) || ev.key.toLowerCase() !== 'a') return;
  const active = sftpTab(state.activeTabId);
  if (!active || active.mode !== 'sftp') return;
  const panel = document.getElementById('sftpPanel-' + active.tabId);
  if (!panel) return;
  ev.preventDefault();
  sftpTabState(active);
  const visible = active._visibleEntries || [];
  active.sftpSelected.clear();
  for (const e of visible) active.sftpSelected.add(e.name);
  sftpRefreshSelectionClasses(active.tabId);
  sftpUpdateStatusBar(active.tabId);
});

function formatSftpSize(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  if (bytes < 1024 * 1024 * 1024) return (bytes / 1024 / 1024).toFixed(1) + ' MB';
  return (bytes / 1024 / 1024 / 1024).toFixed(2) + ' GB';
}

/// Classic `ls -l`-style mode string ("drwxr-xr-x") from a raw POSIX mode
/// (st_mode, type bits included - see the Rust-side SftpEntry doc comment).
/// Handles setuid/setgid/sticky (lower-case when the underlying x bit is
/// also set, upper-case otherwise). Null (a Windows local, or a server that
/// omitted it) renders as an em dash, never a guess.
function formatMode(mode) {
  if (mode == null) return '—';
  let typeChar;
  switch (mode & 0o170000) {
    case 0o120000: typeChar = 'l'; break; // symlink
    case 0o100000: typeChar = '-'; break; // regular file
    case 0o040000: typeChar = 'd'; break; // directory
    case 0o060000: typeChar = 'b'; break; // block device
    case 0o020000: typeChar = 'c'; break; // char device
    case 0o010000: typeChar = 'p'; break; // fifo
    case 0o140000: typeChar = 's'; break; // socket
    default: typeChar = '?';
  }
  const bits = [
    [0o400, 'r'], [0o200, 'w'], [0o100, 'x'],
    [0o040, 'r'], [0o020, 'w'], [0o010, 'x'],
    [0o004, 'r'], [0o002, 'w'], [0o001, 'x'],
  ];
  const rwx = bits.map(([bit, ch]) => (mode & bit) ? ch : '-');
  if (mode & 0o4000) rwx[2] = (mode & 0o100) ? 's' : 'S'; // setuid
  if (mode & 0o2000) rwx[5] = (mode & 0o010) ? 's' : 'S'; // setgid
  if (mode & 0o1000) rwx[8] = (mode & 0o001) ? 't' : 'T'; // sticky
  return typeChar + rwx.join('');
}

function sftpNavigateUp(tabId) {
  const tab = sftpTab(tabId);
  if (!tab) return;
  if (typeof sftpSyncRemoteUp === 'function' && sftpSyncRemoteUp(tabId)) return;
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
      await refreshSftpPanel(tabId, { forceFresh: true });
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
      await refreshSftpPanel(tabId, { forceFresh: true });
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
      el.textContent = `${free} free of ${total}${r.readOnly ? ' (read-only)' : ''}`;
    } else {
      el.textContent = '';
    }
  } catch { el.textContent = ''; }
}

// ─── context menu ───────────────────────────────────────────────────────────

// Session-scoped delete-confirmation state (classic scripts share the global
// lexical scope, so the names are sftp-prefixed on purpose).
let sftpDeleteConfirmSuppressed = false;
let sftpDeleteInFlight = false;

/// In-app delete confirmation: names the item(s), Yes / Cancel, and a
/// session-scoped "don't ask again" checkbox (never persisted - a restart
/// restores the safety prompt). Runs onYes only on Yes.
function sftpConfirmDelete(message, onYes) {
  if (sftpDeleteConfirmSuppressed) { onYes(); return; }
  el('deleteTitle').textContent = 'Delete';
  el('deleteMessage').textContent = message;
  el('deleteSkipSession').checked = false;
  el('deleteModal').hidden = false;
  const finish = (yes) => {
    el('deleteModal').hidden = true;
    // Only a confirmed delete may disarm the prompt. Reading the checkbox on
    // every exit meant ticking it and then backing out via Cancel still
    // switched the safety prompt off for the session, so the NEXT delete —
    // one the user never agreed to skip confirming — went through silently.
    if (yes && el('deleteSkipSession').checked) sftpDeleteConfirmSuppressed = true;
    document.removeEventListener('keydown', onKey, true);
    el('deleteModal').removeEventListener('click', onBackdrop);
    if (yes) onYes();
  };
  function onKey(ev) {
    if (ev.key !== 'Escape') return;
    ev.preventDefault();
    ev.stopPropagation();
    finish(false);
  }
  function onBackdrop(ev) {
    if (ev.target === el('deleteModal')) finish(false);
  }
  el('deleteYesBtn').onclick = () => finish(true);
  el('deleteCancelBtn').onclick = () => finish(false);
  // Escape and a backdrop click both mean "no" — abandoning a destructive
  // prompt must never be harder than confirming it, and both exits are the
  // safe answer. Capture phase so the dialog wins over any handler behind it.
  document.addEventListener('keydown', onKey, true);
  el('deleteModal').addEventListener('click', onBackdrop);
  // Focus Cancel, not Yes: a reflexive Enter or Space on a delete prompt must
  // not be the thing that deletes.
  setTimeout(() => el('deleteCancelBtn').focus(), 0);
}

/// Rename flow shared by the context menu's "Rename..." item and the F2
/// keyboard shortcut (Task 7) - one code path, never duplicated.
function sftpRenamePrompt(tabId, entry) {
  const tab = sftpTab(tabId);
  if (!tab) return;
  const fullPath = sftpJoin(tab.sftpPath, entry.name);
  promptModal('Rename', 'New name:', entry.name, async (newName) => {
    if (!newName || newName === entry.name) return;
    try {
      await sftpCall('sftp_rename', { sessionId: tab.sessionId, from: fullPath, to: sftpJoin(tab.sftpPath, newName) });
      sftpLog(tabId, `rename ${entry.name} → ${newName}`);
      await refreshSftpPanel(tabId, { forceFresh: true });
    } catch (e) { toast(e.message || String(e), 'err'); }
  });
}

/// On-demand recursive directory size (Task 9, context menu "Calculate
/// size"). Can take up to 120s (the walk's own server-side cap) - the size
/// cell shows a spinner meanwhile and is patched in place when it resolves,
/// without needing a full listing refresh (which would also cost a round
/// trip and could race the calculation).
async function sftpCalcDirSize(tabId, name) {
  const tab = sftpTab(tabId);
  if (!tab || !tab._entryMap) return;
  const entry = tab._entryMap.get(name);
  if (!entry || !entry.isDir) return;
  if (entry._dirSize && entry._dirSize.state === 'pending') return; // already running
  entry._dirSize = { state: 'pending' };
  sftpPatchSizeCell(tabId, name, entry);
  const fullPath = sftpJoin(tab.sftpPath, name);
  try {
    const r = await sftpCall('sftp_dir_size', { sessionId: tab.sessionId, path: fullPath });
    entry._dirSize = { state: 'done', bytes: r.bytes || 0, files: r.files || 0, dirs: r.dirs || 0, truncated: !!r.truncated };
    sftpLog(tabId, `size ${name}: ${formatSftpSize(r.bytes || 0)}${r.truncated ? '+ (capped)' : ''} (${r.files} files, ${r.dirs} dirs)`);
  } catch (e) {
    entry._dirSize = { state: 'error', error: e.message || String(e) };
    toast(`Size failed for "${name}": ${e.message || e}`, 'err');
  }
  sftpPatchSizeCell(tabId, name, entry);
}

/// Patch just the size cell of a mounted row - the row may not be mounted
/// right now (windowing scrolled it away), in which case nothing needs to
/// happen here: sftpFillSizeCell reads entry._dirSize the next time this row
/// is actually built.
function sftpPatchSizeCell(tabId, name, entry) {
  const tr = document.querySelector(`#sftpTbody-${tabId} tr[data-name="${CSS.escape(name)}"]`);
  if (!tr) return;
  const td = tr.children[1]; // name, SIZE, modified, permissions, owner
  if (td) sftpFillSizeCell(td, entry);
}

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
    mk('Download as...', 'download', () => sftpDownloadTo(tabId, fullPath, entry.name));
    mk('Open with system app', 'pencil', () => sftpOpenForEdit(tabId, fullPath, entry.name));
  }
  // Directory-only (Task 9): sftpCalcDirSize does the round trip and patches
  // the row's size cell in place - grouped with the other info/properties
  // items, ahead of Rename/Delete rather than beside them.
  if (entry.isDir) {
    mk('Calculate size', 'hard-drive', () => sftpCalcDirSize(tabId, entry.name));
  }
  mk('File permissions...', 'settings', () => openChmodDialog(tabId, multi ? selectedPaths : [fullPath], entry));
  mk(multi ? `Rename... (${selected[0]} +${selected.length - 1})` : 'Rename...', 'pencil', async () => {
    if (multi) { toast('Rename applies to a single item - select one.', 'info'); return; }
    promptModal('Rename', 'New name:', entry.name, async (newName) => {
      if (!newName || newName === entry.name) return;
      try {
        await sftpCall('sftp_rename', { sessionId: tab.sessionId, from: fullPath, to: sftpJoin(tab.sftpPath, newName) });
        sftpLog(tabId, `rename ${entry.name} → ${newName}`);
        // forceFresh (Task 6): same-directory rename, so the current dir's
        // cache entry must not be served stale - see sftpRenamePrompt (F2),
        // which this menu item duplicates for click access.
        await refreshSftpPanel(tabId, { forceFresh: true });
      } catch (e) { toast(e.message || String(e), 'err'); }
    });
  });
  mk(multi ? `Delete ${selected.length} items` : 'Delete', 'trash-2', async () => {
    const paths = selectedPaths.length ? selectedPaths : [fullPath];
    const firstName = paths[0].split('/').filter(Boolean).pop();
    const firstIsDir = (tab._entries || []).find(e => e.name === firstName)?.isDir ?? false;
    const message = paths.length === 1
      ? (firstIsDir
        ? `Are you sure you want to delete the folder "${firstName}" and everything inside it?`
        : `Are you sure you want to delete "${firstName}"?`)
      : `Are you sure you want to delete these ${paths.length} items?`;
    sftpConfirmDelete(message, async () => {
      if (sftpDeleteInFlight) { toast('A delete is already in progress - one moment.', 'info'); return; }
      sftpDeleteInFlight = true;
      toast(paths.length === 1 ? `Deleting "${firstName}"...` : `Deleting ${paths.length} items...`, 'info');
      let ok = 0, fail = 0, lastErr = null;
      for (const p of paths) {
        const name = p.split('/').filter(Boolean).pop();
        const isDir = (tab._entries || []).find(e => e.name === name)?.isDir ?? false;
        try {
          await sftpCall('sftp_remove', { sessionId: tab.sessionId, path: p, isDir });
          ok++;
        } catch (e) { fail++; lastErr = (e && (e.message || e.error)) || String(e); }
      }
      sftpDeleteInFlight = false;
      sftpLog(tabId, `delete ${ok} item(s)${fail ? `, ${fail} failed` : ''}`);
      if (fail) toast(`${ok} deleted, ${fail} failed.${lastErr ? ' ' + lastErr : ''}`, 'err');
      else if (ok) toast(paths.length === 1 ? `Deleted "${firstName}".` : `Deleted ${ok} items.`, 'ok');
      // forceFresh (Task 6): a stale listing after a delete is worse than a
      // slow one - never let this fall through to a cache hit that still
      // shows the just-deleted item(s).
      await refreshSftpPanel(tabId, { forceFresh: true });
    });
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
    sftpUpdateStatusBar(tabId);
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
    sendLabel.innerHTML = `${ico('send')}<span>Send to...</span>`;
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
    ? `Permissions - ${paths[0].split('/').filter(Boolean).pop()}`
    : `Permissions - ${paths.length} items`;

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

  const close = () => {
    modal.hidden = true;
    document.removeEventListener('keydown', onKey, true);
  };
  // Escape closes without applying, matching the backdrop click below. Capture
  // phase and stopPropagation so the keystroke cannot also reach a handler for
  // whatever is open behind this dialog.
  function onKey(ev) {
    if (ev.key !== 'Escape') return;
    ev.preventDefault();
    ev.stopPropagation();
    close();
  }
  document.addEventListener('keydown', onKey, true);
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
    sftpLog(tabId, `chmod ${toOctal()} on ${paths.length} path(s) - ${changed} changed${fail ? `, ${fail} failed` : ''}`);
    toast(fail ? `${changed} updated, ${fail} failed.` : `Permissions set (${toOctal()}).`, fail ? 'err' : 'ok');
    close();
    // forceFresh (Task 6): the Permissions column of a cached listing would
    // otherwise show the pre-chmod mode until the TTL expires.
    refreshSftpPanel(tabId, { forceFresh: true });
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
  status.textContent = 'Searching...';
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
    item.innerHTML = `<span class="sftp-eicon${p.isDir ? ' is-dir' : ''}">${ico(p.isDir ? 'folder' : 'file-text')}</span>${escapeHtml(p.path)}`;
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
  addBtn.innerHTML = `${ico('plus')}<span>Bookmark this directory...</span>`;
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
  // ── agent-e: apply persisted comparison mode + recompute when dual opens ──
  if (typeof sftpCmpApplyPersisted === 'function') sftpCmpApplyPersisted(tabId);
  // Persist the preference globally.
  state.sftpDualPane = tab.dualPane;
  call('settings_set', { key: 'sftpDualPane', value: tab.dualPane ? '1' : '0' }).catch(() => {});
}

/// Core local-pane refresh: lists, renders rows, updates path + status bar.
/// Throws on failure (callers decide whether to toast/revert).
async function sftpUiLocalLoad(tabId) {
  const tab = sftpTab(tabId);
  if (!tab) return;
  const tbody = document.getElementById('sftpLocalTbody-' + tabId);
  const pathEl = document.getElementById('sftpLocalPath-' + tabId);
  if (!tbody) return;
  const r = await sftpCall('sftp_local_list', { path: tab.localPath || '' });
  tab.localPath = r.path || tab.localPath;
  tab._localHome = r.home;
  // _localEntries is the cached ARRAY of local entries (Agent E's comparison
  // consumes it; the status bar derives the count via .length).
  tab._localEntries = r.entries || [];
  if (pathEl && document.activeElement !== pathEl) pathEl.value = tab.localPath;
  tbody.innerHTML = '';
  for (const entry of r.entries || []) {
    const tr = document.createElement('tr');
    tr.className = entry.isDir ? 'sftp-entry sftp-dir' : 'sftp-entry sftp-file';
    tr.dataset.isdir = entry.isDir ? '1' : '0';
    tr.dataset.name = entry.name;
    const tdName = document.createElement('td');
    tdName.className = 'sftp-tdname';
    tdName.appendChild(sftpEntryIcon(entry.isDir));
    tdName.appendChild(document.createTextNode(entry.name));
    const tdSize = document.createElement('td');
    if (entry.isDir) {
      tdSize.className = 'sftp-dirsize';
      tdSize.textContent = '-';
      tdSize.title = 'Directory';
    } else {
      tdSize.textContent = formatSftpSize(entry.size);
    }
    const tdMod = document.createElement('td');
    tdMod.textContent = entry.modifiedMs ? fmtTime(new Date(entry.modifiedMs).toISOString()) : '-';
    tr.appendChild(tdName); tr.appendChild(tdSize); tr.appendChild(tdMod);
    tr.addEventListener('dblclick', () => {
      if (entry.isDir) {
        if (typeof sftpSyncLocalNav === 'function' && sftpSyncLocalNav(tabId, entry.name)) return;
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
  sftpUpdateStatusBar(tabId);
  // Re-run directory comparison with the fresh local entries (no-op when the
  // pane is closed or comparison is off).
  if (typeof sftpCmpAfterRefresh === 'function') sftpCmpAfterRefresh(tabId);
}

/// Public local-pane refresh: swallows errors with a toast (existing callers).
async function refreshLocalPane(tabId) {
  try {
    await sftpUiLocalLoad(tabId);
  } catch (e) {
    // A per-server default directory (Task 6) can go stale - deleted since,
    // or remembered from a different machine sharing the same vault. Fall
    // back to the OS home directory once rather than leaving the pane stuck
    // on a path that no longer resolves on this one.
    const tab = sftpTab(tabId);
    if (tab && tab.localPath) {
      tab.localPath = '';
      try { await sftpUiLocalLoad(tabId); return; } catch (e2) { toast(e2.message || String(e2), 'err'); return; }
    }
    toast(e.message || String(e), 'err');
  }
}

/// Remember the local pane's current directory as this server's default
/// starting point (Task 6) - see sftpLocalDirKey for the settings key shape.
function sftpSetLocalDirDefault(tabId) {
  const tab = sftpTab(tabId);
  if (!tab) return;
  if (!tab.localPath) {
    toast('Navigate the local pane somewhere first.', 'info');
    return;
  }
  const key = sftpLocalDirKey(tab.serverId);
  const dir = tab.localPath;
  // Keep state.settings in step so reopening the panel in this same session
  // sees the new default without waiting for the next settings_get.
  if (state.settings) state.settings[key] = dir;
  call('settings_set', { key, value: dir }).catch(() => {});
  toast(`Default local directory for ${tab.serverName || 'this server'} set to ${tab.localPath}`, 'ok');
}

function joinLocal(dir, name) {
  const sep = dir.includes('\\') && !dir.includes('/') ? '\\' : '/';
  return dir.endsWith(sep) ? dir + name : dir + sep + name;
}

function localNavigateUp(tabId) {
  const tab = sftpTab(tabId);
  if (!tab || !tab.localPath) return;
  if (typeof sftpSyncLocalUp === 'function' && sftpSyncLocalUp(tabId)) return;
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
  // local pane isn't open, open it so the destination is always visible -
  // never a hidden temp folder. Explicit placement stays on "Download as...".
  sftpTabState(tab);
  if (!tab.dualPane) toggleDualPane(tabId);
  if (!tab.localPath) {
    // Local listing hasn't loaded yet (toggle just opened it) - wait briefly.
    await new Promise(r => setTimeout(r, 600));
  }
  const dir = tab.localPath || null;
  if (!dir) {
    toast('Local pane is still loading - try again in a moment.', 'err');
    return;
  }
  try {
    // Conflict check: does <dir>/<name> already exist locally? Directory
    // sources are expanded server-side later, so only plain files are
    // pre-checked (FileZilla does the same for its existence dialog).
    const localEntries = await sftpLocalEntryMap(dir);
    const conflicts = [];
    for (const p of remotePaths) {
      const name = p.split('/').filter(Boolean).pop();
      if (!name) continue;
      const dest = localEntries.get(name);
      if (dest) conflicts.push({ remote: p, name, destDir: dir, destEntry: dest });
    }
    const decided = await resolveBatchConflicts(tabId, 'download', conflicts);
    if (!decided) return; // user cancelled the whole batch
    const survivors = [];
    for (const p of remotePaths) {
      const d = decided.find(x => x.remote === p);
      if (d) {
        if (d.action === 'skip') continue;
        // `localName` is the renamed destination for Agent B's backend
        // update; today the backend derives the local name from the remote
        // basename and ignores it (falls back to overwrite).
        const item = { remote: d.remote, resume: d.action };
        if (d.localName) item.localName = d.localName;
        survivors.push(item);
      } else {
        survivors.push({ remote: p, resume: 'overwrite' });
      }
    }
    if (!survivors.length) { sftpLog(tabId, 'download batch empty after conflict decisions'); return; }
    const r = await sftpCall('sftp_queue_add', {
      sessionId: tab.sessionId,
      direction: 'download',
      items: survivors,
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
    // Conflict check: stat each remote destination. sftp_list_dir on the
    // target directory gives existence + size + mtime in one round-trip
    // for the whole batch (sftp_get_permissions stats one path at a time
    // and returns no size/mtime for the comparison display).
    const byDir = new Map();
    for (const { local, remote } of pairs) {
      const dir = remote.slice(0, remote.lastIndexOf('/')) || '/';
      if (!byDir.has(dir)) byDir.set(dir, []);
      byDir.get(dir).push({ local, remote });
    }
    const remoteEntries = new Map(); // dir -> Map(name -> entry)
    const conflicts = [];
    for (const [dir, group] of byDir) {
      try {
        const r = await sftpCall('sftp_list_dir', { sessionId: tab.sessionId, path: dir });
        remoteEntries.set(dir, new Map((r.entries || []).map(e => [e.name, e])));
      } catch (e) {
        // Destination dir unreadable/missing - no conflict possible; the
        // backend will surface the real error if the upload can't proceed.
        continue;
      }
      for (const { local, remote } of group) {
        const name = remote.split('/').filter(Boolean).pop();
        const dest = remoteEntries.get(dir).get(name);
        if (dest) conflicts.push({ local, remote, destDir: dir, destEntry: dest });
      }
    }
    const decided = await resolveBatchConflicts(tabId, 'upload', conflicts);
    if (!decided) return; // user cancelled the whole batch
    const items = [];
    for (const pair of pairs) {
      const d = decided.find(x => x.remote === pair.remote && x.local === pair.local);
      if (d) {
        if (d.action === 'skip') continue;
        // NOTE: resume:'resume' is honored by the backend once the
        // resume/.part update lands (Agent B); today the backend treats it
        // as a plain overwrite - acceptable interim fallback.
        items.push({ local: pair.local, remote: d.action === 'rename' ? d.renameRemote : pair.remote, resume: d.action });
      } else {
        items.push({ local: pair.local, remote: pair.remote, resume: 'overwrite' });
      }
    }
    if (!items.length) { sftpLog(tabId, 'upload batch empty after conflict decisions'); return; }
    const r = await sftpCall('sftp_queue_add', {
      sessionId: tab.sessionId,
      direction: 'upload',
      items,
      preserveTs: !!tab.sftpPreserveTs,
    });
    sftpLog(tabId, `queued ${r.added} upload(s)`);
    if (r.added > 0) toast(`${r.added} upload(s) queued.`, 'ok');
  } catch (e) { toast(e.message || String(e), 'err'); }
}

// ─── overwrite-conflict handling (FileZilla "file already exists") ──────────

const CONFLICT_ACTIONS = ['overwrite', 'skip', 'rename', 'resume'];

/// Read a local directory once and index it by file name.
async function sftpLocalEntryMap(dir) {
  const r = await sftpCall('sftp_local_list', { path: dir });
  const map = new Map();
  for (const e of r.entries || []) map.set(e.name, e);
  return map;
}

/// Load the persisted default action for a direction. NOTE: settings_get
/// only returns whitelisted keys, so a value written by settings_set is
/// seen via the in-session mirror below; across restarts it reads as 'ask'
/// until the two keys are added to the backend whitelist (one-line change
/// owned by the backend agents).
const sftpConflictDefaults = { sftpConflictUpload: 'ask', sftpConflictDownload: 'ask' };

function sftpConflictDefault(direction) {
  const key = direction === 'upload' ? 'sftpConflictUpload' : 'sftpConflictDownload';
  let v = (state.settings && state.settings[key]) || sftpConflictDefaults[key] || 'ask';
  // Download rename needs the backend `localName` field (remote-basename
  // derivation can't be redirected today) - asking beats silently
  // overwriting when the user asked for a rename.
  if (direction === 'download' && v === 'rename') v = 'ask';
  return CONFLICT_ACTIONS.includes(v) && v !== 'ask' ? v : 'ask';
}

/// Split "name.ext" into ["name", ".ext"] (dotless names get no suffix).
function splitExt(name) {
  const i = name.lastIndexOf('.');
  return i > 0 ? [name.slice(0, i), name.slice(i)] : [name, ''];
}

/// First name of the form "name (n).ext" (n starting at 1) that is NOT
/// taken in `taken` - the FileZilla auto-rename scheme. The original name
/// is already taken (that's why we're renaming).
function sftpFreeName(name, taken) {
  const [base, ext] = splitExt(name);
  for (let n = 1; n < 1000; n++) {
    const candidate = `${base} (${n})${ext}`;
    if (!taken.has(candidate)) return candidate;
  }
  return `${base}-${Date.now()}${ext}`;
}

function sftpConflictMtimeNote(srcMs, dstMs) {
  if (!srcMs || !dstMs || srcMs === dstMs) return '';
  const srcNewer = srcMs > dstMs;
  return srcNewer ? 'Source is newer' : 'Source is older';
}

function fmtSftpTime(ms) {
  if (!ms) return '-';
  const d = new Date(ms);
  return Number.isNaN(d.getTime()) ? '-' : d.toLocaleString();
}

/// Decide the action for every conflict in a batch. Returns an array of
/// { ..., action, renameRemote?/localName? } for the conflicted items only,
/// or null when the user cancels the whole batch. Non-conflicting items are
/// never blocked - they enqueue as overwrite.
async function resolveBatchConflicts(tabId, direction, conflicts) {
  if (!conflicts.length) return [];
  const tab = sftpTab(tabId);
  const defaults = sftpConflictDefault(direction);
  if (defaults !== 'ask') {
    // Persisted non-ask default: apply silently (FileZilla behavior).
    const applied = conflicts.map(c => applyConflictAction(c, defaults, direction));
    sftpLog(tabId, `${conflicts.length} conflict(s) auto-${defaults} (setting)`);
    return applied;
  }
  if (!tab) return conflicts.map(() => ({ action: 'overwrite' }));

  return await new Promise(resolve => {
    const modal = document.getElementById('conflictModal');
    if (!modal) { resolve(conflicts.map(c => applyConflictAction(c, 'overwrite', direction))); return; }
    const title = document.getElementById('conflictTitle');
    const summary = document.getElementById('conflictSummary');
    const listEl = document.getElementById('conflictList');
    const always = document.getElementById('conflictAlways');
    const alwaysLabel = document.getElementById('conflictAlwaysLabel');
    const applyBtn = document.getElementById('conflictApplyBtn');
    const cancelBtn = document.getElementById('conflictCancelBtn');
    const closeBtn = document.getElementById('conflictCloseBtn');
    const hint = document.getElementById('conflictHint');

    const isUp = direction === 'upload';
    title.textContent = conflicts.length === 1
      ? 'Target file already exists'
      : `${conflicts.length} target files already exist`;
    summary.textContent = isUp
      ? 'The remote file already exists. Choose what to do with each upload:'
      : 'The local file already exists. Choose what to do with each download:';
    always.checked = false;
    alwaysLabel.textContent = `Always use this action for ${isUp ? 'uploads' : 'downloads'}`;
    hint.textContent = 'Skip removes a file from this batch.';

    // Source side info (for size/mtime comparison). Uploads: stat the local
    // files via the local pane's dir; downloads: stat remote via list_dir of
    // the parent (already fetched by the caller when possible - refetch here
    // to keep this self-contained).
    listEl.innerHTML = '';
    const rows = [];
    let srcEntryPromise;
    if (isUp) {
      // Local source stats - group by source dir.
      srcEntryPromise = (async () => {
        const dirs = new Map();
        for (const c of conflicts) {
          const dir = c.local.slice(0, Math.max(c.local.lastIndexOf('/'), c.local.lastIndexOf('\\')));
          if (!dirs.has(dir)) dirs.set(dir, null);
        }
        for (const dir of dirs.keys()) {
          try { dirs.set(dir, await sftpLocalEntryMap(dir)); } catch { /* leave null */ }
        }
        return dirs;
      })();
    }

    const mkRow = (c, idx) => {
      const srcName = isUp ? c.local.split(/[\\/]/).filter(Boolean).pop() : c.remote.split('/').filter(Boolean).pop();
      const row = document.createElement('div');
      row.className = 'conflict-item';

      const head = document.createElement('div');
      head.className = 'conflict-item-head';
      head.innerHTML = `<span class="conflict-dir">${isUp ? '↑' : '↓'}</span>
        <span class="conflict-name">${escapeHtml(srcName || '?')}</span>`;
      row.appendChild(head);

      const cmp = document.createElement('div');
      cmp.className = 'conflict-cmp';
      const srcCell = document.createElement('span');
      const dstCell = document.createElement('span');
      srcCell.textContent = '...'; dstCell.textContent = '...';
      cmp.appendChild(srcCell); cmp.appendChild(dstCell);
      row.appendChild(cmp);
      // Fill in source stats asynchronously.
      if (isUp) {
        srcEntryPromise.then(dirs => {
          const dir = c.local.slice(0, Math.max(c.local.lastIndexOf('/'), c.local.lastIndexOf('\\')));
          const e = (dirs.get(dir) || new Map()).get(srcName);
          renderConflictCmp(srcCell, dstCell, e, c.destEntry, isUp);
        }).catch(() => renderConflictCmp(srcCell, dstCell, null, c.destEntry, isUp));
      } else {
        (async () => {
          try {
            const parent = c.remote.slice(0, c.remote.lastIndexOf('/')) || '/';
            const r = await sftpCall('sftp_list_dir', { sessionId: tab.sessionId, path: parent });
            const e = (r.entries || []).find(x => x.name === srcName);
            renderConflictCmp(srcCell, dstCell, e, c.destEntry, isUp);
          } catch { renderConflictCmp(srcCell, dstCell, null, c.destEntry, isUp); }
        })();
      }

      const actions = document.createElement('div');
      actions.className = 'conflict-actions';
      for (const act of CONFLICT_ACTIONS) {
        const id = `conflict-${idx}-${act}`;
        const rb = document.createElement('input');
        rb.type = 'radio';
        rb.name = `conflict-action-${idx}`;
        rb.id = id;
        rb.value = act;
        rb.checked = act === 'overwrite';
        if (act === 'resume') {
          rb.disabled = true;
          rb.title = 'Resume needs the next backend update';
        } else if (act === 'rename' && !isUp) {
          rb.disabled = true;
          rb.title = 'Download rename needs the next backend update';
        }
        const lab = document.createElement('label');
        lab.className = 'conflict-action' + (rb.disabled ? ' disabled' : '');
        lab.htmlFor = id;
        if (rb.title) lab.title = rb.title;
        const names = { overwrite: 'Overwrite', skip: 'Skip', rename: 'Rename', resume: 'Resume' };
        lab.appendChild(rb);
        lab.appendChild(document.createTextNode(names[act]));
        actions.appendChild(lab);
      }
      row.appendChild(actions);
      listEl.appendChild(row);
      return { row, c, actions };
    };

    for (let i = 0; i < conflicts.length; i++) rows.push(mkRow(conflicts[i], i));

    const close = () => {
      modal.hidden = true;
      applyBtn.onclick = null; cancelBtn.onclick = null; closeBtn.onclick = null; modal.onclick = null;
      document.removeEventListener('keydown', onKey, true);
    };
    // Escape means "cancel the whole batch", the same as the X and Cancel
    // buttons — it must resolve(null) too, or the transfer awaiting this
    // promise would hang forever with the dialog gone.
    function onKey(ev) {
      if (ev.key !== 'Escape') return;
      ev.preventDefault();
      ev.stopPropagation();
      close();
      resolve(null);
    }
    document.addEventListener('keydown', onKey, true);
    const finish = () => {
      const out = [];
      for (const { c, actions } of rows) {
        const sel = actions.querySelector('input[type="radio"]:checked');
        const act = sel ? sel.value : 'overwrite';
        out.push(applyConflictAction(c, act, direction));
      }
      if (always.checked) {
        // The "always" action is the first row's choice (all rows start at
        // the same default and FileZilla applies one action to the rest).
        const first = out[0] ? out[0].action : 'overwrite';
        const key = direction === 'upload' ? 'sftpConflictUpload' : 'sftpConflictDownload';
        call('settings_set', { key, value: first }).then(() => {
          sftpConflictDefaults[key] = first;
          if (state.settings) state.settings[key] = first;
        }).catch(() => {});
        sftpLog(tabId, `default for ${direction} conflicts: ${first}`);
      }
      close();
      resolve(out);
    };
    applyBtn.onclick = finish;
    cancelBtn.onclick = () => { close(); resolve(null); };
    closeBtn.onclick = () => { close(); resolve(null); };
    modal.onclick = (ev) => { if (ev.target === modal) { close(); resolve(null); } };

    modal.hidden = false;
    applyBtn.focus();
  });
}

function renderConflictCmp(srcCell, dstCell, srcEntry, dstEntry, isUp) {
  const one = (e, side) => {
    if (!e) return `${side}: unknown`;
    const bits = [formatSftpSize(e.size || 0), fmtSftpTime(e.modifiedMs)];
    return `${side}: ${bits[0]} · ${bits[1]}`;
  };
  srcCell.textContent = one(srcEntry, 'Source');
  dstCell.textContent = one(dstEntry, 'Target');
  const note = sftpConflictMtimeNote(srcEntry && srcEntry.modifiedMs, dstEntry && dstEntry.modifiedMs);
  if (note) {
    const n = document.createElement('span');
    n.className = 'conflict-note';
    n.textContent = note;
    srcCell.parentElement.appendChild(n);
  }
}

/// Attach the chosen action to a conflict record. Rename computes the free
/// name against the destination listing (plus names already claimed by this
/// batch) and reports the adjusted destination:
///   upload → renameRemote (new remote path, applied today)
///   download → localName (honored by the backend once Agent B's update
///              lands; today the remote basename wins = overwrite)
function applyConflictAction(c, action, direction, extraTaken) {
  const out = { ...c, action };
  if (action !== 'rename') return out;
  const name = direction === 'upload'
    ? c.remote.split('/').filter(Boolean).pop()
    : (c.destEntry && c.destEntry.name) || c.remote.split('/').filter(Boolean).pop();
  const taken = new Set(extraTaken || []);
  if (c.destEntry && c.destEntry.name) taken.add(c.destEntry.name);
  const free = sftpFreeName(name, taken);
  if (direction === 'upload') {
    const dir = c.remote.slice(0, c.remote.lastIndexOf('/')) || '/';
    out.renameRemote = sftpJoin(dir, free);
  } else {
    out.localName = free;
  }
  return out;
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
    toast(`Editing ${name} - saves upload automatically.`, 'info');
  } catch (e) { toast(e.message || String(e), 'err'); }
}

// Server-to-server "Send to": enqueues a queue job that downloads from the
// source and uploads to the target on fresh SFTP channels (the interactive
// browse sessions are never used - some servers fail reads on the
// long-lived channel). Progress shows in the transfer queue panel.
async function sftpSendTo(fromTabId, fullPath, targetTab) {
  try {
    const name = fullPath.split('/').filter(Boolean).pop() || 'file';
    terminalSetStatus(`Sending ${name} to ${targetTab.serverName}...`);
    await sftpCall('sftp_server_copy', {
      fromSessionId: state.sessions.get(fromTabId)?.sessionId,
      remote: fullPath,
      targetSessionId: targetTab.sessionId,
      targetDir: targetTab.sftpPath || '/',
    });
    terminalSetStatus(`Sent ${name} to ${targetTab.serverName}.`);
    toast(`Sending ${name} to ${targetTab.serverName} - see Transfers.`, 'ok');
  } catch (e) { toast(e.message || String(e), 'err'); }
}

// ─── transfer queue panel ───────────────────────────────────────────────────

const queueJobs = new Map(); // id -> job
let queueUnlisten = null;
// Which tab is visible. Paused jobs (user-paused, or restored from a
// previous run - see sftpQueueJobResumable) fold into "queued" rather than
// getting a 4th tab: they're still "waiting their turn", just deliberately
// held, and the row rendering (paused fill color, Resume action, the
// restored-jobs banner) already carries the distinction that matters.
let queueTab = 'queued'; // which tab is visible: queued | failed | done
let sftpUiQueueH = null; // persisted queue-panel height (px) set by the drag handle

// Pause/resume glyphs aren't in the shared ICONS table (icons.js is out of
// scope for this pass) - inline the same feather-style stroke icons locally
// so the buttons match every other icon-btn in look.
const Q_ICON_PAUSE = '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="6" y="4" width="4" height="16" rx="1"/><rect x="14" y="4" width="4" height="16" rx="1"/></svg>';
const Q_ICON_RESUME = '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="6 4 20 12 6 20 6 4"/></svg>';

/// True when some tab holds a live session matching this id - i.e. resuming
/// this job can actually reach a server rather than failing immediately.
/// Restored jobs point at a sessionId from the previous run, which no longer
/// exists once the app has restarted.
function sftpQueueLiveSession(sessionId) {
  if (!sessionId) return false;
  return [...state.sessions.values()].some(t => t.sessionId === sessionId);
}

/// A paused job is only safely resumable when every session it touches is
/// still live - for a serverCopy that means both the source AND the target.
/// resume_job (Rust) doesn't check this itself; it just flips the state to
/// Queued and lets the job fail on its next attempt, which would blow away
/// the helpful "needs reconnect" error a restored job carries. So the
/// renderer checks first and refuses to offer a Resume that can't work.
function sftpQueueJobResumable(j) {
  if (!sftpQueueLiveSession(j.sessionId)) return false;
  if (j.kind === 'serverCopy' && j.targetSessionId && !sftpQueueLiveSession(j.targetSessionId)) return false;
  return true;
}

function wireQueueEvents() {
  if (queueUnlisten) return;
  sftpListen('sftp-queue', (ev) => {
    for (const j of ev.payload.jobs || []) {
      queueJobs.set(j.id, j);
      // Mirror failures into the active tab's log + status strip.
      if (j.state === 'failed' && !j._logged) {
        j._logged = true;
        const tab = [...state.sessions.values()].find(t => t.sessionId === j.sessionId);
        if (tab) sftpLog(tab.tabId, `transfer failed: ${j.remotePath || j.localPath} - ${j.error || 'error'}`);
      }
    }
    renderQueuePanel();
  }).then(un => { queueUnlisten = un; });
}

/// Countdown ticker for auto-retry backoffs (Task 2). A single shared
/// interval for the module's whole lifetime - never one per row - so there
/// is nothing to leak as rows are rebuilt on every render or the panel is
/// hidden: it just checks whether any job currently needs a tick and no-ops
/// otherwise. renderQueuePanel() is idempotent (it always redraws the full
/// list from queueJobs), so re-invoking it here is exactly as safe as the
/// backend pushing another sftp-queue event.
setInterval(() => {
  if (!document.getElementById('sftpQueueList')) return;
  const retrying = [...queueJobs.values()].some(j => j.state === 'queued' && j.retryAt);
  if (retrying) renderQueuePanel();
}, 1000);

/// ETA from remaining bytes / speed. '-' when speed is 0/unknown or all done.
/// serverCopy progress counts both halves, so remaining uses 2×size (matching
/// the progress bar's totalUnits).
function sftpUiQueueEta(j, shownDone) {
  if (j.state === 'done') return '-';
  const totalUnits = j.kind === 'serverCopy' ? (j.size || 0) * 2 : (j.size || 0);
  const done = j.kind === 'serverCopy' ? (j.bytesDone || 0) : (shownDone || 0);
  const remaining = totalUnits > 0 ? Math.max(0, totalUnits - done) : 0;
  const speed = j.speed || 0;
  if (speed <= 0 || remaining <= 0) return '-';
  const secs = Math.ceil(remaining / speed);
  if (secs < 60) return secs + 's';
  if (secs < 3600) return Math.floor(secs / 60) + 'm ' + (secs % 60) + 's';
  const h = Math.floor(secs / 3600), m = Math.floor((secs % 3600) / 60);
  return h + 'h ' + m + 'm';
}

function buildQueuePanel() {
  const panel = document.createElement('div');
  panel.className = 'sftp-queuepanel';
  panel.id = 'sftpQueuePanel';
  panel.style.display = 'none';

  // Top-edge drag handle: resize the panel vertically.
  const handle = document.createElement('div');
  handle.className = 'sftp-queuehandle';
  handle.title = 'Drag to resize the transfer panel';
  let qDrag = null;
  handle.addEventListener('mousedown', (ev) => {
    const rect = panel.getBoundingClientRect();
    qDrag = { startY: ev.clientY, startH: rect.height };
    ev.preventDefault();
  });
  document.addEventListener('mousemove', (ev) => {
    if (!qDrag) return;
    const h = Math.min(window.innerHeight * 0.7, Math.max(120, qDrag.startH - (ev.clientY - qDrag.startY)));
    sftpUiQueueH = Math.round(h);
    panel.style.height = sftpUiQueueH + 'px';
  });
  document.addEventListener('mouseup', () => { qDrag = null; });

  // Head: title / summary / tabs / actions. Extra action buttons (pause,
  // priority, ...) append to .sftp-queueactions-head without layout changes.
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
  const headActions = document.createElement('div');
  headActions.className = 'sftp-queueactions-head';
  const pauseAllBtn = document.createElement('button');
  pauseAllBtn.className = 'ghost-btn';
  pauseAllBtn.textContent = 'Pause all';
  pauseAllBtn.title = 'Pause every active and queued transfer';
  pauseAllBtn.addEventListener('click', async () => {
    try { await call('sftp_queue_pause_all'); } catch (e) { toast(e.message || String(e), 'err'); }
  });
  const resumeAllBtn = document.createElement('button');
  resumeAllBtn.className = 'ghost-btn';
  resumeAllBtn.textContent = 'Resume all';
  resumeAllBtn.title = 'Resume every paused transfer whose session is still connected';
  resumeAllBtn.addEventListener('click', () => sftpQueueResumeAllResumable());
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
  headActions.appendChild(pauseAllBtn);
  headActions.appendChild(resumeAllBtn);
  headActions.appendChild(clearBtn);
  head.appendChild(title);
  head.appendChild(summary);
  head.appendChild(tabs);
  head.appendChild(headActions);

  // Restored-transfer banner (Task 5): hidden until renderQueuePanel finds a
  // paused job whose session died with the previous run (see
  // sftpQueueJobResumable). Plain textContent below - only ever a count.
  const restoredBanner = document.createElement('div');
  restoredBanner.className = 'sftp-queuebanner';
  restoredBanner.id = 'sftpQueueRestoredBanner';
  restoredBanner.hidden = true;

  // Column header row + scrolling rows (table-like grid).
  const colhead = document.createElement('div');
  colhead.className = 'sftp-queuecols';
  colhead.innerHTML = `
    <span class="q-col q-dir"></span>
    <span class="q-col q-name">Filename</span>
    <span class="q-col q-route">Route</span>
    <span class="q-col q-prog">Progress</span>
    <span class="q-col q-speed">Speed</span>
    <span class="q-col q-eta">ETA</span>
    <span class="q-col q-err">Error</span>
    <span class="q-col q-act"></span>`;

  const list = document.createElement('div');
  list.className = 'sftp-queuelist';
  list.id = 'sftpQueueList';

  panel.appendChild(handle);
  panel.appendChild(head);
  panel.appendChild(restoredBanner);
  panel.appendChild(colhead);
  panel.appendChild(list);
  return panel;
}

/// "Resume all" (Task 1/5): sftp_queue_resume_all (Rust) resumes every
/// Paused job unconditionally, with no idea which sessions are actually
/// still connected. Calling it directly here would blow past the whole
/// point of Task 5 - a restored job with a dead session would get bounced
/// straight to Failed, losing its helpful "reconnect to X" message. So this
/// resumes jobs one at a time, only the ones sftpQueueJobResumable() says
/// can actually reach a server, and reports how many were left behind.
async function sftpQueueResumeAllResumable() {
  const paused = [...queueJobs.values()].filter(j => j.state === 'paused');
  const resumable = paused.filter(sftpQueueJobResumable);
  const skipped = paused.length - resumable.length;
  if (!resumable.length) {
    toast(skipped ? 'Those paused transfers need a reconnect first.' : 'Nothing paused to resume.', 'info');
    return;
  }
  await Promise.all(resumable.map(j =>
    call('sftp_queue_resume', { jobId: j.id }).catch(e => toast(e.message || String(e), 'err'))
  ));
  if (skipped) toast(`Resumed ${resumable.length} - ${skipped} more need a reconnect first.`, 'info');
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
  const paused = jobs.filter(j => j.state === 'paused');
  const failed = jobs.filter(j => j.state === 'failed');
  const done = jobs.filter(j => j.state === 'done');

  const aggSpeed = active.reduce((s, j) => s + (j.speed || 0), 0);
  const summaryParts = [];
  if (active.length) summaryParts.push(`${active.length} active · ${(aggSpeed / 1024).toFixed(1)} KB/s`);
  if (queued.length) summaryParts.push(`${queued.length} queued`);
  if (paused.length) summaryParts.push(`${paused.length} paused`);
  if (!summaryParts.length && failed.length) summaryParts.push(`${failed.length} failed`);
  summary.textContent = summaryParts.join(' · ');

  // Restored-transfer banner (Task 5): only the jobs a Resume click would
  // actually fail on - see sftpQueueJobResumable.
  const staleRestored = paused.filter(j => !sftpQueueJobResumable(j));
  const banner = document.getElementById('sftpQueueRestoredBanner');
  if (banner) {
    banner.hidden = staleRestored.length === 0;
    banner.textContent = staleRestored.length === 1
      ? '1 transfer from a previous session is paused - reconnect to that server to resume it.'
      : `${staleRestored.length} transfers from a previous session are paused - reconnect to those servers to resume them.`;
  }

  const shown = queueTab === 'queued'
    ? [...active, ...queued, ...paused]
    : queueTab === 'failed' ? failed : done;

  list.innerHTML = '';
  for (const j of shown.slice(-100).reverse()) {
    const row = document.createElement('div');
    row.className = 'sftp-queueitem q-state-' + j.state;
    const name = j.kind === 'upload'
      ? (j.remotePath || '').split('/').filter(Boolean).pop()
      : (j.remotePath || '').split('/').filter(Boolean).pop();
    const dirIcon = j.kind === 'upload'
      ? `<span class="q-dirarrow up" title="Upload">${ico('file-up')}</span>`
      : j.kind === 'serverCopy'
        ? `<span class="q-dirarrow copy" title="Server to server">${ico('send')}</span>`
        : `<span class="q-dirarrow down" title="Download">${ico('download')}</span>`;
    // serverCopy: bytesDone is overall (download half + upload half), so the
    // progress bar maps 0..2×size onto 0..100%.
    const totalUnits = j.kind === 'serverCopy' ? (j.size || 0) * 2 : (j.size || 0);
    // Paused/queued jobs keep whatever bytesDone the backend last reported
    // (the .part on disk is untouched by pausing), so this naturally holds
    // the bar's position instead of zeroing it - nothing extra needed here.
    const pct = totalUnits > 0
      ? Math.min(100, (j.bytesDone / totalUnits) * 100)
      : (j.state === 'done' ? 100 : 0);
    const shownDone = j.kind === 'serverCopy'
      ? Math.min(j.bytesDone || 0, j.size || 0)
      : (j.bytesDone || 0);

    const route = j.kind === 'serverCopy' && j.targetServerName
      ? `${escapeHtml(j.serverName || '')} → ${escapeHtml(j.targetServerName)}`
      : escapeHtml(j.serverName || '');
    const progress = j.size
      ? `${formatSftpSize(shownDone || 0)} / ${formatSftpSize(j.size)}`
      : formatSftpSize(shownDone || 0);
    const speed = j.speed ? (j.speed / 1024).toFixed(1) + ' KB/s' : '-';
    const eta = sftpUiQueueEta(j, shownDone);
    // Verify badge (Task 4): a small marker on jobs that ran (or will run)
    // with post-transfer SHA-256 verification, so the extra traffic/time
    // it costs isn't a silent surprise when watching the queue.
    const verifyBadge = j.verify
      ? `<span class="q-verify" title="Verifying with SHA-256 after transfer">${ico('shield-check')}</span>`
      : '';
    // Auto-retry countdown (Task 2): a backoff-queued job carries
    // attempts > 0 and a future retryAt, plus a human error like
    // "connection reset — retrying (2/3)". Pull just the "(2/3)" back out
    // of that string rather than hardcoding the retry cap here, so the two
    // stay in sync automatically; the full backend message is still the
    // tooltip. A single shared ticker (see setInterval above) redraws this
    // once a second - no per-row timer to leak.
    const retrySecs = (j.state === 'queued' && j.retryAt)
      ? Math.max(0, Math.ceil((j.retryAt - Date.now()) / 1000))
      : null;
    let errDisplay = j.error || '';
    let errClass = '';
    if (retrySecs !== null) {
      const m = errDisplay.match(/\((\d+\/\d+)\)\s*$/);
      errDisplay = `retrying in ${retrySecs}s${m ? ' (' + m[1] + ')' : ''}`;
      errClass = ' retrying';
    } else if (j.state === 'paused' && j.error) {
      errClass = ' info'; // restored/paused note, not a failure - don't paint it red
    }

    row.innerHTML = `
      <span class="q-cell q-dir">${dirIcon}</span>
      <span class="q-cell q-name" title="${escapeHtml(name || '')}">${verifyBadge}${escapeHtml(name || '?')}</span>
      <span class="q-cell q-route" title="${route}">${route}</span>
      <span class="q-cell q-prog">
        <span class="sftp-queuebar"><span class="sftp-queuefill${j.state === 'failed' ? ' failed' : j.state === 'done' ? ' done' : j.state === 'paused' ? ' paused' : ''}" style="width:${pct}%"></span></span>
        <span class="q-progtext">${progress}</span>
      </span>
      <span class="q-cell q-speed">${speed}</span>
      <span class="q-cell q-eta">${eta}</span>
      <span class="q-cell q-err${errClass}" title="${escapeHtml(j.error || '')}">${escapeHtml(errDisplay)}</span>`;

    const actions = document.createElement('span');
    actions.className = 'q-cell q-act sftp-queueactions';
    if (j.state === 'active' || j.state === 'queued') {
      const pause = document.createElement('button');
      pause.className = 'icon-btn';
      pause.title = 'Pause';
      pause.innerHTML = Q_ICON_PAUSE;
      pause.addEventListener('click', () => call('sftp_queue_pause', { jobId: j.id }));
      actions.appendChild(pause);
      const cancel = document.createElement('button');
      cancel.className = 'icon-btn';
      cancel.title = 'Cancel';
      cancel.innerHTML = ico('x');
      cancel.addEventListener('click', () => call('sftp_queue_cancel', { jobId: j.id }));
      actions.appendChild(cancel);
    } else if (j.state === 'paused') {
      const resumable = sftpQueueJobResumable(j);
      const resume = document.createElement('button');
      resume.className = resumable ? 'icon-btn' : 'icon-btn disabled';
      resume.innerHTML = Q_ICON_RESUME;
      if (resumable) {
        resume.title = 'Resume';
        resume.addEventListener('click', () => call('sftp_queue_resume', { jobId: j.id }));
      } else {
        // Session from the previous run (or a since-closed tab) is gone -
        // resume_job would just fail the job. Disabled, not wired.
        resume.title = `Reconnect to "${j.serverName || 'the server'}" to resume`;
        resume.disabled = true;
      }
      actions.appendChild(resume);
      // Cancel is the way off a paused row that can never resume — a job
      // restored from a previous run whose session is gone. cancel_job
      // transitions Paused as well as Queued, so this is not a no-op.
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
      } catch { return null; } // malformed payload - ignore the gesture
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
          // Task 6: this rename crosses directories - the CURRENT dir (source
          // parent) is covered by forceFresh below, but the drop target
          // (new parent) isn't the directory being refreshed, so its cache
          // entry needs an explicit invalidate or a later visit would show
          // it without the item that just moved in.
          sftpCacheInvalidate(tab, sftpJoin(tab.sftpPath, overDir));
          await refreshSftpPanel(tabId, { forceFresh: true });
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
    // a local→local move is not supported - treat as no-op.
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

// ─── directory comparison (agent-e) ─────────────────────────────────────────
//
// FileZilla-parity directory comparison: tint rows in both panes to show which
// files exist on only one side (yellow) or differ between sides (red), in two
// modes - by file size or by modification time. Self-contained section; hooks
// in refreshSftpPanel / refreshLocalPane / renderEntries call sftpCmpAfterRefresh
// guarded with typeof checks, so merging with parallel work stays clean.

// mtime comparison tolerance in ms - two files whose mtimes differ by less
// than this are considered identical (clock skew + FAT-style 2s granularity).
const sftpCmpMtimeToleranceMs = 60 * 1000;

// Per-tab comparison mode: null (off) | 'size' | 'mtime'. Global preference
// persisted via settings key "sftpCmpMode"; applied per tab on demand.
const sftpCmpTabs = new Map(); // tabId -> 'size' | 'mtime'

function sftpCmpModeOf(tabId) {
  return sftpCmpTabs.get(tabId) || null;
}

function sftpCmpPersistedMode() {
  const v = state.settings?.sftpCmpMode;
  return v === 'size' || v === 'mtime' ? v : null;
}

/// Cycle the active tab's comparison mode: off → size → mtime → off.
/// Also exposed as window.sftpCmpToggle(tabId) for toolbar wiring.
async function sftpCmpToggle(tabId) {
  const tab = sftpTab(tabId);
  if (!tab) return;
  if (!tab.dualPane) {
    toast('Directory comparison needs the dual pane open.', 'info');
    return;
  }
  const cur = sftpCmpModeOf(tabId);
  const next = cur === null ? 'size' : cur === 'size' ? 'mtime' : null;
  if (next) sftpCmpTabs.set(tabId, next);
  else sftpCmpTabs.delete(tabId);
  // Persist the last-used mode ('' when turned off from mtime → default off).
  call('settings_set', { key: 'sftpCmpMode', value: next || '' }).catch(() => {});
  sftpLog(tabId, `directory comparison: ${next ? 'by ' + (next === 'size' ? 'file size' : 'modified time') : 'off'}`);
  sftpCmpUpdateButton(tabId);
  if (next) sftpCmpRun(tabId);
  else sftpCmpClear(tabId);
}

/// Apply the persisted mode to a tab when its dual pane opens (called from
/// toggleDualPane via the guarded hook below).
function sftpCmpApplyPersisted(tabId) {
  const tab = sftpTab(tabId);
  if (!tab || !tab.dualPane) { sftpCmpTabs.delete(tabId); return; }
  const persisted = sftpCmpPersistedMode();
  if (persisted) sftpCmpTabs.set(tabId, persisted);
  else sftpCmpTabs.delete(tabId);
  sftpCmpUpdateButton(tabId);
  if (persisted) sftpCmpRun(tabId);
  else sftpCmpClear(tabId);
}

/// Hook invoked (guarded, idempotent) after every remote/local refresh.
/// No-op when the pane is closed or comparison is off for this tab.
function sftpCmpAfterRefresh(tabId) {
  sftpCmpEnsureButtons(tabId);
  const tab = sftpTab(tabId);
  if (!tab || !tab.dualPane) return;
  if (!sftpCmpModeOf(tabId)) return;
  sftpCmpRun(tabId);
}

/// Compute the comparison between tab._localEntries and tab._entries and
/// tint rows in both panes. Files only - directories stay neutral.
function sftpCmpRun(tabId) {
  const tab = sftpTab(tabId);
  if (!tab || !tab.dualPane) return;
  const mode = sftpCmpModeOf(tabId);
  if (!mode) return;
  const remoteTbody = document.getElementById('sftpTbody-' + tabId);
  const localTbody = document.getElementById('sftpLocalTbody-' + tabId);
  if (!remoteTbody || !localTbody) return;

  const remote = (tab._entries || []).filter(e => !e.isDir);
  const local = (tab._localEntries || []).filter(e => !e.isDir);
  const remoteByName = new Map(remote.map(e => [e.name, e]));
  const localByName = new Map(local.map(e => [e.name, e]));

  const cls = { remote: new Map(), local: new Map() }; // name → class
  let onlyLocal = 0, onlyRemote = 0, differ = 0, same = 0;
  for (const e of local) {
    if (!remoteByName.has(e.name)) { cls.local.set(e.name, 'sftp-cmp-only'); onlyLocal++; continue; }
    const r = remoteByName.get(e.name);
    let diff;
    if (mode === 'size') diff = (e.size || 0) !== (r.size || 0);
    else diff = Math.abs((e.modifiedMs || 0) - (r.modifiedMs || 0)) > sftpCmpMtimeToleranceMs;
    if (diff) { cls.local.set(e.name, 'sftp-cmp-diff'); cls.remote.set(e.name, 'sftp-cmp-diff'); differ++; }
    else { cls.local.set(e.name, 'sftp-cmp-same'); cls.remote.set(e.name, 'sftp-cmp-same'); same++; }
  }
  for (const e of remote) {
    if (localByName.has(e.name)) continue;
    cls.remote.set(e.name, 'sftp-cmp-only'); onlyRemote++;
  }

  sftpCmpPaint(remoteTbody, cls.remote);
  sftpCmpPaint(localTbody, cls.local);
  sftpLog(tabId, `compare (${mode === 'size' ? 'by size' : 'by mtime'}): ${onlyLocal} only-local, ${onlyRemote} only-remote, ${differ} differ, ${same} identical`);
}

/// Remove all comparison classes from both panes (mode turned off).
function sftpCmpClear(tabId) {
  const remoteTbody = document.getElementById('sftpTbody-' + tabId);
  const localTbody = document.getElementById('sftpLocalTbody-' + tabId);
  if (remoteTbody) for (const tr of remoteTbody.querySelectorAll('.sftp-cmp-only, .sftp-cmp-diff, .sftp-cmp-same')) {
    tr.classList.remove('sftp-cmp-only', 'sftp-cmp-diff', 'sftp-cmp-same');
  }
  if (localTbody) for (const tr of localTbody.querySelectorAll('.sftp-cmp-only, .sftp-cmp-diff, .sftp-cmp-same')) {
    tr.classList.remove('sftp-cmp-only', 'sftp-cmp-diff', 'sftp-cmp-same');
  }
}

/// Apply a name→class map to one pane's rows (files only; dirs stay neutral).
function sftpCmpPaint(tbody, map) {
  for (const tr of tbody.querySelectorAll('.sftp-entry')) {
    tr.classList.remove('sftp-cmp-only', 'sftp-cmp-diff', 'sftp-cmp-same');
    if (tr.dataset.isdir === '1') continue;
    const c = map.get(tr.dataset.name);
    if (c) tr.classList.add(c);
  }
}

/// Toolbar affordance without touching the toolbar block in buildSftpPanel:
/// append "Compare" / "Sync browse" ghost buttons once, after the panel exists.
function sftpCmpEnsureButtons(tabId) {
  const panel = document.getElementById('sftpPanel-' + tabId);
  if (!panel) return;
  const toolbar = panel.querySelector('.sftp-toolbar');
  if (!toolbar) return;
  if (toolbar.querySelector('.sftp-cmp-btn')) return; // idempotent

  const mkBtn = (cls, icon, title, label, fn) => {
    const b = document.createElement('button');
    b.className = 'ghost-btn ' + cls;
    b.title = title;
    b.innerHTML = `${ico(icon)}<span>${label}</span>`;
    b.addEventListener('click', fn);
    return b;
  };
  const cmpBtn = mkBtn('sftp-cmp-btn', 'eye', 'Compare directories (Ctrl+Y): off → by size → by mtime', 'Compare', () => sftpCmpToggle(tabId));
  const syncBtn = mkBtn('sftp-sync-btn', 'folder-tree', 'Synchronized browsing (Ctrl+Shift+B): mirror navigation in both panes', 'Sync browse', () => sftpSyncToggle(tabId));
  // Insert before the path input so the buttons stay grouped with the others.
  const pathBox = toolbar.querySelector('.sftp-path');
  toolbar.insertBefore(cmpBtn, pathBox);
  toolbar.insertBefore(syncBtn, pathBox);
  sftpCmpUpdateButton(tabId);
  sftpSyncUpdateButton(tabId);
}

/// Reflect the current comparison mode on the Compare button (label + .active).
function sftpCmpUpdateButton(tabId) {
  const btn = document.querySelector(`#sftpPanel-${tabId} .sftp-cmp-btn`);
  if (!btn) return;
  const mode = sftpCmpModeOf(tabId);
  btn.classList.toggle('active', !!mode);
  const span = btn.querySelector('span');
  if (span) span.textContent = mode === 'size' ? 'Cmp·size' : mode === 'mtime' ? 'Cmp·mtime' : 'Compare';
  btn.title = mode
    ? `Comparing by ${mode === 'size' ? 'file size' : 'modified time'} - click or Ctrl+Y to change`
    : 'Compare directories (Ctrl+Y): off → by size → by mtime';
}

// Keyboard shortcut: Ctrl+Y cycles comparison in the active SFTP tab.
document.addEventListener('keydown', (ev) => {
  if (!(ev.ctrlKey || ev.metaKey) || ev.shiftKey || ev.altKey || ev.key.toLowerCase() !== 'y') return;
  const tab = sftpTab(state.activeTabId);
  if (!tab || tab.mode !== 'sftp') return;
  const panel = document.getElementById('sftpPanel-' + tab.tabId);
  if (!panel) return;
  ev.preventDefault();
  sftpCmpToggle(tab.tabId);
});

// ─── synchronized browsing (agent-e) ────────────────────────────────────────
//
// FileZilla-parity synchronized browsing: when enabled with the dual pane
// open, navigating into a directory (or up) on one side mirrors the other.
// The anchor is the local↔remote path pair at the moment sync is enabled -
// mirroring is structural (same subdir name / one level up), not an absolute
// path mapping. If the mirrored directory doesn't exist, sync is suspended
// with a toast until the two sides realign at a shared level.

const sftpSyncTabs = new Set(); // tabIds with synchronized browsing ON

function sftpSyncIsOn(tabId) {
  return sftpSyncTabs.has(tabId);
}

async function sftpSyncToggle(tabId) {
  const tab = sftpTab(tabId);
  if (!tab) return;
  if (!tab.dualPane) {
    toast('Synchronized browsing needs the dual pane open.', 'info');
    return;
  }
  if (sftpSyncTabs.has(tabId)) {
    sftpSyncTabs.delete(tabId);
    sftpLog(tabId, 'synchronized browsing: off');
  } else {
    if (!tab.localPath || !tab.sftpPath) {
      toast('Both panes must finish loading before enabling sync.', 'info');
      return;
    }
    sftpSyncTabs.add(tabId);
    sftpLog(tabId, `synchronized browsing: on (anchored at ${tab.localPath} ⇄ ${tab.sftpPath})`);
  }
  sftpSyncUpdateButton(tabId);
}

/// Reflect the sync state on the Sync browse button.
function sftpSyncUpdateButton(tabId) {
  const btn = document.querySelector(`#sftpPanel-${tabId} .sftp-sync-btn`);
  if (!btn) return;
  btn.classList.toggle('active', sftpSyncTabs.has(tabId));
  btn.title = sftpSyncTabs.has(tabId)
    ? 'Synchronized browsing is ON - click or Ctrl+Shift+B to turn off'
    : 'Synchronized browsing (Ctrl+Shift+B): mirror navigation in both panes';
}

/// True if sync should mirror this tab right now (pane open, both sides
/// loaded, sync enabled, not suspended).
function sftpSyncActive(tabId) {
  const tab = sftpTab(tabId);
  return !!(tab && tab.dualPane && sftpSyncTabs.has(tabId) && tab.localPath && tab.sftpPath);
}

/// Suspend sync for this tab and explain why (missing mirror directory).
function sftpSyncSuspend(tabId, side, name) {
  if (!sftpSyncTabs.delete(tabId)) return;
  toast(`${side} ${name} doesn't exist - sync paused for this level`, 'warn');
  sftpLog(tabId, `synchronized browsing suspended: ${side} "${name}" has no mirror`);
  sftpSyncUpdateButton(tabId);
}

/// Remote dblclick into subdir `name`. Returns true when sync handled the
/// navigation. The local target is verified first; the remote side always
/// navigates (it's where the dblclick happened), the local side mirrors only
/// if sync is still on. tab.localPath is set BEFORE any refresh so the
/// refreshLocalPane nested in refreshSftpPanel lists the new directory.
function sftpSyncRemoteNav(tabId, name) {
  if (!sftpSyncActive(tabId)) return false;
  const tab = sftpTab(tabId);
  const targetLocal = joinLocal(tab.localPath, name);
  const targetRemote = sftpJoin(tab.sftpPath, name);
  sftpCall('sftp_local_list', { path: targetLocal })
    .then(() => {
      const mirror = sftpSyncIsOn(tabId); // may have been toggled off mid-flight
      tab.sftpPath = targetRemote;        // remote always navigates (origin of the dblclick)
      if (mirror) tab.localPath = targetLocal;
      refreshSftpPanel(tabId); // dual mode → also refreshes the local pane
    })
    .catch(() => {
      // Local mirror missing: remote still navigates, sync suspends.
      tab.sftpPath = targetRemote;
      refreshSftpPanel(tabId);
      sftpSyncSuspend(tabId, 'local', name);
    });
  return true;
}

/// Local dblclick into subdir `name`. Returns true when sync handled the
/// navigation. Remote existence is checked against the cached listing of
/// the current remote directory.
function sftpSyncLocalNav(tabId, name) {
  if (!sftpSyncActive(tabId)) return false;
  const tab = sftpTab(tabId);
  const remoteHasDir = (tab._entries || []).some(e => e.isDir && e.name === name);
  tab.localPath = joinLocal(tab.localPath, name);
  if (!remoteHasDir) {
    refreshLocalPane(tabId);
    sftpSyncSuspend(tabId, 'remote', name);
    return true;
  }
  tab.sftpPath = sftpJoin(tab.sftpPath, name);
  refreshSftpPanel(tabId); // dual mode → also refreshes the local pane
  return true;
}

/// Remote "Up" with sync. Returns true when handled. Both paths are updated
/// before any refresh (avoids an old-listing race between the two panes).
function sftpSyncRemoteUp(tabId) {
  if (!sftpSyncActive(tabId)) return false;
  const tab = sftpTab(tabId);
  const upRemote = sftpParent(tab.sftpPath);
  const upLocal = sftpSyncParentLocal(tab.localPath);
  tab.sftpPath = upRemote;
  tab.localPath = upLocal;
  refreshSftpPanel(tabId); // dual mode → also refreshes the local pane
  return true;
}

/// Local "Up" with sync. Returns true when handled.
function sftpSyncLocalUp(tabId) {
  if (!sftpSyncActive(tabId)) return false;
  const tab = sftpTab(tabId);
  if (!tab.localPath) { refreshLocalPane(tabId); return true; } // nothing above local root
  const upLocal = sftpSyncParentLocal(tab.localPath);
  const upRemote = sftpParent(tab.sftpPath);
  tab.localPath = upLocal;
  tab.sftpPath = upRemote;
  refreshSftpPanel(tabId); // dual mode → also refreshes the local pane
  return true;
}

/// Parent of a local path, mirroring localNavigateUp's separator handling.
/// Returns '' at/above the local root (home).
function sftpSyncParentLocal(p) {
  const sep = p.includes('\\') && !p.includes('/') ? '\\' : '/';
  const parts = p.split(sep).filter(Boolean);
  parts.pop();
  if (!parts.length) return '';
  let up = parts.join(sep);
  if (sep === '/') up = '/' + up;
  return up;
}

// Keyboard shortcut: Ctrl+Shift+B toggles synchronized browsing.
document.addEventListener('keydown', (ev) => {
  if (!(ev.ctrlKey || ev.metaKey) || !ev.shiftKey || ev.altKey || ev.key.toLowerCase() !== 'b') return;
  const tab = sftpTab(state.activeTabId);
  if (!tab || tab.mode !== 'sftp') return;
  const panel = document.getElementById('sftpPanel-' + tab.tabId);
  if (!panel) return;
  ev.preventDefault();
  sftpSyncToggle(tab.tabId);
});

// ─── exports ────────────────────────────────────────────────────────────────

window.toggleSshSftpMode = toggleSshSftpMode;
window.refreshSftpPanel = refreshSftpPanel;
window.showSshForTab = showSshForTab;
window.showSftpForTab = showSftpForTab;
window.sftpQueueDownloads = queueDownloads;
window.sftpConflictDefaults = sftpConflictDefaults;
window.sftpCmpToggle = sftpCmpToggle;
window.sftpSyncToggle = sftpSyncToggle;
