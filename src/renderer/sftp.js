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

/// Is the SFTP panel visible for this tab? Split shows the full file browser
/// beside the shell, so it counts. A dozen handlers used to gate on
/// `mode !== 'sftp'`, which silently disabled Ctrl+A, drag&drop, uploads,
/// compare shortcuts and the transfer-done auto-refresh in split mode while
/// navigation still worked - a half-broken panel is worse than a disabled one.
function sftpPanelVisible(tab) {
  return !!tab && tab.mode !== 'ssh';
}

/// Is a dialog open? The same test app.js's own shortcuts use (modalStack).
function sftpDialogOpen() {
  return typeof modalStack !== 'undefined' && modalStack.length > 0;
}

/// Is this tab's file panel actually in front of the user: its tab active on
/// a file surface, the Servers view showing (switching to Keys hides the
/// panel but leaves the tab active) and no dialog over it? Window-wide input -
/// an OS file drop, the SFTP shortcuts - acts only on a panel that passes:
/// a key file dropped on the Keys view used to be uploaded to the active
/// tab's server, and Ctrl+A/Ctrl+Y were taken from every text field in the app.
function sftpPanelOnScreen(tab) {
  if (!sftpPanelVisible(tab) || tab.tabId !== state.activeTabId) return false;
  if (state.view !== 'connect' || sftpDialogOpen()) return false;
  const panel = document.getElementById('sftpPanel-' + tab.tabId);
  return !!panel && panel.getClientRects().length > 0;
}

/// Ensure the tab record has all the SFTP fields this module uses.
function sftpTabState(tab) {
  if (!tab.sftpSelected) tab.sftpSelected = new Set();
  if (!tab.sortKey) tab.sortKey = 'name';
  if (tab.sortDesc === undefined) tab.sortDesc = false;
  if (!tab.log) tab.log = [];
  // Tri-state: undefined = follow the persisted sftpShowHidden setting;
  // true/false = the user's explicit per-tab choice, which must win over the
  // setting. The old falsy-guard (`if (!tab.showHidden) ...`) could not tell
  // "user turned it off" from "never touched", so every re-entry into this
  // function (each refreshSftpPanel navigation, mkdir, chmod...) silently
  // re-applied the SETTING over the user's choice - and the button lost its
  // active state with it.
  if (tab.showHidden === undefined) tab.showHidden = state.settings?.sftpShowHidden === '1';
  if (tab.dualPane === undefined) tab.dualPane = state.sftpDualPane === true;
  // Per-server default local directory, if the user has set one (Task 6);
  // falls back to '' (the OS home directory, sftp_local_list's own default)
  // exactly like before this existed. Tri-state like its neighbours: '' is
  // the deliberate "Home" choice set by the pane's Home button, so a falsy
  // guard would silently re-seed the remembered default over it on every
  // re-entry here.
  if (tab.localPath === undefined) tab.localPath = sftpSettingGet(sftpLocalDirKey(tab.serverId), '');
  if (tab.sftpPreserveTs === undefined) tab.sftpPreserveTs = state.settings?.sftpPreserveTs === '1';
  // Permissions/Owner columns default ON; toggleable per the toolbar button
  // (they widen the table noticeably, so narrow windows may prefer them off -
  // the table wrapper also scrolls horizontally regardless, see styles.css).
  if (tab.showOwnerCols === undefined) tab.showOwnerCols = state.settings?.sftpShowOwnerCols !== '0';
  // Local-pane selection, mirroring sftpSelected on the remote side.
  if (!tab.localSelected) tab.localSelected = new Set();
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

/// Put the active session on one of the three surfaces. 'split' shows the shell
/// and the file browser side by side, because editing a file and running a
/// command against it is one task - the old single toggle made you give up one
/// to see the other.
async function setSessionMode(mode) {
  const tab = sftpTab(state.activeTabId);
  if (!tab) return;
  if (!window.tabSessionLive(tab.tabId)) {
    toast('Connect first - the file browser runs over the live session.', 'err');
    return;
  }
  // The latest click is the one that counts: a Files click, then Split while
  // the file browser is still opening, ends in Split - and so does nothing
  // else (A5-12 b).
  const turn = tab._modeTurn = (tab._modeTurn || 0) + 1;
  if ((mode === 'sftp' || mode === 'split') && !tab.sftpReady) {
    tab._modeWanted = mode;
    const opened = await sftpOpenOnce(tab);
    if (!opened || tab._modeTurn !== turn || sftpTab(tab.tabId) !== tab) return;
  } else if (tab._modeWanted) {
    // Shell while the file browser opens: it is no longer what was asked for.
    tab._modeWanted = null;
    sftpPaintModeBusy();
  }
  tab.mode = mode;
  if (state.activeTabId === tab.tabId) {
    if (typeof window.activateSessionSurface === 'function') window.activateSessionSurface(tab.tabId);
  }
  if (mode === 'sftp' || mode === 'split') await refreshSftpPanel(tab.tabId);
  updateTerminalHead();
}

/// Open SFTP on a tab's session, once: every Files/Split click while it is
/// opening awaits the same request (A5-12 b - a second click used to send a
/// second sftp_open). Resolves true when the tab's file browser is ready.
/// The Shell/Files/Split control shows it is busy meanwhile.
function sftpOpenOnce(tab) {
  if (tab._sftpOpening) { sftpPaintModeBusy(); return tab._sftpOpening; }
  const sessionId = tab.sessionId;
  tab._sftpOpening = (async () => {
    try {
      const r = await sftpCall('sftp_open', { sessionId });
      // The session can end - or be replaced by a reconnect - meanwhile.
      if (tab.sessionId !== sessionId || !window.tabSessionLive(tab.tabId)) return false;
      tab.sftpReady = true;
      tab.sftpPath = r.cwd || '/';
      sftpLog(tab.tabId, `SFTP opened at ${tab.sftpPath}`);
      sftpCall('sftp_keepalive_start', { sessionId }).catch(() => {});
      wireQueueEvents();
      return true;
    } catch (e) {
      toast(e.message || String(e), 'err');
      return false;
    } finally {
      tab._sftpOpening = null;
      tab._modeWanted = null;
      sftpPaintModeBusy();
    }
  })();
  sftpPaintModeBusy();
  return tab._sftpOpening;
}

/// The Shell/Files/Split control while the ACTIVE tab's file browser opens:
/// busy, and the surface asked for marked as pending. Painted again whenever
/// a surface is shown (a tab switch), so the marks follow the tab on screen.
function sftpPaintModeBusy() {
  const seg = document.getElementById('termModeSeg');
  if (!seg) return;
  const tab = sftpTab(state.activeTabId);
  const wanted = tab && tab._sftpOpening ? tab._modeWanted : null;
  if (wanted) seg.setAttribute('aria-busy', 'true');
  else seg.removeAttribute('aria-busy');
  for (const b of seg.querySelectorAll('.seg-btn')) b.classList.toggle('pending', !!wanted && b.dataset.mode === wanted);
}

/// Kept for the terminal context menu and anything else that just wants the
/// other surface; it now cycles shell -> files -> split.
async function toggleSshSftpMode() {
  const tab = sftpTab(state.activeTabId);
  if (!tab) return;
  const next = tab.mode === 'ssh' ? 'sftp' : tab.mode === 'sftp' ? 'split' : 'ssh';
  await setSessionMode(next);
}

/// Shell and file browser at once. The surfaces are siblings in a flex row, so
/// showing both is a class on the wrapper plus leaving the terminal visible;
/// xterm has to be re-fit afterwards or it keeps the old column count.
function showSplitForTab(tabId) {
  showSftpForTab(tabId);
  const surface = document.getElementById('sessionSurface');
  const body = document.getElementById('terminalBody');
  const splitter = document.getElementById('surfaceSplitter');
  const rec = window.tabRecord ? window.tabRecord(tabId) : null;
  if (surface) surface.classList.add('split');
  if (splitter) splitter.hidden = false;
  if (body) body.style.display = 'flex';
  if (rec && rec.hostEl) rec.hostEl.style.display = 'block';
  // Within this window's room: the share kept from an earlier, wider one may
  // not leave the file browser its floor here.
  sftpApplySplit(sftpSplitPct);
  if (typeof window.showTabTerminal === 'function') window.showTabTerminal(tabId);
  requestAnimationFrame(() => {
    if (typeof window.fitActiveTerminal === 'function') window.fitActiveTerminal();
  });
}

// ─── the terminal / file-browser splitter (Split, A1-15) ────────────────────
//
// #surfaceSplitter was drawn with a resize cursor and did nothing: no handler
// ever read it. It is a separator now - dragged, or moved with the arrow keys
// - and it writes the one value Split is laid out from, --split-pct (the
// terminal's share; the file browser takes the rest, see styles.css).

/// The terminal's share of the Split surface, in percent, for the app session.
let sftpSplitPct = 54;
/// Neither side is squeezed below these (A1-03): a terminal of a few columns
/// or a file list with no room for a name is no use.
const SFTP_SPLIT_TERM_MIN_PX = 180;
const SFTP_SPLIT_FILES_MIN_PX = 260;
const SFTP_SPLITTER_PX = 6;
/// The local pane's share of the dual-pane row, in percent (A1-15).
const SFTP_LOCAL_PCT_MIN = 20;
const SFTP_LOCAL_PCT_MAX = 80;

/// The terminal shares the surface can take at its current width.
function sftpSplitBounds() {
  const surface = document.getElementById('sessionSurface');
  const w = (surface && surface.getBoundingClientRect().width) || 1000;
  const lo = Math.min(50, (SFTP_SPLIT_TERM_MIN_PX / w) * 100);
  const hi = Math.max(lo, 100 - ((SFTP_SPLIT_FILES_MIN_PX + SFTP_SPLITTER_PX) / w) * 100);
  return { lo, hi };
}

function sftpApplySplit(pct) {
  const surface = document.getElementById('sessionSurface');
  const sp = document.getElementById('surfaceSplitter');
  if (!surface) return;
  const { lo, hi } = sftpSplitBounds();
  sftpSplitPct = Math.min(hi, Math.max(lo, pct));
  surface.style.setProperty('--split-pct', sftpSplitPct.toFixed(2) + '%');
  if (sp) {
    sp.setAttribute('aria-valuenow', String(Math.round(sftpSplitPct)));
    sp.setAttribute('aria-valuemin', String(Math.floor(lo)));
    sp.setAttribute('aria-valuemax', String(Math.ceil(hi)));
  }
}

/// Follow a press on a handle until it is let go: `onMove(event)` for each
/// move. Pointer capture keeps the moves coming outside the handle and needs
/// no document listener idling between drags. Shared by the splitters and the
/// transfer panel's handle; the handle is marked .dragging meanwhile.
function sftpFollowPointer(handle, ev, onMove) {
  if (ev.button !== 0) return;
  ev.preventDefault();
  handle.setPointerCapture(ev.pointerId);
  handle.classList.add('dragging');
  const up = () => {
    handle.classList.remove('dragging');
    handle.removeEventListener('pointermove', onMove);
    handle.removeEventListener('pointerup', up);
    handle.removeEventListener('pointercancel', up);
  };
  handle.addEventListener('pointermove', onMove);
  handle.addEventListener('pointerup', up);
  handle.addEventListener('pointercancel', up);
}

/// Drag (pointer events, so it works whatever the webview does with HTML5
/// drags) and keyboard for a vertical separator: `toPct(clientX)` maps the
/// pointer to a share, `apply(pct)` sets it, `current()` reads it.
function sftpWireSeparator(sep, { toPct, apply, current }) {
  sep.addEventListener('pointerdown', (ev) => sftpFollowPointer(sep, ev, (e) => apply(toPct(e.clientX))));
  sep.addEventListener('keydown', (ev) => {
    const step = { ArrowLeft: -2, ArrowDown: -2, ArrowRight: 2, ArrowUp: 2, PageDown: -10, PageUp: 10 }[ev.key];
    if (step === undefined && ev.key !== 'Home' && ev.key !== 'End') return;
    ev.preventDefault();
    if (ev.key === 'Home') apply(-Infinity);
    else if (ev.key === 'End') apply(Infinity);
    else apply(current() + step);
  });
}

function sftpWireSurfaceSplitter() {
  const sp = document.getElementById('surfaceSplitter');
  if (!sp || sp._sftpWired) return;
  sp._sftpWired = true;
  sp.setAttribute('role', 'separator');
  sp.setAttribute('aria-orientation', 'vertical');
  sp.setAttribute('aria-label', 'Resize the terminal and the file browser');
  sp.setAttribute('aria-controls', 'terminalBody');
  sp.tabIndex = 0;
  sftpWireSeparator(sp, {
    toPct: (x) => {
      const r = document.getElementById('sessionSurface').getBoundingClientRect();
      return ((x - r.left) / (r.width || 1)) * 100;
    },
    apply: sftpApplySplit,
    current: () => sftpSplitPct,
  });
  sftpApplySplit(sftpSplitPct);
}
sftpWireSurfaceSplitter();

function clearSplit() {
  const surface = document.getElementById('sessionSurface');
  const splitter = document.getElementById('surfaceSplitter');
  if (surface) surface.classList.remove('split');
  if (splitter) splitter.hidden = true;
}

function showSftpForTab(tabId) {
  const body = document.getElementById('terminalBody');
  const sbody = document.getElementById('sftpBody');
  clearSplit();
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
    // A persisted dual pane (or one opened elsewhere for this tab) must show
    // its chrome on every activation, not only when toggled in this session.
    applySftpDualChrome(tabId);
  }
  let queuePanel = document.getElementById('sftpQueuePanel');
  if (!queuePanel && sbody) {
    queuePanel = buildQueuePanel();
    sbody.appendChild(queuePanel);
    renderQueuePanel(); // whatever the queue already knows, without asking again
  }
  if (queuePanel) queuePanel.style.display = 'flex';
  const rec = window.tabRecord ? window.tabRecord(tabId) : null;
  if (rec && rec.hostEl) rec.hostEl.style.display = 'none';
  // A transfer that finished while this tab was in the background changed
  // its folder: list it again now that it is shown.
  const tab = sftpTab(tabId);
  if (tab && tab._listingDirty && tab.sftpReady) {
    tab._listingDirty = false;
    refreshSftpPanel(tabId, { forceFresh: true });
  }
  sftpPaintModeBusy();
}

function showSshForTab(tabId) {
  const rec = window.tabRecord ? window.tabRecord(tabId) : null;
  const sbody = document.getElementById('sftpBody');
  clearSplit();
  if (sbody) {
    sbody.classList.remove('visible');
    for (const child of sbody.children) child.style.display = 'none';
  }
  const body = document.getElementById('terminalBody');
  if (body) body.style.display = 'flex';
  if (rec && rec.hostEl) rec.hostEl.style.display = 'block';
  if (typeof window.showTabTerminal === 'function') window.showTabTerminal(tabId);
  requestAnimationFrame(() => {
    if (typeof window.fitActiveTerminal === 'function') window.fitActiveTerminal();
  });
  sftpPaintModeBusy();
}

// ─── panel construction ─────────────────────────────────────────────────────

function buildSftpPanel(tabId) {
  const panel = document.createElement('div');
  panel.className = 'sftp-panel';
  panel.id = 'sftpPanel-' + tabId;
  panel.style.display = 'none';

  // ── toolbar (every button carries a short label; the row wraps, never clips) ──
  // On a narrow panel the labels are visually hidden but stay each button's
  // name, and the secondary buttons fold into More (A5-07, styles.css).
  const toolbar = document.createElement('div');
  toolbar.className = 'sftp-toolbar';
  const mkBtn = (icon, title, fn, label) => {
    const b = document.createElement('button');
    b.className = 'ghost-btn';
    b.title = title;
    b.innerHTML = `${ico(icon)}${label ? `<span class="btn-label">${label}</span>` : ''}`;
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
  const uploadBtn = mkBtn('upload-cloud',
    'Upload files from this computer to this folder (or drop them from your file manager onto the list)',
    () => sftpUploadSelected(tabId), 'Upload');
  const bookmarkBtn = mkBtn('star', 'Bookmarks', (ev) => openBookmarkMenu(ev, tabId), 'Bookmarks');
  const searchBtn = mkBtn('search', 'Search recursively (in current tree)', () => toggleSearchBar(tabId), 'Search');
  const hiddenBtn = mkBtn('eye', 'Show/hide dotfiles', () => {
    const tab = sftpTabState(sftpTab(tabId));
    tab.showHidden = !tab.showHidden;
    // Client-side re-filter only: sftp_list_dir already returned the hidden
    // entries (the server doesn't filter them), so this never needs a
    // network round trip - just re-run the existing cached listing. The
    // button's active class is set inside renderEntries from tab.showHidden,
    // the single place that keeps it in sync with what the list shows.
    renderEntries(tabId);
    if (typeof sftpCmpAfterRefresh === 'function') sftpCmpAfterRefresh(tabId);
  }, 'Hidden');
  const dualBtn = mkBtn('folder-open', 'Toggle local pane', () => toggleDualPane(tabId), 'Dual');
  const colsBtn = mkBtn('settings', 'Show/hide permissions & owner columns', () => sftpToggleOwnerCols(tabId, panel), 'Columns');
  colsBtn.classList.add('sftp-cols-btn');
  const logBtn = mkBtn('history', 'Activity log', () => sftpToggleLog(tabId), 'Log');
  {
    const t = sftpTabState(sftpTab(tabId));
    if (t && t.showHidden) hiddenBtn.classList.add('active');
    if (t && t.showOwnerCols) colsBtn.classList.add('active');
  }
  panel.classList.toggle('show-owner-cols', !!(sftpTab(tabId) && sftpTab(tabId).showOwnerCols));
  // A5-07: on a narrow panel these fold into More (styles.css container
  // queries), so the toolbar keeps to one row and the file list its room.
  // Compare and Sync browse join them (sftpCmpEnsureButtons).
  for (const b of [colsBtn, dualBtn, logBtn]) b.classList.add('sftp-tb-secondary');
  const moreBtn = mkBtn('ellipsis', 'More actions', () => openSftpMoreMenu(tabId, moreBtn), 'More');
  moreBtn.classList.add('sftp-more-btn');
  moreBtn.setAttribute('aria-haspopup', 'menu');
  moreBtn.setAttribute('aria-expanded', 'false');

  toolbar.appendChild(upBtn);
  toolbar.appendChild(refreshBtn);
  toolbar.appendChild(mkdirBtn);
  toolbar.appendChild(newFileBtn);
  toolbar.appendChild(uploadBtn);
  toolbar.appendChild(bookmarkBtn);
  toolbar.appendChild(searchBtn);
  toolbar.appendChild(hiddenBtn);
  toolbar.appendChild(colsBtn);
  toolbar.appendChild(dualBtn);
  toolbar.appendChild(logBtn);
  toolbar.appendChild(moreBtn);

  // ── search bar (hidden until toggled) ──
  const searchBar = document.createElement('div');
  searchBar.className = 'sftp-searchbar';
  searchBar.id = 'sftpSearchBar-' + tabId;
  searchBar.hidden = true;
  const searchInput = document.createElement('input');
  searchInput.type = 'text';
  searchInput.placeholder = 'Find in this directory tree...';
  searchInput.id = 'sftpSearchInput-' + tabId;
  // A name and a hint of its own (A1-34): it had a placeholder only, and the
  // file names typed into it picked up spellcheck and autofill.
  searchInput.setAttribute('aria-label', 'Search file names under this folder');
  searchInput.spellcheck = false;
  searchInput.autocomplete = 'off';
  const searchHint = document.createElement('span');
  searchHint.className = 'sftp-searchhint';
  searchHint.id = 'sftpSearchHint-' + tabId;
  searchHint.textContent = 'Enter searches the names under this folder and its subfolders; Escape closes.';
  const searchResults = document.createElement('div');
  searchResults.className = 'sftp-searchresults';
  searchResults.id = 'sftpSearchResults-' + tabId;
  const searchStatus = document.createElement('span');
  searchStatus.className = 'sftp-searchstatus';
  searchStatus.id = 'sftpSearchStatus-' + tabId;
  searchStatus.setAttribute('role', 'status');
  searchInput.setAttribute('aria-describedby', searchHint.id + ' ' + searchStatus.id);
  searchBar.appendChild(searchInput);
  searchBar.appendChild(searchHint);
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
  pathBox.hidden = true;   // the breadcrumb below is the default face
  pathBox.addEventListener('keydown', (ev) => {
    if (ev.key === 'Enter') { ev.preventDefault(); sftpUiNavigateRemote(tabId, pathBox.value.trim()); }
    else if (ev.key === 'Escape') { pathBox.value = sftpTab(tabId)?.sftpPath || ''; showRemoteCrumbs(tabId); }
  });
  pathBox.addEventListener('focus', () => pathBox.select());
  pathBox.addEventListener('blur', () => showRemoteCrumbs(tabId));

  /// The path was a bare text field: to go up two directories you edited a
  /// string. Each segment is now a button, and clicking the empty space (or the
  /// pencil) hands you back the field you are reading this in.
  const crumbs = document.createElement('div');
  crumbs.className = 'sftp-crumbs';
  crumbs.id = 'sftpCrumbs-' + tabId;
  crumbs.title = 'Click a folder to jump to it, or click here to type a path';
  crumbs.addEventListener('click', (ev) => {
    if (ev.target.closest('.sftp-crumb')) return;   // a segment handles its own click
    editRemotePath(tabId);
  });

  const remoteCopy = mkPathCopy(() => sftpTab(tabId)?.sftpPath || '');
  remoteHead.appendChild(remoteTitle);
  remoteHead.appendChild(crumbs);
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
  // Focusable by script only (not a Tab stop): the list holds the focus when
  // a quick-find leaves no row to stand on (see sftpRestoreRowFocus).
  tableWrap.tabIndex = -1;
  tableWrap.appendChild(table);
  // Right-click on the list's empty space: the folder's own menu (Upload, New
  // folder, New file, Refresh). Rows have theirs (the tbody delegation).
  tableWrap.addEventListener('contextmenu', (ev) => {
    if (ev.target.closest('tr.sftp-entry')) return;
    ev.preventDefault();
    openSftpDirMenu(ev.clientX, ev.clientY, tabId);
  });
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

  // All row interaction (click/dblclick/keydown/contextmenu/pointerdown,
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
  const localHome = mkBtn('folder', 'Home', () => sftpLocalNavigate(tabId, ''), 'Home');
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
  // Three columns, the three its rows fill (A1-31): sftp_local_list reports
  // no mode or owner, so Permissions/Owner headed two empty columns here.
  localThead.innerHTML = `<tr><th>Name</th><th>Size</th><th>Modified</th></tr>`;
  const localBody = document.createElement('tbody');
  localBody.id = 'sftpLocalTbody-' + tabId;
  localTable.appendChild(localThead);
  localTable.appendChild(localBody);
  const localWrap = document.createElement('div');
  localWrap.className = 'sftp-tablewrap';
  localWrap.appendChild(localTable);
  localPane.appendChild(localHead);
  localPane.appendChild(localWrap);
  // Selection, the right-click menu and the start of a drag are delegated on
  // the wrapper, so a refresh does not have to re-attach them. The per-row
  // dblclick (descend/upload) that predates this still lives in
  // sftpLocalShowListing, where it has always been.
  //
  // The call that used to stand here was left behind by the delegated-rows
  // refactor - the remote pane moved to a delegated tbody listener, the local
  // pane was meant to follow, and the function was never written, so it threw
  // a ReferenceError in buildSftpPanel and the whole SFTP view rendered
  // blank. Removing the call unblocked the view but left the local pane with
  // no selection and no context menu at all, so a right-click there fell
  // through to the webview's own Back/Reload/Save-as menu. This is the
  // function it was always calling for.
  sftpWireLocalTbodyDelegation(tabId, localWrap);

  // ── splitter between the local and the remote pane (A1-15) ──
  // ONE share: --local-pct sizes the local pane and the remote pane takes
  // what is left (styles.css). The drag used to set --local-pct while the
  // remote pane kept a fixed 50% of its own, so a drag pushed the remote pane
  // past the edge or left a blank strip. A separator for the keyboard too.
  const splitter = document.createElement('div');
  splitter.className = 'sftp-splitter';
  splitter.id = 'sftpSplitter-' + tabId;
  splitter.setAttribute('role', 'separator');
  splitter.setAttribute('aria-orientation', 'vertical');
  splitter.setAttribute('aria-label', 'Resize the local and the remote pane');
  splitter.setAttribute('aria-controls', localPane.id);
  splitter.setAttribute('aria-valuemin', String(SFTP_LOCAL_PCT_MIN));
  splitter.setAttribute('aria-valuemax', String(SFTP_LOCAL_PCT_MAX));
  splitter.tabIndex = 0;
  let localPct = 50;
  const applyLocalPct = (pct) => {
    localPct = Math.min(SFTP_LOCAL_PCT_MAX, Math.max(SFTP_LOCAL_PCT_MIN, pct));
    panel.style.setProperty('--local-pct', localPct.toFixed(2) + '%');
    splitter.setAttribute('aria-valuenow', String(Math.round(localPct)));
  };
  applyLocalPct(localPct);
  sftpWireSeparator(splitter, {
    toPct: (x) => {
      const r = splitter.parentElement.getBoundingClientRect();
      return ((x - r.left) / (r.width || 1)) * 100;
    },
    apply: applyLocalPct,
    current: () => localPct,
  });

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
  // Takes the panel itself: it is not in the document yet (the caller appends
  // it), so looking the toolbar up by id found nothing and the toggle never
  // appeared. (In-page drags are wired on the tbodies - sftpRowPointerDown.)
  ensureSftpPreserveTsToggle(tabId, panel);
  return panel;
}

// ─── preserve-timestamps toggle (FileZilla: "Preserve timestamps of
// transferred files") ────────────────────────────────────────────────────────

/// Idempotent: append the toggle next to the hidden-files button if absent
/// (never restructure the toolbar - G owns that block; this appends only).
/// `root` is the panel when it is not in the document yet.
function ensureSftpPreserveTsToggle(tabId, root) {
  const panel = root || document.getElementById('sftpPanel-' + tabId);
  if (!panel || panel.querySelector('#' + CSS.escape('sftpPreserveTsBtn-' + tabId))) return;
  const toolbar = panel.querySelector('.sftp-toolbar');
  if (!toolbar) return;
  const hiddenBtn = [...toolbar.querySelectorAll('button')].find(b => b.title === 'Show/hide dotfiles');
  const tab = sftpTabState(sftpTab(tabId));
  const btn = document.createElement('button');
  btn.className = 'ghost-btn';
  btn.id = 'sftpPreserveTsBtn-' + tabId;
  btn.title = 'Preserve timestamps of transferred files (keep each file\'s modified time)';
  btn.innerHTML = `${ico('history')}<span class="btn-label">Keep times</span>`;
  btn.classList.toggle('active', !!tab.sftpPreserveTs);
  btn.addEventListener('click', () => window.sftpPreserveTsToggle(tabId));
  toolbar.insertBefore(btn, hiddenBtn ? hiddenBtn.nextSibling : null);
}

/// Toggle per-tab preserve-timestamps; persists the global default setting.
function sftpPreserveTsToggle(tabId) {
  const tab = sftpTabState(sftpTab(tabId));
  if (!tab) return;
  const paint = (on) => {
    tab.sftpPreserveTs = on;
    const btn = document.getElementById('sftpPreserveTsBtn-' + tabId);
    if (btn) btn.classList.toggle('active', on);
  };
  const on = !tab.sftpPreserveTs;
  paint(on);
  sftpSaveSetting('sftpPreserveTs', on ? '1' : '0', () => paint(!on));
  sftpLog(tabId, `preserve timestamps ${on ? 'ON' : 'OFF'}`);
}
window.sftpPreserveTsToggle = sftpPreserveTsToggle;

/// Save a preference set from the file browser, whose control has already
/// changed on screen. When settings_set refuses it, `revert` puts the
/// control back to what is in effect and the backend's own message is shown
/// - the rule every Settings row follows (A5-32, app.js save()); these writes
/// used to leave the control flipped on a failure, so the screen and the
/// setting the next launch reads disagreed. state.settings changes only after
/// a save that went through. Resolves true when saved.
async function sftpSaveSetting(key, value, revert) {
  try {
    await call('settings_set', { key, value });
  } catch (e) {
    if (typeof revert === 'function') revert();
    toast((e && (e.message || e.error)) || String(e), 'err');
    return false;
  }
  state.settings = state.settings || {};
  state.settings[key] = value;
  return true;
}

/// Columns: the remote listing's Permissions and Owner columns.
function sftpToggleOwnerCols(tabId, root) {
  const tab = sftpTabState(sftpTab(tabId));
  const panel = root || document.getElementById('sftpPanel-' + tabId);
  if (!tab || !panel) return;
  const paint = (on) => {
    tab.showOwnerCols = on;
    panel.classList.toggle('show-owner-cols', on);
    const btn = panel.querySelector('.sftp-cols-btn');
    if (btn) btn.classList.toggle('active', on);
  };
  const on = !tab.showOwnerCols;
  paint(on);
  sftpSaveSetting('sftpShowOwnerCols', on ? '1' : '0', () => paint(!on));
}

function sftpToggleLog(tabId) {
  const log = document.getElementById('sftpLog-' + tabId);
  if (log) log.hidden = !log.hidden;
}

/// More (A5-07): what the toolbar folds away on a narrow panel, each saying
/// what choosing it does now. The shared menu (openMenu): keyboard, Escape,
/// focus back on More.
function openSftpMoreMenu(tabId, anchor) {
  const tab = sftpTabState(sftpTab(tabId));
  if (!tab) return;
  const log = document.getElementById('sftpLog-' + tabId);
  const cmp = sftpCmpModeOf(tabId);
  openMenu(anchor, [
    { label: tab.showOwnerCols ? 'Hide permissions and owner' : 'Show permissions and owner', icon: 'settings',
      onSelect: () => sftpToggleOwnerCols(tabId) },
    { label: tab.dualPane ? 'Hide local pane' : 'Show local pane', icon: 'folder-open', onSelect: () => toggleDualPane(tabId) },
    { label: log && !log.hidden ? 'Hide activity log' : 'Show activity log', icon: 'history', onSelect: () => sftpToggleLog(tabId) },
    // The next step of each cycle, as an action - "Compare directories off"
    // read as the item that turns comparing off.
    { label: cmp === 'size' ? 'Compare directories by modified time' : cmp === 'mtime' ? 'Stop comparing directories' : 'Compare directories by size',
      icon: 'eye', onSelect: () => sftpCmpToggle(tabId) },
    { label: sftpSyncIsOn(tabId) ? 'Turn off synchronized browsing' : 'Turn on synchronized browsing', icon: 'folder-tree',
      onSelect: () => sftpSyncToggle(tabId) },
  ], { alignRight: true, label: 'More file browser actions' });
}

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

// ─── names as shown ─────────────────────────────────────────────────────────
//
// A file name is whatever the server's owner chose. Shown as it is, a
// direction override reverses what follows it ("report<RLO>gnp.exe" reads as
// "reportexe.png"), a line break adds a line of its own to a question, and
// two ONE DOT LEADERs (U+2024), two LISU TONE MYA TIs or " .." pass for "..",
// the parent folder. So wherever a name is shown - the listing, a question, a
// toast - such characters are spelled out ("<U+202E>", "\n", "<U+0020>"),
// and inside a sentence the name is kept to itself so it cannot carry the
// words after it along.

/// The characters spelled out in any name: controls (C0, DEL, C1), format and
/// default-ignorable characters (direction marks, overrides and isolates,
/// zero-width ones), line and paragraph separators, spaces other than U+0020,
/// and the dots that only ever stand in for "." (U+2024, U+2025, U+FE52,
/// U+FF0E).
const SFTP_ODD_CHARS = /[\u0000-\u001F\u007F-\u009F\p{Cf}\p{Default_Ignorable_Code_Point}\u2028\u2029\u00A0\u1680\u2000-\u200A\u202F\u205F\u3000\u2024\u2025\uFE52\uFF0E]/gu;
const SFTP_ODD_CHAR = new RegExp(SFTP_ODD_CHARS.source, 'u');

/// Characters that pass for a dot: Unicode's confusables of FULL STOP, the
/// middle dots, the ellipsis. Most have uses of their own (U+0660 is the
/// Arabic-Indic zero, U+00B7 the Catalan middle dot), so they are spelled out
/// only in a name of nothing else - one that passes for ".", ".." or "...".
const SFTP_DOT_LOOKALIKES = /[\u00B7\u0387\u0660\u06F0\u0701\u0702\u1427\u16EB\u2024-\u2027\u2219\u22C5\u2E31\u2E33\u30FB\uA4F8\uA60E\uA78F\uFE52\uFF0E\uFF65]|\u{10A50}/gu;
const SFTP_DOT_LOOKALIKE = new RegExp(SFTP_DOT_LOOKALIKES.source, 'u');

/// Whether a name passes for dots: with its spaces (U+0020) taken out,
/// nothing is left, or only dots and look-alikes ("", " ", " ..", ".. ",
/// "...", two U+A4F8).
function sftpDotsOnly(name) {
  const bare = String(name == null ? '' : name).replace(/ /g, '');
  return bare === '' || [...bare].every((ch) => ch === '.' || SFTP_DOT_LOOKALIKE.test(ch));
}

/// One character spelled out: "\n", "\r", "\t" or "<U+XXXX>".
function sftpSpellChar(ch) {
  if (ch === '\n') return '\\n';
  if (ch === '\r') return '\\r';
  if (ch === '\t') return '\\t';
  return '<U+' + ch.codePointAt(0).toString(16).toUpperCase().padStart(4, '0') + '>';
}

/// One name with what cannot be seen, or passes for something else, spelled
/// out: its odd characters; in a name of nothing but dots, the look-alikes;
/// and spaces at either end, or more than one in a row.
function sftpSpellName(name) {
  let out = name.replace(SFTP_ODD_CHARS, sftpSpellChar);
  if (sftpDotsOnly(name)) out = out.replace(SFTP_DOT_LOOKALIKES, sftpSpellChar);
  return out.replace(/^ +| +$| {2,}/g, (run) => '<U+0020>'.repeat(run.length));
}

/// `text` - a name, or a path of names - spelled out name by name
/// (sftpSpellName): a path through a folder named with two U+A4F8 reads
/// "/home/u/<U+A4F8><U+A4F8>/app.conf", not "/home/u/../app.conf". Text only
/// - the result goes through textContent.
function sftpSpell(text) {
  return String(text == null ? '' : text).split('/').map(sftpSpellName).join('/');
}

/// A name for a sentence in plain text (a toast, a question): spelled out,
/// then kept to itself between FIRST STRONG ISOLATE and POP DIRECTIONAL
/// ISOLATE. Spelled out first, it holds no isolate or override of its own to
/// break out with.
function sftpInText(text) {
  return '\u2068' + sftpSpell(text) + '\u2069';
}

/// A name the listing flags: one it spells out anything of, or one that
/// passes for dots (sftpDotsOnly - "..." reads as a way up, and so do " .."
/// and two U+A4F8; an empty one reads as nothing).
function sftpUnusualName(name) {
  const n = String(name == null ? '' : name);
  return sftpDotsOnly(n) || sftpSpellName(n) !== n;
}

/// The Name cell of a listing row, both panes (A1-16). The cell stays a table
/// cell - it was itself the flex box, which took it out of the table's column
/// layout, so long names pushed the other columns about and rows wrapped to
/// different heights. Icon and name sit in a nested flex wrapper; the name is
/// one line, cut with an ellipsis, and shown whole on hover. An unusual name
/// is shown spelled out, with a flag that says why.
function sftpNameCell(entry, isLink) {
  const td = document.createElement('td');
  td.className = 'sftp-tdname';
  const wrap = document.createElement('span');
  wrap.className = 'sftp-namewrap';
  wrap.appendChild(sftpEntryIcon(entry.isDir, isLink));
  const name = document.createElement('span');
  name.className = 'sftp-name';
  const shown = sftpSpell(entry.name);
  name.textContent = shown;
  name.title = shown;
  wrap.appendChild(name);
  if (sftpUnusualName(entry.name)) {
    const flag = document.createElement('span');
    flag.className = 'sftp-name-flag';
    flag.setAttribute('aria-hidden', 'true');
    flag.textContent = '!';
    flag.title = sftpUnusualNote(entry.name);
    wrap.appendChild(flag);
  }
  td.appendChild(wrap);
  return td;
}

/// What the flag on an unusual name says - in its tooltip, and after the
/// question before an upload into such a folder. The name is kept to itself.
function sftpUnusualNote(name) {
  const n = String(name == null ? '' : name);
  if (!n) return 'Unusual name: it is empty.';
  const shown = sftpInText(n);
  if (!n.replace(/ /g, '')) return `Unusual name: ${shown} - only spaces.`;
  if (sftpDotsOnly(n)) return `Unusual name: ${shown} - only dots, or characters that look like dots, so it can read as a way up.`;
  return `Unusual name: ${shown} - it holds characters that are invisible or look like others, spelled out here.`;
}

/// Validate and resolve a typed remote path: it must start with '/'; empty and
/// '.' segments drop out and '..' removes the segment before it, never going
/// above the root. sftp_list_dir echoes whatever path it was asked for, so an
/// unresolved '/var/www/..' used to become the tab's folder verbatim: Up then
/// went one level DEEPER and the dots leaked into every path built from it.
function sftpUiNormalizeRemotePath(input) {
  if (!input || !input.startsWith('/')) return null;
  const parts = [];
  for (const seg of input.split('/')) {
    if (!seg || seg === '.') continue;
    if (seg === '..') parts.pop();
    else parts.push(seg);
  }
  return { path: '/' + parts.join('/'), parts };
}

/// Draw the current remote path as clickable segments, each name spelled out
/// as the listing shows it (a folder that passes for ".." reads as such
/// here too).
function renderRemoteCrumbs(tabId) {
  const crumbs = document.getElementById('sftpCrumbs-' + tabId);
  if (!crumbs) return;
  const full = (sftpTab(tabId) || {}).sftpPath || '/';
  crumbs.innerHTML = '';

  const mk = (label, target, isLast) => {
    const b = document.createElement('button');
    b.type = 'button';
    b.className = 'sftp-crumb' + (isLast ? ' current' : '');
    b.textContent = sftpSpell(label);
    b.title = sftpSpell(target);
    b.addEventListener('click', (ev) => {
      ev.stopPropagation();
      if (!isLast) sftpUiNavigateRemote(tabId, target);
    });
    crumbs.appendChild(b);
  };
  const sep = () => {
    const s = document.createElement('span');
    s.className = 'sftp-crumb-sep';
    s.textContent = '›';
    crumbs.appendChild(s);
  };

  const parts = full.split('/').filter(Boolean);
  mk('/', '/', parts.length === 0);
  let acc = '';
  parts.forEach((p, i) => {
    acc += '/' + p;
    sep();
    mk(p, acc, i === parts.length - 1);
  });
}

/// Swap the breadcrumb for the editable field - the same input that used to be
/// the only way to see where you were.
function editRemotePath(tabId) {
  const crumbs = document.getElementById('sftpCrumbs-' + tabId);
  const pathBox = document.getElementById('sftpPath-' + tabId);
  if (!crumbs || !pathBox) return;
  pathBox.value = (sftpTab(tabId) || {}).sftpPath || '';
  crumbs.hidden = true;
  pathBox.hidden = false;
  pathBox.focus();
}

function showRemoteCrumbs(tabId) {
  const crumbs = document.getElementById('sftpCrumbs-' + tabId);
  const pathBox = document.getElementById('sftpPath-' + tabId);
  if (!crumbs || !pathBox) return;
  pathBox.hidden = true;
  crumbs.hidden = false;
  renderRemoteCrumbs(tabId);
}

/// Enter in the remote path box, or a click on a breadcrumb segment: navigate
/// through the same transactional listing as every other move (see
/// refreshSftpPanel), so the breadcrumb, rows and path all follow - or, when
/// the listing fails, all stay where they were.
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
  // Whether you typed a path or clicked a crumb, you end up back on the
  // breadcrumb - the field is a detour, not the resting state.
  showRemoteCrumbs(tabId);
  if (norm.path === tab.sftpPath) { box.value = tab.sftpPath; return; }
  if (!(await refreshSftpPanel(tabId, { path: norm.path }))) box.value = tab.sftpPath || '/';
}

/// Enter in the local path box: navigate; on failure toast and revert.
async function sftpUiNavigateLocal(tabId, input) {
  const tab = sftpTab(tabId);
  const box = document.getElementById('sftpLocalPath-' + tabId);
  if (!tab || !box || !input) return;
  if (input === tab.localPath) { box.value = tab.localPath; return; }
  if (!(await sftpLocalNavigate(tabId, input))) box.value = tab.localPath || '';
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
    // Multi-select has always worked (ctrl/cmd-click, shift-click for a range,
    // Ctrl+A for all) but nothing on screen said so, and users reported it as
    // missing outright. Spell it out while nothing is selected; the hint is
    // replaced by the live count as soon as it is being used.
    text = `${total} item${total === 1 ? '' : 's'}`;
    if (total) text += '  ·  Ctrl+click to select · Shift+click for a range · Ctrl+A for all';
  }
  if (tab.dualPane) {
    // _localEntries is the cached local-entry ARRAY (see sftpUiLocalLoad).
    const localTotal = (tab._localEntries || []).length;
    if (localTotal) {
      text += ` · local: ${localTotal} item${localTotal === 1 ? '' : 's'}`;
      // Without this the only "N selected" on the line is the remote pane's,
      // which reads as though a local selection had not registered.
      const localSel = tab.localSelected ? tab.localSelected.size : 0;
      if (localSel) text += `, ${localSel} selected`;
    }
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

/// Drop the cached listing of `path` and of every folder under it: a folder
/// that was deleted, renamed or moved, whose subfolders may be cached too.
function sftpCacheInvalidateTree(tab, path) {
  if (!tab || !tab._dirCache || !path) return;
  const prefix = path.endsWith('/') ? path : path + '/';
  for (const key of [...tab._dirCache.keys()]) {
    if (key === path || key.startsWith(prefix)) tab._dirCache.delete(key);
  }
}

/// After a change made on the server: forget the listings it made stale - the
/// folders whose contents changed (`dirs`) and the trees that are gone or
/// moved (`trees`) - and list the folder on screen again if it is one of
/// them. Refreshing whatever folder happened to be on screen instead missed
/// the one that changed when the tab had moved on.
async function sftpAfterRemoteChange(tabId, tab, { dirs = [], trees = [] }) {
  for (const t of trees) sftpCacheInvalidateTree(tab, t);
  for (const d of dirs) sftpCacheInvalidate(tab, d);
  if (sftpTab(tabId) !== tab || !tab.sftpPath) return;
  const cur = tab.sftpPath;
  const shown = dirs.includes(cur) || trees.some((t) => cur === t || cur.startsWith(t.endsWith('/') ? t : t + '/'));
  if (shown) await refreshSftpPanel(tabId, { forceFresh: true });
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
        if (t.sessionId !== j.sessionId && t.sessionId !== j.targetSessionId) continue;
        sftpCacheInvalidateAll(t);
        // Its rows are stale too: redrawn by the transfer-done ticker while
        // on screen, or when the tab is shown again (showSftpForTab).
        t._listingDirty = true;
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
// An outright tab CLOSE needs no equivalent hook for the caches:
// closeSessionTab and clearConnectView (both in app.js) delete the tab from
// state.sessions outright, and _dirCache lives only on that now-unreferenced
// tab object, so it is dropped for free once the object is garbage collected
// - nothing else in this file indexes the cache by tabId independently of the
// tab. The edit-conflict questions are kept apart from the tab, so both call
// sftpPruneEditConflicts.
const sftpPrevOnSessionClosed = window.onSessionClosed;
window.onSessionClosed = function sftpOnSessionClosedWithCacheDrop(tabId) {
  const tab = sftpTab(tabId);
  if (tab) sftpCacheInvalidateAll(tab);
  if (tab) tab._edits = null; // sftp_close stopped every edit watch of the session
  // ...so no question about one of its edits is left either.
  if (tab && tab.sessionId) sftpDropEditConflicts((c) => c.sessionId === tab.sessionId);
  if (tab) sftpForgetPendingListings(tab);
  sftpDisposeSearch(tabId); // an in-flight recursive search dies with its session
  if (typeof sftpPrevOnSessionClosed === 'function') sftpPrevOnSessionClosed(tabId);
};

/// The session of a tab closed: its listings still in flight are about nothing
/// any more. Make them stale (their answers and errors are dropped) and drop
/// the "navigation pending" state, or the reconnected tab's first refresh
/// would wait behind the dead request - up to its timeout - and its error
/// would still be shown. The local pane is reset the same way; it is listed
/// again when the files surface is shown again.
function sftpForgetPendingListings(tab) {
  tab._listSeq = (tab._listSeq || 0) + 1;
  tab._navSeq = 0;
  tab._refreshSeq = 0;
  tab._refreshAfterNav = false;
  tab._localSeq = (tab._localSeq || 0) + 1;
  tab._localNavSeq = 0;
  tab._localRefreshSeq = 0;
  tab._localRefreshAfterNav = false;
}

/// List a remote folder and show it: the tab's current one, or `opts.path` to
/// navigate. `opts.localPath` also moves the local pane once the remote side
/// has succeeded (bookmarks, synchronized browsing). Resolves true when the
/// listing was applied.
///
/// Every remote navigation goes through here, and it is a transaction: the
/// tab's folder changes only once the new listing has ARRIVED, and only the
/// newest request of the tab may apply its answer. Assigning the path first
/// left a failed open on the unreadable folder while the rows still showed the
/// old one, so the next download, rename or delete was built from a folder the
/// user was not looking at; and a slow listing that came back after a quicker,
/// newer one overwrote it.
///
/// A plain refresh (no `opts.path`: a finished transfer, a mkdir, the tab shown
/// again) never overtakes a navigation that is still waiting for its listing -
/// being newer, it would have the navigation's answer thrown away as stale and
/// undo the user's double-click. It is held and runs once the navigation has
/// settled; likewise a refresh a navigation overtakes runs again after it.
async function refreshSftpPanel(tabId, opts = {}) {
  const tab = sftpTab(tabId);
  if (!tab) return false;
  if (!opts.path && tab._navSeq) {
    tab._refreshAfterNav = true;
    return false;
  }
  const seq = tab._listSeq = (tab._listSeq || 0) + 1;
  if (opts.path) {
    if (tab._refreshSeq) tab._refreshAfterNav = true; // that refresh is about to be dropped
    tab._navSeq = seq;
  } else {
    tab._refreshSeq = seq;
  }
  try {
    return await sftpShowListing(tabId, tab, opts, seq);
  } finally {
    if (tab._refreshSeq === seq) tab._refreshSeq = 0;
    if (tab._navSeq === seq) {
      tab._navSeq = 0;
      if (tab._refreshAfterNav) {
        tab._refreshAfterNav = false;
        refreshSftpPanel(tabId, { forceFresh: true });
      }
    }
  }
}

/// One listing request of refreshSftpPanel (request number `seq`): list, then
/// show it only if it is still the tab's newest request.
async function sftpShowListing(tabId, tab, opts, seq) {
  sftpTabState(tab);
  const tbody = document.getElementById('sftpTbody-' + tabId);
  if (!tbody) return false;
  const path = opts.path || tab.sftpPath;
  const sessionId = tab.sessionId;
  let entries, canonicalPath;
  try {
    const cached = !opts.forceFresh && sftpCacheGet(tab, path);
    if (cached) {
      entries = cached.entries;
      canonicalPath = cached.path;
    } else {
      const r = await sftpCall('sftp_list_dir', { sessionId, path });
      entries = r.entries || [];
      canonicalPath = r.path || path;
      sftpCacheSet(tab, path, entries, canonicalPath);
    }
  } catch (e) {
    // An overtaken request has nothing left to say about what is on screen.
    if (seq === tab._listSeq) toast(e.message || String(e), 'err');
    return false;
  }
  if (seq !== tab._listSeq || sftpTab(tabId) !== tab || tab.sessionId !== sessionId) return false;
  if (canonicalPath !== tab.sftpPath) {
    // The selection is a set of NAMES: carried into another folder it selects
    // whatever happens to share a name there.
    tab.sftpSelected.clear();
    tab._focusedName = null;
  }
  tab.sftpPath = canonicalPath;
  sftpSetEntries(tab, entries);
  tab._quickFind = ''; // a fresh listing drops an in-progress quick-find
  const pathBox = document.getElementById('sftpPath-' + tabId);
  if (pathBox && document.activeElement !== pathBox) pathBox.value = tab.sftpPath;
  renderRemoteCrumbs(tabId);
  renderEntries(tabId);
  applySftpDualChrome(tabId);
  if (tab.dualPane) {
    if (opts.localPath !== undefined) sftpLocalNavigate(tabId, opts.localPath);
    else refreshLocalPane(tabId);
  } else if (opts.localPath !== undefined) {
    // Listed when the local pane opens - as a first load, so a folder that
    // is gone by then falls back to home with a message (refreshLocalPane).
    tab.localPath = opts.localPath;
    tab._localLoaded = false;
  }
  if (typeof sftpCmpAfterRefresh === 'function') sftpCmpAfterRefresh(tabId);
  if (typeof sftpCmpEnsureButtons === 'function') sftpCmpEnsureButtons(tabId);
  updateFsInfo(tabId);
  return true;
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
/// <body>, and every handler above - being delegated to the list - would
/// stop receiving keystrokes after a single keypress. While quick-find is
/// active this doubles as "jump to the first match" (classic type-ahead).
///
/// Only called when the focus was in the list before the re-render
/// (renderEntries): a background refresh - a transfer finishing - used to pull
/// it out of the terminal, the path field or an open dialog, and the next
/// keystrokes started a quick-find instead. When no row is left to land on (a
/// quick-find matching nothing) the list itself keeps the focus, so Backspace
/// and Escape still reach the filter.
function sftpRestoreRowFocus(tabId, tbody, visible) {
  const tab = sftpTab(tabId);
  if (!tab) return;
  const targetName = tab._quickFind ? (visible[0] && visible[0].name) : tab._focusedName;
  const row = targetName && tbody.querySelector(`tr[data-name="${CSS.escape(targetName)}"]`);
  if (!row) {
    const wrap = tbody.closest('.sftp-tablewrap');
    if (wrap && !wrap.contains(document.activeElement)) wrap.focus({ preventScroll: true });
    return;
  }
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
  // Comparison tint, re-applied on every virtualized rebuild so scrolling a
  // >300-entry directory does not mount untinted rows mid-compare.
  if (tab._sftpCmpClasses && !entry.isDir) {
    const c = tab._sftpCmpClasses.remote.get(entry.name);
    if (c) tr.classList.add(c);
  }
  tr.tabIndex = 0;
  // Dragged by the pointer (sftpRowPointerDown), not HTML5 drag and drop,
  // which never reaches the page on Windows (A3-23).
  tr.title = (sftpUnusualName(entry.name) ? sftpUnusualNote(entry.name) + ' ' : '') + (entry.isLink
    ? 'Symlink - double-click to resolve and open'
    : entry.isDir ? 'Double-click to open folder' : 'Double-click to download');
  if (tab.sftpSelected.has(entry.name)) tr.classList.add('selected');

  const tdName = sftpNameCell(entry, entry.isLink);

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
  tdOwner.textContent = (entry.uid == null && entry.gid == null) ? '-' : `${entry.uid ?? '?'}:${entry.gid ?? '?'}`;

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
  // Re-measure on EVERY reflow, not just the first: a UI-scale change alters
  // row heights while the cached win.rowH kept the old pixel math (jumpy
  // scrollbar, blank stretches) until the panel was rebuilt. Only a real
  // deviation (>2px) re-runs the windowing with the corrected height.
  const first = tbody.querySelector('tr.sftp-entry');
  if (first) {
    const h = first.getBoundingClientRect().height;
    if (h > 4 && Math.abs(h - win.rowH) > 2) {
      win.rowH = h;
      win.measured = true;
      win.lastRange = null;
      sftpReflowWindow(tbody);
      return;
    }
  }
  if (bottomH > 0) tbody.appendChild(sftpMakeSpacerRow(bottomH, win.colCount));
}

function renderEntries(tabId) {
  const tab = sftpTab(tabId);
  if (!tab || !tab._entries) return;
  const tbody = document.getElementById('sftpTbody-' + tabId);
  if (!tbody) return;
  // The Hidden button's active class is display state, set here from the
  // tab's actual flag rather than only in the click handler: anything that
  // re-renders (navigation, mode switch, compare refresh) then re-asserts it,
  // so the button can never drift out of sync with what the list shows.
  const hiddenBtn = document.querySelector(`#sftpPanel-${tabId} .sftp-toolbar button[title="Show/hide dotfiles"]`);
  if (hiddenBtn) hiddenBtn.classList.toggle('active', !!tab.showHidden);
  sftpWireTbodyDelegation(tabId); // idempotent - the panel already wires this once
  const thead = tbody.parentElement.querySelector('thead');
  if (thead) {
    for (const th of thead.querySelectorAll('th[data-sort]')) {
      th.classList.toggle('sorted', th.dataset.sort === tab.sortKey);
      th.classList.toggle('desc', th.dataset.sort === tab.sortKey && tab.sortDesc);
    }
  }
  tab.sftpSelected = tab.sftpSelected || new Set();

  const sorted = sftpComputeSortedEntries(tab);
  const visible = sftpApplyQuickFind(tab, sorted);
  tab._visibleEntries = visible; // authoritative "all rows" for select-all/shift-range, not just what's mounted
  tab._lastClicked = null; // shift-click anchor doesn't survive a re-render (sort/filter/hidden/quick-find change)
  // The selection is what is on screen. Pruning against the full listing kept
  // rows the dotfile toggle or quick-find had hidden, and Delete then reached
  // a .ssh folder the user could no longer see. (Windowing only limits what is
  // MOUNTED; `visible` is every row the list shows.)
  const shown = new Set(visible.map((e) => e.name));
  for (const n of [...tab.sftpSelected]) if (!shown.has(n)) tab.sftpSelected.delete(n);

  // Captured before the rows are replaced: whether the user was in the list.
  const wrap = tbody.closest('.sftp-tablewrap');
  const hadFocus = !!wrap && wrap.contains(document.activeElement);
  sftpUpdateQuickFindIndicator(tabId, sorted.length, visible.length);
  sftpRenderRows(tbody, visible, (e) => sftpBuildRemoteRow(tab, e), 5);
  if (hadFocus) sftpRestoreRowFocus(tabId, tbody, visible);
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
    // Remember which pane the user is working in, so pane-scoped shortcuts
    // (Ctrl+A) act where they were aimed.
    tab._lastPane = 'remote';
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

  // Dragged to the local pane (download) or onto another remote folder (move)
  // by the pointer - see sftpRowPointerDown.
  tbody.addEventListener('pointerdown', (ev) => sftpRowPointerDown(ev, tabId, 'remote'));

  // On the wrapper rather than the tbody, so the keys still arrive while the
  // list itself has the focus (a quick-find that matches nothing).
  (tbody.closest('.sftp-tablewrap') || tbody).addEventListener('keydown', (ev) => {
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
    // Backspace takes the last character back off the filter: without it a
    // typo filtered the list to nothing and only Escape recovered.
    if (ev.key === 'Backspace' && tab._quickFind) {
      ev.preventDefault();
      tab._quickFind = tab._quickFind.slice(0, -1);
      renderEntries(tabId);
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
        refreshSftpPanel(tabId, { path: full });
      } else {
        queueDownloads(tabId, [full]);
      }
    });
    return;
  }
  if (entry.isDir) {
    if (typeof sftpSyncRemoteNav === 'function' && sftpSyncRemoteNav(tabId, entry.name)) return;
    refreshSftpPanel(tabId, { path: full });
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

/// The tab an SFTP keyboard shortcut may act on, or null. Only while its file
/// panel is in front of the user (sftpPanelOnScreen: no dialog over it, the
/// Servers view showing) and never for a key typed into a text field, where
/// Ctrl+A is "select all" and Ctrl+Y "redo": both used to be taken from every
/// input in the app - the rename prompt, the path field, the Keys search -
/// while a Files tab was active, changing the file selection behind them.
function sftpShortcutTab(ev) {
  const tab = sftpTab(state.activeTabId);
  if (!tab || !sftpPanelOnScreen(tab)) return null;
  const t = ev.target;
  if (t && t.closest && t.closest('input, textarea, select, [contenteditable]:not([contenteditable="false"])')) return null;
  return tab;
}

// Ctrl+A in the file list selects all rows - the full filtered list (Task 4:
// hidden-file toggling and quick-find already narrowed tab._visibleEntries),
// not just whatever the windowed renderer currently has mounted. It belongs
// to the list: it acts on a key from a pane's rows (or the list itself), or
// from no element in particular (the page body - a click on a local row,
// which takes no focus, leaves it there; then the pane last clicked wins).
document.addEventListener('keydown', (ev) => {
  if (!(ev.ctrlKey || ev.metaKey) || ev.shiftKey || ev.altKey || ev.key.toLowerCase() !== 'a') return;
  const active = sftpShortcutTab(ev);
  if (!active) return;
  const t = ev.target;
  const within = (sel) => !!(t && t.closest && t.closest(sel));
  const inLocal = within(`#sftpLocalPane-${CSS.escape(active.tabId)} .sftp-tablewrap`);
  const inRemote = within(`#sftpPanel-${CSS.escape(active.tabId)} .sftp-remote .sftp-tablewrap`);
  const nowhere = !t || t === document || t === document.body || t === document.documentElement;
  if (!inLocal && !inRemote && !nowhere) return;
  ev.preventDefault();
  sftpTabState(active);
  if ((inLocal || (nowhere && active._lastPane === 'local')) && !document.getElementById('sftpLocalPane-' + active.tabId)?.hidden) {
    const localVisible = active._localEntries || [];
    active.localSelected.clear();
    for (const e of localVisible) active.localSelected.add(e.name);
    sftpRefreshLocalSelectionClasses(active.tabId);
    sftpUpdateStatusBar(active.tabId);
    return;
  }
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
  if (mode == null) return '-';
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
  refreshSftpPanel(tabId, { path: sftpParent(tab.sftpPath) });
}

/// New folder / New file go into the folder the prompt NAMES - the one on
/// screen when it opened. A navigation that landed while it was open used to
/// put the folder in the new one instead. Afterwards only that
/// folder's listing is dropped, and re-listed if it is still on screen.
async function sftpMkdirPrompt(tabId) {
  sftpCreatePrompt(tabId, 'New folder', 'Create a folder in', 'new-folder', 'sftp_mkdir', 'mkdir');
}

async function sftpTouchPrompt(tabId) {
  sftpCreatePrompt(tabId, 'New file', 'Create an empty file in', 'new-file.txt', 'sftp_touch', 'touch');
}

/// Whether the answer to a dialog may still act on the session it was asked
/// about - the tab can close, reconnect or be torn down by a lock while it is
/// open. Says so when it may not, rather than ignoring the answer.
function sftpSameSession(tabId, tab, sessionId) {
  if (sftpTab(tabId) === tab && tab.sessionId === sessionId) return true;
  toast('The connection changed while the dialog was open - nothing was done. Try again.', 'warn');
  return false;
}

function sftpCreatePrompt(tabId, title, ask, initial, cmd, verb) {
  const tab = sftpTab(tabId);
  if (!tab) return;
  const dir = tab.sftpPath;
  const sessionId = tab.sessionId;
  promptModal(title, `${ask} ${dir}:`, initial, async (name) => {
    if (!name) return;
    if (!sftpSameSession(tabId, tab, sessionId)) return;
    try {
      await sftpCall(cmd, { sessionId, path: sftpJoin(dir, name) });
      sftpLog(tabId, `${verb} ${sftpJoin(dir, name)}`);
      await sftpAfterRemoteChange(tabId, tab, { dirs: [dir] });
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
// lexical scope, so the names are sftp-prefixed on purpose). "Don't ask again"
// is kept per side: one flag meant ticking it while clearing out remote files
// also switched off the prompt for permanent, recursive LOCAL deletes.
const sftpDeleteConfirmSuppressed = { remote: false, local: false };
let sftpDeleteInFlight = false;

/// `"a.txt", "b.txt", "c.txt" and 2 more` - what a confirmation is about, so
/// it can never be agreed to without seeing what it deletes.
function sftpNameList(names, max = 3) {
  const shown = names.slice(0, max).map((n) => `"${sftpInText(n)}"`).join(', ');
  return names.length > max ? `${shown} and ${names.length - max} more` : shown;
}

/// In-app delete confirmation: names the item(s), Yes / Cancel, and a
/// session-scoped "don't ask again" checkbox for this `side` ('remote' or
/// 'local') only (never persisted - a restart restores the safety prompt).
/// Runs onYes only on Yes.
function sftpConfirmDelete(message, onYes, side = 'remote') {
  if (sftpDeleteConfirmSuppressed[side]) { onYes(); return; }
  el('deleteTitle').textContent = 'Delete';
  el('deleteMessage').textContent = message;
  el('deleteSkipLabel').textContent = `Don't ask again for ${side} deletes this session.`;
  el('deleteSkipSession').checked = false;
  el('deleteModal').hidden = false;
  const finish = (yes) => {
    unregisterModalCloser(el('deleteModal'));
    el('deleteModal').hidden = true;
    // Only a confirmed delete may disarm the prompt. Reading the checkbox on
    // every exit meant ticking it and then backing out via Cancel still
    // switched the safety prompt off for the session, so the NEXT delete -
    // one the user never agreed to skip confirming - went through silently.
    if (yes && el('deleteSkipSession').checked) sftpDeleteConfirmSuppressed[side] = true;
    el('deleteModal').removeEventListener('click', onBackdrop);
    if (yes) onYes();
  };
  function onBackdrop(ev) {
    if (ev.target === el('deleteModal')) finish(false);
  }
  el('deleteYesBtn').onclick = () => finish(true);
  el('deleteCancelBtn').onclick = () => finish(false);
  // Escape, a vault lock and a backdrop click all mean "no" - abandoning a
  // destructive prompt must never be harder than confirming it, and every exit
  // is the safe answer. Escape and the lock arrive through this closer: the
  // central modal handler runs it for the topmost layer, wherever focus is
  // (see registerModalCloser in app.js).
  registerModalCloser(el('deleteModal'), () => finish(false));
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
  // The folder the item is in, taken now: the new name is in that folder even
  // if the tab moved on while the prompt was open.
  const dir = tab.sftpPath;
  const sessionId = tab.sessionId;
  const fullPath = sftpJoin(dir, entry.name);
  promptModal('Rename', 'New name:', entry.name, async (newName) => {
    if (!newName || newName === entry.name) return;
    if (!sftpSameSession(tabId, tab, sessionId)) return;
    try {
      await sftpCall('sftp_rename', { sessionId, from: fullPath, to: sftpJoin(dir, newName) });
      sftpLog(tabId, `rename ${entry.name} → ${newName}`);
      // Its folder changed; a renamed folder's old subtree is gone.
      await sftpAfterRemoteChange(tabId, tab, { dirs: [dir], trees: entry.isDir ? [fullPath] : [] });
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

/// Put a context menu on the page at (x, y) kept fully on screen
/// (positionCtxMenuAt, app.js) - placed at the raw pointer position, a menu
/// opened near the right or bottom edge ran off the window with its last
/// items unreachable - and close it on the next press elsewhere.
function sftpShowMenu(menu, x, y) {
  document.body.appendChild(menu);
  positionCtxMenuAt(menu, x, y);
  const onAway = (ev) => {
    if (ev.target.closest && ev.target.closest('#keyConnectMenu')) return;
    closeKeyConnectMenu();
  };
  setTimeout(() => document.addEventListener('mousedown', onAway, { once: true }), 0);
}

/// Right-click on the remote list's empty space: what can be done in this
/// folder - the file menu only ever existed on a row.
function openSftpDirMenu(x, y, tabId) {
  closeKeyConnectMenu();
  if (!sftpTab(tabId)) return;
  const menu = document.createElement('div');
  menu.className = 'ctx-menu';
  menu.id = 'keyConnectMenu';
  const mk = (label, icon, fn) => {
    const b = document.createElement('button');
    b.className = 'ctx-item';
    b.innerHTML = `${ico(icon)}<span>${escapeHtml(label)}</span>`;
    b.addEventListener('click', () => { closeKeyConnectMenu(); fn(); });
    menu.appendChild(b);
  };
  mk('Upload...', 'upload-cloud', () => sftpUploadSelected(tabId));
  mk('New folder...', 'folder-plus', () => sftpMkdirPrompt(tabId));
  mk('New file...', 'file-text', () => sftpTouchPrompt(tabId));
  mk('Refresh', 'refresh-cw', () => refreshSftpPanel(tabId, { forceFresh: true }));
  sftpShowMenu(menu, x, y);
}

/// Upload, from the toolbar or the folder menu (A5-40): the native picker for
/// several files (system_pick_files - Rust opens it and returns paths, nothing
/// is read here), then every picked file into the folder on screen with ONE
/// sftp_queue_add, through the same conflict check as any upload. Uploading
/// used to need the local pane and a selection in it, which nothing on screen
/// explained. The local pane keeps its own Upload in its menu.
async function sftpUploadSelected(tabId) {
  const tab = sftpTab(tabId);
  if (!tab) return;
  sftpTabState(tab);
  const dir = tab.sftpPath || '/';
  let pick;
  try {
    pick = await sftpCall('system_pick_files', { title: 'Upload to ' + dir, multiple: true });
  } catch (e) {
    toast(e.message || String(e), 'err');
    return;
  }
  const paths = pick && !pick.canceled ? arrayOrEmpty(pick.paths) : [];
  if (!paths.length) return;
  // The file's name on either platform's separator.
  const baseName = (p) => String(p).split(/[\\/]/).filter(Boolean).pop() || String(p);
  await queueUploads(tabId, paths.map((p) => ({ local: p, remote: sftpJoin(dir, baseName(p)) })),
    (r) => sftpReportPickedUploads(tabId, r));
}

/// What became of each picked file (RU6a fix1 contract: `items`, one per
/// picked file - `status` "queued" or "error", `added`, `error`, `warnings`
/// (that item's own notes) - with each error also first in `warnings`; the
/// call fails only when every file does). An item counts as queued only when
/// it put a transfer in the queue: "queued" with `added` 0 is a pick the
/// backend walked and skipped (a FIFO, a link to a folder), its reason in its
/// warnings. Shown generically: every item and its notes in the activity log,
/// and a toast that counts what went and names the first that did not (or,
/// all queued, the first note). Without `items` (an older backend) the usual
/// queue report is used.
function sftpReportPickedUploads(tabId, r) {
  const items = arrayOrEmpty(r && r.items).filter(Boolean);
  if (!items.length) {
    sftpLog(tabId, `queued ${(r && r.added) || 0} upload(s)`);
    sftpReportQueueWarnings(tabId, r);
    if (r && r.added > 0) toast(`${r.added} upload(s) queued.`, 'ok');
    return;
  }
  const queued = (i) => i.status === 'queued' && i.added > 0;
  const notesOf = (i) => arrayOrEmpty(i.warnings).map(String);
  const reasonOf = (i) => i.error || notesOf(i)[0] || `${i.path}: nothing to upload`;
  const left = items.filter((i) => !queued(i));
  const shown = new Set();
  for (const i of items) {
    sftpLog(tabId, queued(i)
      ? `upload queued: ${i.path}${i.added > 1 ? ` (${i.added} transfers)` : ''}`
      : `upload not queued: ${reasonOf(i)}`);
    shown.add(reasonOf(i));
    for (const w of notesOf(i)) {
      if (!queued(i) && w === reasonOf(i)) continue;
      sftpLog(tabId, `  ${w}`);
      shown.add(w);
    }
    if (i.error) shown.add(i.error);
  }
  // Notes that belong to no item (a renamed download, say): the usual report.
  sftpReportQueueWarnings(tabId, { warnings: arrayOrEmpty(r && r.warnings).filter((w) => !shown.has(w)) });
  const notes = items.filter(queued).flatMap(notesOf);
  const more = (n) => (n > 1 ? ` (and ${n - 1} more - see the activity log)` : '');
  if (left.length) {
    toast(`${items.length - left.length} of ${items.length} files queued - ${reasonOf(left[0])}${more(left.length)}`, 'warn');
  } else if (notes.length) {
    toast(`${plural(items.length, 'file')} queued for upload - ${notes[0]}${more(notes.length)}`, 'warn');
  } else {
    toast(`${plural(items.length, 'file')} queued for upload.`, 'ok');
  }
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
    if (tab._edits && tab._edits.has(fullPath)) mk('Stop editing', 'x', () => sftpStopEdit(tabId, fullPath));
  }
  // Directory-only (Task 9): sftpCalcDirSize does the round trip and patches
  // the row's size cell in place - grouped with the other info/properties
  // items, ahead of Rename/Delete rather than beside them.
  if (entry.isDir) {
    mk('Calculate size', 'hard-drive', () => sftpCalcDirSize(tabId, entry.name));
  }
  mk('File permissions...', 'settings', () => openChmodDialog(tabId, multi ? selectedPaths : [fullPath], entry));
  mk(multi ? `Rename... (${selected[0]} +${selected.length - 1})` : 'Rename...', 'pencil', () => {
    if (multi) { toast('Rename applies to a single item - select one.', 'info'); return; }
    sftpRenamePrompt(tabId, entry); // the same flow as F2
  });
  // What a drag onto a folder does, without dragging (SC 2.5.7).
  mk(multi ? `Move ${selected.length} items to...` : 'Move to...', 'move', () => sftpMoveToPrompt(tabId, entry));
  mk(multi ? `Delete ${selected.length} items` : 'Delete', 'trash-2', async () => {
    const paths = selectedPaths.length ? selectedPaths : [fullPath];
    const dir = sftpParent(paths[0]); // the folder the menu was opened in
    const firstName = paths[0].split('/').filter(Boolean).pop();
    const firstIsDir = (tab._entries || []).find(e => e.name === firstName)?.isDir ?? false;
    const message = paths.length === 1
      ? (firstIsDir
        ? `Are you sure you want to delete the folder "${sftpInText(firstName)}" and everything inside it?`
        : `Are you sure you want to delete "${sftpInText(firstName)}"?`)
      : `Are you sure you want to delete these ${paths.length} items: ${sftpNameList(paths.map((p) => p.split('/').filter(Boolean).pop()))}?`;
    sftpConfirmDelete(message, async () => {
      if (sftpDeleteInFlight) { toast('A delete is already in progress - one moment.', 'info'); return; }
      sftpDeleteInFlight = true;
      toast(paths.length === 1 ? `Deleting "${sftpInText(firstName)}"...` : `Deleting ${paths.length} items...`, 'info');
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
      else if (ok) toast(paths.length === 1 ? `Deleted "${sftpInText(firstName)}".` : `Deleted ${ok} items.`, 'ok');
      // A stale listing after a delete is worse than a slow one: the
      // folder they were in, and every cached listing at or under a deleted
      // path - a folder visited before it was deleted was otherwise served
      // from the cache, contents and all.
      await sftpAfterRemoteChange(tabId, tab, { dirs: [dir], trees: paths });
    });
  });
  mk('Copy path', 'copy', () => copyText(fullPath).then(ok => ok && toast('Path copied.', 'ok')));
  mk('Copy URL (sftp://)', 'copy', () => {
    const url = `sftp://${tab.host || 'host'}:${tab.port || 22}${fullPath}`;
    copyText(url).then(ok => ok && toast('URL copied.', 'ok'));
  });
  mk('Select all', 'check-circle', () => {
    // Same source as Ctrl+A (_visibleEntries), not the mounted rows: in a
    // virtualized directory (>300 entries) the DOM holds only the visible
    // window, so the row scan selected a screenful while the status bar
    // reported the full count.
    const visible = tab._visibleEntries || [];
    for (const e of visible) tab.sftpSelected.add(e.name);
    sftpRefreshSelectionClasses(tabId);
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

  sftpShowMenu(menu, x, y);
}

// ─── chmod dialog ───────────────────────────────────────────────────────────

/// The nine permission boxes and the bit each one stands for.
const SFTP_CHMOD_BITS = [
  ['owner', 'r', 0o400], ['owner', 'w', 0o200], ['owner', 'x', 0o100],
  ['group', 'r', 0o040], ['group', 'w', 0o020], ['group', 'x', 0o010],
  ['other', 'r', 0o004], ['other', 'w', 0o002], ['other', 'x', 0o001],
];
let sftpChmodOpenSeq = 0;

/// "644", or "2775" when setuid/setgid/sticky are set.
function sftpModeDigits(mode) {
  const digits = (mode & 0o777).toString(8).padStart(3, '0');
  return mode & 0o7000 ? ((mode & 0o7000) >> 9).toString(8) + digits : digits;
}

/// The sftp_chmod calls for one path. A recursive run applies ONE mode to the
/// folder and to everything it walks, so setuid/setgid/sticky - a shared
/// folder's setgid, typically - must never go out with files in scope: that
/// made every file in the tree setgid. The folders get the full mode first
/// (that call is what restores traversal of a tree the owner cannot enter,
/// e.g. a 2664 folder), then the files the plain bits in a call of their own.
/// A mode without special bits is one call.
///
/// `kind` is the path's type as its own stat reports it ('dir' | 'file' |
/// 'unknown'), and only a stat-reported folder is split: that is the only
/// case in which the backend walks. A stat without type bits gets a change to
/// the path itself whatever applyTo says, so the two calls would set the full
/// mode and then the plain bits on that same path - stripping the special
/// bits the user meant to keep. A file, or a path of unknown type, is ONE
/// full-mode call (nothing spreads from it).
function sftpChmodRequests(mode, kind, recursive, scope) {
  if (!recursive || kind !== 'dir' || !(mode & 0o7000) || scope === 'dirs') return [{ mode, applyTo: scope }];
  const requests = scope === 'all' ? [{ mode, applyTo: 'dirs' }] : [];
  requests.push({ mode: mode & 0o777, applyTo: 'files' });
  return requests;
}

/// Permissions dialog for one or more remote paths. It starts from what is
/// really there - every path is stat'ed - and changes only what the user
/// changes:
///   - setuid/setgid/sticky show as a fourth digit and are kept; typing the
///     numeric value sets exactly what was typed (masking the stat to 0o777
///     used to drop them silently from a setgid shared folder);
///   - with several paths, a box whose bit differs between them is
///     indeterminate and leaves that bit as it is on each path (the first
///     path's mode used to be applied to all of them);
///   - Recurse and Apply-to start fresh every time (a tick left over from the
///     last use made the next chmod recursive without being asked);
///   - when a mode cannot be read, Apply stays disabled and says why, instead
///     of offering 644, which strips a folder's x bit.
function openChmodDialog(tabId, paths, entry) {
  const tab = sftpTab(tabId);
  if (!tab || !paths.length) return;
  const modal = document.getElementById('chmodModal');
  if (!modal) { toast('chmod dialog missing from page.', 'err'); return; }
  const title = document.getElementById('chmodTitle');
  title.textContent = paths.length === 1
    ? `Permissions - ${paths[0].split('/').filter(Boolean).pop()}`
    : `Permissions - ${paths.length} items`;

  const boxes = SFTP_CHMOD_BITS.map(([who, bit, mask]) => ({ mask, cb: document.getElementById(`chmod-${who}-${bit}`) }));
  const octal = document.getElementById('chmodOctal');
  const recurse = document.getElementById('chmodRecurse');
  const applyTo = document.getElementById('chmodApplyTo');
  const applyBtn = document.getElementById('chmodApplyBtn');
  const cancelBtn = document.getElementById('chmodCancelBtn');
  const hint = document.getElementById('chmodHint');
  const sessionId = tab.sessionId;
  const openId = ++sftpChmodOpenSeq;
  let modes = null;   // each path's current mode & 0o7777, once read
  let kinds = null;   // each path's type from its stat's type bits: 'dir' | 'file' | 'unknown'
  let special = null; // setuid/setgid/sticky as typed; null keeps each path's own

  recurse.checked = false;
  applyTo.value = 'all';
  hint.hidden = true;
  hint.textContent = '';
  applyBtn.disabled = true; // until the current modes are known
  octal.value = '';
  octal.placeholder = '...';
  for (const { cb } of boxes) { cb.checked = false; cb.indeterminate = false; }

  const rwx = () => boxes.reduce((m, { mask, cb }) => (cb.checked ? m | mask : m), 0);
  const showOctal = () => {
    const specials = special !== null ? [special] : (modes || []).map((m) => m & 0o7000);
    if (boxes.some(({ cb }) => cb.indeterminate) || new Set(specials).size > 1) {
      octal.value = '';
      octal.placeholder = 'mixed';
      return;
    }
    octal.value = sftpModeDigits((specials[0] || 0) | rwx());
    octal.placeholder = '644';
  };
  for (const { cb } of boxes) {
    cb.onchange = () => { cb.indeterminate = false; showOctal(); };
  }
  octal.oninput = () => {
    const v = octal.value.trim();
    if (!/^[0-7]{3,4}$/.test(v)) return;
    const n = parseInt(v, 8);
    for (const { mask, cb } of boxes) { cb.checked = !!(n & mask); cb.indeterminate = false; }
    special = v.length === 4 ? n & 0o7000 : 0;
  };

  (async () => {
    const results = await Promise.all(paths.map((p) =>
      sftpCall('sftp_get_permissions', { sessionId, path: p })
        .then((r) => (r && r.mode != null
          ? {
            mode: r.mode & 0o7777,
            kind: (r.mode & 0o170000) === 0o040000 ? 'dir' : (r.mode & 0o170000) ? 'file' : 'unknown',
          }
          : { error: 'the server did not report them' }))
        .catch((e) => ({ error: (e && e.message) || String(e) }))));
    if (openId !== sftpChmodOpenSeq || modal.hidden) return; // closed or reopened meanwhile
    const bad = results.findIndex((r) => r.error);
    if (bad >= 0) {
      hint.textContent = `Could not read the current permissions of ${paths[bad]}: ${results[bad].error}`;
      hint.hidden = false;
      return;
    }
    modes = results.map((r) => r.mode);
    // The stat's own type, not the listing's: the backend decides whether to
    // walk from the same stat (see sftpChmodRequests).
    kinds = results.map((r) => r.kind);
    for (const { mask, cb } of boxes) {
      const n = modes.filter((m) => m & mask).length;
      cb.checked = n === modes.length;
      cb.indeterminate = n > 0 && n < modes.length;
    }
    showOctal();
    applyBtn.disabled = false;
  })();

  const close = () => {
    unregisterModalCloser(modal);
    modal.hidden = true;
  };
  // Escape and a vault lock close it without applying, matching the backdrop
  // click below. The central modal handler runs this for the topmost layer only,
  // so the keystroke cannot also reach whatever is open behind the dialog (see
  // registerModalCloser in app.js).
  registerModalCloser(modal, close);
  cancelBtn.onclick = close;
  // The header's X: [data-close] is wired per dialog in app.js, and this one
  // never was - the X did nothing (A1-28).
  const xBtn = modal.querySelector('.modal-header [data-close]');
  if (xBtn) xBtn.onclick = close;
  modal.onclick = (ev) => { if (ev.target === modal) close(); };

  applyBtn.onclick = async () => {
    if (!modes) return;
    const recursive = recurse.checked;
    const scope = applyTo.value;
    const targets = paths.map((p, i) => {
      let mode = modes[i];
      for (const { mask, cb } of boxes) if (!cb.indeterminate) mode = cb.checked ? (mode | mask) : (mode & ~mask);
      if (special !== null) mode = (mode & 0o777) | special;
      return [p, mode, kinds[i]];
    });
    close();
    let changed = 0, failed = 0;
    const errors = [];
    for (const [p, mode, kind] of targets) {
      for (const req of sftpChmodRequests(mode, kind, recursive, scope)) {
        try {
          // A recursive run reports the entries it could not change (Task 10)
          // instead of failing outright; those count as failures too.
          const r = await sftpCall('sftp_chmod', { sessionId, path: p, mode: req.mode, recursive, applyTo: req.applyTo });
          changed += r.changed || 0;
          failed += r.failedCount || 0;
          errors.push(...(r.failed || []));
        } catch (e) {
          failed++;
          errors.push(`${p}: ${(e && e.message) || e}`);
        }
      }
    }
    const same = new Set(targets.map(([, m]) => m)).size === 1;
    const shown = same ? sftpModeDigits(targets[0][1]) : '(per item)';
    sftpLog(tabId, `chmod ${shown} on ${paths.length} path(s) - ${changed} changed${failed ? `, ${failed} failed` : ''}`);
    if (failed) toast(`${changed} updated, ${failed} failed: ${errors[0] || 'unknown error'}`, 'err');
    else toast(same ? `Permissions set (${shown}).` : `Permissions set on ${paths.length} items.`, 'ok');
    // The Permissions column of a cached listing would otherwise show the
    // pre-chmod mode until the TTL expires: the folders the items
    // are in, and with a recursive run everything under them.
    sftpAfterRemoteChange(tabId, tab, {
      dirs: [...new Set(paths.map((p) => sftpParent(p)))],
      trees: recursive ? paths : [],
    });
  };

  modal.hidden = false;
  octal.focus();
}

// ─── search ─────────────────────────────────────────────────────────────────

// Every `sftp-search` event carries the id of the search it belongs to (Task
// 10), so ONE listener routes them all: a tab's current search owns its
// results and anything else - a superseded walk, whose {done, cancelled}
// summary now arrives at once - is ignored. The per-search listener this
// replaces was registered after an await, so a double Enter registered two of
// them and every result showed twice for the rest of the tab's life; and with
// no id, a superseded walk's summary overwrote the live one.
const sftpSearches = new Map(); // tabId -> the tab's current search
let sftpSearchSeq = 0;

/// Stop a tab's search, if one is running: the backend walk is cancelled and
/// its events are ignored from here on. Also run when its session closes.
function sftpDisposeSearch(tabId) {
  const search = sftpSearches.get(tabId);
  if (!search) return;
  sftpSearches.delete(tabId);
  call('sftp_search_cancel', { sessionId: search.sessionId, searchId: search.id }).catch(() => {});
}

function sftpOnSearchEvent(ev) {
  const p = (ev && ev.payload) || {};
  const search = [...sftpSearches.values()].find((x) => x.id === p.searchId);
  if (!search || p.sessionId !== search.sessionId) return;
  if (p.done) {
    sftpSearches.delete(search.tabId); // finished: nothing left to cancel
    search.status.textContent = p.cancelled
      ? 'Search stopped.'
      : `${p.matched} match(es)${p.capped ? ' (capped at 500)' : ''} · ${p.scanned} scanned`;
    return;
  }
  search.count++;
  if (search.count > 50) return; // render only first 50
  const item = document.createElement('div');
  item.className = 'sftp-searchitem';
  item.innerHTML = `<span class="sftp-eicon${p.isDir ? ' is-dir' : ''}">${ico(p.isDir ? 'folder' : 'file-text')}</span>${escapeHtml(p.path)}`;
  item.title = 'Navigate to containing folder';
  const tabId = search.tabId;
  item.addEventListener('click', () => {
    const parent = p.path.slice(0, p.path.lastIndexOf('/')) || '/';
    refreshSftpPanel(tabId, { path: parent });
    toggleSearchBar(tabId);
  });
  search.results.appendChild(item);
}
sftpListen('sftp-search', sftpOnSearchEvent).catch(() => {});

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
  sftpDisposeSearch(tabId); // a new search replaces the tab's previous walk
  const search = {
    id: `${tabId}-${Date.now().toString(36)}-${++sftpSearchSeq}`,
    tabId, sessionId: tab.sessionId, count: 0, results, status,
  };
  sftpSearches.set(tabId, search);
  results.innerHTML = '';
  status.textContent = 'Searching...';
  sftpLog(tabId, `search "${query}" under ${tab.sftpPath}`);
  try {
    await call('sftp_search', { sessionId: tab.sessionId, rootPath: tab.sftpPath, query, searchId: search.id });
  } catch (e) {
    if (sftpSearches.get(tabId) !== search) return;
    sftpSearches.delete(tabId);
    status.textContent = 'Search failed: ' + (e.message || e);
  }
}

// ─── bookmarks ──────────────────────────────────────────────────────────────

async function openBookmarkMenu(ev, tabId) {
  const tab = sftpTab(tabId);
  if (!tab) return;
  // Capture the anchor rect BEFORE the first await: ev.currentTarget is
  // reset to null once event dispatch completes, so reading it after the
  // bookmarks round-trip threw a TypeError and the menu never appeared.
  const anchorRect = ev.currentTarget.getBoundingClientRect();
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
      refreshSftpPanel(tabId, { path: b.remotePath, localPath: b.localPath || undefined });
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

  sftpShowMenu(menu, anchorRect.left, anchorRect.bottom + 4);
}

// ─── local pane (dual mode) ─────────────────────────────────────────────────

/// Single source of truth for the dual-pane chrome: panel class, pane and
/// splitter visibility, and the Dual button's active state, all derived from
/// tab.dualPane. Called on toggle AND on build/refresh/show: the toggle used
/// to be the only writer, so a persisted-on dual pane opened hidden (its
/// listing loaded and the status bar counted local items - nothing visible),
/// and queue-driven auto-open never lit the button.
function applySftpDualChrome(tabId) {
  const tab = sftpTab(tabId);
  if (!tab) return;
  const panel = document.getElementById('sftpPanel-' + tabId);
  if (panel) panel.classList.toggle('dual', !!tab.dualPane);
  const localPane = document.getElementById('sftpLocalPane-' + tabId);
  const splitter = document.getElementById('sftpSplitter-' + tabId);
  if (localPane) localPane.hidden = !tab.dualPane;
  if (splitter) splitter.hidden = !tab.dualPane;
  const dualBtn = [...(panel ? panel.querySelectorAll('.sftp-toolbar button') : [])]
    .find(b => b.title === 'Toggle local pane');
  if (dualBtn) dualBtn.classList.toggle('active', !!tab.dualPane);
}

/// `opts.persist: false` opens or closes the pane without saving a layout
/// preference: a download opens it to show where the file goes, which is not
/// the user choosing the dual layout for every future session (it used to be
/// saved as exactly that). The Dual button saves.
function toggleDualPane(tabId, opts = {}) {
  const tab = sftpTab(tabId);
  if (!tab) return;
  sftpTabState(tab);
  const show = (on) => {
    tab.dualPane = on;
    applySftpDualChrome(tabId);
    if (on) refreshLocalPane(tabId);
    // The saved comparison mode applies, and is worked out, when both panes show.
    if (typeof sftpCmpApplyPersisted === 'function') sftpCmpApplyPersisted(tabId);
  };
  const on = !tab.dualPane;
  show(on);
  if (opts.persist === false) return;
  // Saved as the layout every session opens with. A write the backend
  // refuses puts the pane back as it was and says why, like app.js's save():
  // left open, the screen disagreed with what the next launch would restore.
  // The mirror changes only once the write went through.
  sftpSaveSetting('sftpDualPane', on ? '1' : '0', () => {
    if (sftpTab(tabId) === tab && tab.dualPane === on) show(!on);
  }).then((saved) => { if (saved) state.sftpDualPane = on; });
}

/// Core local-pane listing: lists `path` ('' = home; default: the pane's
/// current folder) and only once that worked makes it the pane's folder and
/// renders it - the same transaction as the remote side (refreshSftpPanel).
/// Resolves true when applied, false when a newer listing of this pane
/// overtook it; throws when it failed, with nothing changed (callers decide
/// what to say).
///
/// As on the remote side, a plain refresh (no `path`) never overtakes a local
/// navigation still waiting for its listing - a remote refresh in dual mode
/// re-lists this pane and used to undo the double-click that way. It is held
/// and runs once the navigation has settled.
async function sftpUiLocalLoad(tabId, path) {
  const tab = sftpTab(tabId);
  if (!tab) return false;
  const navigating = path !== undefined;
  if (!navigating && tab._localNavSeq) {
    tab._localRefreshAfterNav = true;
    return false;
  }
  const seq = tab._localSeq = (tab._localSeq || 0) + 1;
  if (navigating) {
    if (tab._localRefreshSeq) tab._localRefreshAfterNav = true; // that refresh is about to be dropped
    tab._localNavSeq = seq;
  } else {
    tab._localRefreshSeq = seq;
  }
  try {
    return await sftpLocalShowListing(tabId, tab, path, seq);
  } finally {
    if (tab._localRefreshSeq === seq) tab._localRefreshSeq = 0;
    if (tab._localNavSeq === seq) {
      tab._localNavSeq = 0;
      if (tab._localRefreshAfterNav) {
        tab._localRefreshAfterNav = false;
        refreshLocalPane(tabId);
      }
    }
  }
}

/// One listing request of sftpUiLocalLoad (request number `seq`).
async function sftpLocalShowListing(tabId, tab, path, seq) {
  sftpTabState(tab);
  const tbody = document.getElementById('sftpLocalTbody-' + tabId);
  const pathEl = document.getElementById('sftpLocalPath-' + tabId);
  if (!tbody) return false;
  const target = path === undefined ? (tab.localPath || '') : path;
  let r;
  try {
    r = await sftpCall('sftp_local_list', { path: target });
  } catch (e) {
    if (seq !== tab._localSeq) return false;
    throw e;
  }
  if (seq !== tab._localSeq || sftpTab(tabId) !== tab) return false;
  const resolved = r.path || target;
  if (resolved !== tab.localPath) {
    // Like the remote pane: a selection of names must not follow the user
    // into a folder where the same names are other files.
    tab.localSelected.clear();
    tab._localLastClicked = null;
  }
  tab.localPath = resolved;
  tab._localLoaded = true;
  tab._localHome = r.home;
  // _localEntries is the cached ARRAY of local entries (Agent E's comparison
  // consumes it; the status bar derives the count via .length).
  tab._localEntries = r.entries || [];
  if (pathEl && document.activeElement !== pathEl) pathEl.value = tab.localPath;
  tbody.innerHTML = '';
  for (const entry of r.entries || []) {
    const tr = document.createElement('tr');
    tr.className = entry.isDir ? 'sftp-entry sftp-dir' : 'sftp-entry sftp-file';
    // Comparison tint, mirroring sftpBuildRemoteRow (virtualized rebuilds).
    if (tab._sftpCmpClasses && !entry.isDir) {
      const c = tab._sftpCmpClasses.local.get(entry.name);
      if (c) tr.classList.add(c);
    }
    tr.dataset.isdir = entry.isDir ? '1' : '0';
    tr.dataset.name = entry.name;
    const tdName = sftpNameCell(entry, false);
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
        // joinLocal keeps the path's own separator; a hard-coded '/' made
        // `C:\Users\u/Documents`, which Up could no longer take apart.
        sftpLocalNavigate(tabId, joinLocal(tab.localPath, entry.name));
      } else {
        // Upload this local file to the current remote dir via the queue.
        queueUploads(tabId, [{ local: joinLocal(tab.localPath, entry.name), remote: sftpJoin(tab.sftpPath, entry.name) }]);
      }
    });
    // Dragged onto the remote pane or a remote folder by the pointer (the
    // wrapper's pointerdown - sftpWireLocalTbodyDelegation), not HTML5.
    tbody.appendChild(tr);
  }
  // Carry the selection across the re-render, dropping whatever is no longer
  // on disk so a stale name cannot be uploaded from the menu.
  const present = new Set((r.entries || []).map(e => e.name));
  for (const n of [...tab.localSelected]) if (!present.has(n)) tab.localSelected.delete(n);
  sftpRefreshLocalSelectionClasses(tabId);
  sftpUpdateStatusBar(tabId);
  // Re-run directory comparison with the fresh local entries (no-op when the
  // pane is closed or comparison is off).
  if (typeof sftpCmpAfterRefresh === 'function') sftpCmpAfterRefresh(tabId);
  return true;
}

/// Move the local pane to `path` ('' = home) if it can be listed; otherwise
/// keep the folder on screen and say why. Every local navigation (double-click,
/// Open, Up, Home, a typed path, synchronized browsing) goes through here: the
/// old refresh silently fell back to the home folder on ANY error, so a click
/// on an unreadable folder looked ignored and lost the user's place.
async function sftpLocalNavigate(tabId, path) {
  try {
    return await sftpUiLocalLoad(tabId, path);
  } catch (e) {
    toast(e.message || String(e), 'err');
    return false;
  }
}

/// Public local-pane refresh: swallows errors with a toast (existing callers).
/// Paint the local pane's selection classes, the way
/// sftpRefreshSelectionClasses does for the remote one.
function sftpRefreshLocalSelectionClasses(tabId) {
  const tab = sftpTab(tabId);
  const tbody = document.getElementById('sftpLocalTbody-' + tabId);
  if (!tab || !tbody || !tab.localSelected) return;
  for (const row of tbody.querySelectorAll('tr.sftp-entry')) {
    toggleRowSelected(row, tab.localSelected.has(row.dataset.name));
  }
}

/// Local-pane row interaction: click to select, right-click for the menu.
/// Delegated on the table wrapper rather than the tbody so that a right-click
/// in the empty space below the last row is caught too - otherwise that one
/// spot still raised the webview's own menu.
function sftpWireLocalTbodyDelegation(tabId, wrap) {
  const host = wrap || document.getElementById('sftpLocalTbody-' + tabId);
  if (!host || host._sftpLocalWired) return;
  host._sftpLocalWired = true;

  const rowNames = () => Array.from(
    document.querySelectorAll('#sftpLocalTbody-' + tabId + ' tr.sftp-entry')
  ).map(r => r.dataset.name);

  // Dragged onto the remote pane or a remote folder (upload) by the pointer.
  host.addEventListener('pointerdown', (ev) => sftpRowPointerDown(ev, tabId, 'local'));

  host.addEventListener('click', (ev) => {
    const tab = sftpTabState(sftpTab(tabId));
    if (!tab) return;
    // See the remote tbody handler: Ctrl+A follows the pane last clicked in.
    tab._lastPane = 'local';
    const tr = ev.target.closest('tr.sftp-entry');
    if (!tr) {
      // Click on empty space clears, as the remote pane does.
      tab.localSelected.clear();
      sftpRefreshLocalSelectionClasses(tabId);
      sftpUpdateStatusBar(tabId);
      return;
    }
    const name = tr.dataset.name;
    if (ev.ctrlKey || ev.metaKey) {
      if (tab.localSelected.has(name)) tab.localSelected.delete(name);
      else tab.localSelected.add(name);
      tab._localLastClicked = name;
    } else if (ev.shiftKey && tab._localLastClicked) {
      const names = rowNames();
      const i0 = names.indexOf(tab._localLastClicked), i1 = names.indexOf(name);
      if (i0 >= 0 && i1 >= 0) {
        for (let i = Math.min(i0, i1); i <= Math.max(i0, i1); i++) tab.localSelected.add(names[i]);
      }
    } else {
      tab.localSelected.clear();
      tab.localSelected.add(name);
      tab._localLastClicked = name;
    }
    sftpRefreshLocalSelectionClasses(tabId);
    sftpUpdateStatusBar(tabId);
  });

  host.addEventListener('contextmenu', (ev) => {
    const tab = sftpTabState(sftpTab(tabId));
    if (!tab) return;
    ev.preventDefault(); // suppress the webview menu for the whole listing
    const tr = ev.target.closest('tr.sftp-entry');
    if (!tr) { openSftpLocalMenu(ev.clientX, ev.clientY, tabId, null); return; }
    const entry = (tab._localEntries || []).find(e => e.name === tr.dataset.name);
    if (!entry) { openSftpLocalMenu(ev.clientX, ev.clientY, tabId, null); return; }
    // Right-clicking outside the current selection retargets it, so the menu
    // always acts on what the pointer is over - same rule as the remote pane.
    if (!tab.localSelected.has(entry.name)) {
      tab.localSelected.clear();
      tab.localSelected.add(entry.name);
      tab._localLastClicked = entry.name;
      sftpRefreshLocalSelectionClasses(tabId);
      sftpUpdateStatusBar(tabId);
    }
    openSftpLocalMenu(ev.clientX, ev.clientY, tabId, entry);
  });
}

/// Right-click menu for the local pane (selection-aware). The backend gates
/// every local mutation through the same app-data + system-directory rules the
/// transfer paths use (see `validate_local_mutation`), so the entries here are
/// safe to offer; each destructive one confirms first. Passing a null entry
/// builds the empty-space menu.
function openSftpLocalMenu(x, y, tabId, entry) {
  closeKeyConnectMenu();
  const tab = sftpTabState(sftpTab(tabId));
  if (!tab) return;
  const menu = document.createElement('div');
  menu.className = 'ctx-menu';
  menu.id = 'keyConnectMenu';
  const mk = (label, icon, fn) => {
    const b = document.createElement('button');
    b.className = 'ctx-item';
    b.innerHTML = `${ico(icon)}<span>${escapeHtml(label)}</span>`;
    b.addEventListener('click', () => { closeKeyConnectMenu(); fn(); });
    menu.appendChild(b);
  };
  const sep = () => {
    const d = document.createElement('div');
    d.className = 'ctx-sep';
    menu.appendChild(d);
  };

  if (entry) {
    const names = tab.localSelected.size ? [...tab.localSelected] : [entry.name];
    const multi = names.length > 1;
    if (!multi && entry.isDir) {
      mk('Open', 'folder-open', () => {
        if (typeof sftpSyncLocalNav === 'function' && sftpSyncLocalNav(tabId, entry.name)) return;
        sftpLocalNavigate(tabId, joinLocal(tab.localPath, entry.name));
      });
    }
    // The queue expands a folder into one transfer per file (sftp_queue_add),
    // so this is the same entry for files and folders rather than two that
    // differ only in wording.
    mk(multi ? `Upload ${names.length} items` : (entry.isDir ? 'Upload folder' : 'Upload'), 'upload-cloud', () => {
      if (!sftpPanelVisible(tab) || !tab.sessionId) { toast('Not connected.', 'err'); return; }
      queueUploads(tabId, names.map(n => ({
        local: joinLocal(tab.localPath, n),
        remote: sftpJoin(tab.sftpPath, n),
      })));
    });
    sep();
    mk(multi ? `Copy ${names.length} paths` : 'Copy path', 'copy', () => {
      const text = names.map(n => joinLocal(tab.localPath, n)).join('\n');
      copyText(text).then(ok => toast(ok ? 'Path copied.' : 'Clipboard unavailable.', ok ? 'ok' : 'err'));
    });
    sep();
    // Local-side file management. The backend commands behind these
    // (sftp_local_rename/remove/mkdir/open_folder) are gated by the same
    // app-data + system-directory rules as the transfer paths, and every
    // destructive one confirms first.
    if (!multi) {
      mk('Rename...', 'pencil', () => sftpLocalRenamePrompt(tabId, entry));
    }
    mk(multi ? `Delete ${names.length} items` : 'Delete', 'trash-2',
      () => sftpLocalDelete(tabId, names, entry));
    mk(multi ? 'Open containing folder' : (entry.isDir ? 'Open in file manager' : 'Open containing folder'),
      'folder-open', () => {
        const target = multi ? tab.localPath : joinLocal(tab.localPath, entry.name);
        call('sftp_local_open_folder', { path: target })
          .catch((e) => toast((e && (e.message || e.error)) || String(e), 'err'));
      });
  } else {
    mk('Parent directory', 'arrow-up', () => localNavigateUp(tabId));
    mk('Copy current path', 'copy', () => {
      if (!tab.localPath) { toast('Local pane has no path yet.', 'info'); return; }
      copyText(tab.localPath).then(ok => toast(ok ? 'Path copied.' : 'Clipboard unavailable.', ok ? 'ok' : 'err'));
    });
    mk('Set as default local directory', 'star', () => sftpSetLocalDirDefault(tabId));
    mk('New folder...', 'folder-plus', () => sftpLocalMkdirPrompt(tabId));
    sep();
  }
  mk('Refresh', 'refresh-cw', () => refreshLocalPane(tabId));

  sftpShowMenu(menu, x, y);
}

/// Prompt for and create a folder in the local pane (the dual-pane counterpart
/// to the remote "New folder" button).
function sftpLocalMkdirPrompt(tabId) {
  const tab = sftpTab(tabId);
  if (!tab || !tab.localPath) { toast('Local pane has no path yet.', 'info'); return; }
  promptModal('New folder', 'Folder name:', '', async (name) => {
    const trimmed = (name || '').trim();
    if (!trimmed) return;
    try {
      await call('sftp_local_mkdir', { path: joinLocal(tab.localPath, trimmed) });
      await refreshLocalPane(tabId);
      toast('Folder created.', 'ok');
    } catch (e) { toast((e && (e.message || e.error)) || String(e), 'err'); }
  });
}

/// Rename one local entry (single-selection only - the backend takes one pair).
function sftpLocalRenamePrompt(tabId, entry) {
  const tab = sftpTab(tabId);
  if (!tab || !entry) return;
  promptModal('Rename', 'New name:', entry.name, async (name) => {
    const trimmed = (name || '').trim();
    if (!trimmed || trimmed === entry.name) return;
    try {
      await call('sftp_local_rename', {
        from: joinLocal(tab.localPath, entry.name),
        to: joinLocal(tab.localPath, trimmed),
      });
      tab.localSelected.delete(entry.name);
      await refreshLocalPane(tabId);
      toast('Renamed.', 'ok');
    } catch (e) { toast((e && (e.message || e.error)) || String(e), 'err'); }
  });
}

/// Delete the selected local entries, after a confirmation that names them.
/// The folder and each entry's kind are taken when the question is asked, so
/// a "yes" removes exactly what it named even if the pane moved meanwhile.
async function sftpLocalDelete(tabId, names, entry) {
  const tab = sftpTab(tabId);
  if (!tab || !names.length) return;
  const anyDir = names.some(n => {
    const e = (tab._localEntries || []).find(x => x.name === n);
    return e ? e.isDir : (entry && entry.isDir);
  });
  const message = names.length === 1
    ? (anyDir
      ? `Delete the local folder "${sftpInText(names[0])}" and everything inside it? This cannot be undone.`
      : `Delete the local file "${sftpInText(names[0])}"? This cannot be undone.`)
    : `Delete these ${names.length} local items (${sftpNameList(names)})? This cannot be undone.`;
  // The folder the question is about: the pane may move while it is open.
  const dir = tab.localPath;
  const kinds = new Map((tab._localEntries || []).map((x) => [x.name, !!x.isDir]));
  sftpConfirmDelete(message, async () => {
    let ok = 0, fail = 0, lastErr = null;
    for (const name of names) {
      try {
        await call('sftp_local_remove', {
          path: joinLocal(dir, name),
          isDir: !!kinds.get(name),
        });
        tab.localSelected.delete(name);
        ok++;
      } catch (err) { fail++; lastErr = (err && (err.message || err.error)) || String(err); }
    }
    await refreshLocalPane(tabId);
    if (fail) toast(`${ok} deleted, ${fail} failed${lastErr ? `: ${lastErr}` : ''}`, 'err');
    else toast(ok === 1 ? 'Deleted.' : `${ok} items deleted.`, 'ok');
  }, 'local');
}

/// Re-list the local pane's current folder (the pane opening, a mutation, a
/// remote navigation in dual mode). A failure keeps the folder and says why,
/// with one exception: the pane's FIRST load of a remembered folder (a
/// per-server default, Task 6, or a bookmark's) can find it gone - deleted
/// since, or remembered on another machine sharing the vault - and then opens
/// the home folder instead, once, saying which folder was missing.
async function refreshLocalPane(tabId) {
  const tab = sftpTab(tabId);
  if (!tab) return;
  const firstLoad = !tab._localLoaded;
  const wanted = tab.localPath;
  try {
    await sftpUiLocalLoad(tabId);
  } catch (e) {
    if (firstLoad && wanted) {
      if (await sftpLocalNavigate(tabId, '')) {
        toast(`Local folder "${wanted}" is not available - showing your home folder instead.`, 'warn');
      }
      return;
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
  // Toast the OUTCOME, not the intent: the old unconditional success toast
  // fired even when the write was rejected, and the next launch reverted.
  // state.settings follows only a write that went through (sftpSaveSetting),
  // so a refused one is not used for the rest of the session either.
  sftpSaveSetting(key, dir).then((saved) => {
    if (saved) toast(`Default local directory for ${tab.serverName || 'this server'} set to ${dir}`, 'ok');
  });
}

function joinLocal(dir, name) {
  const sep = dir.includes('\\') && !dir.includes('/') ? '\\' : '/';
  return dir.endsWith(sep) ? dir + name : dir + sep + name;
}

/// Parent folder of a local path, for Up. Both separators count (Windows takes
/// either, and a typed path can mix them), a drive letter or UNC share is
/// kept, and the parent of a first-level folder is the drive ROOT `C:\` -
/// never the bare `C:`, which Windows reads as "the current directory on drive
/// C". A root is its own parent. Splitting on one guessed separator turned
/// `C:\Users\u/Documents` into `/C:\Users\u`, and `/home` into '' (home).
function sftpLocalParent(p) {
  if (!p) return p;
  const unc = /^(\\\\|\/\/)[^\\/]+[\\/][^\\/]+/.exec(p);
  const drive = !unc && /^[A-Za-z]:/.exec(p);
  const prefix = unc ? unc[0] : drive ? drive[0] : '';
  const root = unc ? prefix.replace(/\//g, '\\') + '\\' : drive ? prefix + '\\' : '/';
  const parts = p.slice(prefix.length).split(/[\\/]+/).filter(Boolean);
  parts.pop();
  return parts.length ? root + parts.join(root === '/' ? '/' : '\\') : root;
}

function localNavigateUp(tabId) {
  const tab = sftpTab(tabId);
  if (!tab || !tab.localPath) return;
  if (typeof sftpSyncLocalUp === 'function' && sftpSyncLocalUp(tabId)) return;
  const up = sftpLocalParent(tab.localPath);
  if (up === tab.localPath) return; // a drive or file-system root has no parent
  sftpLocalNavigate(tabId, up);
}

// ─── downloads / uploads via the queue ──────────────────────────────────────

/// What sftp_queue_add left out or changed while expanding a request (Task 10:
/// symbolic links and special files skipped, unreadable folders, unusable
/// names, colliding downloads renamed): every line goes to the activity log
/// and the first to a toast, so nothing drops out of a transfer unseen.
function sftpReportQueueWarnings(tabId, r) {
  const warnings = (r && r.warnings) || [];
  if (!warnings.length) return;
  for (const w of warnings) sftpLog(tabId, `queue: ${w}`);
  toast(warnings.length === 1
    ? warnings[0]
    : `${warnings[0]} (and ${warnings.length - 1} more - see the activity log)`, 'warn');
}

/// `into`: the local folder to download to (a drag onto the local pane or
/// one of its folders); without it, the local pane's folder. Either way
/// through the "already exists" question: the folder-drop path used to send
/// its batch without it, so a drop onto a folder replaced a local file of
/// the same name without asking.
async function queueDownloads(tabId, remotePaths, into) {
  const tab = sftpTab(tabId);
  if (!tab) return;
  // Plain "Download" lands in the local pane's current directory. If the
  // local pane isn't open, open it so the destination is always visible -
  // never a hidden temp folder. Explicit placement stays on "Download as...".
  sftpTabState(tab);
  if (!tab.dualPane) toggleDualPane(tabId, { persist: false });
  if (!into && !tab.localPath) {
    // Local listing hasn't loaded yet (toggle just opened it) - wait briefly.
    await new Promise(r => setTimeout(r, 600));
  }
  const dir = into || tab.localPath || null;
  if (!dir) {
    toast('Local pane is still loading - try again in a moment.', 'err');
    return;
  }
  try {
    // Conflict check: does <dir>/<name> already exist locally? Directory
    // sources are expanded server-side later, so only plain files are
    // pre-checked (FileZilla does the same for its existence dialog). A
    // Windows folder matches names without regard to case, as NTFS does:
    // otherwise Readme.md replaced README.md without a prompt.
    const caseless = sftpIsWindowsPath(dir);
    const fold = (n) => (caseless ? n.toLowerCase() : n);
    const localEntries = await sftpLocalEntryMap(dir, caseless);
    const names = remotePaths.map((p) => p.split('/').filter(Boolean).pop()).filter(Boolean);
    const taken = sftpTakenNames([...localEntries.values()].map((e) => e.name).concat(names), caseless);
    const conflicts = [];
    for (const p of remotePaths) {
      const name = p.split('/').filter(Boolean).pop();
      if (!name) continue;
      const dest = localEntries.get(fold(name));
      if (dest) conflicts.push({ remote: p, name, destDir: dir, destEntry: dest, taken });
    }
    const decided = await resolveBatchConflicts(tabId, 'download', conflicts);
    if (!decided) return; // user cancelled the whole batch
    const survivors = [];
    for (const p of remotePaths) {
      const d = decided.find(x => x.remote === p);
      if (d) {
        if (d.action === 'skip') continue;
        // `localName` is the renamed destination the backend applies in
        // `expand_download` (validated by the same containment check as the
        // derived basename); `resume` is per-item, so one batch can mix
        // overwrite/skip/resume decisions.
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
    sftpReportQueueWarnings(tabId, r);
    if (r.added > 0) toast(`${r.added} download(s) → ${dir}`, 'ok');
  } catch (e) { toast(e.message || String(e), 'err'); }
}

/// `report(r)`, when given, shows the result of sftp_queue_add in place of the
/// usual report (the Upload picker's per-file report).
async function queueUploads(tabId, pairs, report) {
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
      // Every name this folder will hold once the batch lands - its listing
      // plus each upload's own target - shared by the conflicts aimed at it,
      // so a Rename picks a name that is still free (see applyConflictAction).
      const baseName = (p) => p.split('/').filter(Boolean).pop();
      const taken = sftpTakenNames([...remoteEntries.get(dir).keys(), ...group.map((g) => baseName(g.remote))], false);
      for (const { local, remote } of group) {
        const dest = remoteEntries.get(dir).get(baseName(remote));
        if (dest) conflicts.push({ local, remote, destDir: dir, destEntry: dest, taken });
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
    if (typeof report === 'function') {
      report(r);
      return;
    }
    sftpLog(tabId, `queued ${r.added} upload(s)`);
    sftpReportQueueWarnings(tabId, r);
    if (r.added > 0) toast(`${r.added} upload(s) queued.`, 'ok');
  } catch (e) { toast(e.message || String(e), 'err'); }
}

// ─── overwrite-conflict handling (FileZilla "file already exists") ──────────

const CONFLICT_ACTIONS = ['overwrite', 'skip', 'rename', 'resume'];

/// Read a local directory once and index it by file name - lower-cased when
/// `caseless` (a Windows folder), so lookups must fold the same way.
async function sftpLocalEntryMap(dir, caseless) {
  const r = await sftpCall('sftp_local_list', { path: dir });
  const map = new Map();
  for (const e of r.entries || []) map.set(caseless ? e.name.toLowerCase() : e.name, e);
  return map;
}

/// A Windows local path: a drive letter, a UNC share, or backslashes only.
/// Such folders treat names without regard to case.
function sftpIsWindowsPath(p) {
  return /^[A-Za-z]:([\\/]|$)/.test(p || '') || /^\\\\/.test(p || '') || (/\\/.test(p || '') && !/\//.test(p || ''));
}

/// The names a destination folder will hold, for picking a free "name (n)":
/// compared without case where the folder ignores it.
function sftpTakenNames(names, caseless) {
  const fold = (n) => (caseless ? n.toLowerCase() : n);
  const set = new Set(names.map(fold));
  return { has: (n) => set.has(fold(n)), add: (n) => { set.add(fold(n)); } };
}

/// Load the persisted default action for a direction. NOTE: settings_get
/// only returns whitelisted keys, so a value written by settings_set is
/// seen via the in-session mirror below; across restarts it reads as 'ask'
/// until the two keys are added to the backend whitelist (one-line change
/// owned by the backend agents).
const sftpConflictDefaults = { sftpConflictUpload: 'ask', sftpConflictDownload: 'ask' };

function sftpConflictDefault(direction) {
  const key = direction === 'upload' ? 'sftpConflictUpload' : 'sftpConflictDownload';
  const v = (state.settings && state.settings[key]) || sftpConflictDefaults[key] || 'ask';
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
/// or null when the whole batch is cancelled - by the user, or because there
/// is no dialog to ask with. Non-conflicting items are never blocked - they
/// enqueue as overwrite (their targets do not exist).
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
  // Fail closed: with no tab or no dialog there is nobody to ask, and the
  // answer this used to assume - overwrite - is the one that destroys files.
  if (!tab) return null;

  return await new Promise(resolve => {
    const modal = document.getElementById('conflictModal');
    if (!modal) {
      toast('Transfer cancelled: some targets already exist and the dialog to choose what happens to them is missing.', 'err');
      resolve(null);
      return;
    }
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
        // Every file starts on Skip: an overwrite is as irreversible as a
        // delete, so it has to be chosen, never fallen into.
        rb.checked = act === 'skip';
        const lab = document.createElement('label');
        lab.className = 'conflict-action';
        lab.htmlFor = id;
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
      unregisterModalCloser(modal);
      modal.hidden = true;
      applyBtn.onclick = null; cancelBtn.onclick = null; closeBtn.onclick = null; modal.onclick = null;
    };
    // Escape and a vault lock mean "cancel the whole batch", the same as the X
    // and Cancel buttons - and they must resolve(null) too, or the transfer
    // awaiting this promise would hang forever with the dialog gone. The central
    // modal handler runs this for the topmost layer only (see registerModalCloser
    // in app.js).
    let settled = false;
    registerModalCloser(modal, () => { settled = true; close(); resolve(null); });
    const finish = async () => {
      if (settled || applyBtn.disabled) return;
      const choice = (actions) => {
        const sel = actions.querySelector('input[type="radio"]:checked');
        return sel ? sel.value : 'skip';
      };
      if (always.checked) {
        // The "always" action is the first row's choice (all rows start at
        // the same default and FileZilla applies one action to the rest).
        // Saved BEFORE the batch goes ahead: a default the backend refuses
        // leaves the dialog open with the box unticked and its message shown.
        // It used to close as if the default were kept, and the next batch
        // asked again.
        const first = rows.length ? choice(rows[0].actions) : 'skip';
        const key = direction === 'upload' ? 'sftpConflictUpload' : 'sftpConflictDownload';
        applyBtn.disabled = true;
        const saved = await sftpSaveSetting(key, first, () => { always.checked = false; });
        applyBtn.disabled = false;
        if (settled) return; // closed (Escape, a lock) while it was saving
        if (!saved) return;
        sftpConflictDefaults[key] = first;
        sftpLog(tabId, `default for ${direction} conflicts: ${first}`);
      }
      // Decided only now, so a Rename claims its name once (applyConflictAction).
      const out = rows.map(({ c, actions }) => applyConflictAction(c, choice(actions), direction));
      settled = true;
      close();
      resolve(out);
    };
    const cancel = () => { settled = true; applyBtn.disabled = false; close(); resolve(null); };
    applyBtn.disabled = false;
    applyBtn.onclick = finish;
    cancelBtn.onclick = cancel;
    closeBtn.onclick = cancel;
    modal.onclick = (ev) => { if (ev.target === modal) cancel(); };

    modal.hidden = false;
    // Cancel has the focus, as on the delete prompt: a reflexive Enter must
    // not be what overwrites. Deferred like confirmModal's, so the modal
    // manager first records the control focus returns to.
    setTimeout(() => cancelBtn.focus(), 0);
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

/// Attach the chosen action to a conflict record. Rename picks the first free
/// "name (n)" against `c.taken` - every name the destination folder will hold
/// once the batch lands (its listing plus the batch's own targets, built by
/// queueUploads / queueDownloads and shared by the batch's conflicts) - and
/// claims it there, so the next rename cannot pick it too. Checking only the
/// conflicting file's own name chose an existing "a (1).txt" and the transfer
/// then replaced it. Reports the adjusted destination:
///   upload → renameRemote (new remote path)
///   download → localName (the backend's expand_download writes it)
function applyConflictAction(c, action, direction) {
  const { taken: sharedTaken, ...rest } = c;
  const out = { ...rest, action };
  if (action !== 'rename') return out;
  const name = direction === 'upload'
    ? c.remote.split('/').filter(Boolean).pop()
    : (c.destEntry && c.destEntry.name) || c.remote.split('/').filter(Boolean).pop();
  const taken = sharedTaken || sftpTakenNames([], false);
  if (c.destEntry && c.destEntry.name) taken.add(c.destEntry.name);
  const free = sftpFreeName(name, taken);
  taken.add(free);
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
    // The save watch exists from here on (even if no editor opens), so the
    // file's menu offers to stop it (sftpStopEdit).
    (tab._edits || (tab._edits = new Set())).add(fullPath);
    await call('system_open_external', { url: r.localPath });
    // A file already open for editing in this session opens the SAME local
    // copy again (`reused`) - say so, or a second "Editing..." reads as a
    // fresh download that dropped the unsaved changes in the first copy.
    if (r && r.reused) {
      sftpLog(tabId, `${sftpSpell(name)} is already open for editing - opened the same copy again`);
      toast(`${sftpInText(name)} is already open for editing - this opens the same copy, and saving it still uploads.`, 'info');
      return;
    }
    sftpLog(tabId, `editing ${sftpSpell(name)} (auto-sync on save)`);
    toast(`Editing ${sftpInText(name)} - saves upload automatically.`, 'info');
  } catch (e) { toast(e.message || String(e), 'err'); }
}

/// "Stop editing": end the save-back of a file opened in an external editor
/// (sftp_close_edit also removes the local copy). Saves made after this stay
/// on this computer, and no question about the file is left.
async function sftpStopEdit(tabId, fullPath) {
  const tab = sftpTab(tabId);
  if (!tab) return;
  const sessionId = tab.sessionId;
  try {
    await call('sftp_close_edit', { sessionId, remote: fullPath });
    if (tab._edits) tab._edits.delete(fullPath);
    sftpDropEditConflicts((c) => c.sessionId === sessionId && c.remote === fullPath);
    sftpLog(tabId, `stopped syncing ${sftpSpell(fullPath)}`);
    toast(`Stopped syncing ${sftpInText(fullPath.split('/').filter(Boolean).pop() || fullPath)}.`, 'info');
  } catch (e) { toast(e.message || String(e), 'err'); }
}

/// A backend message placed inside a sentence of ours, closed exactly once:
/// it usually ends with its own period, and the old "...: <message>. ..."
/// read "Save again to retry.." (A7-19).
function sftpSentence(text) {
  const t = String(text || '').trim();
  return /[.!?]$/.test(t) ? t : t + '.';
}

/// The tab whose session `sessionId` is, or undefined.
function sftpTabOfSession(sessionId) {
  return [...state.sessions.values()].find((t) => t.sessionId && t.sessionId === sessionId);
}

/// Every save-back of a file open in an external editor is reported: the
/// `sftp-edit-sync` event `{ sessionId, editId, remote }` plus ok, a failure's
/// `error`, a `reloaded` flag, or a conflict. A failed upload used to be
/// silent, so a user could close the editor believing the change was live on
/// the server. A conflict - the file changed, or was deleted, on the server
/// since it was opened - is a question, not a failure: the prompt below asks
/// what to do (A7-19). Names are spelled out and kept to themselves in the
/// toasts (a direction override in a file name must not reorder them).
function sftpOnEditSync(ev) {
  const p = (ev && ev.payload) || {};
  const tab = sftpTabOfSession(p.sessionId);
  const remote = String(p.remote || '');
  const name = remote.split('/').filter(Boolean).pop() || remote || 'file';
  if (p.conflict) {
    if (tab) sftpLog(tab.tabId, `${sftpSpell(remote)}: ${p.reason === 'deleted' ? 'deleted' : 'changed'} on the server since it was opened - asking`);
    sftpQueueEditConflict(p);
    return;
  }
  // Saved, or reloaded, some other way meanwhile: nothing is left to ask
  // about that file - the prompt used to stay up, offering to settle a
  // conflict that was gone.
  if (p.ok) sftpDropEditConflicts((c) => (p.editId ? c.editId === p.editId : c.sessionId === p.sessionId && c.remote === remote));
  if (p.ok && p.reloaded) {
    if (tab) sftpLog(tab.tabId, `reloaded ${sftpSpell(remote)} from the server`);
    toast(`Reloaded ${sftpInText(name)} - your copy is now the server's version.`, 'ok');
    return;
  }
  if (p.ok) {
    if (tab) {
      sftpLog(tab.tabId, `saved ${sftpSpell(remote)} to the server`);
      // The file changed on the server: so did its folder's listing.
      sftpCacheInvalidate(tab, sftpParent(remote));
      tab._listingDirty = true;
    }
    toast(`Saved "${sftpInText(name)}" to ${(tab && tab.serverName) || 'the server'}.`, 'ok');
  } else {
    const why = p.error || 'unknown error';
    if (tab) sftpLog(tab.tabId, `save of ${sftpSpell(remote)} FAILED: ${why}`);
    toast(`Could not save "${sftpInText(name)}" to the server: ${sftpSentence(why)} The edit is only on this computer.`, 'err');
  }
}
sftpListen('sftp-edit-sync', sftpOnEditSync).catch(() => {});

// ─── edit conflicts (A7-19) ─────────────────────────────────────────────────
//
// One prompt (#editConflictModal) asks about ONE file at a time. Each edit's
// newest conflict is kept (only the newest can be settled: sftp_edit_resolve
// with its conflictId): a newer one for the file on screen replaces the
// question, one for another file waits its turn and the prompt says how many
// are waiting. Putting another file's question in the place of the one on
// screen let a click meant for a.conf overwrite b.conf, and left a.conf's
// save never uploaded - the backend does not raise an unchanged conflict
// again. After the prompt appears or changes, Overwrite and Reload take no
// click for a moment, so a click aimed at what was there cannot land on
// them; Reload is disabled, never removed, for a deleted file, so no button
// moves. Cancel, Escape and a backdrop click leave the file as it is (its
// next save asks again) and go on to the next file - which, for the same
// moment, they cannot dismiss: the second click of a double-click, or a
// second Enter, would send it away unseen. A vault lock drops every question
// (its own closer, whatever state.unlocked still says), and so does the end of
// their session or the closing of their tab.

/// How long Overwrite and Reload stay disabled after the question changes -
/// and Cancel after the prompt moves on to another file.
const SFTP_EDIT_ARM_MS = 750;
/// editId -> that edit's newest conflict, in the order the files came up:
/// { editId, conflictId, reason, remote, name, sessionId, remoteSize,
///   remoteModifiedMs, busy, armed, dismissable }.
const sftpEditConflicts = new Map();
/// The question on screen (one of sftpEditConflicts' values), or null.
let sftpEditConflict = null;
let sftpEditConflictTimer = 0;

/// A conflict - an event, or a fresh one in an answer: the newest of its edit,
/// shown now if nothing is, in place of an older question about the same
/// file, or after the file on screen.
function sftpQueueEditConflict(p) {
  const remote = String(p.remote || '');
  const c = {
    editId: p.editId, conflictId: p.conflictId, reason: p.reason, remote, sessionId: p.sessionId,
    name: remote.split('/').filter(Boolean).pop() || remote || 'file',
    remoteSize: p.remoteSize, remoteModifiedMs: p.remoteModifiedMs, busy: false, armed: false, dismissable: false,
  };
  // An edit of a session no tab holds any more (closed, or the vault locked
  // meanwhile) has no one left to answer for it.
  if (!sftpTabOfSession(c.sessionId)) return;
  const prev = sftpEditConflicts.get(c.editId);
  if (prev && prev.conflictId === c.conflictId) return; // asked already (an answer's fresh conflict, then its event)
  // What is on screen is the question of a prompt that is up. A hidden one
  // asks nothing: queued behind it, every later question went unseen.
  const shown = sftpEditConflictOnScreen();
  sftpEditConflicts.set(c.editId, c); // an edit keeps its turn when its question is renewed
  if (!shown) sftpShowEditConflict(c, '');
  else if (shown.editId === c.editId) sftpShowEditConflict(c, 'newer');
  else sftpPaintEditQueue(`Another file needs an answer after this one: ${sftpSpell(c.name)}.`);
}

/// The question the prompt shows, or null when it is not up.
function sftpEditConflictOnScreen() {
  const modal = document.getElementById('editConflictModal');
  return modal && !modal.hidden ? sftpEditConflict : null;
}

/// A <bdi> holding `text` spelled out: kept to itself, whatever direction its
/// characters take.
function sftpBdi(text) {
  const b = document.createElement('bdi');
  b.textContent = sftpSpell(text);
  return b;
}

function sftpShowEditConflict(c, why) {
  const modal = document.getElementById('editConflictModal');
  if (!modal) {
    sftpEditConflicts.delete(c.editId);
    toast(`${sftpInText(c.name)} changed on the server since you opened it - the dialog to choose what happens is missing, so nothing was uploaded.`, 'err');
    return;
  }
  sftpEditConflict = c;
  const deleted = c.reason === 'deleted';
  const unsure = c.reason === 'unverifiable';
  const tab = sftpTabOfSession(c.sessionId);
  document.getElementById('editConflictTitle').replaceChildren(sftpBdi(c.name),
    deleted ? ' was deleted on the server' : unsure ? ' may have changed on the server' : ' changed on the server');
  document.getElementById('editConflictMessage').replaceChildren(sftpBdi(c.name), deleted
    ? ' was deleted on the server since you opened it.'
    : unsure
      ? ' could not be checked on the server, so it may have changed since you opened it.'
      : ' changed on the server since you opened it.');
  document.getElementById('editConflictDetail').textContent = deleted
    ? 'Overwrite puts your copy back on the server. There is nothing to reload. Cancel uploads nothing; your copy stays on this computer.'
    : 'Overwrite replaces the server\'s version with your copy. Reload replaces your copy with the server\'s version. Cancel uploads nothing - saving again asks again.';
  const now = !deleted && (c.remoteSize != null || c.remoteModifiedMs)
    ? ` - now ${c.remoteSize != null ? formatSftpSize(c.remoteSize) : 'size unknown'}${c.remoteModifiedMs ? `, modified ${fmtSftpTime(c.remoteModifiedMs)}` : ''}`
    : '';
  document.getElementById('editConflictServer').replaceChildren(`${(tab && tab.serverName) || 'Server'}: `, sftpBdi(c.remote), now);
  const err = document.getElementById('editConflictError');
  err.textContent = '';
  err.hidden = true;
  const reload = document.getElementById('editConflictReloadBtn');
  reload.title = deleted ? 'Nothing to reload: the file was deleted on the server' : 'Replace your copy with the server\'s version';
  // A changed question is said out loud too; a new prompt says it all itself.
  const live = document.getElementById('editConflictLive');
  if (live) {
    live.textContent = why === 'newer'
      ? `${sftpSpell(c.name)} changed again on the server - this now asks about the newer change.`
      : why === 'next' ? `Next file: ${sftpSpell(c.name)}.` : '';
  }
  sftpPaintEditQueue(null);
  // Overwrite and Reload wait a moment before they take a click; so does
  // Cancel (and Escape, and a backdrop click) when the prompt has just moved
  // on to another file.
  clearTimeout(sftpEditConflictTimer);
  c.armed = false;
  c.dismissable = why !== 'next';
  sftpPaintEditButtons();
  sftpEditConflictTimer = setTimeout(() => {
    if (sftpEditConflict !== c) return;
    c.armed = true;
    c.dismissable = true;
    sftpPaintEditButtons();
  }, SFTP_EDIT_ARM_MS);
  if (modal.hidden) {
    // Escape is Cancel; a vault lock drops every question - it closes the
    // dialogs while the vault still reads as unlocked, so it has its own.
    registerModalCloser(modal, () => sftpCancelEditConflict(), () => sftpDropAllEditConflicts());
    modal.onclick = (ev) => { if (ev.target === modal) sftpCancelEditConflict(); };
    modal.hidden = false;
  }
  // Cancel has the focus - on a replaced question too: both other answers
  // replace somebody's work, so a reflexive Enter must not be one of them.
  // Deferred like confirmModal's, after the modal manager noted the opener.
  setTimeout(() => { if (sftpEditConflict === c) document.getElementById('editConflictCancelBtn').focus(); }, 0);
}

/// Overwrite and Reload take a click only once armed and while no answer is
/// on its way; Reload never for a deleted file. Cancel waits only while the
/// prompt has just moved on to another file - aria-disabled, so it keeps the
/// focus put on it.
function sftpPaintEditButtons() {
  const c = sftpEditConflict;
  const ready = !!c && c.armed && !c.busy;
  const ow = document.getElementById('editConflictOverwriteBtn');
  const rl = document.getElementById('editConflictReloadBtn');
  const cancel = document.getElementById('editConflictCancelBtn');
  if (ow) ow.disabled = !ready;
  if (rl) rl.disabled = !ready || c.reason === 'deleted';
  if (cancel) {
    if (c && !c.dismissable) cancel.setAttribute('aria-disabled', 'true');
    else cancel.removeAttribute('aria-disabled');
  }
}

/// "N more files need an answer after this one", from the files waiting;
/// `say`, when given, is announced as well.
function sftpPaintEditQueue(say) {
  const note = document.getElementById('editConflictQueue');
  const waiting = Math.max(0, sftpEditConflicts.size - (sftpEditConflict ? 1 : 0));
  if (note) {
    note.textContent = waiting === 1 ? '1 more file needs an answer after this one.'
      : `${waiting} more files need an answer after this one.`;
    note.hidden = waiting === 0;
  }
  const live = document.getElementById('editConflictLive');
  if (live && say) live.textContent = say;
}

/// Cancel, Escape, a backdrop click: leave the file on screen as it is (its
/// next save asks again) and ask about the next one. Not in the moment after
/// the prompt moved on to this file: a second click, or a second Enter, meant
/// for the last one would send this one away unseen.
function sftpCancelEditConflict() {
  const c = sftpEditConflict;
  if (c && !c.dismissable) return;
  if (c) sftpEditConflicts.delete(c.editId);
  sftpNextEditConflict();
}

/// The next file's question, or close the prompt.
function sftpNextEditConflict() {
  const next = sftpEditConflicts.values().next().value;
  if (next) sftpShowEditConflict(next, 'next');
  else sftpCloseEditConflict();
}

/// A vault lock: every edit session ends with it, so every question goes, on
/// screen or waiting - the lock closes the dialogs while the vault still reads
/// as unlocked, so this cannot be told from Cancel by state.unlocked.
function sftpDropAllEditConflicts() {
  sftpEditConflicts.clear();
  sftpCloseEditConflict();
}

/// Tabs closed outright (closeSessionTab, clearConnectView - neither ends in
/// onSessionClosed): no question is left about an edit of a session that no
/// tab holds any more.
function sftpPruneEditConflicts() {
  sftpDropEditConflicts((c) => !sftpTabOfSession(c.sessionId));
}
window.sftpPruneEditConflicts = sftpPruneEditConflicts;

function sftpCloseEditConflict() {
  const modal = document.getElementById('editConflictModal');
  sftpEditConflict = null;
  clearTimeout(sftpEditConflictTimer);
  if (!modal) return;
  unregisterModalCloser(modal);
  modal.onclick = null;
  modal.hidden = true;
}

/// Drop the questions `match` picks - edits settled some other way, or ended
/// - and go on to the next file if the one on screen is among them.
function sftpDropEditConflicts(match) {
  let onScreen = false;
  for (const [id, c] of [...sftpEditConflicts]) {
    if (!match(c)) continue;
    sftpEditConflicts.delete(id);
    if (c === sftpEditConflict) onScreen = true;
  }
  if (onScreen) sftpNextEditConflict();
  else if (sftpEditConflict) sftpPaintEditQueue(null);
}

/// Overwrite or Reload: answer the question on screen. A refusal is shown in
/// the prompt in the backend's words and the prompt stays to choose again; a
/// fresh conflict in the answer (the server changed again) replaces it; an
/// answer that comes back after the question changed is about nothing on
/// screen and is left alone.
async function sftpAnswerEditConflict(action) {
  const c = sftpEditConflict;
  if (!c || c.busy || !c.armed || (action === 'reload' && c.reason === 'deleted')) return;
  c.busy = true;
  sftpPaintEditButtons();
  const err = document.getElementById('editConflictError');
  err.hidden = true;
  try {
    const r = await sftpCall('sftp_edit_resolve', { editId: c.editId, conflictId: c.conflictId, action });
    if (sftpEditConflict !== c) return; // replaced, settled or closed meanwhile
    if (r && r.conflict) {
      sftpQueueEditConflict(Object.assign({ sessionId: c.sessionId, editId: c.editId, remote: c.remote }, r));
      return;
    }
    sftpEditConflicts.delete(c.editId);
    sftpNextEditConflict();
  } catch (e) {
    if (sftpEditConflict !== c) return;
    c.busy = false;
    sftpPaintEditButtons();
    err.textContent = (e && (e.message || e.error)) || String(e);
    err.hidden = false;
  }
}

(function sftpWireEditConflict() {
  const btn = (id, fn) => { const b = document.getElementById(id); if (b) b.addEventListener('click', fn); };
  btn('editConflictCancelBtn', () => sftpCancelEditConflict());
  btn('editConflictReloadBtn', () => sftpAnswerEditConflict('reload'));
  btn('editConflictOverwriteBtn', () => sftpAnswerEditConflict('overwrite'));
})();

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
let queueWired = false;
// Which tab is visible. Paused jobs (user-paused, or restored from a
// previous run - see sftpQueueJobResumable) fold into "queued" rather than
// getting a 4th tab: they're still "waiting their turn", just deliberately
// held, and the row rendering (paused fill color, Resume action, the
// restored-jobs banner) already carries the distinction that matters.
// Cancelled jobs fold into "failed": that is where their Retry button is.
let queueTab = 'queued'; // which tab is visible: queued | failed | done
let sftpUiQueueH = null; // persisted queue-panel height (px) set by the drag handle

/// Most rows the list draws at once. Running jobs are never cut; past the cap
/// a line says how many were left out.
const SFTP_QUEUE_ROW_CAP = 100;

// Pause/resume glyphs aren't in the shared ICONS table (icons.js is out of
// scope for this pass) - inline the same feather-style stroke icons locally
// so the buttons match every other icon-btn in look.
const Q_ICON_PAUSE = '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="6" y="4" width="4" height="16" rx="1"/><rect x="14" y="4" width="4" height="16" rx="1"/></svg>';
const Q_ICON_RESUME = '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="6 4 20 12 6 20 6 4"/></svg>';

/// "12.5 MB/s" - a transfer rate in the unit that fits (it was always KB/s,
/// so 10 MB/s read "10240.0 KB/s").
function sftpFormatRate(bytesPerSec) {
  return formatSftpSize(Math.round(bytesPerSec || 0)) + '/s';
}

/// True when some tab holds a live session matching this id. Only used for
/// jobs that carry no server id (queued before the queue recorded one).
function sftpQueueLiveSession(sessionId) {
  if (!sessionId) return false;
  return [...state.sessions.values()].some(t => t.sessionId === sessionId);
}

/// Is a connected tab open on this saved server? The backend resumes or
/// retries a job whose session is gone on the newest live session of the
/// SAME SERVER (Task 10), so that - not the job's original session id - is
/// what decides whether Resume can work. Matching the session id meant a job
/// restored after a restart could never be resumed: a reconnect always makes
/// a new session id, while the UI told the user to reconnect.
function sftpQueueServerLive(serverId) {
  if (!serverId) return false;
  return [...state.sessions.values()].some(t =>
    t.serverId === serverId && t.sessionId && window.tabSessionLive(t.tabId));
}

/// A paused job can resume when every server it touches is connected - for a
/// serverCopy that is the source AND the target. A job with no server id
/// (from before ids were recorded) falls back to its session id. The
/// renderer checks first so it never offers a Resume that cannot work.
function sftpQueueJobResumable(j) {
  const live = (serverId, sessionId) => (serverId ? sftpQueueServerLive(serverId) : sftpQueueLiveSession(sessionId));
  if (!live(j.serverId, j.sessionId)) return false;
  if (j.kind === 'serverCopy' && (j.targetServerId || j.targetSessionId) && !live(j.targetServerId, j.targetSessionId)) return false;
  return true;
}

/// Failed jobs already mirrored into a tab's activity log. A flag on the job
/// object did not work: every snapshot replaces the object, so each one
/// logged every failure again and pushed real history out of the log.
const sftpQueueLoggedFailures = new Set();

function wireQueueEvents() {
  if (queueWired) return;
  queueWired = true;
  sftpListen('sftp-queue', (ev) => {
    for (const j of ev.payload.jobs || []) {
      queueJobs.set(j.id, j);
      // Mirror failures into the tab's log + status strip, once per failure
      // (a retried job that fails again is logged again).
      if (j.state !== 'failed') { sftpQueueLoggedFailures.delete(j.id); continue; }
      if (sftpQueueLoggedFailures.has(j.id)) continue;
      sftpQueueLoggedFailures.add(j.id);
      const tab = [...state.sessions.values()].find(t => t.sessionId === j.sessionId);
      if (tab) sftpLog(tab.tabId, `transfer failed: ${j.remotePath || j.localPath} - ${j.error || 'error'}`);
    }
    renderQueuePanel();
  }).then(() => {
    // The starting state, asked for ONCE, now that its answer (an sftp-queue
    // event carrying the snapshot) has a listener. renderQueuePanel used to
    // ask whenever the list was empty - and the answer re-rendered the still
    // empty list, which asked again: an endless IPC loop from one click.
    call('sftp_queue_list').catch(() => {});
  }).catch(() => { queueWired = false; });
}

/// Countdown ticker for auto-retry backoffs (Task 2). A single shared
/// interval for the module's whole lifetime - never one per row - so there
/// is nothing to leak as the panel is hidden: it just checks whether any job
/// currently needs a tick and no-ops otherwise. renderQueuePanel() patches
/// the rows in place, so re-invoking it here is exactly as safe as the
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

/// The transfer panel's height, for the app session (A1-01). Until the user
/// resizes it, it takes at most about a third of the file surface - at the
/// default window it took 220px of 460 and left the file list no rows - and
/// while the queue is empty it is only its header (renderQueuePanel).
const SFTP_QUEUE_MIN_PX = 96;
const SFTP_QUEUE_MAX_SHARE = 0.7;

function sftpApplyQueueHeight(panel) {
  if (sftpUiQueueH === null) return;
  // A height the user chose may take more than the default third.
  panel.style.setProperty('--q-h', sftpUiQueueH + 'px');
  panel.style.setProperty('--q-cap', Math.round(SFTP_QUEUE_MAX_SHARE * 100) + '%');
}

/// The heights the transfer panel can take in this window, the way
/// styles.css lays it out: never under --q-least, never so tall that the
/// file list loses its floor (--q-floor), and one the user chose up to
/// SFTP_QUEUE_MAX_SHARE of the surface. { lo, hi } - equal in a window too
/// small to grow it. The handle offers only these: it used to offer 70% of
/// the surface, the floor then ignored the height it kept, and that "taller"
/// height made the panel SHORTER than the default in a larger window later.
function sftpQueueBounds(panel) {
  const body = panel.parentElement;
  const bodyH = body ? body.getBoundingClientRect().height : window.innerHeight;
  const css = getComputedStyle(panel);
  const least = parseFloat(css.getPropertyValue('--q-least')) || 60;
  const floor = parseFloat(css.getPropertyValue('--q-floor')) || 226;
  const hi = Math.round(Math.max(least, Math.min(bodyH - floor, bodyH * SFTP_QUEUE_MAX_SHARE)));
  return { lo: Math.min(SFTP_QUEUE_MIN_PX, hi), hi };
}

function buildQueuePanel() {
  const panel = document.createElement('div');
  panel.className = 'sftp-queuepanel empty';
  panel.id = 'sftpQueuePanel';
  panel.style.display = 'none';

  // Top-edge handle: resize the panel - dragged (pointer capture, so no
  // document listeners sit idle between drags) or with the arrow keys.
  const handle = document.createElement('div');
  handle.className = 'sftp-queuehandle';
  handle.title = 'Drag to resize the transfer panel';
  handle.setAttribute('role', 'separator');
  handle.setAttribute('aria-orientation', 'horizontal');
  handle.setAttribute('aria-label', 'Resize the transfer panel');
  handle.tabIndex = 0;
  // A focusable separator says where it stands: the panel's height in px,
  // within the heights it can take in this window.
  const paintHandle = () => {
    const { lo, hi } = sftpQueueBounds(panel);
    const h = Math.round(panel.getBoundingClientRect().height);
    handle.setAttribute('aria-valuemin', String(Math.min(lo, h)));
    handle.setAttribute('aria-valuemax', String(Math.max(hi, h)));
    handle.setAttribute('aria-valuenow', String(h));
    handle.setAttribute('aria-valuetext', `${h} pixels high`);
  };
  // A height that would change nothing on screen is not kept.
  const resizeTo = (h) => {
    const { lo, hi } = sftpQueueBounds(panel);
    const want = Math.round(Math.max(lo, Math.min(hi, h)));
    if (want !== Math.round(panel.getBoundingClientRect().height)) {
      sftpUiQueueH = want;
      sftpApplyQueueHeight(panel);
    }
    paintHandle();
  };
  handle.addEventListener('focus', paintHandle);
  handle.addEventListener('pointerdown', (ev) => {
    const startY = ev.clientY;
    const startH = panel.getBoundingClientRect().height;
    sftpFollowPointer(handle, ev, (e) => resizeTo(startH - (e.clientY - startY)));
  });
  handle.addEventListener('keydown', (ev) => {
    const step = { ArrowUp: 24, ArrowDown: -24 }[ev.key];
    if (step === undefined) return;
    ev.preventDefault();
    resizeTo(panel.getBoundingClientRect().height + step);
  });
  sftpApplyQueueHeight(panel);

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
    if (t === 'failed') b.title = 'Failed and cancelled transfers - Retry starts one again';
    b.addEventListener('click', () => {
      queueTab = t;
      renderQueuePanel();
    });
    tabs.appendChild(b);
  }
  const headActions = document.createElement('div');
  headActions.className = 'sftp-queueactions-head';
  // Icon and label; in a narrow panel the label is visually hidden but stays
  // the button's name, so the header keeps to one line (A1-02).
  const headBtn = (iconHtml, label, title) => {
    const b = document.createElement('button');
    b.className = 'ghost-btn';
    b.title = title;
    b.innerHTML = `${iconHtml}<span class="btn-label">${label}</span>`;
    return b;
  };
  const pauseAllBtn = headBtn(Q_ICON_PAUSE, 'Pause all', 'Pause every active and queued transfer');
  pauseAllBtn.addEventListener('click', async () => {
    try { await call('sftp_queue_pause_all'); } catch (e) { toast(e.message || String(e), 'err'); }
  });
  const resumeAllBtn = headBtn(Q_ICON_RESUME, 'Resume all', 'Resume every paused transfer whose server is connected');
  resumeAllBtn.addEventListener('click', () => sftpQueueResumeAllResumable());
  const clearBtn = headBtn(ico('trash-2'), 'Clear finished', 'Remove finished, failed and cancelled transfers from the list');
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
  // paused job whose server is not connected (see sftpQueueJobResumable).
  // Plain textContent below - only ever a count.
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

/// "Resume all": one sftp_queue_resume_all. Since Task 10 the backend resumes
/// what it can rebind to a connected session of the job's server and leaves
/// the rest paused with a "reconnect" note, so it is safe to call blindly and
/// the per-job loop that worked around it is gone. Which jobs will stay
/// paused is still worked out here, to say so.
async function sftpQueueResumeAllResumable() {
  const paused = [...queueJobs.values()].filter(j => j.state === 'paused');
  if (!paused.length) { toast('Nothing paused to resume.', 'info'); return; }
  const skipped = paused.filter(j => !sftpQueueJobResumable(j)).length;
  try {
    await call('sftp_queue_resume_all');
  } catch (e) { toast(e.message || String(e), 'err'); return; }
  if (skipped === paused.length) toast('Those paused transfers need a reconnect first.', 'info');
  else if (skipped) toast(`Resumed ${paused.length - skipped} - ${skipped} more need a reconnect first.`, 'info');
}

// ─── transfer queue: grouping ───────────────────────────────────────────────

/// Group headers the user has collapsed, keyed by server + directory path.
/// The list is redrawn from queueJobs on every change, so this cannot live
/// in the DOM.
const sftpQueueCollapsed = new Set();

function sftpQueueGroupKey(server, dirPath) { return server + '\u0000' + dirPath; }

/// Build server → directory → files out of a flat job list.
///
/// The remote path is what every kind of job has in common (an upload's
/// destination, a download's source, a server-copy's source), and it is the
/// path that belongs to the server the group is named after, so it is what
/// the tree is built from.
///
/// `jobs` arrives oldest-first, so a job's index doubles as its recency.
/// Servers are ordered most-recent-first, which keeps whatever is being
/// transferred right now at the top; everything below sorts by name, because
/// a tree whose rows reshuffle as bytes arrive cannot be read.
function sftpQueueTree(jobs) {
  const mkNode = (name) => ({ name, dirs: new Map(), jobs: [] });
  const servers = new Map();
  jobs.forEach((j, i) => {
    const server = j.serverName || 'Unknown server';
    if (!servers.has(server)) servers.set(server, { name: server, recency: -1, total: 0, root: mkNode('') });
    const s = servers.get(server);
    s.recency = Math.max(s.recency, i);
    s.total++;
    const segs = (j.remotePath || '').split('/').filter(Boolean);
    segs.pop(); // the last segment is the file itself, not a directory
    let node = s.root;
    for (const seg of segs) {
      if (!node.dirs.has(seg)) node.dirs.set(seg, mkNode(seg));
      node = node.dirs.get(seg);
    }
    node.jobs.push(j);
  });
  return [...servers.values()].sort((a, b) => b.recency - a.recency);
}

/// A run of directories that each hold nothing but one subdirectory carries no
/// information spread over several rows, so it collapses into one
/// "var/www/html" row. Returns the deepest node reached and the joined name.
function sftpQueueFlattenChain(node) {
  let name = node.name;
  let cur = node;
  while (cur.jobs.length === 0 && cur.dirs.size === 1) {
    const only = [...cur.dirs.values()][0];
    name = name ? name + '/' + only.name : only.name;
    cur = only;
  }
  return { node: cur, name };
}

function sftpQueueCountJobs(node) {
  let n = node.jobs.length;
  for (const child of node.dirs.values()) n += sftpQueueCountJobs(child);
  return n;
}

/// One header row. Clicking it collapses or expands the branch beneath.
function sftpQueueGroupEl(kind, label, key, depth, count) {
  const row = document.createElement('button');
  const collapsed = sftpQueueCollapsed.has(key);
  row.className = 'sftp-queuegroup q-group-' + kind + (collapsed ? ' collapsed' : '');
  row.style.setProperty('--q-depth', String(depth));
  row.innerHTML = `<span class="q-twisty">${ico('chevron-right')}</span>`
    + `<span class="q-groupicon">${ico(kind === 'server' ? 'server' : 'folder')}</span>`
    + `<span class="q-grouplabel">${escapeHtml(label)}</span>`
    + `<span class="q-groupcount">${count}</span>`;
  row.addEventListener('click', () => {
    if (sftpQueueCollapsed.has(key)) sftpQueueCollapsed.delete(key);
    else sftpQueueCollapsed.add(key);
    renderQueuePanel();
  });
  return row;
}

/// The list as a plan, in display order: group headers and job rows, with
/// their depth. Nothing is drawn here - renderQueuePanel compares plans to
/// decide whether anything but the numbers changed.
function sftpQueuePlan(jobs) {
  const plan = [];
  const byName = (a, b) => a.name.localeCompare(b.name);
  const addNode = (server, node, dirPath, depth) => {
    for (const child of [...node.dirs.values()].sort(byName)) {
      const flat = sftpQueueFlattenChain(child);
      const path = dirPath + '/' + flat.name;
      const key = sftpQueueGroupKey(server, path);
      plan.push({ group: 'dir', label: flat.name, key, depth, count: sftpQueueCountJobs(flat.node) });
      if (!sftpQueueCollapsed.has(key)) addNode(server, flat.node, path, depth + 1);
    }
    // Files sit alongside the subfolders at their own level, not after all of
    // them, which is what "maybe a file here" in a directory listing means.
    for (const j of node.jobs.slice().sort((a, b) =>
      sftpQueueJobName(a).localeCompare(sftpQueueJobName(b)))) {
      plan.push({ job: j, depth });
    }
  };
  for (const s of sftpQueueTree(jobs)) {
    const key = sftpQueueGroupKey(s.name, '');
    plan.push({ group: 'server', label: s.name, key, depth: 0, count: s.total });
    if (!sftpQueueCollapsed.has(key)) addNode(s.name, s.root, '', 1);
  }
  return plan;
}

function sftpQueueJobName(j) {
  return (j.remotePath || '').split('/').filter(Boolean).pop() || '?';
}

// ─── transfer queue: rows, patched in place ─────────────────────────────────
//
// Progress arrives as an sftp-queue event per running job several times a
// second. The list used to be rebuilt from scratch for every one of them, so
// the Pause or Cancel button under the pointer was replaced between mousedown
// and mouseup and the click never happened - stopping a running transfer was
// unreliable exactly while it ran. Each job now keeps ONE row element for as
// long as it is listed: an event updates its text and bar in place, its
// buttons are rebuilt only when its state changes, and the list is re-ordered
// only when its structure (which rows, which groups) changes.

/// jobId -> the row element showing it.
const sftpQueueRows = new Map();
/// Structure the list was last drawn with (see renderQueuePanel).
let sftpQueueLayout = '';

/// Build the fixed skeleton of one transfer row; sftpQueueFillRow puts the
/// job's current numbers in. Dynamic text goes in through textContent only.
function sftpQueueBuildRow(j) {
  const row = document.createElement('div');
  const cell = (cls) => {
    const s = document.createElement('span');
    s.className = 'q-cell ' + cls;
    row.appendChild(s);
    return s;
  };
  const dir = cell('q-dir');
  dir.innerHTML = j.kind === 'upload'
    ? `<span class="q-dirarrow up" title="Upload">${ico('file-up')}</span>`
    : j.kind === 'serverCopy'
      ? `<span class="q-dirarrow copy" title="Server to server">${ico('send')}</span>`
      : `<span class="q-dirarrow down" title="Download">${ico('download')}</span>`;
  const name = cell('q-name');
  const nameText = sftpQueueJobName(j);
  name.title = nameText;
  // Verify badge (Task 4): a small marker on jobs that ran (or will run)
  // with post-transfer SHA-256 verification, so the extra traffic/time it
  // costs isn't a silent surprise when watching the queue.
  if (j.verify) {
    const badge = document.createElement('span');
    badge.className = 'q-verify';
    badge.title = 'Verifying with SHA-256 after transfer';
    badge.innerHTML = ico('shield-check');
    name.appendChild(badge);
  }
  name.appendChild(document.createTextNode(nameText));
  const route = cell('q-route');
  route.textContent = j.kind === 'serverCopy' && j.targetServerName
    ? `${j.serverName || ''} → ${j.targetServerName}`
    : (j.serverName || '');
  route.title = route.textContent;
  const prog = cell('q-prog');
  const bar = document.createElement('span');
  bar.className = 'sftp-queuebar';
  const fill = document.createElement('span');
  bar.appendChild(fill);
  const progText = document.createElement('span');
  progText.className = 'q-progtext';
  prog.appendChild(bar);
  prog.appendChild(progText);
  const speed = cell('q-speed');
  const eta = cell('q-eta');
  const err = cell('q-err');
  const actions = cell('q-act sftp-queueactions');
  row._q = { fill, progText, speed, eta, err, actions, actionsKey: null };
  return row;
}

/// Put a job's current state into its row, touching only what changed.
function sftpQueueFillRow(row, j, depth) {
  const q = row._q;
  row.className = 'sftp-queueitem q-state-' + j.state;
  row.style.setProperty('--q-depth', String(depth));
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
  q.fill.className = 'sftp-queuefill' + (j.state === 'failed' ? ' failed' : j.state === 'done' ? ' done' : j.state === 'paused' ? ' paused' : '');
  q.fill.style.width = pct + '%';
  q.progText.textContent = j.size
    ? `${formatSftpSize(shownDone || 0)} / ${formatSftpSize(j.size)}`
    : formatSftpSize(shownDone || 0);
  q.speed.textContent = j.speed ? sftpFormatRate(j.speed) : '-';
  q.eta.textContent = sftpUiQueueEta(j, shownDone);
  // Auto-retry countdown (Task 2): a backoff-queued job carries
  // attempts > 0 and a future retryAt, plus a human error like
  // "connection reset - retrying (2/3)". Pull just the "(2/3)" back out
  // of that string rather than hardcoding the retry cap here, so the two
  // stay in sync automatically; the full backend message is still the
  // tooltip. A single shared ticker (see setInterval above) redraws this
  // once a second - no per-row timer to leak.
  const retrySecs = (j.state === 'queued' && j.retryAt)
    ? Math.max(0, Math.ceil((j.retryAt - Date.now()) / 1000))
    : null;
  let errDisplay = j.error || (j.state === 'cancelled' ? 'Cancelled' : '');
  let errClass = '';
  if (retrySecs !== null) {
    const m = errDisplay.match(/\((\d+\/\d+)\)\s*$/);
    errDisplay = `retrying in ${retrySecs}s${m ? ' (' + m[1] + ')' : ''}`;
    errClass = ' retrying';
  } else if ((j.state === 'paused' && j.error) || j.state === 'cancelled') {
    errClass = ' info'; // a paused note or a cancel, not a failure - don't paint it red
  }
  q.err.className = 'q-cell q-err' + errClass;
  q.err.title = j.error || '';
  q.err.textContent = errDisplay;
  // The buttons are rebuilt only when what they OFFER changes - not on every
  // state change: queued -> active offers the same Pause/Cancel, and
  // replacing them under a pressed pointer ate the click.
  const resumable = j.state === 'paused' ? sftpQueueJobResumable(j) : null;
  const actionsKey = j.state === 'active' || j.state === 'queued' ? 'pause'
    : j.state === 'paused' ? (resumable ? 'resume' : `reconnect:${j.serverName || ''}`)
      : j.state === 'failed' || j.state === 'cancelled' ? 'retry' : 'none';
  if (q.actionsKey !== actionsKey) {
    q.actionsKey = actionsKey;
    q.actions.replaceChildren(...sftpQueueActionButtons(j, resumable));
  }
}

function sftpQueueActionButtons(j, resumable) {
  const btn = (title, iconHtml, cmd) => {
    const b = document.createElement('button');
    b.className = 'icon-btn';
    b.title = title;
    b.innerHTML = iconHtml;
    if (cmd) b.addEventListener('click', () => call(cmd, { jobId: j.id }).catch((e) => toast(e.message || String(e), 'err')));
    return b;
  };
  if (j.state === 'active' || j.state === 'queued') {
    return [btn('Pause', Q_ICON_PAUSE, 'sftp_queue_pause'), btn('Cancel', ico('x'), 'sftp_queue_cancel')];
  }
  if (j.state === 'paused') {
    let resume;
    if (resumable) {
      resume = btn('Resume', Q_ICON_RESUME, 'sftp_queue_resume');
    } else {
      // No connected tab on the job's server - resume_job would leave it
      // paused anyway. Disabled, not wired.
      resume = btn(`Reconnect to "${j.serverName || 'the server'}" to resume`, Q_ICON_RESUME, null);
      resume.className = 'icon-btn disabled';
      resume.disabled = true;
    }
    // Cancel is the way off a paused row that can never resume - a job
    // restored from a previous run whose server is gone. cancel_job
    // transitions Paused as well as Queued, so this is not a no-op.
    return [resume, btn('Cancel', ico('x'), 'sftp_queue_cancel')];
  }
  if (j.state === 'failed' || j.state === 'cancelled') {
    return [btn('Retry', ico('refresh-cw'), 'sftp_queue_retry')];
  }
  return [];
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
  const cancelled = jobs.filter(j => j.state === 'cancelled');
  const done = jobs.filter(j => j.state === 'done');

  // An empty queue is the panel's header alone (A1-01): the tabs, the bulk
  // actions and the column header have nothing to act on, and the room is the
  // file list's. The first job opens it.
  const panelEl = document.getElementById('sftpQueuePanel');
  if (panelEl) panelEl.classList.toggle('empty', jobs.length === 0);

  const aggSpeed = active.reduce((s, j) => s + (j.speed || 0), 0);
  const summaryParts = [];
  if (active.length) summaryParts.push(`${active.length} active · ${sftpFormatRate(aggSpeed)}`);
  if (queued.length) summaryParts.push(`${queued.length} queued`);
  if (paused.length) summaryParts.push(`${paused.length} paused`);
  if (!summaryParts.length) {
    if (failed.length) summaryParts.push(`${failed.length} failed`);
    if (cancelled.length) summaryParts.push(`${cancelled.length} cancelled`);
  }
  if (!jobs.length) summaryParts.push('None yet - uploads and downloads show here');
  summary.textContent = summaryParts.join(' · ');
  // One line, cut short in a narrow panel; the whole of it on hover.
  summary.title = summary.textContent;

  // Restored-transfer banner (Task 5): only the jobs a Resume click would
  // actually leave paused - see sftpQueueJobResumable.
  const staleRestored = paused.filter(j => !sftpQueueJobResumable(j));
  const banner = document.getElementById('sftpQueueRestoredBanner');
  if (banner) {
    banner.hidden = staleRestored.length === 0;
    banner.textContent = staleRestored.length === 1
      ? '1 paused transfer belongs to a server that is not connected - reconnect to it to resume.'
      : `${staleRestored.length} paused transfers belong to servers that are not connected - reconnect to them to resume.`;
    banner.title = banner.textContent; // one line on screen (styles.css), whole here
  }

  // Never cut the running jobs (their Pause/Cancel are the only way to stop
  // them); the waiting ones share the room that is left - queued first, in
  // the order they run (the next job must stay visible and cancellable before
  // it starts), then the paused ones, which only run after a Resume and so
  // are the tail. Cutting the LAST 100 of [active, queued, paused] dropped
  // exactly the running jobs as soon as a folder transfer queued more than
  // 100 files; exempting paused jobs drew thousands of rows after "Pause all"
  // or a restart.
  let shown;
  let left = 0;
  if (queueTab === 'queued') {
    const waiting = [...queued, ...paused];
    const room = Math.max(0, SFTP_QUEUE_ROW_CAP - active.length);
    shown = [...active, ...waiting.slice(0, room)];
    left = waiting.length - Math.min(waiting.length, room);
  } else {
    const all = queueTab === 'failed' ? jobs.filter(j => j.state === 'failed' || j.state === 'cancelled') : done;
    shown = all.slice(-SFTP_QUEUE_ROW_CAP); // the most recent
    left = all.length - shown.length;
  }

  // Grouped rather than flat: server, then the remote directory tree the
  // transfers land in. See sftpQueueTree for why the ordering is what it is.
  const plan = sftpQueuePlan(shown);
  for (const p of plan) {
    if (!p.job) continue;
    let row = sftpQueueRows.get(p.job.id);
    if (!row) { row = sftpQueueBuildRow(p.job); sftpQueueRows.set(p.job.id, row); }
    sftpQueueFillRow(row, p.job, p.depth);
  }
  const layout = queueTab + '|' + left + '\n' + plan.map(p => (p.job
    ? `j${p.job.id}`
    : `g${p.key}|${p.count}|${sftpQueueCollapsed.has(p.key) ? 1 : 0}`) + '@' + p.depth).join('\n');
  const expected = plan.length + (left ? 1 : 0);
  if (layout === sftpQueueLayout && list.childElementCount === expected) return;
  // The structure changed: lay the list out again, reusing every job's row.
  sftpQueueLayout = layout;
  const nodes = plan.map(p => (p.job
    ? sftpQueueRows.get(p.job.id)
    : sftpQueueGroupEl(p.group, p.label, p.key, p.depth, p.count)));
  if (left) {
    const more = document.createElement('div');
    more.className = 'sftp-queuemore hint';
    more.textContent = queueTab === 'queued'
      ? `+ ${left} more paused or queued transfer${left === 1 ? '' : 's'} not shown.`
      : `+ ${left} earlier transfer${left === 1 ? '' : 's'} not shown.`;
    nodes.push(more);
  }
  // Drop what goes, then insert what is new: a row that stays where it was
  // relative to the others is never detached, so a click on it survives even
  // another job arriving or finishing.
  const keep = new Set(nodes);
  for (const child of [...list.children]) if (!keep.has(child)) child.remove();
  let cursor = list.firstChild;
  for (const node of nodes) {
    if (node === cursor) { cursor = cursor.nextSibling; continue; }
    list.insertBefore(node, cursor);
  }
  const listed = new Set(shown.map(j => j.id));
  for (const id of [...sftpQueueRows.keys()]) if (!listed.has(id)) sftpQueueRows.delete(id);
}

// Refresh the listings a finished transfer changed: the tab on screen within
// 1.5 s (so a folder of a thousand small files costs one listing, not a
// thousand), a tab in the background as soon as it is shown again
// (showSftpForTab). The old ticker looked at the ACTIVE tab only and used the
// completion up, so a tab whose upload finished while the user was elsewhere
// showed the folder without the new file when they came back.
setInterval(() => {
  const tab = sftpTab(state.activeTabId);
  if (!tab || !tab._listingDirty || !tab.sftpReady || !sftpPanelOnScreen(tab)) return;
  tab._listingDirty = false;
  refreshSftpPanel(tab.tabId, { forceFresh: true });
}, 1500);

// ─── OS drag-and-drop upload ────────────────────────────────────────────────

let sftpDropWired = false;
function wireSftpDrop(_panel, _tabId, _hint) {
  if (sftpDropWired) return;
  sftpDropWired = true;
  const win = sftpWindow && sftpWindow.getCurrentWindow ? sftpWindow.getCurrentWindow() : null;
  if (!win || !win.onDragDropEvent) return;
  // One window-level handler, resolving the ACTIVE tab's panel at event time
  // instead of closing over the first panel's hint element - the old closure
  // meant the drop overlay only ever appeared in the first tab ever built.
  win.onDragDropEvent(async (event) => {
    const tab = state.sessions.get(state.activeTabId);
    // Only onto a file panel the user can see: dropped while Keys/Settings or
    // a dialog was in front, a file (a private key, say) used to be uploaded
    // to the active tab's server without a cue.
    if (!sftpPanelOnScreen(tab)) {
      for (const h of document.querySelectorAll('.sftp-drop-hint.dragover')) h.classList.remove('dragover');
      return;
    }
    const hint = document.querySelector(`#sftpPanel-${tab.tabId} .sftp-drop-hint`);
    if (!hint) return;
    if (event.payload.type === 'enter' || event.payload.type === 'over') {
      hint.classList.add('dragover');
    } else if (event.payload.type === 'leave') {
      hint.classList.remove('dragover');
    } else if (event.payload.type === 'drop') {
      hint.classList.remove('dragover');
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
      const names = paths.map((p) => p.split(/[\\/]/).filter(Boolean).pop() || 'file');
      const pairs = paths.map((p, i) => ({ local: p, remote: sftpJoin(remoteDir, names[i]) }));
      // Onto a folder row whose name passes for another folder, it asks
      // first - as a drop from the local pane does.
      if (remoteDir !== tab.sftpPath && sftpUnusualFolder(remoteDir)) {
        const sessionId = tab.sessionId;
        if (!(await sftpAskUploadInto(remoteDir, names))) return;
        if (!sftpSameSession(tab.tabId, tab, sessionId)) return;
      }
      queueUploads(tab.tabId, pairs);
    }
  });
}

// ─── two-pane drag and drop (FileZilla parity), by the pointer ──────────────
//
// Rows are dragged with pointer events (beginPointerDrag, app.js), not HTML5
// drag and drop (A3-23): on Windows the webview's drop handling
// belongs to Tauri while `dragDropEnabled` is on - and OS file drops onto
// this list need it on (wireSftpDrop, above) - so HTML5 `dragover` / `drop`
// never reached the page. A move or a pane-to-pane transfer started, the
// cursor changed, and nothing happened.
//
// What is dragged is the row's selection when the row is part of it, else the
// row alone. Released over:
//   - a remote folder row, remote items MOVE into it (asking first);
//   - the remote pane or a remote folder, local items UPLOAD into it;
//   - the local pane or a local folder, remote items DOWNLOAD into it.
// Escape cancels. Every one of these has a menu equivalent for a single
// pointer without dragging (WCAG 2.2 SC 2.5.7): Move to..., Download, Upload.

/// A press on a listing row that may become a drag.
function sftpRowPointerDown(ev, tabId, side) {
  if (ev.button !== 0 || ev.ctrlKey || ev.metaKey || ev.shiftKey || ev.altKey) return;
  const tr = ev.target.closest ? ev.target.closest('tr.sftp-entry') : null;
  if (!tr) return;
  const drag = sftpDragFromRow(tabId, side, tr.dataset.name);
  if (!drag) return;
  beginPointerDrag(ev, {
    label: drag.items.length === 1 ? sftpSpell(drag.items[0].name) : `${drag.items.length} items`,
    onStart: () => tr.classList.add('sftp-dragging'),
    over: (x, y) => sftpDragOver(drag, x, y),
    cleanup: sftpClearDropMarks,
    drop: (x, y) => {
      const target = sftpDropTargetAt(drag, x, y);
      if (target) sftpDropDragged(drag, target);
    },
  });
}

/// What a drag from row `name` of a pane carries: { tabId, side, dir,
/// sessionId, items: [{ path, name, isDir }] }, or null.
function sftpDragFromRow(tabId, side, name) {
  const tab = sftpTab(tabId);
  if (!tab || !sftpPanelVisible(tab)) return null;
  sftpTabState(tab);
  const remote = side === 'remote';
  const entries = remote ? (tab._entryMap || new Map()) : new Map((tab._localEntries || []).map((e) => [e.name, e]));
  const dir = remote ? tab.sftpPath : tab.localPath;
  if (!entries.has(name) || !dir) return null;
  const selected = remote ? tab.sftpSelected : tab.localSelected;
  const names = selected.has(name) ? [...selected] : [name];
  const join = remote ? sftpJoin : joinLocal;
  const items = names.map((n) => entries.get(n)).filter(Boolean)
    .map((e) => ({ path: join(dir, e.name), name: e.name, isDir: !!e.isDir }));
  return items.length ? { tabId, side, dir, sessionId: tab.sessionId, items } : null;
}

/// Where a drag of `drag` released at (x, y) would go: { side, dir, row,
/// pane }, or null when it can go nowhere there. A folder row of either pane
/// takes it into that folder (never into itself); the other pane's list takes
/// it into that pane's folder. A local drag only goes to the remote side - a
/// local-to-local move is not something this offers.
function sftpDropTargetAt(drag, x, y) {
  const hit = document.elementFromPoint(x, y);
  if (!hit || !hit.closest) return null;
  const panel = hit.closest('.sftp-panel');
  const pane = hit.closest('.sftp-pane');
  if (!panel || panel.id !== 'sftpPanel-' + drag.tabId || !pane) return null;
  const tab = sftpTab(drag.tabId);
  if (!tab) return null;
  const side = pane.classList.contains('sftp-local') ? 'local' : 'remote';
  if (drag.side === 'local' && side === 'local') return null;
  const base = side === 'remote' ? tab.sftpPath : tab.localPath;
  if (!base) return null;
  const join = side === 'remote' ? sftpJoin : joinLocal;
  const row = hit.closest('tr.sftp-entry');
  if (row && row.dataset.isdir === '1') {
    const dir = join(base, row.dataset.name);
    const ontoItself = side === drag.side && drag.items.some((i) => i.path === dir);
    if (!ontoItself) return { side, dir, row, pane };
  }
  // Over its own pane, off a folder, a drag has nowhere new to go.
  if (side === drag.side) return null;
  return { side, dir: base, row: null, pane };
}

/// Light the target under the pointer: a folder row, or the whole pane.
function sftpDragOver(drag, x, y) {
  for (const n of document.querySelectorAll('.sftp-entry.drop-target, .sftp-pane.drag-over')) {
    n.classList.remove('drop-target', 'drag-over');
  }
  const t = sftpDropTargetAt(drag, x, y);
  if (!t) return false;
  if (t.row) t.row.classList.add('drop-target');
  else t.pane.classList.add('drag-over');
  return true;
}

function sftpClearDropMarks() {
  for (const n of document.querySelectorAll('.sftp-entry.drop-target, .sftp-pane.drag-over, .sftp-entry.sftp-dragging')) {
    n.classList.remove('drop-target', 'drag-over', 'sftp-dragging');
  }
}

/// What a drag released on `target` does - the same actions the menus offer:
/// remote items onto a remote folder move there (after asking, as a drop
/// always has), local items onto the remote side upload, remote items onto
/// the local side download (through the usual "already exists" check).
/// `drag` as sftpDragFromRow makes it, `target` as sftpDropTargetAt does
/// ({ side, dir }). Resolves once the move ran or the transfers are queued.
async function sftpDropDragged(drag, target) {
  const tab = drag && sftpTab(drag.tabId);
  if (!tab || !sftpPanelVisible(tab) || !target || !target.dir || !arrayOrEmpty(drag.items).length) return;
  if (drag.side === 'remote' && target.side === 'remote') {
    await sftpMoveRemote(drag.tabId, drag.items, target.dir, { ask: true, sessionId: drag.sessionId });
  } else if (drag.side === 'local' && target.side === 'remote') {
    // Onto a folder row whose name passes for another folder, it asks first.
    if (target.dir !== tab.sftpPath && sftpUnusualFolder(target.dir)) {
      if (!(await sftpAskUploadInto(target.dir, drag.items.map((i) => i.name)))) return;
      if (!sftpSameSession(drag.tabId, tab, drag.sessionId)) return;
    }
    await queueUploads(drag.tabId, drag.items.map((i) => ({ local: i.path, remote: sftpJoin(target.dir, i.name) })));
  } else if (drag.side === 'remote' && target.side === 'local') {
    await queueDownloads(drag.tabId, drag.items.map((i) => i.path), target.dir);
  }
}

/// Move remote items into the folder `dest` (a drag onto a folder row, or
/// Move to...). `o.ask` asks first - a drop can land on the wrong row; Move
/// to... has the folder typed out already. Only over the session the items
/// were listed in (`o.sessionId`): the question is modal, not frozen, and the
/// tab can reconnect or close meanwhile.
async function sftpMoveRemote(tabId, items, dest, o = {}) {
  const tab = sftpTab(tabId);
  if (!tab) return;
  const sessionId = o.sessionId || tab.sessionId;
  const within = (p) => dest === p || dest.startsWith(p.endsWith('/') ? p : p + '/');
  const into = items.filter((i) => i.isDir && within(i.path));
  if (into.length) {
    toast(`"${sftpInText(into[0].name)}" cannot be moved into itself.`, 'err');
    return;
  }
  const moves = items.map((i) => ({ ...i, to: sftpJoin(dest, i.name) })).filter((m) => m.to !== m.path);
  if (!moves.length) return;
  if (o.ask) {
    const what = moves.length === 1 ? `"${sftpInText(moves[0].name)}"` : `${moves.length} items (${sftpNameList(moves.map((m) => m.name))})`;
    const go = await confirmModal(moves.length === 1 ? 'Move item' : 'Move items', `Move ${what} ${sftpIntoFolder(dest)}?`, 'Move', { danger: false });
    if (!go) return;
  }
  if (!sftpSameSession(tabId, tab, sessionId)) return;
  let ok = 0;
  const errors = [];
  for (const m of moves) {
    try {
      await sftpCall('sftp_rename', { sessionId, from: m.path, to: m.to });
      sftpLog(tabId, `move ${sftpSpell(m.name)} → ${sftpSpell(m.to)}`);
      ok++;
    } catch (e) { errors.push((e && (e.message || e.error)) || String(e)); }
  }
  // The folders the items left and the one they went to changed; a moved
  // folder's old subtree is stale wherever it was cached.
  await sftpAfterRemoteChange(tabId, tab, {
    dirs: [dest, ...moves.map((m) => sftpParent(m.path))],
    trees: moves.filter((m) => m.isDir).map((m) => m.path),
  });
  if (errors.length) toast(`${ok} moved, ${errors.length} failed: ${errors[0]}`, 'err');
  else if (ok > 1) toast(`Moved ${ok} items ${sftpIntoFolder(dest)}.`, 'ok');
}

/// Where a move goes, said so a look-alike cannot pass for another folder (a
/// folder named with two ONE DOT LEADERs read as ".." inside one long path):
/// the folder by its own name, then the folder it is in - into the folder
/// "docs" inside /home/u. Text only.
function sftpIntoFolder(dest) {
  if (dest === '/') return 'into the top folder, /';
  const name = dest.split('/').filter(Boolean).pop() || dest;
  return `into the folder "${sftpInText(name)}" inside ${sftpInText(sftpParent(dest))}`;
}

/// Whether the folder `dir` has a name the listing flags (sftpUnusualName).
function sftpUnusualFolder(dir) {
  const name = String(dir || '').split('/').filter(Boolean).pop();
  return name !== undefined && sftpUnusualName(name);
}

/// Before an upload into such a folder: a file dropped on " .." or on two
/// U+A4F8 - the parent folder, at a glance - would land somewhere else than
/// it seems. Resolves true to go ahead.
function sftpAskUploadInto(dir, names) {
  const what = names.length === 1 ? `"${sftpInText(names[0])}"` : `${names.length} items`;
  const name = dir.split('/').filter(Boolean).pop();
  return confirmModal('Upload into an unusual folder',
    `Upload ${what} ${sftpIntoFolder(dir)}? ${sftpUnusualNote(name)}`, 'Upload', { danger: false });
}

/// Move to... (a remote row's menu): the same move as a drag onto a folder,
/// with the destination typed - for a single pointer, no dragging (SC 2.5.7).
function sftpMoveToPrompt(tabId, entry) {
  const tab = sftpTabState(sftpTab(tabId));
  if (!tab || !tab._entryMap) return;
  const dir = tab.sftpPath;
  const sessionId = tab.sessionId;
  const names = tab.sftpSelected.has(entry.name) ? [...tab.sftpSelected] : [entry.name];
  const items = names.map((n) => tab._entryMap.get(n)).filter(Boolean)
    .map((e) => ({ path: sftpJoin(dir, e.name), name: e.name, isDir: !!e.isDir }));
  if (!items.length) return;
  const title = items.length === 1 ? `Move "${sftpSpell(items[0].name)}"` : `Move ${items.length} items`;
  promptModal(title, 'Move to this folder on the server:', dir, (input) => {
    const norm = sftpUiNormalizeRemotePath(String(input || '').trim());
    if (!norm) { toast('Type the folder\'s full path, starting with /.', 'err'); return; }
    if (norm.path === dir) return;
    sftpMoveRemote(tabId, items, norm.path, { sessionId });
  });
}

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
  const show = (mode) => {
    if (mode) sftpCmpTabs.set(tabId, mode);
    else sftpCmpTabs.delete(tabId);
    sftpCmpUpdateButton(tabId);
    if (mode) sftpCmpRun(tabId);
    else sftpCmpClear(tabId);
  };
  show(next);
  sftpLog(tabId, `directory comparison: ${next ? 'by ' + (next === 'size' ? 'file size' : 'modified time') : 'off'}`);
  // Persist the last-used mode ('' when turned off from mtime → default off).
  // A mode the backend refuses to keep is taken back off the screen, with its
  // message, like every other setting saved from here (sftpSaveSetting) - the
  // panes no longer show a comparison the next session would not.
  sftpSaveSetting('sftpCmpMode', next || '', () => {
    if (sftpTab(tabId) !== tab || sftpCmpModeOf(tabId) !== next) return;
    show(cur);
    sftpLog(tabId, `directory comparison back ${cur ? 'to by ' + (cur === 'size' ? 'file size' : 'modified time') : 'off'} - the setting could not be saved`);
  });
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
  // Stash the maps on the tab: the virtualized panes rebuild rows through the
  // row builders on every scroll, and those builders re-apply the tint from
  // here - without it, rows mounted after a scroll came up untinted while
  // the still-mounted ones kept theirs (a contradictory half-tinted view).
  tab._sftpCmpClasses = cls;
  sftpLog(tabId, `compare (${mode === 'size' ? 'by size' : 'by mtime'}): ${onlyLocal} only-local, ${onlyRemote} only-remote, ${differ} differ, ${same} identical`);
}

/// Remove all comparison classes from both panes (mode turned off).
function sftpCmpClear(tabId) {
  const tab = sftpTab(tabId);
  if (tab) tab._sftpCmpClasses = null; // stop future scroll-rebuilds re-tinting
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
    // Secondary: on a narrow panel these fold into More (A5-07).
    b.className = 'ghost-btn sftp-tb-secondary ' + cls;
    b.title = title;
    b.innerHTML = `${ico(icon)}<span class="btn-label">${label}</span>`;
    b.addEventListener('click', fn);
    return b;
  };
  const cmpBtn = mkBtn('sftp-cmp-btn', 'eye', 'Compare directories (Ctrl+Y): off → by size → by mtime', 'Compare', () => sftpCmpToggle(tabId));
  const syncBtn = mkBtn('sftp-sync-btn', 'folder-tree', 'Synchronized browsing (Ctrl+Shift+B): mirror navigation in both panes', 'Sync browse', () => sftpSyncToggle(tabId));
  // With the other buttons, ahead of More - which stays last on the row.
  const more = toolbar.querySelector('.sftp-more-btn');
  toolbar.insertBefore(cmpBtn, more);
  toolbar.insertBefore(syncBtn, more);
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

// Keyboard shortcut: Ctrl+Y cycles comparison in the active SFTP tab - while
// its panel is in front and the key is not for a text field (sftpShortcutTab).
document.addEventListener('keydown', (ev) => {
  if (!(ev.ctrlKey || ev.metaKey) || ev.shiftKey || ev.altKey || ev.key.toLowerCase() !== 'y') return;
  const tab = sftpShortcutTab(ev);
  if (!tab) return;
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
/// navigation. The local target is checked first; the remote side always
/// navigates (it is where the double-click happened) and the local side
/// follows only while sync is still on - and neither moves unless the remote
/// listing arrives (refreshSftpPanel's localPath option).
function sftpSyncRemoteNav(tabId, name) {
  if (!sftpSyncActive(tabId)) return false;
  const tab = sftpTab(tabId);
  const targetLocal = joinLocal(tab.localPath, name);
  const targetRemote = sftpJoin(tab.sftpPath, name);
  sftpCall('sftp_local_list', { path: targetLocal })
    .then(() => {
      const mirror = sftpSyncIsOn(tabId); // may have been toggled off mid-flight
      refreshSftpPanel(tabId, { path: targetRemote, localPath: mirror ? targetLocal : undefined });
    })
    .catch(() => {
      // Local mirror missing: remote still navigates, sync suspends.
      refreshSftpPanel(tabId, { path: targetRemote });
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
  const targetLocal = joinLocal(tab.localPath, name);
  if (!remoteHasDir) {
    sftpLocalNavigate(tabId, targetLocal);
    sftpSyncSuspend(tabId, 'remote', name);
    return true;
  }
  refreshSftpPanel(tabId, { path: sftpJoin(tab.sftpPath, name), localPath: targetLocal });
  return true;
}

/// Remote "Up" with sync. Returns true when handled. One request moves both
/// panes, so there is no old-listing race between them.
function sftpSyncRemoteUp(tabId) {
  if (!sftpSyncActive(tabId)) return false;
  const tab = sftpTab(tabId);
  refreshSftpPanel(tabId, { path: sftpParent(tab.sftpPath), localPath: sftpLocalParent(tab.localPath) });
  return true;
}

/// Local "Up" with sync. Returns true when handled.
function sftpSyncLocalUp(tabId) {
  if (!sftpSyncActive(tabId)) return false;
  const tab = sftpTab(tabId);
  if (!tab.localPath) { refreshLocalPane(tabId); return true; } // nothing above local root
  refreshSftpPanel(tabId, { path: sftpParent(tab.sftpPath), localPath: sftpLocalParent(tab.localPath) });
  return true;
}

// Keyboard shortcut: Ctrl+Shift+B toggles synchronized browsing - under the
// same conditions as Ctrl+Y (sftpShortcutTab).
document.addEventListener('keydown', (ev) => {
  if (!(ev.ctrlKey || ev.metaKey) || !ev.shiftKey || ev.altKey || ev.key.toLowerCase() !== 'b') return;
  const tab = sftpShortcutTab(ev);
  if (!tab) return;
  ev.preventDefault();
  sftpSyncToggle(tab.tabId);
});

// ─── exports ────────────────────────────────────────────────────────────────

window.toggleSshSftpMode = toggleSshSftpMode;
window.refreshSftpPanel = refreshSftpPanel;
window.showSshForTab = showSshForTab;
window.showSftpForTab = showSftpForTab;
window.showSplitForTab = showSplitForTab;
window.setSessionMode = setSessionMode;
window.sftpQueueDownloads = queueDownloads;
window.sftpConflictDefaults = sftpConflictDefaults;
window.sftpCmpToggle = sftpCmpToggle;
window.sftpSyncToggle = sftpSyncToggle;
