/**
 * terminal.js - per-tab xterm.js sessions for the Connect view.
 * ---------------------------------------------------------------------------
 * Every session lives in its own tab: its own xterm instance, host <div>,
 * IPC channel, keystroke subscription, and close-detection poll. Inactive
 * tabs stay mounted (hidden) so scrollback survives tab switches.
 *
 * Public API (called from app.js):
 *   createTabTerminal(tabId)      - build the tab's xterm in a new host div
 *   showTabTerminal(tabId)        - activate a tab (show host + refit + focus)
 *   destroyTabTerminal(tabId)     - dispose the tab's terminal + host
 *   terminalConnectInTab(tabId, srv, opts) - open the SSH session for that tab
 *   terminalCancelConnect(tabId)  - give up on the tab's connect in flight
 *   tabSessionLive(tabId)         - is the tab's SSH session open?
 *   tabRecord(tabId).sessionId    - the session that is really open for it
 *   fitActiveTerminal()           - refit the active tab (resize/maximize)
 *   terminalResetActive()         - clear the active terminal
 *   terminalSetStatus(text)       - bottom status strip (app.js decides what)
 *   session end calls window.onSessionClosed(tabId) (implemented in app.js).
 */

'use strict';

// Loaded marker: app.js's boot checks that this file ran (see main()).
window.__SSHPAN_TERMINAL_JS__ = true;

// app.js already declares top-level `const invoke` in the shared classic-
// script global scope - re-declaring it here is a SyntaxError that kills the
// whole file. Namespace everything.
const tcore = window.__TAURI__.core;
const tclip = (window.__TAURI__ && window.__TAURI__.clipboardManager) || null;

const sshTabs = new Map();   // tabId -> {term, fitAddon, hostEl, sessionId, pollHandle, dataSub, attempt, connecting, ...}
let activeTabId = null;

/// The backend's own closing line, sent on a session's channel as one message
/// when the session ends (ssh_client). When it arrives the renderer adds none
/// of its own: every ended session used to say "[connection closed]" twice
/// (A3-34 #5).
const BACKEND_CLOSED_LINE = '\r\n\x1b[1;33m[connection closed]\x1b[0m\r\n';

/// Why an attempt's late result is thrown away: its tab closed, it was
/// cancelled, or a newer connect on the same tab replaced it.
const CONNECT_ABANDONED = 'This connection attempt was abandoned.';

function terminalSetting(name, fallback) {
  const settings = window.state && window.state.settings ? window.state.settings : {};
  const value = settings[name];
  return value === undefined || value === null || value === '' ? fallback : value;
}

// ─── focus ──────────────────────────────────────────────────────────────────
//
// A tab switch, a connect and a maximize all move the keyboard into the
// terminal a few tens of milliseconds later, once the terminal is visible and
// fitted. That deferred focus must never take the keyboard from where the user
// is by then. It stands down when a dialog is up (the connect password prompt
// opens at the same moment as the tab; the terminal used to win and typed
// characters went nowhere), when a menu is open (a menu opened right after a
// tab switch lost its focus), and when the focus moved after the action began
// (an Enter on a tab's close button reached in those milliseconds went to the
// shell). It may come from <body>, from inside the terminals, or from the
// control that started the action - never out of a text field.

function terminalDialogOpen() {
  return !!document.querySelector('.modal-backdrop:not([hidden])');
}

function terminalMenuOpen() {
  return !!document.querySelector('.ctx-menu');
}

/// What has the focus as an action starts, to tell later whether it moved.
function terminalFocusOrigin() {
  return document.activeElement;
}

/// The same control, or its twin: the tab strip is rebuilt on every switch,
/// so the chip (or close button) that started it has been replaced by an
/// equal one carrying the same tab id.
function sameFocusControl(a, b) {
  if (a === b) return true;
  const chip = (n) => (n && n.closest ? n.closest('.term-tab') : null);
  const ca = chip(a);
  const cb = chip(b);
  if (!ca || !cb || ca.dataset.tabId !== cb.dataset.tabId) return false;
  const isClose = (n) => !!(n.classList && n.classList.contains('term-tab-close'));
  return isClose(a) === isClose(b);
}

function isTextEntry(n) {
  if (!(n instanceof HTMLElement)) return false;
  if (n.isContentEditable || n instanceof HTMLTextAreaElement || n instanceof HTMLSelectElement) return true;
  return n instanceof HTMLInputElement && !/^(button|checkbox|radio|submit|reset|range|color|file|image)$/i.test(n.type);
}

/// Focus the terminal of `rec`. With `origin` (what had the focus when the
/// action began) this is a deferred focus and checks the user has not moved on.
function terminalFocus(rec, origin) {
  if (!rec || terminalDialogOpen() || terminalMenuOpen()) return;
  if (origin !== undefined) {
    const now = document.activeElement;
    const body = document.getElementById('terminalBody');
    const free = !now || now === document.body || (!!body && body.contains(now));
    if (!free && (isTextEntry(now) || !sameFocusControl(now, origin))) return;
  }
  try { rec.term.focus(); } catch (e) {}
}

function terminalScrollback() {
  const value = parseInt(terminalSetting('terminalScrollback', '5000'), 10);
  if (!Number.isFinite(value)) return 5000;
  return Math.max(1000, Math.min(50000, value));
}

function terminalBellMode() {
  return terminalSetting('terminalBell', 'visual');
}

function terminalHomeEndMode() {
  return terminalSetting('terminalHomeEnd', 'default');
}

function terminalAppCursorKeys() {
  return terminalSetting('terminalAppCursorKeys', 'default');
}

function terminalAppKeypad() {
  return terminalSetting('terminalAppKeypad', 'default');
}

/// Developer diagnostics written into the terminal itself (A5-11): every
/// healthy connect used to open with "[sshspan] ..." lines, one of them saying
/// the IPC Channel was not delivering. Off unless switched on from the
/// developer tools with `window.sshspanTerminalTrace = true`, until the window
/// reloads. A page flag, not a setting: there is no Settings row for it,
/// settings_set takes no such key, and state.settings - where it was read
/// before - is replaced whenever Settings loads, which switched it off again
/// unseen. Failures are not traces: terminalNotice writes them whatever this
/// says.
function terminalDebugTrace() {
  return window.sshspanTerminalTrace === true;
}

// ─── wheel policy (alternate screen) ────────────────────────────────────────
//
// xterm.js converts wheel events into ArrowUp/Down sequences whenever the
// active buffer has no scrollback - always true in the alternate screen that
// full-screen apps switch to. For less/vim that is a useful fallback; for a
// multiplexer like `screen`/`tmux` it is garbage: the arrows are passed to
// the inner program, which echoes them literally (^[[A^[[A... on screen).
// When the remote has NOT enabled mouse reporting we therefore swallow
// plain wheel events in the alternate screen (what Windows Terminal does
// there). With mouse reporting on (screen's `mousetrack on`, vim, htop) the
// wheel reaches the app as real mouse events, untouched.
//
// xterm exposes no accessor for the DEC mouse modes, so they are tracked by
// sniffing the output stream for DECSET/DECRST 1000/1002/1003 (the enable
// modes; 1005/1006/1015 are encodings and irrelevant to the decision).

const MOUSE_MODE_RE = /\x1b\[\?(1000|1002|1003)([hl])/g;

function trackMouseReporting(rec, text) {
  if (typeof text !== 'string' || !text.length) return;
  // A DECSET can straddle output chunks; carry the tail of the previous
  // chunk so the regex still sees the whole sequence.
  const hay = (rec._mouseCarry || '') + text;
  let m;
  let last = null;
  MOUSE_MODE_RE.lastIndex = 0;
  while ((m = MOUSE_MODE_RE.exec(hay))) last = m[2];
  if (last) rec.mouseReporting = last === 'h';
  rec._mouseCarry = hay.slice(-8);
}

function wireTerminalWheelPolicy(rec, host, term) {
  host.addEventListener('wheel', (ev) => {
    // Modified wheels (ctrl-zoom, shift horizontal) are left alone.
    if (ev.ctrlKey || ev.metaKey || ev.altKey || ev.shiftKey) return;
    if (rec.mouseReporting) return;
    let type = 'normal';
    try { type = term.buffer.active.type; } catch (e) {}
    if (type === 'alternate') ev.stopPropagation();
  }, { capture: true, passive: true });
}

// ─── keys ───────────────────────────────────────────────────────────────────

/// Chords the app handles itself, in app.js's document keydown handler: the
/// session surfaces (Ctrl+Shift+1/2/3), maximize/restore (Ctrl+Shift+M) and
/// the assistant (Ctrl+Shift+A). xterm has to leave them alone so they reach
/// it - Ctrl+Shift+2 is Ctrl+@ on a US layout, which xterm turned into a NUL
/// for the shell and swallowed (A2-53). Matched on the physical key.
const TERMINAL_APP_CHORDS = new Set(['Digit1', 'Digit2', 'Digit3', 'KeyM', 'KeyA']);

function isAppChord(event) {
  return (event.ctrlKey || event.metaKey) && event.shiftKey && !event.altKey && TERMINAL_APP_CHORDS.has(event.code);
}

/// Key-compatibility layer for the keyboard settings xterm has no option for.
/// Returns null when every setting is at its default, so nothing is
/// intercepted in the common case. Sequences:
/// - rxvt Home/End: CSI 7~ / CSI 8~ (xterm's own Home/End send CSI H / CSI F
///   or SS3 H / F once the app switches DECCKM on).
/// - cursor keys forced to CSI A-D: what arrow keys send before the remote
///   enables application mode, ignoring DECCKM when the user asked for it.
/// - keypad forced to ASCII: the numeric meaning, ignoring DECNKM.
/// - Backspace as BS (0x08) instead of DEL (0x7f), for a host whose erase
///   character is ^H (xterm sends DEL whatever its options say - A3-26).
/// Each one is SENT to the session (term.input, the keystroke path through
/// onData) - it used to be term.write, which only drew into the local screen,
/// so the keys did nothing on the host (A8-03). preventDefault keeps the
/// browser from also typing into xterm's textarea (and from a keypress).
function buildKeyCompatibilityHandler(term) {
  const rxvtHomeEnd = terminalHomeEndMode() === 'rxvt';
  const cursorKeysOff = terminalAppCursorKeys() === 'disabled';
  const keypadOff = terminalAppKeypad() === 'disabled';
  const backspaceIsBs = terminalSetting('terminalBackspace', 'default') === 'backspace';
  if (!rxvtHomeEnd && !cursorKeysOff && !keypadOff && !backspaceIsBs) return null;
  const CURSOR = { ArrowUp: '\x1b[A', ArrowDown: '\x1b[B', ArrowRight: '\x1b[C', ArrowLeft: '\x1b[D' };
  const KEYPAD = {
    Enter: '\r', '+': '+', '-': '-', '*': '*', '/': '/', '.': '.',
    '0': '0', '1': '1', '2': '2', '3': '3', '4': '4',
    '5': '5', '6': '6', '7': '7', '8': '8', '9': '9',
  };
  const send = (event, seq) => {
    event.preventDefault();
    term.input(seq, true);
    return false;
  };
  return (event) => {
    if (event.type !== 'keydown') return true;
    if (event.ctrlKey || event.altKey || event.metaKey) return true;
    // KeyboardEvent.DOM_KEY_LOCATION_NUMPAD
    if (keypadOff && event.location === 3 && KEYPAD[event.key] !== undefined) return send(event, KEYPAD[event.key]);
    // Shifted keys keep xterm's own modified sequences (CSI 1;2 A and so on).
    if (event.shiftKey) return true;
    if (backspaceIsBs && event.key === 'Backspace') return send(event, '\x08');
    if (rxvtHomeEnd && event.key === 'Home') return send(event, '\x1b[7~');
    if (rxvtHomeEnd && event.key === 'End') return send(event, '\x1b[8~');
    if (cursorKeysOff && CURSOR[event.key]) return send(event, CURSOR[event.key]);
    return true;
  };
}

// Keepalives are handled at the SSH protocol level (russh sends
// keepalive@openssh.com global requests every 30 s); the renderer sends
// nothing over the data channel for it - a NUL byte it once wrote reached
// interactive programs as Ctrl-@.

// Everything typed or pasted reaches the session through one path, the tab's
// onData subscription (terminalConnectInTab): keys, the compatibility
// sequences (term.input) and pastes (terminalPaste, term.paste). The assistant
// types through assistant_type_text, never through the terminal.

function terminalBufferText(rec) {
  if (!rec) return '';
  try {
    const active = rec.term.buffer.active;
    const lines = [];
    for (let i = 0; i < active.length; i++) {
      const line = active.getLine(i);
      if (line) lines.push(line.translateToString(true));
    }
    while (lines.length && !lines[lines.length - 1].trim()) lines.pop();
    return lines.join('\n');
  } catch (e) {
    return '';
  }
}

/// Flag a bell on a BACKGROUND tab so the tab strip can show it.
///
/// Deliberately not named `markTerminalBell`. app.js defines a global of that
/// name and assigns it to `window.markTerminalBell`; every renderer script is
/// a classic <script> sharing one global scope, and terminal.js loads AFTER
/// app.js, so a same-named function declaration here replaced the global -
/// making the `window.markTerminalBell(tabId)` call below call THIS function,
/// recursively, until the stack blew:
///   RangeError: Maximum call stack size exceeded
/// on every bell in a non-active tab.
function notifyBackgroundTabBell(tabId) {
  if (tabId === activeTabId) return;
  if (typeof window.markTerminalBell === 'function') window.markTerminalBell(tabId);
}

function playTerminalBell() {
  try {
    const ctx = window.__sshBellAudio || (window.__sshBellAudio = new (window.AudioContext || window.webkitAudioContext)());
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.type = 'sine';
    osc.frequency.value = 880;
    gain.gain.value = 0.04;
    osc.connect(gain);
    gain.connect(ctx.destination);
    osc.start();
    osc.stop(ctx.currentTime + 0.08);
  } catch (e) {}
}


// copyText lives in app.js and is shared. It used to be duplicated here, and
// because terminal.js loads after app.js in the same global scope, THIS
// version won - a fire-and-forget function returning undefined.
//
// Two consequences, both live until now:
//   * sftp.js does `copyText(x).then(...)` in three places (Copy path, Copy
//     URL). `.then` of undefined threw a TypeError and the menu item did
//     nothing visible.
//   * app.js does `const ok = await copyText(x)`. The clipboard write DID
//     succeed, but `ok` was undefined, so both call sites reported
//     "Clipboard unavailable." on a copy that had worked - the exact symptom
//     reported against 1.7.2 and thought fixed.
//
// app.js's version is the one to keep: it tries the Tauri plugin, falls back
// to the browser API, and returns a boolean the callers actually read.

async function readClipboard() {
  if (tclip) { try { return await tclip.readText(); } catch (e) {} }
  try { return await navigator.clipboard.readText(); } catch (e) { return ''; }
}

function tabRecord(tabId) { return sshTabs.get(tabId) || null; }
function activeTab() { return activeTabId ? sshTabs.get(activeTabId) : null; }

/// A developer trace line (only with terminalDebugTrace on - see above).
function trace(tabId, line) {
  if (!terminalDebugTrace()) return;
  const t = tabRecord(tabId);
  if (t) {
    try { t.term.writeln('\x1b[90m' + line + '\x1b[0m'); } catch (e) {}
  }
}

/// A line from the app (not from the server) in a tab's terminal: why a
/// connect failed, that it was cancelled, that the connection closed. Control
/// characters are taken out - the text can carry what a server sent during
/// the handshake, and that must not drive the terminal.
function terminalNotice(rec, text, color) {
  if (!rec) return;
  const clean = String(text).replace(/[\x00-\x1f\x7f-\x9f]/g, ' ');
  try { rec.term.writeln('\r\n\x1b[' + (color || '1;33') + 'm' + clean + '\x1b[0m'); } catch (e) {}
}

/// The schemes a terminal link may open - the backend's system_open_url
/// allowlist, checked here too so a refused link is said, not just dropped.
const TERMINAL_LINK_SCHEMES = new Set(['http:', 'https:']);

/// How much of an address the question shows: enough to read it, never so
/// much that the site line above it scrolls out of the dialog.
const TERMINAL_LINK_SHOWN = 300;

/// Open a link from terminal output in the system browser - an OSC 8 link
/// (xterm's linkHandler) and a plain URL (the web-links addon) alike - after
/// asking in the app's own dialog (A6-12). An OSC 8 link names
/// its target apart from the text it shows, and a plain one can be long enough
/// to hide where it really goes. The address is parsed once; what is checked,
/// shown and opened all come from that parse. Refused outright, with a reason:
/// a scheme other than http(s), and a user name or password in front of the
/// host - "https://accounts.google.com:signin@evil.tld/" opens evil.tld. Any
/// other link is shown site first, on a line of its own, then the address
/// (cut at 300 characters), and opens through the backend only on OK.
async function terminalOpenLink(uri) {
  let url;
  try { url = new URL(uri); } catch (e) { return; }
  const refuse = (text) => { if (typeof toast === 'function') toast(text, 'warn'); };
  if (!TERMINAL_LINK_SCHEMES.has(url.protocol)) {
    refuse('Only web links (http and https) open from the terminal - not opened.');
    return;
  }
  if (url.username || url.password) {
    refuse('This link hides its real address - not opened.');
    return;
  }
  const href = url.href;
  const shown = href.length > TERMINAL_LINK_SHOWN ? href.slice(0, TERMINAL_LINK_SHOWN) + '…' : href;
  const ok = await confirmModal('Open link?',
    'Site: ' + url.host + '\n\n' + shown + '\n\nA link in this terminal points here. Open it in your browser?',
    'Open link', { danger: false });
  if (!ok) return;
  try {
    await tcore.invoke('system_open_url', { url: href });
  } catch (e) {
    if (typeof toast === 'function') toast(errText(e), 'err');
  }
}

/// What a paste may carry into a session: text, TAB, CR and LF.
/// Every other C0 and C1 control, and DEL, is dropped: an ESC in the clipboard
/// could end bracketed paste early ("ESC[201~", or its 8-bit CSI form) and
/// have the rest of the text run as typed commands, or drive the remote
/// program. The bracket markers go first and whole, so no "[201~" is left.
const PASTE_BRACKET_MARKERS = /\x1b\[20[01]~|\x9b20[01]~/g;
const PASTE_CONTROLS = /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]/g;

function terminalPasteText(text) {
  return String(text).replace(PASTE_BRACKET_MARKERS, '').replace(PASTE_CONTROLS, '');
}

function wireTerminalClipboard(t) {
  try {
    t.onSelectionChange(() => {
      const sel = t.getSelection();
      if (sel) copyText(sel);
    });
  } catch (e) {}
  try {
    // xterm keeps its hidden helper textarea positioned ON the cursor cell
    // (a ~9x17px box, despite the off-screen CSS), so a right-click at the
    // prompt hits it and this fires. Route it through terminalPaste - the
    // multi-line paste confirmation and focus restoration live there, and
    // the raw t.paste() call bypassed both. stopPropagation keeps the same
    // click from ALSO opening the app's terminal context menu, which would
    // double-paste when its Paste item is used.
    t.textarea.addEventListener('contextmenu', (e) => {
      e.preventDefault();
      e.stopPropagation();
      const tabId = t.__sshspanTabId;
      readClipboard().then(text => {
        if (!text) return;
        if (typeof window.terminalPaste === 'function' && tabId) window.terminalPaste(tabId, text);
        else t.paste(terminalPasteText(text));
      });
    });
    t.textarea.addEventListener('keydown', (e) => {
      if (!e.ctrlKey || !e.shiftKey) return;
      const k = e.key.toLowerCase();
      if (k === 'c') { const sel = t.getSelection(); if (sel) { copyText(sel); e.preventDefault(); } }
      else if (k === 'v') {
        e.preventDefault();
        readClipboard().then(txt => {
          if (!txt) return;
          if (typeof window.terminalPaste === 'function' && t.__sshspanTabId) window.terminalPaste(t.__sshspanTabId, txt);
          else t.paste(terminalPasteText(txt));
        });
      }
    });
    // A native paste (Shift+Insert, middle-click on Linux, the Edit menu, IME and
    // voice input; a plain Ctrl+V is ^V to a terminal, xterm sends it as such) is
    // a browser paste event on the helper textarea, and xterm turns it straight
    // into input - it never reached the multi-line review that only the explicit
    // paths (Ctrl+Shift+V, the context menu) had.
    // Take the event over in the capture phase on xterm's own element, ahead of
    // every xterm listener, and hand the text to terminalPaste: one review for
    // every way of pasting. terminalPaste sends through term.paste(), which is
    // not a DOM event - so nothing is sent twice and nothing re-enters here -
    // and which keeps bracketed paste, exactly as the native path did.
    t.element.addEventListener('paste', (e) => {
      e.preventDefault();
      e.stopPropagation();
      e.stopImmediatePropagation();
      const text = e.clipboardData ? e.clipboardData.getData('text/plain') : '';
      const tabId = t.__sshspanTabId;
      if (!text || !tabId) return;
      if (typeof window.terminalPaste === 'function') window.terminalPaste(tabId, text);
      else t.paste(terminalPasteText(text));
    }, true);
  } catch (e) {}
}

// ─── size ───────────────────────────────────────────────────────────────────

/// Fit a terminal to its host and tell the session the new size.
function fitTerminal(rec) {
  if (!rec || !rec.fitAddon || rec.hostEl.style.display === 'none') return;
  try {
    const d = rec.fitAddon.proposeDimensions();
    if (!d || !Number.isFinite(d.cols) || !Number.isFinite(d.rows) || d.cols < 2 || d.rows < 2) return;
    rec.fitAddon.fit();
  } catch (e) { return; }
  sendTerminalSize(rec);
}

/// The fit for a size change, at most once per animation frame: a splitter
/// drag used to send one terminal_resize per frame, mostly the same size
/// again, each a SIGWINCH redraw on the server (A3-34 #4).
function scheduleTerminalFit(rec) {
  if (rec.fitFrame) return;
  rec.fitFrame = requestAnimationFrame(() => {
    rec.fitFrame = 0;
    fitTerminal(rec);
  });
}

/// Tell the session the terminal's size: a live session only, and only when
/// the size changed since it was last told (`force`: a new session).
function sendTerminalSize(rec, force) {
  if (!rec || !rec.sessionId) return;
  const cols = rec.term.cols;
  const rows = rec.term.rows;
  if (!force && rec.sentCols === cols && rec.sentRows === rows) return;
  rec.sentCols = cols;
  rec.sentRows = rows;
  tcore.invoke('terminal_resize', { sessionId: rec.sessionId, cols, rows }).catch(() => {});
}

// ─── tabs ───────────────────────────────────────────────────────────────────

/// Factory: build the tab's xterm instance in its own host <div>.
function createTabTerminal(tabId) {
  if (sshTabs.has(tabId)) return sshTabs.get(tabId);
  const body = document.getElementById('terminalBody');
  if (!body) return null;

  const Terminal = window.Terminal;
  const FitAddonCtor = window.FitAddon && window.FitAddon.FitAddon;
  const WebLinksCtor = window.WebLinksAddon && window.WebLinksAddon.WebLinksAddon;
  if (!Terminal) {
    body.textContent = 'Failed to load xterm.js (window.Terminal is undefined).';
    return null;
  }

  const host = document.createElement('div');
  host.className = 'terminal-host';
  host.id = 'terminalHost-' + tabId;
  host.style.display = 'none';
  body.appendChild(host);

  // No bellStyle (xterm 5 has none - the bell is onBell, below) and no
  // windowsMode: it never changed what Backspace sends and switched reflow off
  // (A3-26); the Backspace setting is the key handler's now.
  const term = new Terminal({
    cursorBlink: true,
    cursorStyle: 'block',
    fontFamily: 'Menlo, Consolas, "DejaVu Sans Mono", monospace',
    fontSize: 13,
    theme: {
      background: '#0f1115',
      foreground: '#e7e9ee',
      cursor: '#34d399',
      cursorAccent: '#0f1115',
      selectionBackground: '#4f8ef7',
      selectionForeground: '#ffffff',
      selectionInactiveBackground: '#1d3252',
    },
    scrollback: terminalScrollback(),
    convertEol: false,
    allowProposedApi: true,
    linkHandler: { activate: (_event, uri) => terminalOpenLink(uri) },
  });

  // One key hook for the terminal's lifetime: the app's chords pass through
  // to app.js, the compatibility settings (read now, so they apply to new
  // terminals) send their sequences, everything else is xterm's.
  const compatHandler = buildKeyCompatibilityHandler(term);
  try {
    term.attachCustomKeyEventHandler((event) => {
      if (isAppChord(event)) return false;
      return compatHandler ? compatHandler(event) : true;
    });
  } catch (e) {}

  let fitAddon = null;
  if (FitAddonCtor) {
    fitAddon = new FitAddonCtor();
    try { term.loadAddon(fitAddon); } catch (e) { fitAddon = null; }
  }
  if (WebLinksCtor) {
    try {
      // Plain URLs in the output: the same question as an OSC 8 link (a long
      // one can hide where it goes), then the backend allowlist
      // (system_open_url accepts http/https only) instead of the addon's
      // default window.open, so a link never hands a non-web scheme to the OS.
      term.loadAddon(new WebLinksCtor((_event, uri) => terminalOpenLink(uri)));
    } catch (e) {}
  }

  term.__sshspanTabId = tabId;
  term.open(host);
  requestAnimationFrame(() => requestAnimationFrame(() => {
    try { fitAddon && fitAddon.fit(); } catch (e) {}
  }));
  wireTerminalClipboard(term);
  // Visual (the default) flashes the tab's chip, sound beeps; either way a
  // background tab keeps a bell marker until it is opened. xterm 5 shows
  // nothing by itself: the bellStyle option this relied on no longer exists.
  // The marker first: it redraws the tab strip, which would drop the flash.
  term.onBell(() => {
    const mode = terminalBellMode();
    if (mode === 'silent') return;
    notifyBackgroundTabBell(tabId);
    if (mode === 'sound') playTerminalBell();
    else if (typeof window.flashTerminalTab === 'function') window.flashTerminalTab(tabId);
  });

  const record = {
    term, fitAddon, hostEl: host,
    sessionId: null, pollHandle: null, dataSub: null,
    attempt: 0, connecting: false, sessionEnded: false,
    closedLineSeen: false, closedLineWritten: false,
    fitFrame: 0, resizeObserver: null,
  };
  sshTabs.set(tabId, record);
  wireTerminalWheelPolicy(record, host, term);

  // Refit when the host's size changes - a window resize, a splitter drag, the
  // tab shown again (display:none -> block).
  const ro = new ResizeObserver(() => {
    if (host.style.display !== 'none') scheduleTerminalFit(record);
  });
  ro.observe(host);
  record.resizeObserver = ro;

  return record;
}

/// Activate a tab: show its host, hide the others, refit, focus.
function showTabTerminal(tabId) {
  activeTabId = tabId;
  for (const [id, rec] of sshTabs) {
    rec.hostEl.style.display = (id === tabId) ? 'block' : 'none';
  }
  const rec = sshTabs.get(tabId);
  if (rec) {
    const origin = terminalFocusOrigin();
    setTimeout(() => {
      fitTerminal(rec);
      if (activeTabId === tabId) terminalFocus(rec, origin);
    }, 60);
  }
}

/// Dispose a tab's terminal and host element. A connect still running for it
/// becomes stale: its session is disconnected when it arrives (A2-12).
function destroyTabTerminal(tabId) {
  const rec = sshTabs.get(tabId);
  if (!rec) return;
  if (rec.pollHandle) clearInterval(rec.pollHandle);
  if (rec.fitFrame) cancelAnimationFrame(rec.fitFrame);
  try { rec.resizeObserver && rec.resizeObserver.disconnect(); } catch (e) {}
  try { rec.dataSub && rec.dataSub.dispose(); } catch (e) {}
  try { rec.term.dispose(); } catch (e) {}
  rec.hostEl.remove();
  sshTabs.delete(tabId);
  if (activeTabId === tabId) {
    activeTabId = sshTabs.keys().next().value || null;
    if (activeTabId) showTabTerminal(activeTabId);
  }
}

function tabSessionLive(tabId) {
  const rec = tabRecord(tabId);
  return !!(rec && rec.sessionId);
}

function setTabSession(tabId, sessionId) {
  const rec = tabRecord(tabId);
  if (rec) rec.sessionId = sessionId;
}

function fitActiveTerminal() {
  fitTerminal(activeTab());
  // No focus() here: this runs on every window resize and UI-scale change,
  // where yanking focus into the terminal would steal keystrokes aimed at a
  // modal or the SFTP path box. Callers that want focus after a refit
  // (tab switch, maximize restore) use fitActiveTerminalAndFocus.
}

/// Refit, then focus - deferred callers pass what had the focus when their
/// action began, so a user who moved on keeps the keyboard.
function fitActiveTerminalAndFocus(origin) {
  fitActiveTerminal();
  terminalFocus(activeTab(), origin);
}

function terminalResetActive() {
  const rec = activeTab();
  if (!rec) return;
  rec.term.reset();
  requestAnimationFrame(() => { try { rec.fitAddon && rec.fitAddon.fit(); } catch (e) {} });
}

function terminalSetStatus(text) {
  const s = document.getElementById('termStrip');
  if (s) s.textContent = text;
}

/// Open the SSH session for a tab. Resolves with the sessionId; rejects with
/// the backend's message spelled out (errSpelled, app.js - it can quote the
/// host), or with CONNECT_ABANDONED when the attempt was closed, cancelled or
/// replaced before it finished.
function terminalConnectInTab(tabId, server, opts) {
  return new Promise(async (resolve, reject) => {
    let rec = tabRecord(tabId);
    if (!rec) rec = createTabTerminal(tabId);
    if (!rec) return reject(new Error('xterm.js unavailable'));
    if (!server || !server.id) return reject(new Error('Server is required.'));

    // One attempt per tab (A3-14): a newer connect on the tab - a restart, a
    // second call - makes this one stale, and a stale attempt's session is
    // disconnected the moment it arrives instead of running beside the new
    // one with nobody owning it.
    const attempt = rec.attempt = (rec.attempt || 0) + 1;
    const current = () => sshTabs.get(tabId) === rec && rec.attempt === attempt;

    // The tab's previous session (a restart on a live tab): its poll,
    // keystroke subscription and backend session go before the id is
    // cleared, or the old poll ended the NEW session's close detection, both
    // subscriptions duplicated every keystroke and the old session lived on.
    if (rec.pollHandle) { clearInterval(rec.pollHandle); rec.pollHandle = null; }
    if (rec.dataSub) { try { rec.dataSub.dispose(); } catch (e) {} rec.dataSub = null; }
    if (rec.sessionId) {
      tcore.invoke('terminal_disconnect', { sessionId: rec.sessionId }).catch(() => {});
    }
    // Fresh session: the previous session's DEC mouse modes do not carry
    // over (the remote app re-enables them if it wants them).
    rec.mouseReporting = false;
    rec._mouseCarry = '';

    const t = rec.term;
    rec.sessionEnded = false;
    rec.sessionId = null;
    rec.connecting = true;
    rec.closedLineSeen = false;
    rec.closedLineWritten = false;
    rec.sentCols = undefined;
    rec.sentRows = undefined;

    // A reconnect keeps what the tab shows - why it died, the last command's
    // output (A3-36). The old session's terminal modes are reset softly (no
    // RIS: that wipes the scrollback): back to the main screen, DECSTR,
    // bracketed paste and mouse reporting off. A line marks where the new
    // session starts.
    if (attempt > 1) {
      try { t.write('\x1b[?1049l\x1b[!p\x1b[?2004l\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l'); } catch (e) {}
      // The host spelled out (spellOut, app.js), as the tab and the status
      // line show it; in the trace, too, it carries no control of its own.
      terminalNotice(rec, `--- reconnecting to ${spellOut(server.host)}:${server.port || 22} ---`, '90');
    }
    trace(tabId, `[sshspan] xterm ready (${t.cols}x${t.rows}) - connecting to ${spellOut(server.host)}:${server.port} (auth=${server.authMethod || 'publickey'})`);
    const origin = terminalFocusOrigin();
    setTimeout(() => { if (current()) terminalFocus(rec, origin); }, 50);

    const onData = new tcore.Channel();
    onData.onmessage = (text) => {
      // A replaced or closed attempt's channel writes nothing more: its last
      // words ("[connection closed]") used to land in the NEW session's
      // terminal after a restart (A3-13).
      if (!current()) return;
      if (typeof text !== 'string' || text.length === 0) return;
      if (text === BACKEND_CLOSED_LINE) {
        if (rec.closedLineWritten) return;
        rec.closedLineSeen = true;
      }
      trackMouseReporting(rec, text);
      try { t.write(text); } catch (e) {}
    };

    // overrideUsername: the backend spends a server's saved password only on
    // the server's own user name, so a caller that connects a password or
    // keyboard-interactive server as another user must ask for the password
    // and pass it as promptPassword. (No caller does today: the only override
    // sent is overrideKeyId, from a key's Connect, which lists key-login
    // servers only.)
    const args = {
      serverId: server.id,
      cols: t.cols || 80,
      rows: t.rows || 24,
      onData: onData,
      overrideUsername: opts && opts.overrideUsername,
      overrideKeyId: opts && opts.overrideKeyId,
      promptPassword: opts && opts.promptPassword,
    };

    // Host-key consent (StrictHostKeyChecking semantics) is owned by the
    // backend: when the host is unpinned - or a backup-imported pin has not
    // been confirmed yet - the Rust handler raises a NATIVE dialog showing
    // the fingerprint before the decision. The renderer deliberately has no
    // consent flag to pass: a compromised page cannot mint trust.

    const encoder = new TextEncoder();
    const dataSub = t.onData(async (data) => {
      if (!rec.sessionId) return;
      try {
        await tcore.invoke('terminal_send', {
          sessionId: rec.sessionId,
          bytes: Array.from(encoder.encode(data)),
        });
      } catch (e) { /* closed channel - close-detection handles teardown */ }
    });
    // Stored on the record so the restart path (top of this function) and
    // destroyTabTerminal can dispose it; previously only this closure held
    // it, so a second connect attached a second subscription that nothing
    // could ever remove.
    rec.dataSub = dataSub;
    const dropSubscription = () => {
      try { dataSub.dispose(); } catch (e) {}
      if (rec.dataSub === dataSub) rec.dataSub = null;
    };

    const teardown = (sid) => {
      if (rec.sessionEnded || rec.sessionId !== sid) return;
      rec.sessionEnded = true;
      rec.sessionId = null;
      if (rec.pollHandle) { clearInterval(rec.pollHandle); rec.pollHandle = null; }
      dropSubscription();
      // The backend says it on the channel as the session ends; only when
      // that line never came does the tab say it itself.
      if (!rec.closedLineSeen) {
        rec.closedLineWritten = true;
        terminalNotice(rec, '[connection closed]');
      }
      if (typeof window.onSessionClosed === 'function') window.onSessionClosed(tabId);
    };

    try {
      const r = await tcore.invoke('terminal_connect', args);
      if (!r || !r.ok || !r.sessionId) {
        throw new Error((r && r.error) || 'No session id returned.');
      }
      const sessionId = r.sessionId;
      if (!current()) {
        // Its tab closed, the connect was cancelled or a newer one started
        // while this one ran (A2-12 / A3-14): nobody owns this session. End it
        // rather than leave an authenticated shell open on the server.
        tcore.invoke('terminal_disconnect', { sessionId }).catch(() => {});
        dropSubscription();
        reject(new Error(CONNECT_ABANDONED));
        return;
      }
      rec.connecting = false;
      rec.sessionId = sessionId;
      trace(tabId, `[sshspan] session established (id=${sessionId.slice(0, 8)}...)`);
      sendTerminalSize(rec, true);

      // Close detection via the backend's session registry. Each attempt's
      // poll clears only its own interval: a stale one used to clear the
      // current one's, and that session's end was never noticed (A3-14).
      const handle = setInterval(async () => {
        if (rec.sessionEnded || rec.sessionId !== sessionId) {
          clearInterval(handle);
          if (rec.pollHandle === handle) rec.pollHandle = null;
          return;
        }
        try {
          const res = await tcore.invoke('terminal_list', {});
          const stillThere = (res.active || []).some(s => s.sessionId === sessionId);
          if (!stillThere) teardown(sessionId);
        } catch (e) { teardown(sessionId); }
      }, 1200);
      rec.pollHandle = handle;

      resolve(sessionId);
    } catch (e) {
      dropSubscription();
      const msg = errSpelled(e);
      if (!current()) { reject(new Error(CONNECT_ABANDONED)); return; }
      rec.connecting = false;
      rec.sessionEnded = true;
      rec.sessionId = null;
      // The backend's own words, spelled out (they can quote the host): a
      // host-key mismatch, a declined key, a timeout - the tab is dead and
      // says why.
      terminalNotice(rec, msg, '1;31');
      reject(new Error(msg));
    }
  });
}

/// Give up on the tab's connect in flight (A5-10). The backend cannot abort a
/// handshake, so the attempt is made stale: its session is disconnected when
/// it arrives. The tab is done with it now.
function terminalCancelConnect(tabId) {
  const rec = tabRecord(tabId);
  if (!rec || !rec.connecting) return false;
  rec.attempt = (rec.attempt || 0) + 1;
  rec.connecting = false;
  rec.sessionEnded = true;
  if (rec.dataSub) { try { rec.dataSub.dispose(); } catch (e) {} rec.dataSub = null; }
  terminalNotice(rec, '[connection cancelled]');
  return true;
}

// Window resize refits the ACTIVE tab.
window.addEventListener('resize', () => {
  clearTimeout(window.__sshRefitTimer);
  window.__sshRefitTimer = setTimeout(fitActiveTerminal, 120);
});

window.createTabTerminal = createTabTerminal;
window.showTabTerminal = showTabTerminal;
window.destroyTabTerminal = destroyTabTerminal;
window.tabSessionLive = tabSessionLive;
window.setTabSession = setTabSession;
window.fitActiveTerminal = fitActiveTerminal;
window.fitActiveTerminalAndFocus = fitActiveTerminalAndFocus;
window.terminalResetActive = terminalResetActive;
window.terminalSetStatus = terminalSetStatus;
window.tabRecord = tabRecord;
window.terminalConnectInTab = terminalConnectInTab;
window.terminalCancelConnect = terminalCancelConnect;
window.terminalFocusTab = (tabId) => terminalFocus(tabRecord(tabId));
window.terminalCopySelection = (tabId) => {
  const rec = tabRecord(tabId);
  if (!rec) return false;
  const text = rec.term.getSelection();
  if (text) copyText(text);
  return !!text;
};
window.terminalCopyAll = (tabId) => {
  const text = terminalBufferText(tabRecord(tabId));
  if (text) copyText(text);
  return !!text;
};
window.terminalClearScrollback = (tabId) => {
  const rec = tabRecord(tabId);
  if (rec) rec.term.clear();
};
window.terminalReset = (tabId) => {
  const rec = tabRecord(tabId);
  if (!rec) return;
  rec.term.reset();
  // reset() clears every DEC mode in xterm, including mouse reporting; drop
  // the sniffed flag so the wheel policy does not assume mouse mode.
  rec.mouseReporting = false;
  rec._mouseCarry = '';
  setTimeout(() => { try { rec.fitAddon && rec.fitAddon.fit(); } catch (e) {} }, 30);
};
/// The one way text gets pasted into a session: the context menu, Ctrl+Shift+V
/// and a native paste (Shift+Insert, middle-click, ...) all end up here. Control
/// characters are taken out first (terminalPasteText: TAB, CR and LF stay).
/// Multi-line text is reviewed first - a pasted newline runs the line - in the
/// app's own dialog (the native confirm() is not usable, see confirmModal in
/// app.js). Resolves true when the text was sent.
window.terminalPaste = async (tabId, raw) => {
  const rec = tabRecord(tabId);
  if (typeof raw !== 'string' || !raw) return false;
  if (!rec || !rec.sessionId) return false;
  const text = terminalPasteText(raw);
  if (!text) return false;
  // Paste paths that leave the terminal (the context menu, the review dialog)
  // drop focus to <body>; the next keystroke goes nowhere and the terminal
  // looks dead until clicked. Hand focus back so typing works whether or not
  // the paste lands.
  terminalFocus(rec);
  const needsConfirm = terminalSetting('confirmMultiLinePaste', '1') !== '0';
  if (needsConfirm && (text.includes('\n') || text.includes('\r'))) {
    const lines = text.split(/\r\n|\r|\n/).length;
    const ok = await confirmModal('Paste several lines?',
      `Paste ${lines} lines into this SSH session? Review clipboard content before running commands.`,
      'Paste', { danger: false });
    if (!ok) { terminalFocus(rec); return false; }
    // The dialog is modal, not frozen: the session can end, be replaced by a
    // reconnect, or be torn down by a vault lock while it is open.
    if (tabRecord(tabId) !== rec || !rec.sessionId) return false;
    terminalFocus(rec);
  }
  // xterm's own paste: newlines become CR and bracketed paste mode is honoured
  // when the remote asked for it, exactly like a native paste. The text reaches
  // the session through the onData subscription (terminal_send), once.
  rec.term.paste(text);
  return true;
};
window.terminalReadClipboard = readClipboard;
window.terminalApplySettings = () => {
  const scrollback = terminalScrollback();
  for (const rec of sshTabs.values()) {
    try { rec.term.options.scrollback = scrollback; } catch (e) {}
  }
};
// Introspection hook for the keyboard-compatibility settings; the values are
// read per terminal at creation, by buildKeyCompatibilityHandler.
window.terminalModeSettings = () => ({
  backspace: terminalSetting('terminalBackspace', 'default'),
  homeEnd: terminalHomeEndMode(),
  appCursorKeys: terminalAppCursorKeys(),
  appKeypad: terminalAppKeypad(),
});
