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
 *   connectInTab(tabId, srv, opts)- open the SSH session for that tab
 *   setTabSession(tabId, sid)     - record the live session id on the tab
 *   tabSessionLive(tabId)         - is the tab's SSH session open?
 *   fitActiveTerminal()           - refit the active tab (resize/maximize)
 *   terminalResetActive()         - clear the active terminal
 *   terminalSetStatus(text)       - bottom status strip (global)
 *   session end calls window.onSessionClosed(tabId) (implemented in app.js).
 */

'use strict';

// Boot marker: app.js checks this at startup (see main()).
window.__SSHPAN_TERMINAL_JS__ = 'loaded-v14-tabs';

// app.js already declares top-level `const invoke` in the shared classic-
// script global scope - re-declaring it here is a SyntaxError that kills the
// whole file. Namespace everything.
const tcore = window.__TAURI__.core;
const tclip = (window.__TAURI__ && window.__TAURI__.clipboardManager) || null;

const sshTabs = new Map();   // tabId -> {term, fitAddon, hostEl, sessionId, pollHandle, dataSub, sessionEnded, gotFirstData}
let activeTabId = null;

function terminalSetting(name, fallback) {
  const settings = window.state && window.state.settings ? window.state.settings : {};
  const value = settings[name];
  return value === undefined || value === null || value === '' ? fallback : value;
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

/// Key-compatibility layer for the three keyboard settings that were
/// previously persisted but never applied. Returns null when every setting
/// is at its default, so nothing is intercepted in the common case.
/// Sequences:
/// - rxvt Home/End: CSI 7~ / CSI 8~ (xterm's own Home/End send CSI H / CSI F
///   or SS3 H / F once the app switches DECCKM on).
/// - cursor keys forced to CSI A-D: what arrow keys send before the remote
///   enables application mode, ignoring DECCKM when the user asked for it.
/// - keypad forced to ASCII: the numeric meaning, ignoring DECNKM.
function buildKeyCompatibilityHandler(term) {
  const rxvtHomeEnd = terminalHomeEndMode() === 'rxvt';
  const cursorKeysOff = terminalAppCursorKeys() === 'disabled';
  const keypadOff = terminalAppKeypad() === 'disabled';
  if (!rxvtHomeEnd && !cursorKeysOff && !keypadOff) return null;
  const CURSOR = { ArrowUp: '\x1b[A', ArrowDown: '\x1b[B', ArrowRight: '\x1b[C', ArrowLeft: '\x1b[D' };
  const KEYPAD = {
    Enter: '\r', '+': '+', '-': '-', '*': '*', '/': '/', '.': '.',
    '0': '0', '1': '1', '2': '2', '3': '3', '4': '4',
    '5': '5', '6': '6', '7': '7', '8': '8', '9': '9',
  };
  return (event) => {
    if (event.type !== 'keydown') return true;
    if (event.ctrlKey || event.altKey || event.metaKey) return true;
    if (rxvtHomeEnd) {
      if (event.key === 'Home') { term.write('\x1b[7~'); return false; }
      if (event.key === 'End') { term.write('\x1b[8~'); return false; }
    }
    if (cursorKeysOff && CURSOR[event.key]) { term.write(CURSOR[event.key]); return false; }
    // KeyboardEvent.DOM_KEY_LOCATION_NUMPAD
    if (keypadOff && event.location === 3 && KEYPAD[event.key] !== undefined) {
      term.write(KEYPAD[event.key]);
      return false;
    }
    return true;
  };
}

// (terminalKeepaliveSeconds removed: keepalives are SSH-protocol-level now -
// see startTabKeepalive. The terminalKeepaliveSeconds setting remains stored
// but has no effect.)

function sendTerminalBytes(rec, data) {
  if (!rec || !rec.sessionId) return Promise.resolve(false);
  const encoder = new TextEncoder();
  return tcore.invoke('terminal_send', {
    sessionId: rec.sessionId,
    bytes: Array.from(encoder.encode(data)),
  }).then(() => true).catch(() => false);
}

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

function trace(tabId, line) {
  const t = tabRecord(tabId);
  if (t) {
    try { t.term.writeln('\x1b[90m' + line + '\x1b[0m'); } catch (e) {}
  }
  if (tabId === activeTabId) {
    const s = document.getElementById('termStrip');
    if (s) s.textContent = line.replace(/\x1b\[[0-9;]*m/g, '');
  }
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
        else t.paste(text);
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
          else t.paste(txt);
        });
      }
    });
  } catch (e) {}
}

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
    windowsMode: terminalSetting('terminalBackspace', 'default') === 'backspace',
    // 'visual' lets xterm flash the ACTIVE tab's terminal; 'sound'/'silent'
    // are produced by the app itself (WebAudio beep / nothing) in onBell.
    bellStyle: terminalBellMode() === 'visual' ? 'visual' : 'none',
  });

  // The keyboard-compatibility settings (rxvt Home/End, application cursor
  // keys, application keypad) are enforced here, at creation - xterm has no
  // runtime option for rewriting what a key sends, only this hook. Each
  // branch writes the compatibility sequence and returns false so xterm does
  // not also emit its own.
  const compatHandler = buildKeyCompatibilityHandler(term);
  if (compatHandler) {
    try { term.attachCustomKeyEventHandler(compatHandler); } catch (e) {}
  }

  let fitAddon = null;
  if (FitAddonCtor) {
    fitAddon = new FitAddonCtor();
    try { term.loadAddon(fitAddon); } catch (e) { fitAddon = null; }
  }
  if (WebLinksCtor) {
    try {
      // Route clicks through the backend allowlist (system_open_url accepts
      // http/https only) instead of the addon's default window.open, so a
      // terminal link can never hand a non-web scheme to the OS shell. The
      // addon regex itself only linkifies http(s), this is defense in depth.
      term.loadAddon(new WebLinksCtor((_event, uri) => {
        tcore.invoke('system_open_url', { url: uri })
          .catch((e) => console.warn('[sshspan-terminal] link open refused:', e));
      }));
    } catch (e) {}
  }

  term.__sshspanTabId = tabId;
  term.open(host);
  requestAnimationFrame(() => requestAnimationFrame(() => {
    try { fitAddon && fitAddon.fit(); } catch (e) {}
  }));
  wireTerminalClipboard(term);
  term.onBell(() => {
    const mode = terminalBellMode();
    if (mode === 'silent') return;
    notifyBackgroundTabBell(tabId);
    if (mode === 'sound') playTerminalBell();
  });

  const record = {
    term, fitAddon, hostEl: host,
    sessionId: null, pollHandle: null, dataSub: null, keepaliveHandle: null,
    sessionEnded: false, gotFirstData: false,
  };
  sshTabs.set(tabId, record);
  wireTerminalWheelPolicy(record, host, term);

  // Refit the tab when it becomes visible again (display:none -> block).
  const ro = new ResizeObserver(() => {
    if (host.style.display === 'none') return;
    try {
      const d = fitAddon && fitAddon.proposeDimensions();
      if (d && Number.isFinite(d.cols) && Number.isFinite(d.rows) && d.cols >= 2 && d.rows >= 2) {
        fitAddon.fit();
        if (record.sessionId) {
          tcore.invoke('terminal_resize', { sessionId: record.sessionId, cols: term.cols, rows: term.rows })
            .catch(() => {});
        }
      }
    } catch (e) {}
  });
  ro.observe(host);

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
    setTimeout(() => {
      try { rec.fitAddon && rec.fitAddon.fit(); } catch (e) {}
      try { rec.term.focus(); } catch (e) {}
    }, 60);
  }
}

/// Dispose a tab's terminal and host element.
function destroyTabTerminal(tabId) {
  const rec = sshTabs.get(tabId);
  if (!rec) return;
  if (rec.pollHandle) clearInterval(rec.pollHandle);
  if (rec.keepaliveHandle) clearInterval(rec.keepaliveHandle);
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

// Keepalives are handled at the SSH protocol level (russh sends
// keepalive@openssh.com global requests every 30 s). This used to write a
// NUL byte into the PTY - interactive programs received it as Ctrl-@ - so
// the renderer no longer pings the data channel at all.
function startTabKeepalive(rec) {
  if (rec && rec.keepaliveHandle) {
    clearInterval(rec.keepaliveHandle);
    rec.keepaliveHandle = null;
  }
}

function fitActiveTerminal() {
  const rec = activeTab();
  if (!rec || !rec.fitAddon) return;
  try {
    const d = rec.fitAddon.proposeDimensions();
    if (d && Number.isFinite(d.cols) && Number.isFinite(d.rows) && d.cols >= 2 && d.rows >= 2) {
      rec.fitAddon.fit();
      if (rec.sessionId) {
        tcore.invoke('terminal_resize', { sessionId: rec.sessionId, cols: rec.term.cols, rows: rec.term.rows })
          .catch(() => {});
      }
    }
  } catch (e) {}
  // No focus() here: this runs on every window resize and UI-scale change,
  // where yanking focus into the terminal would steal keystrokes aimed at a
  // modal or the SFTP path box. Callers that want focus after a refit
  // (tab switch, maximize restore) use fitActiveTerminalAndFocus.
}

function fitActiveTerminalAndFocus() {
  fitActiveTerminal();
  const rec = activeTab();
  if (rec) { try { rec.term.focus(); } catch (e) {} }
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

/// Open the SSH session for a tab. Resolves with the sessionId.
function terminalConnectInTab(tabId, server, opts) {
  return new Promise(async (resolve, reject) => {
    let rec = tabRecord(tabId);
    if (!rec) rec = createTabTerminal(tabId);
    if (!rec) return reject(new Error('xterm.js unavailable'));
    if (!server || !server.id) return reject(new Error('Server is required.'));

    // Restart-on-a-live-tab: tear down the previous connect's poll interval,
    // keystroke subscription, and backend session BEFORE nulling the
    // session id. Without this, the old poll's closure killed the NEW
    // handle (no close detection afterwards), both onData subscriptions
    // stayed live and duplicated every keystroke, and the old SSH session
    // was never disconnected.
    if (rec.pollHandle) { clearInterval(rec.pollHandle); rec.pollHandle = null; }
    if (rec.dataSub) { try { rec.dataSub.dispose(); } catch (e) {} rec.dataSub = null; }
    if (rec.sessionId) {
      const oldSession = rec.sessionId;
      tcore.invoke('terminal_disconnect', { sessionId: oldSession }).catch(() => {});
    }
    if (rec.keepaliveHandle) { clearInterval(rec.keepaliveHandle); rec.keepaliveHandle = null; }
    // Fresh session: the previous session's DEC mouse modes do not carry
    // over (the remote app re-enables them if it wants them).
    rec.mouseReporting = false;
    rec._mouseCarry = '';

    const t = rec.term;
    rec.sessionEnded = false;
    rec.gotFirstData = false;
    rec.sessionId = null;

    try { t.reset(); } catch (e) {}
    trace(tabId, `[sshspan] xterm ready (${t.cols}x${t.rows}) - connecting to ${server.host}:${server.port} (auth=${server.authMethod || 'publickey'})`);
    setTimeout(() => { try { t.focus(); } catch (e) {} }, 50);

    const onData = new tcore.Channel();
    onData.onmessage = (text) => {
      if (typeof text !== 'string' || text.length === 0) return;
      if (!rec.gotFirstData) {
        rec.gotFirstData = true;
        if (tabId === activeTabId) terminalSetStatus(`Connected to ${server.host}:${server.port} - streaming`);
      }
      trackMouseReporting(rec, text);
      try { t.write(text); } catch (e) {}
    };

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

    const teardown = (sid) => {
      if (rec.sessionEnded || rec.sessionId !== sid) return;
      rec.sessionEnded = true;
      rec.sessionId = null;
      if (rec.pollHandle) { clearInterval(rec.pollHandle); rec.pollHandle = null; }
      if (rec.keepaliveHandle) { clearInterval(rec.keepaliveHandle); rec.keepaliveHandle = null; }
      try { dataSub.dispose(); } catch (e) {}
      try { t.writeln('\r\n\x1b[1;33m[connection closed]\x1b[0m'); } catch (e) {}
      if (typeof window.onSessionClosed === 'function') window.onSessionClosed(tabId);
    };

    try {
      const r = await tcore.invoke('terminal_connect', args);
      if (!r || !r.ok || !r.sessionId) {
        throw new Error((r && r.error) || 'No session id returned.');
      }
      const sessionId = r.sessionId;
      rec.sessionId = sessionId;
      rec.tabId = tabId;
      startTabKeepalive(rec);
      trace(tabId, `[sshspan] session established (id=${sessionId.slice(0, 8)}...) - waiting for remote output`);
      if (!rec.gotFirstData) {
        trace(tabId, '[sshspan] NOTE: no channel data yet. If this is the last line you see, the IPC Channel is not delivering.');
      }

      try {
        await tcore.invoke('terminal_resize', { sessionId, cols: t.cols, rows: t.rows });
      } catch (e) {}

      // Close detection via registry content per tab.
      rec.pollHandle = setInterval(async () => {
        if (rec.sessionEnded || rec.sessionId !== sessionId) {
          clearInterval(rec.pollHandle);
          rec.pollHandle = null;
          return;
        }
        try {
          const res = await tcore.invoke('terminal_list', {});
          const stillThere = (res.active || []).some(s => s.sessionId === sessionId);
          if (!stillThere) teardown(sessionId);
        } catch (e) { teardown(sessionId); }
      }, 1200);

      resolve(sessionId);
    } catch (e) {
      rec.sessionEnded = true;
      rec.sessionId = null;
      try { dataSub.dispose(); } catch (e2) {}
      const msg = e && e.message ? e.message : String(e);
      trace(tabId, `[sshspan] CONNECT FAILED: ${msg}`);
      reject(new Error(msg));
    }
  });
}

// Window resize refits the ACTIVE tab.
window.addEventListener('resize', () => {
  clearTimeout(window.__sshRefitTimer);
  window.__sshRefitTimer = setTimeout(fitActiveTerminal, 120);
});

window.initTerminal = function () {}; // lazy: tabs build on demand
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
window.terminalSendText = (tabId, text) => sendTerminalBytes(tabRecord(tabId), text);
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
window.terminalPaste = async (tabId, text) => {
  // Paste paths that leave the terminal (context menu click, confirm()
  // dialog) drop focus to <body>; the next keystroke goes nowhere and the
  // terminal looks dead until clicked. Hand focus back first so typing
  // works whether or not the paste lands.
  const rec = tabRecord(tabId);
  try { rec && rec.term.focus(); } catch (e) {}
  if (typeof text !== 'string' || !text) return false;
  const needsConfirm = terminalSetting('confirmMultiLinePaste', '1') !== '0';
  if (needsConfirm && (text.includes('\n') || text.includes('\r'))) {
    const lines = text.split(/\r\n|\r|\n/).length;
    if (!window.confirm(`Paste ${lines} lines into this SSH session? Review clipboard content before running commands.`)) return false;
    try { rec && rec.term.focus(); } catch (e) {}
  }
  return sendTerminalBytes(rec, text);
};
window.terminalReadClipboard = readClipboard;
window.terminalApplySettings = () => {
  const scrollback = terminalScrollback();
  const bellStyle = terminalBellMode() === 'visual' ? 'visual' : 'none';
  for (const rec of sshTabs.values()) {
    try { rec.term.options.scrollback = scrollback; } catch (e) {}
    try { rec.term.options.bellStyle = bellStyle; } catch (e) {}
  }
};
// Introspection hook for the keyboard-compatibility settings; the values are
// enforced per-terminal at creation via buildKeyCompatibilityHandler.
window.terminalModeSettings = () => ({
  backspace: terminalSetting('terminalBackspace', 'default'),
  homeEnd: terminalHomeEndMode(),
  appCursorKeys: terminalAppCursorKeys(),
  appKeypad: terminalAppKeypad(),
});
