/**
 * terminal.js — xterm.js wrapper for the Connect view.
 * ---------------------------------------------------------------------------
 * Loaded after `vendor/xterm.js`, `vendor/addon-fit.js`, `vendor/addon-web-links.js`,
 * which expose globals `Terminal`, `FitAddon.FitAddon`, `WebLinksAddon.WebLinksAddon`
 * (their UMD wrappers attach to globalThis).
 *
 * Public functions (called from app.js):
 *   initTerminal()               - called once at boot (deferred until visible)
 *   ensureTerminalForSession()   - called when a session is starting; open +
 *                                   fit the terminal in its now-visible host.
 *   terminalReset()              - clear screen before a new session
 *   terminalSetStatus(text)      - write to the bottom status strip
 *   terminalConnect(server, opts) - opens the russh session; returns sessionId.
 *
 * The Rust side hands us a `tauri::ipc::Channel<String>` that streams
 * server-rendered terminal output. We feed each line to term.write().
 */

'use strict';

const { invoke, Channel: TauriChannelCtor } = window.__TAURI__.core;
const Channel = TauriChannelCtor;

let term = null;
let fitAddon = null;
let webLinksAddon = null;
let resizeObserver = null;
let sessionEndedFlag = false;
let currentSessionId = null;

function findVendorGlobal(...names) {
  for (const n of names) {
    if (window[n]) return window[n];
    if (window.FitAddon && window.FitAddon.FitAddon && n === 'FitAddon') return window.FitAddon.FitAddon;
    if (window.WebLinksAddon && window.WebLinksAddon.WebLinksAddon && n === 'WebLinksAddon') return window.WebLinksAddon.WebLinksAddon;
  }
  return null;
}

function buildTerminal() {
  if (term) return term;
  const host = document.getElementById('terminalHost');
  if (!host) return null;
  // The host div is inside `.terminal-col` which starts hidden. xterm.js
  // measures on `open()` so we must only build the terminal when the view
  // has been switched to. The host may also have zero size at first paint
  // even after unhide, so we set explicit minimums and use FitAddon only
  // after the first frame is laid out.
  host.style.minHeight = '240px';

  const Terminal = window.Terminal;
  const FitAddon = findVendorGlobal('FitAddon');
  const WebLinksAddon = findVendorGlobal('WebLinksAddon');

  if (!Terminal) {
    host.textContent = 'Failed to load xterm.js (Terminal is undefined). The vendor bundle may be missing.';
    return null;
  }

  term = new Terminal({
    cursorBlink: true,
    fontFamily: 'Menlo, Consolas, "DejaVu Sans Mono", monospace',
    fontSize: 13,
    theme: {
      background: '#0f1115',
      foreground: '#e7e9ee',
      cursor: '#ffffff',
      selectionBackground: '#3b82f640',
    },
    scrollback: 5000,
    convertEol: false,
    allowProposedApi: true,
  });

  if (FitAddon) {
    fitAddon = new FitAddon();
    try { term.loadAddon(fitAddon); } catch (e) { /* addon missing — non-fatal */ }
  }
  if (WebLinksAddon) {
    webLinksAddon = new WebLinksAddon();
    try { term.loadAddon(webLinksAddon); } catch (e) { /* addon missing — non-fatal */ }
  }

  term.open(host);
  // First fit on the next tick so width/height are settled.
  requestAnimationFrame(() => {
    try { fitAddon && fitAddon.fit(); } catch (e) {}
  });

  // ResizeObserver: only run while a session is active to avoid sending
  // resize events with NaN/uninitialized dimensions before connect.
  resizeObserver = new ResizeObserver(() => {
    if (!fitAddon || !term) return;
    try {
      const proposed = fitAddon.proposeDimensions();
      if (proposed && !isNaN(proposed.cols) && !isNaN(proposed.rows)
          && proposed.cols >= 2 && proposed.rows >= 1) {
        fitAddon.fit();
        if (currentSessionId) {
          invoke('terminal_resize', {
            sessionId: currentSessionId,
            cols: term.cols,
            rows: term.rows,
          }).catch(() => {});
        }
      }
    } catch (e) {}
  });
  resizeObserver.observe(host);

  return term;
}

function ensureTerminalForSession() {
  return buildTerminal();
}

function initTerminal() {
  // No-op until a session is starting. Building xterm on a hidden element
  // throws because of zero-dimension measurements; we wait for the user to
  // actually open the Connect view (handled by switchView in app.js, which
  // calls ensureTerminalForSession lazily on the first connect).
}

function terminalReset() {
  const t = buildTerminal();
  if (!t) return;
  t.reset();
  requestAnimationFrame(() => {
    try { fitAddon && fitAddon.fit(); } catch (e) {}
  });
}

function terminalSetStatus(text) {
  const s = document.getElementById('termStrip');
  if (s) s.textContent = text;
}

function terminalConnect(server, opts) {
  return new Promise(async (resolve, reject) => {
    const t = buildTerminal();
    if (!t) return reject(new Error('xterm.js unavailable'));
    if (!server || !server.id) return reject(new Error('Server is required.'));

    sessionEndedFlag = false;
    currentSessionId = null;

    terminalReset();
    // Focus the terminal so it receives keystrokes.
    setTimeout(() => { try { t.focus(); } catch (e) {} }, 50);

    // Tauri v2 Channel: this is a structured IPC channel. Each .send() from
    // Rust triggers onmessage on the JS side. We pass it directly to invoke().
    const onData = new Channel();
    onData.onmessage = (text) => {
      if (typeof text !== 'string') return;
      // text may include ANSI sequences; xterm.js parses them.
      try { t.write(text); } catch (e) {}
    };

    // Tauri command arg naming: Rust side is `onData` (camelCase). The
    // payload key MUST match what Tauri expects, which by default is the
    // camelCase form of the Rust parameter name.
    const args = {
      serverId: server.id,
      cols: t.cols || 80,
      rows: t.rows || 24,
      onData: onData,
      overrideUsername: opts && opts.overrideUsername,
      overrideKeyId: opts && opts.overrideKeyId,
      overridePemPath: opts && opts.overridePemPath,
      promptPassword: opts && opts.promptPassword,
    };

    // Send keystrokes as raw bytes to the SSH session.
    const dataSub = t.onData(async (data) => {
      if (!currentSessionId) return;
      try {
        const bytes = Array.from(data).map(c => c.charCodeAt(0) & 0xff);
        await invoke('terminal_send', {
          sessionId: currentSessionId,
          bytes,
        });
      } catch (e) {
        // Channel may have closed; let the close-detection below tear us down.
      }
    });

    try {
      const r = await invoke('terminal_connect', args);
      if (!r || !r.ok || !r.sessionId) {
        const errMsg = (r && r.error) || 'No session id returned.';
        throw new Error(errMsg);
      }
      const sessionId = r.sessionId;
      currentSessionId = sessionId;
      sessionEndedFlag = false;

      // Push the actual size now that we have a live session.
      try {
        await invoke('terminal_resize', {
          sessionId, cols: t.cols, rows: t.rows,
        });
      } catch (e) {}

      // Close detection: when a send fails because the channel has been
      // dropped on the Rust side, mark the session as ended. This is more
      // reliable than a polling probe and reacts within milliseconds of
      // either side hanging up.
      let pollHandle = null;
      const startCloseDetection = () => {
        pollHandle = setInterval(async () => {
          if (sessionEndedFlag || currentSessionId !== sessionId) {
            clearInterval(pollHandle);
            return;
          }
          try {
            await invoke('terminal_list', {});
          } catch (e) {
            clearInterval(pollHandle);
            if (!sessionEndedFlag) doClose(sessionId);
          }
        }, 1500);
      };

      const doClose = (sid) => {
        if (sessionEndedFlag || currentSessionId !== sid) return;
        sessionEndedFlag = true;
        currentSessionId = null;
        try { dataSub.dispose(); } catch (e) {}
        try { t.writeln('\r\n\x1b[1;33m[connection closed]\x1b[0m'); } catch (e) {}
        if (typeof window.onTerminalClosed === 'function') window.onTerminalClosed();
      };

      // Initial size send might race; trigger after a small delay so the
      // server-side PTY matches what xterm reports.
      setTimeout(() => {
        try {
          invoke('terminal_resize', {
            sessionId, cols: t.cols, rows: t.rows,
          }).catch(() => {});
        } catch (e) {}
        startCloseDetection();
      }, 50);

      resolve(sessionId);
    } catch (e) {
      try { dataSub.dispose(); } catch (e2) {}
      currentSessionId = null;
      const msg = e && e.message ? e.message : String(e);
      try { t.writeln('\r\n\x1b[1;31m[connection failed: ' + msg + ']\x1b[0m'); } catch (e3) {}
      reject(new Error(msg));
    }
  });
}

window.initTerminal = initTerminal;
window.ensureTerminalForSession = ensureTerminalForSession;
window.terminalReset = terminalReset;
window.terminalSetStatus = terminalSetStatus;
window.terminalConnect = terminalConnect;