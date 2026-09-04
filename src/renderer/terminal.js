/**
 * terminal.js — xterm.js wrapper for the Connect view.
 * ---------------------------------------------------------------------------
 * Loaded after `vendor/xterm.js`, `vendor/addon-fit.js`, `vendor/addon-web-links.js`,
 * which expose globals `Terminal`, `FitAddon.FitAddon`, `WebLinksAddon.WebLinksAddon`
 * (their UMD wrappers attach to globalThis).
 *
 * Public functions (called from app.js):
 *   initTerminal()               - called once at boot
 *   terminalReset(bannerText)    - clear screen, optional first line
 *   terminalSetStatus(text)      - write to the bottom status strip
 *   terminalConnect(server, opts) - returns a Promise<string sessionId>;
 *                                   sets up the on_data channel and the
 *                                   keystroke/resize flows.
 *
 * The Rust side hands us a `tauri::ipc::Channel<String>` that streams
 * server-rendered terminal output. We feed each line to term.write().
 */

'use strict';

const { invoke, Channel } = window.__TAURI__.core;

let term = null;
let fitAddon = null;
let resizeObserver = null;

function ensureTerminal() {
  if (term) return term;
  const host = document.getElementById('terminalHost');
  if (!host) return null;

  // xterm.js v5 globals from the vendored UMD bundles.
  const Terminal = window.Terminal;
  const FitAddon = window.FitAddon && window.FitAddon.FitAddon;
  const WebLinksAddon = window.WebLinksAddon && window.WebLinksAddon.WebLinksAddon;

  if (!Terminal) {
    host.textContent = 'Failed to load xterm.js (Terminal is undefined).';
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
    term.loadAddon(fitAddon);
  }
  if (WebLinksAddon) {
    term.loadAddon(new WebLinksAddon());
  }

  term.open(host);
  // Initial fit on the next tick (DOM measurements).
  setTimeout(() => { try { fitAddon && fitAddon.fit(); } catch (e) {} }, 0);

  resizeObserver = new ResizeObserver(() => {
    if (!fitAddon || !term) return;
    try {
      fitAddon.fit();
      if (window.__sshspanActiveSession) {
        invoke('terminal_resize', {
          sessionId: window.__sshspanActiveSession,
          cols: term.cols,
          rows: term.rows,
        }).catch(() => {});
      }
    } catch (e) {}
  });
  resizeObserver.observe(host);

  return term;
}

function initTerminal() {
  ensureTerminal();
}

function terminalReset(bannerText) {
  const t = ensureTerminal();
  if (!t) return;
  t.reset();
  setTimeout(() => { try { fitAddon && fitAddon.fit(); } catch (e) {} }, 0);
  if (bannerText) t.writeln(bannerText);
}

function terminalSetStatus(text) {
  const s = document.getElementById('termStrip');
  if (s) s.textContent = text;
}

// One Channel<String> per session. The Rust terminal_connect handler accepts
// it as a parameter named `on_data` (camelCase) and pipes output into it.
function terminalConnect(server, opts) {
  return new Promise(async (resolve, reject) => {
    const t = ensureTerminal();
    if (!t) return reject(new Error('xterm.js unavailable'));
    if (!server || !server.id) return reject(new Error('Server is required.'));
    terminalReset('');
    setTimeout(() => { try { fitAddon && fitAddon.fit(); } catch (e) {} }, 0);

    const onData = new Channel();
    onData.onmessage = (text) => {
      if (!text) return;
      try { t.write(text); } catch (e) {}
    };

    const args = {
      serverId: server.id,
      cols: t.cols || 80,
      rows: t.rows || 24,
      on_data: onData,
      overrideUsername: opts && opts.overrideUsername,
      overrideKeyId: opts && opts.overrideKeyId,
      overridePemPath: opts && opts.overridePemPath,
      promptPassword: opts && opts.promptPassword,
    };

    // Forward keystrokes to the SSH session. xterm.js sends raw bytes
    // (including escape sequences for arrow keys, Ctrl-C, etc.).
    const dataSub = t.onData(async (data) => {
      if (!window.__sshspanActiveSession) return;
      try {
        await invoke('terminal_send', {
          sessionId: window.__sshspanActiveSession,
          bytes: Array.from(data).map(c => c.charCodeAt(0) & 0xff),
        });
      } catch (e) {
        // ignore individual keystroke errors (closed channel, etc.)
      }
    });

    try {
      const r = await invoke('terminal_connect', args);
      const sessionId = r && r.sessionId;
      if (!sessionId) throw new Error((r && r.error) || 'No session id returned.');

      window.__sshspanActiveSession = sessionId;

      // Stop forwarding keystrokes and tear down on disconnect.
      const oldSession = sessionId;
      const finishOnClose = () => {
        if (window.__sshspanActiveSession !== oldSession) return;
        window.__sshspanActiveSession = null;
        try { dataSub.dispose(); } catch (e) {}
        try { t.writeln('\r\n\x1b[1;33m[connection closed]\x1b[0m'); } catch (e) {}
        if (typeof window.onTerminalClosed === 'function') window.onTerminalClosed();
      };

      // The session ends when the Rust task drops its input_tx (our disconnect)
      // or when the channel closes from the server. We can't observe that from
      // JS directly, so we hook the "exit" pattern: when the next terminal_send
      // fails (channel closed), we treat it as ended.
      const origSend = t.onData;
      // Wrap dataSub by replacing the onData handler: detect closed channel via
      // a one-shot probe after a write.
      const probeId = setInterval(async () => {
        if (window.__sshspanActiveSession !== oldSession) {
          clearInterval(probeId);
          return;
        }
        try {
          await invoke('terminal_list', {});
        } catch (e) {
          clearInterval(probeId);
          finishOnClose();
        }
      }, 4000);

      // Send the actual terminal size now that the session is open.
      try {
        await invoke('terminal_resize', {
          sessionId, cols: t.cols, rows: t.rows,
        });
      } catch (e) {}

      resolve(sessionId);
    } catch (e) {
      try { dataSub.dispose(); } catch (e2) {}
      reject(e);
    }
  });
}

window.initTerminal = initTerminal;
window.terminalReset = terminalReset;
window.terminalSetStatus = terminalSetStatus;
window.terminalConnect = terminalConnect;