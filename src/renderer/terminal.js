/**
 * terminal.js — xterm.js wrapper for the Connect view.
 * ---------------------------------------------------------------------------
 * Loaded after `vendor/xterm.js`, `vendor/addon-fit.js`, `vendor/addon-web-links.js`,
 * which expose globals `Terminal`, `FitAddon`, `WebLinksAddon` on window (UMD).
 *
 * Public functions (called from app.js):
 *   ensureTerminalForSession()   - build/open/fit xterm now that the view is visible
 *   terminalReset()              - clear screen before a new session
 *   terminalSetStatus(text)      - bottom status strip
 *   terminalConnect(server, opts) - opens the russh session; returns sessionId
 *
 * Diagnostics: every connect stage is written DIRECTLY into the terminal via
 * term.writeln so the trace works even when the Tauri Channel is broken.
 */

'use strict';

const { invoke, Channel } = window.__TAURI__.core;

let term = null;
let fitAddon = null;
let currentSessionId = null;
let sessionEndedFlag = false;
let gotFirstChannelData = false;

function trace(line) {
  // Write a diagnostic line straight into the terminal. Independent of the
  // Channel — this is how we tell "channel broken" from "terminal broken".
  if (term) {
    try { term.writeln('\x1b[90m' + line + '\x1b[0m'); } catch (e) {}
  }
  // Mirror to the status strip too: if terminal geometry is broken, the strip
  // still shows the last stage.
  const s = document.getElementById('termStrip');
  if (s) s.textContent = line.replace(/\x1b\[[0-9;]*m/g, '');
}

function buildTerminal() {
  if (term) return term;
  const host = document.getElementById('terminalHost');
  if (!host) return null;

  const Terminal = window.Terminal;
  const FitAddonCtor = window.FitAddon && window.FitAddon.FitAddon;
  const WebLinksCtor = window.WebLinksAddon && window.WebLinksAddon.WebLinksAddon;

  if (!Terminal) {
    host.textContent = 'Failed to load xterm.js (window.Terminal is undefined).';
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

  if (FitAddonCtor) {
    fitAddon = new FitAddonCtor();
    try { term.loadAddon(fitAddon); } catch (e) { fitAddon = null; }
  }
  if (WebLinksCtor) {
    try { term.loadAddon(new WebLinksCtor()); } catch (e) { /* non-fatal */ }
  }

  term.open(host);
  // Fit on the next two frames so layout is fully settled before measuring.
  requestAnimationFrame(() => requestAnimationFrame(() => {
    try { fitAddon && fitAddon.fit(); } catch (e) {}
  }));

  // No !important height CSS — let xterm size itself from rows/cols and let
  // FitAddon pick the row count that fills the host.
  const ro = new ResizeObserver(() => {
    try {
      if (!fitAddon || !term) return;
      const d = fitAddon.proposeDimensions();
      if (d && Number.isFinite(d.cols) && Number.isFinite(d.rows) && d.cols >= 2 && d.rows >= 2) {
        fitAddon.fit();
        if (currentSessionId) {
          invoke('terminal_resize', { sessionId: currentSessionId, cols: term.cols, rows: term.rows })
            .catch(() => {});
        }
      }
    } catch (e) {}
  });
  ro.observe(host);

  return term;
}

function ensureTerminalForSession() {
  return buildTerminal();
}

function initTerminal() {
  // Deliberately lazy: xterm measures its host on open(), and the connect
  // view starts hidden (zero-size measurements break rendering).
}

function terminalReset() {
  const t = buildTerminal();
  if (!t) return;
  t.reset();
  requestAnimationFrame(() => { try { fitAddon && fitAddon.fit(); } catch (e) {} });
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
    gotFirstChannelData = false;
    currentSessionId = null;

    terminalReset();
    trace(`[sshspan] xterm ready (${t.cols}x${t.rows}) — connecting to ${server.host}:${server.port} (auth=${server.authMethod || 'publickey'})`);
    setTimeout(() => { try { t.focus(); } catch (e) {} }, 50);

    // Tauri v2 Channel: each Rust-side .send() triggers onmessage here.
    const onData = new Channel();
    onData.onmessage = (text) => {
      if (typeof text !== 'string' || text.length === 0) return;
      if (!gotFirstChannelData) {
        gotFirstChannelData = true;
        trace('[sshspan] channel data flowing — first bytes received from session');
        terminalSetStatus(`Connected to ${server.host}:${server.port} — streaming`);
      }
      try { t.write(text); } catch (e) {}
    };

    const args = {
      serverId: server.id,
      cols: t.cols || 80,
      rows: t.rows || 24,
      onData: onData,               // Rust param on_data, camelCase payload key
      overrideUsername: opts && opts.overrideUsername,
      overrideKeyId: opts && opts.overrideKeyId,
      overridePemPath: opts && opts.overridePemPath,
      promptPassword: opts && opts.promptPassword,
    };

    // Keystrokes: xterm gives UTF-16 strings; the remote PTY expects UTF-8
    // bytes. Encode properly (charCodeAt&0xff mangles non-ASCII).
    const encoder = new TextEncoder();
    const dataSub = t.onData(async (data) => {
      if (!currentSessionId) return;
      try {
        await invoke('terminal_send', {
          sessionId: currentSessionId,
          bytes: Array.from(encoder.encode(data)),
        });
      } catch (e) { /* closed channel — close-detection handles teardown */ }
    });

    let pollHandle = null;
    const teardown = (sid) => {
      if (sessionEndedFlag || currentSessionId !== sid) return;
      sessionEndedFlag = true;
      currentSessionId = null;
      if (pollHandle) clearInterval(pollHandle);
      try { dataSub.dispose(); } catch (e) {}
      try { t.writeln('\r\n\x1b[1;33m[connection closed]\x1b[0m'); } catch (e) {}
      if (typeof window.onTerminalClosed === 'function') window.onTerminalClosed();
    };

    try {
      const r = await invoke('terminal_connect', args);
      if (!r || !r.ok || !r.sessionId) {
        throw new Error((r && r.error) || 'No session id returned.');
      }
      const sessionId = r.sessionId;
      currentSessionId = sessionId;
      trace(`[sshspan] session established (id=${sessionId.slice(0, 8)}…) — waiting for remote output`);

      if (!gotFirstChannelData) {
        trace('[sshspan] NOTE: no channel data yet. If this line is the last one you see, the Tauri Channel is not delivering.');
      }

      // Push the real terminal size now that the session is live.
      try {
        await invoke('terminal_resize', { sessionId, cols: t.cols, rows: t.rows });
      } catch (e) {}

      // Close detection via registry CONTENT (not invoke errors): when the
      // session id disappears from terminal_list, the Rust task has exited.
      pollHandle = setInterval(async () => {
        if (sessionEndedFlag || currentSessionId !== sessionId) {
          clearInterval(pollHandle);
          return;
        }
        try {
          const res = await invoke('terminal_list', {});
          const stillThere = (res.active || []).some(s => s.sessionId === sessionId);
          if (!stillThere) teardown(sessionId);
        } catch (e) { teardown(sessionId); }
      }, 1200);

      resolve(sessionId);
    } catch (e) {
      sessionEndedFlag = true;
      currentSessionId = null;
      try { dataSub.dispose(); } catch (e2) {}
      const msg = e && e.message ? e.message : String(e);
      trace(`[sshspan] CONNECT FAILED: ${msg}`);
      reject(new Error(msg));
    }
  });
}

window.initTerminal = initTerminal;
window.ensureTerminalForSession = ensureTerminalForSession;
window.terminalReset = terminalReset;
window.terminalSetStatus = terminalSetStatus;
window.terminalConnect = terminalConnect;