/**
 * terminal.js — per-tab xterm.js sessions for the Connect view.
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
// script global scope — re-declaring it here is a SyntaxError that kills the
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


function terminalKeepaliveSeconds() {
  const value = parseInt(terminalSetting('terminalKeepaliveSeconds', '0'), 10);
  if (!Number.isFinite(value) || value <= 0) return 0;
  return Math.max(15, Math.min(3600, value));
}

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

function markTerminalBell(tabId) {
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


function copyText(text) {
  if (!text) return;
  if (tclip) { tclip.writeText(text).catch(() => {}); return; }
  if (navigator.clipboard) navigator.clipboard.writeText(text).catch(() => {});
}

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
    t.textarea.addEventListener('contextmenu', async (e) => {
      e.preventDefault();
      const text = await readClipboard();
      if (text) t.paste(text);
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
  });

  let fitAddon = null;
  if (FitAddonCtor) {
    fitAddon = new FitAddonCtor();
    try { term.loadAddon(fitAddon); } catch (e) { fitAddon = null; }
  }
  if (WebLinksCtor) {
    try { term.loadAddon(new WebLinksCtor()); } catch (e) {}
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
    markTerminalBell(tabId);
    if (mode === 'sound') playTerminalBell();
  });

  const record = {
    term, fitAddon, hostEl: host,
    sessionId: null, pollHandle: null, dataSub: null, keepaliveHandle: null,
    sessionEnded: false, gotFirstData: false,
  };
  sshTabs.set(tabId, record);

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

function startTabKeepalive(rec) {
  if (!rec || !rec.sessionId) return;
  if (rec.keepaliveHandle) clearInterval(rec.keepaliveHandle);
  const seconds = terminalKeepaliveSeconds();
  if (!seconds) return;
  rec.keepaliveHandle = setInterval(() => {
    if (!rec.sessionId || rec.sessionEnded) return;
    tcore.invoke('terminal_keepalive', { sessionId: rec.sessionId }).catch(() => {});
  }, seconds * 1000);
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
  try { rec.term.focus(); } catch (e) {}
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

    const t = rec.term;
    rec.sessionEnded = false;
    rec.gotFirstData = false;
    rec.sessionId = null;

    try { t.reset(); } catch (e) {}
    trace(tabId, `[sshspan] xterm ready (${t.cols}x${t.rows}) — connecting to ${server.host}:${server.port} (auth=${server.authMethod || 'publickey'})`);
    setTimeout(() => { try { t.focus(); } catch (e) {} }, 50);

    const onData = new tcore.Channel();
    onData.onmessage = (text) => {
      if (typeof text !== 'string' || text.length === 0) return;
      if (!rec.gotFirstData) {
        rec.gotFirstData = true;
        if (tabId === activeTabId) terminalSetStatus(`Connected to ${server.host}:${server.port} — streaming`);
      }
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

    const encoder = new TextEncoder();
    const dataSub = t.onData(async (data) => {
      if (!rec.sessionId) return;
      try {
        await tcore.invoke('terminal_send', {
          sessionId: rec.sessionId,
          bytes: Array.from(encoder.encode(data)),
        });
      } catch (e) { /* closed channel — close-detection handles teardown */ }
    });

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
      trace(tabId, `[sshspan] session established (id=${sessionId.slice(0, 8)}…) — waiting for remote output`);
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
  setTimeout(() => { try { rec.fitAddon && rec.fitAddon.fit(); } catch (e) {} }, 30);
};
window.terminalPaste = async (tabId, text) => {
  if (typeof text !== 'string' || !text) return false;
  const needsConfirm = terminalSetting('confirmMultiLinePaste', '1') !== '0';
  if (needsConfirm && (text.includes('\n') || text.includes('\r'))) {
    const lines = text.split(/\r\n|\r|\n/).length;
    if (!window.confirm(`Paste ${lines} lines into this SSH session? Review clipboard content before running commands.`)) return false;
  }
  return sendTerminalBytes(tabRecord(tabId), text);
};
window.terminalReadClipboard = readClipboard;
window.terminalApplySettings = () => {
  const scrollback = terminalScrollback();
  for (const rec of sshTabs.values()) {
    try { rec.term.options.scrollback = scrollback; } catch (e) {}
  }
};
window.terminalModeSettings = () => ({
  backspace: terminalSetting('terminalBackspace', 'default'),
  homeEnd: terminalHomeEndMode(),
  appCursorKeys: terminalAppCursorKeys(),
  appKeypad: terminalAppKeypad(),
});
