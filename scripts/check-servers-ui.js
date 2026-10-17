#!/usr/bin/env node
/*
 * Servers, terminal sessions, app lifecycle, the lock, the updater and
 * Bitwarden sync, driven through the REAL page (index.html and every script it
 * loads, a real xterm.js included) in headless Chromium against the stub Tauri
 * IPC in scripts/lib/renderer-harness.js.
 *
 * Nothing here re-implements production logic: every assertion is about what
 * the page shows, where the focus is, or which IPC commands it sends.
 *
 * What it pins (flaw audit 2026-10-09, unit JU5 - finding ids in each title):
 *   1. the server form and list: a saved password is kept, replaced or
 *      removed on purpose; Test asks for a password; ports are checked;
 *      "Use this key" lists key servers only; a row actions button; the row
 *      and key-row layout; the ~/.ssh/config import;
 *   2. the connect lifecycle: a tab closed or cancelled mid-connect leaves no
 *      session behind; the status strip follows the active tab; Reconnect
 *      reconnects the tab it sits beside; a live restart asks first, resets
 *      SFTP and keeps the scrollback; backend messages are shown as they are;
 *   3. the terminal: key compatibility and Backspace reach the session,
 *      every paste path brackets, app chords work while xterm has focus,
 *      developer traces only behind a setting, OSC 8 links, layout, the menu,
 *      resize chatter, one "[connection closed]", focus that never takes the
 *      user's control;
 *   4. Quit, the tray notice and the real version;
 *   5. the lock: a manual lock with live work asks, an idle lock warns;
 *   6. the updater dialog; 7. Bitwarden sync honesty; 8. the Upload picker;
 *   9. approval cards show invisible characters;
 *   plus the leftovers: busy buttons, dead code, copy, stylesheet hygiene.
 *
 * Run with `npm run test:servers`. Needs playwright (see check-renderer-ui.js);
 * without it only the static checks run. `--only <text>` runs the scenarios
 * whose title contains <text>; SSHSPAN_RENDERER_DIR points the run at another
 * copy of the renderer (a pristine `git archive` of an older commit, to watch
 * these checks fail where they should).
 */
'use strict';

const fs = require('fs');
const path = require('path');
const {
  failures, check, yes, loadChromium, rendererDir, serve, part,
  KEY, SERVER, CATEGORY: CATEGORY_KEY, withApp, settled, waitVisible, focusIs, answerConfirm, openLiveTab, sends, toasts, hold, letGo,
} = require('./lib/renderer-harness');

const ROOT = path.resolve(__dirname, '..');
const RENDERER = rendererDir();

// ─── fixtures ───────────────────────────────────────────────────────────────

// The backend's own texts (RU4 / RU5 contracts): the renderer shows them as
// they are, never prefixed or reworded.
const MISMATCH = 'Host key mismatch for 10.0.0.1:22 - possible man-in-the-middle. If the server\'s key really changed, forget it under Settings > Known hosts and reconnect.';
const DECLINED = 'Connection cancelled: host key not trusted.';
const TIMEOUT = 'Timed out connecting to 10.0.0.1:22.';
const UAC = 'Update cancelled - Windows did not get permission to run the installer.';
const TRAY = 'SSHSpan keeps running in the tray - Quit from the tray or Ctrl+Q';
const WARN60 = 'Locking in 60 s - move the mouse or press a key to stay unlocked';
const WARN30 = 'Locking in 30 s - move the mouse or press a key to stay unlocked';
const CLOSED_BANNER = '\r\n\x1b[1;33m[connection closed]\x1b[0m\r\n';

const PW_SERVER = (id, name) => SERVER(id, name, 'password');
const SAVED_PW_SERVER = (id, name) => Object.assign(SERVER(id, name, 'password'), { hasSavedPassword: true });

const UPDATE = {
  available: true, newerVersion: '1.10.0', current: '1.9.1', version: '1.10.0', notes: 'Fixes and polish.',
  assetUrl: 'https://github.com/AGSQ11/SSHSpan/releases/download/v1.10.0/SSHSpan_1.10.0_x64-setup.exe',
  assetDigest: 'sha256:abcd',
};

const BW_CONFIG = {
  server_url: 'https://vault.example.com', email: 'me@example.com', folder_name: 'SSHSpan_Keys',
  servers_folder_name: 'SSHSpan_Servers', last_sync: null, last_result: null, hasMasterPassword: true,
  // The destination is allowed (fw-rust-report.txt, RENDERER CONTRACT 2).
  confirmed: true,
};

// ─── helpers ────────────────────────────────────────────────────────────────

const strip = (page) => page.evaluate(() => document.getElementById('termStrip').textContent);
const visible = (page, sel) => page.evaluate((s) => {
  const n = document.querySelector(s);
  return !!n && !n.closest('[hidden]') && n.getClientRects().length > 0;
}, sel);
const exists = (page, sel) => page.evaluate((s) => !!document.querySelector(s), sel);
const lastArgs = async (app, cmd) => { const c = await app.calls(cmd); return c.length ? c[c.length - 1].args : null; };
const menuLabels = (page) => page.evaluate(() =>
  [...document.querySelectorAll('#keyConnectMenu .ctx-item')].map((b) => b.textContent.replace(/\s+/g, ' ').trim()));
const menuItem = (page, re) => page.evaluate((src) => {
  const rx = new RegExp(src);
  const b = [...document.querySelectorAll('#keyConnectMenu .ctx-item')].find((x) => rx.test(x.textContent.trim()));
  return b ? { disabled: b.disabled } : null;
}, re.source);
const clickMenuItem = (page, re) => page.evaluate((src) => {
  const rx = new RegExp(src);
  const b = [...document.querySelectorAll('#keyConnectMenu .ctx-item')].find((x) => rx.test(x.textContent.trim()));
  if (!b) return false;
  b.click();
  return true;
}, re.source);
/// The toasts on screen that are not on their way out.
const liveToasts = (page) => page.evaluate(() =>
  [...document.querySelectorAll('#toast .toast-item:not(.leaving)')].map((n) => n.querySelector('.toast-text').textContent));
const confirmText = (page) => page.evaluate(() => ({
  title: document.getElementById('confirmTitle').textContent,
  message: document.getElementById('confirmMessage').textContent,
  ok: document.getElementById('confirmOkBtn').textContent,
}));
const termText = (page, tabId) => page.evaluate((t) => {
  const rec = window.tabRecord && window.tabRecord(t);
  if (!rec) return null;
  const b = rec.term.buffer.active;
  const out = [];
  for (let i = 0; i < b.length; i++) { const l = b.getLine(i); if (l) out.push(l.translateToString(true)); }
  return out.join('\n');
}, tabId);
const writeTerm = (page, tabId, text) => page.evaluate(({ t, s }) =>
  new Promise((r) => window.tabRecord(t).term.write(s, r)), { t: tabId, s: text });
const focusTerm = (page, tabId) => page.evaluate((t) => window.tabRecord(t).term.focus(), tabId);
const inTerminal = (page) => page.evaluate(() =>
  !!document.activeElement && document.activeElement.classList.contains('xterm-helper-textarea'));
const count = (text, needle) => (String(text || '').split(needle).length - 1);

/// Every terminal_connect answers with an id never used before (the stub
/// numbers by the live count, so a reconnect would reuse "sess-1").
const uniqueSessions = (page) => page.evaluate(() => {
  window.__sessionSeq = 0;
  window.__replies.terminal_connect = (a) => {
    const id = 'conn-' + (++window.__sessionSeq);
    window.__backend.sessions.push(id);
    window.__backend.channels.push(a.onData);
    window.__channelOf = window.__channelOf || {};
    window.__channelOf[id] = a.onData;
    return { ok: true, sessionId: id };
  };
});

/// Open a tab through the production entry point and wait until it is live;
/// resolves the new tab's id.
async function openTab(app, srv, opts) {
  const { page } = app;
  const before = await page.evaluate(() => [...state.sessions.keys()]);
  await page.evaluate(({ s, o }) => { window.__tabStart = openSessionTab(s, o || {}); }, { s: srv, o: opts || null });
  await page.waitForFunction((b) => [...state.sessions.keys()].some((id) => !b.includes(id) && window.tabSessionLive(id)), before, { polling: 25 });
  return page.evaluate((b) => [...state.sessions.keys()].find((id) => !b.includes(id)), before);
}

/// The session behind a tab ends on the server side: the close-detection
/// poll (1.2 s) notices it.
async function endSession(app, tabId) {
  await app.page.evaluate(() => { window.__backend.sessions = []; });
  await app.page.waitForFunction((t) => { const s = state.sessions.get(t); return !!s && s.ended; }, tabId, { timeout: 4000, polling: 50 });
}

/// Show the Servers view and wait for its rows.
async function serversView(page) {
  await page.evaluate(() => switchView('connect'));
  await page.waitForSelector('#serverList .server-row');
}

/// An SFTP tab record with a built panel, no shell (the Files surface alone).
async function sftpTab(page, tabId) {
  await page.evaluate((t) => {
    state.sessions.set(t, { tabId: t, sessionId: 'sess-sftp', serverId: 's1', serverName: 'files', host: '10.0.0.1', port: 22, mode: 'sftp', sftpReady: true, sftpPath: '/srv', ended: false });
    const panel = buildSftpPanel(t);
    document.getElementById('sftpBody').appendChild(panel);
    panel.style.display = 'flex';
    document.getElementById('sftpBody').classList.add('visible');
  }, tabId);
}

/// The name and description the browser computes for one element (its
/// accessibility tree node, through the DevTools protocol).
async function axOf(page, sel) {
  const cdp = await page.context().newCDPSession(page);
  try {
    const { root } = await cdp.send('DOM.getDocument', { depth: 0 });
    const { nodeId } = await cdp.send('DOM.querySelector', { nodeId: root.nodeId, selector: sel });
    if (!nodeId) return null;
    const { nodes } = await cdp.send('Accessibility.getPartialAXTree', { nodeId, fetchRelatives: false });
    const n = nodes && nodes[0];
    return n ? { name: (n.name && n.name.value) || '', description: (n.description && n.description.value) || '' } : null;
  } finally {
    await cdp.detach().catch(() => {});
  }
}

/// Answer the connect password prompt (null: Cancel); says whether it showed.
async function answerPassword(page, value) {
  if (!(await waitVisible(page, '#connectPwModal', 1500))) return false;
  if (value === null) await page.click('#connectPwCancelBtn');
  else {
    await page.fill('#connectPwInput', value);
    await page.click('#connectPwOkBtn');
  }
  return true;
}

/// Click the file browser's Upload button (tab "tu"); false when it is missing.
const clickUpload = (page) => page.evaluate(() => {
  const b = [...document.querySelectorAll('#sftpPanel-tu .sftp-toolbar button')].find((x) => /^upload/i.test(x.textContent.trim()));
  if (!b) return false;
  b.click();
  return true;
});

// ─── static checks ──────────────────────────────────────────────────────────

const read = (rel) => fs.readFileSync(path.join(RENDERER, rel), 'utf8');
const readRoot = (rel) => fs.readFileSync(path.join(ROOT, rel), 'utf8');
/// A JS source with its comments blanked (strings kept), so prose cannot
/// satisfy or fail a code check.
const jsCode = (src) => src.replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, ' ')).replace(/(^|[^:'"\\])\/\/[^\n]*/g, '$1');
const cssCode = () => read('styles.css').replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, ' '));

/// The string literals of a JS source - quoted strings, and template literals
/// whole (their ${...} included) - with comments and regex literals skipped.
/// A regex is told from a division by what precedes it, which is enough for
/// this code base (the scan below reports the line of anything it flags).
function jsStringLiterals(src) {
  const out = [];
  const REGEX_AFTER = '(,=:[!&|?{};+-*%<>~^';
  const KEYWORDS = ['return', 'typeof', 'case', 'do', 'else', 'in', 'of', 'new', 'delete', 'void', 'throw', 'yield', 'await'];
  let i = 0;
  let line = 1;
  let prev = '';
  let prevWord = '';
  while (i < src.length) {
    const c = src[i];
    const n = src[i + 1];
    if (c === '\n') { line++; i++; continue; }
    if (/\s/.test(c)) { i++; continue; }
    if (c === '/' && n === '/') { while (i < src.length && src[i] !== '\n') i++; continue; }
    if (c === '/' && n === '*') {
      i += 2;
      while (i < src.length && !(src[i] === '*' && src[i + 1] === '/')) { if (src[i] === '\n') line++; i++; }
      i += 2;
      continue;
    }
    if (c === "'" || c === '"') {
      const start = line;
      let j = i + 1;
      let s = '';
      while (j < src.length && src[j] !== c) {
        if (src[j] === '\\') { s += src[j] + (src[j + 1] || ''); j += 2; continue; }
        if (src[j] === '\n') line++;
        s += src[j];
        j++;
      }
      out.push({ line: start, text: s });
      i = j + 1; prev = 'x'; prevWord = '';
      continue;
    }
    if (c === '`') {
      const start = line;
      let j = i + 1;
      let s = '';
      let depth = 0;
      while (j < src.length) {
        const d = src[j];
        if (d === '\\') { s += d + (src[j + 1] || ''); j += 2; continue; }
        if (d === '\n') line++;
        if (depth === 0 && d === '`') break;
        if (d === '$' && src[j + 1] === '{') { depth++; s += '${'; j += 2; continue; }
        if (depth > 0 && d === '{') depth++;
        if (depth > 0 && d === '}') depth--;
        s += d;
        j++;
      }
      out.push({ line: start, text: s });
      i = j + 1; prev = 'x'; prevWord = '';
      continue;
    }
    if (c === '/' && (!prev || REGEX_AFTER.includes(prev) || KEYWORDS.includes(prevWord))) {
      let j = i + 1;
      let cls = false;
      while (j < src.length && src[j] !== '\n') {
        if (src[j] === '\\') { j += 2; continue; }
        if (src[j] === '[') cls = true;
        else if (src[j] === ']') cls = false;
        else if (src[j] === '/' && !cls) break;
        j++;
      }
      i = j + 1;
      while (/[a-z]/i.test(src[i] || '')) i++;
      prev = 'x'; prevWord = '';
      continue;
    }
    if (/[\w$]/.test(c)) {
      let j = i;
      while (j < src.length && /[\w$]/.test(src[j])) j++;
      prevWord = src.slice(i, j);
      prev = 'x';
      i = j;
      continue;
    }
    prev = c; prevWord = ''; i++;
  }
  return out;
}

const EM_DASH = /—|\\u2014|&mdash;|&#8212;|&#x2014;/i;
/// The one em dash allowed: a string that is nothing else, the empty-value
/// placeholder in a table cell or a field.
const PLACEHOLDER = (text) => text === '—' || text === '\\u2014';

const STATIC = [
  ['A8-25 shown text uses " - ", never an em dash', () => {
    const found = [];
    for (const f of ['app.js', 'terminal.js', 'sftp.js', 'assistant.js', 'mcp.js']) {
      for (const s of jsStringLiterals(read(f))) {
        if (EM_DASH.test(s.text) && !PLACEHOLDER(s.text)) found.push(`${f}:${s.line}`);
      }
    }
    const html = read('index.html')
      .replace(/<!--[\s\S]*?-->/g, (m) => m.replace(/[^\n]/g, ' '))
      .replace(/<(script|style)\b[\s\S]*?<\/\1>/gi, (m) => m.replace(/[^\n]/g, ' '));
    html.split('\n').forEach((l, k) => { if (EM_DASH.test(l)) found.push(`index.html:${k + 1}`); });
    check('A8-25 no em dash in a renderer string or in the markup (the lone "—" placeholder aside)', found, []);
  }],
  ['A8-25 / A2-34 / R12 copy, dead code and the build marker', () => {
    const app = jsCode(read('app.js'));
    const term = jsCode(read('terminal.js'));
    const html = read('index.html');
    check('A8-25 the server dialog title is sentence case in the markup', /<h2 id="serverModalTitle">New server<\/h2>/.test(html), true);
    check('A2-34 the write-only state._pendingConnectKey is gone', /_pendingConnectKey/.test(app), false);
    check('A2-34 openServerModal has no ternary with two identical branches', /'publickey'\s*:\s*'publickey'/.test(app), false);
    check('A2-34 the dead window.initTerminal stub is gone', /initTerminal/.test(term), false);
    check('R12 / A2-24 the v14-tabs build marker is gone everywhere',
      ['app.js', 'terminal.js', 'index.html'].filter((f) => /v14|__SSHPAN_BUILD__/.test(read(f))), []);
    check('RU4 / A8-23 terminal.js no longer says a keepalive setting is stored', /terminalKeepaliveSeconds/.test(read('terminal.js')), false);
  }],
  ['A3-26 / A6-12 terminal options', () => {
    const term = jsCode(read('terminal.js'));
    check('A3-26 no xterm option that does not exist or does something else (bellStyle, windowsMode)',
      { bellStyle: /bellStyle/.test(term), windowsMode: /windowsMode/.test(term) }, { bellStyle: false, windowsMode: false });
    check('A6-12 the Terminal is given a linkHandler for OSC 8 links', /linkHandler\s*:/.test(term), true);
  }],
  ['A1-29 stylesheet leftovers', () => {
    const css = cssCode();
    check('A1-29 the unused tokens --accent-strong and --shadow-glow are gone',
      { accentStrong: /--accent-strong\s*:/.test(css), shadowGlow: /--shadow-glow\s*:/.test(css) }, { accentStrong: false, shadowGlow: false });
    check('A1-29 no "flex-direction: row !important" (.toggle-chip, .opt-row)', /flex-direction\s*:\s*row\s*!important/.test(css), false);
  }],
  ['JU3 deferral: stale assistant comments', () => {
    const src = read('assistant.js');
    check('item 9 the tool-event comment no longer claims masked credentials', /credentials masked/.test(src), false);
    const at = src.indexOf('const AI_EVENT_PREVIEW');
    const comment = src.slice(Math.max(0, src.lastIndexOf('\n', src.lastIndexOf('\n', at - 1) - 1)), at);
    check('item 9 AI_EVENT_PREVIEW is described as the result preview (arguments are shown in full)', /arguments/i.test(comment), false);
  }],
  ['fix1 #5 approval cards escape every character the backend refuses', () => {
    // The backend's table (src-tauri/src/assistant/mod.rs, read only): every
    // range of DISGUISING_CHARS must be escaped on a card, so the renderer's
    // set is a superset of it whatever the two files say in prose.
    const rust = readRoot('src-tauri/src/assistant/mod.rs');
    const at = rust.indexOf('const DISGUISING_CHARS');
    const end = at >= 0 ? rust.indexOf('];', at) : -1;
    const block = end > at ? rust.slice(at, end) : '';
    const declared = Number((/\[\(char, char\);\s*(\d+)\]/.exec(block) || [])[1]);
    const ranges = [...block.matchAll(/\('\\u\{([0-9A-Fa-f]+)\}',\s*'\\u\{([0-9A-Fa-f]+)\}'\)/g)]
      .map((m) => [parseInt(m[1], 16), parseInt(m[2], 16)]);
    check('fix1 #5 the backend table was read, every range of it', [ranges.length > 0, ranges.length], [true, declared]);
    const lit = /const AI_HIDDEN_CHARS = \/(.+)\/([a-z]*);/.exec(read('assistant.js'));
    let re = null;
    try { re = lit ? new RegExp(lit[1], lit[2].replace('g', '')) : null; } catch { re = null; }
    check('fix1 #5 AI_HIDDEN_CHARS is a regular expression literal', !!re, true);
    const missed = [];
    for (const [a, b] of re ? ranges : []) {
      for (let cp = a; cp <= b && missed.length < 12; cp++) {
        if (!re.test(String.fromCodePoint(cp))) missed.push('U+' + cp.toString(16).toUpperCase());
      }
    }
    check('fix1 #5 the renderer escapes every code point of every backend range (a superset)', missed, []);
    check('fix1 #5 TAB and LF stay as they are', re ? [re.test('\t'), re.test('\n')] : null, [false, false]);
  }],
  ['fix1 markup, comments and dead code', () => {
    const html = read('index.html');
    const term = read('terminal.js');
    check('fix1 #3 the saved-password hint is blank in the markup (it describes the field)',
      /<p class="hint" id="srvPwSavedHint" hidden><\/p>/.test(html), true);
    check('fix1 #13 the password prompt is titled in sentence case', /<h2 id="connectPwTitle">Enter password<\/h2>/.test(html), true);
    check('fix1 #14 the trace comment names the switch that works (not state.settings)',
      [/window\.sshspanTerminalTrace/.test(term), /state\.settings\.terminalDebugTrace/.test(term)], [true, false]);
    check('fix1 #18 tabConnecting is gone (nothing called it)', /tabConnecting/.test(term), false);
    check('fix1 #18 nothing writes rec.tabId (nothing read it)', /\brec\.tabId\b/.test(jsCode(term)), false);
  }],
  ['fix1 #9 VENDOR.md tells the truth about terminal links', () => {
    const v = read('vendor/VENDOR.md');
    check('fix1 #9 it no longer says OSC 8 links are unreachable, or that no linkHandler is set',
      [/not\*\* currently reachable/.test(v), /does not set it/.test(v)], [false, false]);
    yes('fix1 #9 it describes the confirmation (linkHandler, the site first, user name or password refused)',
      /linkHandler/.test(v) && /Site:/.test(v) && /user name or password/i.test(v));
  }],
  ['CI runs this suite', () => {
    const pkg = JSON.parse(readRoot('package.json'));
    check('package.json has test:servers', pkg.scripts && pkg.scripts['test:servers'], 'node scripts/check-servers-ui.js');
    check('the CI renderer job runs it', /npm run test:servers/.test(readRoot('.github/workflows/ci.yml')), true);
  }],
];

function runStatic() {
  console.log('static checks');
  for (const [title, fn] of STATIC) {
    try { fn(); } catch (e) { check(title + ' (threw: ' + String(e.message || e).split('\n')[0] + ')', false, true); }
  }
}

// ─── item 1: the server form and list ───────────────────────────────────────

/// Set a field the way typing would (an input event), without waiting for it
/// to be visible: a field a broken build hid must fail its check, not hang.
const setValue = (page, sel, value) => page.evaluate(({ s, v }) => {
  const n = document.querySelector(s);
  if (!n) return false;
  n.value = v;
  n.dispatchEvent(new Event('input', { bubbles: true }));
  n.dispatchEvent(new Event('change', { bubbles: true }));
  return true;
}, { s: sel, v: value });

/// Click Save in the server form and return what server_save was sent (null
/// when nothing was sent within the wait).
async function saveServerForm(app) {
  const { page } = app;
  const n = await app.count('server_save');
  await page.evaluate(() => document.getElementById('srvSaveBtn').click());
  try {
    await page.waitForFunction((k) => window.__calls.filter((c) => c.cmd === 'server_save').length > k, n, { timeout: 800 });
  } catch { return null; }
  return lastArgs(app, 'server_save');
}

async function scenarioSavedPassword(browser, server) {
  const servers = [SERVER('s1', 'web-1'), SAVED_PW_SERVER('s2', 'legacy-box')];
  await withApp(browser, server, { servers }, 'A2-04 / A5-03 a saved password is kept, replaced or removed', async (app) => {
    const { page } = app;
    await serversView(page);
    const pick = (a) => (a ? [a.savedPassword, a.clearSavedPassword] : 'nothing sent');

    await page.evaluate(() => openServerModal({ id: 's2' }));
    const rowText = await page.evaluate(() => document.getElementById('srvPwRow').innerText);
    yes('A5-03 editing a server with a saved password says so', /A password is saved - leave blank to keep it/.test(rowText), rowText);
    check('A5-03 the password field starts empty', await page.inputValue('#srvPassword'), '');
    check('A2-04 saving without touching the password keeps it (savedPassword null, clear false)',
      pick(await saveServerForm(app)), [null, false]);

    await page.evaluate(() => openServerModal({ id: 's2' }));
    const removable = await visible(page, '#srvClearPwBtn');
    yes('A5-03 a "Remove saved password" control is offered', removable);
    if (removable) {
      await page.click('#srvClearPwBtn');
      check('A5-03 pressing it says so and locks the field',
        await page.evaluate(() => [el('srvClearPwBtn').getAttribute('aria-pressed'), el('srvPassword').disabled]), ['true', true]);
      check('A5-03 and Save then sends clearSavedPassword: true', pick(await saveServerForm(app)), [null, true]);
    } else {
      await page.evaluate(() => closeServerModal());
    }

    await page.evaluate(() => openServerModal({ id: 's2' }));
    await setValue(page, '#srvPassword', 'new-secret');
    check('A5-03 a typed password replaces the saved one', pick(await saveServerForm(app)), ['new-secret', false]);

    await page.evaluate(() => { openServerModal({}); setConnectAuthMethod('password'); });
    check('a new server shows neither the "saved" hint nor the Remove control',
      [await visible(page, '#srvPwSavedHint'), await visible(page, '#srvClearPwBtn')], [false, false]);
    await setValue(page, '#srvName', 'fresh');
    await setValue(page, '#srvHost', 'fresh.example');
    await setValue(page, '#srvUser', 'ops');
    await setValue(page, '#srvPassword', 'typed-not-saved');
    check('a new server with "Save password" off stores none', pick(await saveServerForm(app)), [null, false]);
    await page.evaluate(() => { openServerModal({}); setConnectAuthMethod('password'); });
    await setValue(page, '#srvName', 'fresh2');
    await setValue(page, '#srvHost', 'fresh2.example');
    await setValue(page, '#srvUser', 'ops');
    await setValue(page, '#srvPassword', 'kept-pw');
    await page.evaluate(() => { el('srvSavePw').checked = true; });
    check('a new server with "Save password" on stores the typed one', pick(await saveServerForm(app)), ['kept-pw', false]);
    check('no page errors', app.errors, []);
  });
}

/// A saved password belongs to the server and account it was saved for: an
/// edit that changes the host, the port, the user name or the sign-in method
/// needs the password again (or its removal) - said in the form the moment
/// one changes, and Save asks for it before anything is sent.
async function scenarioServerRetarget(browser, server) {
  const NEEDS = 'A changed server needs its password again';
  const REFUSAL = 'Enter the password for the new server or account.';
  const servers = [SAVED_PW_SERVER('s2', 'legacy-box')];
  await withApp(browser, server, { servers }, 'S1 a changed server needs its password again', async (app) => {
    const { page } = app;
    await serversView(page);
    const hint = () => page.evaluate(() => { const h = el('srvPwSavedHint'); return h.hidden ? '' : h.textContent; });
    const pwMsg = () => page.evaluate(() => { const m = el('srvPwMsg'); return m && !m.hidden ? m.textContent : ''; });
    await page.evaluate(() => openServerModal({ id: 's2' }));
    yes('(set-up) unchanged, blank keeps the saved password', /leave blank to keep it/.test(await hint()), await hint());
    await setValue(page, '#srvName', 'renamed-box');
    yes('a rename keeps it', /leave blank to keep it/.test(await hint()), await hint());
    for (const [field, value, back] of [['#srvHost', '10.9.9.9', '10.0.0.2'], ['#srvPort', '2222', '22'], ['#srvUser', 'admin', 'root']]) {
      await setValue(page, field, value);
      yes(`changing ${field} says at once that the password is needed again`, (await hint()).startsWith(NEEDS), await hint());
      await setValue(page, field, back);
      yes(`and back to the saved ${field} it is kept again`, /leave blank to keep it/.test(await hint()), await hint());
    }
    await page.click('#serverModal .seg-btn[data-auth="keyboard-interactive"]');
    yes('so does another sign-in method (password -> keyboard-interactive)', (await hint()).startsWith(NEEDS), await hint());
    await page.click('#serverModal .seg-btn[data-auth="password"]');
    await setValue(page, '#srvHost', '10.9.9.9');
    check('Save without the password sends nothing', await saveServerForm(app), null);
    check('and says why at the password field, in the backend\'s words', await pwMsg(), REFUSAL);
    check('with the focus there', await page.evaluate(() => document.activeElement && document.activeElement.id), 'srvPassword');
    await setValue(page, '#srvPassword', 'new-host-pw');
    check('the message goes as the password is typed', await pwMsg(), '');
    const sent = await saveServerForm(app);
    check('typed, it is saved for the new host', sent && [sent.host, sent.savedPassword, sent.clearSavedPassword], ['10.9.9.9', 'new-host-pw', false]);

    await page.evaluate(() => openServerModal({ id: 's2' }));
    await setValue(page, '#srvUser', 'admin');
    await page.click('#srvClearPwBtn');
    yes('removing the saved password instead is fine too', !(await hint()).startsWith(NEEDS), await hint());
    const cleared = await saveServerForm(app);
    check('and Save sends the removal', cleared && [cleared.username, cleared.savedPassword, cleared.clearSavedPassword], ['admin', null, true]);

    // The backend's refusal, should one come anyway (another save moved the
    // server meanwhile), is shown as it is.
    await page.evaluate((m) => { window.__replies.server_save = { $reject: m }; }, REFUSAL);
    await page.evaluate(() => openServerModal({ id: 's2' }));
    await setValue(page, '#srvName', 'only-a-rename');
    await saveServerForm(app);
    await page.waitForTimeout(100);
    yes('the backend\'s refusal is shown as it is', (await liveToasts(page)).includes(REFUSAL), JSON.stringify(await liveToasts(page)));
    check('no page errors', app.errors, []);
  });
}

async function scenarioPort(browser, server) {
  await withApp(browser, server, {}, 'A2-39 / A5-30 the port is checked in the form', async (app) => {
    const { page } = app;
    await serversView(page);
    const fill = async () => {
      await page.evaluate(() => openServerModal({}));
      await setValue(page, '#srvName', 'p');
      await setValue(page, '#srvHost', 'p.example');
      await setValue(page, '#srvUser', 'u');
      await page.evaluate(() => { el('srvKeyId').value = 'k1'; });
    };
    await fill();
    for (const bad of ['70000', '0', '1.5', '-1']) {
      await setValue(page, '#srvPort', bad);
      const sent = await saveServerForm(app);
      const st = await page.evaluate(() => {
        const m = document.getElementById('srvPortMsg');
        return {
          msg: m && !m.hidden && m.getClientRects().length ? m.textContent : '',
          invalid: el('srvPort').getAttribute('aria-invalid'),
          focused: document.activeElement && document.activeElement.id,
        };
      });
      check(`A5-30 port "${bad}" is refused next to the field, nothing sent`,
        [sent, /1 to 65535/.test(st.msg), st.invalid, st.focused], [null, true, 'true', 'srvPort']);
      if (sent) await fill();
    }
    await setValue(page, '#srvPort', '');
    let a = await saveServerForm(app);
    check('a blank port means 22', a && a.port, 22);
    await fill();
    await setValue(page, '#srvPort', '2222');
    a = await saveServerForm(app);
    check('a valid port is sent as typed', a && a.port, 2222);
    check('no page errors', app.errors, []);
  });
}

async function scenarioTestButton(browser, server) {
  const servers = [SERVER('s1', 'web-1'), PW_SERVER('s3', 'pw-box'), SAVED_PW_SERVER('s4', 'saved-box')];
  await withApp(browser, server, { servers, replies: { server_test: { ok: true, latencyMs: 12 } } }, 'A2-11 / A5-20 / A2-18 Test', async (app) => {
    const { page } = app;
    await serversView(page);
    const tested = () => app.count('server_test');
    await page.evaluate(() => selectServer('s3'));
    await page.click('#termTestBtn');
    yes('A5-20 Test on a password server with nothing saved asks for the password', await waitVisible(page, '#connectPwModal'));
    yes('A5-02 and the prompt has the focus', await focusIs(page, 'connectPwInput', 800));
    check('nothing is sent before the answer', await tested(), 0);
    if (await app.open('connectPwModal')) {
      await page.fill('#connectPwInput', 'pw-1');
      await page.keyboard.press('Enter');
    }
    await page.waitForTimeout(150);
    check('A2-11 the typed password goes with the test (promptPassword)', await lastArgs(app, 'server_test'), { serverId: 's3', promptPassword: 'pw-1' });
    const n = await tested();
    await page.click('#termTestBtn');
    if (await waitVisible(page, '#connectPwModal', 800)) await page.keyboard.press('Escape');
    await page.waitForTimeout(150);
    check('A2-11 cancelling the prompt tests nothing', await tested(), n);

    await page.evaluate(() => selectServer('s4'));
    await page.click('#termTestBtn');
    await page.waitForTimeout(150);
    check('a saved password is used without asking', [await app.open('connectPwModal'), await lastArgs(app, 'server_test')], [false, { serverId: 's4' }]);
    await page.evaluate(() => selectServer('s1'));
    await page.click('#termTestBtn');
    await page.waitForTimeout(150);
    check('a key server is tested without asking', await lastArgs(app, 'server_test'), { serverId: 's1' });
    yes('A2-25 the result is a toast naming the server', (await toasts(page)).some((t) => /web-1/.test(t) && /12 ms/.test(t)), JSON.stringify(await toasts(page)));

    await hold(page, 'server_test');
    const before = await tested();
    await page.dblclick('#termTestBtn');
    await page.waitForTimeout(120);
    check('A2-18 a double click on Test sends one test', (await tested()) - before, 1);
    check('A2-18 and the button says it is working meanwhile', await page.getAttribute('#termTestBtn', 'aria-busy'), 'true');
    await letGo(page, 'server_test');
    await page.waitForTimeout(100);

    await page.evaluate((m) => { window.__replies.server_test = { ok: false, error: m }; }, MISMATCH);
    await page.click('#termTestBtn');
    await page.waitForTimeout(200);
    yes('RU4 a host-key mismatch from Test is shown as it is', (await toasts(page)).includes(MISMATCH), JSON.stringify(await toasts(page)));
    check('no page errors', app.errors, []);
  });

  await withApp(browser, server, { replies: { server_test: { ok: true, latencyMs: 5 } } }, 'A2-25 Test beside a live session', async (app) => {
    const { page } = app;
    await openLiveTab(app);
    await page.waitForTimeout(150);
    const before = await strip(page);
    await page.click('#termTestBtn');
    await page.waitForTimeout(250);
    check('A2-25 testing does not overwrite the live session\'s status line', await strip(page), before);
    check('it tests the server of the tab the header shows', await lastArgs(app, 'server_test'), { serverId: 's1' });
    check('no page errors', app.errors, []);
  });
}

async function scenarioPicker(browser, server) {
  const servers = [SERVER('s1', 'web-1'), PW_SERVER('s2', 'pw-box'), SERVER('s3', 'kbd-box', 'keyboard-interactive')];
  await withApp(browser, server, { servers }, 'A2-35 / A5-41 "Use this key to connect" lists key servers only', async (app) => {
    const { page } = app;
    await page.evaluate(() => {
      // A right-click focuses the row first, as a real one does.
      const row = document.querySelector('#keyList .key-row');
      row.focus();
      row.dispatchEvent(new MouseEvent('contextmenu', { bubbles: true, cancelable: true, clientX: 300, clientY: 300 }));
    });
    await page.click('#keyConnectMenu .ctx-item');
    await page.waitForFunction(() => document.querySelectorAll('#keyConnectMenu .ctx-item').length > 1);
    const labels = await menuLabels(page);
    check('A2-35 only the key server is offered', labels.filter((l) => /web-1|pw-box|kbd-box/.test(l)).map((l) => l.split(' ')[0]), ['web-1']);
    check('A5-41 the picker tree leaves password and keyboard-interactive servers out', await page.evaluate(() => {
      const t = hostPickerTree();
      const ids = [];
      (function walk(ns) { for (const n of ns) { ids.push(...n.hosts.map((h) => h.id)); walk(n.children); } })(t.roots);
      return ids.concat(t.loose.map((s) => s.id)).sort();
    }), ['s1']);
    const note = await page.evaluate(() => {
      const n = document.querySelector('#keyConnectMenu .ctx-note');
      return n ? { tag: n.tagName, id: n.id, text: n.textContent } : null;
    });
    yes('A5-41 and the menu says why they are not there', !!note && /password/i.test(note.text), JSON.stringify(note));
    check('fix1 #17 that note is text, not a disabled button nobody can reach', note && note.tag, 'P');
    const ax = await axOf(page, '#keyConnectMenu');
    yes('fix1 #17 it is the picker\'s description for assistive tech', !!ax && /not listed/.test(ax.description), JSON.stringify(ax));
    check('fix1 #17 the picker takes the focus, so the keyboard reaches it', await page.evaluate(() =>
      !!document.activeElement && !!document.activeElement.closest('#keyConnectMenu')), true);
    await page.keyboard.press('Escape');
    await page.waitForTimeout(60);
    check('fix1 #17 Escape closes it and gives the focus back (not to the page body)', await page.evaluate(() =>
      [document.querySelectorAll('.ctx-menu').length, document.activeElement === document.body]), [0, false]);
    check('no page errors', app.errors, []);
  });
}

async function scenarioRows(browser, server) {
  const long = 'a-very-long-server-name-that-will-never-fit-in-the-server-column';
  const servers = [SERVER('s1', 'ab'), SERVER('s2', long)];
  await withApp(browser, server, { servers }, 'A5-28 / A1-20 server rows', async (app) => {
    const { page } = app;
    await serversView(page);
    await page.mouse.move(2, 2);
    const geo = await page.evaluate(() => [...document.querySelectorAll('#serverList .server-row')].map((r) => {
      const dot = r.querySelector('.server-dot').getBoundingClientRect();
      const nameEl = r.querySelector('.server-name');
      const name = nameEl.getBoundingClientRect();
      const row = r.getBoundingClientRect();
      return { gap: Math.round(name.left - dot.right), width: Math.round(name.width), row: Math.round(row.width), title: nameEl.title };
    }));
    check('A1-20 a name starts right after its status dot, short or long', geo.map((g) => g.gap <= 12), [true, true]);
    yes('A1-20 a long name gets the row\'s width, not what a hidden button leaves', geo[1].width >= geo[1].row - 60, JSON.stringify(geo[1]));
    check('A1-20 the full name is its tooltip', geo.map((g) => g.title), ['ab', long]);

    const more = '#serverList .server-row[data-id="s1"] .server-row-more';
    const has = await exists(page, more);
    yes('A5-28 every server row has an actions button', has);
    if (has) {
      check('A5-28 named for its server and announced as a menu',
        [await page.getAttribute(more, 'aria-label'), await page.getAttribute(more, 'aria-haspopup')], ['Actions for ab', 'menu']);
      await page.focus(more);
      await page.keyboard.press('Enter');
      await page.waitForTimeout(80);
      check('A5-28 it opens the server menu', await menuLabels(page), ['Connect', 'Test connection', 'Edit', 'Delete']);
      check('A5-28 and says it is open', await page.getAttribute(more, 'aria-expanded'), 'true');
      check('A5-28 Enter on it opened the menu only (no connect)', await app.count('terminal_connect'), 0);
      await page.keyboard.press('Escape');
      await page.waitForTimeout(60);
      check('A5-28 Escape gives the focus back to the button', await page.evaluate((s) => document.activeElement === document.querySelector(s), more), true);
      await page.click(more);
      await clickMenuItem(page, /^Edit$/);
      yes('A5-28 its Edit opens the server form', await waitVisible(page, '#serverModal'));
      check('A8-25 titled "Edit server"', await page.textContent('#serverModalTitle'), 'Edit server');
      await page.evaluate(() => closeServerModal());
    }
    await page.focus('#serverList .server-row[data-id="s1"] .server-go');
    await page.keyboard.press('Enter');
    await page.waitForTimeout(400);
    check('Enter on a row\'s Connect button opens one session, not two', await app.count('terminal_connect'), 1);
    check('no page errors', app.errors, []);
  });
}

async function scenarioServerForm(browser, server) {
  await withApp(browser, server, {}, 'A1-21 / A8-25 the server form', async (app) => {
    const { page } = app;
    await serversView(page);
    await page.evaluate(() => openServerModal({}));
    check('A8-25 the dialog says "New server"', await page.textContent('#serverModalTitle'), 'New server');
    check('A1-21 the key row has its own class, not the key list\'s', await page.evaluate(() => {
      const r = document.getElementById('srvKeyRow');
      return [r.classList.contains('server-key-row'), r.classList.contains('key-row')];
    }), [true, false]);
    check('A1-21 so it is not drawn as a key card', await page.evaluate(() => getComputedStyle(el('srvKeyRow')).backgroundColor), 'rgba(0, 0, 0, 0)');
    const w = await page.evaluate(() => Math.round(el('srvPemPath').getBoundingClientRect().width));
    yes('A1-21 the .pem path field is wide enough to read a path', w >= 200, w);
    check('A1-29 every toggle chip and option row still lays out in a row without !important', await page.evaluate(() =>
      [...document.querySelectorAll('label.toggle-chip, label.opt-row')]
        .filter((n) => getComputedStyle(n).flexDirection !== 'row').map((n) => n.id || n.className)), []);
    check('no page errors', app.errors, []);
  });
}

async function scenarioConfigImport(browser, server) {
  const HOSTS = {
    hosts: [{ host: 'bastion', hostname: 'b.example', user: 'ops', port: 2222, identity_file: '/home/u/.ssh/id_ed25519', identities_only: false, forward_agent: false, proxy_jump: null, extra: {} }],
    path: '/home/u/.ssh/config',
  };
  await withApp(browser, server, { replies: { ssh_config_list_hosts: HOSTS } }, 'R4 / A2-43 import from ~/.ssh/config', async (app) => {
    const { page } = app;
    await serversView(page);
    await page.click('#serverImportBtn');
    await page.waitForSelector('#keyConnectMenu .ctx-item');
    check('R4 the import reads the user\'s own ssh config (source "user")', await lastArgs(app, 'ssh_config_list_hosts'), { source: 'user' });
    const labels = await menuLabels(page);
    yes('R4 the menu names the file it read', labels.some((l) => l.includes('/home/u/.ssh/config')), JSON.stringify(labels));
    yes('and lists its hosts', labels.some((l) => /^bastion/.test(l)), JSON.stringify(labels));
    if (await clickMenuItem(page, /^bastion/)) {
      yes('a host opens the server form', await waitVisible(page, '#serverModal'));
      check('prefilled from its Host block', await page.evaluate(() => [el('srvHost').value, el('srvPort').value, el('srvUser').value]), ['b.example', '2222', 'ops']);
      await page.evaluate(() => closeServerModal());
    }
    await page.evaluate(() => { window.__replies.ssh_config_list_hosts = { hosts: [], path: '/home/u/.ssh/config' }; });
    await page.click('#serverImportBtn');
    await page.waitForTimeout(150);
    yes('R4 an empty result names the file that was read',
      (await toasts(page)).some((t) => /No Host blocks/.test(t) && t.includes('/home/u/.ssh/config')), JSON.stringify(await toasts(page)));
    await page.evaluate(() => { window.__backend.unlocked = false; return refreshVaultStatus(); });
    const gate = await page.evaluate(() => ({ disabled: el('serverImportBtn').disabled, title: el('serverImportBtn').title }));
    check('R4 the Config import is lock-gated, and says why', [gate.disabled, /unlock/i.test(gate.title)], [true, true]);
    const n = await app.count('ssh_config_list_hosts');
    await page.evaluate(() => importFromSshConfig(el('serverImportBtn')));
    await page.waitForTimeout(100);
    check('R4 and reads nothing while the vault is locked', await app.count('ssh_config_list_hosts'), n);
    check('no page errors', app.errors, []);
  });
}

// ─── item 2: the connect lifecycle ──────────────────────────────────────────

const connects = (page) => page.evaluate(() => window.__calls.filter((c) => c.cmd === 'terminal_connect').length);
const moreConnects = (page, k) => page.waitForFunction((n) => window.__calls.filter((c) => c.cmd === 'terminal_connect').length > n, k);

async function scenarioCloseMidConnect(browser, server) {
  await withApp(browser, server, {}, 'A2-12 / A5-10 a tab closed while it connects', async (app) => {
    const { page } = app;
    await hold(page, 'terminal_connect');
    await page.evaluate((s) => { window.__open = openSessionTab(s); }, SERVER('s1', 'web-1'));
    await page.waitForFunction(() => state.sessions.size === 1 && window.__calls.some((c) => c.cmd === 'terminal_connect'));
    const tabId = await page.evaluate(() => [...state.sessions.keys()][0]);
    check('A5-10 while it connects the header offers Cancel', await visible(page, '#termCancelBtn'), true);
    yes('A5-10 the status line says it is connecting', /^Connecting to 10\.0\.0\.1:22/.test(await strip(page)), await strip(page));
    check('A5-10 and so does the tab chip', await page.evaluate((t) => !!document.querySelector(`#termTabs .term-tab[data-tab-id="${t}"].connecting`), tabId), true);
    await page.evaluate((t) => closeSessionTab(t), tabId);
    await letGo(page, 'terminal_connect');
    await page.waitForTimeout(250);
    check('A2-12 the session that arrives after its tab closed is disconnected', (await app.calls('terminal_disconnect')).map((c) => c.args.sessionId), ['sess-1']);
    check('A2-12 no tab is left', await page.evaluate(() => state.sessions.size), 0);
    yes('A2-12 the status line does not claim a connection', !/Connected/.test(await strip(page)), await strip(page));
    check('no page errors', app.errors, []);
  });

  await withApp(browser, server, {}, 'A5-10 Cancel while connecting', async (app) => {
    const { page } = app;
    await hold(page, 'terminal_connect');
    await page.evaluate((s) => { window.__open = openSessionTab(s); }, SERVER('s1', 'web-1'));
    await page.waitForFunction(() => window.__calls.some((c) => c.cmd === 'terminal_connect'));
    const tabId = await page.evaluate(() => [...state.sessions.keys()][0]);
    const can = await visible(page, '#termCancelBtn');
    yes('A5-10 Cancel is offered', can);
    if (can) await page.click('#termCancelBtn');
    await page.waitForTimeout(80);
    check('A5-10 Cancel ends the attempt at once', await page.evaluate((t) => {
      const s = state.sessions.get(t);
      return s ? [!!s.ended, document.getElementById('termStrip').textContent] : null;
    }, tabId), [true, 'Connection cancelled.']);
    check('A5-10 and offers Reconnect instead', [await visible(page, '#termReconnectBtn'), await visible(page, '#termCancelBtn')], [true, false]);
    await letGo(page, 'terminal_connect');
    await page.waitForTimeout(250);
    check('A5-10 the session that arrives later is disconnected', (await app.calls('terminal_disconnect')).map((c) => c.args.sessionId), ['sess-1']);
    check('A5-10 and the tab stays ended', await page.evaluate((t) => [!!state.sessions.get(t).ended, window.tabSessionLive(t)], tabId), [true, false]);
    check('no page errors', app.errors, []);
  });
}

async function scenarioStrip(browser, server) {
  const servers = [SERVER('s1', 'web-1'), SERVER('s2', 'db-1')];
  await withApp(browser, server, { servers }, 'A2-25 / A3-27 the status line follows the active tab', async (app) => {
    const { page } = app;
    await hold(page, 'terminal_connect');
    await page.evaluate((s) => { window.__open = openSessionTab(s); }, servers[0]);
    await page.waitForFunction(() => window.__calls.some((c) => c.cmd === 'terminal_connect'));
    await page.evaluate(() => switchView('keys'));
    await page.evaluate(() => switchView('connect'));
    await page.waitForTimeout(150);
    yes('A2-25 a view switch while connecting leaves "Connecting..." in place', /^Connecting to 10\.0\.0\.1:22/.test(await strip(page)), await strip(page));
    await letGo(page, 'terminal_connect');
    await page.waitForFunction(() => [...state.sessions.keys()].some((id) => window.tabSessionLive(id)));
    await page.waitForTimeout(100);
    const first = await page.evaluate(() => [...state.sessions.keys()][0]);
    yes('connected', /^Connected to 10\.0\.0\.1:22/.test(await strip(page)), await strip(page));
    await page.evaluate(() => switchView('settings'));
    await page.evaluate(() => switchView('connect'));
    await page.waitForTimeout(150);
    const back = await strip(page);
    yes('A3-27 back on Servers the live tab\'s status is shown, not "Ready" or a build id', /^Connected to 10\.0\.0\.1:22/.test(back) && !/Ready|build/.test(back), back);
    const second = await openTab(app, servers[1]);
    await page.waitForTimeout(100);
    yes('the new tab\'s status is shown while it is active', /10\.0\.0\.2/.test(await strip(page)), await strip(page));
    await page.evaluate((t) => activateSessionTab(t), first);
    yes('A3-27 switching tabs shows that tab\'s status', /10\.0\.0\.1/.test(await strip(page)), await strip(page));
    await page.evaluate((t) => activateSessionTab(t), second);
    yes('A3-27 and back again', /10\.0\.0\.2/.test(await strip(page)), await strip(page));

    await page.waitForTimeout(200);
    await focusTerm(page, second);
    await page.keyboard.press('Control+1');
    await page.waitForTimeout(100);
    await page.keyboard.press('Control+2');
    await page.waitForTimeout(400);
    check('A3-27 after Keys and back the terminal has the focus again', await inTerminal(page), true);
    const n = (await sends(app)).length;
    await page.keyboard.type('ls');
    await page.waitForTimeout(100);
    check('A3-27 so typing reaches the shell', (await sends(app)).slice(n), ['l', 's']);
    check('no page errors', app.errors, []);
  });
}

async function scenarioReconnect(browser, server) {
  const servers = [SERVER('s1', 'web-1'), SERVER('s2', 'db-1')];
  await withApp(browser, server, { servers }, 'A2-44 / A3-10 Reconnect reconnects the tab it sits beside', async (app) => {
    const { page } = app;
    await uniqueSessions(page);
    const tab = await openTab(app, servers[0], { overrideKeyId: 'k2' });
    await endSession(app, tab);
    await page.evaluate(() => selectServer('s2'));
    const before = await connects(page);
    check('the header offers Reconnect for the ended tab', [await visible(page, '#termReconnectBtn'), (await page.textContent('#termReconnectBtn')).trim()], [true, 'Reconnect']);
    await page.click('#termReconnectBtn');
    await moreConnects(page, before);
    const a = await lastArgs(app, 'terminal_connect');
    check('A3-10 it reconnects the ACTIVE tab\'s server, not the list selection', a.serverId, 's1');
    check('A2-44 with the key that tab was opened with', a.overrideKeyId, 'k2');
    check('A3-10 in the same tab', await page.evaluate(() => state.sessions.size), 1);
    await page.waitForFunction((t) => window.tabSessionLive(t), tab);
    await page.evaluate((t) => closeSessionTab(t, { skipConfirm: true }), tab);
    await page.evaluate(() => selectServer('s2'));
    await page.waitForTimeout(80);
    check('A2-44 with no tab the same button says Connect', [await visible(page, '#termReconnectBtn'), (await page.textContent('#termReconnectBtn')).trim()], [true, 'Connect']);
    const n = await connects(page);
    await page.click('#termReconnectBtn');
    await moreConnects(page, n);
    check('and connects the selected server', (await lastArgs(app, 'terminal_connect')).serverId, 's2');
    check('no page errors', app.errors, []);
  });
}

async function scenarioRestart(browser, server) {
  await withApp(browser, server, {}, 'A3-13 a restart on a live tab', async (app) => {
    const { page } = app;
    await uniqueSessions(page);
    const tab = await openTab(app, SERVER('s1', 'web-1'));
    await page.evaluate(() => setSessionMode('split'));
    await page.waitForFunction((t) => { const s = state.sessions.get(t); return s.mode === 'split' && s.sftpReady; }, tab);
    const restart = async () => {
      await page.evaluate((t) => openTerminalContextMenu(300, 300, t), tab);
      await page.waitForTimeout(60);
      return clickMenuItem(page, /^Restart session$/);
    };
    await restart();
    yes('A3-13 restarting a live session asks first', await waitVisible(page, '#confirmModal', 800));
    const before = { connects: await connects(page), disconnects: await app.count('terminal_disconnect') };
    if (await app.open('confirmModal')) await answerConfirm(page, 'cancel');
    await page.waitForTimeout(150);
    check('A3-13 Cancel leaves the session alone', { connects: await connects(page), disconnects: await app.count('terminal_disconnect') }, before);
    await restart();
    if (await waitVisible(page, '#confirmModal', 800)) await answerConfirm(page, 'ok');
    await page.waitForFunction((t) => window.tabRecord(t).sessionId === 'conn-2', tab);
    await page.waitForTimeout(100);
    check('A3-13 OK ends the old session', (await app.calls('terminal_disconnect')).map((c) => c.args.sessionId), ['conn-1']);
    check('A3-13 and closes its file browser', (await app.calls('sftp_close')).map((c) => c.args.sessionId), ['conn-1']);
    check('A3-13 the tab starts over in the shell; SFTP opens again when asked',
      await page.evaluate((t) => { const s = state.sessions.get(t); return [s.mode, !!s.sftpReady, s.sessionId]; }, tab), ['ssh', false, 'conn-2']);
    check('no page errors', app.errors, []);
  });

  await withApp(browser, server, {}, 'A3-14 no restart while the tab connects', async (app) => {
    const { page } = app;
    await hold(page, 'terminal_connect');
    await page.evaluate((s) => { window.__open = openSessionTab(s); }, SERVER('s1', 'web-1'));
    await page.waitForFunction(() => window.__calls.some((c) => c.cmd === 'terminal_connect'));
    const tab = await page.evaluate(() => [...state.sessions.keys()][0]);
    await page.evaluate((t) => openTerminalContextMenu(300, 300, t), tab);
    await page.waitForTimeout(60);
    check('A3-14 "Restart session" is disabled while the tab connects', await menuItem(page, /^Restart session$/), { disabled: true });
    await page.keyboard.press('Escape');
    await page.evaluate(() => { window.__again = reconnectActiveTab(); });
    await page.waitForTimeout(150);
    check('A3-14 and a restart asked for meanwhile starts no second connect', await connects(page), 1);
    await letGo(page, 'terminal_connect');
    await page.waitForTimeout(150);
    check('no page errors', app.errors, []);
  });
}

async function scenarioOverlap(browser, server) {
  await withApp(browser, server, {}, 'A3-14 two connects on one tab', async (app) => {
    const { page } = app;
    await uniqueSessions(page);
    const tab = await openTab(app, SERVER('s1', 'web-1'));
    await hold(page, 'terminal_connect');
    await page.evaluate((t) => {
      const s = state.sessions.get(t);
      const srv = { id: s.serverId, host: s.host, port: s.port, authMethod: 'publickey' };
      const settle = (p) => p.then((id) => 'ok:' + id, () => 'rejected');
      window.__first = settle(window.terminalConnectInTab(t, srv, {}));
      window.__second = settle(window.terminalConnectInTab(t, srv, {}));
    }, tab);
    await page.waitForTimeout(100);
    await letGo(page, 'terminal_connect');
    const first = await settled(page, () => window.__first, null, 2000);
    const second = await settled(page, () => window.__second, null, 2000);
    check('A3-14 of two overlapping connects on one tab the earlier is abandoned', [first, second], ['rejected', 'ok:conn-3']);
    check('A3-14 its session is disconnected, like the live one before it',
      (await app.calls('terminal_disconnect')).map((c) => c.args.sessionId).sort(), ['conn-1', 'conn-2']);
    check('A3-14 the tab holds the later session', await page.evaluate((t) => window.tabRecord(t).sessionId, tab), 'conn-3');
    await endSession(app, tab);
    check('A3-14 and still notices when that one ends', await page.evaluate((t) => window.tabSessionLive(t), tab), false);
    check('no page errors', app.errors, []);
  });
}

async function scenarioScrollback(browser, server) {
  await withApp(browser, server, {}, 'A3-36 a restart keeps the scrollback', async (app) => {
    const { page } = app;
    await uniqueSessions(page);
    const tab = await openTab(app, SERVER('s1', 'web-1'));
    await writeTerm(page, tab, Array.from({ length: 120 }, (_, i) => 'deploy log line ' + i).join('\r\n') + '\r\n');
    await page.evaluate(() => { window.__restart = reconnectActiveTab(); });
    if (await waitVisible(page, '#confirmModal', 800)) await answerConfirm(page, 'ok');
    await page.waitForFunction((t) => window.tabRecord(t).sessionId === 'conn-2', tab);
    await page.waitForTimeout(100);
    const text = await termText(page, tab);
    check('A3-36 the old output is still there after the restart', ['deploy log line 5', 'deploy log line 100'].map((l) => text.includes(l)), [true, true]);
    yes('A3-36 with a line that marks the restart', /reconnecting to 10\.0\.0\.1:22/i.test(text), text.slice(-300));
    check('no page errors', app.errors, []);
  });
}

async function scenarioMessages(browser, server) {
  for (const [label, msg] of [['host-key mismatch', MISMATCH], ['declined host key', DECLINED], ['connect timeout', TIMEOUT]]) {
    await withApp(browser, server, { replies: { terminal_connect: { $reject: msg } } }, `RU4 ${label} shown as it is`, async (app) => {
      const { page } = app;
      await page.evaluate((s) => { window.__open = openSessionTab(s); }, SERVER('s1', 'web-1'));
      await settled(page, () => window.__open, null, 2000);
      await page.waitForTimeout(100);
      const tab = await page.evaluate(() => [...state.sessions.keys()][0]);
      check(`RU4 the ${label} toast is the backend's text`, (await toasts(page)).filter((t) => t === msg).length, 1);
      check(`RU4 the ${label} status line too`, await strip(page), msg);
      yes(`RU4 the tab says why it is dead (${label})`, ((await termText(page, tab)) || '').replace(/\n/g, '').includes(msg.slice(0, 30)));
      check('no page errors', app.errors, []);
    });
  }
}

// ─── item 3: the terminal ───────────────────────────────────────────────────

/// Press one key in the focused terminal; what went to the session for it.
async function pressSends(app, key) {
  const n = (await sends(app)).length;
  await app.page.keyboard.press(key);
  await app.page.waitForTimeout(80);
  return (await sends(app)).slice(n);
}

const flashing = (page, tabId) => page.evaluate((t) => !!document.querySelector(`#termTabs .term-tab[data-tab-id="${t}"].bell-flash`), tabId);

async function scenarioKeys(browser, server) {
  const compat = { terminalHomeEnd: 'rxvt', terminalAppCursorKeys: 'disabled', terminalAppKeypad: 'disabled', terminalBackspace: 'backspace' };
  await withApp(browser, server, { settings: compat }, 'A8-03 / A3-26 compatibility keys reach the session', async (app) => {
    const { page } = app;
    const tab = await openLiveTab(app);
    await page.waitForTimeout(200);
    await focusTerm(page, tab);
    const before = await termText(page, tab);
    check('A8-03 rxvt Home is sent to the session', await pressSends(app, 'Home'), ['\x1b[7~']);
    check('A8-03 rxvt End is sent to the session', await pressSends(app, 'End'), ['\x1b[8~']);
    await writeTerm(page, tab, '\x1b[?1h\x1b='); // the remote turns on application cursor keys and keypad
    check('A8-03 with application cursor keys refused, ArrowUp sends CSI A', await pressSends(app, 'ArrowUp'), ['\x1b[A']);
    // Playwright's keypad is NumLock-off: unshifted, keypad 7 is Home (and got
    // rxvt Home above, rightly); with Shift it is the digit, as NumLock on.
    check('A8-03 with the application keypad refused, keypad 7 sends 7', await pressSends(app, 'Shift+Numpad7'), ['7']);
    check('A3-26 Backspace set to "Backspace (0x08)" sends 0x08', await pressSends(app, 'Backspace'), ['\x08']);
    check('A8-03 nothing was drawn locally instead', await termText(page, tab), before);
    check('no page errors', app.errors, []);
  });
  await withApp(browser, server, {}, 'A8-03 / A3-26 the default keys', async (app) => {
    const { page } = app;
    const tab = await openLiveTab(app);
    await page.waitForTimeout(200);
    await focusTerm(page, tab);
    check('Home sends xterm\'s own sequence by default', await pressSends(app, 'Home'), ['\x1b[H']);
    check('A3-26 Backspace sends DEL (0x7f) by default', await pressSends(app, 'Backspace'), ['\x7f']);
    check('no page errors', app.errors, []);
  });
}

async function scenarioBell(browser, server) {
  await withApp(browser, server, {}, 'A3-26 the visual bell flashes the tab', async (app) => {
    const { page } = app;
    const tab = await openLiveTab(app);
    await page.waitForTimeout(150);
    await writeTerm(page, tab, '\x07');
    let flashed = false;
    try {
      await page.waitForFunction((t) => !!document.querySelector(`#termTabs .term-tab[data-tab-id="${t}"].bell-flash`), tab, { timeout: 600, polling: 10 });
      flashed = true;
    } catch { /* not flashed */ }
    check('A3-26 a bell in the tab you are watching flashes its tab (Visual, the default)', flashed, true);
    await page.waitForTimeout(900);
    check('A3-26 briefly', await flashing(page, tab), false);
    check('no page errors', app.errors, []);
  });
  await withApp(browser, server, { settings: { terminalBell: 'silent' } }, 'A3-26 a silent bell', async (app) => {
    const { page } = app;
    const tab = await openLiveTab(app);
    await page.waitForTimeout(150);
    await writeTerm(page, tab, '\x07');
    await page.waitForTimeout(100);
    check('A3-26 Silent flashes nothing', await flashing(page, tab), false);
    check('no page errors', app.errors, []);
  });
}

async function scenarioPastePaths(browser, server) {
  await withApp(browser, server, {}, 'A3-11 every paste path brackets', async (app) => {
    const { page } = app;
    const tab = await openLiveTab(app);
    await page.waitForTimeout(150);
    await writeTerm(page, tab, '\x1b[?2004h');
    await page.evaluate(() => navigator.clipboard.writeText('echo hi'));
    const wrapped = '\x1b[200~echo hi\x1b[201~';
    await page.evaluate((t) => openTerminalContextMenu(300, 300, t), tab);
    await page.waitForTimeout(60);
    await clickMenuItem(page, /^Paste$/);
    await page.waitForTimeout(250);
    check('A3-11 the menu\'s Paste goes through bracketed paste', (await sends(app)).filter((s) => s === wrapped).length, 1);
    await focusTerm(page, tab);
    await page.keyboard.press('Control+Shift+V');
    await page.waitForTimeout(250);
    check('A3-11 so does Ctrl+Shift+V', (await sends(app)).filter((s) => s === wrapped).length, 2);
    check('no page errors', app.errors, []);
  });
}

async function scenarioChords(browser, server) {
  await withApp(browser, server, { replies: { sftp_open: { cwd: '/srv' } } }, 'A5-44 / A2-53 app chords while the terminal has the focus', async (app) => {
    const { page } = app;
    const tab = await openLiveTab(app);
    await page.waitForTimeout(200);
    await focusTerm(page, tab);
    const n = (await sends(app)).length;
    const maxed = () => page.evaluate(() => document.getElementById('app').classList.contains('term-max'));
    await page.keyboard.press('Control+Shift+KeyM');
    await page.waitForTimeout(100);
    check('A5-44 Ctrl+Shift+M maximizes the terminal while it has the focus', await maxed(), true);
    const hint = await strip(page);
    yes('A5-44 and the hint names the real way back', /Ctrl\+Shift\+M/.test(hint) && !/Esc/.test(hint), hint);
    await page.waitForTimeout(300);
    await page.keyboard.press('Control+Shift+KeyM');
    await page.waitForTimeout(100);
    check('A5-44 the same chord restores it', await maxed(), false);
    check('A5-44 neither press reached the shell', (await sends(app)).slice(n), []);
    const title = await page.getAttribute('#termMaxBtn', 'title');
    yes('A5-44 the maximize button names the chord too', /Ctrl\+Shift\+M/.test(title || ''), title);
    await page.waitForTimeout(300);
    await focusTerm(page, tab);
    await page.keyboard.press('Control+Shift+Digit2');
    await page.waitForTimeout(250);
    check('A2-53 Ctrl+Shift+2 switches to Files while the terminal has the focus', await page.evaluate((t) => state.sessions.get(t).mode, tab), 'sftp');
    check('A2-53 and no ^@ (NUL) reached the shell', (await sends(app)).slice(n).filter((s) => s.includes('\x00')), []);
    check('no page errors', app.errors, []);
  });
}

async function scenarioTraces(browser, server) {
  await withApp(browser, server, {}, 'A5-11 no developer traces by default', async (app) => {
    const { page } = app;
    const tab = await openLiveTab(app);
    await page.waitForTimeout(200);
    const text = await termText(page, tab);
    check('A5-11 a healthy connect writes no [sshspan] lines into the terminal', /\[sshspan\]/.test(text), false);
    check('A5-11 nor the "IPC Channel is not delivering" note', /not delivering/.test(text), false);
    check('no page errors', app.errors, []);
  });
  await withApp(browser, server, {}, 'A5-11 / fix1 #14 traces behind the developer switch', async (app) => {
    const { page } = app;
    // Switched on from the developer tools; loading Settings (which replaces
    // state.settings) must not switch it off again.
    await page.evaluate(() => { window.sshspanTerminalTrace = true; });
    await page.evaluate(() => switchView('settings'));
    await page.waitForSelector('#settingsRows .settings-row');
    await page.evaluate(() => switchView('connect'));
    const tab = await openLiveTab(app);
    await page.waitForTimeout(200);
    yes('fix1 #14 with the switch on, traces are written - Settings loaded since', /\[sshspan\]/.test(await termText(page, tab)));
    check('no page errors', app.errors, []);
  });
  await withApp(browser, server, { replies: { terminal_connect: { $reject: TIMEOUT } } }, 'A5-11 failures are always shown', async (app) => {
    const { page } = app;
    await page.evaluate((s) => { window.__open = openSessionTab(s); }, SERVER('s1', 'web-1'));
    await settled(page, () => window.__open, null, 2000);
    await page.waitForTimeout(100);
    const tab = await page.evaluate(() => [...state.sessions.keys()][0]);
    yes('A5-11 a failed connect still says why in the terminal', ((await termText(page, tab)) || '').includes(TIMEOUT));
    check('no page errors', app.errors, []);
  });
}

async function scenarioOscLinks(browser, server) {
  await withApp(browser, server, {}, 'A6-12 OSC 8 links go through the app', async (app) => {
    const { page } = app;
    const tab = await openLiveTab(app);
    await page.waitForTimeout(200);
    const target = new URL('/osc-target', page.url()).href;
    check('A6-12 the terminal has the app\'s own link handler', await page.evaluate((t) => {
      const h = window.tabRecord(t).term.options.linkHandler;
      return !!h && typeof h.activate === 'function';
    }, tab), true);
    await writeTerm(page, tab, `\r\n\x1b]8;;${target}\x07OSCLINKTEXT\x1b]8;;\x07 trailing\r\n`);
    const at = await page.evaluate((t) => {
      const term = window.tabRecord(t).term;
      const buf = term.buffer.active;
      const r = term.element.querySelector('.xterm-screen').getBoundingClientRect();
      for (let y = 0; y < term.rows; y++) {
        const line = buf.getLine(buf.viewportY + y);
        const x = line ? line.translateToString(true).indexOf('OSCLINKTEXT') : -1;
        if (x >= 0) return { x: r.left + (x + 3.5) * (r.width / term.cols), y: r.top + (y + 0.5) * (r.height / term.rows) };
      }
      return null;
    }, tab);
    yes('the link text is on screen', !!at);
    if (at) {
      await page.mouse.move(at.x, at.y);
      await page.waitForTimeout(200);
      await page.mouse.click(at.x, at.y);
    }
    const asked = await waitVisible(page, '#confirmModal', 1000);
    check('A6-12 clicking it raises no native dialog', await page.evaluate(() => window.__nativeDialogCalls), 0);
    yes('A6-12 the app asks first, showing where the link really goes', asked && (await page.textContent('#confirmMessage')).includes(target));
    if (asked) await answerConfirm(page, 'ok');
    await page.waitForTimeout(150);
    check('A6-12 and opens it through the backend\'s http(s) allowlist', (await app.calls('system_open_url')).map((c) => c.args.url), [target]);
    check('no page errors', app.errors, []);
  });
}

async function scenarioLayout(browser, server) {
  await withApp(browser, server, {}, 'A1-38 terminal padding and the maximize button', async (app) => {
    const { page } = app;
    const tab = await openLiveTab(app);
    for (const [w, h] of [[880, 560], [1100, 720], [1400, 900]]) {
      await page.setViewportSize({ width: w, height: h });
      await page.waitForTimeout(450);
      const g = await page.evaluate((t) => {
        const rec = window.tabRecord(t);
        const host = rec.hostEl.getBoundingClientRect();
        const screen = rec.term.element.querySelector('.xterm-screen').getBoundingClientRect();
        return { pad: getComputedStyle(rec.hostEl).paddingTop, screenBottom: screen.bottom, hostBottom: host.bottom, screenRight: screen.right, hostRight: host.right };
      }, tab);
      check(`A1-38 at ${w}x${h} the host has no padding of its own (FitAddon measures it)`, g.pad, '0px');
      yes(`A1-38 at ${w}x${h} the last row and column are not clipped`, g.screenBottom <= g.hostBottom + 0.5 && g.screenRight <= g.hostRight + 0.5, JSON.stringify(g));
    }
    const btn = await page.evaluate((t) => {
      const b = document.getElementById('termMaxBtn').getBoundingClientRect();
      const s = window.tabRecord(t).term.element.getBoundingClientRect();
      const overlap = !(b.right <= s.left || b.left >= s.right || b.bottom <= s.top || b.top >= s.bottom);
      return { overlap, opacity: getComputedStyle(document.getElementById('termMaxBtn')).opacity };
    }, tab);
    check('A1-38 the maximize button does not sit on the terminal and is fully drawn', btn, { overlap: false, opacity: '1' });
    check('no page errors', app.errors, []);
  });
}

async function scenarioTermMenu(browser, server) {
  await withApp(browser, server, { replies: { sftp_open: { cwd: '/srv' } } }, 'A3-31 / A5-33 the terminal menu', async (app) => {
    const { page } = app;
    await uniqueSessions(page);
    const tab = await openTab(app, SERVER('s1', 'web-1'), { overrideKeyId: 'k2' });
    await page.evaluate((t) => openTerminalContextMenu(300, 300, t), tab);
    await page.waitForTimeout(60);
    const labels = await menuLabels(page);
    const modeItems = (ls) => ls.filter((l) => /file browser|terminal only|Switch to/i.test(l));
    check('A5-33 no "Duplicate session" (it did exactly what "New session" does)', labels.includes('Duplicate session'), false);
    check('A3-31 in the shell the mode item says where it goes', modeItems(labels), ['Open file browser']);
    const n = await connects(page);
    await clickMenuItem(page, /^New session$/);
    await moreConnects(page, n);
    const a = await lastArgs(app, 'terminal_connect');
    check('A5-33 "New session" opens another tab to the same server with the same key', [a.serverId, a.overrideKeyId], ['s1', 'k2']);
    await page.waitForFunction(() => [...state.sessions.keys()].filter((id) => window.tabSessionLive(id)).length === 2);
    await page.evaluate((t) => activateSessionTab(t), tab);
    await page.evaluate(() => setSessionMode('split'));
    await page.waitForFunction((t) => state.sessions.get(t).mode === 'split', tab);
    await page.evaluate((t) => openTerminalContextMenu(300, 300, t), tab);
    await page.waitForTimeout(60);
    check('A3-31 in split view it offers the terminal alone', modeItems(await menuLabels(page)), ['Show terminal only']);
    await clickMenuItem(page, /^Show terminal only$/);
    await page.waitForTimeout(150);
    check('A3-31 and does what it says', await page.evaluate((t) => state.sessions.get(t).mode, tab), 'ssh');
    check('no page errors', app.errors, []);
  });
}

async function scenarioResize(browser, server) {
  await withApp(browser, server, {}, 'A3-34 #4 resizing sends one size per frame, and none when there is no session', async (app) => {
    const { page } = app;
    await uniqueSessions(page);
    const tab = await openTab(app, SERVER('s1', 'web-1'));
    await page.waitForTimeout(400);
    const base = await app.count('terminal_resize');
    await page.evaluate(async () => {
      const b = document.getElementById('terminalBody');
      const w = b.getBoundingClientRect().width;
      for (let i = 0; i < 40; i++) {
        b.style.width = (w - i * 3) + 'px';
        await new Promise((r) => requestAnimationFrame(r));
      }
    });
    await page.waitForTimeout(400);
    const calls = (await app.calls('terminal_resize')).slice(base).map((c) => [c.args.cols, c.args.rows]);
    yes('A3-34 a 40-frame drag sends far fewer than 40 resizes', calls.length > 0 && calls.length < 20, JSON.stringify(calls));
    check('A3-34 and never the same size twice in a row', calls.some((c, i) => i > 0 && c[0] === calls[i - 1][0] && c[1] === calls[i - 1][1]), false);
    const now = await page.evaluate((t) => { const term = window.tabRecord(t).term; return [term.cols, term.rows]; }, tab);
    check('A3-34 the last one is the size the terminal has now', calls[calls.length - 1], now);
    await endSession(app, tab);
    const ended = await app.count('terminal_resize');
    await page.evaluate(async () => {
      document.getElementById('terminalBody').style.width = '500px';
      await new Promise((r) => requestAnimationFrame(r));
      await new Promise((r) => requestAnimationFrame(r));
    });
    await page.waitForTimeout(300);
    check('A3-34 nothing is sent for a tab whose session ended', await app.count('terminal_resize'), ended);
    check('no page errors', app.errors, []);
  });
}

async function scenarioClosedOnce(browser, server) {
  await withApp(browser, server, {}, 'A3-34 #5 one "[connection closed]"', async (app) => {
    const { page } = app;
    await uniqueSessions(page);
    const tab = await openTab(app, SERVER('s1', 'web-1'));
    await page.evaluate((b) => window.__channelOf['conn-1'].onmessage(b), CLOSED_BANNER);
    await endSession(app, tab);
    await page.waitForTimeout(200);
    check('A3-34 the backend\'s closing line is not repeated by the renderer', count(await termText(page, tab), '[connection closed]'), 1);
    check('no page errors', app.errors, []);
  });
  await withApp(browser, server, {}, 'A3-34 #5 the renderer\'s line when the backend\'s never came', async (app) => {
    const { page } = app;
    await uniqueSessions(page);
    const tab = await openTab(app, SERVER('s1', 'web-1'));
    await endSession(app, tab);
    await page.waitForTimeout(200);
    check('A3-34 the tab still says the connection closed, once', count(await termText(page, tab), '[connection closed]'), 1);
    check('no page errors', app.errors, []);
  });
}

async function scenarioFocus(browser, server) {
  await withApp(browser, server, {}, 'JU6a terminal focus stands down for an open menu', async (app) => {
    const { page } = app;
    await page.evaluate((s) => { openSessionTab(s); openVaultMenu(document.getElementById('vaultStatus')); }, SERVER('s1', 'web-1'));
    await page.waitForTimeout(400);
    check('a menu opened while a tab connects keeps the focus', await page.evaluate(() => !!document.activeElement && !!document.activeElement.closest('#keyConnectMenu')), true);
    check('no page errors', app.errors, []);
  });
  await withApp(browser, server, {}, 'JU4 terminal focus never takes a control the user reached', async (app) => {
    const { page } = app;
    await uniqueSessions(page);
    const first = await openTab(app, SERVER('s1', 'web-1'));
    const second = await openTab(app, SERVER('s1', 'web-1'));
    await page.waitForTimeout(300);
    await page.evaluate((t) => activateSessionTab(t), second);
    await page.focus(`#termTabs .term-tab[data-tab-id="${first}"] .term-tab-close`);
    await page.waitForTimeout(250); // past every deferred terminal focus
    const n = (await sends(app)).length;
    await page.keyboard.press('Enter');
    await page.waitForTimeout(150);
    check('JU4 Enter on a close button reached right after a tab switch asks to close that tab',
      [await app.open('confirmModal'), await page.evaluate(() => state.activeTabId)], [true, second]);
    check('JU4 and nothing went to the shell', (await sends(app)).slice(n), []);
    if (await app.open('confirmModal')) await answerConfirm(page, 'cancel');
    await page.evaluate((s) => { openSessionTab(s); }, SERVER('s1', 'web-1'));
    await page.focus('#serverSearch');
    await page.waitForTimeout(400);
    check('JU4 a field the user moved to while a tab connected keeps the focus', await page.evaluate(() => document.activeElement.id), 'serverSearch');
    check('no page errors', app.errors, []);
  });
  await withApp(browser, server, {}, 'a tab picked with the mouse still focuses its terminal', async (app) => {
    const { page } = app;
    await uniqueSessions(page);
    const first = await openTab(app, SERVER('s1', 'web-1'));
    await openTab(app, SERVER('s1', 'web-1'));
    await page.waitForTimeout(300);
    await page.click(`#termTabs .term-tab[data-tab-id="${first}"] .term-tab-name`);
    await page.waitForTimeout(300);
    check('clicking a tab puts the focus in its terminal', await page.evaluate((t) => document.activeElement === window.tabRecord(t).term.textarea, first), true);
    check('no page errors', app.errors, []);
  });
}

// ─── item 4: quit, the tray notice, the version ─────────────────────────────

const blur = (page) => page.evaluate(() => { if (document.activeElement) document.activeElement.blur(); });
const paletteNames = (page) => page.evaluate(() => [...document.querySelectorAll('#paletteResults .palette-row .palette-name')].map((n) => n.textContent));

async function scenarioQuit(browser, server) {
  await withApp(browser, server, { replies: { app_quit: { ok: true } } }, 'R11 Quit from the vault menu, the palette and Ctrl+Q', async (app) => {
    const { page } = app;
    const quits = () => app.count('app_quit');
    await page.click('#vaultStatus');
    await page.waitForTimeout(80);
    const item = await menuItem(page, /^Quit SSHSpan/);
    yes('R11 the vault menu has Quit', !!item, JSON.stringify(await menuLabels(page)));
    if (item) await clickMenuItem(page, /^Quit SSHSpan/);
    else await page.keyboard.press('Escape');
    await page.waitForTimeout(100);
    check('R11 it quits through app_quit, without a question when nothing runs', [await quits(), await app.open('confirmModal')], [1, false]);
    await page.evaluate(() => openPalette());
    await page.fill('#paletteInput', 'quit');
    await page.waitForTimeout(80);
    const names = await paletteNames(page);
    check('R11 the palette finds Quit first', names[0], 'Quit SSHSpan');
    await page.keyboard.press('Enter');
    await page.waitForTimeout(100);
    check('R11 and runs it', await quits(), 2);
    await blur(page);
    await page.keyboard.press('Control+q');
    await page.waitForTimeout(100);
    check('R11 Ctrl+Q quits', await quits(), 3);
    check('no page errors', app.errors, []);
  });

  await withApp(browser, server, { replies: { app_quit: { ok: true } } }, 'R11 Quit with a live session asks first', async (app) => {
    const { page } = app;
    await openLiveTab(app);
    await page.waitForTimeout(200);
    await blur(page);
    await page.keyboard.press('Control+q');
    const asked = await waitVisible(page, '#confirmModal', 800);
    yes('R11 Quit with a live session asks first', asked);
    if (asked) {
      const c = await confirmText(page);
      yes('R11 naming what it closes', /1 live SSH session/.test(c.message), c.message);
      await answerConfirm(page, 'cancel');
    }
    await page.waitForTimeout(100);
    check('R11 Cancel keeps the app running', await app.count('app_quit'), 0);
    await blur(page);
    await page.keyboard.press('Control+q');
    if (await waitVisible(page, '#confirmModal', 800)) await answerConfirm(page, 'ok');
    await page.waitForTimeout(100);
    check('R11 OK quits', await app.count('app_quit'), 1);
    check('no page errors', app.errors, []);
  });

  await withApp(browser, server, { unlocked: false, replies: { app_quit: { ok: true } } }, 'R11 Quit while locked', async (app) => {
    const { page } = app;
    await page.click('#vaultCancelBtn');
    await page.click('#vaultStatus');
    await page.waitForTimeout(80);
    yes('R11 the vault menu offers Quit while locked too', !!(await menuItem(page, /^Quit SSHSpan/)), JSON.stringify(await menuLabels(page)));
    await page.keyboard.press('Escape');
    await page.evaluate(() => openPalette());
    await page.fill('#paletteInput', 'quit');
    await page.waitForTimeout(80);
    yes('R11 and so does the palette', (await paletteNames(page)).includes('Quit SSHSpan'), JSON.stringify(await paletteNames(page)));
    check('no page errors', app.errors, []);
  });
}

async function scenarioTray(browser, server) {
  await withApp(browser, server, { clock: true }, 'R11 the first close-to-tray says where the app went', async (app) => {
    const { page } = app;
    const shown = async () => (await liveToasts(page)).filter((t) => t === TRAY).length;
    await page.evaluate(() => window.__emit('window-hidden-to-tray', null));
    await app.tick(100);
    check('R11 a notice says the app keeps running and how to quit', await shown(), 1);
    await app.tick(60 * 1000);
    check('R11 it stays until dismissed (the window is hidden when it arrives)', await shown(), 1);
    await page.evaluate(() => window.__emit('window-hidden-to-tray', null));
    await app.tick(100);
    check('R11 once per run', [await shown(), await page.evaluate(() => document.querySelectorAll('#toast .toast-count').length)], [1, 0]);
    check('no page errors', app.errors, []);
  });
}

async function scenarioVersion(browser, server) {
  await withApp(browser, server, { replies: { app_info: { version: '7.7.7', platform: 'linux' } } }, 'R12 the real version', async (app) => {
    const { page } = app;
    await page.waitForTimeout(150);
    const brand = await page.textContent('.brand-sub');
    yes('R12 the sidebar shows the version app_info reports', /v7\.7\.7/.test(brand), brand);
    yes('A8-26 beside the "Key manager" subtitle', /Key manager/.test(brand), brand);
    check('R12 no build marker in the title', /v14|build/.test(await page.evaluate(() => document.title)), false);
    await page.evaluate(() => switchView('settings'));
    await page.waitForSelector('#settingsRows .settings-row');
    yes('R12 Settings shows it too', /7\.7\.7/.test(await page.textContent('#settingsRows')));
    await page.evaluate(() => switchView('connect'));
    await page.waitForTimeout(100);
    check('R12 nor in the status line', /v14|build/.test(await strip(page)), false);
    check('no page errors', app.errors, []);
  });
}

// ─── item 5: the lock ───────────────────────────────────────────────────────

async function scenarioManualLock(browser, server) {
  await withApp(browser, server, {}, 'A5-09 a manual lock with a live session asks first', async (app) => {
    const { page } = app;
    await openLiveTab(app);
    await page.waitForTimeout(200);
    await page.click('#vaultStatus');
    await clickMenuItem(page, /^Lock now/);
    const asked = await waitVisible(page, '#confirmModal', 800);
    yes('A5-09 Lock now with a live session asks first', asked);
    if (asked) {
      const c = await confirmText(page);
      yes('A5-09 naming what locking closes', /1 live SSH session/.test(c.message), c.message);
      await answerConfirm(page, 'cancel');
    }
    await page.waitForTimeout(150);
    check('A5-09 Cancel keeps the vault and the session', [await app.count('vault_lock'), await page.evaluate(() => state.sessions.size)], [0, 1]);
    await blur(page);
    await page.keyboard.press('Control+l');
    const again = await waitVisible(page, '#confirmModal', 800);
    yes('A5-09 Ctrl+L asks too', again);
    if (again) await answerConfirm(page, 'ok');
    await page.waitForTimeout(200);
    check('A5-09 OK locks', await app.count('vault_lock'), 1);
    check('no page errors', app.errors, []);
  });

  await withApp(browser, server, {}, 'A5-09 running transfers count too', async (app) => {
    const { page } = app;
    await page.evaluate(() => window.__emit('sftp-queue', { jobs: [{ id: 1, state: 'active' }, { id: 2, state: 'queued' }, { id: 3, state: 'done' }, { id: 4, state: 'paused' }] }));
    await page.evaluate(() => window.__emit('sftp-queue', { jobs: [{ id: 2, state: 'active' }] }));
    await page.keyboard.press('Control+l');
    const asked = await waitVisible(page, '#confirmModal', 800);
    yes('A5-09 a lock with transfers running asks', asked);
    if (asked) {
      const c = await confirmText(page);
      yes('A5-09 naming the transfers it pauses', /2 transfers/.test(c.message), c.message);
      await answerConfirm(page, 'ok');
    }
    await page.waitForTimeout(200);
    check('A5-09 and locks on OK', await app.count('vault_lock'), 1);
    check('no page errors', app.errors, []);
  });

  await withApp(browser, server, {}, 'A5-09 nothing running: no question', async (app) => {
    const { page } = app;
    await page.click('#vaultStatus');
    await clickMenuItem(page, /^Lock now/);
    await page.waitForTimeout(200);
    check('A5-09 with nothing running Lock now locks at once', [await app.open('confirmModal'), await app.count('vault_lock')], [false, 1]);
    check('no page errors', app.errors, []);
  });

  // The tray locks the vault itself and then tells the page: the page follows
  // and asks nothing - calling vault_lock again wrote a second audit row.
  await withApp(browser, server, {}, 'A5-09 the tray lock does not wait for an answer', async (app) => {
    const { page } = app;
    await openLiveTab(app);
    await page.waitForTimeout(150);
    await page.evaluate(() => { window.__backend.unlocked = false; window.__emit('vault-lock-requested', null); });
    await page.waitForTimeout(250);
    check('A5-09 a lock from the tray (the window may be hidden) is followed at once, unasked',
      [await app.open('confirmModal'), await page.evaluate(() => state.unlocked), await page.evaluate(() => state.sessions.size)], [false, false, 0]);
    check('and the page does not lock the locked vault again', await app.count('vault_lock'), 0);
    check('no page errors', app.errors, []);
  });

  await withApp(browser, server, { unlocked: false }, 'Ctrl+L while locked', async (app) => {
    const { page } = app;
    await page.waitForTimeout(150);
    if (await app.open('vaultModal')) await page.click('#vaultCancelBtn');
    const before = await liveToasts(page);
    await page.keyboard.press('Control+l');
    await page.waitForTimeout(200);
    check('Ctrl+L while locked does nothing: no vault_lock, no "Vault locked." toast',
      [await app.count('vault_lock'), (await liveToasts(page)).filter((t) => !before.includes(t))], [0, []]);
    await page.evaluate(() => lockNow());
    await page.waitForTimeout(150);
    check('nor does any other lock of a locked vault (the idle timer\'s lockNow)', await app.count('vault_lock'), 0);
    check('Lock now is lock-gated while locked', await page.evaluate(() => [el('lockBtn').disabled, el('lockBtn').title]),
      [true, 'The vault is already locked.']);
    check('no page errors', app.errors, []);
  });

  await withApp(browser, server, { replies: { vault_lock: { ok: true, alreadyLocked: true } } }, 'a lock the tray beat', async (app) => {
    const { page } = app;
    await page.waitForTimeout(150);
    await page.evaluate(() => { window.__backend.unlocked = false; });
    await page.keyboard.press('Control+l');
    await page.waitForTimeout(250);
    check('alreadyLocked from vault_lock is no error: the page shows the vault locked',
      [await page.evaluate(() => state.unlocked), (await liveToasts(page)).some((t) => /error|failed/i.test(t))], [false, false]);
    check('no page errors', app.errors, []);
  });
}

async function scenarioIdleWarning(browser, server) {
  await withApp(browser, server, { clock: true, settings: { autoLockMinutes: '2' } }, 'A5-09 a warning before an idle lock', async (app) => {
    const { page } = app;
    const warned = async () => (await liveToasts(page)).filter((t) => t === WARN60).length;
    await app.tick(58 * 1000);
    check('A5-09 no warning while more than a minute is left', await warned(), 0);
    await app.tick(3 * 1000);
    check('A5-09 a minute before the idle lock a warning says so', await warned(), 1);
    await page.mouse.move(400, 300);
    await page.mouse.move(420, 320);
    await app.tick(300);
    check('A5-09 moving the mouse takes the warning away', await warned(), 0);
    await app.tick(70 * 1000);
    check('A5-09 and keeps the vault unlocked past the old deadline', await app.count('vault_lock'), 0);
    check('A5-09 the warning is back a minute before the new deadline', await warned(), 1);
    await page.keyboard.press('Shift');
    await app.tick(300);
    check('A5-09 a key press takes it away too', await warned(), 0);
    await app.tick(125 * 1000);
    check('A5-09 left alone, the vault locks at the deadline', await app.count('vault_lock'), 1);
    check('A5-09 and the warning goes with the lock', await warned(), 0);
    check('no page errors', app.errors, []);
  });
  await withApp(browser, server, { clock: true, settings: { autoLockMinutes: '1' } }, 'A5-09 a one-minute auto-lock', async (app) => {
    const { page } = app;
    const warnings = async () => (await liveToasts(page)).filter((t) => /^Locking in/.test(t));
    await app.tick(28 * 1000);
    check('A5-09 with a one-minute auto-lock nothing at 28 s', await warnings(), []);
    await app.tick(3 * 1000);
    check('A5-09 the warning comes half-way, saying how long is left', await warnings(), [WARN30]);
    check('no page errors', app.errors, []);
  });
}

// ─── item 6: the updater ────────────────────────────────────────────────────

const updateButton = (page) => page.locator('#settingsRows .settings-row', { hasText: 'Check for an update now' }).locator('button');

async function scenarioUpdater(browser, server) {
  await withApp(browser, server, { replies: { update_check: UPDATE } }, 'A5-22 the update dialog', async (app) => {
    const { page } = app;
    await openLiveTab(app);
    await page.waitForTimeout(150);
    await page.evaluate(() => switchView('settings'));
    await page.waitForSelector('#settingsRows .settings-row');
    await updateButton(page).click();
    const asked = await waitVisible(page, '#confirmModal', 1000);
    yes('A5-22 an available update is offered in the app\'s own dialog', asked);
    if (asked) {
      const c = await confirmText(page);
      yes('A5-22 naming the version', /1\.10\.0/.test(c.title) && /1\.9\.1/.test(c.message), JSON.stringify(c));
      yes('A5-22 saying SSHSpan will close to install it', /SSHSpan will close to install/.test(c.message), c.message);
      yes('A5-22 and what that ends', /1 live SSH session/.test(c.message), c.message);
      await answerConfirm(page, 'cancel');
    }
    await page.waitForTimeout(100);
    check('A5-22 Cancel downloads nothing', await app.count('update_download_and_run'), 0);
    await hold(page, 'update_download_and_run');
    await updateButton(page).click();
    if (await waitVisible(page, '#confirmModal', 1000)) await answerConfirm(page, 'ok');
    await page.waitForFunction(() => window.__calls.some((c) => c.cmd === 'update_download_and_run'));
    check('A5-22 OK downloads the release\'s own installer, checked against its digest', await lastArgs(app, 'update_download_and_run'),
      { url: UPDATE.assetUrl, version: '1.10.0', expectedSha256: 'sha256:abcd' });
    check('A5-22 the button is busy while it downloads', await updateButton(page).getAttribute('aria-busy'), 'true');
    yes('A5-22 and a notice says what is happening', (await liveToasts(page)).some((t) => /Downloading/.test(t) && /SSHSpan will close/.test(t)), JSON.stringify(await liveToasts(page)));
    await letGo(page, 'update_download_and_run');
    await page.waitForTimeout(150);
    check('no page errors', app.errors, []);
  });

  await withApp(browser, server, { replies: { update_check: UPDATE, update_download_and_run: { $reject: UAC } } }, 'A5-22 an installer that does not start', async (app) => {
    const { page } = app;
    await page.evaluate(() => { window.__u = manualUpdateCheck(); });
    if (await waitVisible(page, '#confirmModal', 1000)) await answerConfirm(page, 'ok');
    await settled(page, () => window.__u, null, 2000);
    await page.waitForTimeout(100);
    check('RU5 the backend\'s reason is shown as it is', (await liveToasts(page)).filter((t) => t === UAC).length, 1);
    yes('A5-22 and the "downloading" notice is gone', !(await liveToasts(page)).some((t) => /Downloading/.test(t)), JSON.stringify(await liveToasts(page)));
    check('no page errors', app.errors, []);
  });

  const NO_ASSET = { available: false, newerVersion: '2.0.0', current: '1.9.1', version: '2.0.0', notes: '', assetUrl: null, assetDigest: null };
  const LATEST = { available: false, newerVersion: null, current: '1.9.1', version: '1.9.1', notes: '', assetUrl: null, assetDigest: null };
  await withApp(browser, server, { replies: { update_check: NO_ASSET } }, 'A2-41 a release without an installer for this platform', async (app) => {
    const { page } = app;
    await page.evaluate(() => manualUpdateCheck());
    await page.waitForTimeout(100);
    check('A2-41 says so, instead of "you are on the latest version"', await liveToasts(page), ['Version 2.0.0 exists but has no installer for this platform.']);
    await page.evaluate((r) => { window.__replies.update_check = r; }, LATEST);
    await page.evaluate(() => manualUpdateCheck());
    await page.waitForTimeout(100);
    yes('and "latest" when nothing newer exists', (await liveToasts(page)).includes('You are on the latest version (1.9.1).'), JSON.stringify(await liveToasts(page)));
    await page.evaluate(() => switchView('settings'));
    await page.waitForSelector('#settingsRows .settings-row');
    await hold(page, 'update_check');
    const n = await app.count('update_check');
    await updateButton(page).dblclick();
    await page.waitForTimeout(120);
    check('A2-18 a double click on "Check now" checks once', (await app.count('update_check')) - n, 1);
    await letGo(page, 'update_check');
    check('no page errors', app.errors, []);
  });
}

// ─── item 7: Bitwarden sync ─────────────────────────────────────────────────

async function bwOpen(page) {
  await page.evaluate(() => switchView('settings'));
  await page.evaluate(() => showSettingsSection('sync'));
  await page.waitForSelector('#bw_master_password', { state: 'attached' });
}
const bwHint = (page) => page.evaluate(() => {
  const h = document.getElementById('bwPasswordHint');
  return h && !h.hidden ? h.textContent : '';
});
const bwStatus = (page) => page.evaluate(() => ({ text: el('bwStatus').textContent, cls: el('bwStatus').className }));

async function scenarioBwForm(browser, server) {
  await withApp(browser, server, { replies: { bitwarden_get_config: BW_CONFIG } }, 'A5-35 / A8-25 the stored-password hint', async (app) => {
    const { page } = app;
    await bwOpen(page);
    const caption = await page.evaluate(() => {
      const id = el('bw_master_password').getAttribute('aria-labelledby');
      return id ? document.getElementById(id).textContent.trim() : '';
    });
    check('A8-25 the field is captioned "Master password"', caption, 'Master password');
    yes('A5-35 a stored password is announced, and blank keeps it', /stored - leave blank to keep it/i.test(await bwHint(page)), await bwHint(page));
    check('A5-35 the hint describes the field', await page.evaluate(() =>
      (el('bw_master_password').getAttribute('aria-describedby') || '').split(' ').includes('bwPasswordHint')), true);
    await setValue(page, '#bw_email', 'other@example.com');
    yes('RU5 changing the account says a password is needed', /needed/i.test(await bwHint(page)), await bwHint(page));
    await setValue(page, '#bw_email', 'me@example.com');
    yes('back on the saved account, blank keeps the stored one again', /leave blank to keep it/i.test(await bwHint(page)), await bwHint(page));
    await setValue(page, '#bw_server_url', 'https://other.example.com');
    yes('RU5 changing the server says so too', /needed/i.test(await bwHint(page)), await bwHint(page));
    check('no page errors', app.errors, []);
  });
}

async function scenarioBwTest(browser, server) {
  const OK = { ok: true, server: 'https://vault.example.com', account: 'me@example.com', kdf: { type: 0, iterations: 600000 }, sshItemCount: 3, folders: [] };
  const replies = { bitwarden_get_config: BW_CONFIG, bitwarden_test_connection: OK, bitwarden_save_config: { ok: true, confirmed: true, warning: null } };
  await withApp(browser, server, { replies }, 'A2-52 / A2-18 Test and Save', async (app) => {
    const { page } = app;
    await bwOpen(page);
    await page.click('#bwTestBtn');
    await page.waitForTimeout(150);
    check('A2-52 Test sends what the form shows (a blank password: the stored one, where the backend allows)',
      await lastArgs(app, 'bitwarden_test_connection'), { serverUrl: 'https://vault.example.com', email: 'me@example.com' });
    const status = await page.textContent('#bwStatus');
    yes('A2-52 the result names the server and the account it tested', status.includes('https://vault.example.com') && status.includes('me@example.com'), status);
    await setValue(page, '#bw_master_password', 'typed-pw');
    await page.click('#bwTestBtn');
    await page.waitForTimeout(150);
    check('A2-52 a typed password is what gets tested', (await lastArgs(app, 'bitwarden_test_connection')).masterPassword, 'typed-pw');
    const refusal = 'Enter the vault master password to test a different server or account.';
    await page.evaluate((m) => { window.__replies.bitwarden_test_connection = { $reject: m }; }, refusal);
    await setValue(page, '#bw_master_password', '');
    await page.click('#bwTestBtn');
    await page.waitForTimeout(150);
    check('RU5 a refusal is shown as it is', await page.textContent('#bwStatus'), refusal);
    for (const [btn, cmd] of [['#bwTestBtn', 'bitwarden_test_connection'], ['#bwSaveBtn', 'bitwarden_save_config']]) {
      await hold(page, cmd);
      const n = await app.count(cmd);
      await page.dblclick(btn);
      await page.waitForTimeout(120);
      check(`A2-18 a double click on ${btn} sends one ${cmd}`, (await app.count(cmd)) - n, 1);
      await letGo(page, cmd);
      await page.waitForTimeout(150);
    }
    check('no page errors', app.errors, []);
  });
}

async function scenarioBwSync(browser, server) {
  const WITH_ERRORS = {
    ok: true, pushed: 1, pulled: 0, updatedRemote: 0, updatedLocal: 0, linked: 0, conflicts: 0, remoteDeleted: 1,
    serversPushed: 2, serversPulled: 0, serversUpdatedRemote: 0, serversUpdatedLocal: 0,
    errors: [
      { name: 'alpha', error: 'could not decrypt the item\'s name' },
      { server: 'web-1', error: 'push failed <img src=x onerror="window.__xss=1">' },
      { folder: 'SSHSpan', error: 'could not rename the old folder' },
      { cipher_id: 'c-9', error: 'older copy - not imported.' },
    ],
  };
  await withApp(browser, server, { replies: { bitwarden_get_config: BW_CONFIG, bitwarden_sync: WITH_ERRORS } }, 'A2-08 / A7-24 a sync with errors', async (app) => {
    const { page } = app;
    await bwOpen(page);
    await page.click('#bwSyncNowBtn');
    await page.waitForTimeout(250);
    const st = await bwStatus(page);
    yes('A2-08 a sync with errors is not reported as clean: the status warns', /\bwarn\b|\berr\b/.test(st.cls), st.cls);
    yes('A2-08 and says how many failed', /4 errors/.test(st.text), st.text);
    yes('A7-24 the server counters are shown', /Servers:[^.]*2 pushed/.test(st.text), st.text);
    yes('A7-24 so are linked items gone from Bitwarden', /1 [^.]*gone from Bitwarden/.test(st.text), st.text);
    check('A2-08 every error is listed with what it is about', await page.evaluate(() => [...document.querySelectorAll('#bwErrors li')].map((li) => li.textContent)), [
      'alpha: could not decrypt the item\'s name', 'web-1: push failed <img src=x onerror="window.__xss=1">',
      'SSHSpan: could not rename the old folder', 'c-9: older copy - not imported.']);
    check('the error texts stay text, never markup', await page.evaluate(() => [document.querySelectorAll('#bwErrors img').length, window.__xss || 0]), [0, 0]);
    const t = await liveToasts(page);
    yes('A2-08 no "Sync complete." toast', !t.includes('Sync complete.'), JSON.stringify(t));
    yes('A2-08 a warning toast says it finished with errors', t.some((x) => /4 errors/.test(x)), JSON.stringify(t));
    check('no page errors', app.errors, []);
  });

  const ABORTED = { ok: false, aborted: 'Vault was locked; sync aborted.', pushed: 1, errors: [] };
  await withApp(browser, server, { replies: { bitwarden_get_config: BW_CONFIG, bitwarden_sync: ABORTED } }, 'RU5 a sync stopped part-way', async (app) => {
    const { page } = app;
    await bwOpen(page);
    await page.click('#bwSyncNowBtn');
    await page.waitForTimeout(250);
    const st = await bwStatus(page);
    yes('RU5 a stopped run is a failure, with its reason', /\berr\b|\bwarn\b/.test(st.cls) && st.text.includes('Vault was locked; sync aborted.'), JSON.stringify(st));
    yes('RU5 and what it did before it stopped', /1 pushed/.test(st.text), st.text);
    yes('RU5 never "Sync complete."', !(await liveToasts(page)).includes('Sync complete.'), JSON.stringify(await liveToasts(page)));
    check('no page errors', app.errors, []);
  });

  await withApp(browser, server, { replies: { bitwarden_get_config: BW_CONFIG } }, 'A2-47 the confirmation covers servers', async (app) => {
    const { page } = app;
    await page.evaluate(() => {
      window.__replies.bitwarden_sync = (a) => (a.allowRemoteOverwrite
        ? { ok: true, serversPulled: 3, errors: [] }
        : { ok: true, skippedServerOverwrites: 1, skippedServerNew: 2, errors: [] });
    });
    await bwOpen(page);
    await page.click('#bwSyncNowBtn');
    const asked = await waitVisible(page, '#confirmModal', 1000);
    yes('A2-47 server changes from Bitwarden wait for approval', asked);
    if (asked) {
      const c = await confirmText(page);
      yes('A2-47 the question names the server overwrites and the new servers', /1 server/.test(c.message) && /2 new servers/.test(c.message), c.message);
      await answerConfirm(page, 'ok');
    }
    await page.waitForTimeout(250);
    check('A2-47 and OK applies them', (await app.calls('bitwarden_sync')).map((c) => c.args.allowRemoteOverwrite), [false, true]);
    yes('the applied run is reported', /3 pulled/.test((await bwStatus(page)).text), (await bwStatus(page)).text);
    check('no page errors', app.errors, []);
  });

  await withApp(browser, server, { replies: { bitwarden_get_config: BW_CONFIG, bitwarden_sync: { ok: true, errors: [] } } }, 'a clean sync', async (app) => {
    const { page } = app;
    await bwOpen(page);
    await page.click('#bwSyncNowBtn');
    await page.waitForTimeout(250);
    check('nothing to do reads as such', (await bwStatus(page)).text, 'Nothing to sync.');
    yes('and is complete', (await liveToasts(page)).includes('Sync complete.'), JSON.stringify(await liveToasts(page)));
    check('no page errors', app.errors, []);
  });
}

// ─── Bitwarden: the last result, the approval token, the lock gates ─────────

async function scenarioBwLastResult(browser, server) {
  const cfg = (lastResult) => Object.assign({}, BW_CONFIG, { last_sync: '2026-10-12T08:30:00Z', last_result: lastResult });
  const STOPPED = { ok: false, aborted: 'Vault was locked; sync aborted.', pushed: 1, errors: [] };
  await withApp(browser, server, { replies: { bitwarden_get_config: cfg(STOPPED) } }, 'the last run stopped part-way', async (app) => {
    const { page } = app;
    await bwOpen(page);
    const st = await bwStatus(page);
    check('a last run that stopped says so, with its reason, as an error',
      [st.text, /\berr\b/.test(st.cls)], ['Last sync stopped: Vault was locked; sync aborted.', true]);
    check('no page errors', app.errors, []);
  });
  const ERRORS = { ok: true, pushed: 2, errors: [{ name: 'alpha', error: 'could not decrypt the item\'s name' }, { server: 'web-1', error: 'push failed' }] };
  await withApp(browser, server, { replies: { bitwarden_get_config: cfg(ERRORS) } }, 'the last run had errors', async (app) => {
    const { page } = app;
    await bwOpen(page);
    const st = await bwStatus(page);
    yes('a last run with errors counts them, as a warning', /2 errors/.test(st.text) && /\bwarn\b/.test(st.cls), JSON.stringify(st));
    yes('and still says when it ran', st.text.startsWith('Last synced: '), st.text);
    check('its errors are listed', await page.evaluate(() => [...document.querySelectorAll('#bwErrors li')].map((li) => li.textContent)),
      ['alpha: could not decrypt the item\'s name', 'web-1: push failed']);
    check('no page errors', app.errors, []);
  });
  // J1: a failed item's name and reason are text from outside - spelled out,
  // each in a <bdi> of its own - so an item title cannot turn the advice
  // after it around.
  const RLO = '\u{202E}';
  const TURNING = { ok: true, pushed: 1, errors: [
    { name: `evil${RLO}txt.exe`, error: `the item evil${RLO}gpj claims a fingerprint that does not match its key - not imported.` },
    { error: `${RLO}not imported` },
  ] };
  await withApp(browser, server, { replies: { bitwarden_get_config: cfg(TURNING) } }, 'J1 a failed item named to turn the advice around', async (app) => {
    const { page } = app;
    await bwOpen(page);
    const items = await page.evaluate(() => [...document.querySelectorAll('#bwErrors li')].map((li) => ({
      text: li.textContent, parts: [...li.querySelectorAll('bdi')].map((b) => b.textContent),
    })));
    check('J1 no direction character reaches the error list', items.some((i) => i.text.includes(RLO)), false);
    check('J1 the name and the reason each sit in a <bdi> of their own, spelled out', items.map((i) => i.parts), [
      ['evil<U+202E>txt.exe', 'the item evil<U+202E>gpj claims a fingerprint that does not match its key - not imported.'],
      ['<U+202E>not imported'],
    ]);
    check('J1 read as one line each, as before', items.map((i) => i.text), [
      'evil<U+202E>txt.exe: the item evil<U+202E>gpj claims a fingerprint that does not match its key - not imported.',
      '<U+202E>not imported',
    ]);
    check('no page errors', app.errors, []);
  });
  await withApp(browser, server, { replies: { bitwarden_get_config: cfg({ ok: true, pushed: 1, errors: [] }) } }, 'the last run was clean', async (app) => {
    const { page } = app;
    await bwOpen(page);
    const st = await bwStatus(page);
    yes('a clean last run reads "Last synced"', st.text.startsWith('Last synced: ') && !/error/.test(st.text), JSON.stringify(st));
    check('with no error list', await page.evaluate(() => document.getElementById('bwErrors').hidden), true);
    check('no page errors', app.errors, []);
  });
}

async function scenarioBwApproval(browser, server) {
  const LIST = (token, name) => ({
    ok: true, errors: [], skippedServerOverwrites: 1, approvalToken: token,
    pendingServers: [{ kind: 'overwrite', name, incomingName: name, host: '10.0.0.9', port: 22, localHost: '10.0.0.1', localPort: 22,
      changes: ['name', 'host', 'category'] }],
    pendingKeys: [],
  });
  await withApp(browser, server, { replies: { bitwarden_get_config: BW_CONFIG } }, 'S4 an approval carries the token of the list it approves', async (app) => {
    const { page } = app;
    await page.evaluate(({ first, second }) => {
      let n = 0;
      window.__replies.bitwarden_sync = (a) => {
        n += 1;
        if (!a.allowRemoteOverwrite) return first;
        // The list changed between the question and the Apply: nothing is
        // applied, the new list and its token come back (approvalStale).
        if (a.approvalToken === 'tok-1') return Object.assign({}, second, { approvalStale: true });
        if (a.approvalToken === 'tok-2') return { ok: true, serversPulled: 1, errors: [] };
        return { ok: true, errors: [] };
      };
    }, { first: LIST('tok-1', 'web-1'), second: LIST('tok-2', 'web-2') });
    await bwOpen(page);
    await page.click('#bwSyncNowBtn');
    yes('(set-up) the approval is asked', await waitVisible(page, '#confirmModal', 1500));
    const list1 = await page.evaluate(() => (document.querySelector('#confirmModal .bw-pending') || {}).textContent || '');
    yes('S6 the changes name a rename and a new category too', /changes: name, host, host category/.test(list1), list1);
    await answerConfirm(page, 'ok');
    yes('S4 a list that changed meanwhile is shown again, and asked again', await waitVisible(page, '#confirmModal', 1500));
    const list2 = await page.evaluate(() => (document.querySelector('#confirmModal .bw-pending') || {}).textContent || '');
    yes('with the new list', /web-2/.test(list2) && !/web-1/.test(list2), list2);
    const msg2 = await page.textContent('#confirmMessage');
    yes('saying the list changed', /changed/i.test(msg2), msg2);
    await answerConfirm(page, 'ok');
    await page.waitForTimeout(250);
    check('S4 each Apply sends back the token of exactly the list it showed',
      (await app.calls('bitwarden_sync')).map((c) => [c.args.allowRemoteOverwrite, c.args.approvalToken || null]),
      [[false, null], [true, 'tok-1'], [true, 'tok-2']]);
    yes('the applied run is reported', /1 pulled/.test((await bwStatus(page)).text), (await bwStatus(page)).text);
    check('no page errors', app.errors, []);
  });

  // Every Apply meets another list (approvalStale each time): asked three
  // times, then said - nothing from Bitwarden was applied - where it used to
  // read "Sync complete.".
  const KEPT_CHANGING = 'The changes in Bitwarden changed each time you applied them, so nothing from Bitwarden was applied - sync again to review them.';
  await withApp(browser, server, { replies: { bitwarden_get_config: BW_CONFIG } }, 'S4 a list that changes at every Apply', async (app) => {
    const { page } = app;
    await page.evaluate((list) => {
      let n = 0;
      window.__replies.bitwarden_sync = (a) => {
        n += 1;
        const entry = Object.assign({}, list.pendingServers[0], { name: 'web-' + n, incomingName: 'web-' + n });
        return Object.assign({}, list, { approvalToken: 'tok-' + n, pendingServers: [entry] }, a.allowRemoteOverwrite ? { approvalStale: true } : {});
      };
    }, LIST('tok-0', 'web-0'));
    await bwOpen(page);
    await page.click('#bwSyncNowBtn');
    let asked = 0;
    while (asked < 5 && await waitVisible(page, '#confirmModal', 1500)) {
      asked += 1;
      await answerConfirm(page, 'ok');
    }
    await page.waitForTimeout(250);
    check('asked three times, each Apply with the token of the list it showed, then no more',
      [asked, (await app.calls('bitwarden_sync')).map((c) => [c.args.allowRemoteOverwrite, c.args.approvalToken || null])],
      [3, [[false, null], [true, 'tok-1'], [true, 'tok-2'], [true, 'tok-3']]]);
    const st = await bwStatus(page);
    yes('then it says nothing from Bitwarden was applied, as a warning', st.text.includes(KEPT_CHANGING) && /\bwarn\b/.test(st.cls), JSON.stringify(st));
    const said = await liveToasts(page);
    yes('and its toast says so, not "Sync complete."', said.includes(KEPT_CHANGING) && !said.includes('Sync complete.'), JSON.stringify(said));
    check('no page errors', app.errors, []);
  });
  await withApp(browser, server, { replies: { bitwarden_get_config: BW_CONFIG } }, 'S4 a changed list declined', async (app) => {
    const { page } = app;
    await page.evaluate((list) => {
      let n = 0;
      window.__replies.bitwarden_sync = (a) => {
        n += 1;
        return Object.assign({}, list, { approvalToken: 'tok-' + n }, a.allowRemoteOverwrite ? { approvalStale: true } : {});
      };
    }, LIST('tok-0', 'web-1'));
    await bwOpen(page);
    await page.click('#bwSyncNowBtn');
    yes('(set-up) the approval is asked', await waitVisible(page, '#confirmModal', 1500));
    await answerConfirm(page, 'ok');
    yes('(set-up) the changed list is asked about', await waitVisible(page, '#confirmModal', 1500));
    await answerConfirm(page, 'cancel');
    await page.waitForTimeout(250);
    const st = await bwStatus(page);
    yes('declining the changed list is a plain decline: not said to have kept changing',
      !st.text.includes(KEPT_CHANGING) && /Not applied/.test(st.text), JSON.stringify(st));
    check('no page errors', app.errors, []);
  });

  // A name that is blank after cleaning (U+2800 shows as nothing) reads
  // "(blank name)" with its characters spelled out - never as nothing at all.
  await withApp(browser, server, { replies: { bitwarden_get_config: BW_CONFIG } }, 'I3 a Bitwarden name that shows nothing', async (app) => {
    const { page } = app;
    await page.evaluate((list) => {
      window.__replies.bitwarden_sync = (a) => (a.allowRemoteOverwrite ? { ok: true, errors: [] } : list);
    }, LIST('tok-1', '\u{2800}\u{2800}\u{2800}'));
    await bwOpen(page);
    await page.click('#bwSyncNowBtn');
    yes('(set-up) the approval is asked', await waitVisible(page, '#confirmModal', 1500));
    const entry = await page.evaluate(() => ([...document.querySelectorAll('#confirmModal .bw-pending li')][0] || {}).textContent || '');
    yes('I3 a name blank after cleaning reads "(blank name)" with its characters spelled out',
      entry.startsWith('(blank name) <U+2800><U+2800><U+2800>: '), entry);
    await answerConfirm(page, 'cancel');
    // MUSICAL SYMBOL NULL NOTEHEAD shows as nothing too.
    check('I3 so does a name of U+1D159', await page.evaluate(() => bwName('\u{1D159}\u{1D159}')), '(blank name) <U+1D159><U+1D159>');
    check('no page errors', app.errors, []);
  });
  // The "Renamed:" part of the status line names items as the list does.
  await withApp(browser, server, { replies: { bitwarden_get_config: BW_CONFIG } }, 'I3 a blank name in the Renamed line', async (app) => {
    const { page } = app;
    await page.evaluate(() => {
      window.__replies.bitwarden_sync = { ok: true, pulled: 1, errors: [], renamed: [{ name: '\u{2800}\u{2800}', storedAs: 'web' }] };
    });
    await bwOpen(page);
    await page.click('#bwSyncNowBtn');
    await page.waitForTimeout(250);
    const st = (await bwStatus(page)).text.replace(/[\u{2068}\u{2069}]/gu, '');
    yes('I3 a blank name in the Renamed line reads "(blank name)" spelled out', st.includes('Renamed: (blank name) <U+2800><U+2800> stored as web.'), st);
    check('no page errors', app.errors, []);
  });

  const REFUSED = 'Too many changes to review at once (612) - nothing from Bitwarden was applied. SSHSpan can show at most 500 server and 500 key changes for approval: bring the new or changed items in Bitwarden below that, then sync again.';
  await withApp(browser, server, { replies: { bitwarden_get_config: BW_CONFIG } }, 'S4 a list too long to review cannot be approved', async (app) => {
    const { page } = app;
    await page.evaluate((m) => {
      window.__replies.bitwarden_sync = () => ({ ok: true, errors: [], skippedServerOverwrites: 612, pendingTruncated: true,
        pendingServers: [{ kind: 'overwrite', name: 'web-1', incomingName: 'web-1', host: 'h', port: 22, localHost: 'h0', localPort: 22, changes: ['host'] }],
        pendingKeys: [], approvalRefused: m });
    }, REFUSED);
    await bwOpen(page);
    await page.click('#bwSyncNowBtn');
    await page.waitForTimeout(300);
    check('no Apply question is offered', await app.open('confirmModal'), false);
    const st = await bwStatus(page);
    yes('the refusal is said as the backend words it', st.text.includes(REFUSED) && /\bwarn\b|\berr\b/.test(st.cls), JSON.stringify(st));
    check('and nothing is sent to apply', (await app.calls('bitwarden_sync')).map((c) => !!c.args.allowRemoteOverwrite), [false]);
    check('no page errors', app.errors, []);
  });
}

async function scenarioSettingsLockGates(browser, server) {
  await withApp(browser, server, { replies: { bitwarden_get_config: BW_CONFIG } }, 'A6-08 settings buttons that need the vault', async (app) => {
    const { page } = app;
    await bwOpen(page);
    const read = () => page.evaluate(() => ['bwSaveBtn', 'bwTestBtn', 'bwSyncNowBtn', 'backupExportBtn', 'backupImportBtn', 'lockBtn']
      .map((id) => [id, el(id).disabled, el(id).disabled ? el(id).title : '']));
    check('unlocked: all of them work', (await read()).map(([id, d]) => [id, d]),
      [['bwSaveBtn', false], ['bwTestBtn', false], ['bwSyncNowBtn', false], ['backupExportBtn', false], ['backupImportBtn', false], ['lockBtn', false]]);
    await page.evaluate(() => { window.__backend.unlocked = false; return refreshVaultStatus(); });
    await page.waitForTimeout(150);
    if (await app.open('vaultModal')) await page.click('#vaultCancelBtn');
    check('locked: each is disabled and says why', await read(), [
      ['bwSaveBtn', true, 'Unlock the vault to save, test or run the Bitwarden sync.'],
      ['bwTestBtn', true, 'Unlock the vault to save, test or run the Bitwarden sync.'],
      ['bwSyncNowBtn', true, 'Unlock the vault to save, test or run the Bitwarden sync.'],
      ['backupExportBtn', true, 'Unlock the vault to create or restore a backup.'],
      ['backupImportBtn', true, 'Unlock the vault to create or restore a backup.'],
      ['lockBtn', true, 'The vault is already locked.'],
    ]);
    await page.evaluate(() => { window.__backend.unlocked = true; return refreshVaultStatus(); });
    await page.waitForTimeout(150);
    check('unlocked again: they work again', (await read()).map(([, d]) => d), [false, false, false, false, false, false]);
    check('no page errors', app.errors, []);
  });
  // With no vault at all there is nothing locked - and nothing to lock.
  await withApp(browser, server, { hasVault: false, unlocked: false }, 'Lock now with no vault yet', async (app) => {
    const { page } = app;
    await page.waitForTimeout(150);
    if (await app.open('vaultModal')) await page.click('#vaultCancelBtn');
    check('with no vault yet, Lock now says there is no vault to lock', await page.evaluate(() => [el('lockBtn').disabled, el('lockBtn').title]),
      [true, 'There is no vault to lock yet.']);
    check('no page errors', app.errors, []);
  });

  const W = 'The sync settings were saved, but their audit row could not be written: disk I/O error';
  await withApp(browser, server, { replies: { bitwarden_get_config: BW_CONFIG, bitwarden_save_config: { ok: true, confirmed: true, warning: W } } }, 'B1 the sync settings saved without their audit row', async (app) => {
    const { page } = app;
    await bwOpen(page);
    await page.click('#bwSaveBtn');
    await page.waitForTimeout(200);
    yes('the warning is shown as it is', (await liveToasts(page)).includes(W), JSON.stringify(await liveToasts(page)));
    check('once: the save did happen', await app.count('bitwarden_save_config'), 1);
    check('no page errors', app.errors, []);
  });
}

// ─── J5 (A5-42): a new server while a host category filters the list ───────
//
// The New server dialog starts in the active host category (as New key does
// in the key category), and a saved server the filter still hides is said
// to be hidden, in the key version's words - it read as plainly "saved" and
// was nowhere in the list.

async function scenarioServerNewInFilter(browser, server) {
  const categories = [CATEGORY_KEY,
    { id: 'h1', name: 'EU', parent_id: null, scope: 'host', sort_index: 0, color: null },
    { id: 'h2', name: 'US', parent_id: null, scope: 'host', sort_index: 1, color: null }];
  const servers = [Object.assign(SERVER('s1', 'web-1'), { categoryId: 'h1' }), SERVER('s2', 'db-1')];
  const HIDDEN = 'Server saved - it is hidden by the current filter. Clear the filter to see it.';
  // server_save as the backend does it: the saved server is in the next server_list.
  const stubSaves = (page) => page.evaluate((list) => {
    window.__servers = list;
    window.__replies.server_list = () => ({ servers: window.__servers });
    window.__replies.server_save = (a) => {
      const id = a.id || 's-new-' + window.__servers.length;
      window.__servers = window.__servers.filter((s) => s.id !== id).concat([{
        id, name: a.name, host: a.host, port: a.port, username: a.username, authMethod: a.authMethod,
        hasSavedPassword: false, categoryId: a.categoryId || null, keyId: a.keyId, pemPath: a.pemPath,
      }]);
      // As the contract has it (fw-rust-report.txt 7): no warning here.
      return { ok: true, id, warning: null };
    };
  }, servers);
  const newServer = async (page, name) => {
    await page.evaluate(() => { openServerModal({}); setConnectAuthMethod('password'); });
    await setValue(page, '#srvName', name);
    await setValue(page, '#srvHost', name + '.example');
    await setValue(page, '#srvUser', 'ops');
  };
  const chips = (page) => page.evaluate(() => [state._pendingServerCategory, [...document.querySelectorAll('#srvCategory .cat-chip')].map((c) => c.textContent.trim())]);
  const names = (page) => page.evaluate(() => [...document.querySelectorAll('#serverList .server-row .server-name')].map((n) => n.textContent));
  const lastToast = async (page) => (await liveToasts(page)).slice(-1)[0];
  await withApp(browser, server, { servers, categories }, 'J5 a new server while the list is filtered by a host category', async (app) => {
    const { page } = app;
    await stubSaves(page);
    await serversView(page);
    await page.evaluate(() => setActiveCategory('h1'));
    await page.waitForTimeout(80);
    await newServer(page, 'eu-2');
    const [pending, shown] = await chips(page);
    check('J5 the New server dialog starts in the active host category', [pending, shown.some((t) => /EU/.test(t))], ['h1', true]);
    check('J5 and saves the server there', ((await saveServerForm(app)) || {}).categoryId, 'h1');
    await page.waitForTimeout(150);
    check('J5 so it appears in the filtered list', (await names(page)).includes('eu-2'), true);
    check('J5 and the toast is a plain "saved"', await lastToast(page), 'Server saved.');
    // The user chooses another category, or none: the server the filter hides
    // is said to be hidden.
    await newServer(page, 'us-1');
    await page.evaluate(() => { state._pendingServerCategory = 'h2'; renderServerCategoryChips(); });
    check('(set-up) saved in US', ((await saveServerForm(app)) || {}).categoryId, 'h2');
    await page.waitForTimeout(150);
    check('J5 a server saved into another category is said to be hidden', [(await names(page)).includes('us-1'), await lastToast(page)], [false, HIDDEN]);
    await newServer(page, 'none-1');
    await page.evaluate(() => { state._pendingServerCategory = null; renderServerCategoryChips(); });
    check('(set-up) saved in no category', ((await saveServerForm(app)) || {}).categoryId, null);
    await page.waitForTimeout(150);
    check('J5 and so is one saved in none', [(await names(page)).includes('none-1'), await lastToast(page)], [false, HIDDEN]);
    // An edited server keeps its own category - none stays none, though the
    // list is filtered by EU.
    await page.evaluate(() => openServerModal({ id: 's2' }));
    check('J5 editing a server keeps its own category (none), not the active one', (await chips(page))[0], null);
    await page.evaluate(() => closeServerModal());
    check('no page errors', app.errors, []);
  });
  await withApp(browser, server, { servers, categories }, 'J5 a new server with no filter', async (app) => {
    const { page } = app;
    await stubSaves(page);
    await serversView(page);
    await newServer(page, 'plain-1');
    check('J5 with no filter the dialog starts in no category', (await chips(page))[0], null);
    check('J5 and saves the server in none', ((await saveServerForm(app)) || {}).categoryId, null);
    await page.waitForTimeout(150);
    check('J5 it is in the list, and the toast is a plain "saved"', [(await names(page)).includes('plain-1'), await lastToast(page)], [true, 'Server saved.']);
    // "Uncategorized" is no category to start in, and a server in none is shown there.
    await page.evaluate(() => setActiveCategory('uncategorized'));
    await page.waitForTimeout(80);
    await newServer(page, 'plain-2');
    check('J5 the Uncategorized filter preselects nothing', (await chips(page))[0], null);
    await saveServerForm(app);
    await page.waitForTimeout(150);
    check('J5 and the server saved in none is in that list', [(await names(page)).includes('plain-2'), await lastToast(page)], [true, 'Server saved.']);
    check('no page errors', app.errors, []);
  });
}

// ─── J6 (A5-26): a server saved with a warning ─────────────────────────────
//
// server_save's result carries `warning` when the server uses a key file
// protected by a passphrase, which SSHSpan cannot ask for when connecting
// (fw-rust-report.txt, RENDERER CONTRACT 7). The server is saved either way:
// the save says so as before (the J5 "hidden by the current filter" text
// included), and the warning follows as a warning toast of its own, in the
// backend's words, spelled out - from the server dialog, and so from the ssh
// config import, which saves through it.

const PASSPHRASE_KEY = 'This key file is protected by a passphrase, which SSHSpan cannot ask for when connecting. Import it under Keys (New key > Import asks for the passphrase) and choose that key for this server, or remove the passphrase from the file.';

async function scenarioServerSaveWarning(browser, server) {
  const categories = [CATEGORY_KEY,
    { id: 'h1', name: 'EU', parent_id: null, scope: 'host', sort_index: 0, color: null },
    { id: 'h2', name: 'US', parent_id: null, scope: 'host', sort_index: 1, color: null }];
  const servers = [Object.assign(SERVER('s1', 'web-1'), { categoryId: 'h1' })];
  // server_save as the backend does it - the saved server is in the next
  // server_list - answering with the warning given (null: none).
  const stubSaves = (page, warning) => page.evaluate(({ list, w }) => {
    window.__servers = window.__servers || list;
    window.__replies.server_list = () => ({ servers: window.__servers });
    window.__replies.server_save = (a) => {
      const id = a.id || 's-new-' + window.__servers.length;
      window.__servers = window.__servers.filter((s) => s.id !== id).concat([{
        id, name: a.name, host: a.host, port: a.port, username: a.username, authMethod: a.authMethod,
        hasSavedPassword: false, categoryId: a.categoryId || null, keyId: a.keyId, pemPath: a.pemPath,
      }]);
      return { ok: true, id, warning: w };
    };
  }, { list: servers, w: warning });
  // A new server signing in with a key file (a new server signs in with a key).
  const newServer = async (page, name) => {
    await page.evaluate(() => openServerModal({}));
    await setValue(page, '#srvName', name);
    await setValue(page, '#srvHost', name + '.example');
    await setValue(page, '#srvUser', 'ops');
    await setValue(page, '#srvPemPath', '/home/u/keys/' + name + '.pem');
  };
  const clearToasts = (page) => page.evaluate(() => [...document.querySelectorAll('#toast .toast-item')].forEach((t) => t.remove()));
  // The toasts on screen, oldest first, each as [kind, text] - with its count
  // badge (" ×2") when the same message came twice, so each is said once.
  const said = (page) => page.evaluate(() => [...document.querySelectorAll('#toast .toast-item:not(.leaving)')]
    .map((n) => {
      const badge = n.querySelector('.toast-count');
      return [['ok', 'warn', 'err', 'info'].find((k) => n.classList.contains(k)) || '?',
        n.querySelector('.toast-text').textContent + (badge ? ' ' + badge.textContent : '')];
    }));
  const save = async (app) => {
    await clearToasts(app.page);
    const sent = await saveServerForm(app);
    await app.page.waitForTimeout(150);
    return sent;
  };
  await withApp(browser, server, { servers, categories }, 'J6 a server saved from the dialog, with a warning', async (app) => {
    const { page } = app;
    await serversView(page);
    await stubSaves(page, PASSPHRASE_KEY);
    await newServer(page, 'enc-1');
    check('(set-up) the server is saved with its key file', ((await save(app)) || {}).pemPath, '/home/u/keys/enc-1.pem');
    check('J6 saved as before, then the warning as a warning toast, in the backend\'s words',
      await said(page), [['ok', 'Server saved.'], ['warn', PASSPHRASE_KEY]]);
    // The backend's words are text from outside: spelled out.
    await stubSaves(page, 'This key file \u{202E}mep.esrever is protected by a passphrase.');
    await newServer(page, 'enc-2');
    await save(app);
    check('J6 the warning is spelled out (no direction character reaches the toast)',
      await said(page), [['ok', 'Server saved.'], ['warn', 'This key file <U+202E>mep.esrever is protected by a passphrase.']]);
    // No warning: as before.
    await stubSaves(page, null);
    await newServer(page, 'plain-1');
    await save(app);
    check('J6 a save whose warning is null says "Server saved." alone, as before', await said(page), [['ok', 'Server saved.']]);
    check('no page errors', app.errors, []);
  });
  await withApp(browser, server, { servers, categories }, 'J6 hidden by the filter, and a warning', async (app) => {
    const { page } = app;
    await serversView(page);
    await stubSaves(page, PASSPHRASE_KEY);
    await page.evaluate(() => setActiveCategory('h1'));
    await page.waitForTimeout(80);
    await newServer(page, 'us-enc');
    await page.evaluate(() => { state._pendingServerCategory = 'h2'; renderServerCategoryChips(); });
    check('(set-up) saved into US, while the list shows EU', ((await save(app)) || {}).categoryId, 'h2');
    check('J6 both are said: hidden by the filter, and the warning',
      await said(page), [['ok', 'Server saved - it is hidden by the current filter. Clear the filter to see it.'], ['warn', PASSPHRASE_KEY]]);
    check('no page errors', app.errors, []);
  });
  // The ssh config import prefills the dialog, and its Save is the dialog's.
  const HOSTS = {
    hosts: [{ host: 'bastion', hostname: 'b.example', user: 'ops', port: 22, identity_file: '/home/u/.ssh/id_enc', identities_only: false, forward_agent: false, proxy_jump: null, extra: {} }],
    path: '/home/u/.ssh/config',
  };
  await withApp(browser, server, { servers, categories, replies: { ssh_config_list_hosts: HOSTS } }, 'J6 a server imported from ~/.ssh/config, with a warning', async (app) => {
    const { page } = app;
    await serversView(page);
    await stubSaves(page, PASSPHRASE_KEY);
    await page.click('#serverImportBtn');
    await page.waitForSelector('#keyConnectMenu .ctx-item');
    yes('(set-up) the host opens the server form', (await clickMenuItem(page, /^bastion/)) && await waitVisible(page, '#serverModal'));
    check('(set-up) saved with the key file of its Host block', ((await save(app)) || {}).pemPath, '/home/u/.ssh/id_enc');
    check('J6 the imported server\'s save says the warning too', await said(page), [['ok', 'Server saved.'], ['warn', PASSPHRASE_KEY]]);
    check('no page errors', app.errors, []);
  });
}

// ─── J7: Bitwarden texts from the backend, spelled out ──────────────────────
//
// A backend sentence can quote a name the server or the page chose - an
// account email, a host, an item: shown with its direction and invisible
// characters spelled out ("<U+202E>"), so none can turn the rest around. A
// whole sentence cannot sit in a <bdi> around just the name; spelled out, it
// holds no control (as the Stop-editing question). The sync refusal and W8
// below are the backend's coming texts, each with a U+202E in what it quotes;
// the save refusal, the Test and "Allow syncing..." errors are made up around
// one.

async function scenarioBwSpelled(browser, server) {
  const RLO = '\u{202E}';
  const spelled = (t) => t.split(RLO).join('<U+202E>');
  const SYNC_OFF = `Bitwarden sync is off until you allow it to upload your keys and passwords to the account me${RLO}@example.com on vault.example.com. Use "Allow syncing..." in Settings > Bitwarden.`;
  const W8 = `Bitwarden sync stays off, because uploading to vault${RLO}.example.com was declined a moment ago. Wait 30 seconds, then use "Allow syncing..." in Settings > Bitwarden.`;
  const AUDIT = `The sync settings were saved, but their audit row could not be written: disk ${RLO}full`;
  const SAVE_REFUSAL = `Enter the Bitwarden account as one email address, like name@example.com - not me${RLO}@example.com.`;
  const clear = (page) => page.evaluate(() => [...document.querySelectorAll('#toast .toast-item')].forEach((t) => t.remove()));
  const warned = (page) => page.evaluate(() => [...document.querySelectorAll('#toast .toast-item.warn .toast-text')].map((t) => t.textContent));
  const shown = async (page) => [(await bwStatus(page)).text, ...(await liveToasts(page))];
  const turned = async (page) => (await shown(page)).filter((t) => t.includes(RLO));
  const UNCONFIRMED = Object.assign({}, BW_CONFIG, { confirmed: false });

  await withApp(browser, server, { replies: { bitwarden_get_config: Object.assign({}, BW_CONFIG, {
    last_sync: '2026-10-12T08:30:00Z', last_result: { ok: false, aborted: `Stopped at the item evil${RLO}txt.exe.`, errors: [] },
  }) } }, 'J7 the last run stopped, its reason turning', async (app) => {
    const { page } = app;
    await bwOpen(page);
    check('J7 the last run\'s reason is spelled out', (await bwStatus(page)).text, 'Last sync stopped: Stopped at the item evil<U+202E>txt.exe.');
    check('no page errors', app.errors, []);
  });

  await withApp(browser, server, { replies: { bitwarden_get_config: BW_CONFIG } }, 'J7 the save\'s texts', async (app) => {
    const { page } = app;
    await bwOpen(page);
    const saveWith = async (reply) => {
      await clear(page);
      await page.evaluate((r) => { window.__replies.bitwarden_save_config = r; }, reply);
      await page.click('#bwSaveBtn');
      await page.waitForTimeout(250);
    };
    await saveWith({ $reject: SAVE_REFUSAL });
    check('J7 a save refused: the refusal spelled out', [(await liveToasts(page)).includes(spelled(SAVE_REFUSAL)), await turned(page)], [true, []]);
    await saveWith({ ok: true, confirmed: false, warning: W8 });
    check('J7 a save not allowed (W8): its warning spelled out', [await warned(page), await turned(page)], [[spelled(W8)], []]);
    await saveWith({ ok: true, confirmed: true, warning: AUDIT });
    check('J7 a save with an audit warning: saved, and the warning spelled out',
      [(await liveToasts(page)).includes('Bitwarden settings saved.'), await warned(page), await turned(page)], [true, [spelled(AUDIT)], []]);
    check('no page errors', app.errors, []);
  });

  await withApp(browser, server, { replies: { bitwarden_get_config: BW_CONFIG } }, 'J7 Test connection\'s texts', async (app) => {
    const { page } = app;
    await bwOpen(page);
    const REACH = `Could not reach vault${RLO}.example.com.`;
    await page.evaluate((m) => { window.__replies.bitwarden_test_connection = { $reject: m }; }, REACH);
    await page.click('#bwTestBtn');
    await page.waitForTimeout(250);
    check('J7 a failed Test: the error spelled out, in the status line and the toast',
      [(await bwStatus(page)).text, (await liveToasts(page)).includes(spelled(REACH)), await turned(page)], [spelled(REACH), true, []]);
    await clear(page);
    await page.evaluate((r) => { window.__replies.bitwarden_test_connection = { ok: true, server: 'https://vault' + r + '.example.com', account: 'me' + r + '@example.com', kdf: { type: 0, iterations: 600000 }, sshItemCount: 3, folders: [] }; }, RLO);
    await page.click('#bwTestBtn');
    await page.waitForTimeout(250);
    const st = (await bwStatus(page)).text;
    check('J7 a good Test: the account and server it names are spelled out',
      [st.includes('me<U+202E>@example.com on https://vault<U+202E>.example.com'), await turned(page)], [true, []]);
    check('no page errors', app.errors, []);
  });

  await withApp(browser, server, { replies: { bitwarden_get_config: UNCONFIRMED } }, 'J7 Allow syncing...\'s texts', async (app) => {
    const { page } = app;
    await bwOpen(page);
    const ASK = `Could not ask about vault${RLO}.example.com.`;
    await page.evaluate((m) => { window.__replies.bitwarden_allow_sync = { $reject: m }; }, ASK);
    await page.click('#bwAllowBtn');
    await page.waitForTimeout(250);
    check('J7 a refused Allow syncing...: the error spelled out', [(await bwStatus(page)).text, await turned(page)], [spelled(ASK), []]);
    await clear(page);
    await page.evaluate((w) => { window.__replies.bitwarden_allow_sync = { ok: true, confirmed: false, warning: w }; }, W8);
    await page.click('#bwAllowBtn');
    await page.waitForTimeout(250);
    check('J7 Allow syncing... not allowed (W8): the warning spelled out',
      [(await bwStatus(page)).text, await warned(page), await turned(page)], [spelled(W8), [spelled(W8)], []]);
    check('no page errors', app.errors, []);
  });

  await withApp(browser, server, { replies: { bitwarden_get_config: UNCONFIRMED, bitwarden_sync: { $reject: SYNC_OFF } } }, 'J7 a sync refused', async (app) => {
    const { page } = app;
    await bwOpen(page);
    await page.click('#bwSyncNowBtn');
    await page.waitForTimeout(250);
    check('J7 the sync refusal (with the account email) spelled out',
      [(await bwStatus(page)).text, (await liveToasts(page)).includes(spelled(SYNC_OFF)), await turned(page)], [spelled(SYNC_OFF), true, []]);
    check('no page errors', app.errors, []);
  });

  await withApp(browser, server, { replies: { bitwarden_get_config: BW_CONFIG } }, 'J7 a sync stopped, a list too long', async (app) => {
    const { page } = app;
    await bwOpen(page);
    const ABORTED = `The vault${RLO} was locked; sync aborted.`;
    await page.evaluate((m) => { window.__replies.bitwarden_sync = { ok: false, aborted: m, errors: [] }; }, ABORTED);
    await page.click('#bwSyncNowBtn');
    await page.waitForTimeout(250);
    check('J7 a stopped sync: its reason spelled out, in the status line and the toast',
      [(await bwStatus(page)).text, (await liveToasts(page)).includes('Bitwarden sync stopped: ' + spelled(ABORTED)), await turned(page)],
      ['Sync stopped: ' + spelled(ABORTED), true, []]);
    await clear(page);
    const REFUSED = `Too many changes to review at once (612) - nothing from Bitwarden was applied, item ${RLO}evil included.`;
    await page.evaluate((m) => {
      window.__replies.bitwarden_sync = () => ({ ok: true, errors: [], skippedServerOverwrites: 612, pendingTruncated: true,
        pendingServers: [{ kind: 'overwrite', name: 'web-1', incomingName: 'web-1', host: 'h', port: 22, localHost: 'h0', localPort: 22, changes: ['host'] }],
        pendingKeys: [], approvalRefused: m });
    }, REFUSED);
    await page.click('#bwSyncNowBtn');
    await page.waitForTimeout(300);
    check('J7 a list too long: the refusal spelled out',
      [(await bwStatus(page)).text.includes(spelled(REFUSED)), (await warned(page)).includes(spelled(REFUSED)), await turned(page)], [true, true, []]);
    check('no page errors', app.errors, []);
  });
}

// ─── J4: the Bitwarden destination, allowed or not ─────────────────────────
//
// The backend asks a native question before keys and passwords may go to a
// server and account (bitwarden_save_config, bitwarden_allow_sync); until it
// is answered "Allow", bitwarden_get_config says confirmed: false and every
// sync is refused (fw-rust-report.txt, RENDERER CONTRACT). Stubs follow that
// contract: { ok: true, confirmed, warning } and the W1 text.

const BW_W1 = 'Bitwarden sync stays off, because uploading your keys and passwords to vault.example.com was not allowed. Use "Allow syncing..." in Settings > Bitwarden to be asked again.';
const BW_SYNC_OFF = 'Bitwarden sync is off until you allow it to upload your keys and passwords to the account me@example.com on vault.example.com. Use "Allow syncing..." in Settings > Bitwarden.';
const BW_NOTE = (host) => `Not confirmed - SSHSpan will not sync with ${host} until you allow it.`;

async function scenarioBwDestination(browser, server) {
  const UNCONFIRMED = Object.assign({}, BW_CONFIG, { confirmed: false });
  const state = (page) => page.evaluate(() => {
    const n = document.getElementById('bwUnconfirmed');
    const b = document.getElementById('bwAllowBtn');
    return {
      note: n && !n.hidden ? n.textContent : null,
      isolated: n && !n.hidden ? [...n.querySelectorAll('bdi')].map((x) => x.textContent) : null,
      allow: b && !b.hidden ? [b.textContent.trim(), b.disabled] : null,
      syncEnabled: !document.getElementById('bwSyncNowBtn').disabled,
    };
  });
  const warned = (page) => page.evaluate(() => [...document.querySelectorAll('#toast .toast-item.warn .toast-text')].map((t) => t.textContent));
  await withApp(browser, server, { replies: { bitwarden_get_config: UNCONFIRMED } }, 'J4 a destination not allowed yet, then allowed', async (app) => {
    const { page } = app;
    await bwOpen(page);
    check('J4 the settings say so, the host isolated; Allow syncing... offered; Sync stays enabled', await state(page), {
      note: BW_NOTE('vault.example.com'), isolated: ['vault.example.com'], allow: ['Allow syncing...', false], syncEnabled: true,
    });
    check('J4 Allow syncing... is described by the note', await page.evaluate(() => el('bwAllowBtn').getAttribute('aria-describedby')), 'bwUnconfirmed');
    await page.evaluate(() => {
      window.__replies.bitwarden_allow_sync = () => {
        window.__replies.bitwarden_get_config = Object.assign({}, window.__replies.bitwarden_get_config, { confirmed: true });
        return { ok: true, confirmed: true, warning: null };
      };
    });
    await page.click('#bwAllowBtn');
    await page.waitForTimeout(250);
    check('J4 Allow syncing... asks the backend once, with no arguments', (await app.calls('bitwarden_allow_sync')).map((c) => c.args), [{}]);
    check('J4 allowed: the note and the button go', await state(page), { note: null, isolated: null, allow: null, syncEnabled: true });
    yes('J4 and it says so', (await liveToasts(page)).some((t) => /^Bitwarden sync is allowed - SSHSpan may upload your keys and passwords to /.test(t)),
      JSON.stringify(await liveToasts(page)));
    check('no page errors', app.errors, []);
  });
  await withApp(browser, server, { replies: { bitwarden_get_config: UNCONFIRMED, bitwarden_allow_sync: { ok: true, confirmed: false, warning: BW_W1 } } },
    'J4 Allow syncing... answered no again', async (app) => {
      const { page } = app;
      await bwOpen(page);
      await page.click('#bwAllowBtn');
      await page.waitForTimeout(250);
      const st = await bwStatus(page);
      check('J4 still not allowed: the backend\'s reason, as a warning', [st.text, /\bwarn\b/.test(st.cls)], [BW_W1, true]);
      yes('J4 and as a warning toast', (await warned(page)).includes(BW_W1), JSON.stringify(await warned(page)));
      check('J4 the note stays', (await state(page)).note, BW_NOTE('vault.example.com'));
      check('no page errors', app.errors, []);
    });
  await withApp(browser, server, { replies: { bitwarden_get_config: UNCONFIRMED } }, 'J4 Allow syncing... while its question is open', async (app) => {
    const { page } = app;
    await bwOpen(page);
    await hold(page, 'bitwarden_allow_sync');
    await page.click('#bwAllowBtn');
    await page.waitForTimeout(120);
    check('J4 busy while the native question is open', await page.evaluate(() => [el('bwAllowBtn').disabled, el('bwAllowBtn').getAttribute('aria-busy')]), [true, 'true']);
    check('J4 and the status says what it waits for, the host isolated', (await bwStatus(page)).text,
      'Waiting for your answer: SSHSpan asks in its own dialog whether it may upload your keys and passwords to \u{2068}vault.example.com\u{2069}.');
    await page.evaluate(() => el('bwAllowBtn').click());
    check('J4 a second click asks nothing more', await app.count('bitwarden_allow_sync'), 1);
    await page.evaluate(() => { window.__replies.bitwarden_allow_sync = { $reject: 'Save the Bitwarden sync settings first.' }; });
    await letGo(page, 'bitwarden_allow_sync');
    await page.waitForTimeout(200);
    const st = await bwStatus(page);
    check('J4 a refusal is said as it is, as an error', [st.text, /\berr\b/.test(st.cls)], ['Save the Bitwarden sync settings first.', true]);
    check('no page errors', app.errors, []);
  });
  await withApp(browser, server, { replies: { bitwarden_get_config: UNCONFIRMED } }, 'J4 Allow syncing... and the lock', async (app) => {
    const { page } = app;
    await bwOpen(page);
    await page.evaluate(() => { window.__backend.unlocked = false; return refreshVaultStatus(); });
    await page.waitForTimeout(150);
    if (await app.open('vaultModal')) await page.click('#vaultCancelBtn');
    check('J4 lock-gated like its neighbours', await page.evaluate(() => [el('bwAllowBtn').disabled, el('bwAllowBtn').title]),
      [true, 'Unlock the vault to allow the Bitwarden sync.']);
    check('no page errors', app.errors, []);
  });
  // Only a stored destination that is not allowed is said: none saved, or an
  // allowed one, shows nothing; a URL that is no URL is shown as it is,
  // spelled out.
  for (const [title, config, want] of [
    ['nothing saved', Object.assign({}, BW_CONFIG, { server_url: '', email: '', confirmed: false }), null],
    ['no account email saved', Object.assign({}, BW_CONFIG, { email: '', confirmed: false }), null],
    ['allowed', BW_CONFIG, null],
    ['an answer that says nothing of confirmed (fails closed)', (() => { const c = Object.assign({}, BW_CONFIG); delete c.confirmed; return c; })(), ['vault.example.com']],
    ['a host with a port', Object.assign({}, UNCONFIRMED, { server_url: 'https://vault.example.com:8443/' }), ['vault.example.com:8443']],
    ['no URL at all', Object.assign({}, UNCONFIRMED, { server_url: 'vault\u{202E}moc' }), ['vault<U+202E>moc']],
  ]) {
    await withApp(browser, server, { replies: { bitwarden_get_config: config } }, `J4 the note: ${title}`, async (app) => {
      const { page } = app;
      await bwOpen(page);
      const s = await state(page);
      check(`J4 ${title}: ${want ? 'the note names the host, spelled out' : 'no note, no Allow syncing...'}`, [s.isolated, !!s.allow], [want, !!want]);
      check('no page errors', app.errors, []);
    });
  }
  // A save the native question did not allow: its warning, as a warning
  // toast - the settings are stored, but "saved" alone would read as done.
  const AUDIT = 'The sync settings were saved, but their audit row could not be written: disk I/O error';
  for (const [title, warning] of [['a save not allowed', BW_W1], ['and its audit row failed too', `${AUDIT} ${BW_W1}`]]) {
    await withApp(browser, server, { replies: { bitwarden_get_config: BW_CONFIG, bitwarden_save_config: { ok: true, confirmed: false, warning } } },
      `J4 ${title}`, async (app) => {
        const { page } = app;
        await bwOpen(page);
        await page.click('#bwSaveBtn');
        await page.waitForTimeout(250);
        check(`J4 ${title}: its warning as a warning toast, and no "saved"`,
          [(await warned(page)).includes(warning), (await liveToasts(page)).includes('Bitwarden settings saved.')], [true, false]);
        check('no page errors', app.errors, []);
      });
  }
  // J8: the focus of a keyboard user. Allowed, "Allow syncing..." goes with
  // the note - the focus goes on to Sync now, the next step (or Save, when Sync
  // now cannot take it), not to the page; answered "no", it stays on the
  // button. A user who moved on keeps their place; one whose click did not
  // focus the button is not moved.
  const focused = (page) => page.evaluate(() => (document.activeElement && document.activeElement.id) || 'body');
  const allowing = (page, confirmed) => page.evaluate((c) => {
    window.__replies.bitwarden_allow_sync = () => {
      window.__replies.bitwarden_get_config = Object.assign({}, window.__replies.bitwarden_get_config, { confirmed: c });
      return { ok: true, confirmed: c, warning: c ? null : 'Bitwarden sync stays off, because uploading your keys and passwords to vault.example.com was not allowed. Use "Allow syncing..." in Settings > Bitwarden to be asked again.' };
    };
  }, confirmed);
  for (const [title, confirmed, prepare, want] of [
    ['J8 Enter on Allow syncing..., allowed: the focus goes on to Sync now', true, null, 'bwSyncNowBtn'],
    ['J8 Enter on Allow syncing..., answered no: the focus stays on it', false, null, 'bwAllowBtn'],
    ['J8 allowed while Sync now cannot take the focus: Save takes it', true, () => { el('bwSyncNowBtn').hidden = true; }, 'bwSaveBtn'],
  ]) {
    await withApp(browser, server, { replies: { bitwarden_get_config: UNCONFIRMED } }, title, async (app) => {
      const { page } = app;
      await bwOpen(page);
      await allowing(page, confirmed);
      if (prepare) await page.evaluate(prepare);
      await page.focus('#bwAllowBtn');
      await page.keyboard.press('Enter');
      await page.waitForTimeout(300);
      check(title, await focused(page), want);
      check('no page errors', app.errors, []);
    });
  }
  // While the question is open the user moves on: to a control the reload
  // keeps - their place stays; into the form - the reload builds its fields
  // anew (A2-29), so that place is gone, and the focus goes on to Sync now
  // rather than to the page.
  for (const [title, movedTo, want] of [
    ['J8 a user who moved on while the question was open keeps their place', '#bwTestBtn', 'bwTestBtn'],
    ['J8 a user who moved into the form, which the reload rebuilds, lands on Sync now', '#bw_email', 'bwSyncNowBtn'],
  ]) {
    await withApp(browser, server, { replies: { bitwarden_get_config: UNCONFIRMED } }, title, async (app) => {
      const { page } = app;
      await bwOpen(page);
      await allowing(page, true);
      await hold(page, 'bitwarden_allow_sync');
      await page.focus('#bwAllowBtn');
      await page.keyboard.press('Enter');
      await page.waitForTimeout(100);
      await page.focus(movedTo);
      await letGo(page, 'bitwarden_allow_sync');
      await page.waitForTimeout(300);
      check(title, await focused(page), want);
      check('no page errors', app.errors, []);
    });
  }
  await withApp(browser, server, { replies: { bitwarden_get_config: UNCONFIRMED } }, 'J8 allowed by a click that did not focus it', async (app) => {
    const { page } = app;
    await bwOpen(page);
    await allowing(page, true);
    // As WebKit's click: the button never had the focus, the page did.
    await page.evaluate(() => { document.activeElement && document.activeElement.blur && document.activeElement.blur(); el('bwAllowBtn').click(); });
    await page.waitForTimeout(300);
    check('J8 a click that did not focus the button moves no focus', await focused(page), 'body');
    check('no page errors', app.errors, []);
  });
  // Sync stays enabled; the backend's refusal is said as it is.
  await withApp(browser, server, { replies: { bitwarden_get_config: UNCONFIRMED, bitwarden_sync: { $reject: BW_SYNC_OFF } } }, 'J4 a sync before it is allowed', async (app) => {
    const { page } = app;
    await bwOpen(page);
    await page.click('#bwSyncNowBtn');
    await page.waitForTimeout(250);
    const st = await bwStatus(page);
    check('J4 the backend\'s refusal of a sync, as it is', [st.text, (await liveToasts(page)).includes(BW_SYNC_OFF)], [BW_SYNC_OFF, true]);
    check('no page errors', app.errors, []);
  });
}

// ─── item 8: the Upload picker ──────────────────────────────────────────────

async function scenarioUpload(browser, server) {
  const RESULT = {
    ok: true, added: 1, warnings: ['C:\\Users\\me\\b.log: could not be read (gone).'],
    items: [
      { path: '/home/me/a.txt', status: 'queued', added: 1 },
      { path: 'C:\\Users\\me\\b.log', status: 'error', added: 0, error: 'C:\\Users\\me\\b.log: could not be read (gone).' },
    ],
  };
  const replies = {
    system_pick_files: { canceled: false, paths: ['/home/me/a.txt', 'C:\\Users\\me\\b.log'] },
    sftp_list_dir: { entries: [], path: '/srv' }, sftp_queue_add: RESULT, sftp_bookmarks_list: { bookmarks: [] },
  };
  await withApp(browser, server, { replies }, 'A5-40 Upload picks files from this computer', async (app) => {
    const { page } = app;
    await sftpTab(page, 'tu');
    yes('the file browser has an Upload button', await clickUpload(page));
    await page.waitForTimeout(400);
    check('A5-40 Upload opens the native picker for several files', await lastArgs(app, 'system_pick_files'), { title: 'Upload to /srv', multiple: true });
    const adds = await app.calls('sftp_queue_add');
    check('A5-40 the picked files are queued with ONE sftp_queue_add', adds.length, 1);
    check('A5-40 each into the folder on screen', adds.length ? adds[0].args.items.map((i) => [i.local, i.remote]) : null,
      [['/home/me/a.txt', '/srv/a.txt'], ['C:\\Users\\me\\b.log', '/srv/b.log']]);
    const t = await liveToasts(page);
    yes('A5-40 the result says what was queued and what was not', t.some((x) => /1 of 2/.test(x) && x.includes('could not be read')), JSON.stringify(t));
    const log = await page.evaluate(() => state.sessions.get('tu').log.join('\n'));
    yes('A5-40 the activity log has a line per picked file', log.includes('/home/me/a.txt') && log.includes('C:\\Users\\me\\b.log'), log);
    check('no page errors', app.errors, []);
  });
  await withApp(browser, server, { replies: { ...replies, system_pick_files: { canceled: true, paths: [] } } }, 'A5-40 a cancelled pick', async (app) => {
    const { page } = app;
    await sftpTab(page, 'tu');
    await clickUpload(page);
    await page.waitForTimeout(300);
    check('A5-40 cancelling the picker queues nothing', [await app.count('system_pick_files'), await app.count('sftp_queue_add')], [1, 0]);
    check('no page errors', app.errors, []);
  });
  await withApp(browser, server, { replies: { ...replies, sftp_queue_add: { $reject: '/home/me/a.txt: refused.\nC:\\Users\\me\\b.log: refused.' } } }, 'A5-40 every file refused', async (app) => {
    const { page } = app;
    await sftpTab(page, 'tu');
    await clickUpload(page);
    await page.waitForTimeout(400);
    yes('A5-40 when every file is refused the reasons are shown', (await liveToasts(page)).some((x) => x.includes('/home/me/a.txt: refused.')), JSON.stringify(await liveToasts(page)));
    check('no page errors', app.errors, []);
  });
}

// ─── item 9: approval cards (JU3 deferral) ──────────────────────────────────

async function scenarioCardEscapes(browser, server) {
  await withApp(browser, server, {}, 'JU3 deferral: approval cards show invisible characters', async (app) => {
    const { page } = app;
    const r = await page.evaluate(() => {
      const d = document.createElement('div');
      aiCardCmd(d, 'cat notes\u202Etxt.sh');
      const a = document.createElement('div');
      aiArgsBlock(a, { file: 'a\u200Bb', note: 'x\u2066y' });
      const plain = document.createElement('div');
      aiCardCmd(plain, 'ls -la /tmp');
      return { cmd: d.textContent, args: a.textContent, plain: plain.textContent };
    });
    const hidden = /[\u00AD\u061C\u180E\u200B-\u200F\u2028\u2029\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF]/;
    check('item 9 the command on a card keeps no invisible or direction-changing character', hidden.test(r.cmd), false);
    yes('item 9 it shows where one was, by code point', /U\+202E/.test(r.cmd), r.cmd);
    check('item 9 the arguments likewise', [hidden.test(r.args), /U\+200B/.test(r.args) && /U\+2066/.test(r.args)], [false, true]);
    check('item 9 ordinary text is unchanged', r.plain, 'ls -la /tmp');
    check('no page errors', app.errors, []);
  });
}

// ─── fix round 1 ────────────────────────────────────────────────────────────

/// A live password tab in split view (SFTP open), then a restart answered OK
/// and the password prompt answered Cancel. Resolves the tab id.
async function cancelledRestart(app, srv) {
  const { page } = app;
  await uniqueSessions(page);
  await page.evaluate((s) => { window.__open = openSessionTab(s); }, srv);
  await answerPassword(page, 'pw-1');
  await page.waitForFunction(() => [...state.sessions.keys()].some((id) => window.tabSessionLive(id)), null, { polling: 25 });
  const tab = await page.evaluate(() => [...state.sessions.keys()][0]);
  await page.evaluate(() => setSessionMode('split'));
  await page.waitForFunction((t) => { const s = state.sessions.get(t); return s.mode === 'split' && s.sftpReady; }, tab);
  await page.evaluate(() => { window.__restart = reconnectActiveTab(); });
  await answerConfirm(page, 'ok');
  const prompted = await answerPassword(page, null);
  await page.waitForTimeout(150);
  return { tab, prompted };
}

async function scenarioRestartCancel(browser, server) {
  const srv = PW_SERVER('s1', 'pw-box');
  await withApp(browser, server, { servers: [srv] }, 'fix1 #1 a restart cancelled at the password prompt', async (app) => {
    const { page } = app;
    const { tab, prompted } = await cancelledRestart(app, srv);
    yes('fix1 #1 the restart asks for the password', prompted);
    check('fix1 #1 Cancel at the prompt keeps the running session, in app.js and terminal.js alike',
      await page.evaluate((t) => [window.tabSessionLive(t), state.sessions.get(t).sessionId, window.tabRecord(t).sessionId, !!state.sessions.get(t).ended], tab),
      [true, 'conn-1', 'conn-1', false]);
    check('fix1 #1 nothing was disconnected', await app.count('terminal_disconnect'), 0);
    check('fix1 #1 its file browser stays open', [await app.count('sftp_close'), await page.evaluate((t) => [state.sessions.get(t).mode, !!state.sessions.get(t).sftpReady], tab)], [0, ['split', true]]);
    check('fix1 #1 the assistant is not sent back to Read', (await app.calls('assistant_set_level')).filter((c) => c.args.level === 'read').length, 0);
    yes('fix1 #1 the status line says the restart was cancelled', /cancel/i.test(await strip(page)), await strip(page));
    await page.click('#termDisconnectBtn');
    await page.waitForTimeout(150);
    check('fix1 #1 Disconnect then ends the real session', (await app.calls('terminal_disconnect')).map((c) => c.args.sessionId), ['conn-1']);
    check('no page errors', app.errors, []);
  });
  await withApp(browser, server, { servers: [srv] }, 'fix1 #1 closing the tab after a cancelled restart', async (app) => {
    const { page } = app;
    const { tab } = await cancelledRestart(app, srv);
    await page.evaluate((t) => { window.__close = closeSessionTab(t); }, tab);
    await answerConfirm(page, 'ok');
    await page.waitForTimeout(150);
    check('fix1 #1 closing the tab ends the real session', (await app.calls('terminal_disconnect')).map((c) => c.args.sessionId), ['conn-1']);
    check('fix1 #1 and the file browser of that session', (await app.calls('sftp_close')).map((c) => c.args.sessionId), ['conn-1']);
    check('no page errors', app.errors, []);
  });
  await withApp(browser, server, { servers: [srv] }, 'fix1 #1 a lock after a cancelled restart', async (app) => {
    const { page } = app;
    await cancelledRestart(app, srv);
    await page.evaluate(() => lockNow());
    await page.waitForTimeout(250);
    check('fix1 #1 the lock ends the real session', (await app.calls('terminal_disconnect')).map((c) => c.args.sessionId), ['conn-1']);
    check('no page errors', app.errors, []);
  });
  await withApp(browser, server, { servers: [srv] }, 'fix1 #1 a restart with the password given', async (app) => {
    const { page } = app;
    await uniqueSessions(page);
    await page.evaluate((s) => { window.__open = openSessionTab(s); }, srv);
    await answerPassword(page, 'pw-1');
    await page.waitForFunction(() => [...state.sessions.keys()].some((id) => window.tabSessionLive(id)), null, { polling: 25 });
    const tab = await page.evaluate(() => [...state.sessions.keys()][0]);
    await page.evaluate(() => { window.__restart = reconnectActiveTab(); });
    await answerConfirm(page, 'ok');
    check('fix1 #1 while the prompt is open the old session still runs', [await app.count('terminal_disconnect'), await page.evaluate((t) => window.tabSessionLive(t), tab)], [0, true]);
    await answerPassword(page, 'pw-2');
    await page.waitForFunction((t) => window.tabRecord(t).sessionId === 'conn-2', tab);
    check('fix1 #1 the password given, the old session ends and the new one starts with it',
      [(await app.calls('terminal_disconnect')).map((c) => c.args.sessionId), (await lastArgs(app, 'terminal_connect')).promptPassword], [['conn-1'], 'pw-2']);
    check('no page errors', app.errors, []);
  });
}

async function scenarioHeadFits(browser, server) {
  await withApp(browser, server, {}, 'fix1 #2 every terminal header control is on screen', async (app) => {
    const { page } = app;
    await openLiveTab(app);
    for (const [w, h, max] of [[880, 560, false], [1100, 720, false], [1400, 900, false], [880, 560, true]]) {
      if (max) await page.evaluate(() => toggleTermMax());
      await page.setViewportSize({ width: w, height: h });
      await page.waitForTimeout(350);
      const bad = await page.evaluate(() => {
        const col = document.querySelector('.terminal-col').getBoundingClientRect();
        const out = [];
        let shown = 0;
        for (const b of document.querySelectorAll('.terminal-head button')) {
          if (b.closest('[hidden]') || !b.getClientRects().length) continue;
          shown += 1;
          const r = b.getBoundingClientRect();
          const inside = r.left >= col.left - 0.5 && r.right <= col.right + 0.5 && r.top >= col.top - 0.5 && r.bottom <= col.bottom + 0.5;
          const hit = document.elementFromPoint(r.left + r.width / 2, r.top + r.height / 2);
          const clickable = !!hit && (hit === b || b.contains(hit));
          const uncut = b.scrollWidth <= b.clientWidth + 1;
          const target = r.width >= 24 && r.height >= 24;
          const named = !!(b.getAttribute('aria-label') || b.textContent).trim();
          if (!inside || !clickable || !uncut || !target || !named) {
            out.push({ id: b.id || b.dataset.mode, inside, clickable, uncut, target, named, left: Math.round(r.left), right: Math.round(r.right), colRight: Math.round(col.right) });
          }
        }
        return shown >= 6 ? out : ['only ' + shown + ' controls shown'];
      });
      check(`fix1 #2 ${max ? 'maximized ' : ''}${w}x${h}: every header control is inside the column, uncut, 24 px and clickable`, bad, []);
      const tall = await page.evaluate(() => Math.round(document.querySelector('.terminal-head').getBoundingClientRect().height));
      yes(`fix1 #2 ${max ? 'maximized ' : ''}${w}x${h}: and the header stays one row (icons only when narrow), not a stack of wrapped rows`, tall <= 64, tall + ' px');
    }
    check('no page errors', app.errors, []);
  });
}

async function scenarioHintDescription(browser, server) {
  const servers = [SERVER('s1', 'web-1'), SAVED_PW_SERVER('s2', 'legacy-box')];
  await withApp(browser, server, { servers }, 'fix1 #3 the saved-password hint describes the field only when shown', async (app) => {
    const { page } = app;
    await serversView(page);
    const SAVED = 'A password is saved - leave blank to keep it.';
    await page.evaluate(() => { openServerModal({}); setConnectAuthMethod('password'); });
    const fresh = await axOf(page, '#srvPassword');
    yes('fix1 #3 a new server\'s password field is not described as having a saved password', !!fresh && !fresh.description.includes(SAVED), JSON.stringify(fresh));
    await page.evaluate(() => { closeServerModal(); openServerModal({ id: 's2' }); });
    const saved = await axOf(page, '#srvPassword');
    yes('fix1 #3 a saved password is the field\'s description', !!saved && saved.description.includes(SAVED), JSON.stringify(saved));
    await page.click('#srvClearPwBtn');
    const clearing = await axOf(page, '#srvPassword');
    yes('fix1 #3 with Remove pressed it says the password goes', !!clearing && clearing.description.includes('The saved password is removed when you save.'), JSON.stringify(clearing));
    await page.evaluate(() => { closeServerModal(); openServerModal({}); setConnectAuthMethod('password'); });
    const again = await axOf(page, '#srvPassword');
    yes('fix1 #3 and the next new server is not described so either', !!again && !again.description.includes('saved password') && !again.description.includes(SAVED), JSON.stringify(again));
    check('no page errors', app.errors, []);
  });
}

const HIDES_ADDRESS = 'This link hides its real address - not opened.';

/// Hand a link to the terminal's own OSC 8 handler, the way xterm does on a click.
async function linkProbe(page, tab, uri) {
  await page.evaluate(({ t, u }) => { window.tabRecord(t).term.options.linkHandler.activate(new MouseEvent('click'), u); }, { t: tab, u: uri });
  await page.waitForTimeout(150);
}

/// Where a text sits in the active tab's terminal, in page coordinates.
const textAt = (page, tab, needle, dx) => page.evaluate(({ t, s, d }) => {
  const term = window.tabRecord(t).term;
  const buf = term.buffer.active;
  const r = term.element.querySelector('.xterm-screen').getBoundingClientRect();
  for (let y = 0; y < term.rows; y++) {
    const line = buf.getLine(buf.viewportY + y);
    const x = line ? line.translateToString(true).indexOf(s) : -1;
    if (x >= 0) return { x: r.left + (x + d) * (r.width / term.cols), y: r.top + (y + 0.5) * (r.height / term.rows) };
  }
  return null;
}, { t: tab, s: needle, d: dx });

async function scenarioLinkSafety(browser, server) {
  await withApp(browser, server, {}, 'fix1 #4 links that hide their address', async (app) => {
    const { page } = app;
    const tab = await openLiveTab(app);
    await page.waitForTimeout(150);
    for (const [label, uri] of [
      ['a long user name in front of the real host', 'https://accounts.google.com.' + 'a'.repeat(3000) + '@evil.tld/'],
      ['a user name and password', 'https://accounts.google.com:signin@evil.tld/'],
    ]) {
      await linkProbe(page, tab, uri);
      const asked = await app.open('confirmModal');
      check(`fix1 #4 ${label}: not offered at all`, asked, false);
      if (asked) await answerConfirm(page, 'cancel');
      yes(`fix1 #4 ${label}: the user is told why`, (await liveToasts(page)).includes(HIDES_ADDRESS), JSON.stringify(await liveToasts(page)));
    }
    for (const uri of ['javascript:alert(1)', 'file:///etc/passwd']) {
      await linkProbe(page, tab, uri);
      const asked = await app.open('confirmModal');
      check(`fix1 #4 a ${uri.split(':')[0]}: link is refused in the renderer, not offered`, asked, false);
      if (asked) await answerConfirm(page, 'cancel');
    }
    check('fix1 #4 none of them was opened', await app.count('system_open_url'), 0);

    const long = 'https://evil.tld/' + 'x'.repeat(3000);
    await linkProbe(page, tab, long);
    const asked = await waitVisible(page, '#confirmModal', 800);
    yes('fix1 #4 an ordinary long link is offered', asked);
    if (asked) {
      const c = await confirmText(page);
      check('fix1 #4 the site comes first, on a line of its own', c.message.split('\n')[0], 'Site: evil.tld');
      yes('fix1 #4 the address under it is cut short', c.message.length < 700 && c.message.includes('…'), String(c.message.length));
      const seen = await page.evaluate(() => {
        const p = document.getElementById('confirmMessage');
        const text = p.firstChild;
        if (!text || text.nodeType !== 3 || text.data.indexOf('\n') < 0) return 'no first line';
        const range = document.createRange();
        range.setStart(text, 0);
        range.setEnd(text, text.data.indexOf('\n'));
        const r = range.getBoundingClientRect();
        const box = document.querySelector('#confirmModal .modal').getBoundingClientRect();
        const hit = document.elementFromPoint(r.left + 4, r.top + r.height / 2);
        return r.height > 0 && r.top >= box.top && r.bottom <= box.bottom && r.bottom <= window.innerHeight && hit === p;
      });
      check('fix1 #4 and the site line is on screen without scrolling', seen, true);
      await answerConfirm(page, 'ok');
      await page.waitForTimeout(100);
      check('fix1 #4 OK opens the whole address', (await app.calls('system_open_url')).map((c) => c.args.url), [new URL(long).href]);
    }
    check('no page errors', app.errors, []);
  });

  await withApp(browser, server, {}, 'fix1 #7 a plain link in the output asks first too', async (app) => {
    const { page } = app;
    const tab = await openLiveTab(app);
    await page.waitForTimeout(200);
    const target = new URL('/plain-target', page.url());
    await writeTerm(page, tab, `\r\nsee ${target.href} now\r\n`);
    const at = await textAt(page, tab, '/plain-target', 3.5);
    yes('the plain link is on screen', !!at);
    if (at) {
      await page.mouse.move(at.x, at.y);
      await page.waitForTimeout(250);
      await page.mouse.click(at.x, at.y);
    }
    const asked = await waitVisible(page, '#confirmModal', 1000);
    check('fix1 #7 clicking a plain link opens nothing before an answer', await app.count('system_open_url'), 0);
    yes('fix1 #7 it asks the same way, the site first', asked && (await confirmText(page)).message.split('\n')[0] === 'Site: ' + target.host,
      asked ? (await confirmText(page)).message : 'no question');
    if (asked) await answerConfirm(page, 'ok');
    await page.waitForTimeout(150);
    check('fix1 #7 and OK opens it', (await app.calls('system_open_url')).map((c) => c.args.url), [target.href]);
    check('no page errors', app.errors, []);
  });
}

async function scenarioCardCoverage(browser, server) {
  await withApp(browser, server, {}, 'fix1 #5 the widened table on a card', async (app) => {
    const { page } = app;
    const r = await page.evaluate(() => {
      const d = document.createElement('div');
      d.className = 'ai-card';
      document.body.appendChild(d);
      aiCardCmd(d, 'a\u034Fb\u3164c\uFFA0d\uFE0Fe\u{E0101}f\u{1D173}g\u0600h');
      const plain = document.createElement('div');
      aiCardCmd(plain, 'printf "a\tb"\nls');
      const code = d.querySelector('code');
      const cs = getComputedStyle(code);
      return { text: d.textContent, plain: plain.textContent, bidi: cs.unicodeBidi, dir: cs.direction };
    });
    check('fix1 #5 every one of them is shown by code point', ['034F', '3164', 'FFA0', 'FE0F', 'E0101', '1D173', '0600'].filter((cp) => !r.text.includes('<U+' + cp + '>')), []);
    check('fix1 #5 and none is left in the text', /[\u034F\u3164\uFFA0\uFE0F\u0600]|\u{E0101}|\u{1D173}/u.test(r.text), false);
    check('fix1 #5 TAB and newline are kept as they are', r.plain, 'printf "a\tb"\nls');
    check('fix1 #5 a card lays its text out in the order it is sent (bidi override, left to right)', [r.bidi, r.dir], ['bidi-override', 'ltr']);
    check('no page errors', app.errors, []);
  });
}

async function scenarioChordAnswers(browser, server) {
  await withApp(browser, server, {}, 'fix1 #6 the lock question', async (app) => {
    const { page } = app;
    await openLiveTab(app);
    await page.waitForTimeout(200);
    await blur(page);
    await page.keyboard.press('Control+l');
    const asked = await waitVisible(page, '#confirmModal', 800);
    yes('fix1 #6 Ctrl+L with a live session asks', asked);
    if (asked) {
      yes('fix1 #6 the lock question has Lock focused', await focusIs(page, 'confirmOkBtn', 800), await app.focused());
      const msg = (await confirmText(page)).message;
      yes('fix1 #6 and says a second Ctrl+L locks', /Press Ctrl\+L again to lock/.test(msg), msg);
      await page.keyboard.press('Control+l');
      await page.waitForTimeout(250);
    }
    check('fix1 #6 a second Ctrl+L is the yes: locked once, no question left', [await app.count('vault_lock'), await app.open('confirmModal')], [1, false]);
    check('no page errors', app.errors, []);
  });
  await withApp(browser, server, {}, 'fix1 #6 Enter on the lock question', async (app) => {
    const { page } = app;
    await openLiveTab(app);
    await page.waitForTimeout(200);
    await page.click('#vaultStatus');
    await clickMenuItem(page, /^Lock now/);
    if (await waitVisible(page, '#confirmModal', 800)) {
      await focusIs(page, 'confirmOkBtn', 800);
      await page.keyboard.press('Enter');
    }
    await page.waitForTimeout(250);
    check('fix1 #6 Enter locks', await app.count('vault_lock'), 1);
    check('no page errors', app.errors, []);
  });
  await withApp(browser, server, { replies: { app_quit: { ok: true } } }, 'fix1 #6 the quit question', async (app) => {
    const { page } = app;
    await openLiveTab(app);
    await page.waitForTimeout(200);
    await blur(page);
    await page.keyboard.press('Control+q');
    const asked = await waitVisible(page, '#confirmModal', 800);
    yes('fix1 #6 Ctrl+Q with a live session asks', asked);
    if (asked) {
      yes('fix1 #6 the quit question keeps Cancel focused', await focusIs(page, 'confirmCancelBtn', 800), await app.focused());
      const msg = (await confirmText(page)).message;
      yes('fix1 #6 and says a second Ctrl+Q quits', /Press Ctrl\+Q again to quit/.test(msg), msg);
      await page.keyboard.press('Control+q');
      await page.waitForTimeout(250);
    }
    check('fix1 #6 a second Ctrl+Q is the yes: quit once, no question left', [await app.count('app_quit'), await app.open('confirmModal')], [1, false]);
    check('no page errors', app.errors, []);
  });
}

async function scenarioPasteClean(browser, server) {
  await withApp(browser, server, {}, 'fix1 #8 pasted control characters', async (app) => {
    const { page } = app;
    const tab = await openLiveTab(app);
    await page.waitForTimeout(150);
    await writeTerm(page, tab, '\x1b[?2004h');
    const dirty = 'echo a\x1b[201~; id\x9b201~b\x00c\x07d\x1b]0;t\x07e\tf\x7fg\x85h';
    const clean = 'echo a; idbcd]0;te\tfgh';
    let n = (await sends(app)).length;
    await page.evaluate(({ t, s }) => window.terminalPaste(t, s), { t: tab, s: dirty });
    await page.waitForTimeout(150);
    check('fix1 #8 a paste sends no control character but TAB, CR and LF - an end-of-paste marker in it included',
      (await sends(app)).slice(n), ['\x1b[200~' + clean + '\x1b[201~']);
    n = (await sends(app)).length;
    await page.evaluate(({ t, s }) => {
      const dt = new DataTransfer();
      dt.setData('text/plain', s);
      window.tabRecord(t).term.element.dispatchEvent(new ClipboardEvent('paste', { clipboardData: dt, bubbles: true, cancelable: true }));
    }, { t: tab, s: dirty });
    await page.waitForTimeout(150);
    check('fix1 #8 a native paste likewise', (await sends(app)).slice(n), ['\x1b[200~' + clean + '\x1b[201~']);
    n = (await sends(app)).length;
    await page.evaluate(({ t, s }) => { window.__p = window.terminalPaste(t, s); }, { t: tab, s: 'ls\x1b[201~\nid' });
    if (await waitVisible(page, '#confirmModal', 800)) await answerConfirm(page, 'ok');
    await page.waitForTimeout(150);
    check('fix1 #8 line breaks stay (a newline goes as CR)', (await sends(app)).slice(n), ['\x1b[200~ls\rid\x1b[201~']);
    n = (await sends(app)).length;
    const sent = await page.evaluate(({ t }) => window.terminalPaste(t, '\x1b[201~\x00'), { t: tab });
    await page.waitForTimeout(100);
    check('fix1 #8 a paste of control characters only sends nothing', [sent, (await sends(app)).slice(n)], [false, []]);
    check('no page errors', app.errors, []);
  });
}

async function scenarioSyncGroups(browser, server) {
  const RESULT = { ok: true, pushed: 1, linked: 3, conflicts: 1, serversPushed: 2, errors: [] };
  await withApp(browser, server, { replies: { bitwarden_get_config: BW_CONFIG, bitwarden_sync: RESULT } }, 'fix1 #10 linked items and conflicts', async (app) => {
    const { page } = app;
    await bwOpen(page);
    await page.click('#bwSyncNowBtn');
    await page.waitForTimeout(250);
    const text = (await bwStatus(page)).text;
    check('fix1 #10 the Keys and Servers groups count only their own kind (linked and conflicts are both kinds)',
      [/Keys:[^.]*(linked|conflict)/i.test(text), /Servers:[^.]*(linked|conflict)/i.test(text)], [false, false]);
    yes('fix1 #10 the matched items are said apart', /Matched to existing Bitwarden items: 3\./.test(text), text);
    yes('fix1 #10 and the conflicts', /Conflicts[^:]*: 1\./.test(text), text);
    yes('the per-kind counts are still there', /Keys: 1 pushed\./.test(text) && /Servers: 2 pushed\./.test(text), text);
    check('no page errors', app.errors, []);
  });
}

async function scenarioUploadSkipped(browser, server) {
  const RESULT = {
    ok: true, added: 3,
    warnings: ['skipped /home/me/fifo: it is not a regular file', 'skipped /home/me/proj/.ssh/id_ed25519: a private key is never uploaded'],
    items: [
      { path: '/home/me/proj', status: 'queued', added: 3, warnings: ['skipped /home/me/proj/.ssh/id_ed25519: a private key is never uploaded'] },
      { path: '/home/me/fifo', status: 'queued', added: 0, warnings: ['skipped /home/me/fifo: it is not a regular file'] },
    ],
  };
  const replies = {
    system_pick_files: { canceled: false, paths: ['/home/me/proj', '/home/me/fifo'] },
    sftp_list_dir: { entries: [], path: '/srv' }, sftp_queue_add: RESULT, sftp_bookmarks_list: { bookmarks: [] },
  };
  await withApp(browser, server, { replies }, 'fix1 #11 an upload pick the backend skipped', async (app) => {
    const { page } = app;
    await sftpTab(page, 'tu');
    await clickUpload(page);
    await page.waitForTimeout(400);
    const t = await liveToasts(page);
    yes('fix1 #11 a pick answered "queued" with nothing added counts as not queued', t.some((x) => /1 of 2/.test(x) && x.includes('/home/me/fifo: it is not a regular file')), JSON.stringify(t));
    yes('fix1 #11 no toast claims both were queued', !t.some((x) => /^2 files queued/.test(x)), JSON.stringify(t));
    const log = await page.evaluate(() => state.sessions.get('tu').log.join('\n'));
    yes('fix1 #11 the activity log says the skipped one was not queued, and why', /not queued[^\n]*\/home\/me\/fifo: it is not a regular file/.test(log), log);
    yes('fix1 #11 and keeps what was left out of the queued folder, under it', log.includes('/home/me/proj/.ssh/id_ed25519: a private key is never uploaded'), log);
    check('no page errors', app.errors, []);
  });
  const ONLY_NOTES = {
    ok: true, added: 2, warnings: [],
    items: [{ path: '/home/me/proj', status: 'queued', added: 2, warnings: ['skipped /home/me/proj/link: it is a link to a folder'] }],
  };
  await withApp(browser, server, { replies: { ...replies, system_pick_files: { canceled: false, paths: ['/home/me/proj'] }, sftp_queue_add: ONLY_NOTES } }, 'fix1 #11 an item\'s own notes', async (app) => {
    const { page } = app;
    await sftpTab(page, 'tu');
    await clickUpload(page);
    await page.waitForTimeout(400);
    const t = await liveToasts(page);
    yes('fix1 #11 an item\'s own warnings are shown even when the overall list has none', t.some((x) => x.includes('it is a link to a folder')), JSON.stringify(t));
    check('no page errors', app.errors, []);
  });
}

async function scenarioRowTest(browser, server) {
  const servers = [SERVER('s1', 'web-1'), PW_SERVER('s2', 'pw-box')];
  await withApp(browser, server, { servers, replies: { server_test: { ok: true, latencyMs: 7 } } }, 'fix1 #12 / #13 Test connection from a server row', async (app) => {
    const { page } = app;
    await serversView(page);
    const more = (id) => `#serverList .server-row[data-id="${id}"] .server-row-more`;
    await page.click(more('s1'));
    await page.waitForTimeout(60);
    check('fix1 #12 the row menu offers Test connection', await menuLabels(page), ['Connect', 'Test connection', 'Edit', 'Delete']);
    await clickMenuItem(page, /^Test connection$/);
    await page.waitForTimeout(150);
    check('fix1 #12 it tests that server', await lastArgs(app, 'server_test'), { serverId: 's1' });
    yes('fix1 #12 the result is a toast naming it', (await toasts(page)).some((x) => /web-1/.test(x) && /7 ms/.test(x)), JSON.stringify(await toasts(page)));
    check('fix1 #12 and no session is opened', await app.count('terminal_connect'), 0);
    await page.evaluate(() => {
      document.querySelector('#serverList .server-row[data-id="s2"]').dispatchEvent(
        new MouseEvent('contextmenu', { bubbles: true, cancelable: true, clientX: 200, clientY: 200 }));
    });
    await page.waitForTimeout(60);
    await clickMenuItem(page, /^Test connection$/);
    const asked = await waitVisible(page, '#connectPwModal', 800);
    yes('fix1 #13 from the right-click menu, a password server asks for the password first', asked);
    check('fix1 #13 the prompt is titled in sentence case', (await page.textContent('#connectPwTitle')).trim(), 'Enter password');
    check('fix1 #13 its button says what happens next: Test', (await page.textContent('#connectPwOkBtn')).trim(), 'Test');
    if (asked) {
      await page.fill('#connectPwInput', 'pw');
      await page.keyboard.press('Enter');
    }
    await page.waitForTimeout(150);
    check('fix1 #13 the typed password goes with the test', await lastArgs(app, 'server_test'), { serverId: 's2', promptPassword: 'pw' });
    await page.evaluate((s) => { window.__o = openSessionTab(s); }, servers[1]);
    if (await waitVisible(page, '#connectPwModal', 800)) {
      check('fix1 #13 a connect\'s prompt still says Connect', (await page.textContent('#connectPwOkBtn')).trim(), 'Connect');
      await page.click('#connectPwCancelBtn');
    } else {
      check('fix1 #13 a connect asks for the password', false, true);
    }
    check('no page errors', app.errors, []);
  });
}

async function scenarioIdleRealTime(browser, server) {
  await withApp(browser, server, { clock: true, settings: { autoLockMinutes: '5' } }, 'fix1 #15 the idle warning', async (app) => {
    const { page } = app;
    const warnings = async () => (await liveToasts(page)).filter((t) => /^Locking in/.test(t));
    await page.evaluate(() => noteUserActivity());
    await app.tick(64 * 1000);
    check('no warning with four minutes left', await warnings(), []);
    // The auto-lock shortened meanwhile (another window, a restore): the
    // deadline is now 56 s away, and the warning must say so - not "60 s".
    await page.evaluate(() => { state.settings.autoLockMinutes = '2'; armAutoLockTimer(); });
    await app.tick(200);
    check('fix1 #15 the warning says the time really left', await warnings(), ['Locking in 56 s - move the mouse or press a key to stay unlocked']);
    await page.evaluate(() => { for (let i = 0; i < 6; i++) toast('a newer notice ' + i, 'info'); });
    await app.tick(1100);
    check('fix1 #15 newer toasts do not push it off the screen', (await warnings()).length, 1);
    check('no page errors', app.errors, []);
  });
}

async function scenarioUpdateGuard(browser, server) {
  await withApp(browser, server, { replies: { update_check: UPDATE } }, 'fix1 #16 one update run at a time, whatever starts it', async (app) => {
    const { page } = app;
    await page.waitForTimeout(150);
    // The boot's own silent check (autoUpdateCheck) is not one of these.
    const base = await app.count('update_check');
    const checks = async () => (await app.count('update_check')) - base;
    await hold(page, 'update_check');
    await page.evaluate(() => { window.__u1 = manualUpdateCheck(); window.__u2 = manualUpdateCheck(); });
    await page.waitForTimeout(100);
    check('fix1 #16 two checks from the palette send one update_check', await checks(), 1);
    yes('fix1 #16 the second says one is running', (await liveToasts(page)).some((t) => /already/i.test(t)), JSON.stringify(await liveToasts(page)));
    await page.evaluate(() => switchView('settings'));
    await page.waitForSelector('#settingsRows .settings-row');
    await updateButton(page).click();
    await page.waitForTimeout(100);
    check('fix1 #16 "Check now" adds none while the palette\'s check runs', await checks(), 1);
    await page.evaluate(() => switchView('keys'));
    await page.evaluate(() => switchView('settings'));
    await page.waitForSelector('#settingsRows .settings-row');
    await updateButton(page).click();
    await page.waitForTimeout(100);
    check('fix1 #16 nor does a re-rendered "Check now"', await checks(), 1);
    await letGo(page, 'update_check');
    if (await waitVisible(page, '#confirmModal', 1000)) await answerConfirm(page, 'cancel');
    await settled(page, () => window.__u1, null, 1500);
    await page.waitForTimeout(100);
    await page.evaluate(() => { window.__u3 = manualUpdateCheck(); });
    if (await waitVisible(page, '#confirmModal', 1000)) await answerConfirm(page, 'cancel');
    await page.waitForTimeout(100);
    check('fix1 #16 once a run is over, the next check runs', await checks(), 2);
    await hold(page, 'update_download_and_run');
    await page.evaluate(() => { window.__u4 = manualUpdateCheck(); });
    if (await waitVisible(page, '#confirmModal', 1000)) await answerConfirm(page, 'ok');
    await page.waitForFunction(() => window.__calls.some((c) => c.cmd === 'update_download_and_run'));
    await page.evaluate(() => { window.__u5 = manualUpdateCheck(); });
    await page.waitForTimeout(100);
    check('fix1 #16 a check asked for while the update downloads starts nothing',
      [await checks(), await app.count('update_download_and_run'), await app.open('confirmModal')], [3, 1, false]);
    await letGo(page, 'update_download_and_run');
    check('no page errors', app.errors, []);
  });
}

async function scenarioHeadNames(browser, server) {
  await withApp(browser, server, {}, 'fix1 #17 the maximize toggle and Cancel', async (app) => {
    const { page } = app;
    await openLiveTab(app);
    await page.waitForTimeout(150);
    const state = () => page.evaluate(() => [el('termMaxBtn').getAttribute('aria-label'), el('termMaxBtn').getAttribute('aria-pressed')]);
    const before = await state();
    await page.click('#termMaxBtn');
    await page.waitForTimeout(100);
    const after = await state();
    check('fix1 #17 the maximize button keeps its name; aria-pressed alone says it is on', [before, after], [['Maximize terminal', 'false'], ['Maximize terminal', 'true']]);
    await page.click('#termMaxBtn');
    await page.waitForTimeout(100);
    await hold(page, 'terminal_connect');
    await page.evaluate((s) => { window.__o = openSessionTab(s); }, SERVER('s1', 'web-1'));
    await page.waitForFunction(() => window.__calls.filter((c) => c.cmd === 'terminal_connect').length === 2);
    const cancel = await axOf(page, '#termCancelBtn');
    check('fix1 #17 Cancel names what it cancels', cancel && cancel.name, 'Cancel connecting to web-1');
    await letGo(page, 'terminal_connect');
    await page.waitForTimeout(150);
    check('no page errors', app.errors, []);
  });
}

async function scenarioRu6bWarnings(browser, server) {
  const TOOL = {
    name: 'echo', display_name: 'Echo', description: 'Return the text.', enabled: false, auto_approve: false, pinned: false,
    definition_changed: false, definition_hash: 'hash-one', exposed_name: 'mcp__svc__echo', inputSchema: { type: 'object' }, annotations: null,
  };
  const MCPSV = {
    id: 'm1', name: 'svc', url: 'https://mcp.example.test/mcp', auth_type: 'none', auth_header_name: null, auth_env_var: null,
    has_secret: false, protocol_version: '2025-03-26', confirmed: true, loopback_insecure: false, status: 'connected', tool_count: 1, tools: [TOOL],
  };
  const W_TOOL = 'The tool was approved, but its audit row could not be written: disk I/O error';
  const W_SAVE = 'The server was saved, but its audit row could not be written: disk I/O error';
  const W_REMOVE = 'The server was removed, but its audit row could not be written: disk I/O error';
  const W_AI = 'The settings were saved, but their audit row could not be written: disk I/O error';
  const QUERY = 'MCP server URLs cannot contain ?query or #fragment parts.';
  const STALE = 'The saved assistant URL is no longer accepted - open Assistant settings and save it again.';
  const CONFIG = { provider: 'openai', base_url: 'https://api.openai.com/v1', model: 'm', has_api_key: true };
  const replies = { mcp_list_servers: [MCPSV], assistant_get_config: CONFIG };
  await withApp(browser, server, { replies }, 'fix1 #19 MCP and assistant warnings and errors', async (app) => {
    const { page } = app;
    const openSettings = () => page.evaluate(async () => { await switchView('settings'); showSettingsSection('assistant'); await aiLoadConfig(); await mcpLoadSettings(); });
    await openSettings();
    await page.evaluate((w) => { window.__replies.mcp_set_tool_state = { ok: true, warning: w }; }, W_TOOL);
    await page.evaluate(() => mcpShowToolsFor('m1'));
    await page.locator('.mcp-tool-row label').filter({ hasText: /^Enable$/ }).click();
    await page.waitForTimeout(200);
    yes('fix1 #19 an approval\'s warning is shown', (await liveToasts(page)).includes(W_TOOL), JSON.stringify(await liveToasts(page)));

    await page.evaluate((w) => { window.__replies.mcp_save_server = { ok: true, id: 'm1', warning: w }; }, W_SAVE);
    await page.locator('.mcp-server-row button').filter({ hasText: /^Edit$/ }).click();
    await page.click('#mcpSaveBtn');
    await page.waitForTimeout(200);
    yes('fix1 #19 a save\'s warning is shown', (await liveToasts(page)).includes(W_SAVE), JSON.stringify(await liveToasts(page)));

    await page.evaluate((w) => { window.__replies.mcp_remove_server = { ok: true, warning: w }; }, W_REMOVE);
    await page.locator('.mcp-server-row button').filter({ hasText: /^Remove$/ }).click();
    await answerConfirm(page, 'ok');
    await page.waitForTimeout(200);
    const t = await liveToasts(page);
    yes('fix1 #19 a removal\'s audit note is shown as it is', t.some((x) => x.includes(W_REMOVE)), JSON.stringify(t));
    yes('fix1 #19 and not called a failed session teardown', !t.some((x) => /teardown failed/.test(x)), JSON.stringify(t));

    await page.evaluate((w) => { window.__replies.assistant_save_config = { ok: true, warning: w }; }, W_AI);
    await page.click('#aiSaveBtn');
    await page.waitForTimeout(200);
    yes('fix1 #19 the assistant settings\' warning is shown', (await page.textContent('#aiStatus')).includes(W_AI) && (await liveToasts(page)).includes(W_AI),
      JSON.stringify([await page.textContent('#aiStatus'), await liveToasts(page)]));

    await page.evaluate((m) => { window.__replies.assistant_save_config = { ok: true, warning: null }; window.__replies.assistant_test_connection = { $reject: m }; }, STALE);
    await page.click('#aiTestBtn');
    await page.waitForTimeout(250);
    check('fix1 #19 a refused saved URL is shown as it is by Save & test', (await page.textContent('#aiStatus')).trim(), STALE);

    await page.evaluate((m) => { window.__replies.mcp_list_servers = []; window.__replies.mcp_save_server = { $reject: m }; }, QUERY);
    await page.evaluate(() => mcpLoadSettings());
    await page.click('#mcpAddBtn');
    await page.fill('#mcpName', 'svc2');
    await page.fill('#mcpUrl', 'https://mcp2.example.test/mcp');
    await page.click('#mcpSaveBtn');
    await page.waitForTimeout(200);
    yes('fix1 #19 the backend\'s URL refusal is shown as it is', (await liveToasts(page)).includes(QUERY), JSON.stringify(await liveToasts(page)));
    check('no page errors', app.errors, []);
  });
  await withApp(browser, server, { replies }, 'fix1 #19 a chat refused for the saved URL', async (app) => {
    const { page } = app;
    await openLiveTab(app);
    await page.evaluate(() => { if (!assistantIsOpen()) assistantToggle(); });
    await page.waitForTimeout(200);
    await page.evaluate((m) => {
      window.__replies.assistant_get_level = () => ({ level: 'read' });
      window.__replies.assistant_chat = { $reject: m };
    }, STALE);
    await page.fill('#assistantInput', 'hello');
    await page.evaluate(() => { aiSend(); });
    await page.waitForTimeout(400);
    const row = await page.evaluate(() => {
      const r = [...document.querySelectorAll('#assistantMessages .ai-msg.error')].pop();
      return r ? { text: r.firstChild && r.firstChild.textContent, button: !!r.querySelector('button') } : null;
    });
    check('fix1 #19 the chat shows the refusal as it is, with a way to the settings', row, { text: STALE, button: true });
    check('no page errors', app.errors, []);
  });
}

// ─── fix round 2 ────────────────────────────────────────────────────────────

async function scenarioHeldChords(browser, server) {
  for (const [key, label, cmd, opts] of [['l', 'Ctrl+L', 'vault_lock', {}], ['q', 'Ctrl+Q', 'app_quit', { replies: { app_quit: { ok: true } } }]]) {
    await withApp(browser, server, opts, `fix2 #1 holding ${label}`, async (app) => {
      const { page } = app;
      await openLiveTab(app);
      await page.waitForTimeout(200);
      await blur(page);
      await page.evaluate(() => {
        window.__repeats = 0;
        window.addEventListener('keydown', (e) => { if (e.repeat) window.__repeats += 1; }, true);
      });
      await page.keyboard.down('Control');
      await page.keyboard.down(key); // a real press: the question
      const asked = await waitVisible(page, '#confirmModal', 800);
      await page.keyboard.down(key); // the key still held: the keyboard's auto-repeat
      await page.keyboard.down(key);
      await page.waitForTimeout(250);
      check(`the held key did auto-repeat (${label})`, (await page.evaluate(() => window.__repeats)) >= 2, true);
      check(`fix2 #1 holding ${label}: its question stays open and nothing is sent`,
        [asked, await app.open('confirmModal'), await app.count(cmd)], [true, true, 0]);
      await page.keyboard.up(key);
      await page.keyboard.down(key); // released, then pressed again
      await page.keyboard.up(key);
      await page.keyboard.up('Control');
      await page.waitForTimeout(250);
      check(`fix2 #1 ${label} released and pressed again is the yes`, [await app.count(cmd), await app.open('confirmModal')], [1, false]);
      check('no page errors', app.errors, []);
    });
  }
}

async function scenarioOneTest(browser, server) {
  const servers = [SERVER('s1', 'web-1'), PW_SERVER('s2', 'pw-box')];
  const RUNNING = 'A connection test is already running.';
  const rowTest = async (page, id) => {
    await page.click(`#serverList .server-row[data-id="${id}"] .server-row-more`);
    await page.waitForTimeout(60);
    return clickMenuItem(page, /^Test connection$/);
  };
  await withApp(browser, server, { servers, replies: { server_test: { ok: true, latencyMs: 3 } } }, 'fix2 #2 a row test while another test runs', async (app) => {
    const { page } = app;
    await serversView(page);
    await page.evaluate(() => selectServer('s1'));
    await hold(page, 'server_test');
    await page.click('#termTestBtn');
    await page.waitForFunction(() => window.__calls.some((c) => c.cmd === 'server_test'));
    await rowTest(page, 's2');
    await page.waitForTimeout(150);
    check('fix2 #2 a second test is refused before any password is asked',
      [await app.open('connectPwModal'), await app.count('server_test')], [false, 1]);
    yes('fix2 #2 and says so', (await liveToasts(page)).includes(RUNNING), JSON.stringify(await liveToasts(page)));
    await letGo(page, 'server_test');
    await page.waitForTimeout(150);
    await rowTest(page, 's2');
    const asked = await waitVisible(page, '#connectPwModal', 800);
    yes('fix2 #2 once the first is over, the row test runs and asks for its password', asked);
    await page.evaluate(() => testSelectedServer(headServer()));
    await page.waitForTimeout(100);
    check('fix2 #2 a test asked for while that prompt is open is refused too, and the prompt stays',
      [await app.count('server_test'), await app.open('connectPwModal')], [1, true]);
    if (asked) {
      await page.fill('#connectPwInput', 'pw');
      await page.keyboard.press('Enter');
    }
    await page.waitForTimeout(150);
    check('fix2 #2 and the typed password goes with the test it was asked for', await lastArgs(app, 'server_test'), { serverId: 's2', promptPassword: 'pw' });
    check('no page errors', app.errors, []);
  });
}

async function scenarioServerNoMatch(browser, server) {
  const servers = [SERVER('s1', 'web-1'), SERVER('s2', 'db-1')];
  const categories = [CATEGORY_KEY, { id: 'h1', name: 'Empty hosts', parent_id: null, scope: 'host', sort_index: 0, color: null }];
  const noMatch = (page) => page.evaluate(() => {
    const r = document.querySelector('#serverList .server-list-nomatch');
    if (!r) return null;
    const b = r.querySelector('button');
    return { text: r.querySelector('span').textContent, button: b ? b.textContent.trim() : null, role: r.getAttribute('role') };
  });
  const rows = (page) => page.evaluate(() => document.querySelectorAll('#serverList .server-row').length);
  await withApp(browser, server, { servers, categories }, 'fix2 #3 a server filter that matches nothing', async (app) => {
    const { page } = app;
    await serversView(page);
    await page.evaluate(() => selectServer('s2'));
    check('the header shows the selected server', await page.textContent('#termTitle'), 'db-1');
    await page.fill('#serverSearch', 'zzz-nothing');
    await page.waitForTimeout(80);
    check('fix2 #3 a search that matches nothing says so, with a way back', await noMatch(page),
      { text: 'No servers match "zzz-nothing".', button: 'Clear filter', role: 'status' });
    check('fix2 #3 the selected server the filter hides is not selected any more - the header does not show it',
      await page.evaluate(() => [state.connectSelectedId, el('termTitle').textContent, el('termTestBtn').hidden, el('termReconnectBtn').hidden]),
      [null, 'No connection', true, true]);
    await page.click('#serverList .server-list-nomatch button');
    await page.waitForTimeout(80);
    check('fix2 #3 Clear filter brings every server back, the focus in the search box',
      [await rows(page), await page.inputValue('#serverSearch'), await page.evaluate(() => document.activeElement.id)], [2, '', 'serverSearch']);
    await page.fill('#serverSearch', 'web');
    await page.waitForTimeout(80);
    check('a search that matches shows its rows and no "no match" row', [await rows(page), await noMatch(page)], [1, null]);
    await page.fill('#serverSearch', '');
    await page.evaluate(() => setActiveCategory('h1'));
    await page.waitForTimeout(80);
    check('fix2 #3 a category with no servers says so too', await noMatch(page),
      { text: 'No servers match the current filter.', button: 'Clear filter', role: 'status' });
    await page.click('#serverList .server-list-nomatch button');
    await page.waitForTimeout(80);
    check('fix2 #3 and Clear filter resets the category as well', [await rows(page), await page.evaluate(() => state.activeCategoryByScope.host)], [2, 'all']);
    check('no page errors', app.errors, []);
  });
  await withApp(browser, server, { servers: [] }, 'fix2 #3 no servers at all', async (app) => {
    const { page } = app;
    await page.evaluate(() => switchView('connect'));
    await page.waitForTimeout(150);
    check('with no servers the empty state shows, not the "no match" row', [await visible(page, '#serverEmpty'), await noMatch(page)], [true, null]);
    check('no page errors', app.errors, []);
  });
}

// ─── JU6b item 10: the names behind "Apply remote changes" (JU5 F6, RU6b) ───

/// The question as it reads.
const plainConfirm = async (page) => (await confirmText(page)).message;
/// The list of pending changes under the question: one entry per line item,
/// its text, and the text of each value kept to itself in a <bdi>.
const pendingList = (page) => page.evaluate(() => {
  const box = document.querySelector('#confirmModal .bw-pending');
  if (!box) return null;
  return {
    heads: [...box.querySelectorAll('.bw-pending-head')].map((n) => n.textContent),
    items: [...box.querySelectorAll('li')].map((li) => ({ text: li.textContent, values: [...li.querySelectorAll('bdi')].map((b) => b.textContent) })),
    note: (box.querySelector('.bw-pending-note') || {}).textContent || '',
  };
});

async function scenarioBwPendingNames(browser, server) {
  // The reviewers' probes (review F2 / L3): a name that closes the isolate
  // and turns the text around (PDI + RLO), and one that pads itself out to
  // look like a line of its own under pre-wrap.
  const PDI_RLO = 'web-2\u2069\u202Eevil';
  const FAKE_LINE = 'db' + ' '.repeat(150) + 'web-9: 10.0.0.1:22 → 6.6.6.6:22' + ' and so on'.repeat(8);
  const PENDING = {
    ok: true, errors: [], skippedServerOverwrites: 3, skippedServerNew: 4, skippedOverwrites: 1, skippedNew: 3,
    pendingServers: [
      { kind: 'overwrite', name: 'web-1', incomingName: 'web-1 (Bitwarden)', host: '10.0.0.9', port: 2222, localHost: '10.0.0.1', localPort: 22,
        changes: ['host', 'port', 'user', 'password'] },
      { kind: 'new', name: 'db-<img src=x onerror="window.__xss=1">', incomingName: null, host: null, port: null, localHost: null, localPort: null },
      { kind: 'overwrite', name: PDI_RLO, incomingName: PDI_RLO, host: 'a.example', port: 22, localHost: 'a.example', localPort: 22, changes: null },
      { kind: 'overwrite', name: 'v6', incomingName: 'v6', host: '2001:db8::5', port: 22, localHost: '::1', localPort: 22, changes: ['host'] },
      { kind: 'new', name: FAKE_LINE, incomingName: null, host: '10.0.0.7', port: 22, localHost: null, localPort: null },
    ],
    pendingKeys: [
      { kind: 'overwrite', name: 'alpha', incomingName: 'alpha', fingerprint: 'SHA256:NEWfp', localFingerprint: 'SHA256:OLDfp' },
      { kind: 'new', name: 'gamma', incomingName: null, fingerprint: 'SHA256:gammafp', localFingerprint: null },
    ],
    pendingTruncated: true,
  };
  await withApp(browser, server, { replies: { bitwarden_get_config: BW_CONFIG } }, 'JU5 F6 the approval names what it applies', async (app) => {
    const { page } = app;
    await page.evaluate((p) => {
      window.__replies.bitwarden_sync = (a) => (a.allowRemoteOverwrite ? { ok: true, pulled: 2, serversPulled: 2, errors: [] } : p);
    }, PENDING);
    await bwOpen(page);
    await page.click('#bwSyncNowBtn');
    yes('(set-up) the approval is asked', await waitVisible(page, '#confirmModal', 1500));
    const msg = await plainConfirm(page);
    yes('F6 the counts are still said', /3 servers/.test(msg) && /4 new servers/.test(msg) && /3 new keys/.test(msg), msg);
    const list = await pendingList(page);
    yes('F2 the changes are listed under the question, one entry each', !!list && list.items.length === 9, JSON.stringify(list));
    const item = (re) => (list ? list.items.find((i) => re.test(i.text)) : null);
    const web1 = item(/^web-1:/);
    yes('F6 a server overwrite names the server, its address now and the address it would get',
      !!web1 && /^web-1: 10\.0\.0\.1:22 → 10\.0\.0\.9:2222/.test(web1.text) && web1.text.includes('web-1 (Bitwarden)'), JSON.stringify(web1));
    yes('F5 and which of its settings the pull would change', !!web1 && /changes: host, port, user name, saved password/.test(web1.text), JSON.stringify(web1));
    check('F2 each value is kept to itself in a <bdi>', web1 && web1.values, ['web-1', '10.0.0.1:22', '10.0.0.9:2222', 'web-1 (Bitwarden)']);
    yes('F6 a new server is named, and an item without an address says so',
      !!item(/^new: db-<img src=x onerror="window\.__xss=1">, no address/), JSON.stringify(list && list.items));
    const evil = list && list.items.find((i) => i.values.some((v) => v.startsWith('web-2')));
    check('F2 a name cannot close its isolate or turn the text around: those characters are dropped',
      evil && evil.values[0], 'web-2evil');
    const fake = list && list.items.find((i) => i.values.some((v) => v.startsWith('db ')));
    yes('F2 a run of spaces is one space, and a long value is cut short: no line of its own',
      !!fake && !/ {2}/.test(fake.text) && fake.values[0].length <= 80 && fake.values[0].endsWith('…'), JSON.stringify(fake));
    yes('L8 an IPv6 address is bracketed before its port', !!item(/^v6: \[::1\]:22 → \[2001:db8::5\]:22/), JSON.stringify(list && list.items));
    yes('F6 a key overwrite names the key and the fingerprint it would get', !!item(/^alpha: SHA256:OLDfp → SHA256:NEWfp/), JSON.stringify(list && list.items));
    yes('F6 a new key is named with its fingerprint', !!item(/^new: gamma, SHA256:gammafp/), JSON.stringify(list && list.items));
    check('F6 a cut list says how many more there are', list && list.items.filter((i) => /^and \d+ more$/.test(i.text)).map((i) => i.text), ['and 2 more', 'and 2 more']);
    yes('F5 and that Apply applies the ones not listed too', !!list && /not listed/.test(list.note) && /Apply/.test(list.note), list && list.note);
    check('F6 every name stays text, never markup',
      await page.evaluate(() => [document.querySelectorAll('#confirmModal img').length, window.__xss || 0]), [0, 0]);
    check('F2 no direction or isolate character reaches the dialog',
      await page.evaluate(() => /[\u202A-\u202E\u2066-\u2069\u061C]/.test(document.getElementById('confirmModal').textContent)), false);
    await answerConfirm(page, 'ok');
    await page.waitForTimeout(250);
    check('OK still applies them', (await app.calls('bitwarden_sync')).map((c) => c.args.allowRemoteOverwrite), [false, true]);
    await page.evaluate(() => { window.__next = confirmModal('Another question', 'Something else', 'OK'); });
    await waitVisible(page, '#confirmModal');
    check('the list leaves with its question (the dialog is shared)', await pendingList(page), null);
    await answerConfirm(page, 'cancel');
    check('no page errors', app.errors, []);
  });

  // A backend without the lists (RU6b not in it yet): today's counts, nothing else.
  await withApp(browser, server, { replies: { bitwarden_get_config: BW_CONFIG } }, 'JU5 F6 without the lists', async (app) => {
    const { page } = app;
    await page.evaluate(() => {
      window.__replies.bitwarden_sync = (a) => (a.allowRemoteOverwrite ? { ok: true, errors: [] }
        : { ok: true, errors: [], skippedOverwrites: 2, skippedServerNew: 1 });
    });
    await bwOpen(page);
    await page.click('#bwSyncNowBtn');
    yes('(set-up) the approval is asked', await waitVisible(page, '#confirmModal', 1500));
    check('F6 without pending lists the question is the counts alone', await plainConfirm(page),
      'Bitwarden has changes that need your approval: 2 keys replaced by a newer Bitwarden copy, 1 new server from Bitwarden. Apply them now?');
    await answerConfirm(page, 'cancel');
    check('no page errors', app.errors, []);
  });
}

// ─── JU6b fix round 2: Bitwarden names in the status line ───────────────────

async function scenarioBwStatusNames(browser, server) {
  // The "Renamed:" part of a sync's summary names Bitwarden items too: an
  // override in one turned the rest of the status line around.
  const RESULT = {
    ok: true, errors: [], pulled: 1,
    renamed: [{ name: 'web\u202Etxt.exe', storedAs: 'web\u202Etxt.exe (2)' }, { name: 'db\u2069\u202E', storedAs: 'db (2)' }],
  };
  await withApp(browser, server, { replies: { bitwarden_get_config: BW_CONFIG, bitwarden_sync: RESULT } }, 'round 2 #5 renamed items in the status line', async (app) => {
    const { page } = app;
    await bwOpen(page);
    await page.click('#bwSyncNowBtn');
    await page.waitForTimeout(250);
    const text = (await bwStatus(page)).text;
    check('round 2 #5 a renamed name cannot turn the status line around: its direction characters are dropped',
      /[\u202A-\u202E\u2066\u2067\u200E\u200F\u061C]/.test(text), false);
    yes('round 2 #5 and each name is kept to itself, closing its own isolate',
      text.includes('Renamed: \u2068webtxt.exe\u2069 stored as \u2068webtxt.exe (2)\u2069, \u2068db\u2069 stored as \u2068db (2)\u2069.'),
      JSON.stringify(text));
    check('no page errors', app.errors, []);
  });
}

// ─── JU6b item 11: the server list keeps the HOST category everywhere ───────

async function scenarioHostScopeReload(browser, server) {
  const servers = [SERVER('s1', 'web-1'), SERVER('s2', 'db-1')];
  await withApp(browser, server, { servers }, 'JU5 review: a server list rebuilt from Keys', async (app) => {
    const { page } = app;
    await serversView(page);
    await page.evaluate(() => selectServer('s2'));
    check('(set-up) db-1 is selected', await page.textContent('#termTitle'), 'db-1');
    await page.evaluate(() => switchView('keys'));
    await page.waitForTimeout(80);
    await page.evaluate(() => setActiveCategory('c1'));
    check('(set-up) the key list is filtered by key category c1', await page.evaluate(() => activeCategoryId()), 'c1');
    // What a Bitwarden sync started from Settings does: the server list is
    // read again while another view - and another category tree - is shown.
    await page.evaluate(() => loadServers());
    await page.waitForTimeout(80);
    await serversView(page);
    await page.waitForTimeout(80);
    check('the server list was filtered by the HOST category: both rows are still listed',
      await page.evaluate(() => [...document.querySelectorAll('#serverList .server-row')].map((r) => r.dataset.id)), ['s1', 's2']);
    check('the selection is kept', await page.evaluate(() => state.connectSelectedId), 's2');
    check('and the header does not read "No connection"', await page.textContent('#termTitle'), 'db-1');
    check('no page errors', app.errors, []);
  });
}

// ─── runner ─────────────────────────────────────────────────────────────────

const SCENARIOS = [
  ['item 1: server form - saved passwords (A2-04 A5-03)', scenarioSavedPassword],
  ['item 1: server form - port (A2-39 A5-30)', scenarioPort],
  ['item 1: Test - prompt, one call, toasts (A2-11 A5-20 A2-18 A2-25)', scenarioTestButton],
  ['item 1: "Use this key" picker (A2-35 A5-41)', scenarioPicker],
  ['item 1: server rows - actions button, layout (A5-28 A1-20)', scenarioRows],
  ['item 1: server form - key row, titles (A1-21 A8-25)', scenarioServerForm],
  ['item 1: ~/.ssh/config import (R4 A2-43)', scenarioConfigImport],
  ['item 2: closing or cancelling mid-connect (A2-12 A5-10)', scenarioCloseMidConnect],
  ['item 2: status line and focus (A2-25 A3-27)', scenarioStrip],
  ['item 2: Reconnect (A2-44 A3-10)', scenarioReconnect],
  ['item 2: restart (A3-13 A3-14)', scenarioRestart],
  ['item 2: overlapping connects (A3-14)', scenarioOverlap],
  ['item 2: restart keeps the scrollback (A3-36)', scenarioScrollback],
  ['item 2: connect errors as they are (RU4)', scenarioMessages],
  ['item 3: key compatibility, Backspace (A8-03 A3-26)', scenarioKeys],
  ['item 3: bell (A3-26)', scenarioBell],
  ['item 3: paste paths (A3-11)', scenarioPastePaths],
  ['item 3: chords in the terminal (A5-44 A2-53)', scenarioChords],
  ['item 3: developer traces (A5-11)', scenarioTraces],
  ['item 3: OSC 8 links (A6-12)', scenarioOscLinks],
  ['item 3: padding and the maximize button (A1-38)', scenarioLayout],
  ['item 3: terminal menu (A3-31 A5-33)', scenarioTermMenu],
  ['item 3: resize chatter (A3-34 #4)', scenarioResize],
  ['item 3: one "[connection closed]" (A3-34 #5)', scenarioClosedOnce],
  ['item 3: terminal focus (JU4 JU6a)', scenarioFocus],
  ['item 4: Quit (R11)', scenarioQuit],
  ['item 4: tray notice (R11)', scenarioTray],
  ['item 4: version (R12 A2-24 A8-26)', scenarioVersion],
  ['item 5: manual lock (A5-09)', scenarioManualLock],
  ['item 5: idle-lock warning (A5-09)', scenarioIdleWarning],
  ['item 6: updater (A5-22 A2-41)', scenarioUpdater],
  ['item 7: Bitwarden form (A5-35 A8-25)', scenarioBwForm],
  ['item 7: Bitwarden test and save (A2-52 A2-18)', scenarioBwTest],
  ['item 7: Bitwarden sync (A2-08 A7-24 A2-47)', scenarioBwSync],
  ['item 8: Upload (A5-40)', scenarioUpload],
  ['item 9: approval cards (JU3)', scenarioCardEscapes],
  ['fix1 #1: a restart cancelled at the password prompt', scenarioRestartCancel],
  ['fix1 #2: the terminal header fits', scenarioHeadFits],
  ['fix1 #3: the saved-password hint as a description', scenarioHintDescription],
  ['fix1 #4 #7: terminal links', scenarioLinkSafety],
  ['fix1 #5: hidden characters on cards', scenarioCardCoverage],
  ['fix1 #6: the lock and quit questions', scenarioChordAnswers],
  ['fix1 #8: paste control characters', scenarioPasteClean],
  ['fix1 #10: sync summary groups', scenarioSyncGroups],
  ['fix1 #11: upload picks skipped', scenarioUploadSkipped],
  ['fix1 #12 #13: Test connection from a row', scenarioRowTest],
  ['fix1 #15: the idle warning', scenarioIdleRealTime],
  ['fix1 #16: one update run', scenarioUpdateGuard],
  ['fix1 #17: header names', scenarioHeadNames],
  ['fix1 #19: RU6b warnings and errors', scenarioRu6bWarnings],
  ['fix2 #1: held lock and quit chords', scenarioHeldChords],
  ['fix2 #2: one connection test at a time', scenarioOneTest],
  ['fix2 #3: a server filter with no matches', scenarioServerNoMatch],
  ['JU6b item 10: Bitwarden approval names (JU5 F6)', scenarioBwPendingNames],
  ['JU6b item 11: the host category survives a reload from Keys', scenarioHostScopeReload],
  ['JU6b fix round 2: Bitwarden names in the status line', scenarioBwStatusNames],
  ['server retarget: a changed server needs its password again (S1)', scenarioServerRetarget],
  ['bitwarden last result: the status line after a stopped or failed run', scenarioBwLastResult],
  ['bitwarden approval: the token, a changed list, a list too long (S4 S6)', scenarioBwApproval],
  ['settings lock gates: Bitwarden, backup and Lock now (A6-08 B1)', scenarioSettingsLockGates],
  ['bitwarden destination: not allowed yet, Allow syncing... (J4)', scenarioBwDestination],
  ['new server in a filtered list (A5-42 J5)', scenarioServerNewInFilter],
  ['server save warning (R10 J6)', scenarioServerSaveWarning],
  ['bitwarden texts spelled out (J7)', scenarioBwSpelled],
];

(async () => {
  const only = process.argv.includes('--only') ? process.argv[process.argv.indexOf('--only') + 1] : null;
  if (!only || 'static'.includes(String(only).toLowerCase())) runStatic();
  const chromium = loadChromium();
  if (!chromium) {
    console.log('playwright not installed - skipping the browser checks.');
    process.exit(failures.length ? 1 : 0);
  }
  const server = await serve(RENDERER);
  const browser = await chromium.launch();
  try {
    for (const [title, fn] of SCENARIOS) {
      if (only && !title.toLowerCase().includes(String(only).toLowerCase())) continue;
      console.log(title);
      await part(title, () => fn(browser, server));
    }
  } finally {
    await browser.close();
    server.close();
  }
  if (failures.length) {
    console.error(`\n${failures.length} servers/terminal UI check(s) failed.`);
    process.exit(1);
  }
  console.log('\nAll servers/terminal UI checks passed.');
})().catch((e) => { console.error(e); process.exit(1); });
