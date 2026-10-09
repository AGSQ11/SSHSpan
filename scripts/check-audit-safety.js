#!/usr/bin/env node
/*
 * Safety and lifecycle regression checks for the renderer, driven through the
 * REAL page (index.html + app.js + terminal.js + sftp.js + assistant.js +
 * mcp.js + the vendored xterm) in headless Chromium, against a stub Tauri IPC.
 *
 * Nothing here re-implements production logic. The stub only answers invoke()
 * the way the Rust side would (and records what was asked); every behaviour
 * asserted below is observed on the page: which dialogs are visible, what has
 * focus, which IPC commands were sent, what is left in the DOM.
 *
 * What it pins (flaw-audit 2026-10-09, group 1):
 *   - no guard depends on the native confirm(): tauri-plugin-dialog replaces
 *     window.confirm with an async function, so `if (!confirm(..)) return` can
 *     never return. The stub here does exactly that (a rejected Promise, which
 *     is what the shipped plugin does under this app's ACL).
 *   - Cancel / Escape / backdrop have no effect, one confirmation at a time,
 *     Cancel is focused first, and locking the vault settles pending dialogs.
 *   - idle auto-lock: absent setting means 15, explicit 0 means off, the 10 s
 *     status poll never extends idle time, typing in xterm does, remote output
 *     does not, and the backend heartbeat follows real activity (fake clock).
 *   - vault dialog: change mode survives polls, a dismissed gate stays
 *     dismissed, current password comes first, lock wipes every secret field.
 *   - dialog stacking, Escape closing only the top layer, chords suppressed
 *     behind dialogs, no focus theft by terminal timers, fail-closed YOLO.
 *   - a native paste (Shift+Insert, middle-click, the Edit menu; a plain Ctrl+V
 *     is ^V to a terminal) goes through the same multi-line review as the
 *     explicit paste, once, with bracketed paste preserved.
 *
 * Run with `npm run test:safety`. Needs playwright, which is not a
 * devDependency (see check-renderer-ui.js):
 *
 *     npm install --no-save playwright@1.56.1 && npx playwright install chromium
 *
 * Without it this skips (exit 0) so a checkout that has not set it up still
 * runs every other check. Optional: `--only <text>` runs the scenarios whose
 * title contains <text>; SSHSPAN_RENDERER_DIR points the run at another copy of
 * the renderer (for example a pristine `git archive` of an older commit, to
 * watch these checks fail where they should).
 */
'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');

const failures = [];
function check(name, got, want) {
  const ok = JSON.stringify(got) === JSON.stringify(want);
  console.log(`  ${ok ? 'ok  ' : 'FAIL'}  ${name}`);
  if (!ok) {
    console.log(`          got:  ${JSON.stringify(got)}`);
    console.log(`          want: ${JSON.stringify(want)}`);
    failures.push(name);
  }
}
function yes(name, cond, detail) {
  check(name, !!cond, true);
  if (!cond && detail !== undefined) console.log(`          note: ${detail}`);
}

// ─── static guard: no native confirm() left in the renderer ────────────────
//
// Runs first and needs no browser, so it still runs where Playwright is not
// installed (like the MCP contract block in check-renderer-ui.js).

const RENDERER = process.env.SSHSPAN_RENDERER_DIR
  ? path.resolve(process.env.SSHSPAN_RENDERER_DIR)
  : path.join(__dirname, '..', 'src', 'renderer');
const RENDERER_JS = ['app.js', 'terminal.js', 'sftp.js', 'mcp.js', 'assistant.js'];

/**
 * Drop comments, string and template literals and regex literals, so prose
 * cannot produce hits and a quote inside a regex cannot swallow code. (The
 * first version treated the quote in escapeHtml's /"/g as the start of a string
 * and lost sync for the rest of the file; the bracket-balance check below is
 * what catches that class of mistake.)
 *
 * A "/" opens a regex literal when the last significant character is one that
 * cannot end an operand - ( , = : [ ! & | ? { } ; + - * % < > ~ ^ - or the last
 * word was a keyword such as return; after an identifier, number, ) or ] it is
 * a division. A regex never spans a line, so a wrong guess costs one line.
 */
function scrub(src) {
  const KEYWORDS = new Set(['return', 'typeof', 'case', 'in', 'of', 'delete', 'void', 'throw', 'new', 'else', 'do', 'instanceof', 'yield', 'await']);
  const REGEX_AFTER = '(,=:[!&|?{};+-*%<>~^';
  let out = '';
  let prev = '';   // last significant (non-space) character
  let word = '';   // identifier or number being read, or the one just finished
  let last = '';   // previous raw character
  let i = 0;
  while (i < src.length) {
    const c = src[i];
    const n = src[i + 1];
    if (c === '/' && n === '/') { while (i < src.length && src[i] !== '\n') i++; continue; }
    if (c === '/' && n === '*') {
      i += 2;
      while (i < src.length && !(src[i] === '*' && src[i + 1] === '/')) { if (src[i] === '\n') out += '\n'; i++; }
      i += 2;
      continue;
    }
    if (c === "'" || c === '"' || c === '`') {
      const q = c; i++;
      while (i < src.length) {
        if (src[i] === '\\') { i += 2; continue; }
        if (src[i] === '\n') out += '\n';
        if (src[i] === q) { i++; break; }
        i++;
      }
      out += '""'; prev = '"'; word = ''; last = '"';
      continue;
    }
    if (c === '/' && (prev === '' || REGEX_AFTER.includes(prev) || KEYWORDS.has(word))) {
      i++;
      let inClass = false;
      while (i < src.length) {
        const d = src[i];
        if (d === '\\') { i += 2; continue; }
        if (d === '\n') break;
        if (inClass) { if (d === ']') inClass = false; }
        else if (d === '[') inClass = true;
        else if (d === '/') { i++; break; }
        i++;
      }
      while (i < src.length && /[a-z]/i.test(src[i])) i++;
      out += '0'; prev = '0'; word = ''; last = '0';
      continue;
    }
    out += c;
    if (/[\w$]/.test(c)) word = /[\w$]/.test(last) ? word + c : c;
    else if (!/\s/.test(c)) word = '';
    if (!/\s/.test(c)) prev = c;
    last = c;
    i++;
  }
  return out;
}

const nativeConfirmLine = (line) =>
  /(^|[^.\w$])confirm\s*\(/.test(line) || /\b(?:window|globalThis|self)\.confirm\s*\(/.test(line);

function nativeConfirmSites(clean, label) {
  const sites = [];
  clean.split('\n').forEach((line, idx) => {
    if (nativeConfirmLine(line)) sites.push(`${label}:${idx + 1}  ${line.trim()}`);
  });
  return sites;
}

const brackets = (s) => ({
  braces: (s.match(/\{/g) || []).length - (s.match(/\}/g) || []).length,
  parens: (s.match(/\(/g) || []).length - (s.match(/\)/g) || []).length,
  squares: (s.match(/\[/g) || []).length - (s.match(/\]/g) || []).length,
});

function runStaticChecks() {
  console.log('static: no native confirm() in the renderer (no browser needed)');
  // The scan is only as good as the scrubber: a regex literal holding a quote
  // (escapeHtml has /"/g) once made it lose sync and skip ~90 boot lines.
  const probes = [
    'function esc(s) { return s.replace(/"/g, "&quot;").replace(/\'/g, "&#39;"); }\nconst a = confirm("x");\n',
    'const q = a / b; const r = /[/"]x/g; const c = window.confirm("y");\n',
    '// confirm("comment")\n/* confirm("block") */ const t = `confirm(`; const d = 4 / 2;\nif (!confirm("z")) return;\n',
  ];
  check('the scrubber still finds a confirm() call after regex literals, divisions, comments and templates',
    probes.map((p) => nativeConfirmSites(scrub(p), 'probe').length), [1, 1, 1]);
  const sites = [];
  const unbalanced = {};
  for (const f of RENDERER_JS) {
    const clean = scrub(fs.readFileSync(path.join(RENDERER, f), 'utf8'));
    sites.push(...nativeConfirmSites(clean, f));
    const b = brackets(clean);
    if (b.braces || b.parens || b.squares) unbalanced[f] = b;
  }
  check('the scrubber stays in sync with every renderer script (brackets balance)', unbalanced, {});
  check('every guard uses the in-app dialog', sites, []);
}
runStaticChecks();

// ─── playwright ─────────────────────────────────────────────────────────────

let chromium;
try {
  ({ chromium } = require('playwright'));
} catch {
  try {
    ({ chromium } = require(path.join(
      require('child_process').execSync('npm root -g', { encoding: 'utf8' }).trim(), 'playwright')));
  } catch {
    console.log('playwright not installed - skipping the browser checks.');
    if (failures.length) console.error(`\n${failures.length} audit safety check(s) failed.`);
    process.exit(failures.length ? 1 : 0);
  }
}

const TYPES = {
  '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css',
  '.svg': 'image/svg+xml', '.png': 'image/png', '.woff2': 'font/woff2',
};

const delay = (ms) => new Promise((r) => setTimeout(r, ms));
const firstLine = (e) => String((e && e.message) || e).split('\n')[0];

/// A block that may throw (a selector that never appears, a timeout) must fail
/// its own checks, not take the rest of the scenario down with it.
async function part(title, fn) {
  try {
    await fn();
  } catch (e) {
    console.log(`  FAIL  ${title} - aborted: ${firstLine(e)}`);
    failures.push(`${title} (aborted)`);
  }
}

/// Serve src/renderer over http: file:// would block the module loads.
function serve() {
  const server = http.createServer((req, res) => {
    const rel = decodeURIComponent(req.url.split('?')[0]).replace(/^\/+/, '') || 'index.html';
    const file = path.join(RENDERER, rel);
    if (!file.startsWith(RENDERER) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) {
      res.writeHead(404); res.end('not found'); return;
    }
    res.writeHead(200, { 'Content-Type': TYPES[path.extname(file)] || 'application/octet-stream' });
    res.end(fs.readFileSync(file));
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server)));
}

// ─── the stub backend (runs inside the page) ────────────────────────────────

/// Installed before any page script. It answers the commands the renderer
/// sends, records every call in window.__calls, and exposes just enough control
/// for a test: window.__backend (vault/session state), window.__replies
/// (per-command override: a value or a function(args)), window.__gates (hold a
/// command until released), window.__emit (fire a Tauri event).
function stubInit(cfg) {
  const calls = [];
  const listeners = {};
  const backend = {
    hasVault: cfg.hasVault, unlocked: cfg.unlocked,
    settings: Object.assign({}, cfg.settings),
    sessions: [], channels: [],
  };
  const clone = (v) => {
    try { return JSON.parse(JSON.stringify(v === undefined ? null : v)); } catch (e) { return String(v); }
  };
  window.__calls = calls;
  window.__backend = backend;
  window.__gates = {};
  window.__replies = Object.assign({}, cfg.replies);
  window.__nativeDialogCalls = 0;

  // What tauri-plugin-dialog installs, under this app's ACL (no dialog:*
  // permission): an async function, so callers get a Promise - always truthy -
  // that then rejects because the command is not allowed.
  window.confirm = () => {
    window.__nativeDialogCalls += 1;
    return Promise.reject(new Error('plugin:dialog|confirm not allowed by ACL'));
  };
  window.alert = () => {
    window.__nativeDialogCalls += 1;
    return Promise.reject(new Error('plugin:dialog|message not allowed by ACL'));
  };

  const H = {
    vault_status: () => ({ hasVault: backend.hasVault, unlocked: backend.unlocked }),
    vault_lock: () => { backend.unlocked = false; return { ok: true }; },
    vault_unlock: (a) => {
      if (a.password !== cfg.password) throw 'Incorrect master password.';
      backend.unlocked = true; return { ok: true };
    },
    vault_create: () => { backend.hasVault = true; backend.unlocked = true; return { ok: true }; },
    vault_change_password: () => ({ ok: true }),
    settings_get: () => Object.assign({}, backend.settings),
    settings_set: (a) => { backend.settings[a.key] = a.value; return { ok: true }; },
    key_list: () => ({ keys: cfg.keys }),
    key_get: (a) => cfg.keys.find((k) => k.id === a.id) || cfg.keys[0],
    category_list: () => ({ categories: cfg.categories, allKeyCategories: {}, orphans: false, hostOrphans: false }),
    server_list: () => ({ servers: cfg.servers }),
    system_paths: () => ({ database: '/data/sshspan.db', sshConfig: '/cfg/ssh_config', deployDir: '/home/u/.ssh' }),
    key_deploy: () => ({ keys: [{ name: 'alpha', file: '/home/u/.ssh/sshspan_alpha' }] }),
    update_check: () => ({ available: false, current: '1.9.1' }),
    known_hosts_list: () => ({ hosts: [] }),
    audit_list: () => ({ rows: [], total: 0 }),
    bitwarden_get_config: () => ({}),
    mcp_list_servers: () => [],
    terminal_connect: (a) => {
      const id = 'sess-' + (backend.sessions.length + 1);
      backend.sessions.push(id);
      backend.channels.push(a.onData);
      return { ok: true, sessionId: id };
    },
    terminal_list: () => ({ active: backend.sessions.map((sessionId) => ({ sessionId })) }),
    terminal_disconnect: (a) => { backend.sessions = backend.sessions.filter((s) => s !== a.sessionId); return {}; },
    sftp_list_dir: () => ({ entries: [], path: '/' }),
  };

  async function invoke(cmd, args) {
    calls.push({ cmd, args: clone(args) });
    const gate = window.__gates[cmd];
    if (gate) await gate.promise;
    const r = window.__replies[cmd];
    if (typeof r === 'function') return r(args || {});
    if (r !== undefined) return r;
    const h = H[cmd];
    return h ? h(args || {}) : {};
  }

  window.__TAURI__ = {
    core: { invoke, Channel: class { constructor() { this.onmessage = null; } } },
    event: {
      listen: async (name, cb) => {
        (listeners[name] = listeners[name] || []).push(cb);
        return () => { listeners[name] = (listeners[name] || []).filter((f) => f !== cb); };
      },
    },
  };
  window.__emit = (name, payload) => { for (const cb of (listeners[name] || [])) cb({ payload }); };

  // Count outstanding long timers (the auto-lock timer is minutes long; every
  // other timer in the app is seconds), so "exactly one timer" is observable.
  if (cfg.countTimers) {
    const live = new Map();
    const st = window.setTimeout;
    const ct = window.clearTimeout;
    window.setTimeout = function (fn, ms, ...rest) {
      const id = st.call(this, function (...a) { live.delete(id); return fn.apply(this, a); }, ms, ...rest);
      if (typeof ms === 'number' && ms >= 30000) live.set(id, ms);
      return id;
    };
    window.clearTimeout = function (id) { live.delete(id); return ct.call(this, id); };
    window.__longTimers = () => live.size;
  }
}

// ─── fixtures and helpers ───────────────────────────────────────────────────

const PASSWORD = 'correct horse battery';
const T0 = Date.parse('2026-06-01T12:00:00Z');
const KEY = (id, name) => ({
  id, name, key_type: 'ed25519', has_private: true, public_key: 'ssh-ed25519 AAAA' + id,
  fingerprint_sha256: 'SHA256:' + id, comment: name + '@host', created_at: '2026-09-01T10:00:00Z',
  deployed: false, bitwarden_sync: false, category_ids: [],
});
const SERVER = (id, name, auth) => ({
  id, name, host: '10.0.0.' + id.replace(/\D/g, ''), port: 22, username: 'root',
  authMethod: auth || 'publickey', hasSavedPassword: false, categoryId: null, keyId: null, pemPath: null,
});
const CATEGORY = { id: 'c1', name: 'Prod', parent_id: null, scope: 'key', sort_index: 0, color: null };

/// Open the real app against the stub. `clock: true` installs Playwright's fake
/// clock and pauses it after boot, so time only moves through app.tick().
async function openApp(browser, server, o = {}) {
  const context = await browser.newContext({ viewport: { width: 1400, height: 900 } });
  // The paste checks put real text on the clipboard and press a real key.
  await context.grantPermissions(['clipboard-read', 'clipboard-write'], { origin: `http://127.0.0.1:${server.address().port}` });
  const page = await context.newPage();
  page.setDefaultTimeout(3500);
  const errors = [];
  page.on('pageerror', (e) => errors.push(String((e && e.message) || e)));
  const warnings = [];
  page.on('console', (m) => { if (m.type() === 'warning') warnings.push(m.text()); });
  if (o.clock) await page.clock.install({ time: T0 });
  await page.addInitScript(stubInit, {
    hasVault: o.hasVault !== false,
    unlocked: o.unlocked !== false,
    settings: o.settings || {},
    keys: o.keys || [KEY('k1', 'alpha'), KEY('k2', 'beta')],
    servers: o.servers || [SERVER('s1', 'web-1')],
    categories: o.categories || [CATEGORY],
    replies: o.replies || {},
    password: PASSWORD,
    countTimers: !!o.countTimers,
  });
  await page.goto(`http://127.0.0.1:${server.address().port}/index.html`);
  // main() reads settings only after every script has loaded and the first
  // vault_status has been applied, so this means "booted".
  await page.waitForFunction(() => window.__calls.some((c) => c.cmd === 'settings_get'));
  await page.waitForTimeout(60);
  if (o.clock) {
    const now = await page.evaluate(() => Date.now());
    await page.clock.pauseAt(now + 20);
  }
  const app = {
    page, context, errors, warnings,
    calls: (cmd) => page.evaluate((c) => window.__calls.filter((x) => !c || x.cmd === c), cmd || null),
    count: async (cmd) => (await app.calls(cmd)).length,
    // runFor fires every timer in between (polls, tickers); jump fires each due
    // timer once, like a laptop lid closing for a while - cheap for long spans.
    tick: (ms) => page.clock.runFor(ms),
    jump: (ms) => page.clock.fastForward(ms),
    open: (id) => page.evaluate((i) => { const n = document.getElementById(i); return !!n && !n.hidden; }, id),
    focused: () => page.evaluate(() => (document.activeElement && (document.activeElement.id || document.activeElement.className)) || ''),
    openIds: () => page.evaluate(() => [...document.querySelectorAll('.modal-backdrop')].filter((n) => !n.hidden).map((n) => n.id)),
    close: () => context.close(),
  };
  return app;
}

/// Run `fn(app)` on a fresh app; always close it, and contain any throw.
async function withApp(browser, server, opts, title, fn) {
  await part(title, async () => {
    const app = await openApp(browser, server, opts);
    try { await fn(app); } finally { await app.close().catch(() => {}); }
  });
}

/// Value of an in-page promise, or 'PENDING' if it does not settle: a dialog
/// that never answers must fail a check, not hang the whole run.
async function settled(page, fn, arg, ms) {
  const p = page.evaluate(fn, arg).catch((e) => ({ error: firstLine(e) }));
  return Promise.race([p, delay(ms || 1500).then(() => 'PENDING')]);
}

async function waitVisible(page, sel, ms) {
  try { await page.waitForSelector(sel, { state: 'visible', timeout: ms || 1500 }); return true; } catch { return false; }
}

async function focusIs(page, id, ms) {
  try {
    await page.waitForFunction((i) => document.activeElement && document.activeElement.id === i, id, { timeout: ms || 1500, polling: 25 });
    return true;
  } catch { return false; }
}

/// Answer the app's confirmation dialog if it appears; says whether it did.
async function answerConfirm(page, how) {
  if (!(await waitVisible(page, '#confirmModal', 1200))) return false;
  if (how === 'ok') await page.click('#confirmOkBtn');
  else if (how === 'escape') await page.keyboard.press('Escape');
  else await page.click('#confirmCancelBtn');
  return true;
}

/// Start a live shell tab through the production entry point.
async function openLiveTab(app, auth) {
  const { page } = app;
  const srv = Object.assign(SERVER('s1', 'web-1', auth || 'publickey'), { hasSavedPassword: false });
  await page.evaluate((s) => { window.__tabStart = openSessionTab(s); }, srv);
  if ((auth || 'publickey') !== 'publickey') return null;
  await page.waitForFunction(() => Array.from(state.sessions.keys()).some((id) => window.tabSessionLive(id)), null, { polling: 25 });
  return page.evaluate(() => [...state.sessions.keys()][0]);
}

const bytesOf = (c) => String.fromCharCode(...(c.args.bytes || []));
const sends = async (app) => (await app.calls('terminal_send')).map(bytesOf);

// ─── scenarios ──────────────────────────────────────────────────────────────

/// confirmModal's own contract: one at a time, safe default, settles once.
async function scenarioConfirmContract(browser, server) {
  await withApp(browser, server, {}, 'confirm contract', async (app) => {
    const { page } = app;
    await page.evaluate(() => {
      window.__a = confirmModal('First', 'first question', 'Yes');
      window.__b = confirmModal('Second', 'second question', 'Yes');
    });
    check('a second question while one is open is refused (fails closed)',
      await settled(page, () => window.__b, null, 800), false);
    check('and it does not rewrite the question being answered', await page.textContent('#confirmTitle'), 'First');
    await page.click('#confirmOkBtn');
    check('OK answers only the first question', await settled(page, () => window.__a, null, 800), true);
    yes('the dialog closes', !(await app.open('confirmModal')));

    await page.evaluate(() => { window.__c = confirmModal('Third', 'again', 'Do it'); });
    yes('a new question can be asked once the last is answered', await waitVisible(page, '#confirmModal'));
    check('the button carries the caller label', await page.textContent('#confirmOkBtn'), 'Do it');
    await page.evaluate(() => document.getElementById('confirmModal').click());
    check('clicking the backdrop is a no', await settled(page, () => window.__c, null, 800), false);

    // Neither button handler may survive to answer the next question.
    await page.evaluate(() => { window.__d = confirmModal('Fourth', 'fresh', 'Go'); });
    await answerConfirm(page, 'cancel');
    check('Cancel answers no', await settled(page, () => window.__d, null, 800), false);
    await page.evaluate(() => { window.__e = confirmModal('Fifth', 'fresh again', 'Go'); });
    await answerConfirm(page, 'ok');
    check('handlers from an earlier question do not answer the next one',
      await settled(page, () => window.__e, null, 800), true);

    // If something hides the dialog without answering it, that must neither
    // wedge every later question nor leave its caller waiting for ever.
    await page.evaluate(() => {
      window.__f = confirmModal('Stale', 'hidden behind its back', 'Go');
      document.getElementById('confirmModal').hidden = true;
      window.__g = confirmModal('After', 'asked next', 'Go');
    });
    check('a question hidden without an answer is answered no when the next one is asked',
      await settled(page, () => window.__f, null, 800), false);
    yes('and the next question is shown', await waitVisible(page, '#confirmModal'));
    check('with its own text', await page.textContent('#confirmTitle'), 'After');
    await answerConfirm(page, 'ok');
    check('and answered normally', await settled(page, () => window.__g, null, 800), true);
    check('no page errors', app.errors, []);
  });
}

/// A5-01: every guard asks in-app, and Cancel / Escape change nothing.
async function scenarioGuards(browser, server) {
  const opts = {
    settings: { confirmDelete: 'true' },
    replies: {
      known_hosts_list: { hosts: [{ host: 'example.org', fingerprintSha256: 'SHA256:abc', firstSeen: '2026-01-01T00:00:00Z' }] },
      update_check: { available: true, current: '1.9.1', version: '9.9.9', notes: 'notes', assetUrl: 'https://example.invalid/x', assetDigest: 'abc' },
      system_select_file: { canceled: false, text: '{"v":1}', path: '/tmp/b.json', name: 'b.json' },
      vault_backup_restore: { counts: { keys: 0, categories: 0, servers: 0, knownHosts: 0 } },
      category_delete: { reassigned: [] },
    },
  };
  await withApp(browser, server, opts, 'guards', async (app) => {
    const { page } = app;
    await page.evaluate(() => {
      window.__replies.bitwarden_sync = (a) => (a.allowRemoteOverwrite
        ? { pushed: 0, pulled: 1 } : { skippedOverwrites: 1, skippedNew: 0 });
    });
    await page.evaluate(() => loadKnownHosts());
    await openLiveTab(app);
    // A plain tab record with an SFTP panel for the move guard (no shell).
    // buildSftpPanel() wires the pane's drop listeners before the panel is in
    // the document (getElementById finds nothing yet), so wire it again once it
    // is attached - that is the state the listeners are meant to run in.
    await page.evaluate(() => {
      state.sessions.set('tm', { tabId: 'tm', sessionId: 'sess-move', serverId: 's1', serverName: 'files', host: '10.0.0.1', port: 22, mode: 'sftp', sftpReady: true, sftpPath: '/srv', ended: false });
      const panel = buildSftpPanel('tm');
      document.getElementById('sftpBody').appendChild(panel);
      wireSftpPaneDnd('tm');
      const row = document.createElement('tr');
      row.className = 'sftp-entry'; row.dataset.isdir = '1'; row.dataset.name = 'dest';
      document.getElementById('sftpTbody-tm').appendChild(row);
    });

    const multi = 'echo a\nrm -rf /tmp/x\n';
    const guards = [
      { name: 'delete category', n: 1,
        effect: (c) => c.cmd === 'category_delete',
        trigger: () => { window.__action = deleteCategory('c1'); } },
      { name: 'delete the open key', n: 1,
        effect: (c) => c.cmd === 'key_delete',
        trigger: () => { state.selectedId = 'k1'; state.settings.confirmDelete = 'true'; window.__action = deleteSelected(); } },
      { name: 'delete the selected keys', n: 2,
        effect: (c) => c.cmd === 'key_delete',
        trigger: () => { state.deploySelected = new Set(['k1', 'k2']); state.settings.confirmDelete = 'true'; window.__action = deleteSelectedKeys(); } },
      { name: 'deploy keys', n: 1,
        effect: (c) => c.cmd === 'key_deploy',
        trigger: () => { state.deploySelected = new Set(['k1']); window.__action = deployConfig(); } },
      { name: 'apply remote Bitwarden changes', n: 1,
        effect: (c) => c.cmd === 'bitwarden_sync' && c.args.allowRemoteOverwrite === true,
        trigger: () => { window.__action = bwSyncNow(); } },
      { name: 'restore a backup', n: 1,
        effect: (c) => c.cmd === 'vault_backup_restore',
        trigger: () => { window.__action = backupRestore(); } },
      { name: 'forget a pinned host', n: 1,
        effect: (c) => c.cmd === 'known_hosts_forget',
        trigger: () => { window.__action = undefined; document.querySelector('#knownHostsBody .ghost-btn').click(); } },
      { name: 'install an update', n: 1,
        effect: (c) => c.cmd === 'update_download_and_run',
        trigger: () => { window.__action = manualUpdateCheck(); } },
      { name: 'delete a server', n: 1,
        effect: (c) => c.cmd === 'server_delete',
        trigger: () => {
          window.__action = undefined;
          openServerContextMenu(10, 10, { id: 's1', name: 'web-1', host: '10.0.0.1', port: 22 });
          [...document.querySelectorAll('#keyConnectMenu .ctx-item')].find((b) => /Delete/.test(b.textContent)).click();
        } },
      { name: 'remove an MCP server', n: 1,
        effect: (c) => c.cmd === 'mcp_remove_server',
        trigger: () => {
          window.__action = undefined;
          const row = mcpServerRow({ id: 'm1', name: 'docs' });
          document.body.appendChild(row);
          [...row.querySelectorAll('button')].find((b) => b.textContent === 'Remove').click();
        } },
      { name: 'paste several lines into the shell', n: 1,
        effect: (c) => c.cmd === 'terminal_send' && bytesOf(c).includes('rm -rf'),
        trigger: (text) => { window.__action = window.terminalPaste([...state.sessions.keys()][0], text); }, arg: multi },
      { name: 'move a remote file by drag and drop', n: 1,
        effect: (c) => c.cmd === 'sftp_rename',
        trigger: () => {
          window.__action = undefined;
          // A refresh (after a move that did happen) rebuilds the rows; make
          // sure the directory row to drop on is there.
          const tbody = document.getElementById('sftpTbody-tm');
          let row = tbody.querySelector('tr.sftp-entry');
          if (!row) {
            row = document.createElement('tr');
            row.className = 'sftp-entry'; row.dataset.isdir = '1'; row.dataset.name = 'dest';
            tbody.appendChild(row);
          }
          const dt = new DataTransfer();
          dt.setData('text/sftp-remote', JSON.stringify({ path: '/srv/file.txt', name: 'file.txt' }));
          row.dispatchEvent(new DragEvent('drop', { dataTransfer: dt, bubbles: true, cancelable: true }));
        } },
      { name: 'close a live session tab', n: 1,
        effect: (c) => c.cmd === 'terminal_disconnect',
        trigger: () => {
          state.sessions.delete('tm');
          const p = document.getElementById('sftpPanel-tm'); if (p) p.remove();
          window.__action = closeSessionTab([...state.sessions.keys()][0]);
        } },
    ];

    const effects = async (g) => (await app.calls()).filter(g.effect).length;
    for (const g of guards) {
      console.log(`  - ${g.name}`);
      for (const how of ['cancel', 'escape', 'ok']) {
        await part(`${g.name} (${how})`, async () => {
          const before = await effects(g);
          await page.evaluate(g.trigger, g.arg);
          const shown = await waitVisible(page, '#confirmModal', 1200);
          if (how === 'cancel') {
            yes(`${g.name}: asks in the app, not with a native dialog`, shown);
            yes(`${g.name}: Cancel has the focus`, shown && await focusIs(page, 'confirmCancelBtn'));
          }
          if (shown) await answerConfirm(page, how);
          await settled(page, () => window.__action, null, 1200);
          await page.waitForTimeout(70);
          const delta = (await effects(g)) - before;
          if (how === 'ok') check(`${g.name}: OK performs it`, delta, g.n);
          else check(`${g.name}: ${how === 'cancel' ? 'Cancel' : 'Escape'} has no effect`, delta, 0);
          yes(`${g.name}: the dialog is gone afterwards (${how})`, !(await app.open('confirmModal')));
        });
      }
    }
    check('the native confirm() was never called', await page.evaluate(() => window.__nativeDialogCalls), 0);
    check('no page errors from the guards', app.errors, []);
  });
}

/// A2-09 / A5-01: locking settles dialogs and wipes every secret field.
async function scenarioLockSweep(browser, server) {
  await withApp(browser, server, {}, 'lock sweep', async (app) => {
    const { page } = app;
    // Fill every place a secret can sit, open several dialogs, then lock.
    await page.evaluate(() => {
      openKeyModal();
      switchTab('import');
      document.getElementById('importPem').value = '-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----';
      document.getElementById('importPass').value = 'pem-pass';
      document.getElementById('detailExportPass').value = 'export-pass';
      document.getElementById('keyPassphraseInput').value = 'deploy-pass';
      document.getElementById('configPreview').value = 'Deployed 1 key(s)\n  alpha -> /home/u/.ssh/sshspan_alpha';
      openServerModal({});
      document.getElementById('srvPassword').value = 'server-pass';
      window.__confirmAnswer = confirmModal('Delete key', 'Delete alpha?', 'Delete');
      promptModal('Backup password', 'secret please', '', () => { window.__promptRan = true; }, { secret: true });
      document.getElementById('promptInput').value = 'backup-pass';
      window.__pwAnswer = new Promise((resolve) => askConnectPassword({ username: 'root', host: 'h' }, resolve));
      document.getElementById('connectPwInput').value = 'connect-pass';
      openPalette();
    });
    await page.keyboard.press('Control+l');
    await page.waitForTimeout(150);

    check('a pending confirmation is answered no when the vault locks',
      await settled(page, () => window.__confirmAnswer, null, 800), false);
    check('a pending connect-password prompt is cancelled when the vault locks',
      await settled(page, () => window.__pwAnswer, null, 800), null);
    check('only the unlock dialog is left open after locking', await app.openIds(), ['vaultModal']);
    const secrets = await page.evaluate(() => ({
      passwordInputsWithText: [...document.querySelectorAll('input[type="password"]')].filter((i) => i.value !== '').map((i) => i.id),
      pem: document.getElementById('importPem').value,
      preview: document.getElementById('configPreview').value,
    }));
    check('no password field keeps text after locking', secrets.passwordInputsWithText, []);
    check('the pasted private key is wiped on lock', secrets.pem, '');
    check('the deploy preview is wiped on lock', secrets.preview, '');
    check('a prompt callback is not run by the lock', await page.evaluate(() => window.__promptRan === true), false);
    check('the lock IPC was issued once', await app.count('vault_lock'), 1);
    check('no page errors', app.errors, []);
  });

  // Locking by hand stays immediate: no question, live shells or not.
  await withApp(browser, server, {}, 'manual lock is immediate', async (app) => {
    await openLiveTab(app);
    await app.page.waitForTimeout(150);
    await app.page.click('#vaultStatus');
    await app.page.click('#keyConnectMenu .ctx-item:has-text("Lock now")');
    await app.page.waitForTimeout(150);
    check('Lock now asks nothing and locks at once, with a live session open',
      { asked: await app.open('confirmModal'), locks: await app.count('vault_lock') }, { asked: false, locks: 1 });
    check('and the live shell is torn down', await app.page.evaluate(() => state.sessions.size), 0);
    check('no page errors', app.errors, []);
  });

  // Late approval: the action behind a confirmation must not run after a lock.
  await withApp(browser, server, { settings: { confirmDelete: 'true' } }, 'late approval', async (app) => {
    await app.page.evaluate(() => { state.selectedId = 'k1'; window.__action = deleteSelected(); });
    await waitVisible(app.page, '#confirmModal');
    await app.page.keyboard.press('Control+l');
    await app.page.waitForTimeout(150);
    yes('the confirmation is gone after the lock', !(await app.open('confirmModal')));
    check('so the key is never deleted behind a locked vault', await app.count('key_delete'), 0);
  });
}

/// A2-01 / A2-53 / A5-06: the idle timer, on a fake clock.
async function scenarioIdle(browser, server) {
  const MIN = 60000;

  await withApp(browser, server, { clock: true, settings: { autoLockMinutes: '1' } }, 'poll does not extend idle', async (app) => {
    await app.tick(50 * 1000);
    check('not locked before the timeout', await app.count('vault_lock'), 0);
    await app.tick(11 * 1000);
    check('locks after one idle minute although the vault was polled every 10 s', await app.count('vault_lock'), 1);
    yes('and the unlock dialog is up', await app.open('vaultModal'));
    check('the countdown disappears while locked', await app.page.evaluate(() => document.getElementById('vaultSub').hidden), true);
    check('no page errors', app.errors, []);
  });

  await withApp(browser, server, { clock: true, settings: {} }, 'absent setting', async (app) => {
    await app.page.click('.nav-item[data-view="settings"]');
    await app.page.waitForSelector('#settingsRows input[type="number"]');
    check('an absent setting shows 15 minutes in Settings',
      await app.page.inputValue('#settingsRows input[type="number"]'), '15');
    await app.page.click('.nav-item[data-view="keys"]');
    check('the countdown shows a real deadline, not "auto-lock off"',
      /locks in 1[45]:\d\d/.test(await app.page.textContent('#vaultSub')), true);
    await app.tick(14 * MIN);
    check('still unlocked at 14 minutes', await app.count('vault_lock'), 0);
    await app.tick(61 * 1000);
    check('locked at 15 minutes when the setting was never saved', await app.count('vault_lock'), 1);
  });

  await withApp(browser, server, { clock: true, settings: { autoLockMinutes: 'soon' } }, 'invalid setting', async (app) => {
    await app.tick(15 * MIN + 1000);
    check('an unparsable setting falls back to 15 minutes', await app.count('vault_lock'), 1);
  });

  await withApp(browser, server, { clock: true, countTimers: true, settings: { autoLockMinutes: '0' } }, 'explicit zero', async (app) => {
    await app.tick(20 * MIN);
    await app.jump(3 * 60 * MIN);
    check('an explicit 0 never locks, even after hours', await app.count('vault_lock'), 0);
    check('and the sidebar says auto-lock is off', await app.page.textContent('#vaultSub'), 'auto-lock off');
    check('and no timer is armed', await app.page.evaluate(() => window.__longTimers()), 0);
  });

  // Arming happens on the unlock TRANSITION only; the next poll sees an already
  // unlocked vault and arms nothing. So a load that fails right after unlocking
  // (category_list rejects, see A2-20) must not be allowed to skip the arming.
  await withApp(browser, server, { clock: true, countTimers: true, unlocked: false, settings: { autoLockMinutes: '1' } }, 'failed load after unlock', async (app) => {
    const { page } = app;
    await page.evaluate(() => { window.__replies.category_list = () => { throw 'category list failed'; }; });
    await page.fill('#vaultPassword', PASSWORD);
    await page.click('#vaultPrimary');
    await page.waitForTimeout(150);
    check('the unlock went through', await page.evaluate(() => state.unlocked), true);
    check('although the category load behind it failed', (await app.count('category_list')) >= 1, true);
    check('auto-lock is armed anyway: the sidebar counts down',
      /^locks in [01]:\d\d$/.test(await page.textContent('#vaultSub')), true);
    check('with exactly one timer', await page.evaluate(() => window.__longTimers()), 1);
    await app.tick(61 * 1000);
    check('and the vault locks after the idle minute', await app.count('vault_lock'), 1);
  });

  await withApp(browser, server, { clock: true, settings: { autoLockMinutes: '1' } }, 'terminal typing', async (app) => {
    const tab = await openLiveTab(app);
    await app.page.evaluate((id) => window.tabRecord(id).term.focus(), tab);
    await app.tick(50 * 1000);
    await app.page.keyboard.type('ls');
    check('typed keys still reach the shell',
      (await sends(app)).filter((s) => s === 'l' || s === 's'), ['l', 's']);
    await app.tick(40 * 1000);
    check('typing in the terminal postponed the lock (xterm cancels bubbling)', await app.count('vault_lock'), 0);
    await app.page.evaluate(() => { window.__backend.channels[0].onmessage('remote output that is not the user\r\n'); });
    await app.tick(25 * 1000);
    check('remote output did not count as activity: locked one minute after the last key',
      await app.count('vault_lock'), 1);
    check('the terminal tab is gone after the lock', await app.page.evaluate(() => state.sessions.size), 0);
    check('no page errors', app.errors, []);
  });

  await withApp(browser, server, { clock: true, settings: { autoLockMinutes: '1' } }, 'pointer and synthetic input', async (app) => {
    await app.tick(50 * 1000);
    await app.page.mouse.click(700, 450);
    await app.tick(40 * 1000);
    check('a real click postpones the lock', await app.count('vault_lock'), 0);
    await app.page.evaluate(() => document.dispatchEvent(new KeyboardEvent('keydown', { key: 'a', bubbles: true })));
    await app.tick(25 * 1000);
    check('a scripted key event is not human activity', await app.count('vault_lock'), 1);
  });

  await withApp(browser, server, { clock: true, settings: { autoLockMinutes: '1' } }, 'activity helper', async (app) => {
    check('noteUserActivity is exposed', await app.page.evaluate(() => typeof window.noteUserActivity), 'function');
    await app.tick(50 * 1000);
    await app.page.evaluate(() => window.noteUserActivity());
    await app.tick(40 * 1000);
    check('calling it postpones the lock', await app.count('vault_lock'), 0);
    await app.tick(25 * 1000);
    check('and it still locks afterwards', await app.count('vault_lock'), 1);
  });

  await withApp(browser, server, { clock: true, settings: { autoLockMinutes: '0' } }, 'heartbeat', async (app) => {
    const base = await app.count('heartbeat');
    await app.tick(5 * MIN);
    check('no heartbeat while the user is idle', (await app.count('heartbeat')) - base, 0);
    await app.page.keyboard.press('a');
    check('a key press sends one at once', (await app.count('heartbeat')) - base, 1);
    await app.page.keyboard.press('b');
    await app.tick(10 * 1000);
    check('further activity is coalesced into one more', (await app.count('heartbeat')) - base, 2);
    await app.tick(5 * MIN);
    check('and it goes quiet again when the user stops', (await app.count('heartbeat')) - base, 2);
  });

  await withApp(browser, server, { clock: true, countTimers: true, settings: { autoLockMinutes: '5' } }, 'one timer', async (app) => {
    const timers = () => app.page.evaluate(() => window.__longTimers());
    check('one timer is armed after boot', await timers(), 1);
    await app.tick(35 * 1000);
    await app.page.keyboard.press('x');
    check('still one after polls and a key press', await timers(), 1);
    await app.page.click('.nav-item[data-view="settings"]');
    await app.page.waitForSelector('#settingsRows input[type="number"]');
    // The first number field in Settings is the auto-lock minutes.
    const input = app.page.locator('#settingsRows input[type="number"]').first();
    const setMinutes = async (v) => { await input.fill(v); await app.page.keyboard.press('Tab'); await app.page.waitForTimeout(60); };
    await setMinutes('7');
    check('one after the setting changes', await timers(), 1);
    await setMinutes('0');
    check('none while it is off', await timers(), 0);
    await setMinutes('3');
    check('one again when it is turned back on', await timers(), 1);
    await app.page.keyboard.press('Control+l');
    await app.page.waitForTimeout(80);
    check('none while locked', await timers(), 0);
    await app.tick(35 * 1000);
    check('polls while locked do not arm one', await timers(), 0);
    await app.page.fill('#vaultPassword', PASSWORD);
    await app.page.click('#vaultPrimary');
    await app.page.waitForTimeout(100);
    check('exactly one after unlocking', await timers(), 1);
    check('settings_set carried the minutes that were typed',
      (await app.calls('settings_set')).map((c) => c.args.value), ['7', '0', '3']);
  });

  await withApp(browser, server, { clock: true, settings: { autoLockMinutes: '30' } }, 'watchdog event', async (app) => {
    await app.page.evaluate(() => { window.__backend.unlocked = false; window.__emit('vault-locked-by-watchdog', null); });
    await app.page.waitForTimeout(150);
    yes('the unlock dialog appears without waiting for the next poll', await app.open('vaultModal'));
    check('the keys were cleared', await app.page.evaluate(() => state.keys.length), 0);
  });
}

/// Settings: truthful copy, whole minutes only.
async function scenarioAutoLockSettings(browser, server) {
  await withApp(browser, server, { settings: { autoLockMinutes: '20' } }, 'auto-lock settings', async (app) => {
    const { page } = app;
    await page.click('.nav-item[data-view="settings"]');
    await page.waitForSelector('#settingsRows input[type="number"]');
    const row = await page.evaluate(() => {
      const r = [...document.querySelectorAll('#settingsRows .settings-row')]
        .find((x) => /idle/i.test(x.querySelector('.settings-row-title').textContent));
      return { title: r.querySelector('.settings-row-title').textContent, sub: r.querySelector('.settings-row-sub').textContent };
    });
    yes('the copy warns that SSH sessions are closed', /ssh sessions/i.test(row.sub) && /clos/i.test(row.sub), row.sub);
    yes('the copy warns that transfers are paused', /transfers/i.test(row.sub) && /paus/i.test(row.sub), row.sub);
    yes('the copy says 0 turns it off', /\b0\b/.test(row.sub) && /off/i.test(row.sub), row.sub);
    yes('the copy says remote output is not activity', /output/i.test(row.sub), row.sub);

    // The first number field in Settings is the auto-lock minutes.
    const input = page.locator('#settingsRows input[type="number"]').first();
    check('the stored value is shown', await input.inputValue(), '20');
    const saved = async () => (await app.calls('settings_set')).filter((c) => c.args.key === 'autoLockMinutes').map((c) => c.args.value);
    await input.fill('-5');
    await page.keyboard.press('Tab');
    await page.waitForTimeout(80);
    check('a negative number is refused, not stored', await saved(), []);
    check('and the field goes back to the effective value', await input.inputValue(), '20');
    await input.fill('99999');
    await page.keyboard.press('Tab');
    await page.waitForTimeout(80);
    check('an absurd number is clamped to a day', await saved(), ['1440']);
    check('no page errors', app.errors, []);
  });
}

/// A2-06 / A2-10 / A2-22 / A2-49 / A2-18: the vault dialog.
async function scenarioVaultDialog(browser, server) {
  await withApp(browser, server, { clock: true, settings: { autoLockMinutes: '0' } }, 'change password', async (app) => {
    const { page } = app;
    await page.click('#vaultStatus');
    await page.click('#keyConnectMenu .ctx-item:has-text("Change master password")');
    yes('the change dialog is open', await app.open('vaultModal'));
    check('the current password has the focus', await app.focused(), 'vaultPasswordCurrent');
    check('the visible fields run current, new, confirm',
      await page.evaluate(() => [...document.querySelectorAll('#vaultModal input')].filter((i) => !i.hidden).map((i) => i.id)),
      ['vaultPasswordCurrent', 'vaultPassword', 'vaultPasswordConfirm']);
    check('and are labelled for what they are',
      await page.evaluate(() => ['vaultPasswordCurrent', 'vaultPassword', 'vaultPasswordConfirm']
        .map((id) => document.getElementById(id).placeholder)),
      ['Current master password', 'New master password', 'Confirm new password']);
    await page.fill('#vaultPasswordCurrent', 'old-password-1');
    await page.fill('#vaultPassword', 'new-password-2');
    await page.fill('#vaultPasswordConfirm', 'new-password-2');
    await app.tick(35 * 1000);
    yes('the dialog survives three status polls', await app.open('vaultModal'));
    check('and keeps what was typed',
      await page.evaluate(() => ['vaultPasswordCurrent', 'vaultPassword', 'vaultPasswordConfirm'].map((id) => document.getElementById(id).value)),
      ['old-password-1', 'new-password-2', 'new-password-2']);
    await page.click('#vaultPrimary');
    await page.waitForTimeout(100);
    check('it sends the current and the new password',
      (await app.calls('vault_change_password')).map((c) => c.args),
      [{ currentPassword: 'old-password-1', newPassword: 'new-password-2' }]);
    yes('and closes', !(await app.open('vaultModal')));
    check('leaving no password behind',
      await page.evaluate(() => [...document.querySelectorAll('#vaultModal input')].map((i) => i.value)), ['', '', '']);
    check('no page errors', app.errors, []);
  });

  await withApp(browser, server, { clock: true, unlocked: false, settings: { autoLockMinutes: '0' } }, 'dismissed unlock', async (app) => {
    const { page } = app;
    yes('the unlock dialog opens on a locked vault', await app.open('vaultModal'));
    await page.click('#vaultCancelBtn');
    yes('Cancel closes it', !(await app.open('vaultModal')));
    await app.tick(35 * 1000);
    yes('it stays closed across polls', !(await app.open('vaultModal')));
    await page.keyboard.press('Control+n');
    yes('an explicit request (Ctrl+N) opens it again', await app.open('vaultModal'));
    check('as the unlock dialog, because a vault exists', await page.textContent('#vaultModalTitle'), 'Unlock vault');
    await page.keyboard.press('Escape');
    yes('Escape dismisses it like Cancel', !(await app.open('vaultModal')));
    await app.tick(35 * 1000);
    yes('and it stays dismissed', !(await app.open('vaultModal')));
    await page.click('#vaultStatus');
    await page.click('#keyConnectMenu .ctx-item:has-text("Unlock vault")');
    yes('the vault menu reopens it', await app.open('vaultModal'));
    await page.click('#vaultCancelBtn');
    // A real state change re-arms the gate: unlock behind its back, then lock again.
    await page.evaluate(() => { window.__backend.unlocked = true; });
    await app.tick(11 * 1000);
    check('an unlock elsewhere is noticed', await page.evaluate(() => state.unlocked), true);
    await page.evaluate(() => { window.__backend.unlocked = false; window.__emit('vault-locked-by-watchdog', null); });
    await page.waitForTimeout(150);
    yes('a lock re-opens the gate even though it was dismissed before', await app.open('vaultModal'));
    check('no page errors', app.errors, []);
  });

  await withApp(browser, server, { clock: true, hasVault: false, unlocked: false }, 'create flow', async (app) => {
    const { page } = app;
    check('first run shows the create dialog', await page.textContent('#vaultModalTitle'), 'Create your vault');
    await page.fill('#vaultPassword', 'typed-so-far');
    await page.keyboard.press('Control+n');
    check('Ctrl+N does not flip it to Unlock', await page.textContent('#vaultModalTitle'), 'Create your vault');
    check('and does not wipe the typed password', await page.inputValue('#vaultPassword'), 'typed-so-far');
    await app.tick(35 * 1000);
    check('polls leave it alone too', await page.inputValue('#vaultPassword'), 'typed-so-far');
    await page.click('#vaultCancelBtn');
    await app.tick(35 * 1000);
    yes('a dismissed create dialog stays dismissed', !(await app.open('vaultModal')));
    await page.keyboard.press('Control+n');
    check('Ctrl+N then opens Create, not Unlock', await page.textContent('#vaultModalTitle'), 'Create your vault');
  });

  await withApp(browser, server, { clock: true, unlocked: false, settings: { autoLockMinutes: '0' } }, 'double vault submit', async (app) => {
    const { page } = app;
    await page.evaluate(() => {
      let release; window.__gates.vault_unlock = { promise: new Promise((r) => { release = r; }), release };
    });
    await page.fill('#vaultPassword', PASSWORD);
    await page.evaluate(() => { const b = document.getElementById('vaultPrimary'); b.click(); b.click(); });
    await page.keyboard.press('Enter');
    await page.keyboard.press('Enter');
    await page.waitForTimeout(60);
    check('double click and held Enter send one unlock', await app.count('vault_unlock'), 1);
    await page.evaluate(() => window.__gates.vault_unlock.release());
    await page.waitForTimeout(150);
    check('and it completes', await page.evaluate(() => state.unlocked), true);
    check('with no second attempt', await app.count('vault_unlock'), 1);
    check('no page errors', app.errors, []);
  });

  await withApp(browser, server, { clock: true, settings: { autoLockMinutes: '0' } }, 'double key submit', async (app) => {
    const { page } = app;
    await page.evaluate(() => {
      openKeyModal();
      let release; window.__gates.key_create_with_categories = { promise: new Promise((r) => { release = r; }), release };
    });
    await page.fill('#genName', 'ci-key');
    await page.evaluate(() => { const b = document.getElementById('modalPrimary'); b.click(); b.click(); });
    await page.waitForTimeout(60);
    check('double click creates one key', await app.count('key_create_with_categories'), 1);
    await page.evaluate(() => window.__gates.key_create_with_categories.release());
    await page.waitForTimeout(150);
    check('and the dialog closes when it finishes', await app.open('modalBackdrop'), false);
  });
}

/// A2-09: cancelling a key import must not leave the pasted key behind.
async function scenarioKeyImportCancel(browser, server) {
  await withApp(browser, server, {}, 'key import cancel', async (app) => {
    const { page } = app;
    const fill = async () => {
      await page.evaluate(() => { openKeyModal(); switchTab('import'); });
      await page.fill('#importPem', '-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----');
      await page.fill('#importPass', 'pem-pass');
    };
    const left = () => page.evaluate(() => [document.getElementById('importPem').value, document.getElementById('importPass').value]);
    await fill();
    await page.click('#modalBackdrop .modal-footer [data-close]');
    check('Cancel clears the pasted key and passphrase', await left(), ['', '']);
    await fill();
    await page.keyboard.press('Escape');
    check('Escape clears them too', await left(), ['', '']);
    await fill();
    await page.evaluate(() => document.getElementById('modalBackdrop').click());
    check('and so does a click on the backdrop', await left(), ['', '']);
    check('no page errors', app.errors, []);
  });
}

/// A2-13: the backup password prompt is a secret field and keeps its spaces.
async function scenarioSecretPrompt(browser, server) {
  const replies = { system_select_file: { canceled: false, text: '{"v":1}', path: '/tmp/b.json', name: 'b.json' } };
  await withApp(browser, server, { replies }, 'backup password prompt', async (app) => {
    const { page } = app;
    await page.evaluate(() => {
      window.__replies.vault_backup_restore = (a) => {
        if (a.backupPassword == null) throw 'This backup was created with a different master password.';
        return { counts: { keys: 1, categories: 0, servers: 0, knownHosts: 0 } };
      };
      window.__action = backupRestore();
    });
    yes('restoring asks for confirmation first', await answerConfirm(page, 'ok'));
    yes('the backup password prompt appears', await waitVisible(page, '#promptModal'));
    check('it is a password field', await page.getAttribute('#promptInput', 'type'), 'password');
    await page.fill('#promptInput', '  spaced pw  ');
    await page.click('#promptOkBtn');
    await page.waitForTimeout(100);
    check('the password is sent untrimmed',
      (await app.calls('vault_backup_restore')).map((c) => c.args.backupPassword), [null, '  spaced pw  ']);
    check('the field is emptied when the prompt closes', await page.inputValue('#promptInput'), '');
    check('and goes back to a plain text field', await page.getAttribute('#promptInput', 'type'), 'text');
    check('no page errors', app.errors, []);
  });

  await withApp(browser, server, {}, 'ordinary prompt', async (app) => {
    const { page } = app;
    await page.evaluate(() => { window.__renamed = null; promptModal('Rename', 'New name', 'x', (v) => { window.__renamed = v; }); });
    check('an ordinary prompt is a text field', await page.getAttribute('#promptInput', 'type'), 'text');
    await page.fill('#promptInput', '  new-name  ');
    await page.click('#promptOkBtn');
    check('an ordinary prompt still trims', await page.evaluate(() => window.__renamed), 'new-name');
    await page.evaluate(() => { window.__renamed = 'untouched'; promptModal('Rename', 'New name', 'x', (v) => { window.__renamed = v; }); });
    await focusIs(page, 'promptInput');
    await page.keyboard.press('Escape');
    check('Escape in a prompt runs nothing', await page.evaluate(() => window.__renamed), 'untouched');
    yes('and closes it', !(await app.open('promptModal')));
  });
}

/// A1-09 / A1-27 / A2-40 / A2-22 / A5-02: stacking, Escape, chords, focus.
async function scenarioModals(browser, server) {
  await withApp(browser, server, {}, 'stacking', async (app) => {
    const { page } = app;
    const topAt = (id) => page.evaluate((i) => {
      const m = document.querySelector('#' + i + ' .modal').getBoundingClientRect();
      const hit = document.elementFromPoint(m.left + m.width / 2, m.top + m.height / 2);
      const b = hit && hit.closest('.modal-backdrop');
      return b ? b.id : null;
    }, id);
    await page.evaluate(() => { openServerModal({}); });
    await page.evaluate(() => { openPalette(); });
    await page.waitForTimeout(80);
    check('a dialog opened over another paints above it (palette over server)', await topAt('paletteModal'), 'paletteModal');
    await page.evaluate(() => { showVaultModal('unlock'); });
    await page.waitForTimeout(80);
    check('the vault gate paints above both', await topAt('vaultModal'), 'vaultModal');
    await page.evaluate(() => { hideVaultModal(); closePalette(); closeServerModal(); });
    await page.waitForTimeout(80);
    // Close a lower layer, open another: layers are renumbered, never tied.
    await page.evaluate(() => { openServerModal({}); openPalette(); });
    await page.waitForTimeout(60);
    await page.evaluate(() => { closeServerModal(); });
    await page.waitForTimeout(60);
    await page.evaluate(() => { showVaultModal('unlock'); });
    await page.waitForTimeout(80);
    check('a layer opened after a lower one closed is still on top', await topAt('vaultModal'), 'vaultModal');
    check('no page errors', app.errors, []);
  });

  await withApp(browser, server, {}, 'escape layers', async (app) => {
    const { page } = app;
    await page.evaluate(() => { openServerModal({}); window.__q = confirmModal('Sure?', 'over the server form', 'Yes'); });
    await waitVisible(page, '#confirmModal');
    await page.keyboard.press('Escape');
    check('Escape answers the confirmation no', await settled(page, () => window.__q, null, 800), false);
    yes('and leaves the form underneath open', await app.open('serverModal'));
    await page.keyboard.press('Escape');
    yes('the next Escape closes the form', !(await app.open('serverModal')));
    // A server password typed into the form does not stay in the hidden field.
    await page.evaluate(() => { openServerModal({}); document.getElementById('srvPassword').value = 'typed-server-pw'; });
    await page.keyboard.press('Escape');
    check('closing the host form drops a typed server password', await page.inputValue('#srvPassword'), '');

    // Let the dialog's own deferred focus land first, then put focus on a
    // button: the old Escape handling lived on the input only.
    await page.evaluate(() => {
      window.__pw = 'pending';
      askConnectPassword({ username: 'root', host: 'h' }, (v) => { window.__pw = v; });
    });
    await focusIs(page, 'connectPwInput');
    await page.evaluate(() => { document.getElementById('connectPwCancelBtn').focus(); });
    await page.keyboard.press('Escape');
    check('Escape with a button focused cancels the connect password prompt', await page.evaluate(() => window.__pw), null);
    yes('and closes it', !(await app.open('connectPwModal')));

    await page.evaluate(() => { promptModal('Rename', 'New name', 'x', () => {}); });
    await focusIs(page, 'promptInput');
    await page.evaluate(() => { document.getElementById('promptOkBtn').focus(); });
    await page.keyboard.press('Escape');
    yes('Escape with the OK button focused closes a prompt', !(await app.open('promptModal')));

    // One keypress must not unwind two layers.
    await page.evaluate(() => { toggleTermMax(); promptModal('Rename', 'New name', 'x', () => {}); });
    await focusIs(page, 'promptInput');
    await page.keyboard.press('Escape');
    check('Escape in a prompt does not also leave maximized-terminal mode',
      await page.evaluate(() => document.getElementById('app').classList.contains('term-max')), true);
    check('no page errors', app.errors, []);
  });

  await withApp(browser, server, {}, 'chords', async (app) => {
    const { page } = app;
    await page.evaluate(() => { openKeyModal(); });
    await page.keyboard.press('Control+2');
    check('Ctrl+2 does not switch views behind a dialog', await page.evaluate(() => state.view), 'keys');
    await page.keyboard.press('Control+k');
    yes('Ctrl+K does not open the palette over a dialog', !(await app.open('paletteModal')));
    await page.keyboard.press('Control+n');
    check('Ctrl+N does not stack a second New Key dialog', await app.openIds(), ['modalBackdrop']);
    await page.keyboard.press('Escape');
    await page.keyboard.press('Control+2');
    check('with no dialog open the same chord works', await page.evaluate(() => state.view), 'connect');
    await page.evaluate(() => { openKeyModal(); });
    await page.keyboard.press('Control+l');
    await page.waitForTimeout(100);
    check('Ctrl+L still locks while a dialog is open', await app.count('vault_lock'), 1);
    check('no page errors', app.errors, []);
  });

  // A closer that throws must not trap the user in the dialog - and the failure
  // must be logged, not swallowed.
  await withApp(browser, server, {}, 'failing closer', async (app) => {
    const { page } = app;
    await page.evaluate(() => {
      registerModalCloser(document.getElementById('promptModal'), () => { throw new Error('closer exploded'); });
      promptModal('Rename', 'New name', '', () => {});
    });
    await focusIs(page, 'promptInput');
    await page.keyboard.press('Escape');
    yes('Escape still closes a dialog whose closer throws', !(await app.open('promptModal')));
    const escapeWarnings = app.warnings.filter((w) => /closer exploded/.test(w)).length;
    yes('and the failure is logged', escapeWarnings >= 1, JSON.stringify(app.warnings));
    await page.evaluate(() => { promptModal('Rename', 'New name', '', () => {}); });
    await focusIs(page, 'promptInput');
    await page.keyboard.press('Control+l');
    await page.waitForTimeout(150);
    yes('a lock still closes a dialog whose closer throws', !(await app.open('promptModal')));
    yes('and logs that too', app.warnings.filter((w) => /closer exploded/.test(w)).length > escapeWarnings, JSON.stringify(app.warnings));
    check('the lock still went through', await app.count('vault_lock'), 1);
    check('no page errors', app.errors, []);
  });

  // The assistant's own chord must not open its panel (and take the focus into
  // its input) from behind or over a dialog.
  await withApp(browser, server, {}, 'assistant chord', async (app) => {
    const { page } = app;
    await page.evaluate(() => switchView('connect'));
    await page.evaluate(() => { openServerModal({}); });
    await page.keyboard.press('Control+Shift+A');
    await page.waitForTimeout(150);
    check('Ctrl+Shift+A does nothing behind a dialog', await page.evaluate(() => document.getElementById('assistantPanel').hidden), true);
    await page.keyboard.press('Escape');
    await page.keyboard.press('Control+Shift+A');
    await page.waitForTimeout(150);
    check('and works again once the dialog is closed', await page.evaluate(() => document.getElementById('assistantPanel').hidden), false);
    check('no page errors', app.errors, []);
  });

  // Maximizing refits and refocuses the terminal on 80 ms and 250 ms timers.
  await withApp(browser, server, {}, 'maximize timers', async (app) => {
    const { page } = app;
    await openLiveTab(app);
    await page.waitForTimeout(150);
    await page.evaluate(() => { promptModal('Rename', 'New name', '', () => {}); toggleTermMax(); });
    await focusIs(page, 'promptInput');
    await page.waitForTimeout(400); // past both deferred refit-and-focus timers
    check('a maximize does not pull the focus out of an open dialog', await app.focused(), 'promptInput');
    await page.keyboard.type('abc');
    check('typing lands in the dialog', await page.inputValue('#promptInput'), 'abc');
    check('and none of it reaches the shell', (await sends(app)).length, 0);
    check('no page errors', app.errors, []);
  });

  // With nothing open, Escape belongs to the shell (vim, readline): the
  // central dialog handler must not swallow it.
  await withApp(browser, server, {}, 'escape reaches the shell', async (app) => {
    const { page } = app;
    const tab = await openLiveTab(app);
    await page.evaluate((id) => window.tabRecord(id).term.focus(), tab);
    await page.waitForTimeout(100);
    await page.keyboard.press('Escape');
    check('Escape with no dialog open is sent to the session', await sends(app), ['\x1b']);
  });

  await withApp(browser, server, {}, 'connect password focus', async (app) => {
    const { page } = app;
    await openLiveTab(app, 'password');
    yes('the connect password prompt opens', await waitVisible(page, '#connectPwModal'));
    await page.waitForTimeout(350); // longer than every deferred terminal focus timer
    check('it still has the focus after the terminal timers have run', await app.focused(), 'connectPwInput');
    await page.keyboard.type('hunter2');
    check('typed characters land in the password field', await page.inputValue('#connectPwInput'), 'hunter2');
    check('and none of them reached a shell', (await sends(app)).length, 0);
    await page.keyboard.press('Enter');
    await page.waitForTimeout(150);
    check('Enter connects with that password',
      (await app.calls('terminal_connect')).map((c) => c.args.promptPassword), ['hunter2']);
    check('the field is emptied afterwards', await page.inputValue('#connectPwInput'), '');
    check('no page errors', app.errors, []);
  });
}

/// The SFTP delete, chmod and conflict dialogs have no Escape handler of their
/// own: the central one closes them, and so does a vault lock, and each settles
/// whatever it was holding.
async function scenarioSftpDialogs(browser, server) {
  const modalId = { delete: 'deleteModal', chmod: 'chmodModal', conflict: 'conflictModal' };
  const opener = {
    delete: () => { window.__yes = 0; sftpConfirmDelete('Delete 1 item?', () => { window.__yes += 1; }); },
    chmod: () => { openChmodDialog('tm', ['/srv/a.txt'], { name: 'a.txt' }); },
    conflict: () => {
      window.__batch = resolveBatchConflicts('tm', 'upload',
        [{ local: '/home/u/a.txt', remote: '/srv/a.txt', destEntry: { size: 1, modifiedMs: 1 } }]);
    },
  };
  for (const kind of ['delete', 'chmod', 'conflict']) {
    for (const how of ['escape', 'lock']) {
      await withApp(browser, server, {}, `${kind} dialog via ${how}`, async (app) => {
        const { page } = app;
        await page.evaluate(() => {
          state.sessions.set('tm', { tabId: 'tm', sessionId: 'sess-sftp', serverId: 's1', serverName: 'files', host: '10.0.0.1', port: 22, mode: 'sftp', sftpReady: true, sftpPath: '/srv', ended: false });
        });
        await page.evaluate(opener[kind]);
        yes(`${kind}: the dialog opens`, await waitVisible(page, '#' + modalId[kind]));
        await page.keyboard.press(how === 'escape' ? 'Escape' : 'Control+l');
        await page.waitForTimeout(150);
        yes(`${kind}: ${how} closes it`, !(await app.open(modalId[kind])));
        if (kind === 'delete') check(`delete: ${how} deletes nothing`, await page.evaluate(() => window.__yes), 0);
        if (kind === 'conflict') {
          check(`conflict: ${how} cancels the whole batch (the awaiting transfer is released)`,
            await settled(page, () => window.__batch, null, 800), null);
        }
        if (how === 'escape') {
          yes(`${kind}: and the page behind it is untouched (the vault is still unlocked)`, await page.evaluate(() => state.unlocked));
        } else {
          check(`${kind}: the vault locked`, await app.count('vault_lock'), 1);
        }
        check(`${kind}: no page errors`, app.errors, []);
      });
    }
  }
}

/// A5-45: a native paste (Shift+Insert, middle-click, Edit menu) goes through
/// the same review as the explicit paste.
async function scenarioPaste(browser, server) {
  await withApp(browser, server, {}, 'paste', async (app) => {
    const { page } = app;
    const tab = await openLiveTab(app);
    await page.evaluate((id) => window.tabRecord(id).term.focus(), tab);
    await page.waitForTimeout(100);
    const nativePaste = (text) => page.evaluate((t) => {
      const ta = document.querySelector('.xterm-helper-textarea');
      const dt = new DataTransfer();
      dt.setData('text/plain', t);
      const ev = new ClipboardEvent('paste', { clipboardData: dt, bubbles: true, cancelable: true });
      ta.dispatchEvent(ev);
      return ev.defaultPrevented;
    }, text);
    const multi = 'echo one\nrm -rf /tmp/demo\nshutdown -h now\n';
    const wire = 'echo one\rrm -rf /tmp/demo\rshutdown -h now\r';
    const pasted = async () => (await sends(app)).filter((s) => s.includes('shutdown'));

    check('the native paste event is taken over (default prevented)', await nativePaste(multi), true);
    yes('a multi-line native paste asks first', await waitVisible(page, '#confirmModal'));
    check('and has not been sent yet', await pasted(), []);
    await answerConfirm(page, 'cancel');
    await page.waitForTimeout(80);
    check('Cancel sends nothing', await pasted(), []);

    await nativePaste(multi);
    await answerConfirm(page, 'escape');
    await page.waitForTimeout(80);
    check('Escape sends nothing', await pasted(), []);

    await nativePaste(multi);
    await answerConfirm(page, 'ok');
    await page.waitForTimeout(100);
    check('approval sends the text exactly once', await pasted(), [wire]);

    // The real gesture, not a synthetic event: Shift+Insert is the browser's own
    // paste shortcut (xterm lets it through) and reads the real clipboard. If
    // this browser does not deliver a paste event for it there is nothing to
    // judge; but text must never go out unreviewed.
    await page.evaluate((t) => navigator.clipboard.writeText(t), multi);
    await page.evaluate((id) => window.tabRecord(id).term.focus(), tab);
    const sentBefore = (await pasted()).length;
    await page.keyboard.press('Shift+Insert');
    const asked = await waitVisible(page, '#confirmModal', 1500);
    const leaked = (await pasted()).length - sentBefore;
    if (!asked && leaked === 0) {
      console.log('  skip  a real Shift+Insert did not produce a paste event in this browser');
    } else {
      yes('a real Shift+Insert paste asks first', asked);
      check('and nothing was sent before the answer', leaked, 0);
      if (asked) {
        await answerConfirm(page, 'cancel');
        await page.waitForTimeout(100);
        check('Cancel on the real paste sends nothing', (await pasted()).length - sentBefore, 0);
        await page.evaluate((id) => window.tabRecord(id).term.focus(), tab);
        await page.keyboard.press('Shift+Insert');
        await answerConfirm(page, 'ok');
        await page.waitForTimeout(100);
        check('approving the real paste sends it once', (await pasted()).slice(sentBefore), [wire]);
      }
    }

    // Bracketed paste is preserved for the approved paste, native or explicit.
    await page.evaluate((id) => new Promise((r) => window.tabRecord(id).term.write('\x1b[?2004h', r)), tab);
    const bracketBase = (await pasted()).length;
    await nativePaste(multi);
    await answerConfirm(page, 'ok');
    await page.waitForTimeout(100);
    check('with bracketed paste on, the native paste is wrapped in the markers once',
      (await pasted()).slice(bracketBase), ['\x1b[200~' + wire + '\x1b[201~']);
    await page.evaluate((a) => { window.__action = window.terminalPaste(a.id, a.text); }, { id: tab, text: multi });
    await answerConfirm(page, 'ok');
    await page.waitForTimeout(100);
    check('the explicit paste path is wrapped the same way',
      (await pasted()).slice(bracketBase + 1), ['\x1b[200~' + wire + '\x1b[201~']);

    // Single lines and the setting off do not ask.
    const before = (await sends(app)).length;
    await nativePaste('ls -la');
    await page.waitForTimeout(80);
    check('a single-line paste is not interrupted and goes out once',
      (await sends(app)).slice(before), ['\x1b[200~ls -la\x1b[201~']);
    yes('with no dialog', !(await app.open('confirmModal')));
    await page.evaluate(() => { state.settings.confirmMultiLinePaste = '0'; });
    const before2 = (await sends(app)).length;
    await nativePaste('a\nb\n');
    await page.waitForTimeout(80);
    check('with the setting off a multi-line paste goes straight out once',
      (await sends(app)).slice(before2), ['\x1b[200~a\rb\r\x1b[201~']);
    yes('with no dialog either', !(await app.open('confirmModal')));
    check('the native confirm() was never called', await page.evaluate(() => window.__nativeDialogCalls), 0);
    check('no page errors', app.errors, []);
  });
}

/// A1-27: the YOLO dialog fails closed and Escape cancels it.
async function scenarioYolo(browser, server) {
  const yoloCalls = async (app) => (await app.calls('assistant_set_level')).filter((c) => c.args.level === 'yolo').length;

  await withApp(browser, server, {}, 'yolo dialog', async (app) => {
    const { page } = app;
    const tab = await openLiveTab(app);
    await page.waitForTimeout(150); // the terminal's own deferred focus is covered by the connect-password check
    await page.evaluate((id) => { aiSetLevel(id, 'yolo'); }, tab);
    yes('the YOLO dialog opens', await waitVisible(page, '#yoloModal'));
    yes('Cancel has the focus', await focusIs(page, 'yoloCancelBtn'));
    await page.keyboard.press('Escape');
    yes('Escape closes it', !(await app.open('yoloModal')));
    check('and does not enable YOLO', await yoloCalls(app), 0);

    await page.evaluate((id) => { aiSetLevel(id, 'yolo'); }, tab);
    await waitVisible(page, '#yoloModal');
    await page.click('#yoloEnableBtn');
    await page.waitForTimeout(80);
    check('the Enable button enables it, once', await yoloCalls(app), 1);

    await page.evaluate((id) => { aiTabState(id).level = 'read'; aiSetLevel(id, 'yolo'); }, tab);
    await waitVisible(page, '#yoloModal');
    await page.keyboard.press('Control+l');
    await page.waitForTimeout(120);
    yes('locking the vault closes it', !(await app.open('yoloModal')));
    check('without enabling YOLO', await yoloCalls(app), 1);
  });

  await withApp(browser, server, {}, 'yolo dialog missing', async (app) => {
    const tab = await openLiveTab(app);
    await app.page.evaluate(() => { document.getElementById('yoloModal').remove(); });
    await app.page.evaluate((id) => { aiSetLevel(id, 'yolo'); }, tab);
    await app.page.waitForTimeout(100);
    check('with the dialog missing YOLO is not enabled', await yoloCalls(app), 0);
    yes('and the user is told why', /yolo/i.test(await app.page.evaluate(() =>
      [...document.querySelectorAll('.toast-item')].map((n) => n.textContent).join(' | '))));
  });
}

// ─── runner ─────────────────────────────────────────────────────────────────

const SCENARIOS = [
  ['confirm: one shared dialog, safe default, settles once', scenarioConfirmContract],
  ['confirm: every guarded action asks in the app; Cancel and Escape change nothing', scenarioGuards],
  ['lock: settles dialogs, wipes secrets, blocks late approval', scenarioLockSweep],
  ['idle auto-lock, heartbeat and watchdog (fake clock)', scenarioIdle],
  ['settings: truthful auto-lock copy and validation', scenarioAutoLockSettings],
  ['vault dialog: change mode, dismissal, create flow, double submit', scenarioVaultDialog],
  ['key import: cancel clears the pasted secret', scenarioKeyImportCancel],
  ['prompt: secret mode for the backup password', scenarioSecretPrompt],
  ['dialogs: stacking, Escape layers, chords, focus', scenarioModals],
  ['sftp dialogs: closed by the central Escape handler and by a lock', scenarioSftpDialogs],
  ['terminal paste: native paste is reviewed like explicit paste', scenarioPaste],
  ['assistant: YOLO dialog fails closed', scenarioYolo],
];

(async () => {
  const only = process.argv.includes('--only') ? process.argv[process.argv.indexOf('--only') + 1] : null;
  const server = await serve();
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
    console.error(`\n${failures.length} audit safety check(s) failed.`);
    process.exit(1);
  }
  console.log('\nAll audit safety checks passed.');
})().catch((e) => { console.error(e); process.exit(1); });
