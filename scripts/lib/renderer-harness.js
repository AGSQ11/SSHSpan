/*
 * Shared scaffolding for the renderer regression suites: check-renderer-ui.js,
 * check-audit-safety.js and check-sftp-ui.js.
 *
 * Each suite drives the REAL renderer (index.html and every script it loads)
 * in headless Chromium against a stubbed window.__TAURI__, and the first two
 * had grown their own copies of the same plumbing: the static file server, the
 * Playwright lookup, the ok/FAIL reporter and the page setup. One copy now, so
 * a fix to the plumbing reaches every suite. Nothing in here asserts anything;
 * the suites do.
 */
'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');

// ─── reporting ──────────────────────────────────────────────────────────────

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

// ─── playwright ─────────────────────────────────────────────────────────────

/// Playwright is not a devDependency (only these suites use it):
///
///     npm install --no-save playwright@1.56.1 && npx playwright install chromium
///
/// A global install is accepted too. Returns null when neither is there, so
/// each suite decides for itself what skipping means.
function loadChromium() {
  try {
    return require('playwright').chromium;
  } catch {
    try {
      return require(path.join(
        require('child_process').execSync('npm root -g', { encoding: 'utf8' }).trim(), 'playwright')).chromium;
    } catch {
      return null;
    }
  }
}

// ─── the renderer, served over http ─────────────────────────────────────────

const DEFAULT_RENDERER_DIR = path.join(__dirname, '..', '..', 'src', 'renderer');

/// SSHSPAN_RENDERER_DIR points a run at another copy of the renderer (for
/// example a pristine `git archive` of an older commit, to watch the checks
/// fail where they should).
function rendererDir() {
  return process.env.SSHSPAN_RENDERER_DIR
    ? path.resolve(process.env.SSHSPAN_RENDERER_DIR)
    : DEFAULT_RENDERER_DIR;
}

const TYPES = {
  '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css',
  '.svg': 'image/svg+xml', '.png': 'image/png', '.woff2': 'font/woff2',
};

/// Serve a renderer directory over http: file:// would block the module loads.
function serve(root = DEFAULT_RENDERER_DIR) {
  const server = http.createServer((req, res) => {
    const rel = decodeURIComponent(req.url.split('?')[0]).replace(/^\/+/, '') || 'index.html';
    const file = path.join(root, rel);
    // With the separator: a sibling folder whose name begins with the
    // root's (`renderer-old`) is outside the root, not inside it.
    if (!file.startsWith(root + path.sep) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) {
      res.writeHead(404); res.end('not found'); return;
    }
    res.writeHead(200, { 'Content-Type': TYPES[path.extname(file)] || 'application/octet-stream' });
    res.end(fs.readFileSync(file));
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server)));
}

// ─── small helpers ──────────────────────────────────────────────────────────

const delay = (ms) => new Promise((r) => setTimeout(r, ms));
const firstLine = (e) => String((e && e.message) || e).split('\n')[0];
/// Playwright's call log says what it was waiting for ("waiting for
/// locator(...)", "element is not visible"); without it a timeout in a
/// shared run cannot be told apart from another.
const waitedFor = (e) => {
  const lines = String((e && e.message) || '').split('\n').map((l) => l.trim()).filter((l) => l.startsWith('- '));
  const target = lines.find((l) => /waiting for (locator|selector|function)/.test(l));
  const reason = [...lines].reverse().find((l) => /not |intercepts|detached|unstable/.test(l));
  return [target, reason].filter(Boolean).join(' / ');
};

/// A block that may throw (a selector that never appears, a timeout) must fail
/// its own checks, not take the rest of the scenario down with it.
async function part(title, fn) {
  try {
    await fn();
  } catch (e) {
    const why = waitedFor(e);
    console.log(`  FAIL  ${title} - aborted: ${firstLine(e)}${why ? ' [' + why + ']' : ''}`);
    failures.push(`${title} (aborted)`);
  }
}

// ─── page with a fixed reply table (check-renderer-ui.js) ───────────────────

/// app.js reads window.__TAURI__ at module scope; without this stub it throws
/// there and every later top-level const is stuck in the temporal dead zone,
/// so the page half-initialises and the checks below measure nothing.
async function openPage(browser, server, replies) {
  const page = await browser.newPage({ viewport: { width: 1400, height: 900 } });
  await page.addInitScript(({ r }) => {
    window.__TAURI__ = {
      core: { invoke: async (cmd) => r[cmd] ?? {} },
      event: { listen: async () => () => {} },
    };
  }, { r: replies });
  const errors = [];
  page.on('pageerror', e => errors.push(String(e.message || e)));
  await page.goto(`http://127.0.0.1:${server.address().port}/index.html`);
  await page.waitForSelector('#keyList .key-row', { timeout: 15000 });
  return { page, errors };
}

// ─── the stub backend (runs inside the page) ────────────────────────────────

/// Installed before any page script. It answers the commands the renderer
/// sends, records every call in window.__calls, and exposes just enough control
/// for a test: window.__backend (vault/session state), window.__replies
/// (per-command override: a value, a function(args), or { $reject: message }
/// for a command that fails), window.__gates (hold a command until released),
/// window.__emit (fire a Tauri event).
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
    // A failing command, declared as data so it can be set before boot (a
    // function does not survive addInitScript's argument). Rejects with the
    // bare message string, the way a Rust Err(String) reaches the page.
    if (r && typeof r === 'object' && Object.prototype.hasOwnProperty.call(r, '$reject')) throw r.$reject;
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

  // Opt-in: the window API's OS file drop (Tauri's onDragDropEvent). The
  // handler the renderer registers is kept as window.__dragDrop, so a test can
  // deliver {type, paths, position} the way the webview would.
  if (cfg.dragDrop) {
    window.__TAURI__.window = {
      getCurrentWindow: () => ({
        onDragDropEvent: async (cb) => { window.__dragDrop = cb; return () => {}; },
      }),
    };
  }

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

// ─── fixtures and helpers for the stubbed app ───────────────────────────────

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

/// How long the app may take to load and boot (openApp) - not a step's wait.
const BOOT_TIMEOUT_MS = 20000;

/// Pause the fake clock `lead` ms ahead of the page's own time. Installed, the
/// clock runs at real speed until it is paused, so on a loaded machine the
/// page's time can pass the target between reading it and pausing there:
/// pauseAt then throws "Cannot fast-forward to the past" (test:safety under
/// load - JU5 fix round 2). It has paused the clock by then (Playwright pauses
/// first, then fast-forwards), so the next try, from the page's now frozen
/// time, lands - the clock still stops `lead` ms past where the page is.
async function pauseClockAhead(page, lead) {
  for (let tries = 1; ; tries++) {
    const now = await page.evaluate(() => Date.now());
    try {
      await page.clock.pauseAt(now + lead);
      return;
    } catch (e) {
      if (tries >= 3 || !/fast-forward to the past/i.test(String((e && e.message) || e))) throw e;
    }
  }
}

/// Open the real app against the stub. `clock: true` installs Playwright's fake
/// clock and pauses it after boot, so time only moves through app.tick().
/// `bootCmd` names the IPC command whose first call counts as "booted"
/// (default settings_get); a test of a boot that may not get that far waits
/// for an earlier one instead.
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
    dragDrop: !!o.dragDrop,
  });
  // The boot is setup, not a check: on a loaded machine (suites run side by
  // side, a coverage run) loading the page and its scripts took longer than
  // the 3.5 s every step gets, and a run failed before it began. The steps
  // keep their 3.5 s (JU5 fix round 2).
  await page.goto(`http://127.0.0.1:${server.address().port}/index.html`, { timeout: BOOT_TIMEOUT_MS });
  // main() reads settings only after every script has loaded and the first
  // vault_status has been applied, so this means "booted". Polled on an
  // interval, not on animation frames, which a starved renderer can hold back;
  // a boot that does not get there says how far it got.
  try {
    await page.waitForFunction((cmd) => window.__calls.some((c) => c.cmd === cmd), o.bootCmd || 'settings_get',
      { timeout: BOOT_TIMEOUT_MS, polling: 50 });
  } catch (e) {
    const where = await page.evaluate(() => ({
      calls: (window.__calls || []).map((c) => c.cmd).slice(0, 12),
      bootErrors: window.__bootErrors || [],
      scripts: [...document.scripts].map((s) => (s.src || '').split('/').pop()).filter(Boolean),
      ready: document.readyState,
    })).catch((x) => ({ unreadable: String((x && x.message) || x).split('\n')[0] }));
    throw new Error(`the app did not boot in ${BOOT_TIMEOUT_MS} ms: ${JSON.stringify(where)}`);
  }
  await page.waitForTimeout(60);
  if (o.clock) await pauseClockAhead(page, 20);
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

/// Let every timer the page has ALREADY scheduled, with a delay of up to `ms`,
/// run first. Timers run in due-time order, so one scheduled now for `ms` from
/// now runs after all of them: an ordering barrier, not a guess at how slow
/// the machine is. Used where a step must follow the page's own deferred work
/// (check-keys-ui.js: the open key's answer resets the detail pane before the
/// Export tab is chosen). It is no longer needed around the terminal's deferred
/// focus: since JU5 that never takes the keyboard from a control the user has
/// moved to (terminal.js terminalFocus), so the two test:polish waits that
/// worked around it are gone.
const afterScheduledTimers = (page, ms = 100) =>
  page.evaluate((d) => new Promise((r) => setTimeout(r, d)), ms);

/// What Tauri's `dragDropEnabled` (on, because OS file drops need it) does to
/// in-page HTML5 drag and drop on Windows (A3-23): WebView2's drop handler is
/// replaced, so a drag can start but `dragover` / `drop` never reach the page.
/// Headless Chromium has no such handler and runs HTML5 drags happily, so a
/// drag test without this would pass for code that is dead on Windows.
const emulateWindowsDragDrop = (page) => page.evaluate(() => {
  if (window.__noHtml5Drops) return;
  window.__noHtml5Drops = true;
  for (const type of ['dragenter', 'dragover', 'drop']) {
    window.addEventListener(type, (e) => { e.stopImmediatePropagation(); }, true);
  }
});

/// A real mouse drag (pointer events): press over `from`, move past the drag
/// threshold, glide to `to` (at `o.at` of its height, default the middle),
/// optionally look around while still pressed (`o.during(point)`) or press
/// Escape (`o.escape`), then release. Selectors or { x, y } points. Returns
/// what `o.during` returned.
async function mouseDrag(page, from, to, o = {}) {
  const point = async (target, frac, dx) => {
    if (typeof target !== 'string') return target;
    const box = await page.locator(target).first().boundingBox();
    if (!box) throw new Error(`mouseDrag: ${target} is not on screen`);
    return { x: box.x + (dx == null ? box.width / 2 : dx), y: box.y + box.height * (frac == null ? 0.5 : frac) };
  };
  const a = await point(from, 0.5, o.fromX);
  const b = await point(to, o.at, o.toX);
  await page.mouse.move(a.x, a.y);
  await page.mouse.down();
  await page.mouse.move(a.x + 6, a.y + 4, { steps: 2 });
  await page.mouse.move(b.x, b.y, { steps: 8 });
  const seen = o.during ? await o.during(b) : undefined;
  if (o.escape) await page.keyboard.press('Escape');
  await page.mouse.up();
  return seen;
}

const bytesOf = (c) => String.fromCharCode(...(c.args.bytes || []));
const sends = async (app) => (await app.calls('terminal_send')).map(bytesOf);

/// The texts of the toasts on screen, oldest first.
const toasts = (page) => page.evaluate(() =>
  [...document.querySelectorAll('#toast .toast-item')].map((n) => n.querySelector('.toast-text').textContent));

/// Hold a command at the stub until letGo(): what the page shows while it runs.
const hold = (page, cmd) => page.evaluate((c) => {
  let release;
  window.__gates[c] = { promise: new Promise((r) => { release = r; }), release };
}, cmd);
const letGo = (page, cmd) => page.evaluate((c) => {
  const g = window.__gates[c];
  delete window.__gates[c];
  if (g) g.release();
}, cmd);

module.exports = {
  failures, check, yes,
  loadChromium,
  DEFAULT_RENDERER_DIR, rendererDir, serve,
  delay, firstLine, part,
  openPage,
  stubInit, PASSWORD, T0, KEY, SERVER, CATEGORY, pauseClockAhead,
  openApp, withApp, settled, waitVisible, focusIs, answerConfirm, openLiveTab, afterScheduledTimers, bytesOf, sends,
  toasts, hold, letGo, emulateWindowsDragDrop, mouseDrag,
};
