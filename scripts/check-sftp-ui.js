#!/usr/bin/env node
/*
 * SFTP file browser regression checks, driven through the REAL page
 * (index.html and every script it loads) in headless Chromium against a stub
 * Tauri IPC (scripts/lib/renderer-harness.js) plus the fake remote and local
 * file systems installed below.
 *
 * Nothing here re-implements production logic: the stub answers invoke() the
 * way the Rust commands do (sftp_list_dir echoes the path it was given, a
 * missing folder fails like read_dir, sftp_queue_list answers by EMITTING the
 * queue snapshot as emit_queue does) and every assertion is about what the
 * page shows or which IPC commands it sends.
 *
 * What it pins (flaw audit 2026-10-09, unit JU1 - finding ids in each title):
 *   - navigation is transactional and sequenced: a failed or overtaken listing
 *     never moves the tab; breadcrumbs follow; `.`/`..` are resolved;
 *   - the selection is only ever what is on screen in the current folder;
 *   - the transfer queue patches rows in place (a click survives progress),
 *     never loops on sftp_queue_list, never hides running jobs and has a
 *     bucket for cancelled ones;
 *   - local-pane paths on Windows, conflict handling, the chmod dialog, the
 *     delete prompts, focus, keyboard shortcuts, OS drops, background tabs,
 *     search ids and edit-in-editor sync reporting.
 *
 * Run with `npm run test:sftp`. Needs playwright (see check-renderer-ui.js);
 * without it this skips with exit 0. `--only <text>` runs the scenarios whose
 * title contains <text>; SSHSPAN_RENDERER_DIR points the run at another copy
 * of the renderer (a pristine `git archive` of an older commit, to watch these
 * checks fail where they should).
 */
'use strict';

const {
  failures, check, yes, loadChromium, rendererDir, serve, part,
  withApp, waitVisible, focusIs, openLiveTab,
} = require('./lib/renderer-harness');

const chromium = loadChromium();
if (!chromium) {
  console.log('playwright not installed - skipping the SFTP checks.');
  process.exit(0);
}

// ─── the fake file systems (run inside the page) ────────────────────────────

/// Installed after boot, because functions cannot travel through
/// addInitScript's argument. `spec.remote` / `spec.local` map a folder to its
/// entries: a string is a file, a string ending in '/' a folder, an object is
/// taken as it is. window.__fs stays live, so a test can change a listing, slow
/// a path down (delays) or make it fail (errors) halfway through.
function installFs(spec) {
  const clone = (v) => JSON.parse(JSON.stringify(v));
  const F = (name, extra) => Object.assign({
    name, isDir: false, isLink: false, size: 10, modifiedMs: 1700000000000,
    permissions: 0o100644, uid: 1000, gid: 1000,
  }, extra || {});
  const D = (name, extra) => F(name, Object.assign({ isDir: true, size: 0, permissions: 0o40755 }, extra || {}));
  const entry = (e) => (typeof e !== 'string' ? e : e.endsWith('/') ? D(e.slice(0, -1)) : F(e));
  const tree = (t) => Object.fromEntries(Object.entries(t || {}).map(([p, list]) => [p, list.map(entry)]));
  const fs = window.__fs = {
    remote: tree(spec.remote), local: tree(spec.local), home: spec.home || '/home/me',
    delays: {}, errors: {}, modes: Object.assign({}, spec.modes), queue: [], entry,
  };
  const wait = (ms) => new Promise((r) => setTimeout(r, ms));
  const R = window.__replies;
  R.sftp_list_dir = async (a) => {
    if (fs.delays[a.path]) await wait(fs.delays[a.path]);
    if (fs.errors[a.path]) throw fs.errors[a.path];
    if (!fs.remote[a.path]) throw `List failed: No such file (${a.path})`;
    return { ok: true, entries: clone(fs.remote[a.path]), path: a.path };
  };
  R.sftp_local_list = async (a) => {
    const p = a.path || fs.home;
    if (fs.delays[p]) await wait(fs.delays[p]);
    if (fs.errors[p]) throw fs.errors[p];
    if (!fs.local[p]) throw 'read_dir failed: The system cannot find the path specified. (os error 3)';
    return { ok: true, path: p, home: fs.home, entries: clone(fs.local[p]) };
  };
  R.sftp_queue_add = (a) => ({ ok: true, added: (a.items || []).length, warnings: [] });
  // emit_queue: the answer is an EVENT carrying the whole snapshot, delivered
  // after the command returned.
  R.sftp_queue_list = () => {
    setTimeout(() => window.__emit('sftp-queue', { jobs: clone(fs.queue) }), 0);
    return { ok: true };
  };
  R.sftp_bookmarks_list = { ok: true, bookmarks: [] };
  R.sftp_fs_info = { ok: true, supported: false };
  R.sftp_get_permissions = (a) => {
    if (fs.modes[a.path] == null) throw `stat failed: Permission denied (${a.path})`;
    return { ok: true, mode: fs.modes[a.path] };
  };
  R.sftp_chmod = { ok: true, changed: 1, failed: [], failedCount: 0, skippedLinks: 0 };
  R.sftp_search = { ok: true };
  R.sftp_search_cancel = { ok: true, cancelled: true };
  for (const c of ['sftp_queue_cancel', 'sftp_queue_pause', 'sftp_queue_resume', 'sftp_queue_resume_all',
    'sftp_queue_retry', 'sftp_queue_pause_all', 'sftp_queue_clear_finished', 'sftp_remove', 'sftp_rename',
    'sftp_mkdir', 'sftp_touch', 'sftp_local_remove', 'sftp_local_mkdir', 'sftp_local_rename',
    'sftp_close_edit', 'sftp_close', 'sftp_keepalive_start', 'system_open_external']) {
    R[c] = { ok: true };
  }
}

// ─── helpers ────────────────────────────────────────────────────────────────

/// A fresh app with the fake file systems in place.
async function withFiles(browser, server, spec, title, fn) {
  await withApp(browser, server, Object.assign({ dragDrop: true }, spec.app || {}), title, async (app) => {
    await app.page.evaluate(installFs, spec);
    await fn(app);
  });
}

/// A session tab on its file surface, built and listed the way the app does it
/// (setSessionMode: queue events wired, activateSessionSurface -> showSftpForTab,
/// then the first listing).
async function openFilesTab(page, o = {}) {
  return page.evaluate(async (opt) => {
    const tabId = opt.tabId || 't1';
    state.sessions.set(tabId, Object.assign({
      tabId, sessionId: 'sess-' + tabId, serverId: 'srv-' + tabId, serverName: 'host-' + tabId,
      host: '10.0.0.1', port: 22, mode: 'sftp', sftpReady: true, sftpPath: '/home/u', ended: false,
    }, opt.tab || {}));
    if (state.view !== 'connect') await switchView('connect');
    wireQueueEvents();
    activateSessionSurface(tabId);
    if ((opt.tab && opt.tab.mode) !== 'ssh') await refreshSftpPanel(tabId);
    return tabId;
  }, o);
}

const rowNames = (page, tabId) => page.evaluate((t) =>
  [...document.querySelectorAll(`#sftpTbody-${t} tr.sftp-entry`)].map((r) => r.dataset.name), tabId || 't1');
const localRowNames = (page, tabId) => page.evaluate((t) =>
  [...document.querySelectorAll(`#sftpLocalTbody-${t} tr.sftp-entry`)].map((r) => r.dataset.name), tabId || 't1');
const crumbsOf = (page, tabId) => page.evaluate((t) => {
  const bar = document.getElementById('sftpCrumbs-' + t);
  const cur = bar && bar.querySelector('.sftp-crumb.current');
  return {
    parts: bar ? [...bar.querySelectorAll('.sftp-crumb')].map((b) => b.textContent) : null,
    current: cur ? cur.textContent : null,
  };
}, tabId || 't1');
const tabField = (page, field, tabId) => page.evaluate(({ f, t }) => {
  const v = state.sessions.get(t)[f];
  return v instanceof Set ? [...v].sort() : v;
}, { f: field, t: tabId || 't1' });
const toasts = (page) => page.evaluate(() =>
  [...document.querySelectorAll('#toast .toast-item')].map((n) => n.querySelector('.toast-text').textContent));
const menuItems = (page) => page.evaluate(() => {
  const m = document.getElementById('keyConnectMenu');
  return m ? [...m.querySelectorAll('.ctx-item')].map((b) => b.textContent.trim()) : null;
});
const clickMenuItem = (page, label) => page.evaluate((l) => {
  const b = [...document.querySelectorAll('#keyConnectMenu .ctx-item')].find((x) => x.textContent.trim() === l);
  if (!b) return false;
  b.click();
  return true;
}, label);
/// Fire a pointer gesture at a row through the page (it bubbles to the
/// delegated listeners exactly like a real one).
const rowEvent = (page, type, name, o) => page.evaluate(({ type: ty, name: n, o: opt }) => {
  const sel = `#${opt.local ? 'sftpLocalTbody-' : 'sftpTbody-'}${opt.tab || 't1'} tr.sftp-entry`;
  const row = [...document.querySelectorAll(sel)].find((r) => r.dataset.name === n);
  if (!row) return false;
  row.dispatchEvent(new MouseEvent(ty, Object.assign({ bubbles: true, cancelable: true, clientX: 300, clientY: 300 }, opt.init || {})));
  return true;
}, { type, name, o: o || {} });
const queueAdds = async (app) => (await app.calls('sftp_queue_add')).map((c) => c.args);
const settle = (page, ms) => page.waitForTimeout(ms || 120);

// ─── scenarios ──────────────────────────────────────────────────────────────

const REMOTE_TREE = {
  '/': ['etc/', 'home/', 'srv/', 'var/'],
  '/home/u': ['secret/', 'slow/', 'fast/', 'notes.txt'],
  '/home/u/secret': ['private.key'],
  '/home/u/slow': ['file-in-slow.txt'],
  '/home/u/fast': ['file-in-fast.txt'],
  '/srv': ['api/', 'in-srv.txt'],
  '/srv/api': ['releases/'],
  '/srv/api/releases': ['v1.tar'],
  '/etc': ['nginx/'],
  '/etc/nginx': ['in-nginx.txt'],
  '/var': ['www/', 'in-var.txt'],
  '/var/www': ['index.html'],
  '/a/c/d': ['deep.txt'],
};
const HOME_ONLY = { '/home/me': [] };

/// Type a path into the remote path field and press Enter, as a user does.
async function typePath(page, value, tabId) {
  const t = tabId || 't1';
  await page.evaluate((id) => editRemotePath(id), t);
  await page.fill(`#sftpPath-${t}`, value);
  await page.press(`#sftpPath-${t}`, 'Enter');
}

/// A3-04 / A3-09 / A3-15 / A3-16: the tab only moves to a folder whose listing
/// arrived, the newest request wins, and the breadcrumb follows.
async function scenarioNavigation(browser, server) {
  const spec = { remote: REMOTE_TREE, local: HOME_ONLY };

  await withFiles(browser, server, spec, 'A3-04 failed folder open', async (app) => {
    const { page } = app;
    await openFilesTab(page);
    await page.evaluate(() => { window.__fs.errors['/home/u/secret'] = 'List failed: Permission denied'; });
    await rowEvent(page, 'dblclick', 'secret');
    await settle(page, 200);
    check('A3-04 a folder that cannot be listed leaves the tab where it was', await tabField(page, 'sftpPath'), '/home/u');
    check('A3-04 the rows are still that folder\'s', await rowNames(page), ['fast', 'secret', 'slow', 'notes.txt']);
    check('A3-04 and so is the breadcrumb', (await crumbsOf(page)).current, 'u');
    yes('A3-04 the reason is shown', (await toasts(page)).some((t) => /Permission denied/.test(t)));
    await rowEvent(page, 'dblclick', 'notes.txt');
    await settle(page, 900); // a download opens the local pane first
    check('A3-04 a download afterwards takes the file from the folder on screen',
      (await queueAdds(app)).map((a) => a.items.map((i) => i.remote)), [['/home/u/notes.txt']]);
    check('no page errors', app.errors, []);
  });

  await withFiles(browser, server, spec, 'A3-09 listing race', async (app) => {
    const { page } = app;
    await openFilesTab(page);
    await page.evaluate(() => { window.__fs.delays['/home/u/slow'] = 400; window.__fs.delays['/home/u/fast'] = 30; });
    await rowEvent(page, 'dblclick', 'slow');
    await settle(page, 100);
    await typePath(page, '/home/u/fast');
    await settle(page, 700);
    check('A3-09 a slower, older listing does not overwrite the newer navigation', await tabField(page, 'sftpPath'), '/home/u/fast');
    check('A3-09 the rows are the newer folder\'s', await rowNames(page), ['file-in-fast.txt']);
    check('A3-09 so is the breadcrumb', (await crumbsOf(page)).current, 'fast');
    check('no page errors', app.errors, []);
  });

  // A plain refresh of the current folder - what a finished transfer, a
  // mkdir/rename/delete or showing the tab again does - must not overtake a
  // navigation that is still waiting for its listing.
  await withFiles(browser, server, spec, 'A3-09 refresh during a pending navigation', async (app) => {
    const { page } = app;
    await openFilesTab(page);
    const listedSince = async (n) => (await app.calls('sftp_list_dir')).slice(n).map((c) => c.args.path);
    await page.evaluate(() => { window.__fs.delays['/home/u/slow'] = 600; });
    let from = await app.count('sftp_list_dir');
    await rowEvent(page, 'dblclick', 'slow');
    await settle(page, 100);
    await page.evaluate(() => refreshSftpPanel('t1', { forceFresh: true }));
    await settle(page, 1500);
    check('A3-09 a refresh while a folder is opening does not cancel the opening', await tabField(page, 'sftpPath'), '/home/u/slow');
    check('A3-09 the rows are the opened folder\'s', await rowNames(page), ['file-in-slow.txt']);
    check('A3-09 the held-back refresh runs afterwards, on the opened folder', await listedSince(from), ['/home/u/slow', '/home/u/slow']);
    // The real trigger: a transfer finishing while the next folder opens (the
    // 1.5 s transfer-done ticker refreshes the tab on screen).
    await page.evaluate(() => { window.__fs.delays['/home/u/fast'] = 2000; });
    from = await app.count('sftp_list_dir');
    await typePath(page, '/home/u/fast');
    await emitJobs(page, [JOB(77, 'x.bin', 'done', { kind: 'upload', remotePath: '/home/u/slow/x.bin', bytesDone: 1000 })]);
    await page.waitForTimeout(2600);
    check('A3-09 a transfer finishing while a folder opens does not cancel the opening', await tabField(page, 'sftpPath'), '/home/u/fast');
    check('A3-09 nothing re-listed the folder being left', (await listedSince(from)).filter((p) => p !== '/home/u/fast'), []);
    check('no page errors', app.errors, []);
  });

  await withFiles(browser, server, {
    remote: REMOTE_TREE, local: { '/home/me': ['big/', 'x.txt'], '/home/me/big': ['inside.txt'] },
  }, 'A3-09 local refresh during a pending local navigation', async (app) => {
    const { page } = app;
    await openFilesTab(page);
    await openDual(page);
    await page.evaluate(() => { window.__fs.delays['/home/me/big'] = 600; });
    await rowEvent(page, 'dblclick', 'big', { local: true });
    await settle(page, 100);
    // A remote refresh in dual mode re-lists the local pane too.
    await page.evaluate(() => refreshSftpPanel('t1', { forceFresh: true }));
    await settle(page, 1500);
    check('A3-09 a refresh while a local folder is opening does not cancel the opening', await tabField(page, 'localPath'), '/home/me/big');
    check('A3-09 the local rows are the opened folder\'s', await localRowNames(page), ['inside.txt']);
    check('no page errors', app.errors, []);
  });

  // The session dies while a folder is opening; the tab is reconnected and
  // opened again. The dead request must not hold the new session's first
  // listing (it would wait for the old request's timeout), nor speak up.
  await withFiles(browser, server, spec, 'A3-09 pending listing of a closed session', async (app) => {
    const { page } = app;
    await openFilesTab(page);
    await page.evaluate(() => { window.__fs.delays['/home/u/slow'] = 1500; });
    await rowEvent(page, 'dblclick', 'slow');
    await settle(page, 100);
    await page.evaluate(() => { window.__fs.errors['/home/u/slow'] = 'Session closed.'; });
    const applied = await page.evaluate(async () => {
      window.onSessionClosed('t1');
      // Reconnected (a new session id) and back on Files, as setSessionMode does.
      const t = state.sessions.get('t1');
      Object.assign(t, { sessionId: 'sess-t1-new', ended: false, sftpReady: true, mode: 'sftp', sftpPath: '/home/u' });
      activateSessionSurface('t1');
      return refreshSftpPanel('t1');
    });
    check('A3-09 the first listing after a reconnect is not held behind the dead session\'s request', applied, true);
    check('A3-09 it lists through the new session',
      (await app.calls('sftp_list_dir')).filter((c) => c.args.sessionId === 'sess-t1-new').map((c) => c.args.path), ['/home/u']);
    await page.waitForTimeout(1700);
    check('A3-09 the dead request\'s error is not shown', (await toasts(page)).filter((t) => /Session closed/.test(t)), []);
    check('A3-09 and the tab stays on the folder it reopened', await tabField(page, 'sftpPath'), '/home/u');
    check('no page errors', app.errors, []);
  });

  await withFiles(browser, server, spec, 'A3-15 breadcrumb', async (app) => {
    const { page } = app;
    await openFilesTab(page, { tab: { sftpPath: '/srv/api/releases' } });
    check('the breadcrumb starts at the tab\'s folder', await crumbsOf(page), { parts: ['/', 'srv', 'api', 'releases'], current: 'releases' });
    await page.evaluate(() => [...document.querySelectorAll('#sftpCrumbs-t1 .sftp-crumb')].find((b) => b.textContent === 'srv').click());
    await settle(page);
    check('A3-15 clicking a breadcrumb segment redraws the breadcrumb', await crumbsOf(page), { parts: ['/', 'srv'], current: 'srv' });
    check('A3-15 next to the right rows', await rowNames(page), ['api', 'in-srv.txt']);
    await typePath(page, '/etc/nginx');
    await settle(page);
    check('A3-15 a typed path redraws it too', await crumbsOf(page), { parts: ['/', 'etc', 'nginx'], current: 'nginx' });
    check('no page errors', app.errors, []);
  });

  await withFiles(browser, server, spec, 'A3-16 dot segments', async (app) => {
    const { page } = app;
    await openFilesTab(page);
    check('A3-16 the path parser resolves . and ..',
      await page.evaluate(() => ['/a/b/../c/./d', '/var/www/..', '/../..', '/a/./'].map((p) => (sftpUiNormalizeRemotePath(p) || {}).path)),
      ['/a/c/d', '/var', '/', '/a']);
    await typePath(page, '/var/www/..');
    await settle(page);
    check('A3-16 a typed /var/www/.. lands in /var', await tabField(page, 'sftpPath'), '/var');
    check('A3-16 and lists /var itself', (await app.calls('sftp_list_dir')).pop().args.path, '/var');
    check('A3-16 with a breadcrumb free of dots', (await crumbsOf(page)).parts, ['/', 'var']);
    await page.click('#sftpPanel-t1 .sftp-toolbar button[title="Parent directory"]');
    await settle(page);
    check('A3-16 Up from there goes to the real parent', await tabField(page, 'sftpPath'), '/');
    await typePath(page, '/a/b/../c/./d');
    await settle(page);
    check('A3-16 mixed segments resolve before listing', await tabField(page, 'sftpPath'), '/a/c/d');
    check('no page errors', app.errors, []);
  });
}

/// A3-05: the selection is only ever what is on screen, in this folder.
async function scenarioSelection(browser, server) {
  const remote = {
    '/home/u': ['.ssh/', '.bashrc', 'a.txt', 'b.txt', 'c.txt', 'd.txt'],
    '/a': ['index.html', 'other.html'],
    '/b': ['index.html'],
  };
  const hiddenBtn = '#sftpPanel-t1 .sftp-toolbar button[title="Show/hide dotfiles"]';

  await withFiles(browser, server, { remote, local: HOME_ONLY }, 'A3-05 hidden files and quick-find', async (app) => {
    const { page } = app;
    await openFilesTab(page);
    await page.click(hiddenBtn);
    await settle(page);
    check('dotfiles are listed once shown', await rowNames(page), ['.ssh', '.bashrc', 'a.txt', 'b.txt', 'c.txt', 'd.txt']);
    await rowEvent(page, 'contextmenu', 'a.txt');
    await clickMenuItem(page, 'Select all');
    check('Select all takes every listed row', await tabField(page, 'sftpSelected'),
      ['.bashrc', '.ssh', 'a.txt', 'b.txt', 'c.txt', 'd.txt']);
    await page.click(hiddenBtn);
    await settle(page);
    check('A3-05 hiding dotfiles drops them from the selection', await tabField(page, 'sftpSelected'),
      ['a.txt', 'b.txt', 'c.txt', 'd.txt']);
    yes('A3-05 the status bar counts what is selected on screen',
      /4 selected/.test(await page.textContent('#sftpStatusLeft-t1')), await page.textContent('#sftpStatusLeft-t1'));
    await rowEvent(page, 'contextmenu', 'a.txt');
    check('A3-05 the menu offers to delete the four visible files', (await menuItems(page) || []).filter((l) => /^Delete/.test(l)), ['Delete 4 items']);
    await clickMenuItem(page, 'Delete 4 items');
    yes('the delete prompt opens', await waitVisible(page, '#deleteModal'));
    const msg = await page.textContent('#deleteMessage');
    yes('A3-05 the delete prompt names the first items and counts the rest',
      /a\.txt/.test(msg) && /b\.txt/.test(msg) && /c\.txt/.test(msg) && /1 more/.test(msg) && !/\.ssh|\.bashrc/.test(msg), msg);
    await page.click('#deleteCancelBtn');
    check('Cancel deletes nothing', await app.count('sftp_remove'), 0);
    // Type-to-filter narrows the view; the selection narrows with it.
    await page.click('#sftpTbody-t1 tr.sftp-entry[data-name="b.txt"]');
    await rowEvent(page, 'contextmenu', 'b.txt');
    await clickMenuItem(page, 'Select all');
    await page.focus('#sftpTbody-t1 tr.sftp-entry[data-name="b.txt"]');
    await page.keyboard.type('a');
    await settle(page);
    check('quick-find shows the matching row', await rowNames(page), ['a.txt']);
    check('A3-05 rows hidden by quick-find leave the selection', await tabField(page, 'sftpSelected'), ['a.txt']);
    check('no page errors', app.errors, []);
  });

  await withFiles(browser, server, { remote, local: HOME_ONLY }, 'A3-05 folder change', async (app) => {
    const { page } = app;
    await openFilesTab(page, { tab: { sftpPath: '/a' } });
    await rowEvent(page, 'click', 'index.html');
    check('a click selects the row', await tabField(page, 'sftpSelected'), ['index.html']);
    await typePath(page, '/b');
    await settle(page);
    check('A3-05 the selection does not follow a name into another folder', await tabField(page, 'sftpSelected'), []);
    check('A3-05 and no row there is highlighted',
      await page.evaluate(() => document.querySelectorAll('#sftpTbody-t1 tr.selected').length), 0);
    check('no page errors', app.errors, []);
  });
}

/// A3-07: a refresh puts the focus back on a row only when it was in the list.
async function scenarioFocus(browser, server) {
  const remote = { '/home/u': ['a.txt', 'b.txt'] };
  await withFiles(browser, server, { remote, local: HOME_ONLY }, 'A3-07 focus', async (app) => {
    const { page } = app;
    await openFilesTab(page);
    const focusedRow = () => page.evaluate(() => {
      const a = document.activeElement;
      return a && a.matches && a.matches('tr.sftp-entry') ? a.dataset.name : null;
    });
    await page.click('#sftpTbody-t1 tr.sftp-entry[data-name="a.txt"]');
    check('a clicked row takes the focus', await focusedRow(), 'a.txt');
    await page.evaluate(() => editRemotePath('t1'));
    await focusIs(page, 'sftpPath-t1');
    await page.evaluate(() => refreshSftpPanel('t1', { forceFresh: true }));
    await settle(page);
    check('A3-07 a refresh leaves the focus in the path field', await app.focused(), 'sftpPath-t1');
    await page.keyboard.press('Escape');
    await page.evaluate(() => promptModal('Rename', 'New name:', 'x', () => {}));
    await focusIs(page, 'promptInput');
    await page.evaluate(() => refreshSftpPanel('t1', { forceFresh: true }));
    await settle(page);
    check('A3-07 a refresh leaves the focus in an open dialog', await app.focused(), 'promptInput');
    await page.keyboard.press('Escape');
    // A transfer finishing in the background refreshes the listing.
    await page.evaluate(() => editRemotePath('t1'));
    await focusIs(page, 'sftpPath-t1');
    await page.evaluate(() => window.__emit('sftp-queue', { jobs: [{
      id: 900, kind: 'upload', sessionId: 'sess-t1', serverId: 'srv-t1', serverName: 'host-t1',
      localPath: '/home/me/b.txt', remotePath: '/home/u/b.txt', size: 1, bytesDone: 1, state: 'done',
    }] }));
    await page.waitForTimeout(1800);
    check('A3-07 a finished transfer does not pull the focus into the list', await app.focused(), 'sftpPath-t1');
    await page.keyboard.press('Escape');
    await page.click('#sftpTbody-t1 tr.sftp-entry[data-name="b.txt"]');
    await page.evaluate(() => refreshSftpPanel('t1', { forceFresh: true }));
    await settle(page);
    check('a keyboard user in the list keeps their row across a refresh', await focusedRow(), 'b.txt');
    check('no page errors', app.errors, []);
  });
}

const WIN_LOCAL = {
  'C:\\Users\\u': ['Documents/', 'Application Data/', 'client-work/', 'notes.txt'],
  'C:\\Users\\u\\Documents': ['Projects/'],
  'C:\\Users\\u\\Documents\\Projects': ['x.txt'],
  'C:\\Users': ['u/'],
  'C:\\': ['Users/'],
};

const openDual = async (page) => {
  await page.click('#sftpPanel-t1 .sftp-toolbar button[title="Toggle local pane"]');
  await settle(page, 200);
};
const localUp = async (page) => {
  await page.click('#sftpLocalPane-t1 .sftp-panehead button[title="Parent directory"]');
  await settle(page, 150);
};

/// A3-17 / A3-18 / A3-29: the local pane on Windows and its delete prompt.
async function scenarioLocalPane(browser, server) {
  const remote = { '/home/u': ['a.txt', 'b.txt'] };

  await withFiles(browser, server, { remote, local: WIN_LOCAL, home: 'C:\\Users\\u' }, 'A3-17 Windows paths', async (app) => {
    const { page } = app;
    check('A3-17 the parent of a Windows path keeps the drive and both separators count',
      await page.evaluate(() => (typeof sftpLocalParent !== 'function' ? 'missing' : [
        'C:\\Users\\u', 'C:\\Users', 'C:\\', 'C:\\Users\\u/Documents', 'C:/Users/u', '\\\\nas\\share\\dir',
        '/home/u', '/home', '/',
      ].map((p) => sftpLocalParent(p)))),
      ['C:\\Users', 'C:\\', 'C:\\', 'C:\\Users\\u', 'C:\\Users', '\\\\nas\\share\\', '/home', '/', '/']);
    await openFilesTab(page);
    await openDual(page);
    check('the local pane opens at home', await tabField(page, 'localPath'), 'C:\\Users\\u');
    await rowEvent(page, 'dblclick', 'Documents', { local: true });
    await settle(page, 150);
    check('A3-17 a double-click descends with the path\'s own separator', await tabField(page, 'localPath'), 'C:\\Users\\u\\Documents');
    await rowEvent(page, 'dblclick', 'Projects', { local: true });
    await settle(page, 150);
    const ups = [];
    for (let i = 0; i < 5; i++) { await localUp(page); ups.push(await tabField(page, 'localPath')); }
    check('A3-17 Up walks back to the drive root and stays there', ups,
      ['C:\\Users\\u\\Documents', 'C:\\Users\\u', 'C:\\Users', 'C:\\', 'C:\\']);
    const asked = (await app.calls('sftp_local_list')).map((c) => c.args.path);
    const malformed = (p) => (p.includes('\\') && p.includes('/')) || /^\/[A-Za-z]:/.test(p) || /^[A-Za-z]:$/.test(p);
    check('A3-17 no listing was ever asked for a mixed, slash-prefixed or drive-relative path',
      asked.filter(malformed), []);
    check('no page errors', app.errors, []);
  });

  await withFiles(browser, server, { remote, local: { '/home/me': [], '/home': ['me/'], '/': ['home/'] } }, 'A3-17 POSIX root', async (app) => {
    const { page } = app;
    await openFilesTab(page);
    await openDual(page);
    const ups = [];
    for (let i = 0; i < 3; i++) { await localUp(page); ups.push(await tabField(page, 'localPath')); }
    check('A3-17 on Linux, Up reaches / and stays there instead of jumping home', ups, ['/home', '/', '/']);
    check('no page errors', app.errors, []);
  });

  await withFiles(browser, server, { remote, local: WIN_LOCAL, home: 'C:\\Users\\u' }, 'A3-18 local listing error', async (app) => {
    const { page } = app;
    await openFilesTab(page);
    await openDual(page);
    await page.evaluate(() => { window.__fs.errors['C:\\Users\\u\\Application Data'] = 'read_dir failed: Access is denied. (os error 5)'; });
    const before = await app.count('sftp_local_list');
    await rowEvent(page, 'dblclick', 'Application Data', { local: true });
    await settle(page, 200);
    check('A3-18 an unreadable folder keeps the local pane where it was', await tabField(page, 'localPath'), 'C:\\Users\\u');
    check('A3-18 it does not fall back to home', (await app.calls('sftp_local_list')).slice(before).map((c) => c.args.path),
      ['C:\\Users\\u\\Application Data']);
    yes('A3-18 and says why', (await toasts(page)).some((t) => /Access is denied/.test(t)));
    check('the rows are unchanged', await localRowNames(page), ['Documents', 'Application Data', 'client-work', 'notes.txt']);
    check('no page errors', app.errors, []);
  });

  await withFiles(browser, server, {
    remote, local: WIN_LOCAL, home: 'C:\\Users\\u', app: { settings: { 'sftpLocalDir:srv-t1': 'D:\\gone' } },
  }, 'A3-18 stale remembered folder', async (app) => {
    const { page } = app;
    await openFilesTab(page);
    await openDual(page);
    check('a remembered default that no longer exists still opens home', await tabField(page, 'localPath'), 'C:\\Users\\u');
    yes('A3-18 and the user is told which folder was missing', (await toasts(page)).some((t) => /D:\\gone/.test(t)));
    check('no page errors', app.errors, []);
  });

  await withFiles(browser, server, { remote, local: WIN_LOCAL, home: 'C:\\Users\\u' }, 'A3-29 delete prompts', async (app) => {
    const { page } = app;
    await openFilesTab(page);
    const deleteRemote = async (name) => {
      await rowEvent(page, 'contextmenu', name);
      await clickMenuItem(page, 'Delete');
    };
    await deleteRemote('a.txt');
    yes('a remote delete asks', await waitVisible(page, '#deleteModal'));
    yes('A3-29 the opt-out names the remote side', /remote/i.test(await page.textContent('#deleteModal label')),
      await page.textContent('#deleteModal label'));
    await page.check('#deleteSkipSession');
    await page.click('#deleteYesBtn');
    await settle(page, 200);
    check('the remote file is deleted', (await app.calls('sftp_remove')).map((c) => c.args.path), ['/home/u/a.txt']);
    await openDual(page);
    await rowEvent(page, 'contextmenu', 'client-work', { local: true });
    await clickMenuItem(page, 'Delete');
    yes('A3-29 a local delete still asks after "don\'t ask again" on a remote one', await waitVisible(page, '#deleteModal'));
    yes('A3-29 and its opt-out names the local side', /local/i.test(await page.textContent('#deleteModal label')),
      await page.textContent('#deleteModal label'));
    await page.click('#deleteCancelBtn');
    await settle(page);
    check('A3-29 nothing local was removed', await app.count('sftp_local_remove'), 0);
    await deleteRemote('b.txt');
    await settle(page, 200);
    yes('the remote opt-out still holds for remote deletes', !(await app.open('deleteModal')));
    check('so the second remote file went at once', (await app.calls('sftp_remove')).map((c) => c.args.path), ['/home/u/a.txt', '/home/u/b.txt']);
    check('no page errors', app.errors, []);
  });
}

/// A3-06 / A3-19 / A5-47 and the missing-dialog leftover: transfer conflicts.
async function scenarioConflicts(browser, server) {
  const remote = { '/home/u': ['a.txt', 'Readme.md'], '/srv': ['a.txt', 'a (1).txt'] };

  await withFiles(browser, server, { remote, local: { '/home/me': ['a.txt', 'a (1).txt'] } }, 'A3-06 rename picks a free name', async (app) => {
    const { page } = app;
    await openFilesTab(page, { tab: { sftpPath: '/srv' } });
    await page.evaluate(() => { window.__q = queueUploads('t1', [{ local: '/tmp/a.txt', remote: '/srv/a.txt' }]); });
    yes('an existing target asks', await waitVisible(page, '#conflictModal'));
    await page.check('#conflict-0-rename');
    await page.click('#conflictApplyBtn');
    await settle(page, 200);
    check('A3-06 Rename skips a name that is already taken in the folder',
      (await queueAdds(app)).map((a) => a.items.map((i) => i.remote)), [['/srv/a (2).txt']]);
    await page.evaluate(() => { state.settings.sftpConflictUpload = 'rename'; });
    await page.evaluate(() => queueUploads('t1', [
      { local: '/tmp/x/a.txt', remote: '/srv/a.txt' },
      { local: '/tmp/y/a.txt', remote: '/srv/a.txt' },
      { local: '/tmp/a (2).txt', remote: '/srv/a (2).txt' },
    ]));
    await settle(page, 200);
    check('A3-06 renames in one batch avoid each other and the batch\'s own new files',
      (await queueAdds(app)).pop().items, [
        { local: '/tmp/x/a.txt', remote: '/srv/a (3).txt', resume: 'rename' },
        { local: '/tmp/y/a.txt', remote: '/srv/a (4).txt', resume: 'rename' },
        { local: '/tmp/a (2).txt', remote: '/srv/a (2).txt', resume: 'overwrite' },
      ]);
    await page.evaluate(() => { state.settings.sftpConflictDownload = 'rename'; });
    await openDual(page);
    await page.evaluate(() => queueDownloads('t1', ['/srv/a.txt']));
    await settle(page, 300);
    check('A3-06 a renamed download skips the names already in the local folder',
      (await queueAdds(app)).pop().items, [{ remote: '/srv/a.txt', resume: 'rename', localName: 'a (2).txt' }]);
    check('no page errors', app.errors, []);
  });

  await withFiles(browser, server, { remote, local: { 'C:\\dl': ['README.md'] }, home: 'C:\\dl' }, 'A3-19 / A5-47 Windows case', async (app) => {
    const { page } = app;
    await openFilesTab(page);
    await openDual(page);
    await page.evaluate(() => { window.__d = queueDownloads('t1', ['/home/u/Readme.md']); });
    yes('A3-19 a download that differs only in case from a local file asks first on Windows',
      await waitVisible(page, '#conflictModal'));
    check('A5-47 every conflicting file starts on Skip',
      await page.evaluate(() => [...document.querySelectorAll('#conflictList input[type="radio"]:checked')].map((r) => r.value)), ['skip']);
    yes('A5-47 Cancel has the focus', await focusIs(page, 'conflictCancelBtn'));
    await page.keyboard.press('Enter');
    await settle(page, 200);
    yes('A5-47 a reflexive Enter cancels the batch', !(await app.open('conflictModal')));
    check('A5-47 and nothing is queued', await queueAdds(app), []);
    check('no page errors', app.errors, []);
  });

  await withFiles(browser, server, { remote, local: { '/home/me/dl': ['README.md'] }, home: '/home/me/dl' }, 'A3-19 Linux case', async (app) => {
    const { page } = app;
    await openFilesTab(page);
    await openDual(page);
    await page.evaluate(() => queueDownloads('t1', ['/home/u/Readme.md']));
    await settle(page, 300);
    yes('a Linux folder keeps Readme.md and README.md apart (no prompt)', !(await app.open('conflictModal')));
    check('and the download is queued', (await queueAdds(app)).map((a) => a.items.map((i) => i.remote)), [['/home/u/Readme.md']]);
    check('no page errors', app.errors, []);
  });

  await withFiles(browser, server, { remote, local: HOME_ONLY }, 'conflict dialog missing', async (app) => {
    const { page } = app;
    await openFilesTab(page, { tab: { sftpPath: '/srv' } });
    await page.evaluate(() => document.getElementById('conflictModal').remove());
    await page.evaluate(() => queueUploads('t1', [{ local: '/tmp/a.txt', remote: '/srv/a.txt' }]));
    await settle(page, 200);
    check('with the conflict dialog missing nothing is overwritten', await queueAdds(app), []);
    yes('and the user is told the transfer was cancelled', (await toasts(page)).some((t) => /cancel/i.test(t)));
    check('no page errors', app.errors, []);
  });
}

/// A3-20: the permissions dialog.
async function scenarioChmod(browser, server) {
  const remote = { '/srv': ['shared/', 'other/', 'a.txt', 'b.sh', 'nostat.txt'] };
  const modes = { '/srv/shared': 0o42775, '/srv/other': 0o40755, '/srv/a.txt': 0o100644, '/srv/b.sh': 0o100755 };
  await withFiles(browser, server, { remote, modes, local: HOME_ONLY }, 'A3-20 chmod dialog', async (app) => {
    const { page } = app;
    await openFilesTab(page, { tab: { sftpPath: '/srv' } });
    const open = async (paths) => {
      await page.evaluate((p) => openChmodDialog('t1', p, { name: p[0].split('/').pop() }), paths);
      await waitVisible(page, '#chmodModal');
      await settle(page, 150);
    };
    const lastChmod = async () => (await app.calls('sftp_chmod')).map((c) => c.args);
    const apply = async () => { await page.click('#chmodApplyBtn'); await settle(page, 200); };

    await open(['/srv/shared']);
    check('A3-20 setuid/setgid/sticky bits show in the numeric value', await page.inputValue('#chmodOctal'), '2775');
    yes('A3-20 the dialog says that three typed digits clear them', /three digits/i.test(await page.textContent('#chmodModal')));
    await apply();
    check('A3-20 and are kept when applying', (await lastChmod()).pop().mode, 0o2775);

    // Recursive: the backend applies ONE mode to everything it walks, so the
    // folder's setgid must reach the folders only, never the files.
    let since = (await lastChmod()).length;
    await open(['/srv/shared']);
    await page.click('#chmodModal label:has(#chmodRecurse)'); // the input itself takes no pointer events
    await apply();
    // Folders first: that call is what restores traversal of a tree the owner
    // cannot enter (a 2664 folder), so the files call can then reach the files.
    check('A3-20 a recursive chmod gives setgid to the folders, then plain bits to the files',
      (await lastChmod()).slice(since).map((a) => [a.path, a.mode, a.recursive, a.applyTo]),
      [['/srv/shared', 0o2775, true, 'dirs'], ['/srv/shared', 0o775, true, 'files']]);

    since = (await lastChmod()).length;
    await open(['/srv/shared']);
    await page.click('#chmodModal label:has(#chmodRecurse)');
    await page.selectOption('#chmodApplyTo', 'files');
    await apply();
    check('A3-20 files only: no special bits at all',
      (await lastChmod()).slice(since).map((a) => [a.mode, a.recursive, a.applyTo]), [[0o775, true, 'files']]);
    await open(['/srv/other']);
    check('A3-20 Recurse starts unticked every time', await page.isChecked('#chmodRecurse'), false);
    check('A3-20 and Apply-to starts at files and directories', await page.inputValue('#chmodApplyTo'), 'all');
    await apply();
    const last = (await lastChmod()).pop();
    check('A3-20 so a later chmod is not silently recursive', { recursive: last.recursive, applyTo: last.applyTo }, { recursive: false, applyTo: 'all' });

    const before = (await lastChmod()).length;
    await open(['/srv/a.txt', '/srv/b.sh']);
    check('A3-20 with mixed modes an owner-execute box is indeterminate',
      await page.evaluate(() => document.getElementById('chmod-owner-x').indeterminate), true);
    await apply();
    check('A3-20 applying untouched mixed bits keeps each file\'s own mode',
      (await lastChmod()).slice(before).map((a) => [a.path, a.mode]), [['/srv/a.txt', 0o644], ['/srv/b.sh', 0o755]]);

    await open(['/srv/nostat.txt']);
    check('A3-20 when the current mode cannot be read, Apply is disabled instead of offering 644',
      await page.evaluate(() => document.getElementById('chmodApplyBtn').disabled), true);
    yes('A3-20 and the dialog says why', /Permission denied/.test(await page.textContent('#chmodModal')));
    await page.keyboard.press('Escape');

    await page.evaluate(() => {
      window.__replies.sftp_chmod = { ok: true, changed: 3, failed: ['/srv/shared/x: Permission denied'], failedCount: 1, skippedLinks: 0 };
    });
    await open(['/srv/shared']);
    await page.click('#chmodModal label:has(#chmodRecurse)'); // the input itself takes no pointer events
    await apply();
    // Two calls (folders, then files), each reporting 3 changed and 1 refused.
    yes('a partly failed recursive chmod is reported as a failure, with the reason',
      (await toasts(page)).includes('6 updated, 2 failed: /srv/shared/x: Permission denied'), JSON.stringify(await toasts(page)));
    check('no page errors', app.errors, []);
  });

  // A server that leaves the file-type bits out of the mode: the type comes
  // from the listing instead (a folder is split, a file never is).
  await withFiles(browser, server, { remote, modes: { '/srv/shared': 0o2775, '/srv/b.sh': 0o4755 }, local: HOME_ONLY },
    'A3-20 chmod without type bits', async (app) => {
      const { page } = app;
      await openFilesTab(page, { tab: { sftpPath: '/srv' } });
      const sent = async (n) => (await app.calls('sftp_chmod')).slice(n).map((c) => [c.args.path, c.args.mode, c.args.recursive, c.args.applyTo]);
      const recursiveApply = async (p) => {
        await page.evaluate((x) => openChmodDialog('t1', [x], { name: x.split('/').pop() }), p);
        await waitVisible(page, '#chmodModal');
        await settle(page, 150);
        await page.click('#chmodModal label:has(#chmodRecurse)');
        await page.click('#chmodApplyBtn');
        await settle(page, 200);
      };
      let n = await app.count('sftp_chmod');
      await recursiveApply('/srv/shared');
      check('A3-20 a folder whose type the server did not report is still split, folders first',
        await sent(n), [['/srv/shared', 0o2775, true, 'dirs'], ['/srv/shared', 0o775, true, 'files']]);
      n = await app.count('sftp_chmod');
      await recursiveApply('/srv/b.sh');
      check('A3-20 a setuid file is never split: it keeps its own bits', await sent(n), [['/srv/b.sh', 0o4755, true, 'all']]);
      check('no page errors', app.errors, []);
    });
}

/// One job as the queue snapshot carries it (sftp/queue.rs TransferJob::snapshot).
const JOB = (id, name, state, extra) => Object.assign({
  id, kind: 'download', sessionId: 'sess-t1', serverId: 'srv-t1', serverName: 'host-t1',
  localPath: '/home/me/' + name, remotePath: '/home/u/' + name, size: 1000, bytesDone: 0,
  state, error: null, speed: null, targetSessionId: null, targetServerName: null,
  targetServerId: null, attempts: 0, retryAt: null, verify: false,
}, extra || {});
const emitJobs = (page, jobs) => page.evaluate((j) => window.__emit('sftp-queue', { jobs: j }), jobs);
const queueRowNames = (page) => page.evaluate(() =>
  [...document.querySelectorAll('#sftpQueueList .sftp-queueitem .q-name')].map((n) => n.textContent.trim()));
const showQueueTab = async (page, t) => { await page.click(`.sftp-queuetab[data-tab="${t}"]`); await settle(page, 80); };

/// A3-02 / A3-03 / A3-12 / A3-33 / A3-21 / A3-34: the transfer queue panel.
async function scenarioQueue(browser, server) {
  const spec = { remote: { '/home/u': ['a.txt'] }, local: HOME_ONLY };

  await withFiles(browser, server, spec, 'A3-02 no list loop', async (app) => {
    const { page } = app;
    await openFilesTab(page);
    await settle(page, 200);
    check('A3-02 the queue snapshot is asked for once when the queue is wired', await app.count('sftp_queue_list'), 1);
    const before = await app.count('sftp_queue_list');
    await showQueueTab(page, 'done');
    await settle(page, 600);
    const afterTab = (await app.count('sftp_queue_list')) - before;
    yes('A3-02 showing the Done tab of an empty queue asks at most once', afterTab <= 1, `${afterTab} sftp_queue_list calls`);
    const before2 = await app.count('sftp_queue_list');
    await page.click('#sftpQueuePanel .sftp-queueactions-head button:has-text("Clear finished")');
    await settle(page, 600);
    const afterClear = (await app.count('sftp_queue_list')) - before2;
    yes('A3-02 Clear finished on an empty queue does not start a loop either', afterClear <= 1, `${afterClear} sftp_queue_list calls`);
    check('no page errors', app.errors, []);
  });

  await withFiles(browser, server, spec, 'A3-03 rows patched in place', async (app) => {
    const { page } = app;
    await openFilesTab(page);
    await emitJobs(page, [JOB(7, 'big.iso', 'active', { bytesDone: 100, speed: 2048 })]);
    await settle(page);
    await page.evaluate(() => { window.__row = document.querySelector('#sftpQueueList .sftp-queueitem'); });
    await emitJobs(page, [JOB(7, 'big.iso', 'active', { bytesDone: 300, speed: 2048 })]);
    await settle(page, 60);
    check('A3-03 a progress event updates the row in place (same element)',
      await page.evaluate(() => document.querySelector('#sftpQueueList .sftp-queueitem') === window.__row), true);
    yes('A3-03 with the new numbers', /300 B \/ 1000 B/.test(await page.textContent('#sftpQueueList .sftp-queueitem')));
    const box = await page.locator('#sftpQueueList .sftp-queueitem button[title="Cancel"]').boundingBox();
    await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
    await page.mouse.down();
    for (let i = 1; i <= 3; i++) {
      await emitJobs(page, [JOB(7, 'big.iso', 'active', { bytesDone: 300 + i * 100, speed: 2048 })]);
      await page.waitForTimeout(60);
    }
    await page.mouse.up();
    await settle(page);
    check('A3-03 a Cancel click held across progress events reaches the queue',
      (await app.calls('sftp_queue_cancel')).map((c) => c.args), [{ jobId: 7 }]);
    // The list's structure changing under the press (another job arriving)
    // must not detach the row either.
    const pause = await page.locator('#sftpQueueList .sftp-queueitem button[title="Pause"]').boundingBox();
    await page.mouse.move(pause.x + pause.width / 2, pause.y + pause.height / 2);
    await page.mouse.down();
    await emitJobs(page, [JOB(70, 'zz-late.bin', 'queued')]);
    await page.waitForTimeout(60);
    await emitJobs(page, [JOB(7, 'big.iso', 'active', { bytesDone: 800, speed: 2048 })]);
    await page.waitForTimeout(60);
    await page.mouse.up();
    await settle(page);
    check('A3-03 a Pause click held while another job arrives reaches the queue',
      (await app.calls('sftp_queue_pause')).map((c) => c.args), [{ jobId: 7 }]);
    check('and the new job is listed after it', await queueRowNames(page), ['big.iso', 'zz-late.bin']);
    // Every state still renders, in the right tab.
    await emitJobs(page, [JOB(7, 'big.iso', 'paused', { bytesDone: 600 })]);
    await settle(page);
    // This tab has no live shell, so Resume is the disabled "Reconnect to ..."
    // form (scenario A3-21 covers a connected server).
    check('a paused row offers Resume and Cancel',
      await page.evaluate(() => [...document.querySelectorAll('#sftpQueueList .sftp-queueitem')]
        .filter((r) => r.querySelector('.q-name').textContent.trim() === 'big.iso')
        .flatMap((r) => [...r.querySelectorAll('button')])
        .map((b) => (/^(Resume$|Reconnect)/.test(b.title) ? 'resume' : b.title))),
      ['resume', 'Cancel']);
    await emitJobs(page, [JOB(7, 'big.iso', 'failed', { bytesDone: 600, error: 'connection reset' })]);
    await settle(page);
    check('a failed job leaves the Queued tab', (await queueRowNames(page)).includes('big.iso'), false);
    await showQueueTab(page, 'failed');
    check('and shows under Failed', await queueRowNames(page), ['big.iso']);
    await emitJobs(page, [JOB(8, 'small.txt', 'done', { bytesDone: 1000 })]);
    await showQueueTab(page, 'done');
    check('a finished job shows under Done', await queueRowNames(page), ['small.txt']);
    await page.click('#sftpQueuePanel .sftp-queueactions-head button:has-text("Clear finished")');
    await settle(page);
    check('Clear finished empties Done', await queueRowNames(page), []);
    await showQueueTab(page, 'failed');
    check('and Failed', await queueRowNames(page), []);
    check('no page errors', app.errors, []);
  });

  await withFiles(browser, server, spec, 'A3-12 long queue', async (app) => {
    const { page } = app;
    await openFilesTab(page);
    const jobs = [JOB(1, 'ACTIVE-ONE.bin', 'active', { bytesDone: 500 }), JOB(2, 'ACTIVE-TWO.bin', 'active', { bytesDone: 500 })];
    for (let i = 0; i < 150; i++) jobs.push(JOB(100 + i, `queued-${String(i).padStart(3, '0')}.bin`, 'queued'));
    await emitJobs(page, jobs);
    await settle(page, 200);
    const names = await queueRowNames(page);
    yes('A3-12 the running jobs are listed however long the queue is', names.includes('ACTIVE-ONE.bin') && names.includes('ACTIVE-TWO.bin'));
    yes('A3-12 so are the next ones to run', names.includes('queued-000.bin'));
    yes('A3-12 the list stays bounded', names.length <= 100, `${names.length} rows`);
    const moreText = () => page.evaluate(() =>
      [...document.querySelectorAll('#sftpQueueList > :not(.sftp-queueitem):not(.sftp-queuegroup)')].map((n) => n.textContent).join(' | '));
    yes('A3-12 and says how many it left out', /\+ 52 more\b/.test(await moreText()), await moreText());
    check('no page errors', app.errors, []);
  });

  await withFiles(browser, server, spec, 'A3-12 many paused jobs', async (app) => {
    const { page } = app;
    await openFilesTab(page);
    const jobs = [JOB(1, 'ACTIVE-ONE.bin', 'active', { bytesDone: 500 })];
    for (let i = 0; i < 300; i++) jobs.push(JOB(200 + i, `paused-${String(i).padStart(3, '0')}.bin`, 'paused', { bytesDone: 10 }));
    await emitJobs(page, jobs);
    await settle(page, 300);
    const names = await queueRowNames(page);
    yes('A3-12 the running job is listed beside hundreds of paused ones', names.includes('ACTIVE-ONE.bin'));
    yes('A3-12 paused jobs count against the row cap too (Pause all, a restart)', names.length <= 100, `${names.length} rows`);
    yes('A3-12 and the ones left out are counted', /\+ 201 more\b/.test(await page.textContent('#sftpQueueList')),
      await page.evaluate(() => [...document.querySelectorAll('#sftpQueueList .sftp-queuemore')].map((n) => n.textContent).join(' | ')));
    check('no page errors', app.errors, []);
  });

  // Paused jobs only run after Resume: they are the tail. The next job to run
  // must stay visible (and cancellable) however many are paused.
  await withFiles(browser, server, spec, 'A3-12 queued jobs behind many paused ones', async (app) => {
    const { page } = app;
    await openFilesTab(page);
    const jobs = [JOB(1, 'ACTIVE-ONE.bin', 'active', { bytesDone: 500 })];
    for (let i = 0; i < 150; i++) jobs.push(JOB(300 + i, `paused-${String(i).padStart(3, '0')}.bin`, 'paused', { bytesDone: 10 }));
    for (let i = 0; i < 3; i++) jobs.push(JOB(600 + i, `queued-${String(i).padStart(3, '0')}.bin`, 'queued'));
    await emitJobs(page, jobs);
    await settle(page, 300);
    const names = await queueRowNames(page);
    yes('A3-12 the next job to run is listed even behind 150 paused ones', names.includes('queued-000.bin'));
    yes('A3-12 so are the other queued jobs', ['queued-001.bin', 'queued-002.bin'].every((n) => names.includes(n)));
    yes('A3-12 the paused ones are the tail that is cut', /\+ 54 more\b/.test(await page.textContent('#sftpQueueList')) && names.length <= 100,
      `${names.length} rows`);
    check('no page errors', app.errors, []);
  });

  await withFiles(browser, server, spec, 'A3-03 queued to active', async (app) => {
    const { page } = app;
    await openFilesTab(page);
    const cancelButton = () => page.evaluate(() => {
      const row = [...document.querySelectorAll('#sftpQueueList .sftp-queueitem')]
        .find((r) => r.querySelector('.q-name').textContent.trim() === 'later.bin');
      const b = row && row.querySelector('button[title="Cancel"]');
      if (!window.__cancelBtn) window.__cancelBtn = b;
      return !!b && b === window.__cancelBtn;
    });
    await emitJobs(page, [JOB(80, 'later.bin', 'queued')]);
    await settle(page);
    yes('a queued job offers Cancel', await cancelButton());
    await emitJobs(page, [JOB(80, 'later.bin', 'active', { bytesDone: 1, speed: 100 })]);
    await settle(page);
    check('A3-03 a queued job that starts keeps its Pause/Cancel buttons (a click on them survives)',
      await cancelButton(), true);
    check('no page errors', app.errors, []);
  });

  await withFiles(browser, server, spec, 'A3-33 cancelled jobs', async (app) => {
    const { page } = app;
    await openFilesTab(page);
    await emitJobs(page, [JOB(40, 'half.iso', 'cancelled', { bytesDone: 400 })]);
    await settle(page);
    await showQueueTab(page, 'failed');
    check('A3-33 a cancelled job is listed under Failed', await queueRowNames(page), ['half.iso']);
    yes('A3-33 the summary counts it', /cancelled/.test(await page.textContent('#sftpQueueSummary')),
      await page.textContent('#sftpQueueSummary'));
    await page.click('#sftpQueueList .sftp-queueitem button[title="Retry"]');
    await settle(page);
    check('A3-33 and its Retry button works', (await app.calls('sftp_queue_retry')).map((c) => c.args), [{ jobId: 40 }]);
    await emitJobs(page, [JOB(41, 'broken.bin', 'failed', { error: 'disk full' })]);
    await settle(page);
    yes('A3-33 the summary counts failed and cancelled jobs together',
      /1 failed/.test(await page.textContent('#sftpQueueSummary')) && /1 cancelled/.test(await page.textContent('#sftpQueueSummary')),
      await page.textContent('#sftpQueueSummary'));
    check('no page errors', app.errors, []);
  });

  await withFiles(browser, server, spec, 'A3-21 resumable by server', async (app) => {
    const { page } = app;
    await openLiveTab(app); // server s1, a live shell with a NEW session id
    await openFilesTab(page);
    await emitJobs(page, [JOB(31, 'restored.iso', 'paused', {
      sessionId: 'OLD-SESSION', serverId: 's1', serverName: 'web-1', bytesDone: 400, error: 'Restored from a previous session',
    })]);
    await settle(page);
    const resume = '#sftpQueueList .sftp-queueitem button[title="Resume"]';
    yes('A3-21 a paused job of a connected server can be resumed although its old session is gone',
      await page.evaluate((s) => { const b = document.querySelector(s); return !!b && !b.disabled; }, resume));
    yes('A3-21 the reconnect banner stays hidden', await page.evaluate(() => document.getElementById('sftpQueueRestoredBanner').hidden));
    await page.click(resume);
    await settle(page);
    check('A3-21 Resume goes to the backend, which rebinds the session', (await app.calls('sftp_queue_resume')).map((c) => c.args), [{ jobId: 31 }]);
    await page.click('#sftpQueuePanel .sftp-queueactions-head button:has-text("Resume all")');
    await settle(page);
    check('Resume all is one sftp_queue_resume_all call', await app.count('sftp_queue_resume_all'), 1);
    await emitJobs(page, [JOB(32, 'elsewhere.iso', 'paused', { sessionId: 'OLD-2', serverId: 'srv-gone', serverName: 'gone-1' })]);
    await settle(page);
    check('A3-21 a job whose server is not connected waits for a reconnect',
      await page.evaluate(() => [...document.querySelectorAll('#sftpQueueList .sftp-queueitem')]
        .filter((r) => r.textContent.includes('elsewhere.iso'))
        .map((r) => { const b = r.querySelector('button[title^="Reconnect"]'); return !!b && b.disabled; })), [true]);
    yes('and the banner says so', await page.evaluate(() => !document.getElementById('sftpQueueRestoredBanner').hidden));
    check('no page errors', app.errors, []);
  });

  await withFiles(browser, server, spec, 'A3-34 queue log and speed', async (app) => {
    const { page } = app;
    await openFilesTab(page);
    for (let i = 0; i < 4; i++) {
      await emitJobs(page, [JOB(50, 'broken.bin', 'failed', { error: 'disk full' })]);
      await settle(page, 40);
    }
    check('A3-34 a failed job is logged once, not once per snapshot',
      await page.evaluate(() => state.sessions.get('t1').log.filter((l) => /transfer failed/.test(l)).length), 1);
    await emitJobs(page, [JOB(51, 'fast.bin', 'active', { bytesDone: 10, size: 1e9, speed: 10 * 1024 * 1024 })]);
    await showQueueTab(page, 'queued');
    check('A3-34 a fast transfer shows its speed in MB/s',
      await page.evaluate(() => [...document.querySelectorAll('#sftpQueueList .sftp-queueitem')]
        .filter((r) => r.textContent.includes('fast.bin')).map((r) => r.querySelector('.q-speed').textContent.trim())), ['10.0 MB/s']);
    yes('A3-34 so does the summary', /10\.0 MB\/s/.test(await page.textContent('#sftpQueueSummary')), await page.textContent('#sftpQueueSummary'));
    check('no page errors', app.errors, []);
  });
}

/// The whole text of a field is selected (what Ctrl+A in a text field means).
const allSelected = (page, id) => page.evaluate((i) => {
  const n = document.getElementById(i);
  return n.value.length > 0 && n.selectionStart === 0 && n.selectionEnd === n.value.length;
}, id);
const collapseSelection = (page, id) => page.evaluate((i) => document.getElementById(i).setSelectionRange(1, 1), id);

/// A5-46 and the chords leftover: the SFTP shortcuts act on the file list only.
async function scenarioShortcuts(browser, server) {
  const spec = { remote: { '/home/u': ['a.txt', 'b.txt'] }, local: { '/home/me': ['l1.txt'] } };

  await withFiles(browser, server, spec, 'A5-46 Ctrl+A in text fields', async (app) => {
    const { page } = app;
    await openFilesTab(page);
    const selected = () => tabField(page, 'sftpSelected');
    await page.evaluate(() => editRemotePath('t1'));
    await focusIs(page, 'sftpPath-t1');
    await collapseSelection(page, 'sftpPath-t1');
    await page.keyboard.press('Control+A');
    yes('A5-46 Ctrl+A in the path field selects its text', await allSelected(page, 'sftpPath-t1'));
    check('A5-46 and leaves the files alone', await selected(), []);
    await page.keyboard.press('Escape');
    await page.evaluate(() => promptModal('Rename', 'New name:', 'a.log', () => {}));
    await focusIs(page, 'promptInput');
    await collapseSelection(page, 'promptInput');
    await page.keyboard.press('Control+A');
    yes('A5-46 Ctrl+A in the rename prompt selects the name', await allSelected(page, 'promptInput'));
    check('A5-46 not the files behind it', await selected(), []);
    await page.keyboard.press('Escape');
    await page.evaluate(() => switchView('keys'));
    await page.fill('#searchInput', 'abc');
    await collapseSelection(page, 'searchInput');
    await page.keyboard.press('Control+A');
    yes('A5-46 Ctrl+A in the Keys search box selects its text', await allSelected(page, 'searchInput'));
    check('A5-46 the hidden file list is untouched', await selected(), []);
    await page.fill('#searchInput', '');
    await page.evaluate(() => switchView('connect'));
    await settle(page);
    await page.click('#sftpTbody-t1 tr.sftp-entry[data-name="a.txt"]');
    await page.keyboard.press('Control+A');
    check('Ctrl+A in the file list still selects every file', await selected(), ['a.txt', 'b.txt']);
    check('no page errors', app.errors, []);
  });

  await withFiles(browser, server, spec, 'SFTP chords behind dialogs', async (app) => {
    const { page } = app;
    await openFilesTab(page);
    await openDual(page);
    const cmpWrites = async () => (await app.calls('settings_set')).filter((c) => c.args.key === 'sftpCmpMode').length;
    const syncOn = () => page.evaluate(() => document.querySelector('#sftpPanel-t1 .sftp-sync-btn').classList.contains('active'));
    await page.evaluate(() => { window.__answer = confirmModal('Sure?', 'Something else is being asked', 'OK'); });
    await focusIs(page, 'confirmCancelBtn');
    await page.keyboard.press('Control+Y');
    await page.keyboard.press('Control+Shift+B');
    await page.keyboard.press('Control+A');
    await settle(page);
    check('Ctrl+Y does not toggle comparison behind a dialog', await cmpWrites(), 0);
    check('Ctrl+Shift+B does not toggle synchronized browsing behind a dialog', await syncOn(), false);
    check('Ctrl+A selects no files behind a dialog', await tabField(page, 'sftpSelected'), []);
    yes('the dialog is still up', await app.open('confirmModal'));
    await page.keyboard.press('Escape');
    await page.evaluate(() => switchView('keys'));
    await page.evaluate(() => document.activeElement && document.activeElement.blur());
    await page.keyboard.press('Control+Y');
    await settle(page);
    check('A3-22 Ctrl+Y does nothing while the Files view is not on screen', await cmpWrites(), 0);
    await page.evaluate(() => switchView('connect'));
    await page.evaluate(() => document.activeElement && document.activeElement.blur());
    await page.keyboard.press('Control+Y');
    await page.keyboard.press('Control+Shift+B');
    await settle(page);
    check('with nothing in the way Ctrl+Y works', await cmpWrites(), 1);
    check('and so does Ctrl+Shift+B', await syncOn(), true);
    check('no page errors', app.errors, []);
  });

  await withFiles(browser, server, spec, 'A3-22 OS file drops', async (app) => {
    const { page } = app;
    await openFilesTab(page);
    yes('the window drop handler is registered', await page.evaluate(() => typeof window.__dragDrop === 'function'));
    const drop = (paths) => page.evaluate((p) => window.__dragDrop({ payload: { type: 'drop', paths: p, position: { x: 5, y: 5 } } }), paths);
    const lists = () => app.count('sftp_list_dir');
    await page.evaluate(() => switchView('keys'));
    const before = await lists();
    await drop(['C:\\Users\\u\\.ssh\\id_ed25519']);
    await settle(page, 300);
    check('A3-22 a file dropped while Keys is on screen is not uploaded', await queueAdds(app), []);
    check('A3-22 not even checked for a conflict', (await lists()) - before, 0);
    await page.evaluate(() => switchView('connect'));
    await page.evaluate(() => promptModal('Rename', 'New name:', 'x', () => {}));
    await drop(['C:\\Users\\u\\.ssh\\id_ed25519']);
    await settle(page, 300);
    check('A3-22 nor while a dialog is open', await queueAdds(app), []);
    await page.keyboard.press('Escape');
    await drop(['C:\\Users\\u\\report.pdf']);
    await settle(page, 300);
    check('a drop onto the visible file list uploads to its folder',
      (await queueAdds(app)).map((a) => a.items.map((i) => [i.local, i.remote])), [[['C:\\Users\\u\\report.pdf', '/home/u/report.pdf']]]);
    check('no page errors', app.errors, []);
  });
}

/// A3-37: a transfer finishing on a background tab refreshes it when it returns.
async function scenarioBackgroundTab(browser, server) {
  const spec = { remote: { '/up': [], '/home/u': [] }, local: HOME_ONLY };
  await withFiles(browser, server, spec, 'A3-37 background tab', async (app) => {
    const { page } = app;
    await openFilesTab(page, { tabId: 'tB', tab: { sftpPath: '/up' } });
    check('tab B starts empty', await rowNames(page, 'tB'), []);
    await openFilesTab(page, { tabId: 'tA', tab: { mode: 'ssh' } });
    await page.evaluate(() => { window.__fs.remote['/up'] = [window.__fs.entry('big-upload.iso')]; });
    await emitJobs(page, [JOB(60, 'big-upload.iso', 'done', { kind: 'upload', sessionId: 'sess-tB', serverId: 'srv-tB', remotePath: '/up/big-upload.iso', bytesDone: 1000 })]);
    await page.waitForTimeout(1800); // longer than the transfer-done ticker
    await page.evaluate(() => activateSessionSurface('tB'));
    await settle(page, 300);
    check('A3-37 returning to the tab shows the file its background transfer delivered', await rowNames(page, 'tB'), ['big-upload.iso']);
    check('no page errors', app.errors, []);
  });
}

/// Task 10 contract: searches carry ids; a stale or superseded walk is ignored.
async function scenarioSearch(browser, server) {
  const spec = { remote: { '/home/u': ['etc/'] }, local: HOME_ONLY };
  await withFiles(browser, server, spec, 'search ids', async (app) => {
    const { page } = app;
    await openFilesTab(page);
    await page.click('#sftpPanel-t1 .sftp-toolbar button[title^="Search"]');
    const search = async (q) => {
      await page.fill('#sftpSearchInput-t1', q);
      await page.press('#sftpSearchInput-t1', 'Enter');
      await settle(page);
      return (await app.calls('sftp_search')).pop().args;
    };
    const ev = (p) => page.evaluate((x) => window.__emit('sftp-search', Object.assign({ sessionId: 'sess-t1' }, x)), p);
    const resultCount = () => page.evaluate(() => document.querySelectorAll('#sftpSearchResults-t1 .sftp-searchitem').length);
    const s1 = await search('conf');
    yes('a search sends an id', typeof s1.searchId === 'string' && s1.searchId.length > 0, JSON.stringify(s1));
    const s2 = await search('nginx');
    yes('the next search gets a new id', typeof s2.searchId === 'string' && s2.searchId !== s1.searchId);
    check('and the previous walk is cancelled', (await app.calls('sftp_search_cancel')).map((c) => c.args),
      [{ sessionId: 'sess-t1', searchId: s1.searchId }]);
    await ev({ searchId: s1.searchId, done: true, cancelled: true, matched: 0, scanned: 3, capped: false });
    await ev({ searchId: s1.searchId, done: false, path: '/home/u/etc/old.conf', name: 'old.conf', isDir: false });
    await settle(page, 60);
    check('a stale walk\'s results and summary are ignored', { rows: await resultCount(), status: await page.textContent('#sftpSearchStatus-t1') },
      { rows: 0, status: 'Searching...' });
    await ev({ searchId: s2.searchId, done: false, path: '/home/u/etc/nginx/nginx.conf', name: 'nginx.conf', isDir: false });
    await ev({ searchId: s2.searchId, done: true, cancelled: false, matched: 1, scanned: 9, capped: false });
    await settle(page, 60);
    check('the current walk\'s results show once', await resultCount(), 1);
    yes('with its summary', /^1 match/.test(await page.textContent('#sftpSearchStatus-t1')), await page.textContent('#sftpSearchStatus-t1'));
    // A3-34: a double Enter (key repeat: both before either search got going)
    // must not leave two listeners behind.
    await page.fill('#sftpSearchInput-t1', 'host');
    await page.evaluate(() => {
      const input = document.getElementById('sftpSearchInput-t1');
      for (let i = 0; i < 2; i++) input.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true, cancelable: true }));
    });
    await settle(page);
    const s4 = (await app.calls('sftp_search')).pop().args;
    await ev({ searchId: s4.searchId, done: false, path: '/home/u/etc/hosts', name: 'hosts', isDir: false });
    await settle(page, 60);
    check('A3-34 a double Enter still renders each result once', await resultCount(), 1);
    check('no page errors', app.errors, []);
  });
}

/// Task 10 contract: edit-in-editor reports every sync; editing can be stopped.
async function scenarioEditSync(browser, server) {
  const spec = { remote: { '/home/u': ['app.conf'] }, local: HOME_ONLY };
  await withFiles(browser, server, spec, 'edit sync', async (app) => {
    const { page } = app;
    await openFilesTab(page);
    await page.evaluate(() => {
      window.__replies.sftp_open_for_edit = { ok: true, localPath: 'C:\\stage\\app.conf.txt', remote: '/home/u/app.conf' };
    });
    await rowEvent(page, 'contextmenu', 'app.conf');
    await clickMenuItem(page, 'Open with system app');
    await settle(page, 200);
    const sync = (p) => page.evaluate((x) => window.__emit('sftp-edit-sync', Object.assign({ sessionId: 'sess-t1', remote: '/home/u/app.conf' }, x)), p);
    await sync({ ok: false, error: 'Permission denied' });
    await settle(page);
    yes('a failed save-back is reported with its reason',
      (await toasts(page)).some((t) => /app\.conf/.test(t) && /Permission denied/.test(t)), JSON.stringify(await toasts(page)));
    await sync({ ok: true });
    await settle(page);
    yes('a successful one is confirmed', (await toasts(page)).some((t) => /app\.conf/.test(t) && /saved/i.test(t)), JSON.stringify(await toasts(page)));
    await rowEvent(page, 'contextmenu', 'app.conf');
    yes('the file being edited offers Stop editing', (await menuItems(page) || []).includes('Stop editing'));
    await clickMenuItem(page, 'Stop editing');
    await settle(page);
    check('which ends the sync', (await app.calls('sftp_close_edit')).map((c) => c.args), [{ sessionId: 'sess-t1', remote: '/home/u/app.conf' }]);
    await rowEvent(page, 'contextmenu', 'app.conf');
    check('and is gone from the menu afterwards', (await menuItems(page) || []).includes('Stop editing'), false);
    check('no page errors', app.errors, []);
  });
}

/// A3-34: quick-find Backspace, and a download does not rewrite the layout.
async function scenarioListDetails(browser, server) {
  const spec = { remote: { '/home/u': ['alpha.txt', 'alps.txt', 'beta.txt'] }, local: HOME_ONLY };
  await withFiles(browser, server, spec, 'A3-34 quick-find and layout', async (app) => {
    const { page } = app;
    await openFilesTab(page);
    await page.click('#sftpTbody-t1 tr.sftp-entry[data-name="alpha.txt"]');
    await page.keyboard.type('alx');
    await settle(page, 60);
    check('a typo filters everything away', await rowNames(page), []);
    await page.keyboard.press('Backspace');
    await settle(page, 60);
    check('A3-34 Backspace takes the last character back off the filter', await rowNames(page), ['alpha.txt', 'alps.txt']);
    await page.keyboard.press('Escape');
    await settle(page, 60);
    check('Escape clears it', await rowNames(page), ['alpha.txt', 'alps.txt', 'beta.txt']);
    check('no page errors', app.errors, []);
  });

  await withFiles(browser, server, spec, 'A3-34 download and the layout', async (app) => {
    const { page } = app;
    await openFilesTab(page);
    await rowEvent(page, 'dblclick', 'beta.txt');
    await settle(page, 900);
    check('the download is queued', (await queueAdds(app)).length, 1);
    check('A3-34 opening the local pane for a download does not save the layout preference',
      (await app.calls('settings_set')).filter((c) => c.args.key === 'sftpDualPane').length, 0);
    // Task 10: sftp_queue_add reports what it skipped or renamed.
    await page.evaluate(() => {
      window.__replies.sftp_queue_add = (a) => ({ ok: true, added: a.items.length,
        warnings: ['Skipped symbolic link /home/u/alps.txt', 'Renamed alps.txt to alps (1).txt'] });
    });
    await rowEvent(page, 'dblclick', 'alps.txt');
    await settle(page, 400);
    yes('what the queue skipped or renamed is shown', (await toasts(page)).some((t) => /Skipped symbolic link/.test(t)),
      JSON.stringify(await toasts(page)));
    check('and every warning is logged', await page.evaluate(() =>
      state.sessions.get('t1').log.filter((l) => /Skipped symbolic link|Renamed alps/.test(l)).length), 2);
    check('no page errors', app.errors, []);
  });
}

/// A3-01 / A5-40 / A1-04: what the panel offers, wired to a panel the app built.
async function scenarioPanel(browser, server) {
  const spec = { remote: { '/home/u': ['docs/', 'a.txt'], '/home/u/docs': [] }, local: { '/home/me': ['l1.txt', 'l2.txt'] } };
  await withFiles(browser, server, spec, 'A3-01 / A5-40 panel controls', async (app) => {
    const { page } = app;
    await openFilesTab(page);
    const ts = await page.evaluate(() => { const b = document.getElementById('sftpPreserveTsBtn-t1'); return b ? b.textContent.trim() : null; });
    yes('A3-01 the preserve-timestamps toggle is on the toolbar of a panel built by the app', ts !== null);
    yes('A3-01 and says what it is in words', !!ts && /time/i.test(ts), ts);
    if (ts !== null) await page.click('#sftpPreserveTsBtn-t1');
    check('A3-01 the toggle saves the preference',
      (await app.calls('settings_set')).filter((c) => c.args.key === 'sftpPreserveTs').map((c) => c.args.value), ['1']);
    await page.evaluate(() => {
      const row = [...document.querySelectorAll('#sftpTbody-t1 tr.sftp-entry')].find((r) => r.dataset.name === 'docs');
      const dt = new DataTransfer();
      dt.setData('text/sftp-local', JSON.stringify({ tabId: 't1', path: '/home/me/l1.txt', name: 'l1.txt', isDir: false }));
      row.dispatchEvent(new DragEvent('drop', { dataTransfer: dt, bubbles: true, cancelable: true }));
    });
    await settle(page, 300);
    check('A3-01 a local file dropped on a remote folder row is uploaded into that folder',
      (await queueAdds(app)).map((a) => a.items), [[{ local: '/home/me/l1.txt', remote: '/home/u/docs/l1.txt', resume: 'overwrite' }]]);
    await rowEvent(page, 'dblclick', 'a.txt');
    await settle(page, 900);
    check('A3-01 a download then keeps the remote timestamps', (await queueAdds(app)).pop().preserveTs, true);

    const uploadBtn = await page.evaluate(() => {
      const b = [...document.querySelectorAll('#sftpPanel-t1 .sftp-toolbar button')].find((x) => /^upload/i.test(x.textContent.trim()));
      return b ? b.textContent.trim() : null;
    });
    yes('A5-40 the toolbar has an Upload button', uploadBtn !== null, uploadBtn);
    check('Upload for a tab that is gone does nothing (no exception)',
      await page.evaluate(() => { try { sftpUploadSelected('no-such-tab'); return 'ok'; } catch (e) { return String(e); } }), 'ok');
    const clickUpload = () => page.evaluate(() =>
      [...document.querySelectorAll('#sftpPanel-t1 .sftp-toolbar button')].find((x) => /^upload/i.test(x.textContent.trim())).click());
    await rowEvent(page, 'click', 'l1.txt', { local: true });
    await rowEvent(page, 'click', 'l2.txt', { local: true, init: { ctrlKey: true } });
    const adds = (await queueAdds(app)).length;
    if (uploadBtn !== null) await clickUpload();
    await settle(page, 300);
    check('A5-40 Upload sends the files selected in the local pane to the remote folder',
      (await queueAdds(app)).slice(adds).map((a) => a.items.map((i) => [i.local, i.remote])),
      [[['/home/me/l1.txt', '/home/u/l1.txt'], ['/home/me/l2.txt', '/home/u/l2.txt']]]);
    await page.evaluate(() => document.querySelector('#sftpLocalPane-t1 .sftp-tablewrap').dispatchEvent(new MouseEvent('click', { bubbles: true })));
    if (uploadBtn !== null) await clickUpload();
    await settle(page);
    yes('A5-40 with nothing selected it explains where to pick files', (await toasts(page)).some((t) => /local/i.test(t) && /select/i.test(t)),
      JSON.stringify(await toasts(page)));
    await page.evaluate(() => document.querySelector('#sftpPanel-t1 .sftp-remote .sftp-tablewrap')
      .dispatchEvent(new MouseEvent('contextmenu', { bubbles: true, cancelable: true, clientX: 600, clientY: 600 })));
    await settle(page, 60);
    check('A5-40 right-clicking empty space in the remote list opens a folder menu', await menuItems(page),
      ['Upload...', 'New folder...', 'New file...', 'Refresh']);
    await clickMenuItem(page, 'New folder...');
    yes('A5-40 whose New folder asks for a name', await waitVisible(page, '#promptModal'));
    check('in the remote folder', await page.textContent('#promptTitle'), 'New folder');
    await page.keyboard.press('Escape');
    check('no page errors', app.errors, []);
  });

  await withFiles(browser, server, spec, 'A1-04 menus stay on screen', async (app) => {
    const { page } = app;
    await openFilesTab(page);
    await openDual(page);
    const onScreen = () => page.evaluate(() => {
      const m = document.getElementById('keyConnectMenu');
      if (!m) return 'no menu';
      const r = m.getBoundingClientRect();
      return r.left >= 0 && r.top >= 0 && r.right <= window.innerWidth && r.bottom <= window.innerHeight;
    });
    await page.evaluate(() => openSftpFileMenu(window.innerWidth - 4, window.innerHeight - 4, 't1', state.sessions.get('t1')._entryMap.get('a.txt')));
    check('A1-04 the remote file menu opened in the corner stays on screen', await onScreen(), true);
    await page.evaluate(() => openSftpLocalMenu(window.innerWidth - 4, window.innerHeight - 4, 't1', null));
    check('A1-04 so does the local pane menu', await onScreen(), true);
    await page.evaluate(() => document.querySelector('#sftpPanel-t1 .sftp-remote .sftp-tablewrap').dispatchEvent(
      new MouseEvent('contextmenu', { bubbles: true, cancelable: true, clientX: window.innerWidth - 4, clientY: window.innerHeight - 4 })));
    await settle(page, 60);
    check('A1-04 and the empty-space folder menu', await onScreen(), true);
    await page.evaluate(() => {
      const b = document.createElement('button');
      b.id = 'cornerAnchor';
      b.style.cssText = 'position:fixed; right:0; bottom:0; width:40px; height:20px';
      document.body.appendChild(b);
      return openBookmarkMenu({ currentTarget: b }, 't1');
    });
    await settle(page, 60);
    check('A1-04 and the bookmarks menu anchored at the bottom edge', await onScreen(), true);
    check('no page errors', app.errors, []);
  });
}

// ─── runner ─────────────────────────────────────────────────────────────────

const SCENARIOS = [
  ['navigation: transactional, sequenced, breadcrumb, dot segments (A3-04 A3-09 A3-15 A3-16)', scenarioNavigation],
  ['selection: only what is on screen in this folder (A3-05)', scenarioSelection],
  ['focus: refreshes do not steal it (A3-07)', scenarioFocus],
  ['local pane: Windows paths, listing errors, delete prompts (A3-17 A3-18 A3-29)', scenarioLocalPane],
  ['conflicts: free names, case, safe defaults, fail closed (A3-06 A3-19 A5-47)', scenarioConflicts],
  ['chmod dialog (A3-20)', scenarioChmod],
  ['transfer queue (A3-02 A3-03 A3-12 A3-21 A3-33 A3-34)', scenarioQueue],
  ['shortcuts and OS drops (A5-46 A3-22)', scenarioShortcuts],
  ['background tabs (A3-37)', scenarioBackgroundTab],
  ['search ids (Task 10 contract, A3-34)', scenarioSearch],
  ['edit-in-editor sync (Task 10 contract)', scenarioEditSync],
  ['list details (A3-34)', scenarioListDetails],
  ['panel controls and menus (A3-01 A5-40 A1-04)', scenarioPanel],
];

(async () => {
  const only = process.argv.includes('--only') ? process.argv[process.argv.indexOf('--only') + 1] : null;
  const server = await serve(rendererDir());
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
    console.error(`\n${failures.length} SFTP check(s) failed.`);
    process.exit(1);
  }
  console.log('\nAll SFTP checks passed.');
})().catch((e) => { console.error(e); process.exit(1); });
