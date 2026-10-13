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
 *     search ids and edit-in-editor sync reporting;
 * and (unit JU6b):
 *   - the layout at 880x560, 1100x720 and 1600x1000: rows on screen with an
 *     empty queue, a queue whose actions stay reachable, Split inside its
 *     column, the toolbar's More menu, working splitters, single-line rows;
 *   - pointer-event drag and drop (HTML5 drops never reach the page on
 *     Windows - A3-23), Escape to cancel, and the menu alternatives;
 *   - one sftp_open per tab, the edit-conflict prompt, settings that revert
 *     when they cannot be saved, caches dropped for the folder that changed.
 *
 * Run with `npm run test:sftp`. Needs playwright (see check-renderer-ui.js);
 * without it this skips with exit 0. `--only <text>` runs the scenarios whose
 * title contains <text>; SSHSPAN_RENDERER_DIR points the run at another copy
 * of the renderer (a pristine `git archive` of an older commit, to watch these
 * checks fail where they should).
 */
'use strict';

const {
  failures, check, yes, loadChromium, rendererDir, serve, part, PASSWORD, pauseClockAhead,
  withApp, waitVisible, focusIs, openLiveTab, toasts, hold, letGo, emulateWindowsDragDrop, mouseDrag,
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

/// The Dual button, or - where the toolbar folds it away (A5-07: secondary
/// buttons go into More on a narrow panel) - the same action from More.
const openDual = async (page, tabId) => {
  const t = tabId || 't1';
  const btn = page.locator(`#sftpPanel-${t} .sftp-toolbar button[title="Toggle local pane"]`);
  if (await btn.isVisible()) {
    await btn.click();
  } else {
    await page.click(`#sftpPanel-${t} .sftp-more-btn`);
    await clickMenuItem(page, 'Show local pane');
  }
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
    // The option is the app's toggle chip (A1-33): the box itself is hidden,
    // the chip is what is clicked.
    await page.click('#deleteModal .toggle-chip');
    yes('the opt-out is ticked', await page.isChecked('#deleteSkipSession'));
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

  // A server that leaves the file-type bits out of the mode. sftp_chmod walks
  // only a path its own stat calls a folder; anything else gets a root-only
  // change whatever applyTo says. So the folders-then-files split would set
  // the full mode and then the plain bits on the SAME path, stripping the
  // special bits that were meant to stay: one full-mode call instead, whatever
  // the listing says the path is.
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
      check('A3-20 a folder whose type the server did not report gets ONE full-mode call (its special bits stay)',
        await sent(n), [['/srv/shared', 0o2775, true, 'all']]);
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
    // An empty queue shows the panel's header alone (JU6b, A1-01), so the tabs
    // and "Clear finished" are not on screen: their handlers are run directly,
    // which is what the loop came from.
    const clickHidden = (sel) => page.evaluate((s) => document.querySelector(s).click(), sel);
    check('(JU6b) an empty queue is collapsed to its header', await page.evaluate(() =>
      document.getElementById('sftpQueuePanel').classList.contains('empty')), true);
    const before = await app.count('sftp_queue_list');
    await clickHidden('.sftp-queuetab[data-tab="done"]');
    await settle(page, 600);
    const afterTab = (await app.count('sftp_queue_list')) - before;
    yes('A3-02 showing the Done tab of an empty queue asks at most once', afterTab <= 1, `${afterTab} sftp_queue_list calls`);
    const before2 = await app.count('sftp_queue_list');
    await clickHidden('#sftpQueuePanel .sftp-queueactions-head button:last-child');
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
    // Dragged with the mouse (Task 16): the HTML5 drop this test used to fire
    // never reaches the page on Windows (A3-23), so the drop is a pointer one.
    await emulateWindowsDragDrop(page);
    await openDual(page);
    await mouseDrag(page, '#sftpLocalTbody-t1 tr.sftp-entry[data-name="l1.txt"]', '#sftpTbody-t1 tr.sftp-entry[data-name="docs"]');
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
    // Upload opens the native picker for several files and queues the picks
    // into the folder on screen with one call (A5-40, JU5); the per-file
    // report and the refusals are pinned in check-servers-ui.js.
    const clickUpload = () => page.evaluate(() =>
      [...document.querySelectorAll('#sftpPanel-t1 .sftp-toolbar button')].find((x) => /^upload/i.test(x.textContent.trim())).click());
    await page.evaluate(() => {
      window.__replies.system_pick_files = { canceled: false, paths: ['/home/me/l1.txt', '/home/me/l2.txt'] };
    });
    const adds = (await queueAdds(app)).length;
    if (uploadBtn !== null) await clickUpload();
    await settle(page, 300);
    check('A5-40 Upload asks for files with the native picker', (await app.calls('system_pick_files')).map((c) => c.args.multiple), [true]);
    check('A5-40 and sends the picked files to the remote folder in one batch',
      (await queueAdds(app)).slice(adds).map((a) => a.items.map((i) => [i.local, i.remote])),
      [[['/home/me/l1.txt', '/home/u/l1.txt'], ['/home/me/l2.txt', '/home/u/l2.txt']]]);
    await page.evaluate(() => { window.__replies.system_pick_files = { canceled: true, paths: [] }; });
    const before = (await queueAdds(app)).length;
    if (uploadBtn !== null) await clickUpload();
    await settle(page);
    check('A5-40 a cancelled pick uploads nothing', (await queueAdds(app)).length, before);
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

// ─── JU6b: layout (A1-01 A5-07 A1-02 A1-03) ─────────────────────────────────

const MANY = (n) => Array.from({ length: n }, (_, i) => `file-${String(i).padStart(2, '0')}.txt`);
const LONG_NAME = 'a-really-long-file-name-that-goes-on-and-on-and-on-and-on-and-on-and-on-forever.tar.gz';
const LAYOUT_SPEC = {
  remote: { '/home/u': ['docs/', 'src/', LONG_NAME, ...MANY(27)], '/home/u/docs': ['in-docs.txt'] },
  local: { '/home/me': ['Documents/', 'l1.txt', 'l2.txt'] },
};
const LAYOUT_JOBS = [
  JOB(1, 'big-backup.tar.gz', 'active', { bytesDone: 400000, size: 1000000, speed: 204800 }),
  JOB(2, 'next-in-line.txt', 'queued'),
  JOB(3, 'held.iso', 'paused', { bytesDone: 10000, error: 'Paused by you' }),
];
/// The toolbar buttons More takes over on a narrow panel (A5-07).
const SECONDARY = ['Show/hide permissions & owner columns', 'Toggle local pane', 'Activity log'];

/// Measured rects of the file surface (CSS px). Rows count as visible when
/// they sit wholly inside the list, below its sticky header.
const layoutOf = (page, tabId) => page.evaluate((t) => {
  const R = (n) => (n ? n.getBoundingClientRect() : null);
  const panel = document.getElementById('sftpPanel-' + t);
  const wrap = panel.querySelector('.sftp-remote .sftp-tablewrap');
  const wr = R(wrap);
  const head = wrap.querySelector('thead');
  const headH = head ? R(head).height : 0;
  const rows = [...wrap.querySelectorAll('tr.sftp-entry')].map(R);
  const body = document.getElementById('sftpBody');
  const q = document.getElementById('sftpQueuePanel');
  const list = document.getElementById('sftpQueueList');
  const lr = R(list);
  const acts = [...document.querySelectorAll('#sftpQueueList .sftp-queueitem .q-act')];
  const firstBtn = acts.length ? acts[0].querySelector('button') : null;
  // The list scrolls vertically - in a small window the first job can sit
  // below its fold (under the server and folder rows and a reconnect note).
  // What A1-02 is about is that, once scrolled to, nothing covers its buttons
  // and they are not off to the side - so the list is scrolled down only,
  // never sideways.
  if (firstBtn && list) {
    const below = firstBtn.getBoundingClientRect().bottom - list.getBoundingClientRect().bottom;
    if (below > 0) list.scrollTop += Math.ceil(below);
  }
  const fb = R(firstBtn);
  const topAt = fb ? document.elementFromPoint(fb.left + fb.width / 2, fb.top + fb.height / 2) : null;
  const surface = document.getElementById('sessionSurface');
  const col = document.querySelector('.terminal-col');
  const panes = panel.querySelector('.sftp-panes');
  const shownPanes = [...panes.children].filter((c) => c.getClientRects().length > 0);
  const summary = document.getElementById('sftpQueueSummary');
  const lineH = summary ? parseFloat(getComputedStyle(summary).lineHeight) || 16 : 16;
  // A row counts when it is wholly on screen: inside the list below its
  // header, and inside the panel's own box (the panel scrolls when even the
  // list's floor does not fit - a row below that fold is not on screen).
  const pr = R(panel);
  const top = Math.max(wr.top + headH, pr.top);
  const bottom = Math.min(wr.bottom, pr.bottom, innerHeight);
  return {
    visibleRows: rows.filter((b) => b.height > 0 && b.top >= top - 1 && b.bottom <= bottom + 1).length,
    panelOverflowY: panel.scrollHeight - panel.clientHeight,
    summaryW: summary && summary.getClientRects().length ? Math.round(R(summary).width) : null,
    bodyH: Math.round(R(body).height),
    bodyOverflowX: body.scrollWidth - body.clientWidth,
    queueH: q && q.getClientRects().length ? Math.round(R(q).height) : null,
    queueOverflowX: list && list.getClientRects().length ? list.scrollWidth - list.clientWidth : 0,
    actsInside: acts.length > 0 && acts.every((a) => {
      const r = R(a);
      return r.width > 0 && r.right <= innerWidth && r.left >= lr.left - 1 && r.right <= lr.right + 1;
    }),
    firstActOnTop: !!(firstBtn && topAt && firstBtn.contains(topAt)),
    // For a failure note: where the button is, the list's box, what is on top.
    firstAct: fb ? [Math.round(fb.top), Math.round(fb.bottom)] : null,
    list: lr ? [Math.round(lr.top), Math.round(lr.bottom)] : null,
    onTop: topAt ? `${topAt.tagName.toLowerCase()}.${String(topAt.className && topAt.className.baseVal !== undefined ? topAt.className.baseVal : topAt.className).split(' ').join('.')}` : null,
    summaryLines: summary && summary.textContent ? Math.round(R(summary).height / lineH) : 0,
    surfaceOverflowX: surface.scrollWidth - surface.clientWidth,
    bodyRight: Math.round(R(body).right),
    colRight: Math.round(R(col).right),
    panesW: Math.round(R(panes).width),
    panesSum: Math.round(shownPanes.reduce((s, c) => s + R(c).width, 0)),
  };
}, tabId || 't1');

/// The toolbar as seen: which buttons show, on how many rows, and More.
const toolbarOf = (page, tabId) => page.evaluate((t) => {
  const bar = document.querySelector(`#sftpPanel-${t} .sftp-toolbar`);
  const shown = [...bar.querySelectorAll('button')].filter((b) => b.getClientRects().length > 0);
  const more = bar.querySelector('.sftp-more-btn');
  return {
    titles: shown.map((b) => b.title),
    rows: new Set(shown.map((b) => Math.round(b.getBoundingClientRect().top))).size,
    more: !!more && more.getClientRects().length > 0,
    moreLast: !!more && shown[shown.length - 1] === more,
  };
}, tabId || 't1');

/// Put a Files tab into Split (as setSessionMode does once SFTP is open).
const toSplit = (page, tabId) => page.evaluate((t) => {
  state.sessions.get(t).mode = 'split';
  activateSessionSurface(t);
}, tabId || 't1');

async function scenarioLayout(browser, server) {
  for (const [w, h, minRows] of [[880, 560, 3], [1100, 720, 5], [1600, 1000, 5]]) {
    const at = `${w}x${h}`;
    await withFiles(browser, server, LAYOUT_SPEC, `A1-01 / A1-02 / A1-03 layout at ${at}`, async (app) => {
      const { page } = app;
      await page.setViewportSize({ width: w, height: h });
      await openFilesTab(page);
      await settle(page, 250);
      let m = await layoutOf(page);
      yes(`A1-01 ${at}: with an empty queue the file list shows at least ${minRows} whole rows`, m.visibleRows >= minRows, JSON.stringify(m));
      yes(`A1-01 ${at}: the empty transfer panel is collapsed to its header`, m.queueH !== null && m.queueH <= 48, JSON.stringify(m));
      yes(`A1-02 ${at}: the SFTP body does not scroll sideways`, m.bodyOverflowX <= 0, JSON.stringify(m));

      await emitJobs(page, LAYOUT_JOBS);
      await settle(page, 200);
      m = await layoutOf(page);
      yes(`A1-01 ${at}: the panel opens for the first job`, m.queueH !== null && m.queueH > 70, JSON.stringify(m));
      yes(`A1-01 ${at}: and takes at most about 35% of the surface`, m.queueH <= m.bodyH * 0.35 + 2, JSON.stringify(m));
      yes(`A1-02 ${at}: every job's Pause/Cancel/Retry sits inside the window and the list`, m.actsInside, JSON.stringify(m));
      yes(`A1-02 ${at}: the first job's buttons are not covered`, m.firstActOnTop, JSON.stringify(m));
      yes(`A1-02 ${at}: the job list does not scroll sideways`, m.queueOverflowX <= 0, JSON.stringify(m));
      check(`A1-02 ${at}: the summary stays on one line`, m.summaryLines, 1);
      yes(`A1-02 ${at}: still no sideways scroll of the SFTP body`, m.bodyOverflowX <= 0, JSON.stringify(m));
      // With jobs listed the file list keeps its floor too (review L5): at
      // 880x560 it was down to one row. Two there - a third would leave the
      // job list no room for a job (the checks above) - three above it.
      const jobRows = w === 880 ? 2 : 3;
      yes(`L5 ${at}: with jobs listed the file list still shows at least ${jobRows} whole rows`, m.visibleRows >= jobRows, JSON.stringify(m));
      yes(`L5 ${at}: and the file panel needs no scrolling of its own`, m.panelOverflowY <= 1, JSON.stringify(m));

      await openDual(page);
      m = await layoutOf(page);
      yes(`A1-15 ${at}: the two panes and the splitter fill the pane area exactly`, Math.abs(m.panesSum - m.panesW) <= 1, JSON.stringify(m));
      yes(`A1-02 ${at}: no sideways scroll with both panes`, m.bodyOverflowX <= 0, JSON.stringify(m));

      await toSplit(page);
      await settle(page, 250);
      m = await layoutOf(page);
      yes(`A1-03 ${at}: Split stays inside its column`, m.surfaceOverflowX <= 0 && m.bodyRight <= m.colRight + 1, JSON.stringify(m));
      yes(`A1-02 ${at}: no sideways scroll of the SFTP body in Split`, m.bodyOverflowX <= 0, JSON.stringify(m));
      // Review L4: in Split the summary was squeezed to about one character.
      yes(`L4 ${at}: in Split the transfer summary keeps a readable width (6em or more)`, m.summaryW !== null && m.summaryW >= 66, JSON.stringify(m));
      check(`L4 ${at}: and stays on one line`, m.summaryLines, 1);
      check('no page errors', app.errors, []);
    });
  }

  await withFiles(browser, server, LAYOUT_SPEC, 'A5-07 the toolbar folds into More', async (app) => {
    const { page } = app;
    await page.setViewportSize({ width: 1100, height: 720 });
    await openFilesTab(page);
    await settle(page, 200);
    let tb = await toolbarOf(page);
    check('A5-07 at 1100x720 the toolbar is a single row', tb.rows, 1);
    check('A5-07 the secondary buttons are folded away', tb.titles.filter((x) => SECONDARY.includes(x)), []);
    check('A5-07 into a More button, last on the row', [tb.more, tb.moreLast], [true, true]);
    await page.click('#sftpPanel-t1 .sftp-more-btn');
    await settle(page, 80);
    const labels = (await menuItems(page)) || [];
    // Each item says what choosing it does now (review L6: "Compare
    // directories off" read as the action that turns it off).
    check('A5-07 More offers what was folded away, each as the action it takes', labels.map((l) => l.replace(/\s+/g, ' ')), [
      'Hide permissions and owner', 'Show local pane', 'Show activity log', 'Compare directories by size', 'Turn on synchronized browsing']);
    check('the More button says its menu is open', await page.getAttribute('#sftpPanel-t1 .sftp-more-btn', 'aria-expanded'), 'true');
    await clickMenuItem(page, 'Show local pane');
    await settle(page, 250);
    check('A5-07 an action chosen from More does what its button does', await tabField(page, 'dualPane'), true);
    await page.click('#sftpPanel-t1 .sftp-more-btn');
    await settle(page, 80);
    check('the menu follows the state it toggles', ((await menuItems(page)) || []).filter((l) => /local pane/.test(l)), ['Hide local pane']);
    await clickMenuItem(page, 'Show activity log');
    await settle(page, 80);
    check('Show activity log opens the log', await page.evaluate(() => document.getElementById('sftpLog-t1').hidden), false);
    await page.click('#sftpPanel-t1 .sftp-more-btn');
    await settle(page, 80);
    await clickMenuItem(page, 'Turn on synchronized browsing');
    await settle(page, 80);
    await page.click('#sftpPanel-t1 .sftp-more-btn');
    await settle(page, 80);
    await clickMenuItem(page, 'Compare directories by size');
    await settle(page, 80);
    await page.click('#sftpPanel-t1 .sftp-more-btn');
    await settle(page, 80);
    check('L6 once on, the items offer the next step', ((await menuItems(page)) || []).slice(3).map((l) => l.replace(/\s+/g, ' ')),
      ['Compare directories by modified time', 'Turn off synchronized browsing']);
    await page.keyboard.press('Escape');

    await page.setViewportSize({ width: 1600, height: 1000 });
    await settle(page, 200);
    tb = await toolbarOf(page);
    check('A5-07 with room for them the secondary buttons are back and More is gone',
      [SECONDARY.every((x) => tb.titles.includes(x)), tb.more], [true, false]);
    check('no page errors', app.errors, []);
  });
}

// ─── JU6b: splitters (A1-15) ────────────────────────────────────────────────

const separatorOf = (page, sel) => page.evaluate((s) => {
  const n = document.querySelector(s);
  if (!n) return null;
  return {
    role: n.getAttribute('role'), orientation: n.getAttribute('aria-orientation'), tabIndex: n.tabIndex,
    label: !!n.getAttribute('aria-label'), now: n.getAttribute('aria-valuenow') === null ? null : Number(n.getAttribute('aria-valuenow')),
    min: n.getAttribute('aria-valuemin'), max: n.getAttribute('aria-valuemax'),
  };
}, sel);

async function scenarioSplitters(browser, server) {
  await withFiles(browser, server, LAYOUT_SPEC, 'A1-15 the dual-pane splitter', async (app) => {
    const { page } = app;
    await page.setViewportSize({ width: 1600, height: 1000 });
    await openFilesTab(page);
    await openDual(page);
    const sp = '#sftpSplitter-t1';
    const widths = () => page.evaluate(() => {
      const r = (s) => document.querySelector(s).getBoundingClientRect().width;
      const panes = document.querySelector('#sftpPanel-t1 .sftp-panes');
      return {
        local: Math.round(r('#sftpLocalPane-t1')), splitter: Math.round(r('#sftpSplitter-t1')),
        remote: Math.round(r('#sftpPanel-t1 .sftp-remote')), panes: Math.round(panes.getBoundingClientRect().width),
        overflow: panes.scrollWidth - panes.clientWidth,
      };
    });
    const fits = (w) => Math.abs(w.local + w.splitter + w.remote - w.panes) <= 2 && w.overflow <= 0;
    const s0 = await separatorOf(page, sp);
    check('A1-15 the splitter is a separator the keyboard can reach',
      s0 && [s0.role, s0.orientation, s0.tabIndex, s0.label, s0.now !== null], ['separator', 'vertical', 0, true, true]);
    const w0 = await widths();
    yes('A1-15 at rest the panes fill the row exactly', fits(w0), JSON.stringify(w0));
    const box = await page.locator(sp).boundingBox();
    await mouseDrag(page, sp, { x: box.x + box.width / 2 + 200, y: box.y + box.height / 2 });
    await settle(page, 80);
    const w1 = await widths();
    yes('A1-15 dragging it right widens the local pane', w1.local > w0.local + 150, JSON.stringify([w0, w1]));
    yes('A1-15 and the remote pane takes exactly what is left (one percentage)', fits(w1), JSON.stringify(w1));
    const s1 = await separatorOf(page, sp);
    yes('A1-15 aria-valuenow follows the drag', s1.now > s0.now, JSON.stringify([s0, s1]));
    await mouseDrag(page, sp, { x: box.x - 900, y: box.y + box.height / 2 });
    await settle(page, 80);
    const w2 = await widths();
    yes('A1-15 a drag far past the edge stops at a minimum width', w2.local >= w2.panes * 0.19 && fits(w2), JSON.stringify(w2));
    await page.focus(sp);
    const k0 = (await separatorOf(page, sp)).now;
    await page.keyboard.press('ArrowRight');
    await page.keyboard.press('ArrowRight');
    const k1 = (await separatorOf(page, sp)).now;
    yes('A1-15 ArrowRight moves it', k1 > k0, JSON.stringify([k0, k1]));
    await page.keyboard.press('ArrowLeft');
    const k2 = (await separatorOf(page, sp)).now;
    yes('A1-15 ArrowLeft moves it back', k2 < k1, JSON.stringify([k1, k2]));
    yes('A1-15 and the panes still fill the row', fits(await widths()), JSON.stringify(await widths()));
    check('no page errors', app.errors, []);
  });

  for (const [w, h] of [[1100, 720], [1600, 1000]]) {
    await withFiles(browser, server, LAYOUT_SPEC, `A1-15 the terminal/files splitter at ${w}x${h}`, async (app) => {
      const { page } = app;
      await page.setViewportSize({ width: w, height: h });
      await openFilesTab(page);
      await toSplit(page);
      await settle(page, 200);
      const sp = '#surfaceSplitter';
      const termW = () => page.evaluate(() => Math.round(document.getElementById('terminalBody').getBoundingClientRect().width));
      const s0 = await separatorOf(page, sp);
      check('A1-15 the Split splitter is a separator the keyboard can reach',
        s0 && [s0.role, s0.orientation, s0.tabIndex, s0.label, s0.now !== null], ['separator', 'vertical', 0, true, true]);
      const t0 = await termW();
      const box = await page.locator(sp).boundingBox();
      await mouseDrag(page, sp, { x: box.x + box.width / 2 - 100, y: box.y + box.height / 2 });
      await settle(page, 120);
      const t1 = await termW();
      yes('A1-15 dragging it left narrows the terminal', t1 < t0 - 60, JSON.stringify([t0, t1]));
      const s1 = await separatorOf(page, sp);
      yes('A1-15 aria-valuenow follows', s1.now < s0.now, JSON.stringify([s0, s1]));
      let m = await layoutOf(page);
      yes('A1-03 and Split still fits its column', m.surfaceOverflowX <= 0 && m.bodyRight <= m.colRight + 1, JSON.stringify(m));
      await mouseDrag(page, sp, { x: box.x + 2000, y: box.y + box.height / 2 });
      await settle(page, 120);
      m = await layoutOf(page);
      yes('A1-03 a drag far right stops before the file browser is squeezed out', m.surfaceOverflowX <= 0 && m.bodyRight <= m.colRight + 1, JSON.stringify(m));
      await page.focus(sp);
      const k0 = (await separatorOf(page, sp)).now;
      await page.keyboard.press('ArrowLeft');
      await page.keyboard.press('ArrowLeft');
      await settle(page, 80);
      const k1 = (await separatorOf(page, sp)).now;
      yes('A1-15 ArrowLeft moves it from the keyboard', k1 < k0, JSON.stringify([k0, k1]));
      check('no page errors', app.errors, []);
    });
  }
}

// ─── JU6b: table cells, styles, dialog bits (A1-16 A1-17 A1-31 A1-28 A1-34) ─

async function scenarioTableCells(browser, server) {
  const LINK = (name) => ({ name, isDir: false, isLink: true, size: 0, modifiedMs: 1700000000000, permissions: 0o120777, uid: 0, gid: 0 });
  const spec = {
    remote: { '/home/u': ['docs/', LONG_NAME, 'notes.txt', LINK('current'), LINK('dangling')], '/srv': ['a.txt'] },
    local: { '/home/me': ['Documents/', 'l1.txt'] },
  };
  await withFiles(browser, server, spec, 'A1-16 / A1-17 / A1-31 rows and their cells', async (app) => {
    const { page } = app;
    await page.setViewportSize({ width: 1100, height: 720 });
    await openFilesTab(page);
    await settle(page, 150);
    const cells = await page.evaluate((longName) => {
      const rows = [...document.querySelectorAll('#sftpTbody-t1 tr.sftp-entry')];
      const row = rows.find((r) => r.dataset.name === longName);
      const td = row.querySelector('td');
      const name = td.querySelector('.sftp-name');
      const cs = (n) => getComputedStyle(n);
      return {
        display: cs(td).display,
        wrapper: !!td.querySelector('.sftp-namewrap'),
        title: name ? name.title : null,
        clip: name ? [cs(name).whiteSpace, cs(name).textOverflow, cs(name).overflowX] : null,
        nowrap: [...new Set([...row.querySelectorAll('td')].slice(1).map((c) => cs(c).whiteSpace))],
        heights: [...new Set(rows.map((r) => Math.round(r.getBoundingClientRect().height)))],
      };
    }, LONG_NAME);
    check('A1-16 the name cell stays a table cell', cells.display, 'table-cell');
    check('A1-16 icon and name sit in a nested wrapper', cells.wrapper, true);
    check('A1-16 a long name is cut with an ellipsis and shown whole on hover', [cells.title, cells.clip], [LONG_NAME, ['nowrap', 'ellipsis', 'hidden']]);
    check('A1-16 size, modified, permissions and owner never wrap', cells.nowrap, ['nowrap']);
    yes('A1-16 every row is one line of the same height', cells.heights.length === 1 && cells.heights[0] <= 40, JSON.stringify(cells.heights));

    const badge = (name) => page.evaluate((n) => {
      const i = document.querySelector(`#sftpTbody-t1 tr[data-name="${n}"] .sftp-eicon`);
      const a = getComputedStyle(i, '::after');
      return { content: a.content, display: a.display, color: a.color };
    }, name);
    const linkBadge = await badge('current');
    yes('A1-17 a symbolic link carries a visible badge', !['none', 'normal'].includes(linkBadge.content) && linkBadge.display !== 'none', JSON.stringify(linkBadge));
    check('A1-17 a plain file does not', (await badge('notes.txt')).content, 'none');
    await page.evaluate(() => {
      window.__replies.sftp_resolve_link = (a) => (a.path.endsWith('/dangling') ? { ok: true, broken: true } : { ok: true, broken: false, isDir: true });
    });
    await rowEvent(page, 'dblclick', 'dangling');
    await settle(page, 150);
    const brokenBadge = await badge('dangling');
    yes('A1-17 a broken link looks different from a working one',
      !['none', 'normal'].includes(brokenBadge.content) && (brokenBadge.color !== linkBadge.color || brokenBadge.content !== linkBadge.content),
      JSON.stringify([linkBadge, brokenBadge]));

    await hold(page, 'sftp_dir_size');
    await rowEvent(page, 'contextmenu', 'docs');
    await clickMenuItem(page, 'Calculate size');
    await settle(page, 80);
    const spin = await page.evaluate(() => {
      const s = document.querySelector('#sftpTbody-t1 tr[data-name="docs"] .sftp-spinner');
      if (!s) return null;
      const c = getComputedStyle(s);
      const r = s.getBoundingClientRect();
      return { w: Math.round(r.width), h: Math.round(r.height), animation: c.animationName, border: c.borderTopStyle };
    });
    yes('A1-17 a folder being sized shows a turning spinner', !!spin && spin.w >= 8 && spin.h >= 8 && spin.animation !== 'none' && spin.border !== 'none', JSON.stringify(spin));
    await letGo(page, 'sftp_dir_size');
    await settle(page, 80);

    const wrapH = () => page.evaluate(() => Math.round(document.querySelector('#sftpPanel-t1 .sftp-remote .sftp-tablewrap').getBoundingClientRect().height));
    const h0 = await wrapH();
    await page.click('#sftpTbody-t1 tr.sftp-entry[data-name="notes.txt"]');
    await page.keyboard.type('not');
    await settle(page, 80);
    const qf = await page.evaluate(() => {
      const q = document.getElementById('sftpQuickFind-t1');
      const c = getComputedStyle(q);
      const alpha = (c.backgroundColor.match(/rgba?\(([^)]+)\)/) || [])[1];
      const parts = alpha ? alpha.split(',').map((x) => x.trim()) : [];
      return { shown: !q.hidden && q.getClientRects().length > 0, position: c.position, opaque: parts.length === 3 || (parts.length === 4 && Number(parts[3]) === 1), text: q.textContent };
    });
    check('A1-17 the quick-find indicator is shown over the pane, opaque', [qf.shown, qf.position, qf.opaque], [true, 'absolute', true]);
    check('A1-17 and takes no room from the list', await wrapH(), h0);
    await page.keyboard.press('Escape');

    await openDual(page);
    const local = await page.evaluate(() => ({
      head: document.querySelectorAll('#sftpLocalPane-t1 thead th').length,
      shownHead: [...document.querySelectorAll('#sftpLocalPane-t1 thead th')].filter((th) => th.getClientRects().length > 0).length,
      cells: [...new Set([...document.querySelectorAll('#sftpLocalTbody-t1 tr.sftp-entry')].map((r) => r.children.length))],
    }));
    check('A1-31 the local table has only the columns its rows fill (with Columns on)', [local.head, local.shownHead, local.cells], [3, 3, [3]]);
    check('no page errors', app.errors, []);
  });

  await withFiles(browser, server, spec, 'A1-28(c) / A1-34 dialog close buttons and the search box', async (app) => {
    const { page } = app;
    await openFilesTab(page, { tab: { sftpPath: '/srv' } });
    await page.evaluate(() => { window.__q = queueUploads('t1', [{ local: '/tmp/a.txt', remote: '/srv/a.txt' }]); });
    await waitVisible(page, '#conflictModal');
    const close = await page.evaluate(() => {
      const b = document.getElementById('conflictCloseBtn');
      return { icon: !!b.querySelector('svg'), label: b.getAttribute('aria-label') };
    });
    check('A1-28(c) the conflict dialog\'s close button shows its icon and has a name', close, { icon: true, label: 'Close' });
    await page.click('#conflictCloseBtn');
    await settle(page, 150);
    check('and closing it that way cancels the batch', [await app.open('conflictModal'), (await queueAdds(app)).length], [false, 0]);

    await page.evaluate(() => { window.__fs.modes['/srv/a.txt'] = 0o100644; openChmodDialog('t1', ['/srv/a.txt'], { name: 'a.txt' }); });
    await waitVisible(page, '#chmodModal');
    check('the permissions dialog\'s X has a name', await page.getAttribute('#chmodModal .modal-header .icon-btn', 'aria-label'), 'Close');
    await page.click('#chmodModal .modal-header .icon-btn');
    await settle(page, 80);
    check('and closes the dialog', await app.open('chmodModal'), false);

    await page.click('#sftpPanel-t1 .sftp-toolbar button[title^="Search"]');
    const box = await page.evaluate(() => {
      const i = document.getElementById('sftpSearchInput-t1');
      const described = (i.getAttribute('aria-describedby') || '').split(/\s+/).filter(Boolean);
      return {
        label: !!(i.getAttribute('aria-label') || (i.labels && i.labels.length)),
        spellcheck: i.spellcheck, autocomplete: i.getAttribute('autocomplete'),
        described: described.length > 0 && described.every((id) => !!document.getElementById(id)),
      };
    });
    check('A1-34 the search box has a name, a hint and no spellcheck or autofill', box,
      { label: true, spellcheck: false, autocomplete: 'off', described: true });
    check('no page errors', app.errors, []);
  });
}

// ─── JU6b: pointer drag and drop (Task 16, A3-23, SC 2.5.7) ─────────────────

const DND_SPEC = {
  remote: { '/home/u': ['docs/', 'a.txt', 'b.txt'], '/home/u/docs': [] },
  local: { '/home/me': ['Downloads/', 'l1.txt'], '/home/me/Downloads': [] },
};
const remoteRow = (n) => `#sftpTbody-t1 tr.sftp-entry[data-name="${n}"]`;
const localRow = (n) => `#sftpLocalTbody-t1 tr.sftp-entry[data-name="${n}"]`;
/// What a drag shows while it is held: the ghost, where it is, what is lit.
const dragView = (page, at) => page.evaluate((p) => {
  const g = document.querySelector('.drag-ghost');
  const r = g && g.getBoundingClientRect();
  return {
    ghost: g ? g.textContent : null,
    near: !!r && Math.abs(r.left - p.x) < 80 && Math.abs(r.top - p.y) < 80,
    rows: [...document.querySelectorAll('tr.sftp-entry.drop-target')].map((t) => t.dataset.name),
    panes: [...document.querySelectorAll('.sftp-pane.drag-over')].map((t) => (t.classList.contains('sftp-local') ? 'local' : 'remote')),
  };
}, at);
const dragLeftovers = (page) => page.evaluate(() =>
  document.querySelectorAll('.drag-ghost, .drop-target, .drag-over, .sftp-dragging').length);
/// A text as read, without the bidi isolates (U+2068 ... U+2069) a name is
/// wrapped in inside a sentence.
const plain = (s) => String(s || '').replace(/[\u2068\u2069]/g, '');
/// The centre of a row, for a press or release made by hand.
const centre = async (page, sel) => {
  const b = await page.locator(sel).boundingBox();
  return { x: b.x + b.width / 2, y: b.y + b.height / 2 };
};

async function scenarioPointerDnd(browser, server) {
  await withFiles(browser, server, DND_SPEC, 'A3-23 a file dragged onto a folder', async (app) => {
    const { page } = app;
    await emulateWindowsDragDrop(page);
    await openFilesTab(page);
    const seen = await mouseDrag(page, remoteRow('a.txt'), remoteRow('docs'), { during: (at) => dragView(page, at) });
    yes('A3-23 a ghost of the dragged file follows the pointer', !!seen && /a\.txt/.test(seen.ghost || '') && seen.near, JSON.stringify(seen));
    check('A3-23 the folder under the pointer is lit as the drop target', seen && seen.rows, ['docs']);
    yes('A3-23 the move still asks first', await waitVisible(page, '#confirmModal'));
    const msg = plain(await page.textContent('#confirmMessage'));
    // Review F4: the target as a folder inside a folder, not one path a
    // look-alike name can pass for another's.
    check('naming what goes where: into the folder, inside the folder it is in', msg, 'Move "a.txt" into the folder "docs" inside /home/u?');
    await page.click('#confirmOkBtn');
    await settle(page, 250);
    check('A3-23 releasing over the folder moves the file into it',
      (await app.calls('sftp_rename')).map((c) => c.args), [{ sessionId: 'sess-t1', from: '/home/u/a.txt', to: '/home/u/docs/a.txt' }]);
    check('the ghost and the highlights are gone', await dragLeftovers(page), 0);
    check('no page errors', app.errors, []);
  });

  await withFiles(browser, server, DND_SPEC, 'A3-23 Escape mid-drag', async (app) => {
    const { page } = app;
    await emulateWindowsDragDrop(page);
    await openFilesTab(page);
    await page.click(remoteRow('b.txt'));
    const seen = await mouseDrag(page, remoteRow('a.txt'), remoteRow('docs'), { escape: true, during: (at) => dragView(page, at) });
    await settle(page, 250);
    yes('(set-up) a drag was under way', !!seen && !!seen.ghost, JSON.stringify(seen));
    check('A3-23 Escape mid-drag posts nothing', [await app.count('sftp_rename'), await app.open('confirmModal'), (await queueAdds(app)).length], [0, false, 0]);
    check('A3-23 and leaves no ghost or highlight behind', await dragLeftovers(page), 0);
    check('the release after Escape does not change the selection', await tabField(page, 'sftpSelected'), ['b.txt']);
    await page.click(remoteRow('a.txt'));
    check('a plain click (no drag) still selects', await tabField(page, 'sftpSelected'), ['a.txt']);
    check('no page errors', app.errors, []);
  });

  await withFiles(browser, server, DND_SPEC, 'A3-23 dragged between the panes', async (app) => {
    const { page } = app;
    await emulateWindowsDragDrop(page);
    await openFilesTab(page);
    await openDual(page);
    const seen = await mouseDrag(page, localRow('l1.txt'), remoteRow('b.txt'), { during: (at) => dragView(page, at) });
    await settle(page, 300);
    check('A3-23 over the remote list (not on a folder) the remote pane is the target', seen && [seen.rows, seen.panes], [[], ['remote']]);
    check('A3-23 a local file dropped on the remote pane uploads into the remote folder',
      (await queueAdds(app)).map((a) => [a.direction, a.items]), [['upload', [{ local: '/home/me/l1.txt', remote: '/home/u/l1.txt', resume: 'overwrite' }]]]);
    await mouseDrag(page, localRow('l1.txt'), remoteRow('docs'));
    await settle(page, 300);
    check('A3-23 dropped on a remote folder it uploads into that folder',
      (await queueAdds(app)).slice(1).map((a) => a.items), [[{ local: '/home/me/l1.txt', remote: '/home/u/docs/l1.txt', resume: 'overwrite' }]]);
    await mouseDrag(page, remoteRow('b.txt'), localRow('l1.txt'));
    await settle(page, 400);
    check('A3-23 a remote file dropped on the local pane downloads into the local folder',
      (await queueAdds(app)).slice(2).map((a) => [a.direction, a.destDir, a.items.map((i) => i.remote)]), [['download', '/home/me', ['/home/u/b.txt']]]);
    await mouseDrag(page, remoteRow('b.txt'), localRow('Downloads'));
    await settle(page, 400);
    check('A3-23 dropped on a local folder it downloads into that folder',
      (await queueAdds(app)).slice(3).map((a) => [a.direction, a.destDir, a.items.map((i) => i.remote)]), [['download', '/home/me/Downloads', ['/home/u/b.txt']]]);
    check('no page errors', app.errors, []);
  });

  // A drop on the local side goes through the "already exists" question like
  // every download: the folder-drop path used to queue straight away and
  // replace a local file of the same name.
  const CLASH = { remote: { '/home/u': ['a.txt'] }, local: { '/home/me': ['Downloads/', 'a.txt'], '/home/me/Downloads': [] } };
  await withFiles(browser, server, CLASH, 'A3-23 a drop that would replace a local file', async (app) => {
    const { page } = app;
    await emulateWindowsDragDrop(page);
    await openFilesTab(page);
    await openDual(page);
    await mouseDrag(page, remoteRow('a.txt'), localRow('a.txt'));
    yes('A3-23 a drop that would replace a local file asks first', await waitVisible(page, '#conflictModal'));
    check('and nothing is queued before the answer', (await queueAdds(app)).length, 0);
    await page.click('#conflictCancelBtn');
    await settle(page, 200);
    check('Cancel queues nothing', (await queueAdds(app)).length, 0);
    check('no page errors', app.errors, []);
  });

  await withFiles(browser, server, DND_SPEC, 'SC 2.5.7 the same without dragging', async (app) => {
    const { page } = app;
    await openFilesTab(page);
    await rowEvent(page, 'contextmenu', 'a.txt');
    const items = (await menuItems(page)) || [];
    check('SC 2.5.7 the remote file menu offers Download and Move to...', ['Download', 'Move to...'].filter((x) => items.includes(x)), ['Download', 'Move to...']);
    await clickMenuItem(page, 'Move to...');
    yes('SC 2.5.7 Move to... asks for the folder', await waitVisible(page, '#promptModal'));
    check('starting from the folder on screen', await page.inputValue('#promptInput'), '/home/u');
    await page.fill('#promptInput', '/home/u/docs');
    await page.click('#promptOkBtn');
    await settle(page, 300);
    check('SC 2.5.7 and moves the file there without a drag',
      (await app.calls('sftp_rename')).map((c) => c.args), [{ sessionId: 'sess-t1', from: '/home/u/a.txt', to: '/home/u/docs/a.txt' }]);
    await openDual(page);
    await rowEvent(page, 'contextmenu', 'l1.txt', { local: true });
    yes('SC 2.5.7 the local file menu offers Upload', ((await menuItems(page)) || []).includes('Upload'), JSON.stringify(await menuItems(page)));
    check('no page errors', app.errors, []);
  });

  // Review L1: a press that ends a double-click and then drags - its release
  // is not a double-click (that downloads a remote file, uploads a local one).
  await withFiles(browser, server, DND_SPEC, 'L1 a drag is not a double-click', async (app) => {
    const { page } = app;
    await emulateWindowsDragDrop(page);
    await openFilesTab(page);
    await openDual(page);
    for (const [side, sel] of [['remote', remoteRow('a.txt')], ['local', localRow('l1.txt')]]) {
      const p = await centre(page, sel);
      await page.mouse.click(p.x, p.y);
      await page.mouse.move(p.x, p.y);
      await page.mouse.down({ clickCount: 2 });
      await page.mouse.move(p.x + 60, p.y + 4, { steps: 4 });
      await page.mouse.move(p.x, p.y, { steps: 4 });
      await page.mouse.up({ clickCount: 2 });
      await settle(page, 700);
      check(`L1 the release of a ${side} drag that began as a double-click transfers nothing`,
        [(await queueAdds(app)).length, await app.count('sftp_rename'), await app.open('confirmModal')], [0, 0, false]);
    }
    check('no page errors', app.errors, []);
  });

  // Review L1 / L7: a drag the window lost (blur) or the system took back
  // (pointercancel) ends there - no drop on the release, no click either.
  for (const [how, cancel] of [
    ['the window losing focus', () => window.dispatchEvent(new Event('blur'))],
    ['a pointercancel', () => window.dispatchEvent(new PointerEvent('pointercancel', { pointerId: 1, bubbles: true }))],
  ]) {
    await withFiles(browser, server, DND_SPEC, `L7 a drag cut short by ${how}`, async (app) => {
      const { page } = app;
      await emulateWindowsDragDrop(page);
      await openFilesTab(page);
      await page.click(remoteRow('b.txt'));
      const seen = await mouseDrag(page, remoteRow('a.txt'), remoteRow('docs'), {
        during: async (at) => {
          const before = await dragView(page, at);
          await page.evaluate(cancel);
          return { before, after: await dragView(page, at) };
        },
      });
      await settle(page, 250);
      yes('(set-up) a drag was under way', !!seen && !!seen.before.ghost, JSON.stringify(seen));
      check(`L7 ${how} ends the drag at once: no ghost, nothing lit`, seen && [seen.after.ghost, seen.after.rows], [null, []]);
      check(`L7 after ${how} the release drops nothing`, [await app.count('sftp_rename'), await app.open('confirmModal')], [0, false]);
      check(`L1 and is not a click on the list (the selection stays)`, await tabField(page, 'sftpSelected'), ['b.txt']);
      await page.click(remoteRow('a.txt'));
      check('a later click still selects', await tabField(page, 'sftpSelected'), ['a.txt']);
      check('no page errors', app.errors, []);
    });
  }

  // Review F4: a folder named with look-alike dots (U+2024 ONE DOT LEADER
  // twice) poses as the parent, and a name with a line break adds sentences
  // of its own to a question.
  const DOTS = '\u2024\u2024';
  const BREAK = 'x\nThen everything is deleted';
  const ODD = {
    remote: { '/home/u': [DOTS + '/', BREAK + '/', 'a.txt'], ['/home/u/' + DOTS]: [], ['/home/u/' + BREAK]: [] },
    local: HOME_ONLY,
  };
  /// The centre of the remote row of `name` (an attribute selector cannot
  /// hold a line break).
  const rowAt = (page, name) => page.evaluate((n) => {
    const tr = [...document.querySelectorAll('#sftpTbody-t1 tr.sftp-entry')].find((r) => r.dataset.name === n);
    const b = tr.getBoundingClientRect();
    return { x: b.left + b.width / 2, y: b.top + b.height / 2 };
  }, name);
  await withFiles(browser, server, ODD, 'F4 look-alike and multi-line names', async (app) => {
    const { page } = app;
    await emulateWindowsDragDrop(page);
    await openFilesTab(page);
    const cell = (name) => page.evaluate((n) => {
      const tr = [...document.querySelectorAll('#sftpTbody-t1 tr.sftp-entry')].find((r) => r.dataset.name === n);
      return tr && { text: tr.querySelector('.sftp-name').textContent, flagged: !!tr.querySelector('.sftp-name-flag'), title: tr.title };
    }, name);
    const dots = await cell(DOTS);
    check('F4 a name of look-alike dots is shown with its characters spelled out', dots && dots.text, '<U+2024><U+2024>');
    yes('F4 and flagged in the listing', !!dots && dots.flagged && /unusual/i.test(dots.title), JSON.stringify(dots));
    const lines = await cell(BREAK);
    check('F4 a line break in a name is shown as \\n', lines && lines.text, 'x\\nThen everything is deleted');
    check('a plain name is shown as it is, unflagged', await cell('a.txt').then((c) => c && [c.text, c.flagged]), ['a.txt', false]);
    await mouseDrag(page, remoteRow('a.txt'), await rowAt(page, DOTS));
    yes('(set-up) the move asks', await waitVisible(page, '#confirmModal'));
    check('F4 the question spells the look-alike out and says where that folder is',
      plain(await page.textContent('#confirmMessage')), 'Move "a.txt" into the folder "<U+2024><U+2024>" inside /home/u?');
    await page.click('#confirmCancelBtn');
    await settle(page, 150);
    await mouseDrag(page, remoteRow('a.txt'), await rowAt(page, BREAK));
    yes('(set-up) the move asks again', await waitVisible(page, '#confirmModal'));
    const q = await page.textContent('#confirmMessage');
    check('F4 a name with a line break adds no line to the question', [q.includes('\n'), plain(q)],
      [false, 'Move "a.txt" into the folder "x\\nThen everything is deleted" inside /home/u?']);
    await page.click('#confirmCancelBtn');
    check('nothing was moved', await app.count('sftp_rename'), 0);
    check('no page errors', app.errors, []);
  });
}

// ─── JU6b: one sftp_open per tab (A5-12 b) ──────────────────────────────────

async function scenarioSessionMode(browser, server) {
  await withFiles(browser, server, { remote: { '/home/u': ['a.txt'], '/': ['home/'] }, local: HOME_ONLY }, 'A5-12(b) Files while SFTP opens', async (app) => {
    const { page } = app;
    await page.evaluate(() => switchView('connect'));
    await openLiveTab(app);
    await page.evaluate(() => { window.__replies.sftp_open = { ok: true, cwd: '/home/u' }; });
    const seg = () => page.evaluate(() => {
      const s = document.getElementById('termModeSeg');
      return { busy: s.getAttribute('aria-busy') === 'true', pending: [...s.querySelectorAll('.seg-btn.pending')].map((b) => b.dataset.mode) };
    });
    await hold(page, 'sftp_open');
    await page.click('#termModeSeg .seg-btn[data-mode="sftp"]');
    await settle(page, 80);
    check('A5-12(b) the Shell/Files/Split control shows that the file browser is opening', await seg(), { busy: true, pending: ['sftp'] });
    await page.click('#termModeSeg .seg-btn[data-mode="split"]');
    await page.click('#termModeSeg .seg-btn[data-mode="split"]');
    await settle(page, 80);
    check('A5-12(b) more Files/Split clicks while it opens send no second sftp_open', await app.count('sftp_open'), 1);
    check('the control follows the latest choice', await seg(), { busy: true, pending: ['split'] });
    await letGo(page, 'sftp_open');
    await settle(page, 400);
    check('one sftp_open in all', await app.count('sftp_open'), 1);
    check('A5-12(b) once open, the last click is what the tab shows', await page.evaluate(() => state.sessions.get(state.activeTabId).mode), 'split');
    check('A5-12(b) and the control is no longer busy', await seg(), { busy: false, pending: [] });
    check('no page errors', app.errors, []);
  });
}

// ─── JU6b: the edit-conflict prompt (A7-19, RU6a contract) ──────────────────

const CONFLICT = (id, reason) => ({
  ok: false, conflict: true, conflictId: id, reason,
  error: reason === 'deleted'
    ? 'app.conf was deleted on the server since you opened it - choose Overwrite to put your copy back, or close it.'
    : 'app.conf changed on the server since you opened it - choose Overwrite or Reload.',
  remoteSize: reason === 'deleted' ? null : 2048,
  remoteModifiedMs: reason === 'deleted' ? null : 1700000000000,
});
const shownButtons = (page, sel) => page.evaluate((s) =>
  [...document.querySelectorAll(s)].filter((b) => b.getClientRects().length > 0).map((b) => b.textContent.trim()), sel);
/// Overwrite and Reload take no click for this long after the prompt appears
/// or changes (review H1), plus a margin.
const EDIT_ARM_MS = 850;

/// The scenarios about that moment run with the page's clock installed (the
/// app option below) and running; around a step that must land inside the
/// moment they hold it still - no timer of the page fires, the moment's end
/// included, until the test moves the clock on. On a loaded machine a step
/// alone took longer than the moment, and a check meant for inside it ran
/// after it (review round 2).
const CLOCK_APP = { app: { clock: true } };
const clockRuns = (page) => page.clock.resume();
const clockHolds = (page) => pauseClockAhead(page, 1);
const clockPasses = (page, ms) => page.clock.runFor(ms);
/// A dialog's entrance animation (popIn, 0.16 s) runs in real time - the
/// held clock does not stop it - and a position read during it is a few
/// pixels off: wait until it has finished.
const animationsDone = (page, id) => page.waitForFunction((i) =>
  document.getElementById(i).getAnimations({ subtree: true }).every((a) => a.playState !== 'running'), id, { polling: 25 });

async function scenarioEditConflict(browser, server) {
  const spec = { remote: { '/home/u': ['app.conf'] }, local: HOME_ONLY };
  const sync = (page, p) => page.evaluate((x) => window.__emit('sftp-edit-sync',
    Object.assign({ sessionId: 'sess-t1', editId: 'e1', remote: '/home/u/app.conf' }, x)), p);
  const resolves = async (app) => (await app.calls('sftp_edit_resolve')).map((c) => c.args);

  await withFiles(browser, server, Object.assign({}, spec, CLOCK_APP), 'A7-19 a remote change while editing', async (app) => {
    const { page } = app;
    await clockRuns(page);
    await openFilesTab(page);
    await page.evaluate((fresh) => {
      let n = 0;
      // The first Overwrite meets ANOTHER change on the server: the backend
      // answers with a fresh conflict (and emits it); the second goes through.
      window.__replies.sftp_edit_resolve = (a) => (++n === 1 ? fresh
        : { ok: true, editId: a.editId, action: a.action, remoteSize: 9, remoteModifiedMs: 1700000001000 });
    }, CONFLICT('c2', 'changed'));
    await sync(page, CONFLICT('c1', 'changed'));
    yes('A7-19 a remote change while editing asks what to do', await waitVisible(page, '#editConflictModal'));
    const msg = (await page.textContent('#editConflictMessage')) || '';
    yes('A7-19 saying the file changed on the server since it was opened', /app\.conf changed on the server since you opened it/.test(msg), msg);
    check('A7-19 with Overwrite, Reload and Cancel', await shownButtons(page, '#editConflictModal .modal-footer button'), ['Cancel', 'Reload', 'Overwrite']);
    yes('Cancel has the focus (both other answers replace something)', await focusIs(page, 'editConflictCancelBtn'));
    await page.click('#editConflictOverwriteBtn');
    await settle(page, 250);
    check('A7-19 Overwrite answers that conflict', await resolves(app), [{ editId: 'e1', conflictId: 'c1', action: 'overwrite' }]);
    await sync(page, CONFLICT('c2', 'changed')); // the same fresh conflict, as the event
    await settle(page, 120);
    check('A7-19 a fresh conflict replaces the prompt - never two of them',
      await page.evaluate(() => [document.querySelectorAll('#editConflictModal').length, modalStack.filter((m) => m.node.id === 'editConflictModal').length]), [1, 1]);
    yes('and the prompt is still up', await app.open('editConflictModal'));
    await page.click('#editConflictOverwriteBtn');
    await settle(page, 250);
    check('A7-19 the next answer uses the NEW conflict id', (await resolves(app)).map((a) => a.conflictId), ['c1', 'c2']);
    yes('the prompt closes once it is settled', !(await app.open('editConflictModal')));
    await sync(page, { ok: true });
    yes('and the upload is confirmed', (await toasts(page)).some((t) => /Saved "app\.conf"/.test(plain(t))), JSON.stringify(await toasts(page)));

    await sync(page, CONFLICT('c3', 'changed'));
    await waitVisible(page, '#editConflictModal');
    await page.click('#editConflictReloadBtn');
    await settle(page, 250);
    check('A7-19 Reload answers with action reload', (await resolves(app)).pop(), { editId: 'e1', conflictId: 'c3', action: 'reload' });
    await sync(page, { ok: true, reloaded: true });
    yes('a reload is reported', (await toasts(page)).some((t) => /app\.conf/.test(t) && /server's version/.test(t)), JSON.stringify(await toasts(page)));

    await sync(page, CONFLICT('c4', 'deleted'));
    await waitVisible(page, '#editConflictModal');
    const gone = (await page.textContent('#editConflictMessage')) || '';
    yes('A7-19 a file deleted on the server says so', /app\.conf was deleted on the server/.test(gone), gone);
    await clockHolds(page);
    await clockPasses(page, EDIT_ARM_MS);
    // Disabled, not hidden (review H1): with Reload gone Cancel took its place,
    // so a click aimed at one prompt's Reload landed on the next one's Cancel.
    check('A7-19 and Reload is offered disabled - nothing to reload - with every button where it was',
      await page.evaluate(() => [...document.querySelectorAll('#editConflictModal .modal-footer button')]
        .map((b) => [b.textContent.trim(), b.getClientRects().length > 0, b.disabled])),
      [['Cancel', true, false], ['Reload', true, true], ['Overwrite', true, false]]);
    await clockRuns(page);
    const before = (await resolves(app)).length;
    await page.click('#editConflictCancelBtn');
    await settle(page, 120);
    check('Cancel settles nothing and closes the prompt', [(await resolves(app)).length - before, await app.open('editConflictModal')], [0, false]);
    await sync(page, CONFLICT('c5', 'changed'));
    await waitVisible(page, '#editConflictModal');
    await page.keyboard.press('Escape');
    await settle(page, 120);
    check('Escape is Cancel', [(await resolves(app)).length - before, await app.open('editConflictModal')], [0, false]);

    const FAIL = 'Could not check app.conf on the server before syncing (timeout), so your save was not uploaded. Save again to retry.';
    await sync(page, { ok: false, error: FAIL });
    await settle(page, 80);
    const t = await toasts(page);
    yes('A7-19 a failed save shows the backend message as it is', t.some((x) => x.includes(FAIL)), JSON.stringify(t));
    check('A7-19 with no doubled period anywhere', t.filter((x) => /[^.]\.\.(?!\.)/.test(x)), []);
    check('a conflict was never toasted as a failed save', t.filter((x) => /changed on the server/.test(x)), []);
    check('no page errors', app.errors, []);
  });

  await withFiles(browser, server, spec, 'A7-19 a refused answer', async (app) => {
    const { page } = app;
    await openFilesTab(page);
    const WHY = 'Could not check app.conf on the server (timeout); nothing was uploaded.';
    await page.evaluate((w) => { window.__replies.sftp_edit_resolve = { $reject: w }; }, WHY);
    await sync(page, CONFLICT('c1', 'changed'));
    await waitVisible(page, '#editConflictModal');
    await page.click('#editConflictOverwriteBtn');
    await settle(page, 200);
    check('A7-19 a refused answer is shown in the prompt, in the backend\'s words', (await page.textContent('#editConflictError') || '').trim(), WHY);
    yes('and the prompt stays to choose again', await app.open('editConflictModal'));
    check('no page errors', app.errors, []);
  });

  await withFiles(browser, server, spec, 'RU6a opening a file already being edited', async (app) => {
    const { page } = app;
    await openFilesTab(page);
    await page.evaluate(() => {
      window.__replies.sftp_open_for_edit = { ok: true, localPath: 'C:\\stage\\app.conf', remote: '/home/u/app.conf', editId: 'e1', reused: true };
    });
    await rowEvent(page, 'contextmenu', 'app.conf');
    await clickMenuItem(page, 'Open with system app');
    await settle(page, 200);
    yes('RU6a a file already open for editing says so (same copy)', (await toasts(page)).some((x) => /already/i.test(x)), JSON.stringify(await toasts(page)));
    check('no page errors', app.errors, []);
  });
}

// ─── JU6b fix round: one question per file, in turn (review H1 L2 F3 L7) ────

async function scenarioEditConflictQueue(browser, server) {
  const RLO = 'report\u202Egnp.exe';
  const spec = { remote: { '/home/u': ['a.conf', 'b.conf', RLO] }, local: HOME_ONLY };
  const ev = (page, editId, remote, p) => page.evaluate((x) => window.__emit('sftp-edit-sync', x),
    Object.assign({ sessionId: 'sess-t1', editId, remote }, p));
  const resolves = async (app) => (await app.calls('sftp_edit_resolve')).map((c) => c.args);
  const prompt = (page) => page.evaluate(() => {
    const q = document.getElementById('editConflictQueue');
    return {
      open: !document.getElementById('editConflictModal').hidden,
      title: document.getElementById('editConflictTitle').textContent,
      message: document.getElementById('editConflictMessage').textContent,
      queue: q && !q.hidden ? q.textContent : '',
      disabled: ['editConflictCancelBtn', 'editConflictReloadBtn', 'editConflictOverwriteBtn'].map((id) => document.getElementById(id).disabled),
    };
  });
  /// A click made by hand at the button's centre - it goes to whatever is
  /// there, enabled or not (page.click would wait for it to be enabled).
  const press = async (page, id) => {
    const b = await page.locator('#' + id).boundingBox();
    await page.mouse.click(b.x + b.width / 2, b.y + b.height / 2);
  };
  const okReply = (page) => page.evaluate(() => {
    window.__replies.sftp_edit_resolve = (a) => ({ ok: true, editId: a.editId, action: a.action, remoteSize: 1, remoteModifiedMs: 1 });
  });

  await withFiles(browser, server, Object.assign({}, spec, CLOCK_APP), 'H1 conflicts on two files are asked one at a time', async (app) => {
    const { page } = app;
    await clockRuns(page);
    await openFilesTab(page);
    await okReply(page);
    await clockHolds(page);
    await ev(page, 'ea', '/home/u/a.conf', CONFLICT('a1', 'changed'));
    await clockPasses(page, 30);
    let s = await prompt(page);
    yes('H1 the prompt names the file in its title', /a\.conf/.test(s.title), s.title);
    check('H1 Overwrite and Reload take no click for a moment after the prompt appears', s.disabled, [false, true, true]);
    await press(page, 'editConflictOverwriteBtn');
    await settle(page, 80);
    check('H1 a click in that moment does nothing', (await resolves(app)).length, 0);
    // Nor does an answer that does not come through the (disabled) button.
    await page.evaluate(() => sftpAnswerEditConflict('overwrite'));
    await settle(page, 80);
    check('H1 the prompt itself refuses an answer before it is ready', (await resolves(app)).length, 0);
    await clockPasses(page, EDIT_ARM_MS);
    await ev(page, 'eb', '/home/u/b.conf', CONFLICT('b1', 'changed'));
    s = await prompt(page);
    yes('H1 a conflict on another file does not take the place of the question on screen',
      /a\.conf/.test(s.message) && !/b\.conf/.test(s.message + s.title), JSON.stringify(s));
    check('H1 it waits its turn, and the prompt says so', s.queue, '1 more file needs an answer after this one.');
    check('H1 the question on screen stays answerable', s.disabled, [false, false, false]);
    await press(page, 'editConflictOverwriteBtn');
    await settle(page, 200);
    check('H1 the answer goes to the file it was asked about', await resolves(app), [{ editId: 'ea', conflictId: 'a1', action: 'overwrite' }]);
    s = await prompt(page);
    yes('H1 then the next file is asked about', s.open && /b\.conf/.test(s.message) && /b\.conf/.test(s.title), JSON.stringify(s));
    check('H1 with no file left waiting', s.queue, '');
    await press(page, 'editConflictOverwriteBtn');
    await settle(page, 80);
    check('H1 its buttons too take no click for a moment', (await resolves(app)).length, 1);
    await clockPasses(page, EDIT_ARM_MS);
    await press(page, 'editConflictOverwriteBtn');
    await settle(page, 200);
    check('H1 and its answer names its own file', (await resolves(app)).pop(), { editId: 'eb', conflictId: 'b1', action: 'overwrite' });
    yes('the prompt closes when no question is left', !(await prompt(page)).open);
    check('no page errors', app.errors, []);
  });

  await withFiles(browser, server, Object.assign({}, spec, CLOCK_APP), 'H1 a deleted file, then another file', async (app) => {
    const { page } = app;
    await clockRuns(page);
    await openFilesTab(page);
    await okReply(page);
    const rects = () => page.evaluate(() => ['editConflictCancelBtn', 'editConflictReloadBtn', 'editConflictOverwriteBtn']
      .map((id) => { const r = document.getElementById(id).getBoundingClientRect(); return [Math.round(r.left), Math.round(r.top)]; }));
    await clockHolds(page);
    await ev(page, 'ea', '/home/u/a.conf', CONFLICT('a1', 'deleted'));
    await clockPasses(page, EDIT_ARM_MS);
    await animationsDone(page, 'editConflictModal');
    const where = await rects();
    await ev(page, 'eb', '/home/u/b.conf', CONFLICT('b1', 'changed'));
    check('(set-up) a.conf is asked about, b.conf waits', [(await prompt(page)).message.includes('a.conf'), (await prompt(page)).queue],
      [true, '1 more file needs an answer after this one.']);
    await press(page, 'editConflictCancelBtn');
    await settle(page, 80);
    const s = await prompt(page);
    yes('H1 Cancel leaves a.conf as it is and asks about b.conf', s.open && /b\.conf/.test(s.message), JSON.stringify(s));
    check('H1 every button is where it was on the deleted file\'s prompt', await rects(), where);
    // A second click where the last prompt's Cancel was - it is this one's
    // Cancel now, and must not dismiss b.conf unseen (review round 2, N2).
    await press(page, 'editConflictCancelBtn');
    await settle(page, 80);
    const t = await prompt(page);
    check('H1 a click that was aimed at the last prompt\'s Cancel does nothing on this one',
      [t.open && /b\.conf/.test(t.title), (await resolves(app)).length], [true, 0]);
    await clockPasses(page, EDIT_ARM_MS);
    await press(page, 'editConflictReloadBtn');
    await settle(page, 200);
    check('H1 once armed, Reload answers b.conf\'s conflict', await resolves(app), [{ editId: 'eb', conflictId: 'b1', action: 'reload' }]);
    check('no page errors', app.errors, []);
  });

  await withFiles(browser, server, Object.assign({}, spec, CLOCK_APP), 'H1 a newer question about the same file', async (app) => {
    const { page } = app;
    await clockRuns(page);
    await openFilesTab(page);
    await okReply(page);
    await clockHolds(page);
    await ev(page, 'ea', '/home/u/a.conf', CONFLICT('a1', 'changed'));
    await clockPasses(page, EDIT_ARM_MS);
    await ev(page, 'ea', '/home/u/a.conf', CONFLICT('a2', 'changed'));
    const s = await prompt(page);
    check('H1 a newer conflict of the file on screen replaces the question, and takes no click for a moment', [s.queue, s.disabled], ['', [false, true, true]]);
    yes('H1 and the change is announced', /newer/i.test(await page.textContent('#editConflictLive')), await page.textContent('#editConflictLive'));
    await press(page, 'editConflictOverwriteBtn');
    await settle(page, 80);
    check('H1 a click meant for the replaced question does nothing', (await resolves(app)).length, 0);
    await clockPasses(page, EDIT_ARM_MS);
    await press(page, 'editConflictOverwriteBtn');
    await settle(page, 200);
    check('H1 the answer settles the newer conflict', await resolves(app), [{ editId: 'ea', conflictId: 'a2', action: 'overwrite' }]);
    check('no page errors', app.errors, []);
  });

  await withFiles(browser, server, Object.assign({}, spec, CLOCK_APP), 'L7 a late answer', async (app) => {
    const { page } = app;
    await clockRuns(page);
    await openFilesTab(page);
    await okReply(page);
    await hold(page, 'sftp_edit_resolve');
    await clockHolds(page);
    await ev(page, 'ea', '/home/u/a.conf', CONFLICT('a1', 'changed'));
    await clockPasses(page, EDIT_ARM_MS);
    await press(page, 'editConflictOverwriteBtn');
    await settle(page, 80);
    await ev(page, 'ea', '/home/u/a.conf', CONFLICT('a2', 'changed'));
    await letGo(page, 'sftp_edit_resolve');
    await settle(page, 200);
    const s = await prompt(page);
    yes('L7 the answer to a replaced question does not close the newer one', s.open, JSON.stringify(s));
    await clockPasses(page, EDIT_ARM_MS);
    await press(page, 'editConflictOverwriteBtn');
    await settle(page, 200);
    check('L7 which is still answered on its own', (await resolves(app)).map((a) => a.conflictId), ['a1', 'a2']);
    check('no page errors', app.errors, []);
  });

  await withFiles(browser, server, Object.assign({}, spec, CLOCK_APP), 'L2 settled elsewhere', async (app) => {
    const { page } = app;
    await clockRuns(page);
    await openFilesTab(page);
    await ev(page, 'ea', '/home/u/a.conf', CONFLICT('a1', 'changed'));
    await ev(page, 'eb', '/home/u/b.conf', CONFLICT('b1', 'changed'));
    await ev(page, 'eb', '/home/u/b.conf', { ok: true, reloaded: true });
    check('L2 a waiting file whose edit was settled meanwhile is not asked about', (await prompt(page)).queue, '');
    await ev(page, 'ea', '/home/u/a.conf', { ok: true });
    check('L2 the prompt closes when the file on screen is saved meanwhile', (await prompt(page)).open, false);
    check('and nothing was answered for it', await app.count('sftp_edit_resolve'), 0);
    await clockHolds(page);
    await ev(page, 'ea', '/home/u/a.conf', CONFLICT('a3', 'unverifiable'));
    await clockPasses(page, EDIT_ARM_MS);
    const s = await prompt(page);
    yes('L7 a file the server cannot compare is asked about as such', /could not be checked/.test(s.message), s.message);
    check('L7 with Reload and Overwrite both offered', s.disabled, [false, false, false]);
    check('no page errors', app.errors, []);
  });

  await withFiles(browser, server, spec, 'F3 a file name with a direction override', async (app) => {
    const { page } = app;
    await openFilesTab(page);
    await ev(page, 'er', '/home/u/' + RLO, CONFLICT('r1', 'changed'));
    const s = await page.evaluate(() => ({
      text: document.getElementById('editConflictTitle').textContent + ' ' + document.getElementById('editConflictMessage').textContent,
      isolated: [...document.querySelectorAll('#editConflictTitle bdi, #editConflictMessage bdi')].map((b) => b.textContent),
    }));
    check('F3 the override is shown, not obeyed', [s.text.includes('\u202E'), s.text.includes('report<U+202E>gnp.exe')], [false, true]);
    check('F3 and the name is kept to itself (bdi)', s.isolated, ['report<U+202E>gnp.exe', 'report<U+202E>gnp.exe']);
    await page.click('#editConflictCancelBtn');
    await ev(page, 'er', '/home/u/' + RLO, { ok: true });
    await ev(page, 'er', '/home/u/' + RLO, { ok: false, error: 'Permission denied' });
    const t = (await toasts(page)).filter((x) => /report/.test(x));
    check('F3 the save toasts show it too, never obey it', t.map((x) => [x.includes('\u202E'), x.includes('report<U+202E>gnp.exe')]), [[false, true], [false, true]]);
    check('no page errors', app.errors, []);
  });
}

// ─── JU6b: settings that cannot be saved, caches after a change (JU1/JU2) ───

async function scenarioSettingsRevert(browser, server) {
  await withFiles(browser, server, { remote: { '/home/u': ['a.txt'] }, local: HOME_ONLY }, 'JU2 leftover: the dual pane when its setting fails', async (app) => {
    const { page } = app;
    await openFilesTab(page);
    await page.evaluate(() => {
      window.__replies.settings_set = (a) => {
        if (a.key === 'sftpDualPane') throw 'Could not save the setting: the database is read-only.';
        return { ok: true };
      };
    });
    await openDual(page);
    await settle(page, 200);
    const shown = await page.evaluate(() => ({
      dual: state.sessions.get('t1').dualPane,
      pane: !document.getElementById('sftpLocalPane-t1').hidden,
      button: document.querySelector('#sftpPanel-t1 .sftp-toolbar button[title="Toggle local pane"]').classList.contains('active'),
      saved: state.sftpDualPane === true,
    }));
    check('JU2 a dual-pane toggle that could not be saved is put back', shown, { dual: false, pane: false, button: false, saved: false });
    yes('JU2 and the backend says why', (await toasts(page)).includes('Could not save the setting: the database is read-only.'), JSON.stringify(await toasts(page)));
    check('no page errors', app.errors, []);
  });

  await withFiles(browser, server, { remote: { '/srv': ['a.txt'] }, local: HOME_ONLY }, 'JU2 leftover: "always" when its setting fails', async (app) => {
    const { page } = app;
    await openFilesTab(page, { tab: { sftpPath: '/srv' } });
    await page.evaluate(() => {
      window.__replies.settings_set = (a) => {
        if (a.key === 'sftpConflictUpload') throw 'Settings cannot be written right now.';
        return { ok: true };
      };
      window.__up = queueUploads('t1', [{ local: '/tmp/a.txt', remote: '/srv/a.txt' }]);
    });
    await waitVisible(page, '#conflictModal');
    await page.check('#conflict-0-overwrite');
    await page.click('#conflictModal label:has(#conflictAlways)');
    await page.click('#conflictApplyBtn');
    await settle(page, 250);
    check('JU2 a failed "always" keeps the dialog open with the box unticked',
      [await app.open('conflictModal'), await page.isChecked('#conflictAlways')], [true, false]);
    yes('JU2 and says why', (await toasts(page)).some((x) => x.includes('Settings cannot be written right now.')), JSON.stringify(await toasts(page)));
    check('nothing was queued yet, and no default was kept', [(await queueAdds(app)).length, await page.evaluate(() => state.settings.sftpConflictUpload || null)], [0, null]);
    await page.click('#conflictApplyBtn');
    await settle(page, 250);
    check('Continue then goes ahead with this batch alone', (await queueAdds(app)).map((a) => a.items),
      [[{ local: '/tmp/a.txt', remote: '/srv/a.txt', resume: 'overwrite' }]]);
    check('no page errors', app.errors, []);
  });
}

/// Item 8 (final review): EVERY preference the file browser saves - Columns,
/// Keep times, Dual, Compare and the conflict dialog's "Always use this
/// action" - is put back on screen, with the backend's message, when
/// settings_set refuses it. Before, only the message was shown (or nothing),
/// and the screen disagreed with what the next launch would restore.
async function scenarioEverySettingReverts(browser, server) {
  const spec = { remote: { '/home/u': ['a.txt'], '/srv': ['a.txt'] }, local: { '/home/me': ['a.txt'] } };
  await withFiles(browser, server, spec, 'item 8: a refused setting puts every file-browser control back', async (app) => {
    const { page } = app;
    await page.setViewportSize({ width: 1600, height: 1000 });
    await openFilesTab(page);
    await settle(page, 150);
    await page.evaluate(() => {
      window.__replies.settings_set = (a) => { throw `Could not save ${a.key}: the settings store is read-only.`; };
    });
    const btn = (title) => `#sftpPanel-t1 .sftp-toolbar button[title="${title}"]`;
    const looks = () => page.evaluate(() => {
      const t = state.sessions.get('t1');
      const panel = document.getElementById('sftpPanel-t1');
      const active = (sel) => { const b = panel.querySelector(sel); return !!b && b.classList.contains('active'); };
      return {
        columns: [!!t.showOwnerCols, panel.classList.contains('show-owner-cols'), active('button[title="Show/hide permissions & owner columns"]')],
        keepTimes: [!!t.sftpPreserveTs, active('#sftpPreserveTsBtn-t1')],
        dual: [!!t.dualPane, !document.getElementById('sftpLocalPane-t1').hidden, active('button[title="Toggle local pane"]')],
        compare: [sftpCmpModeOf('t1'), active('.sftp-cmp-btn')],
      };
    });
    const saved = () => page.evaluate(() => ['sftpShowOwnerCols', 'sftpPreserveTs', 'sftpDualPane', 'sftpCmpMode', 'sftpConflictUpload']
      .map((k) => state.settings[k] === undefined ? null : state.settings[k]));
    const savedBefore = await saved();
    // Each refusal is checked as it happens: toasts expire.
    const unsaid = [];
    const said = async (key) => {
      if (!(await toasts(page)).includes(`Could not save ${key}: the settings store is read-only.`)) unsaid.push(key);
    };
    const before = await looks();
    check('(set-up) Columns on, Keep times off, one pane, no comparison', before, {
      columns: [true, true, true], keepTimes: [false, false], dual: [false, false, false], compare: [null, false] });

    await page.click(btn('Show/hide permissions & owner columns'));
    await settle(page, 150);
    check('item 8 Columns that could not be saved is put back', (await looks()).columns, before.columns);
    await said('sftpShowOwnerCols');
    await page.click('#sftpPreserveTsBtn-t1');
    await settle(page, 150);
    check('item 8 Keep times that could not be saved is put back', (await looks()).keepTimes, before.keepTimes);
    await said('sftpPreserveTs');
    await page.click(btn('Toggle local pane'));
    await settle(page, 200);
    check('item 8 Dual that could not be saved is put back', (await looks()).dual, before.dual);
    await said('sftpDualPane');
    // Compare needs both panes: opened the way a download opens them (no
    // save) - unless a Dual that was not put back left them open.
    await page.evaluate(() => { if (!state.sessions.get('t1').dualPane) toggleDualPane('t1', { persist: false }); });
    await settle(page, 250);
    await page.click('#sftpPanel-t1 .sftp-cmp-btn');
    await settle(page, 150);
    check('item 8 Compare that could not be saved is put back', (await looks()).compare, before.compare);
    await said('sftpCmpMode');

    await page.evaluate(() => { window.__up = queueUploads('t1', [{ local: '/tmp/a.txt', remote: '/srv/a.txt' }]); });
    await waitVisible(page, '#conflictModal');
    await page.check('#conflict-0-overwrite');
    await page.click('#conflictModal label:has(#conflictAlways)');
    await page.click('#conflictApplyBtn');
    await settle(page, 250);
    check('item 8 "Always use this action" that could not be saved is unticked, the dialog still open',
      [await page.isChecked('#conflictAlways'), await app.open('conflictModal')], [false, true]);
    await said('sftpConflictUpload');
    if (await app.open('conflictModal')) await page.click('#conflictCancelBtn');

    check('item 8 each refusal is said in the backend\'s words', unsaid, []);
    check('item 8 and nothing refused is kept as a setting for this session', await saved(), savedBefore);
    check('no page errors', app.errors, []);
  });
}

async function scenarioMutationCache(browser, server) {
  const remote = { '/home/u': ['docs/', 'a.txt'], '/home/u/docs': ['inside.txt'], '/srv': ['x.txt'] };
  await withFiles(browser, server, { remote, local: HOME_ONLY }, 'JU1 leftover: a change drops the cache of the folder it changed', async (app) => {
    const { page } = app;
    await openFilesTab(page);
    await rowEvent(page, 'dblclick', 'docs');
    await settle(page);
    await page.click('#sftpPanel-t1 .sftp-toolbar button[title="Parent directory"]');
    await settle(page);
    check('(set-up) back in /home/u', await tabField(page, 'sftpPath'), '/home/u');
    await rowEvent(page, 'contextmenu', 'docs');
    await clickMenuItem(page, 'Delete');
    await waitVisible(page, '#deleteModal');
    await page.click('#deleteYesBtn');
    await settle(page, 300);
    await page.evaluate(() => {
      delete window.__fs.remote['/home/u/docs'];
      window.__fs.remote['/home/u'] = window.__fs.remote['/home/u'].filter((e) => e.name !== 'docs');
    });
    let n = await app.count('sftp_list_dir');
    await typePath(page, '/home/u/docs');
    await settle(page, 200);
    check('JU1 a deleted folder is not served from the listing cache',
      (await app.calls('sftp_list_dir')).slice(n).map((c) => c.args.path), ['/home/u/docs']);
    check('so the tab stays where it is', await tabField(page, 'sftpPath'), '/home/u');

    // A navigation that lands while the New folder prompt is open.
    await page.evaluate(() => { window.__fs.delays['/srv'] = 500; window.__nav = refreshSftpPanel('t1', { path: '/srv' }); });
    await page.click('#sftpPanel-t1 .sftp-toolbar button[title="New folder"]');
    await waitVisible(page, '#promptModal');
    const asked = await page.textContent('#promptMessage');
    await settle(page, 700);
    check('(set-up) the tab moved to /srv meanwhile', await tabField(page, 'sftpPath'), '/srv');
    await page.fill('#promptInput', 'made-here');
    await page.click('#promptOkBtn');
    await settle(page, 250);
    yes('(set-up) the prompt named /home/u', /\/home\/u/.test(asked || ''), asked);
    check('JU1 mkdir goes into the folder the prompt named', (await app.calls('sftp_mkdir')).map((c) => c.args.path), ['/home/u/made-here']);
    n = await app.count('sftp_list_dir');
    await typePath(page, '/home/u');
    await settle(page, 200);
    check('JU1 and that folder is listed afresh when it is shown again', (await app.calls('sftp_list_dir')).slice(n).map((c) => c.args.path), ['/home/u']);
    check('no page errors', app.errors, []);
  });
}

/// Review L7: a move, a recursive chmod and a rename each drop the cached
/// listings they made stale - a folder visited before is listed afresh, not
/// served from the cache (12 s) as it was before the change.
async function scenarioCacheAfterChanges(browser, server) {
  const remote = {
    '/home/u': ['docs/', 'keep/', 'a.txt'], '/home/u/docs': ['in-docs.txt'], '/home/u/keep': ['in-keep.txt'],
  };
  await withFiles(browser, server, { remote, modes: { '/home/u/keep': 0o40755 }, local: HOME_ONLY }, 'L7 the cache after a move, a chmod and a rename', async (app) => {
    const { page } = app;
    await openFilesTab(page);
    const visit = async (name) => {
      await rowEvent(page, 'dblclick', name);
      await settle(page);
      await page.click('#sftpPanel-t1 .sftp-toolbar button[title="Parent directory"]');
      await settle(page);
    };
    const listedOnVisit = async (path) => {
      const n = await app.count('sftp_list_dir');
      await typePath(page, path);
      await settle(page, 200);
      const asked = (await app.calls('sftp_list_dir')).slice(n).map((c) => c.args.path);
      await typePath(page, '/home/u');
      await settle(page, 200);
      return asked;
    };
    await visit('docs');
    await visit('keep');
    check('(set-up) a cached folder is not listed again', await listedOnVisit('/home/u/docs'), []);

    await rowEvent(page, 'contextmenu', 'a.txt');
    await clickMenuItem(page, 'Move to...');
    await waitVisible(page, '#promptModal');
    await page.fill('#promptInput', '/home/u/docs');
    await page.click('#promptOkBtn');
    await settle(page, 250);
    check('(set-up) the file was moved', (await app.calls('sftp_rename')).map((c) => c.args.to), ['/home/u/docs/a.txt']);
    check('L7 the folder a file was moved into is listed afresh', await listedOnVisit('/home/u/docs'), ['/home/u/docs']);

    await page.evaluate(() => openChmodDialog('t1', ['/home/u/keep'], { name: 'keep', isDir: true }));
    await waitVisible(page, '#chmodModal');
    await settle(page, 150);
    await page.click('#chmodModal label:has(#chmodRecurse)');
    await page.click('#chmodApplyBtn');
    await settle(page, 250);
    check('L7 a folder whose permissions changed all the way down is listed afresh', await listedOnVisit('/home/u/keep'), ['/home/u/keep']);

    await page.evaluate(() => {
      const fs = window.__fs;
      fs.remote['/home/u/docs2'] = fs.remote['/home/u/docs'];
      fs.remote['/home/u'] = fs.remote['/home/u'].map((e) => (e.name === 'docs' ? Object.assign({}, e, { name: 'docs2' }) : e));
      delete fs.remote['/home/u/docs'];
    });
    await page.evaluate(() => sftpRenamePrompt('t1', state.sessions.get('t1')._entryMap.get('docs')));
    await waitVisible(page, '#promptModal');
    await page.fill('#promptInput', 'docs2');
    await page.click('#promptOkBtn');
    await settle(page, 250);
    const n = await app.count('sftp_list_dir');
    await typePath(page, '/home/u/docs');
    await settle(page, 200);
    check('L7 a renamed folder is not served from the cache under its old name',
      [(await app.calls('sftp_list_dir')).slice(n).map((c) => c.args.path), await tabField(page, 'sftpPath')], [['/home/u/docs'], '/home/u']);
    check('no page errors', app.errors, []);
  });
}

// ─── JU6b fix round 2: the questions, the vault lock and closed tabs ────────

/// The edit-conflict prompt as seen: open, whose title, the "N more" note,
/// and whether Cancel is held (aria-disabled - it keeps the focus).
const conflictPrompt = (page) => page.evaluate(() => {
  const q = document.getElementById('editConflictQueue');
  return {
    open: !document.getElementById('editConflictModal').hidden,
    title: document.getElementById('editConflictTitle').textContent,
    queue: q && !q.hidden ? q.textContent : '',
    cancelHeld: document.getElementById('editConflictCancelBtn').getAttribute('aria-disabled') === 'true',
  };
});

/// Unlock through the gate the lock put up, as a user does.
async function unlockVault(page) {
  await waitVisible(page, '#vaultModal');
  await page.fill('#vaultPassword', PASSWORD);
  await page.click('#vaultPrimary');
  await page.waitForFunction(() => state.unlocked, null, { polling: 25 });
}

/// The ways the vault locks: Ctrl+L (lockNow, asking first when there is live
/// work), the tray's Lock and the idle timer (lockNow as they call it - the
/// timer through its own handler), and the backend watchdog (the vault is
/// locked already when the page hears of it).
const LOCK_PATHS = [
  ['Ctrl+L', (page) => page.keyboard.press('Control+l')],
  ['the tray Lock', (page) => page.evaluate(() => window.__emit('vault-lock-requested', {}))],
  ['the idle auto-lock', (page) => page.evaluate(() => { autoLockDeadline = Date.now() - 1; onAutoLockTimer(); })],
  ['the backend watchdog', (page) => page.evaluate(() => { window.__backend.unlocked = false; window.__emit('vault-locked-by-watchdog', {}); })],
];

async function scenarioEditConflictLock(browser, server) {
  const spec = { remote: { '/home/u': ['a.conf', 'b.conf', 'c.conf'] }, local: HOME_ONLY };
  const ev = (page, editId, name, p, sessionId) => page.evaluate((x) => window.__emit('sftp-edit-sync', x),
    Object.assign({ sessionId: sessionId || 'sess-t1', editId, remote: '/home/u/' + name }, p));
  const twoWaiting = async (page) => {
    await ev(page, 'ea', 'a.conf', CONFLICT('a1', 'changed'));
    await ev(page, 'eb', 'b.conf', CONFLICT('b1', 'changed'));
    const s = await conflictPrompt(page);
    check('(set-up) a.conf is asked about, b.conf waits', [s.open && /a\.conf/.test(s.title), s.queue],
      [true, '1 more file needs an answer after this one.']);
  };
  /// After a lock: unlock, open a tab again (the lock closed every tab) and
  /// see whether a new conflict is asked about - the review's probe found it
  /// queued, for the rest of the session, behind a question the lock had hidden.
  const askedAfterUnlock = async (app, how) => {
    const { page } = app;
    await unlockVault(page);
    await openFilesTab(page);
    await ev(page, 'ec', 'c.conf', CONFLICT('c1', 'changed'));
    const s = await conflictPrompt(page);
    yes(`H1-lock after ${how} and unlocking, a new conflict is asked about`, s.open && /c\.conf/.test(s.title), JSON.stringify(s));
    check('H1-lock and no question from before the lock waits behind it', s.queue, '');
  };

  for (const [how, lock] of LOCK_PATHS) {
    await withFiles(browser, server, spec, `H1-lock two questions, then ${how}`, async (app) => {
      const { page } = app;
      await openFilesTab(page);
      await twoWaiting(page);
      await lock(page);
      await settle(page, 250);
      check(`H1-lock ${how} locks the vault and closes the prompt`,
        [await page.evaluate(() => state.unlocked), await app.open('editConflictModal')], [false, false]);
      // An event still on its way for a session the lock closed.
      await ev(page, 'ed', 'a.conf', CONFLICT('a9', 'changed'));
      check('H1-lock a late conflict of a closed session asks nothing', await app.open('editConflictModal'), false);
      await askedAfterUnlock(app, how);
      check('nothing was answered for the files of before', await app.count('sftp_edit_resolve'), 0);
      check('no page errors', app.errors, []);
    });
  }

  // The lock settles every dialog before its round trip (lockNow), while the
  // vault still reads as unlocked and the tabs are still open: every question
  // goes then - not only once the vault reports locked and the tabs close.
  await withFiles(browser, server, spec, 'H1-lock every question goes as the lock starts', async (app) => {
    const { page } = app;
    await openFilesTab(page);
    await twoWaiting(page);
    await hold(page, 'vault_lock');
    await page.keyboard.press('Control+l');
    await settle(page, 150);
    check('H1-lock the prompt closes as the lock starts', await app.open('editConflictModal'), false);
    await ev(page, 'ec', 'c.conf', CONFLICT('c1', 'changed'));
    const s = await conflictPrompt(page);
    check('H1-lock no question from before the lock is left waiting, even before the vault reports locked',
      [s.open && /c\.conf/.test(s.title), s.queue], [true, '']);
    await letGo(page, 'vault_lock');
    await settle(page, 250);
    check('and once the lock is through, that one goes too',
      [await page.evaluate(() => state.unlocked), await app.open('editConflictModal')], [false, false]);
    check('nothing was answered', await app.count('sftp_edit_resolve'), 0);
    check('no page errors', app.errors, []);
  });

  await withFiles(browser, server, spec, 'H1-lock a closed tab takes its questions along', async (app) => {
    const { page } = app;
    await openFilesTab(page, { tabId: 't2' });
    await openFilesTab(page);
    await ev(page, 'ea', 'a.conf', CONFLICT('a1', 'changed'));
    await ev(page, 'eb', 'b.conf', CONFLICT('b1', 'changed'), 'sess-t2');
    // closeSessionTab and clearConnectView close tabs without onSessionClosed.
    await page.evaluate(() => closeSessionTab('t1', { skipConfirm: true }));
    await settle(page, 150);
    const s = await conflictPrompt(page);
    yes('H1-lock closing a tab drops the question about its file, and the other tab\'s file is asked about',
      s.open && /b\.conf/.test(s.title) && s.queue === '', JSON.stringify(s));
    await page.evaluate(() => clearConnectView());
    await settle(page, 150);
    check('H1-lock closing every tab at once (clearConnectView) leaves no question', (await conflictPrompt(page)).open, false);
    await openFilesTab(page);
    await ev(page, 'ec', 'c.conf', CONFLICT('c1', 'changed'));
    const t = await conflictPrompt(page);
    yes('and a later conflict is asked about', t.open && /c\.conf/.test(t.title) && t.queue === '', JSON.stringify(t));
    check('no page errors', app.errors, []);
  });

  await withFiles(browser, server, spec, 'H1-lock a hidden prompt holds no place', async (app) => {
    const { page } = app;
    await openFilesTab(page);
    await ev(page, 'ea', 'a.conf', CONFLICT('a1', 'changed'));
    // Hidden without its closer (a lock hides every dialog, a closer that
    // threw included).
    await page.evaluate(() => { document.getElementById('editConflictModal').hidden = true; });
    await settle(page, 50);
    await ev(page, 'eb', 'b.conf', CONFLICT('b1', 'changed'));
    const s = await conflictPrompt(page);
    yes('H1-lock a conflict that comes while the prompt is hidden is asked about, not queued behind it',
      s.open && /b\.conf/.test(s.title), JSON.stringify(s));
    check('and the hidden question is asked again after it', s.queue, '1 more file needs an answer after this one.');
    check('no page errors', app.errors, []);
  });

  // Review N2: Cancel took the next file's question along - the second click
  // of a double-click, a second Enter, a second Escape. The page's clock is
  // held from here on, so "a moment" lasts until the test moves it on.
  const armedPair = async (page) => {
    await clockRuns(page);
    await openFilesTab(page);
    await ev(page, 'ea', 'a.conf', CONFLICT('a1', 'changed'));
    await ev(page, 'eb', 'b.conf', CONFLICT('b1', 'changed'));
    await clockHolds(page);
    await clockPasses(page, EDIT_ARM_MS);
  };
  const pressCancel = async (page) => {
    const c = await centre(page, '#editConflictCancelBtn');
    await page.mouse.click(c.x, c.y);
  };
  for (const [how, act] of [
    ['a double-click on Cancel', async (page) => {
      const c = await centre(page, '#editConflictCancelBtn');
      await page.mouse.dblclick(c.x, c.y);
    }],
    ['Enter twice on Cancel, 40 ms apart', async (page) => {
      await focusIs(page, 'editConflictCancelBtn');
      await page.keyboard.press('Enter');
      await page.waitForTimeout(40);
      await page.keyboard.press('Enter');
    }],
    ['Escape twice, 40 ms apart', async (page) => {
      await page.keyboard.press('Escape');
      await page.waitForTimeout(40);
      await page.keyboard.press('Escape');
    }],
    ['a double-click on the backdrop', (page) => page.mouse.dblclick(8, 8)],
  ]) {
    await withFiles(browser, server, Object.assign({}, spec, CLOCK_APP), `N2 ${how}`, async (app) => {
      const { page } = app;
      await armedPair(page);
      await act(page);
      await settle(page, 120);
      const s = await conflictPrompt(page);
      yes(`N2 ${how} dismisses a.conf only: b.conf is still asked about`, s.open && /b\.conf/.test(s.title), JSON.stringify(s));
      check('N2 Cancel on the next file waits a moment too (aria-disabled, still focusable)', s.cancelHeld, true);
      await clockPasses(page, EDIT_ARM_MS);
      check('then it takes a click', (await conflictPrompt(page)).cancelHeld, false);
      await pressCancel(page);
      await settle(page, 80);
      check('and Cancel dismisses b.conf', (await conflictPrompt(page)).open, false);
      check('nothing was answered', await app.count('sftp_edit_resolve'), 0);
      check('no page errors', app.errors, []);
    });
  }

  await withFiles(browser, server, Object.assign({}, spec, CLOCK_APP), 'N2 a lock while Cancel waits', async (app) => {
    const { page } = app;
    await armedPair(page);
    await pressCancel(page);
    await settle(page, 40);
    const s = await conflictPrompt(page);
    check('(set-up) b.conf is asked about, its Cancel held', [s.open && /b\.conf/.test(s.title), s.cancelHeld], [true, true]);
    await page.keyboard.press('Control+l');
    await settle(page, 250);
    check('N2 a lock in that moment still closes the prompt', await app.open('editConflictModal'), false);
    await clockRuns(page);
    await askedAfterUnlock(app, 'that lock');
    check('no page errors', app.errors, []);
  });
}

// ─── JU6b fix round 2: the transfer panel's height in a small window (N3) ───

async function scenarioQueueHeight(browser, server) {
  const handle = '#sftpQueuePanel .sftp-queuehandle';
  /// The panel's height and what its handle says about it.
  const queueOf = (page) => page.evaluate((sel) => {
    const h = document.querySelector(sel);
    const n = (a) => (h.getAttribute(a) === null ? null : Number(h.getAttribute(a)));
    return {
      h: Math.round(document.getElementById('sftpQueuePanel').getBoundingClientRect().height),
      now: n('aria-valuenow'), min: n('aria-valuemin'), max: n('aria-valuemax'),
    };
  }, handle);
  await withFiles(browser, server, LAYOUT_SPEC, 'N3 the transfer panel at a small height', async (app) => {
    const { page } = app;
    await page.setViewportSize({ width: 1600, height: 1000 });
    await openFilesTab(page);
    await emitJobs(page, LAYOUT_JOBS);
    await settle(page, 200);
    const roomy = await queueOf(page);
    await page.setViewportSize({ width: 880, height: 560 });
    await settle(page, 200);
    await page.focus(handle);
    const small = await queueOf(page);
    check('N3 at 880x560 the handle says the panel cannot grow there: its maximum is its height',
      [small.now, small.max], [small.h, small.h]);
    for (let i = 0; i < 3; i++) await page.keyboard.press('ArrowUp');
    await settle(page, 80);
    check('N3 ArrowUp there changes nothing', (await queueOf(page)).h, small.h);
    await page.setViewportSize({ width: 1600, height: 1000 });
    await settle(page, 200);
    check('N3 and leaves no height behind: in a larger window the panel is as tall as before', (await queueOf(page)).h, roomy.h);

    await page.setViewportSize({ width: 1100, height: 720 });
    await settle(page, 200);
    await page.focus(handle);
    const mid = await queueOf(page);
    await page.keyboard.press('ArrowUp');
    await settle(page, 60);
    const up = await queueOf(page);
    yes('N3 with room, ArrowUp raises the panel and the handle follows', up.h > mid.h && up.now === up.h, JSON.stringify([mid, up]));
    for (let i = 0; i < 25; i++) await page.keyboard.press('ArrowUp');
    await settle(page, 60);
    const top = await queueOf(page);
    check('N3 up to the maximum the handle gives, and no further', [top.h, top.now], [top.max, top.max]);
    check('no page errors', app.errors, []);
  });
}

// ─── JU6b fix round 2: names that pass for dots (review F4, the rest) ───────

async function scenarioDotNames(browser, server) {
  const SPACE_DOTS = ' ..';
  const DOTS_SPACE = '.. ';
  const LISU = '\uA4F8\uA4F8'; // LISU LETTER TONE MYA TI, twice
  const ZEROS = '\u0660\u0660'; // ARABIC-INDIC DIGIT ZERO, twice
  const CATALAN = 'col\u00B7lecci\u00F3.txt'; // a middle dot inside a word
  const YEAR = '\u0662\u0660\u0662\u0664.txt'; // 2024 in Arabic-Indic digits
  const GAPS = 'two  spaces.txt';
  const SPACE = ' ';
  const DOT_GAP = '. .'; // dots once its space is taken out
  const spec = {
    remote: {
      '/home/u': [SPACE_DOTS + '/', DOTS_SPACE + '/', LISU + '/', ZEROS + '/', DOT_GAP + '/', 'docs/', CATALAN, YEAR, GAPS, SPACE],
      ['/home/u/' + SPACE_DOTS]: [], ['/home/u/' + DOTS_SPACE]: [], ['/home/u/' + LISU]: [], ['/home/u/' + ZEROS]: [],
      ['/home/u/' + DOT_GAP]: [], '/home/u/docs': [],
    },
    local: { '/home/me': ['l1.txt'] },
  };
  /// A remote row by name: [name as shown, flagged?].
  const cell = (page, n) => page.evaluate((name) => {
    const tr = [...document.querySelectorAll('#sftpTbody-t1 tr.sftp-entry')].find((r) => r.dataset.name === name);
    return tr ? [tr.querySelector('.sftp-name').textContent, !!tr.querySelector('.sftp-name-flag')] : null;
  }, n);
  /// The centre of the remote row of `name` (an attribute selector would
  /// have to quote its spaces and look-alikes).
  const rowAt = (page, n) => page.evaluate((name) => {
    const tr = [...document.querySelectorAll('#sftpTbody-t1 tr.sftp-entry')].find((r) => r.dataset.name === name);
    const b = tr.getBoundingClientRect();
    return { x: b.left + b.width / 2, y: b.top + b.height / 2 };
  }, n);
  await withFiles(browser, server, spec, 'F4 names that pass for dots', async (app) => {
    const { page } = app;
    await emulateWindowsDragDrop(page);
    await openFilesTab(page, { tab: { showHidden: true } });
    check('F4 a leading space is spelled out, and the name flagged', await cell(page, SPACE_DOTS), ['<U+0020>..', true]);
    check('F4 so is a trailing one (shown with hidden files on)', await cell(page, DOTS_SPACE), ['..<U+0020>', true]);
    check('F4 a name of look-alike dots (U+A4F8) is spelled out and flagged', await cell(page, LISU), ['<U+A4F8><U+A4F8>', true]);
    check('F4 so is one of Arabic-Indic zeros, which pass for dots', await cell(page, ZEROS), ['<U+0660><U+0660>', true]);
    check('F4 dots with a single space between are flagged (dots once the space is taken out)', await cell(page, DOT_GAP), [DOT_GAP, true]);
    check('F4 two spaces in a row are spelled out', await cell(page, GAPS), ['two<U+0020><U+0020>spaces.txt', true]);
    check('F4 a name of a space alone is spelled out and flagged', await cell(page, SPACE), ['<U+0020>', true]);
    check('F4 an empty name is flagged too', await page.evaluate(() => [sftpUnusualName(''), sftpUnusualNote('')]),
      [true, 'Unusual name: it is empty.']);
    check('F4 a middle dot inside a word is left as it is', await cell(page, CATALAN), [CATALAN, false]);
    check('F4 and so are Arabic-Indic digits in a name', await cell(page, YEAR), [YEAR, false]);

    await openDual(page);
    await mouseDrag(page, localRow('l1.txt'), await rowAt(page, SPACE_DOTS));
    yes('F4 a local file dropped on such a folder asks first', await waitVisible(page, '#confirmModal'));
    const asked = (await page.textContent('#confirmMessage')) || '';
    check('saying which folder that is, spelled out, and why it asks', plain(asked),
      'Upload "l1.txt" into the folder "<U+0020>.." inside /home/u? Unusual name: <U+0020>.. - only dots, or characters that look like dots, so it can read as a way up.');
    yes('the name in that note is kept to itself as well', asked.includes('Unusual name: \u2068<U+0020>..\u2069'), JSON.stringify(asked));
    check('and nothing is queued before the answer', (await queueAdds(app)).length, 0);
    await page.click('#confirmCancelBtn');
    await settle(page, 150);
    check('F4 Cancel uploads nothing', (await queueAdds(app)).length, 0);
    await mouseDrag(page, localRow('l1.txt'), await rowAt(page, LISU));
    yes('(set-up) asked again for the other folder', await waitVisible(page, '#confirmModal'));
    await page.click('#confirmOkBtn');
    await settle(page, 300);
    check('F4 OK uploads into that folder', (await queueAdds(app)).map((a) => a.items.map((i) => i.remote)), [['/home/u/' + LISU + '/l1.txt']]);
    const at = await rowAt(page, DOTS_SPACE);
    // Not awaited: the drop handler waits for the answer.
    await page.evaluate((p) => { window.__dragDrop({ payload: { type: 'drop', paths: ['/home/me/os.txt'], position: p } }); }, at);
    yes('F4 so does a file dropped on it from the system', await waitVisible(page, '#confirmModal'));
    await page.click('#confirmCancelBtn');
    await settle(page, 150);
    check('and Cancel uploads nothing from there either', (await queueAdds(app)).length, 1);
    await mouseDrag(page, localRow('l1.txt'), remoteRow('docs'));
    await settle(page, 300);
    check('a folder with a plain name takes the drop without a question, as before',
      [await app.open('confirmModal'), (await queueAdds(app)).slice(1).map((a) => a.items.map((i) => i.remote))], [false, [['/home/u/docs/l1.txt']]]);

    await page.evaluate((p) => sftpUiNavigateRemote('t1', p), '/home/u/' + LISU);
    await settle(page, 250);
    check('F4 inside such a folder, the path above the list spells it out too', (await crumbsOf(page)).current, '<U+A4F8><U+A4F8>');
    // A path is spelled out name by name: through that folder it does not
    // read as "/home/u/../app.conf".
    await page.evaluate((r) => window.__emit('sftp-edit-sync', Object.assign({ sessionId: 'sess-t1', editId: 'ez', remote: r },
      { ok: false, conflict: true, conflictId: 'z1', reason: 'changed', remoteSize: 1, remoteModifiedMs: 1700000000000 })), '/home/u/' + LISU + '/app.conf');
    yes('F4 a path through such a folder is spelled out in it too',
      (await page.textContent('#editConflictServer')).includes('/home/u/<U+A4F8><U+A4F8>/app.conf'), await page.textContent('#editConflictServer'));
    await page.click('#editConflictCancelBtn');
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
  ['JU6b layout: rows, queue, Split, More (A1-01 A1-02 A1-03 A5-07)', scenarioLayout],
  ['JU6b splitters (A1-15)', scenarioSplitters],
  ['JU6b cells, styles and dialog bits (A1-16 A1-17 A1-31 A1-28 A1-34)', scenarioTableCells],
  ['JU6b pointer drag and drop (Task 16 A3-23 SC 2.5.7)', scenarioPointerDnd],
  ['JU6b one sftp_open per tab (A5-12)', scenarioSessionMode],
  ['JU6b edit conflicts (A7-19)', scenarioEditConflict],
  ['JU6b settings that cannot be saved (JU2 leftover)', scenarioSettingsRevert],
  ['JU6b item 8: every setting the file browser saves reverts when refused', scenarioEverySettingReverts],
  ['JU6b the cache after a change (JU1 leftover)', scenarioMutationCache],
  ['JU6b fix round: edit conflicts one file at a time (H1 L2 F3 L7)', scenarioEditConflictQueue],
  ['JU6b fix round: the cache after a move, chmod and rename (L7)', scenarioCacheAfterChanges],
  ['JU6b fix round 2: the questions, the vault lock and closed tabs (H1-lock N2)', scenarioEditConflictLock],
  ['JU6b fix round 2: the transfer panel\'s height in a small window (N3)', scenarioQueueHeight],
  ['JU6b fix round 2: names that pass for dots (F4)', scenarioDotNames],
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
