#!/usr/bin/env node
/*
 * Drives the real renderer in headless Chromium and asserts the behaviour of
 * two paths that have failed silently before: the key list's grouped view and
 * the "use this key to connect..." host picker.
 *
 * The static checkers next to this one can only find shapes we have already
 * been burned by - a call to a function that does not exist, a name declared
 * twice. Neither would have caught a key list that renders nothing because it
 * read .parent_id off a string, because that is valid JavaScript producing a
 * page that merely looks empty. Driving the page is the only way to tell an
 * empty list from a broken one.
 *
 * Run with `npm run test:ui`. Needs playwright, which is not a devDependency
 * because only this one script uses it:
 *
 *     npm install --no-save playwright@1.56.1 && npx playwright install chromium
 *
 * Without it this skips (exit 0) rather than failing, so a checkout that has
 * not set it up still runs every other check.
 */
'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');

let chromium;
try {
  ({ chromium } = require('playwright'));
} catch {
  try {
    ({ chromium } = require(path.join(
      require('child_process').execSync('npm root -g', { encoding: 'utf8' }).trim(), 'playwright')));
  } catch {
    console.log('playwright not installed - skipping renderer UI checks.');
    process.exit(0);
  }
}

const ROOT = path.join(__dirname, '..', 'src', 'renderer');
const TYPES = {
  '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css',
  '.svg': 'image/svg+xml', '.png': 'image/png', '.woff2': 'font/woff2',
};

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

/// Serve src/renderer over http: file:// would block the module loads.
function serve() {
  const server = http.createServer((req, res) => {
    const rel = decodeURIComponent(req.url.split('?')[0]).replace(/^\/+/, '') || 'index.html';
    const file = path.join(ROOT, rel);
    if (!file.startsWith(ROOT) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) {
      res.writeHead(404); res.end('not found'); return;
    }
    res.writeHead(200, { 'Content-Type': TYPES[path.extname(file)] || 'application/octet-stream' });
    res.end(fs.readFileSync(file));
  });
  return new Promise(resolve => server.listen(0, '127.0.0.1', () => resolve(server)));
}

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

const KEY = (id, name, cats) => ({
  id, name, key_type: 'ed25519', has_private: true,
  fingerprint: 'SHA256:' + id, comment: '', category_ids: cats,
});
const SRV = (id, name, host, categoryId) => ({
  id, name, host, port: 22, username: 'root', categoryId, authMethod: 'publickey',
});

// ─── key list: the grouped "all categories" view ───────────────────────────

async function checkKeyListGrouping(browser, server) {
  console.log('key list, grouped view');
  const keys = [
    KEY('a', 'eu-root', ['eu']), KEY('b', 'eu-nested', ['prod']),
    KEY('c', 'asia', ['asia']), KEY('d', 'both', ['eu', 'asia']),
    KEY('e', 'orphaned', ['lost']), KEY('f', 'loose-1', []),
    KEY('g', 'loose-2', []), KEY('h', 'ghost-cat', ['deleted-cat']),
  ];
  const { page, errors } = await openPage(browser, server, {
    vault_status: { hasVault: true, unlocked: true },
    key_list: { keys },
    category_list: {
      categories: [
        { id: 'eu',   name: 'EU DC1',    parent_id: null,   scope: 'key',  sort_index: 0, color: null },
        { id: 'prod', name: 'Prod',      parent_id: 'eu',   scope: 'key',  sort_index: 0, color: null },
        { id: 'asia', name: 'Asia DC1',  parent_id: null,   scope: 'key',  sort_index: 1, color: null },
        { id: 'lost', name: 'Orphan',    parent_id: 'gone', scope: 'key',  sort_index: 2, color: null },
        { id: 'hosts',name: 'Hosts',     parent_id: null,   scope: 'host', sort_index: 0, color: null },
      ],
      allKeyCategories: { a: ['eu'], b: ['prod'], c: ['asia'], d: ['eu', 'asia'], e: ['lost'], h: ['deleted-cat'] },
      orphans: true, hostOrphans: false,
    },
    server_list: { servers: [] },
    settings_get: {},
  });

  const shape = await page.evaluate(() =>
    Array.from(document.querySelectorAll('#keyList .key-group')).map(g => ({
      name: g.querySelector('.key-group-name').textContent,
      keys: Array.from(g.querySelectorAll('.key-row')).map(r => r.dataset.id),
    })));

  // The regression this file exists for: every key must be reachable in the
  // default view, categorized or not.
  check('every key is visible with no category filter',
    Array.from(new Set(shape.flatMap(g => g.keys))).sort(), keys.map(k => k.id).sort());
  check('groups follow root sort order; a key under two roots shows in both; uncategorized last', shape, [
    { name: 'EU DC1',        keys: ['a', 'b', 'd'] },
    { name: 'Asia DC1',      keys: ['c', 'd'] },
    { name: 'Orphan',        keys: ['e'] },           // parent id points at nothing
    { name: 'Uncategorized', keys: ['f', 'g', 'h'] }, // 'h' names a deleted category
  ]);
  check('no group header is repeated', shape.length, new Set(shape.map(g => g.name)).size);
  check('no page errors', errors, []);
  await page.close();
}

// ─── connect picker: key -> category -> ... -> host ────────────────────────

async function checkConnectPicker(browser, server) {
  console.log('connect picker');
  const servers = [
    SRV('s1', 'eu-da-mx', '10.0.0.1', 'h-eu'),
    SRV('s2', 'fra-web-1', '10.0.1.1', 'h-fra'),
    SRV('s3', 'fra-web-2', '10.0.1.2', 'h-fra'),
    SRV('s4', 'ams-db', '10.0.2.1', 'h-ams'),
    SRV('s5', 'us-slc', '10.1.0.1', 'h-us'),
    SRV('s6', 'no-category', '10.2.0.1', null),
    SRV('s7', 'stale-cat', '10.2.0.2', 'gone'),
    SRV('s8', 'in-a-cycle', '10.9.9.9', 'cyc-a'),
    SRV('s9', 'key-scope-cat', '10.8.8.8', 'k-work'),
  ];
  const { page, errors } = await openPage(browser, server, {
    vault_status: { hasVault: true, unlocked: true },
    key_list: { keys: [KEY('k1', 'da-mx-eu', [])] },
    category_list: {
      categories: [
        { id: 'h-eu',    name: 'Europe',    parent_id: null,    scope: 'host', sort_index: 0, color: null },
        { id: 'h-fra',   name: 'Frankfurt', parent_id: 'h-eu',  scope: 'host', sort_index: 0, color: null },
        { id: 'h-ams',   name: 'Amsterdam', parent_id: 'h-eu',  scope: 'host', sort_index: 1, color: null },
        { id: 'h-us',    name: 'Americas',  parent_id: null,    scope: 'host', sort_index: 1, color: null },
        { id: 'h-empty', name: 'Retired',   parent_id: null,    scope: 'host', sort_index: 2, color: null },
        { id: 'cyc-a',   name: 'CycA',      parent_id: 'cyc-b', scope: 'host', sort_index: 3, color: null },
        { id: 'cyc-b',   name: 'CycB',      parent_id: 'cyc-a', scope: 'host', sort_index: 4, color: null },
        { id: 'k-work',  name: 'Work keys', parent_id: null,    scope: 'key',  sort_index: 0, color: null },
      ],
      allKeyCategories: {}, orphans: true, hostOrphans: true,
    },
    server_list: { servers },
    settings_get: {},
  });

  // Nothing but switchView('connect') loads the server list, so this is the
  // state a user is in until they open that view: the picker has to cope.
  check('the server list is not loaded before the picker runs',
    await page.evaluate(() => state.servers.length), 0);

  const openPicker = () => page.evaluate(() => {
    document.querySelector('#keyList .key-row').dispatchEvent(
      new MouseEvent('contextmenu', { bubbles: true, cancelable: true, clientX: 300, clientY: 400 }));
    document.getElementById('keyConnectMenu').querySelector('.ctx-item').click();
  });
  await openPicker();
  await page.waitForTimeout(150);

  check('the view does not change when the picker opens',
    await page.evaluate(() => state.view), 'keys');
  check('the picker loads the server list itself',
    await page.evaluate(() => state.servers.length), servers.length);
  check('the menu opens at the cursor',
    await page.evaluate(() => {
      const r = document.getElementById('keyConnectMenu').getBoundingClientRect();
      return { left: Math.round(r.left), top: Math.round(r.top) };
    }), { left: 300, top: 400 });

  const tree = await page.evaluate(() => {
    const t = hostPickerTree();
    const reached = [];
    (function walk(ns) { for (const n of ns) { for (const h of n.hosts) reached.push(h.id); walk(n.children); } })(t.roots);
    return {
      all: reached.concat(t.loose.map(s => s.id)).sort(),
      unique: new Set(reached.concat(t.loose.map(s => s.id))).size,
      loose: t.loose.map(s => s.id).sort(),
      roots: t.roots.map(n => [n.cat.name, n.total]),
    };
  });
  check('every server is reachable through the picker', tree.all, servers.map(s => s.id).sort());
  check('no server is listed twice', tree.unique, servers.length);
  check('uncategorized, stale, cyclic and wrong-scope servers fall to the top level',
    tree.loose, ['s6', 's7', 's8', 's9']);
  check('empty categories are pruned and counts are recursive',
    tree.roots, [['Europe', 4], ['Americas', 1]]);

  // Hovering a category opens its flyout; hovering one inside that opens another.
  const depths = await page.evaluate(async () => {
    const hover = (root, label) => Array.from(root.querySelectorAll('.ctx-item'))
      .find(b => b.textContent.includes(label))
      .dispatchEvent(new MouseEvent('mouseenter'));
    hover(document.getElementById('keyConnectMenu'), 'Europe');
    await new Promise(r => setTimeout(r, 30));
    hover(document.querySelector('.ctx-submenu[data-depth="1"]'), 'Frankfurt');
    await new Promise(r => setTimeout(r, 30));
    return Array.from(document.querySelectorAll('.ctx-menu')).map(m => ({
      depth: m.dataset.depth ?? '0',
      rows: Array.from(m.querySelectorAll(':scope > .ctx-item')).map(b => b.dataset.host || b.textContent.trim()),
    }));
  });
  check('a nested category opens a second level of flyout', depths.length, 3);
  check('the deepest flyout holds that category\'s hosts',
    depths[2].rows.map(t => t.split(' ')[0]), ['fra-web-1', 'fra-web-2']);

  check('Escape closes the whole chain', await (async () => {
    await page.keyboard.press('Escape');
    await page.waitForTimeout(60);
    return page.evaluate(() => document.querySelectorAll('.ctx-menu').length);
  })(), 0);

  // A click inside the menu must not dismiss it.
  await openPicker();
  await page.waitForTimeout(150);
  const row = await page.evaluate(() => {
    const b = Array.from(document.getElementById('keyConnectMenu').querySelectorAll('.ctx-item'))
      .find(x => x.textContent.includes('Europe')).getBoundingClientRect();
    return { x: Math.round(b.left + b.width / 2), y: Math.round(b.top + b.height / 2) };
  });
  await page.mouse.click(row.x, row.y);
  await page.waitForTimeout(120);
  check('clicking a category opens its flyout and keeps the menu open',
    await page.evaluate(() => document.querySelectorAll('.ctx-menu').length), 2);
  await page.mouse.click(1200, 820);
  await page.waitForTimeout(120);
  check('clicking away closes everything',
    await page.evaluate(() => document.querySelectorAll('.ctx-menu').length), 0);
  check('no page errors', errors, []);
  await page.close();
}

// ─── SFTP local pane: selection, context menu, column toggle ───────────────

async function checkSftpLocalPane(browser, server) {
  console.log('sftp local pane');
  const { page, errors } = await openPage(browser, server, {
    vault_status: { hasVault: true, unlocked: true },
    key_list: { keys: [KEY('k1', 'a-key', [])] },
    category_list: { categories: [], allKeyCategories: {}, orphans: false, hostOrphans: false },
    server_list: { servers: [] },
    settings_get: {},
    // Stub reply for the fake sftp_local_list IPC - a Windows-shaped path so
    // the separator handling gets exercised, with no real user in it.
    sftp_local_list: {
      path: 'C:\\Users\\example', home: 'C:\\Users\\example',
      entries: [
        { name: '.anaconda', isDir: true, size: null, modifiedMs: 1756075901000 },
        { name: '.bun', isDir: true, size: null, modifiedMs: 1777576926000 },
        { name: 'notes.txt', isDir: false, size: 1234, modifiedMs: 1777576926000 },
      ],
    },
    // Remote side needs real rows too: the Ctrl+A check below proves the
    // shortcut switches panes, which needs something on both sides.
    sftp_list_dir: {
      path: '/',
      entries: [
        { name: 'etc', isDir: true, size: null, modifiedMs: 1756075901000 },
        { name: 'var', isDir: true, size: null, modifiedMs: 1756075901000 },
      ],
    },
    sftp_bookmarks_list: { bookmarks: [] },
    sftp_queue_list: { jobs: [] },
  });

  const built = await page.evaluate(async () => {
    const tabId = 't1';
    // Pane-scoped shortcuts (Ctrl+A) resolve the active tab, so the harness has
    // to name one - the same thing activateSessionTab does in the real app.
    state.activeTabId = tabId;
    state.sessions.set(tabId, {
      tabId, sessionId: 'sess', serverId: 'srv', serverName: 'host',
      host: '10.0.0.1', port: 22, mode: 'sftp', sftpReady: true, sftpPath: '/', ended: false,
    });
    const panel = buildSftpPanel(tabId);
    document.getElementById('sftpBody').appendChild(panel);
    panel.style.display = 'flex';
    document.getElementById('sftpBody').classList.add('visible');
    // buildSftpPanel wires the toolbar but does not fetch; the real app calls
    // this on connect. Needed here so the remote side has rows for the
    // pane-scoped Ctrl+A check.
    await refreshSftpPanel(tabId);
    toggleDualPane(tabId);                       // open the local pane
    await new Promise(r => setTimeout(r, 300));
    const tbody = document.getElementById('sftpLocalTbody-' + tabId);
    return tbody ? tbody.querySelectorAll('tr.sftp-entry').length : 0;
  });
  check('the local pane lists its entries', built, 3);

  // A right-click that nothing handles falls through to the webview's own
  // Back/Reload/Save-as menu, which is what users saw here.
  const ctx = await page.evaluate(async () => {
    const rows = document.querySelectorAll('#sftpLocalTbody-t1 tr.sftp-entry');
    const ev = new MouseEvent('contextmenu', { bubbles: true, cancelable: true, clientX: 200, clientY: 300 });
    rows[0].dispatchEvent(ev);
    await new Promise(r => setTimeout(r, 60));
    const menu = document.getElementById('keyConnectMenu');
    return {
      prevented: ev.defaultPrevented,
      items: menu ? Array.from(menu.querySelectorAll('.ctx-item')).map(b => b.textContent.trim()) : [],
      selected: document.querySelectorAll('#sftpLocalTbody-t1 tr.selected').length,
    };
  });
  check('a right-click on a local row suppresses the webview menu', ctx.prevented, true);
  // The local pane offers file management now: rename/delete/open-folder for a
  // row, new-folder on empty space. It previously carried only Open/Upload/
  // Copy path because the backend had no local mutation commands at all.
  check('it opens the app menu for a folder', ctx.items,
    ['Open', 'Upload folder', 'Copy path', 'Rename...', 'Delete', 'Open in file manager', 'Refresh']);
  check('and retargets the selection to the row under the pointer', ctx.selected, 1);

  const empty = await page.evaluate(async () => {
    closeKeyConnectMenu();
    const wrap = document.querySelector('#sftpLocalPane-t1 .sftp-tablewrap');
    const ev = new MouseEvent('contextmenu', { bubbles: true, cancelable: true, clientX: 200, clientY: 700 });
    wrap.dispatchEvent(ev);
    await new Promise(r => setTimeout(r, 60));
    const menu = document.getElementById('keyConnectMenu');
    return {
      prevented: ev.defaultPrevented,
      items: menu ? Array.from(menu.querySelectorAll('.ctx-item')).map(b => b.textContent.trim()) : [],
    };
  });
  check('the empty space below the rows is covered too', empty.prevented, true);
  check('with a directory-level menu', empty.items,
    ['Parent directory', 'Copy current path', 'Set as default local directory', 'New folder...', 'Refresh']);

  const sel = await page.evaluate(async () => {
    closeKeyConnectMenu();
    const rows = document.querySelectorAll('#sftpLocalTbody-t1 tr.sftp-entry');
    rows[0].click();
    const after1 = document.querySelectorAll('#sftpLocalTbody-t1 tr.selected').length;
    rows[2].dispatchEvent(new MouseEvent('click', { bubbles: true, shiftKey: true }));
    const afterShift = document.querySelectorAll('#sftpLocalTbody-t1 tr.selected').length;
    const ev = new MouseEvent('contextmenu', { bubbles: true, cancelable: true, clientX: 200, clientY: 300 });
    rows[2].dispatchEvent(ev);
    await new Promise(r => setTimeout(r, 60));
    const menu = document.getElementById('keyConnectMenu');
    return {
      after1, afterShift,
      items: menu ? Array.from(menu.querySelectorAll('.ctx-item')).map(b => b.textContent.trim()) : [],
      status: (document.getElementById('sftpStatusLeft-t1') || {}).textContent || '',
    };
  });
  check('a plain click selects one row', sel.after1, 1);
  check('shift-click extends the range', sel.afterShift, 3);
  check('the menu acts on the whole selection', sel.items,
    ['Upload 3 items', 'Copy 3 paths', 'Delete 3 items', 'Open containing folder', 'Refresh']);
  check('the status bar counts the local selection', /local: 3 items, 3 selected/.test(sel.status), true);

  // Ctrl+A follows the pane last clicked: clicking a local row then pressing
  // Ctrl+A must select every local entry, not the remote listing. The handler
  // only ever touched the remote selection before.
  const selectAll = await page.evaluate(async () => {
    closeKeyConnectMenu();
    const localRows = document.querySelectorAll('#sftpLocalTbody-t1 tr.sftp-entry');
    localRows[0].click();
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'a', ctrlKey: true, bubbles: true }));
    await new Promise(r => setTimeout(r, 60));
    const localSelected = document.querySelectorAll('#sftpLocalTbody-t1 tr.selected').length;
    const remoteSelected = document.querySelectorAll('#sftpTbody-t1 tr.selected').length;
    // Now click a REMOTE row and repeat: the same shortcut must target remote.
    const remoteRows = document.querySelectorAll('#sftpTbody-t1 tr.sftp-entry');
    if (remoteRows.length) remoteRows[0].click();
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'a', ctrlKey: true, bubbles: true }));
    await new Promise(r => setTimeout(r, 60));
    return {
      localSelected,
      remoteSelected,
      afterRemoteClick: document.querySelectorAll('#sftpTbody-t1 tr.selected').length,
    };
  });
  check('Ctrl+A selects every local entry when the local pane has focus', selectAll.localSelected, 3);
  check('and leaves the remote selection alone', selectAll.remoteSelected, 0);
  check('Ctrl+A follows the pointer back to the remote pane',
    selectAll.afterRemoteClick > 0, true);

  // The Columns button flips .show-owner-cols on the panel; nothing read it.
  const cols = await page.evaluate(async () => {
    closeKeyConnectMenu();
    const panel = document.getElementById('sftpPanel-t1');
    const btn = Array.from(panel.querySelectorAll('.sftp-toolbar .ghost-btn'))
      .find(b => b.textContent.trim() === 'Columns');
    const cell = panel.querySelector('.col-extra');
    const before = getComputedStyle(cell).display;
    btn.click();
    await new Promise(r => setTimeout(r, 40));
    const off = getComputedStyle(cell).display;
    btn.click();
    await new Promise(r => setTimeout(r, 40));
    return { before, off, on: getComputedStyle(cell).display };
  });
  check('permissions/owner columns start visible', cols.before, 'table-cell');
  check('the Columns button actually hides them', cols.off, 'none');
  check('and brings them back', cols.on, 'table-cell');
  check('no page errors', errors, []);
  await page.close();
}

// ─── transfer queue: grouped by server, then by remote directory ───────────

async function checkQueueGrouping(browser, server) {
  console.log('transfer queue grouping');
  const { page, errors } = await openPage(browser, server, {
    vault_status: { hasVault: true, unlocked: true },
    key_list: { keys: [KEY('k1', 'a-key', [])] },
    category_list: { categories: [], allKeyCategories: {}, orphans: false, hostOrphans: false },
    server_list: { servers: [] },
    settings_get: {},
    sftp_queue_list: { jobs: [] },
  });

  // Oldest first, the order queueJobs itself holds.
  const JOB = (id, server, remotePath, state, extra) => Object.assign({
    id, kind: 'upload', serverName: server, remotePath,
    localPath: '/tmp/' + id, size: 1000, bytesDone: 0, state,
  }, extra || {});
  const jobs = [
    JOB('1', 'us-slc', '/root/dump.sql', 'done', { kind: 'download', bytesDone: 1000 }),
    JOB('2', 'eu-da-mx', '/var/www/html/index.php', 'queued'),
    JOB('3', 'eu-da-mx', '/var/www/html/app.js', 'active', { bytesDone: 500 }),
    JOB('4', 'eu-da-mx', '/var/www/html/css/site.css', 'queued'),
    JOB('5', 'eu-da-mx', '/var/www/html/css/img/logo.png', 'queued'),
    JOB('6', 'eu-da-mx', '/var/www/README.md', 'queued'),
    JOB('7', 'eu-da-mx', '/top-level.txt', 'queued'),
  ];

  const draw = () => page.evaluate(() =>
    Array.from(document.getElementById('sftpQueueList').children).map((el) => {
      const depth = Number(getComputedStyle(el).getPropertyValue('--q-depth')) || 0;
      if (el.classList.contains('sftp-queuegroup')) {
        return { depth, kind: el.classList.contains('q-group-server') ? 'server' : 'dir',
                 label: el.querySelector('.q-grouplabel').textContent,
                 count: Number(el.querySelector('.q-groupcount').textContent),
                 collapsed: el.classList.contains('collapsed') };
      }
      return { depth, kind: 'job', label: el.querySelector('.q-name').textContent.trim() };
    }));

  await page.evaluate((jobs) => {
    queueJobs.clear();
    for (const j of jobs) queueJobs.set(j.id, j);
    const panel = buildQueuePanel();
    document.getElementById('sftpBody').appendChild(panel);
    panel.style.display = 'flex';
    document.getElementById('sftpBody').classList.add('visible');
    queueTab = 'queued';
    renderQueuePanel();
  }, jobs);

  check('the queue nests server > folder > file', await draw(), [
    { depth: 0, kind: 'server', label: 'eu-da-mx', count: 6, collapsed: false },
    // A run of folders holding nothing but one subfolder collapses to one row.
    { depth: 1, kind: 'dir', label: 'var/www', count: 5, collapsed: false },
    { depth: 2, kind: 'dir', label: 'html', count: 4, collapsed: false },
    { depth: 3, kind: 'dir', label: 'css', count: 2, collapsed: false },
    { depth: 4, kind: 'dir', label: 'img', count: 1, collapsed: false },
    { depth: 5, kind: 'job', label: 'logo.png' },
    // Files sit beside the subfolders at their own level, not after all of them.
    { depth: 4, kind: 'job', label: 'site.css' },
    { depth: 3, kind: 'job', label: 'app.js' },
    { depth: 3, kind: 'job', label: 'index.php' },
    { depth: 2, kind: 'job', label: 'README.md' },
    { depth: 1, kind: 'job', label: 'top-level.txt' },
  ]);

  // Only the filename indents; the progress columns stay in one line.
  check('indentation does not move the progress column', await page.evaluate(() => {
    const lefts = Array.from(document.querySelectorAll('#sftpQueueList .sftp-queueitem .q-prog'))
      .map(c => Math.round(c.getBoundingClientRect().left));
    return new Set(lefts).size;
  }), 1);

  const collapsed = await page.evaluate(async () => {
    Array.from(document.querySelectorAll('.sftp-queuegroup'))
      .find(r => r.querySelector('.q-grouplabel').textContent === 'css').click();
    await new Promise(r => setTimeout(r, 40));
    return Array.from(document.getElementById('sftpQueueList').children).length;
  });
  check('collapsing a folder hides its whole branch', collapsed, 8); // 11 - css's 3 rows

  check('the collapse survives a progress redraw', await page.evaluate(async () => {
    renderQueuePanel();
    await new Promise(r => setTimeout(r, 40));
    return Array.from(document.querySelectorAll('.sftp-queuegroup.collapsed'))
      .map(r => r.querySelector('.q-grouplabel').textContent);
  }), ['css']);

  // The Done tab is a different job set; the same grouping has to apply.
  check('the other tabs group too', await page.evaluate(async () => {
    queueTab = 'done';
    renderQueuePanel();
    await new Promise(r => setTimeout(r, 40));
    return Array.from(document.getElementById('sftpQueueList').children).map(el =>
      el.classList.contains('sftp-queuegroup')
        ? el.querySelector('.q-grouplabel').textContent
        : el.querySelector('.q-name').textContent.trim());
  }), ['us-slc', 'root', 'dump.sql']);

  check('no page errors', errors, []);
  await page.close();
}

// ─── UX refactor: nav shape, palette, selection/deploy, export, settings ───
//
// These cover the surfaces the 2026 UX pass introduced. They exist for the
// same reason as everything above: each one is a path that can break while
// still rendering a page that merely looks fine.

const UX_KEY = (id, name, extra) => Object.assign({
  id, name, key_type: 'ed25519', has_private: true, public_key: 'ssh-ed25519 AAAA' + id,
  fingerprint_sha256: 'SHA256:' + id, comment: name + '@host',
  created_at: '2026-09-01T10:00:00Z', deployed: false, bitwarden_sync: false, category_ids: [],
}, extra || {});

async function checkUxRefactor(browser, server) {
  console.log('ux: nav, palette, selection, export, settings');
  const keys = [
    UX_KEY('a', 'prod-deploy', { deployed: true, deploy_path: '~/.sshspan/keys/a' }),
    UX_KEY('b', 'staging'),
    UX_KEY('c', 'laptop'),
  ];
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
  await page.addInitScript(({ r }) => {
    window.__TAURI__ = {
      core: {
        invoke: async (cmd, args) => {
          if (cmd === 'key_get') return r.key_list.keys.find(k => k.id === args.id);
          return r[cmd] ?? {};
        },
      },
      event: { listen: async () => () => {} },
    };
  }, { r: {
    vault_status: { hasVault: true, unlocked: true },
    key_list: { keys },
    category_list: {
      categories: [{ id: 'p', name: 'Prod', parent_id: null, scope: 'key', sort_index: 0, color: null }],
      allKeyCategories: {}, orphans: true, hostOrphans: false,
    },
    server_list: { servers: [SRV('s1', 'web-1', '10.0.0.1', null), SRV('s2', 'db-1', '10.0.0.2', null)] },
    settings_get: { autoLockMinutes: 15, confirmDelete: true },
    known_hosts_list: { hosts: [] },
    audit_list: { entries: [] },
    system_paths: { deployDir: '~/.sshspan/keys', sshConfig: '~/.ssh/config', dataDir: '~/.sshspan/sshspan.db' },
  } });
  const errors = [];
  page.on('pageerror', e => errors.push(String(e.message || e)));
  await page.goto(`http://127.0.0.1:${server.address().port}/index.html`);
  await page.waitForSelector('#keyList .key-row', { timeout: 15000 });

  // Deploy and Audit are no longer destinations; both are still reachable.
  check('nav is two objects plus Settings',
    await page.$$eval('.nav-item', ns => ns.map(n => n.dataset.view)), ['keys', 'connect', 'settings']);
  check('the vault control shows the auto-lock countdown',
    /locks in \d+:\d\d/.test(await page.textContent('#vaultSub')), true);

  // The row's sub-line used to be the full fingerprint, which nobody scans by.
  check('a key row leads with its comment',
    await page.textContent('#keyList .key-row .key-row-sub'), 'prod-deploy@host');

  // The grouped view used to walk state.keys, so the search box did nothing
  // unless it matched zero keys.
  await page.fill('#searchInput', 'staging');
  check('the search box filters the grouped view',
    await page.$$eval('#keyList .key-row', rs => rs.map(r => r.dataset.id)), ['b']);
  await page.fill('#searchInput', '');

  // Export: its own tab, and a passphrase field only for the format using one.
  await page.click('#keyList .key-row');
  await page.waitForTimeout(80);
  check('the detail pane opens on Overview', await page.isVisible('#detailPanel-overview'), true);
  await page.click('.detail-tab[data-detail-tab="export"]');
  check('the passphrase field is hidden for an unencrypted format',
    await page.isHidden('#detailExportPass'), true);
  await page.click('.format-row[data-format="pkcs8-encrypted"]');
  check('and appears for the encrypted one', await page.isVisible('#detailExportPass'), true);
  check('every format is marked with what it hands you',
    await page.$$eval('.risk-chip', cs => cs.map(c => c.textContent)),
    ['Secret', 'Secret', 'Sealed', 'Secret', 'Public', 'Public']);
  await page.fill('#detailExportPass', 'unused');
  await page.click('.detail-tab[data-detail-tab="overview"]');
  check('leaving the Export tab clears a typed passphrase',
    await page.inputValue('#detailExportPass'), '');

  // Deploy is an action on the selection, with a preview that is live.
  check('the selection bar is hidden with nothing selected',
    await page.isHidden('#selectionBar'), true);
  await page.locator('#keyList .key-row .deploy-check').nth(0).click();
  await page.locator('#keyList .key-row .deploy-check').nth(1).click();
  check('it appears and counts the selection',
    await page.textContent('#selectionHint'), '2 keys selected');
  await page.click('#selDeployBtn');
  await page.waitForTimeout(120);
  check('Deploy opens a sheet carrying the selection',
    await page.$$eval('#deployKeyChips .cat-chip', cs => cs.map(c => c.textContent)),
    ['prod-deploy', 'staging']);
  const preview = await page.inputValue('#configPreview');
  check('the preview is populated before any button is pressed', preview.length > 0, true);
  // join('\\n') here rendered the two characters \n and put the whole config
  // on one line; deployConfig() a few lines away always used a real newline.
  check('the preview breaks lines instead of printing a literal backslash-n',
    preview.includes('\\n'), false);
  await page.fill('#cfgHost', 'prod-web-1');
  await page.waitForTimeout(80);
  check('and follows the form as you type',
    (await page.inputValue('#configPreview')).includes('Host prod-web-1'), true);
  await page.keyboard.press('Escape');
  check('Escape closes the sheet', await page.isHidden('#deployModal'), true);

  // One search across everything, where there used to be three boxes.
  await page.keyboard.press('Control+k');
  await page.waitForTimeout(150);
  check('the palette spans every kind of thing',
    await page.$$eval('.palette-group', gs => gs.map(g => g.textContent)),
    ['Servers', 'Keys', 'Categories', 'Actions']);
  await page.fill('#paletteInput', 'web-1');
  await page.waitForTimeout(80);
  check('a server is reachable from it',
    await page.$$eval('.palette-name', ns => ns.map(n => n.textContent)), ['web-1']);
  await page.keyboard.press('Escape');
  await page.waitForTimeout(80);
  check('Escape closes the palette', await page.isHidden('#paletteModal'), true);

  // Server rows carry their own live state and a way to act on it.
  await page.click('.nav-item[data-view="connect"]');
  await page.waitForTimeout(200);
  check('the view is called Servers', await page.textContent('#viewTitle'), 'Servers');
  check('each row shows connection state and a Connect button',
    await page.$$eval('.server-row', rs => rs.map(r => !!r.querySelector('.server-dot') && !!r.querySelector('.server-go'))),
    [true, true]);
  check('the surface control names all three surfaces',
    await page.$$eval('#termModeSeg .seg-btn', bs => bs.map(b => b.dataset.mode)), ['ssh', 'sftp', 'split']);

  // Settings is one page with a rail, and the audit log lives in it.
  await page.click('.nav-item[data-view="settings"]');
  await page.waitForTimeout(250);
  check('settings has a section rail including the audit log',
    await page.$$eval('.settings-nav-item', ns => ns.map(n => n.dataset.section)),
    ['general', 'vault', 'hosts', 'backup', 'sync', 'audit']);
  check('only one section shows at a time',
    await page.$$eval('.settings-section', ss => ss.filter(s => !s.hidden).length), 1);
  // Settings used to render bare browser checkboxes while the deploy options
  // one screen away used the styled toggle.
  check('no bare checkbox is left visible in settings',
    await page.$$eval('#settingsRows input[type=checkbox]',
      is => is.filter(i => getComputedStyle(i).opacity !== '0' && !i.classList.contains('toggle-input')).length), 0);
  check('every settings row states what it costs you',
    await page.$$eval('#settingsRows .settings-row',
      rs => rs.every(r => r.querySelector('.settings-row-title') && r.querySelector('.settings-row-sub'))), true);

  check('no page errors', errors, []);
  await page.close();
}

// ─── session surface: split view and the remote path breadcrumb ────────────

async function checkSessionSurface(browser, server) {
  console.log('session surface');
  const { page, errors } = await openPage(browser, server, {
    vault_status: { hasVault: true, unlocked: true },
    key_list: { keys: [UX_KEY('k1', 'a-key')] },
    category_list: { categories: [], allKeyCategories: {}, orphans: false, hostOrphans: false },
    server_list: { servers: [] },
    settings_get: {},
    sftp_list_dir: { entries: [], path: '/srv/api/releases' },
    sftp_bookmarks_list: { bookmarks: [] },
    sftp_queue_list: { jobs: [] },
    sftp_local_list: { path: '/home/u', home: '/home/u', entries: [] },
  });

  const built = await page.evaluate(async () => {
    state.sessions.set('t1', {
      tabId: 't1', sessionId: 'sess', serverId: 'srv', serverName: 'host',
      host: '10.0.0.1', port: 22, mode: 'sftp', sftpReady: true,
      sftpPath: '/srv/api/releases', ended: false,
    });
    state.activeTabId = 't1';
    const panel = buildSftpPanel('t1');
    document.getElementById('sftpBody').appendChild(panel);
    panel.style.display = 'flex';
    document.getElementById('sftpBody').classList.add('visible');
    renderRemoteCrumbs('t1');
    await new Promise(r => setTimeout(r, 120));
    return Array.from(document.querySelectorAll('#sftpCrumbs-t1 .sftp-crumb')).map(b => b.textContent);
  });
  // The path was a text field: going up two levels meant editing a string.
  check('the remote path renders as clickable segments', built, ['/', 'srv', 'api', 'releases']);
  check('the deepest segment is marked as where you are', await page.evaluate(() =>
    document.querySelector('#sftpCrumbs-t1 .sftp-crumb.current').textContent), 'releases');

  const edit = await page.evaluate(async () => {
    editRemotePath('t1');
    await new Promise(r => setTimeout(r, 40));
    const typing = { box: !document.getElementById('sftpPath-t1').hidden, crumbs: document.getElementById('sftpCrumbs-t1').hidden };
    showRemoteCrumbs('t1');
    await new Promise(r => setTimeout(r, 40));
    return { typing, back: { box: document.getElementById('sftpPath-t1').hidden, crumbs: !document.getElementById('sftpCrumbs-t1').hidden } };
  });
  check('clicking the path hands you the editable field', edit.typing, { box: true, crumbs: true });
  check('and it returns to the breadcrumb afterwards', edit.back, { box: true, crumbs: true });

  // Split is the point of the surface control: both at once, not either/or.
  const split = await page.evaluate(async () => {
    window.showSplitForTab('t1');
    await new Promise(r => setTimeout(r, 60));
    const surface = document.getElementById('sessionSurface');
    return {
      split: surface.classList.contains('split'),
      row: getComputedStyle(surface).flexDirection,
      termVisible: getComputedStyle(document.getElementById('terminalBody')).display !== 'none',
      filesVisible: document.getElementById('sftpBody').classList.contains('visible'),
      splitter: !document.getElementById('surfaceSplitter').hidden,
    };
  });
  check('split shows the shell and the file browser together', split,
    { split: true, row: 'row', termVisible: true, filesVisible: true, splitter: true });

  const back = await page.evaluate(async () => {
    window.showSshForTab('t1');
    await new Promise(r => setTimeout(r, 60));
    return {
      split: document.getElementById('sessionSurface').classList.contains('split'),
      filesVisible: document.getElementById('sftpBody').classList.contains('visible'),
    };
  });
  check('leaving split restores the single surface', back, { split: false, filesVisible: false });

  check('no page errors', errors, []);
  await page.close();
}

(async () => {
  const server = await serve();
  const browser = await chromium.launch();
  try {
    await checkKeyListGrouping(browser, server);
    await checkConnectPicker(browser, server);
    await checkSftpLocalPane(browser, server);
    await checkQueueGrouping(browser, server);
    await checkUxRefactor(browser, server);
    await checkSessionSurface(browser, server);
  } finally {
    await browser.close();
    server.close();
  }
  if (failures.length) {
    console.error(`\n${failures.length} renderer UI check(s) failed.`);
    process.exit(1);
  }
  console.log('\nAll renderer UI checks passed.');
})().catch((e) => { console.error(e); process.exit(1); });
