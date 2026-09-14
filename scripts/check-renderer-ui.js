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
    sftp_list_dir: { entries: [] },
    sftp_bookmarks_list: { bookmarks: [] },
    sftp_queue_list: { jobs: [] },
  });

  const built = await page.evaluate(async () => {
    const tabId = 't1';
    state.sessions.set(tabId, {
      tabId, sessionId: 'sess', serverId: 'srv', serverName: 'host',
      host: '10.0.0.1', port: 22, mode: 'sftp', sftpReady: true, sftpPath: '/', ended: false,
    });
    const panel = buildSftpPanel(tabId);
    document.getElementById('sftpBody').appendChild(panel);
    panel.style.display = 'flex';
    document.getElementById('sftpBody').classList.add('visible');
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
  check('it opens the app menu for a folder', ctx.items, ['Open', 'Upload folder', 'Copy path', 'Refresh']);
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
    ['Parent directory', 'Copy current path', 'Set as default local directory', 'Refresh']);

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
    ['Upload 3 items', 'Copy 3 paths', 'Refresh']);
  check('the status bar counts the local selection', /local: 3 items, 3 selected/.test(sel.status), true);

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

(async () => {
  const server = await serve();
  const browser = await chromium.launch();
  try {
    await checkKeyListGrouping(browser, server);
    await checkConnectPicker(browser, server);
    await checkSftpLocalPane(browser, server);
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
