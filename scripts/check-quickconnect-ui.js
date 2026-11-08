#!/usr/bin/env node
/*
 * Quick connect, sshspan:// links from PMXSpan and the "Import from PMXSpan"
 * dialog, driven through the REAL page (index.html and every script it
 * loads) in headless Chromium against the stub Tauri IPC in
 * scripts/lib/renderer-harness.js. No PMXSpan, no backend: every assertion
 * is about what the page shows and which IPC commands it sends with which
 * arguments (INTEGRATION-SPEC v1, sections 2 and 6).
 *
 * What it pins:
 *   1. Quick connect without saving: the button and Ctrl+Shift+N open it;
 *      quick_connect_open, then terminal_connect for the ephemeral id; the
 *      tab is titled user@host; nothing is saved; the tab menu offers
 *      "Save this server..."; closing the last tab forgets it;
 *   2. Save for future reconnects: server_save with the dialog's values,
 *      then a connect of the saved id; the tick is remembered;
 *   3. "Save this server..." on an unsaved tab rebinds the tab;
 *   4. a connect link: prefilled, nothing sent before a click, "Open saved
 *      server <name>" first when a saved server matches; a refused link is
 *      a toast; a link waiting for an unlock says so;
 *   5. PMXSpan reported a different host key: the usual check is a second,
 *      explicit step (terminal_connect with skipProposedHostKeys);
 *   6. the import dialog: rows, ticks, reasons, host-key status, category
 *      creation and server_save with each row's token;
 *   7. "Manage in PMXSpan" / "Add to PMXSpan...": disabled with the hint
 *      when PMXSpan is not found, sent with ids only when it is.
 *
 * Run with `node scripts/check-quickconnect-ui.js` (`--only <text>` picks
 * scenarios). Needs playwright; without it, nothing runs and it says so.
 */
'use strict';

const {
  failures, check, yes, loadChromium, rendererDir, serve, part,
  SERVER, withApp, waitVisible, focusIs, answerConfirm, toasts,
} = require('./lib/renderer-harness');

const RENDERER = rendererDir();
const NOT_FOUND = 'PMXSpan was not found on this computer. Install it or set its path in Settings.';

const EPHEMERAL = {
  id: 'quick-0123456789abcdef', name: 'ops@10.9.9.9', host: '10.9.9.9', port: 2222, username: 'ops',
  authMethod: 'password', keyId: null, pemPath: null, hasSavedPassword: true, categoryId: null, ephemeral: true,
};

const quickReplies = () => ({
  quick_connect_open: { ok: true, warning: null, server: EPHEMERAL },
  quick_connect_forget: { ok: true, forgotten: true },
});

async function fillQuick(page, { host, port, user, password }) {
  await page.fill('#qcHost', host);
  await page.fill('#qcPort', String(port));
  await page.fill('#qcUser', user);
  await page.click('#qcAuthSeg [data-qauth="password"]');
  if (password) await page.fill('#qcPassword', password);
}

async function scenarioQuickUnsaved(browser, server) {
  await withApp(browser, server, { replies: quickReplies() }, 'Quick connect: unsaved, ephemeral', async (app) => {
    const { page } = app;
    await page.evaluate(() => switchView('connect'));
    yes('the Quick button sits beside New', await page.evaluate(() => {
      const q = document.getElementById('serverQuickBtn');
      return !!q && q.nextElementSibling === document.getElementById('serverNewBtn');
    }));
    await page.keyboard.press('Control+Shift+N');
    yes('Ctrl+Shift+N opens Quick connect', await waitVisible(page, '#quickModal'));
    check('unticked the first time', await page.isChecked('#qcSave'), false);
    yes('the save fields are hidden while unticked', await page.evaluate(() => document.getElementById('qcSaveFields').hidden));
    await fillQuick(page, { host: '10.9.9.9', port: 2222, user: 'ops', password: 'typed' });
    await page.click('#qcConnectBtn');
    await page.waitForFunction(() => window.__calls.some((c) => c.cmd === 'terminal_connect'), null, { polling: 25 });
    const open = (await app.calls('quick_connect_open'))[0].args;
    check('quick_connect_open gets the dialog\'s values (and the typed password)', {
      host: open.host, port: open.port, username: open.username, authMethod: open.authMethod, password: open.password,
    }, { host: '10.9.9.9', port: 2222, username: 'ops', authMethod: 'password', password: 'typed' });
    check('nothing is saved', await app.count('server_save'), 0);
    const tc = (await app.calls('terminal_connect'))[0].args;
    check('the tab connects the ephemeral id', tc.serverId, EPHEMERAL.id);
    check('without asking for a password again', tc.promptPassword || null, null);
    check('the tab is titled user@host', await page.evaluate(() => document.querySelector('.term-tab .term-tab-name').textContent), 'ops@10.9.9.9');
    check('the tick is remembered (off)', (await app.calls('settings_set')).map((c) => c.args), [{ key: 'quickConnectSave', value: '0' }]);
    // The tab's menu offers to save it.
    const items = await page.evaluate(() => {
      openTerminalContextMenu(10, 10, state.activeTabId);
      return [...document.querySelectorAll('#keyConnectMenu .ctx-item')].map((b) => b.textContent.trim());
    });
    yes('"Save this server..." is in the unsaved tab\'s menu', items.includes('Save this server...'), items.join(' | '));
    await page.keyboard.press('Escape');
    // Close: forgotten.
    await page.evaluate(() => closeSessionTab(state.activeTabId, { skipConfirm: true }));
    check('closing the last tab forgets the ephemeral server', (await app.calls('quick_connect_forget')).map((c) => c.args.id), [EPHEMERAL.id]);
    check('and the page forgets it too', await page.evaluate((id) => state.ephemeral.has(id), EPHEMERAL.id), false);
    check('no page errors', app.errors, []);
  });
}

async function scenarioQuickSaved(browser, server) {
  const replies = Object.assign(quickReplies(), {
    server_save: { ok: true, id: 's7', warning: null },
  });
  await withApp(browser, server, { replies, servers: [SERVER('s1', 'web-1')] }, 'Quick connect: saved through server_save', async (app) => {
    const { page } = app;
    await page.evaluate(() => switchView('connect'));
    // After the save the list holds the new server.
    await page.evaluate(() => {
      window.__replies.server_list = () => ({ servers: [
        { id: 's1', name: 'web-1', host: '10.0.0.1', port: 22, username: 'root', authMethod: 'publickey', hasSavedPassword: false },
        { id: 's7', name: 'db-7', host: '10.9.9.7', port: 22, username: 'ops', authMethod: 'password', hasSavedPassword: false },
      ] });
    });
    await page.click('#serverQuickBtn');
    yes('the button opens Quick connect', await waitVisible(page, '#quickModal'));
    await fillQuick(page, { host: '10.9.9.7', port: 22, user: 'ops', password: 'once' });
    await page.click('label:has(#qcSave)');
    yes('ticked: name and category appear', await waitVisible(page, '#qcName'));
    check('the button says what it does', (await page.textContent('#qcConnectLabel')).trim(), 'Save & connect');
    await page.click('#qcConnectBtn');
    yes('a name is required to save', (await toasts(page)).some((t) => t.includes('Name is required')));
    await page.fill('#qcName', 'db-7');
    await page.click('#qcConnectBtn');
    await page.waitForFunction(() => window.__calls.some((c) => c.cmd === 'terminal_connect'), null, { polling: 25 });
    const save = (await app.calls('server_save'))[0].args;
    check('server_save gets the server dialog\'s arguments, no password stored', {
      id: save.id, name: save.name, host: save.host, port: save.port, username: save.username,
      authMethod: save.authMethod, savedPassword: save.savedPassword, originToken: save.originToken,
    }, { id: null, name: 'db-7', host: '10.9.9.7', port: 22, username: 'ops', authMethod: 'password', savedPassword: null, originToken: null });
    check('no ephemeral server is made', await app.count('quick_connect_open'), 0);
    const tc = (await app.calls('terminal_connect'))[0].args;
    check('the saved server is connected, with the typed password for this connect', [tc.serverId, tc.promptPassword], ['s7', 'once']);
    check('the tick is remembered (on)', (await app.calls('settings_set')).map((c) => c.args), [{ key: 'quickConnectSave', value: '1' }]);
    check('no page errors', app.errors, []);
  });
}

async function scenarioSaveThisServer(browser, server) {
  const replies = Object.assign(quickReplies(), { server_save: { ok: true, id: 's9', warning: null } });
  await withApp(browser, server, { replies }, 'Quick connect: "Save this server..." rebinds the tab', async (app) => {
    const { page } = app;
    await page.evaluate(() => switchView('connect'));
    await page.click('#serverQuickBtn');
    await fillQuick(page, { host: '10.9.9.9', port: 2222, user: 'ops', password: 'typed' });
    await page.click('#qcConnectBtn');
    await page.waitForFunction(() => window.__calls.some((c) => c.cmd === 'terminal_connect'), null, { polling: 25 });
    await page.evaluate(() => {
      window.__replies.server_list = () => ({ servers: [{ id: 's9', name: 'saved-9', host: '10.9.9.9', port: 2222, username: 'ops', authMethod: 'password', hasSavedPassword: false }] });
      saveEphemeralServer([...state.sessions.values()][0].serverId);
    });
    yes('the server dialog opens', await waitVisible(page, '#serverModal'));
    check('prefilled from the tab', await page.evaluate(() => [srvHost.value, srvPort.value, srvUser.value, state.connectAuthMethod]),
      ['10.9.9.9', '2222', 'ops', 'password']);
    await page.fill('#srvName', 'saved-9');
    await page.click('#srvSaveBtn');
    await page.waitForFunction(() => window.__calls.some((c) => c.cmd === 'quick_connect_forget'), null, { polling: 25 });
    check('the tab is bound to the saved server', await page.evaluate(() => [...state.sessions.values()].map((t) => [t.serverId, t.serverName])), [['s9', 'saved-9']]);
    check('no page errors', app.errors, []);
  });
}

const OFFER = {
  kind: 'connect', token: 'tok-1',
  link: {
    host: '10.0.1.5', port: 22, user: 'debian', name: 'web01', source: 'pmxspan', fromPmxspan: true,
    origin: { kind: 'pmxspan', clusterId: 'prof-1', clusterName: 'lab', vmid: 100, node: 'pve1', guestKind: 'vm' },
    pool: null, hostKeys: [{ type: 'ssh-ed25519', fingerprint: 'SHA256:abcdef' }], hostKeyRotated: null,
  },
  match: null,
};

async function scenarioConnectLink(browser, server) {
  await withApp(browser, server, { replies: quickReplies() }, 'links: a connect link lands in Quick connect', async (app) => {
    const { page } = app;
    await page.evaluate((o) => { window.__replies.handoff_take_pending = ((v) => { let u = false; return () => { if (u) return { kind: 'none' }; u = true; return v; }; })(o); window.__emit('handoff-received'); }, OFFER);
    yes('the dialog opens', await waitVisible(page, '#quickModal'));
    check('prefilled from the validated link', await page.evaluate(() => [qcHost.value, qcPort.value, qcUser.value, qcName.value]),
      ['10.0.1.5', '22', 'debian', 'web01']);
    const info = await page.textContent('#qcLinkInfo');
    yes('it says where it came from and shows the proposed fingerprint', info.includes('From PMXSpan: lab / 100') && info.includes('SHA256:abcdef'), info);
    check('nothing was sent before a click', [await app.count('quick_connect_open'), await app.count('terminal_connect'), await app.count('server_save')], [0, 0, 0]);
    await page.click('#qcAuthSeg [data-qauth="password"]');
    await page.click('#qcConnectBtn');
    await page.waitForFunction(() => window.__calls.some((c) => c.cmd === 'quick_connect_open'), null, { polling: 25 });
    check('the link\'s token goes with the connect', (await app.calls('quick_connect_open'))[0].args.handoffToken, 'tok-1');
    check('no page errors', app.errors, []);
  });
  await withApp(browser, server, { servers: [SERVER('s1', 'web-1')] }, 'links: a saved server that matches comes first', async (app) => {
    const { page } = app;
    const offer = Object.assign({}, OFFER, { match: { id: 's1', name: 'web-1' } });
    await page.evaluate((o) => { let u = false; window.__replies.handoff_take_pending = () => { if (u) return { kind: 'none' }; u = true; return o; }; window.__emit('handoff-received'); }, offer);
    yes('the dialog opens', await waitVisible(page, '#quickModal'));
    check('"Open saved server web-1" is the primary button', await page.evaluate(() => [qcOpenSavedBtn.hidden, qcOpenSavedBtn.className, qcOpenSavedLabel.textContent, qcConnectBtn.className]),
      [false, 'primary-btn', 'Open saved server web-1', 'ghost-btn']);
    yes('and has the focus', await focusIs(page, 'qcOpenSavedBtn'));
    await page.click('#qcOpenSavedBtn');
    await page.waitForFunction(() => window.__calls.some((c) => c.cmd === 'terminal_connect'), null, { polling: 25 });
    check('the saved server is connected', (await app.calls('terminal_connect'))[0].args.serverId, 's1');
    check('no ephemeral server', await app.count('quick_connect_open'), 0);
  });
  await withApp(browser, server, {}, 'links: refused and waiting links', async (app) => {
    const { page } = app;
    await page.evaluate(() => { let u = false; window.__replies.handoff_take_pending = () => { if (u) return { kind: 'none' }; u = true; return { kind: 'error', message: 'The link has no host.' }; }; window.__emit('handoff-received'); });
    await page.waitForTimeout(200);
    yes('a refused link is a toast naming the problem', (await toasts(page)).some((t) => t.includes('The link has no host.')));
    check('and no dialog', await app.open('quickModal'), false);
    await page.evaluate(() => { let u = false; window.__replies.handoff_take_pending = () => { if (u) return { kind: 'none' }; u = true; return { kind: 'waiting' }; }; window.__emit('handoff-received'); });
    await page.waitForTimeout(200);
    yes('a link waiting for the unlock says so', (await toasts(page)).some((t) => t.includes('unlock the vault to continue')));
  });
}

async function scenarioProposalMismatch(browser, server) {
  const MSG = 'PMXSpan reported a different host key for 10.0.0.1:22, so the connection was refused.\nThe server presented: SHA256:live\nPMXSpan reported: SHA256:other';
  await withApp(browser, server, {}, 'links: a different host key needs the explicit second step', async (app) => {
    const { page } = app;
    await page.evaluate((m) => {
      let n = 0;
      window.__replies.terminal_connect = () => { n += 1; if (n === 1) throw m; return { ok: true, sessionId: 'sess-x' }; };
      switchView('connect').then(() => openSessionTab(state.servers[0]));
    }, MSG);
    yes('the refusal asks whether to check the key the usual way', await answerConfirm(page, 'ok'));
    await page.waitForFunction(() => window.__calls.filter((c) => c.cmd === 'terminal_connect').length === 2, null, { polling: 25 });
    const calls = (await app.calls('terminal_connect')).map((c) => c.args.skipProposedHostKeys);
    check('the second connect sets PMXSpan\'s keys aside, the first did not', calls, [false, true]);
  });
}

const LISTING = {
  kind: 'import', cluster: { id: 'prof-1', name: 'lab' }, pmxspanVersion: '0.7.0',
  rows: [
    { index: 0, kind: 'vm', vmid: 100, node: 'pve1', name: 'web01', host: '10.0.1.5', port: 22, user: 'debian', category: ['Proxmox', 'lab'], token: 't0', hostKey: { status: 'new', new: 'SHA256:n' }, alreadySaved: null },
    { index: 1, kind: 'vm', vmid: 101, node: 'pve1', name: 'web02', host: '10.0.1.6', port: 22, user: 'debian', category: [], token: 't1', hostKey: { status: 'rotated', old: 'SHA256:o', new: 'SHA256:n' }, alreadySaved: { id: 's1', name: 'web-1' } },
    { index: 2, kind: 'ct', vmid: 102, name: 'nohost', host: '', port: 22, user: 'root', category: [], problem: 'It has no host address.' },
  ],
};

async function scenarioImport(browser, server) {
  await withApp(browser, server, { replies: { server_save: { ok: true, id: 'new', warning: null }, category_ensure_host_path: { id: 'cat-x' } } }, 'import: the PMXSpan import dialog', async (app) => {
    const { page } = app;
    await page.evaluate((l) => { let u = false; window.__replies.handoff_take_pending = () => { if (u) return { kind: 'none' }; u = true; return l; }; window.__emit('handoff-received'); }, LISTING);
    yes('the dialog opens', await waitVisible(page, '#pmxImportModal'));
    const rows = await page.evaluate(() => [...document.querySelectorAll('#pmxImportList .putty-row')].map((li) => ({
      ticked: li.querySelector('input[type=checkbox]').checked,
      disabled: li.querySelector('input[type=checkbox]').disabled,
      text: li.textContent,
    })));
    check('new rows ticked, "Already in SSHSpan" unticked, a row that cannot be imported disabled', rows.map((r) => [r.ticked, r.disabled]), [[true, false], [false, false], [false, true]]);
    yes('host-key status: new', rows[0].text.includes('host key: new'));
    yes('host-key status: rotated old -> new', rows[1].text.includes('rotated: SHA256:o -> SHA256:n') && rows[1].text.includes('Already in SSHSpan'));
    yes('the reason a row cannot be imported', rows[2].text.includes('Cannot be imported: It has no host address.'));
    check('the footer counts the ticks', (await page.textContent('#pmxImportBtnLabel')).trim(), 'Import 1 server');
    await page.click('#pmxImportBtn');
    await page.waitForFunction(() => document.getElementById('pmxImportModal').hidden, null, { polling: 25 });
    check('the category path is created first', (await app.calls('category_ensure_host_path')).map((c) => c.args.path), ['Proxmox/lab']);
    const save = (await app.calls('server_save')).map((c) => [c.args.name, c.args.host, c.args.username, c.args.authMethod, c.args.categoryId, c.args.originToken]);
    check('server_save per ticked row, with its token', save, [['web01', '10.0.1.5', 'debian', 'password', 'cat-x', 't0']]);
    yes('it reports what it did', (await toasts(page)).some((t) => t.includes('1 server(s) saved from PMXSpan')));
    check('no page errors', app.errors, []);
  });
}

async function scenarioPmxspanActions(browser, server) {
  const pmxServer = Object.assign(SERVER('s1', 'web-1'), { origin: { kind: 'pmxspan', clusterId: 'prof-1', clusterName: 'lab', vmid: 100, node: 'pve1', guestKind: 'vm' } });
  await withApp(browser, server, { servers: [pmxServer], replies: { pmxspan_status: { available: false, route: 'none', hint: NOT_FOUND } } }, 'PMXSpan actions: not found', async (app) => {
    const { page } = app;
    await page.evaluate(() => switchView('connect'));
    yes('the server row has a PMXSpan badge', await waitVisible(page, '#serverList .pmx-badge'));
    check('its tooltip says where it lives', await page.getAttribute('#serverList .pmx-badge', 'title'), 'Managed in PMXSpan: lab / 100');
    await page.click('#serverList .server-row-more', { force: true });
    await page.waitForSelector('#keyConnectMenu');
    const item = await page.evaluate(() => {
      const b = [...document.querySelectorAll('#keyConnectMenu .ctx-item')].find((x) => x.textContent.includes('Manage in PMXSpan'));
      return b ? [b.disabled, b.textContent] : null;
    });
    yes('"Manage in PMXSpan" is disabled with the hint', item && item[0] === true && item[1].includes(NOT_FOUND), JSON.stringify(item));
    await page.keyboard.press('Escape');
    await page.evaluate(() => openServerModal({ id: 's1' }));
    check('the server dialog says where it lives', await page.textContent('#srvOriginLine'), 'Managed in PMXSpan: lab / 100');
  });
  await withApp(browser, server, { servers: [pmxServer], replies: { pmxspan_status: { available: true, route: 'detected', path: '/usr/bin/pmxspan' }, pmxspan_manage_server: { ok: true }, pmxspan_add_key: { ok: true } } }, 'PMXSpan actions: found', async (app) => {
    const { page } = app;
    await page.evaluate(() => switchView('connect'));
    await page.click('#serverList .server-row-more', { force: true });
    await page.waitForSelector('#keyConnectMenu');
    await page.evaluate(() => [...document.querySelectorAll('#keyConnectMenu .ctx-item')].find((x) => x.textContent.includes('Manage in PMXSpan')).click());
    await page.waitForFunction(() => window.__calls.some((c) => c.cmd === 'pmxspan_manage_server'), null, { polling: 25 });
    check('"Manage in PMXSpan" sends the server id only', (await app.calls('pmxspan_manage_server'))[0].args, { serverId: 's1' });
    await page.evaluate(() => { switchView('keys'); openKeyConnectMenu(20, 20, state.keys[0]); });
    await page.waitForSelector('#keyConnectMenu');
    await page.evaluate(() => [...document.querySelectorAll('#keyConnectMenu .ctx-item')].find((x) => x.textContent.includes('Add to PMXSpan')).click());
    await page.waitForFunction(() => window.__calls.some((c) => c.cmd === 'pmxspan_add_key'), null, { polling: 25 });
    check('"Add to PMXSpan..." sends the key id only - the URL is built in Rust', (await app.calls('pmxspan_add_key'))[0].args, { keyId: 'k1' });
    check('no page errors', app.errors, []);
  });
}

const SCENARIOS = [
  ['quick connect: unsaved', scenarioQuickUnsaved],
  ['quick connect: saved', scenarioQuickSaved],
  ['quick connect: save this server', scenarioSaveThisServer],
  ['links: connect', scenarioConnectLink],
  ['links: host key mismatch', scenarioProposalMismatch],
  ['import from PMXSpan', scenarioImport],
  ['PMXSpan actions', scenarioPmxspanActions],
];

(async () => {
  const only = process.argv.includes('--only') ? process.argv[process.argv.indexOf('--only') + 1] : null;
  const chromium = loadChromium();
  if (!chromium) {
    console.log('playwright not installed - skipping the browser checks.');
    process.exit(0);
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
    console.error(`\n${failures.length} Quick connect / PMXSpan UI check(s) failed.`);
    process.exit(1);
  }
  console.log('\nAll Quick connect / PMXSpan UI checks passed.');
})().catch((e) => { console.error(e); process.exit(1); });
