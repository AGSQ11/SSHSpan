#!/usr/bin/env node
/*
 * Keys, categories and the deploy sheet, driven through the REAL page
 * (index.html and every script it loads) in headless Chromium against the
 * stub Tauri IPC in scripts/lib/renderer-harness.js.
 *
 * Nothing here re-implements production logic: every assertion is about what
 * the page shows, where the focus is, or which IPC commands it sends.
 *
 * What it pins (flaw audit 2026-10-09, unit JU4 - finding ids in each title):
 *   1. creating and exporting keys: the ECDSA curve values, the encrypted
 *      PKCS#8 passphrase, optional passphrases for OpenSSH and PPK, public
 *      exports through a save dialog, a New key dialog that starts fresh, one
 *      submit per click;
 *   2. importing: the two formats it reads, every other format recognised
 *      before anything is sent, with the backend's own conversion guidance;
 *   3. the key list: a "no match" row, recursive counts, avatars, collapse,
 *      one-line names, a detail pane that stays in view, select-all and
 *      selection pruning;
 *   4. categories: drag and drop, the picker's scope and keys, cycles,
 *      deletes;
 *   5. loaders that cannot duplicate rows or show a stale key;
 *   6. the deploy sheet: the backend's preview, the fields it sends, the
 *      Include line, validation before anything is written, servers saved
 *      before it closes;
 *   7. removing a deployed copy;
 *   plus the key row's Connect menu, the category drawer while locked and
 *   the tree on lock; and (JU6b) category drags made with the mouse - pointer
 *   events, since HTML5 drops never reach the page on Windows (A3-23) - with
 *   the JU4 review's order probes.
 *
 * Run with `npm run test:keys`. Needs playwright (see check-renderer-ui.js);
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
  KEY, SERVER, CATEGORY, withApp, settled, waitVisible, answerConfirm, toasts, hold, letGo, afterScheduledTimers,
  emulateWindowsDragDrop, mouseDrag,
} = require('./lib/renderer-harness');

const ROOT = path.resolve(__dirname, '..');
const RENDERER = rendererDir();

// ─── fixtures and helpers ───────────────────────────────────────────────────

const CAT = (id, name, parent, sortIndex, scope) =>
  ({ id, name, parent_id: parent || null, scope: scope || 'key', sort_index: sortIndex || 0, color: null });
const CATS = [CATEGORY, CAT('c2', 'EU', 'c1', 0)];
const CAT_REPLY = (allKeyCategories, extra) => Object.assign(
  { categories: CATS, allKeyCategories: allKeyCategories || {}, orphans: true, hostOrphans: false }, extra || {});
const DEPLOYED = (id, name) => Object.assign(KEY(id, name), { deployed: true, deploy_path: '/home/u/.ssh/sshspan_' + name });

const OPENSSH_PEM = '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----';
const PPK_TEXT = 'PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\nComment: alpha\nPublic-Lines: 2\nAAAA\nAAAA\n';

// What key_import says about each format it does not read - copied from
// keys::unsupported_import_message (src-tauri/src/crypto/keys.rs). The static
// check at the end of this file fails if the backend's wording drifts from
// these, so the renderer's copy of the guidance cannot silently disagree.
const SUPPORTED = 'SSHSpan imports OpenSSH private keys (-----BEGIN OPENSSH PRIVATE KEY-----) and PuTTY .ppk files only.';
const CONVERT = 'Convert a copy with: ssh-keygen -p -o -f <copy-of-the-key-file> (it rewrites that file in OpenSSH format and asks for a passphrase to keep or set), then import the result.';
const PUTTYGEN = ' Or load it in PuTTYgen and use "Save private key" to get a .ppk.';
const PUBLIC_HALF = 'which holds only the public half. A vault key needs the private key - import the matching OpenSSH private key or PuTTY .ppk file instead.';
const privateMsg = (what, header, puttygen) =>
  `Unsupported key format: this is ${what} (${header}). ${SUPPORTED} ${CONVERT}${puttygen ? PUTTYGEN : ''}`;
const publicMsg = (what) => `Unsupported key format: this is ${what}, ${PUBLIC_HALF}`;
const pem = (label) => `-----BEGIN ${label}-----\nMIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n-----END ${label}-----`;
const UNSUPPORTED = [
  ['PKCS#1', pem('RSA PRIVATE KEY'), privateMsg('a PKCS#1 RSA private key', '-----BEGIN RSA PRIVATE KEY-----', true)],
  ['SEC1', pem('EC PRIVATE KEY'), privateMsg('a SEC1 EC private key', '-----BEGIN EC PRIVATE KEY-----', true)],
  ['encrypted PKCS#8', pem('ENCRYPTED PRIVATE KEY'), privateMsg('an encrypted PKCS#8 private key', '-----BEGIN ENCRYPTED PRIVATE KEY-----', false)],
  ['PKCS#8', pem('PRIVATE KEY'), privateMsg('a PKCS#8 private key', '-----BEGIN PRIVATE KEY-----', false)],
  ['SPKI public', pem('PUBLIC KEY'), publicMsg('an SPKI public key (-----BEGIN PUBLIC KEY-----)')],
  ['RFC 4716 public', '---- BEGIN SSH2 PUBLIC KEY ----\nComment: "alpha"\nAAAAC3NzaC1lZDI1NTE5AAAAI\n---- END SSH2 PUBLIC KEY ----',
    publicMsg('an RFC 4716 public key (---- BEGIN SSH2 PUBLIC KEY ----)')],
  ['authorized_keys line', 'from="10.0.0.1",no-pty ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl alpha@host',
    publicMsg('an OpenSSH public key line (authorized_keys / .pub)')],
];
const UNKNOWN_FORMAT = 'Unsupported key format. Expected an OpenSSH private key (-----BEGIN OPENSSH PRIVATE KEY-----) or a PuTTY .ppk file.';

const ids = (page) => page.$$eval('#keyList .key-row', (rs) => rs.map((r) => r.dataset.id));
const chips = (page, sel) => page.$$eval(sel + ' .cat-chip:not(.add-chip)', (cs) => cs.map((c) => c.textContent.trim()));
const lastArgs = async (app, cmd) => {
  const c = await app.calls(cmd);
  return c.length ? c[c.length - 1].args : null;
};
/// On screen: in the layout, not display:none, inside no hidden ancestor.
const shown = (page, sel) => page.evaluate((s) => {
  const n = document.querySelector(s);
  if (!n || n.closest('[hidden]')) return false;
  const r = n.getBoundingClientRect();
  return getComputedStyle(n).display !== 'none' && r.width > 0 && r.height > 0;
}, sel);
const text = (page, sel) => page.evaluate((s) => {
  const n = document.querySelector(s);
  return n ? n.textContent.replace(/\s+/g, ' ').trim() : null;
}, sel);
/// Fill a field only if it exists, so a check against an older renderer
/// fails on its assertion instead of aborting the whole block.
const fillIf = async (page, sel, value) => { if (await page.$(sel)) await page.fill(sel, value); };

// ─── item 1: creating and exporting keys ───────────────────────────────────

async function scenarioCreate(browser, server) {
  await withApp(browser, server, {}, 'A2-02 ECDSA curves', async (app) => {
    const { page } = app;
    check('A2-02 the Curve options carry p256 / p384 / p521 and keep their labels',
      await page.$$eval('#genCurve option', (os) => os.map((o) => [o.value, o.textContent.trim()])),
      [['p256', 'nistp256'], ['p384', 'nistp384'], ['p521', 'nistp521']]);
    for (let i = 0; i < 3; i++) {
      await page.evaluate((idx) => {
        openKeyModal();
        document.getElementById('genType').value = 'ecdsa';
        onGenTypeChange();
        document.getElementById('genCurve').selectedIndex = idx;
        document.getElementById('genName').value = 'ec-' + idx;
      }, i);
      await page.click('#modalPrimary');
      await page.waitForTimeout(150);
    }
    check('A2-02 each curve is created as a key type the backend reads',
      (await app.calls('key_create_with_categories')).map((c) => c.args.keyType), ['ecdsa-p256', 'ecdsa-p384', 'ecdsa-p521']);
    check('no page errors', app.errors, []);
  });

  await withApp(browser, server, { categories: CATS, replies: { category_list: CAT_REPLY() } }, 'A2-37 the New key dialog starts fresh', async (app) => {
    const { page } = app;
    await page.evaluate(() => openKeyModal());
    await page.click('#genBrowseCategoriesBtn');
    await waitVisible(page, '#pickerModal');
    await page.click('#pickerTree .picker-row[data-id="c1"]');
    await page.click('#pickerSaveBtn');
    await page.waitForTimeout(60);
    check('(set-up) a category was chosen for the key', await chips(page, '#genCategories'), ['Prod']);
    await page.click('#tabBtn-import');
    await page.click('#modalBackdrop .modal-footer [data-close]');
    await page.evaluate(() => openKeyModal());
    await page.waitForTimeout(60);
    check('A2-37 the dialog opens on Generate again, whatever tab was used last',
      await page.evaluate(() => [!document.getElementById('tab-generate').hidden, document.getElementById('tab-import').hidden,
        document.getElementById('modalPrimary').textContent.trim()]), [true, true, 'Create']);
    check('A2-37 and carries no categories over from the last key', await chips(page, '#genCategories'), []);
    check('no page errors', app.errors, []);
  });

  await withApp(browser, server, { categories: CATS, replies: { category_list: CAT_REPLY() } }, 'a chip removed in the New key dialog', async (app) => {
    const { page } = app;
    await page.evaluate(() => openKeyModal());
    await page.click('#genBrowseCategoriesBtn');
    await waitVisible(page, '#pickerModal');
    await page.click('#pickerTree .picker-row[data-id="c1"]');
    await page.click('#pickerSaveBtn');
    await page.waitForTimeout(60);
    await page.click('#genCategories .cat-chip .cat-chip-x');
    await page.waitForTimeout(60);
    check('a category removed with its x leaves the dialog too (it stayed on show)', await chips(page, '#genCategories'), []);
    await page.fill('#genName', 'no-cat');
    await page.click('#modalPrimary');
    await page.waitForTimeout(150);
    check('and the key is created without it', ((await lastArgs(app, 'key_create_with_categories')) || {}).categoryIds, []);
    check('no page errors', app.errors, []);
  });

  await withApp(browser, server, { categories: CATS, replies: { category_list: CAT_REPLY({ k1: ['c1'] }) } }, 'A5-42 new keys and the filter', async (app) => {
    const { page } = app;
    await page.evaluate(() => setActiveCategory('c1'));
    await page.evaluate(() => openKeyModal());
    await page.waitForTimeout(60);
    check('A5-42 a new key starts in the category the list is filtered by (both tabs)',
      [await chips(page, '#genCategories'), await chips(page, '#importCategories')], [['Prod'], ['Prod']]);
    await page.fill('#genName', 'in-prod');
    await page.click('#modalPrimary');
    await page.waitForTimeout(150);
    check('A5-42 and is created there', ((await lastArgs(app, 'key_create_with_categories')) || {}).categoryIds, ['c1']);

    await page.evaluate(() => {
      setActiveCategory('all');
      window.__replies.key_create_with_categories = { ok: true, id: 'k9', fingerprint: 'SHA256:k9' };
      window.__replies.key_list = { keys: [...state.keys, Object.assign({}, state.keys[0], { id: 'k9', name: 'zeta', comment: 'zeta@host', category_ids: [] })] };
    });
    await page.fill('#searchInput', 'alpha');
    await page.evaluate(() => openKeyModal());
    await page.fill('#genName', 'zeta');
    await page.click('#modalPrimary');
    await page.waitForTimeout(200);
    const t = await toasts(page);
    yes('A5-42 a key the filter hides is reported as hidden, not just "generated"',
      t.some((x) => /hidden by the current filter/i.test(x)), JSON.stringify(t));
    check('no page errors', app.errors, []);
  });

  await withApp(browser, server, {}, 'A2-18 one import per click', async (app) => {
    const { page } = app;
    await page.evaluate(() => { openKeyModal(); switchTab('import'); });
    await page.fill('#importPem', OPENSSH_PEM);
    await hold(page, 'key_import');
    await page.evaluate(() => { const b = document.getElementById('modalPrimary'); b.click(); b.click(); });
    await page.waitForTimeout(60);
    check('A2-18 a double click imports once', await app.count('key_import'), 1);
    check('A2-18 and the button says it is working meanwhile',
      await page.evaluate(() => document.getElementById('modalPrimary').getAttribute('aria-busy')), 'true');
    await page.press('#importName', 'Enter');
    await page.waitForTimeout(60);
    check('A2-18 Enter while it runs neither imports again nor relabels the busy button',
      [await app.count('key_import'), await page.evaluate(() => document.getElementById('modalPrimary').textContent.trim())], [1, 'Importing…']);
    await letGo(page, 'key_import');
    await page.waitForTimeout(150);
    check('no page errors', app.errors, []);
  });
}

/// The detail pane's Export tab for the key that is open.
/// The open key's answer resets the pane to Overview; switch to Export only
/// after it landed, then wait for the panel (no fixed sleep: a loaded machine
/// once aborted this block with the Export panel still hidden).
async function openExportTab(page) {
  await page.click('#keyList .key-row[data-id="k1"]');
  await page.waitForFunction(() => state.selectedId === 'k1' && !document.getElementById('detailPane').hidden
    && document.getElementById('detailName').textContent === 'alpha');
  await afterScheduledTimers(page, 0);
  await page.click('.detail-tab[data-detail-tab="export"]');
  await page.waitForSelector('#detailPanel-export', { state: 'visible' });
}

async function scenarioExport(browser, server) {
  await withApp(browser, server, {}, 'A2-03 / A8-12 passphrases', async (app) => {
    const { page } = app;
    await page.evaluate(() => {
      window.__replies.key_export_to_file = (a) => ({ ok: true, canceled: false, path: '/tmp/alpha-' + a.format });
    });
    await openExportTab(page);

    await page.click('.format-row[data-format="pkcs8-encrypted"]');
    await page.fill('#detailExportPass', '');
    await page.click('#detailExportBtn');
    await page.waitForTimeout(100);
    check('A2-03 an encrypted PKCS#8 export with no passphrase is never sent', await app.count('key_export_to_file'), 0);
    const t1 = await toasts(page);
    yes('A2-03 it asks for the passphrase instead', t1.some((x) => /passphrase/i.test(x)), JSON.stringify(t1));
    check('A2-03 with the focus on the passphrase field', await page.evaluate(() => document.activeElement && document.activeElement.id), 'detailExportPass');
    await page.fill('#detailExportPass', 'secret-pp');
    await page.click('#detailExportBtn');
    await page.waitForTimeout(120);
    check('A2-03 with a passphrase it is sent, passphrase and all',
      await lastArgs(app, 'key_export_to_file'), { id: 'k1', format: 'pkcs8-encrypted', passphrase: 'secret-pp' });
    const t2 = await toasts(page);
    yes('A5-38 the toast names the format that was written, not an internal id',
      t2.some((x) => /PKCS#8 PEM, encrypted/.test(x) && x.includes('/tmp/alpha-pkcs8-encrypted')) && !t2.some((x) => /Exported pkcs8-encrypted/.test(x)),
      JSON.stringify(t2));

    await page.click('.format-row[data-format="openssh-private"]');
    check('A8-12 the OpenSSH export offers a passphrase', await shown(page, '#detailExportPass'), true);
    yes('A8-12 an optional one', /optional/i.test((await text(page, '#exportPassLabel')) || ''), await text(page, '#exportPassLabel'));
    yes('A8-12 the format says it is unprotected only without one',
      /Unprotected unless you set a passphrase/.test((await text(page, '.format-row[data-format="openssh-private"]')) || ''),
      await text(page, '.format-row[data-format="openssh-private"]'));
    await page.fill('#detailExportPass', 'pp-ssh');
    await page.click('#detailExportBtn');
    await page.waitForTimeout(120);
    check('A8-12 the OpenSSH export carries the passphrase',
      ((await lastArgs(app, 'key_export_to_file')) || {}).passphrase, 'pp-ssh');
    const t3 = await toasts(page);
    yes('A8-12 and says the file is passphrase-protected', t3.some((x) => /OpenSSH private key/.test(x) && /passphrase-protected/.test(x)), JSON.stringify(t3));

    await page.click('.format-row[data-format="ppk"]');
    check('A8-12 so does the PuTTY export', await shown(page, '#detailExportPass'), true);
    await page.click('#detailExportBtn');
    await page.waitForTimeout(120);
    const ppk = (await lastArgs(app, 'key_export_to_file')) || {};
    check('A8-12 left blank, the PuTTY export goes out without one', [ppk.format, !ppk.passphrase], ['ppk', true]);
    const t4 = await toasts(page);
    yes('A8-12 and the toast says so', t4.some((x) => /PuTTY/.test(x) && /no passphrase/.test(x)), JSON.stringify(t4));

    await page.click('.format-row[data-format="pkcs8"]');
    check('the unencrypted PKCS#8 export has no passphrase field', await shown(page, '#detailExportPass'), false);
    check('no page errors', app.errors, []);
  });

  await withApp(browser, server, {}, 'A2-42 public exports', async (app) => {
    const { page } = app;
    await page.evaluate(() => {
      window.__blobs = 0;
      const orig = URL.createObjectURL;
      URL.createObjectURL = (b) => { window.__blobs += 1; return orig(b); };
      window.__replies.key_export = (a) => ({ data: a.format === 'public-pem' ? '-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n' : 'ssh-ed25519 AAAAk1 alpha@host' });
      window.__replies.system_pick_save_path = (a) => ({ canceled: false, path: '/tmp/' + a.defaultName });
      window.__replies.system_write_text_file = { ok: true };
    });
    await openExportTab(page);
    await page.click('.format-row[data-format="authorized_keys"]');
    await page.click('#detailExportBtn');
    await page.waitForTimeout(150);
    check('A2-42 a public export asks where to save, through Rust',
      ((await lastArgs(app, 'system_pick_save_path')) || {}).defaultName, 'alpha.authorized_keys');
    check('A2-42 and writes the exported text there',
      await lastArgs(app, 'system_write_text_file'), { path: '/tmp/alpha.authorized_keys', contents: 'ssh-ed25519 AAAAk1 alpha@host' });
    check('A2-42 no blob download is attempted', await page.evaluate(() => window.__blobs), 0);
    const t1 = await toasts(page);
    yes('A2-42 the toast names the file written', t1.some((x) => x.includes('/tmp/alpha.authorized_keys')), JSON.stringify(t1));

    await page.click('.format-row[data-format="public-pem"]');
    await page.click('#detailExportBtn');
    await page.waitForTimeout(150);
    check('A2-42 an SPKI public key is offered as .pem, not .pub',
      ((await lastArgs(app, 'system_pick_save_path')) || {}).defaultName, 'alpha.pem');

    const writes = await app.count('system_write_text_file');
    await page.evaluate(() => { window.__replies.system_pick_save_path = { canceled: true }; });
    await page.click('#detailExportBtn');
    await page.waitForTimeout(150);
    check('A2-42 cancelling the save dialog writes nothing', await app.count('system_write_text_file'), writes);
    check('no page errors', app.errors, []);
  });

  await withApp(browser, server, {}, 'A2-18 one export per click', async (app) => {
    const { page } = app;
    await page.evaluate(() => { window.__replies.key_export_to_file = { ok: true, canceled: false, path: '/tmp/k' }; });
    await openExportTab(page);
    await page.click('.format-row[data-format="openssh-private"]');
    await hold(page, 'key_export_to_file');
    await page.evaluate(() => { const b = document.getElementById('detailExportBtn'); b.click(); b.click(); });
    await page.waitForTimeout(60);
    check('A2-18 a double click exports once', await app.count('key_export_to_file'), 1);
    await letGo(page, 'key_export_to_file');
    await page.waitForTimeout(100);
    check('no page errors', app.errors, []);
  });
}

// ─── item 2: import (R9, A7-03 / A5-39, A2-46) ─────────────────────────────

async function scenarioImport(browser, server) {
  await withApp(browser, server, {}, 'formats', async (app) => {
    const { page } = app;
    const label = await page.evaluate(() => document.getElementById('importPem').closest('label').textContent.replace(/\s+/g, ' '));
    yes('R9 the import field names the two formats it reads',
      /OpenSSH private key/.test(label) && /PuTTY \.ppk/.test(label), label);
    yes('R9 and no longer promises SPKI, PEM or authorized_keys import',
      !/SPKI|authorized_keys|PKCS#8 \/ PEM/.test(label), label);

    await page.evaluate(() => { openKeyModal(); switchTab('import'); });
    for (const [kind, body, want] of UNSUPPORTED) {
      await part(`import ${kind}`, async () => {
        const before = await app.count('key_import');
        await page.fill('#importPem', body);
        await page.fill('#importName', 'x-' + kind.replace(/\W+/g, '-'));
        await page.click('#modalPrimary');
        await page.waitForTimeout(80);
        check(`A5-39 ${kind}: recognised before anything is sent to the backend`, (await app.count('key_import')) - before, 0);
        check(`A5-39 ${kind}: the dialog shows the backend's conversion guidance`,
          [await shown(page, '#importFormatMsg'), await text(page, '#importFormatMsg')], [true, want]);
      });
    }
    await page.fill('#importPem', OPENSSH_PEM);
    check('A5-39 the guidance goes when the text is replaced by a supported key', await shown(page, '#importFormatMsg'), false);
    const n0 = await app.count('key_import');
    await page.click('#modalPrimary');
    await page.waitForTimeout(120);
    check('an OpenSSH private key is sent to the backend', (await app.count('key_import')) - n0, 1);
    await page.evaluate(() => { openKeyModal(); switchTab('import'); });
    await page.fill('#importPem', PPK_TEXT);
    await page.click('#modalPrimary');
    await page.waitForTimeout(120);
    check('a PuTTY .ppk is sent to the backend', (await app.count('key_import')) - n0, 2);

    await page.evaluate((msg) => { window.__replies.key_import = { $reject: msg }; openKeyModal(); switchTab('import'); }, UNKNOWN_FORMAT);
    await page.fill('#importPem', 'not a key at all');
    await page.click('#modalPrimary');
    await page.waitForTimeout(120);
    check('text it does not recognise is left to the backend to judge', (await app.count('key_import')) - n0, 3);
    check('A5-39 and the backend\'s format message is shown in the dialog', await text(page, '#importFormatMsg'), UNKNOWN_FORMAT);
    check('no page errors', app.errors, []);
  });

  await withApp(browser, server, {}, 'A2-46 duplicate names', async (app) => {
    const { page } = app;
    const dup = 'A key named "alpha" already exists. Choose a different name.';
    await page.evaluate((m) => {
      window.__replies.key_import = { $reject: m };
      window.__replies.key_create_with_categories = { $reject: m };
      openKeyModal();
    }, dup);
    await page.fill('#genName', 'ALPHA');
    await page.click('#modalPrimary');
    await page.waitForTimeout(120);
    yes('A2-46 a duplicate name on create is shown as the backend says it', (await toasts(page)).includes(dup), JSON.stringify(await toasts(page)));
    check('A2-46 and the dialog stays open on the name', [await app.open('modalBackdrop'),
      await page.evaluate(() => document.activeElement && document.activeElement.id)], [true, 'genName']);
    // Do not let the create error satisfy the import assertion (M6): clear
    // the old notification before the second request, and check its focus too.
    await page.evaluate(() => document.getElementById('toast').replaceChildren());
    await page.evaluate(() => switchTab('import'));
    await page.fill('#importPem', OPENSSH_PEM);
    await page.fill('#importName', 'Alpha');
    await page.click('#modalPrimary');
    await page.waitForTimeout(120);
    check('A2-46 import shows a fresh duplicate-name error', (await toasts(page)).includes(dup), true);
    check('A2-46 and focuses the import name, not the create name', await app.focused(), 'importName');
    check('no page errors', app.errors, []);
  });
}

// ─── item 3: the key list ──────────────────────────────────────────────────

async function scenarioKeyList(browser, server) {
  await withApp(browser, server, {}, 'A2-26 / A5-27 no match', async (app) => {
    const { page } = app;
    await page.click('#keyList .key-row[data-id="k1"]');
    await page.waitForTimeout(80);
    await page.fill('#searchInput', 'zzzz');
    await page.waitForTimeout(60);
    yes('A2-26 a search with no match says so', /No keys match "zzzz"/.test((await text(page, '#keyList')) || ''), await text(page, '#keyList'));
    check('A5-27 the detail pane is cleared when its key is filtered out',
      await page.evaluate(() => [document.getElementById('detailPane').hidden, state.selectedId]), [true, null]);
    await part('Clear filter', async () => {
      await page.click('#keyList .key-list-nomatch button');
      await page.waitForTimeout(60);
      check('A2-26 "Clear filter" brings every key back', [await ids(page), await page.inputValue('#searchInput')], [['k1', 'k2'], '']);
    });
    check('no page errors', app.errors, []);
  });

  // key_get answers with the same categories category_list reports (the pane
  // writes them back into the list's map when a key opens).
  const counted = {
    categories: CATS,
    keys: [Object.assign(KEY('k1', 'alpha'), { category_ids: ['c1', 'c2'] }), Object.assign(KEY('k2', 'beta'), { category_ids: ['c2'] })],
    replies: { category_list: CAT_REPLY({ k1: ['c1', 'c2'], k2: ['c2'] }) },
  };
  await withApp(browser, server, counted, 'A2-23 category counts', async (app) => {
    const { page } = app;
    const counts = await page.evaluate(() => Object.fromEntries([...document.querySelectorAll('#catTree .cat-node[data-id]')]
      .map((n) => [n.dataset.id, n.querySelector('.cat-count') ? n.querySelector('.cat-count').textContent : null])));
    check('A2-23 a category counts its own keys and its subcategories\' keys, each key once',
      [counts.c1, counts.c2], ['2', '2']);
    await page.evaluate(() => setActiveCategory('c1'));
    check('A2-23 the count matches what selecting it lists', (await ids(page)).length, 2);
    check('no page errors', app.errors, []);
  });

  const ecKeys = [KEY('k1', 'alpha'), Object.assign(KEY('k3', 'ec'), { key_type: 'ecdsa-p256' })];
  await withApp(browser, server, { keys: ecKeys }, 'A2-28 / A1-12 avatars and collapse', async (app) => {
    const { page } = app;
    check('A2-28 an ECDSA key gets the ECDSA avatar colour in the list',
      await page.evaluate(() => document.querySelector('#keyList .key-row[data-id="k3"] .key-avatar').dataset.type), 'ecdsa');
    await page.click('#keyList .key-group .key-group-head .icon-btn');
    await page.waitForTimeout(60);
    check('A1-12 collapsing a group hides its rows', await page.evaluate(() =>
      [...document.querySelectorAll('#keyList .key-group')[0].querySelectorAll('.key-row')].map((r) => r.offsetParent === null)), [true, true]);
    check('A1-12 and keeps its header', await shown(page, '#keyList .key-group .key-group-head'), true);
    check('no page errors', app.errors, []);
  });

  const long = 'a-very-long-key-name-for-the-production-deployment-pipeline-runner-in-eu-west';
  await withApp(browser, server, { keys: [KEY('k1', long), KEY('k2', 'beta')] }, 'A1-07 one-line names', async (app) => {
    const { page } = app;
    await page.setViewportSize({ width: 1100, height: 720 });
    await page.mouse.move(2, 2);
    await page.waitForTimeout(150);
    const r = await page.evaluate((name) => {
      const box = document.querySelector('#keyList .key-row[data-id="k1"] .key-row-name');
      const holder = [...box.querySelectorAll('*')].find((n) => n.textContent === name) || box;
      const cs = getComputedStyle(holder);
      return { nowrap: cs.whiteSpace, ellipsis: cs.textOverflow, oneLine: box.getBoundingClientRect().height < 24 };
    }, long);
    check('A1-07 a long key name stays on one line and ends in "..."', r, { nowrap: 'nowrap', ellipsis: 'ellipsis', oneLine: true });
    check('A1-07 the Connect button of a row that is not hovered or selected takes no room',
      await page.evaluate(() => Math.round(document.querySelector('#keyList .key-row[data-id="k2"] .row-btn').getBoundingClientRect().width)), 0);
    await page.hover('#keyList .key-row[data-id="k2"]');
    await page.waitForTimeout(150);
    yes('A1-07 it shows when the row is hovered', await page.evaluate(() =>
      document.querySelector('#keyList .key-row[data-id="k2"] .row-btn').getBoundingClientRect().width > 40));
    check('no page errors', app.errors, []);
  });

  const many = Array.from({ length: 30 }, (_, i) => KEY('k' + (i + 1), 'key-' + String(i + 1).padStart(2, '0')));
  await withApp(browser, server, { keys: many }, 'A1-24 the detail pane in view', async (app) => {
    const { page } = app;
    await page.setViewportSize({ width: 1100, height: 720 });
    await page.evaluate(() => { document.getElementById('view-keys').scrollTop = 1e6; });
    await page.click('#keyList .key-row[data-id="k28"]');
    await page.waitForTimeout(150);
    const r = await page.evaluate(() => {
      const p = document.getElementById('detailPane').getBoundingClientRect();
      const v = document.getElementById('view-keys').getBoundingClientRect();
      return { top: Math.round(p.top - v.top), bottom: Math.round(v.bottom - p.top), name: document.getElementById('detailName').textContent };
    });
    yes('A1-24 beside a long list, the pane of a key near the end is on screen',
      r.name === 'key-28' && r.top >= -1 && r.bottom > 150, JSON.stringify(r));
    await page.setViewportSize({ width: 880, height: 560 });
    await page.evaluate(() => { document.getElementById('view-keys').scrollTop = 0; });
    await page.waitForTimeout(100);
    await page.click('#keyList .key-row[data-id="k3"]');
    await page.waitForTimeout(200);
    const s = await page.evaluate(() => {
      const p = document.getElementById('detailPane').getBoundingClientRect();
      return { top: Math.round(p.top), name: document.getElementById('detailName').textContent };
    });
    yes('A1-24 stacked under the list (narrow window), the pane is scrolled into view',
      s.name === 'key-03' && s.top >= 0 && s.top < 260, JSON.stringify(s));
    check('no page errors', app.errors, []);
  });

  await withApp(browser, server, {}, 'A1-40 warning badge', async (app) => {
    check('A1-40 .badge.warn is drawn in the warning colour', await app.page.evaluate(() => {
      const b = document.createElement('span');
      b.className = 'badge warn';
      document.body.appendChild(b);
      const c = getComputedStyle(b).color;
      b.remove();
      return c;
    }), 'rgb(245, 181, 68)');
  });

  await withApp(browser, server, { keys: [KEY('k1', 'alpha'), KEY('k2', 'beta'), KEY('k3', 'gamma')] }, 'A5-34 selection', async (app) => {
    const { page } = app;
    await part('select all shown', async () => {
      yes('A5-34 there is a select-all control', await shown(page, '#selectAllKeys'));
      await page.fill('#searchInput', 'alp');
      await page.waitForTimeout(60);
      await page.click('#selectAllKeys');
      check('A5-34 it selects every key shown, and only those', await page.evaluate(() => [...state.deploySelected]), ['k1']);
      await page.fill('#searchInput', '');
      await page.waitForTimeout(60);
      check('A5-34 it shows a partial selection as such',
        await page.evaluate(() => [document.getElementById('selectAllKeys').checked, document.getElementById('selectAllKeys').indeterminate]), [false, true]);
      await page.click('#selectAllKeys');
      check('A5-34 a second click selects the rest', await page.evaluate(() => [...state.deploySelected].sort()), ['k1', 'k2', 'k3']);
      await page.click('#selectAllKeys');
      check('A5-34 and a third clears them', await page.evaluate(() => state.deploySelected.size), 0);
    });
    await page.evaluate(() => { state.deploySelected = new Set(['k1', 'k2']); renderKeyList(); updateSelectionHint(); });
    await page.fill('#searchInput', 'bet');
    await page.waitForTimeout(60);
    check('A5-34 a key the filter hides leaves the selection', await page.evaluate(() => [...state.deploySelected]), ['k2']);
    check('A5-34 and the selection bar counts what is left', await text(page, '#selectionHint'), '1 key selected');
    await page.fill('#searchInput', '');
    await page.click('#keyList .key-row[data-id="k1"]');
    await page.waitForTimeout(80);
    await page.evaluate(() => { window.__replies.key_list = { keys: state.keys.filter((k) => k.id !== 'k1') }; });
    await page.click('#detailDeleteBtn');
    await answerConfirm(page, 'ok');
    await page.waitForTimeout(200);
    check('A5-34 deleting the open key does not open another key in its place',
      await page.evaluate(() => [state.selectedId, document.getElementById('detailPane').hidden]), [null, true]);
    check('no page errors', app.errors, []);
  });
}

// ─── item 4: categories ────────────────────────────────────────────────────

/// A mouse drag of one category row onto another, released at `frac` of the
/// target row's height (0.1 = its top edge, 0.5 = its middle, 0.9 = its
/// bottom). Pointer events with the page's HTML5 drops switched off, as they
/// are on Windows while Tauri handles OS file drops (Task 16 / A3-23): the
/// HTML5 drag this used to dispatch never reaches the page there.
const dragCategory = async (page, from, to, frac, o = {}) => {
  await emulateWindowsDragDrop(page);
  // A mouse can only press a row that is on screen: open the branches above
  // it, as a user would (the shown parents, so a loop member's chain ends).
  await page.evaluate((id) => {
    let opened = false;
    for (let p = state.uiParentOf.get(id), n = 0; p && n < 64; p = state.uiParentOf.get(p), n++) {
      if (!state.expandedCatIds.has(p)) { state.expandedCatIds.add(p); opened = true; }
    }
    if (opened) renderCategoryTree();
  }, from);
  return mouseDrag(page, `#catTree .cat-node[data-id="${from}"] .cat-label`, `#catTree .cat-node[data-id="${to}"]`,
    Object.assign({ at: frac }, o));
};

async function scenarioCategories(browser, server) {
  const ROOTS = [CAT('c1', 'Alpha', null, 0), CAT('c2', 'Beta', null, 1), CAT('c3', 'Gamma', null, 2)];
  const rootsReply = { categories: ROOTS, allKeyCategories: {}, orphans: true, hostOrphans: false };
  await withApp(browser, server, { categories: ROOTS, replies: { category_list: rootsReply } }, 'A2-07 drag and drop', async (app) => {
    const { page } = app;
    // A parent changes only through category_reparent; the order is written
    // as one whole list (category_set_order), so no two siblings can share a
    // position and none the user did not move is moved.
    const moves = async (fn) => {
      const r = (await app.calls('category_reparent')).length;
      const o = (await app.calls('category_set_order')).length;
      await fn();
      await page.waitForTimeout(200);
      return {
        reparents: (await app.calls('category_reparent')).slice(r).map((c) => c.args),
        orders: (await app.calls('category_set_order')).slice(o).map((c) => c.args),
      };
    };
    check('A2-07 dropped on the top edge of a row, it goes BEFORE it and the siblings are numbered as shown',
      await moves(() => dragCategory(page, 'c3', 'c1', 0.1)),
      { reparents: [], orders: [{ parentId: null, orderedIds: ['c3', 'c1', 'c2'] }] });
    check('A2-07 dropped on the middle of a row, it goes INTO it',
      await moves(() => dragCategory(page, 'c3', 'c1', 0.5)),
      { reparents: [{ id: 'c3', newParentId: 'c1' }], orders: [{ parentId: 'c1', orderedIds: ['c3'] }] });
    check('A2-07 dropped on the bottom edge, it goes AFTER it, with no two siblings sharing a position',
      await moves(() => dragCategory(page, 'c1', 'c3', 0.9)),
      { reparents: [], orders: [{ parentId: null, orderedIds: ['c2', 'c3', 'c1'] }] });
    check('no page errors', app.errors, []);
  });

  const FOUR = [...ROOTS, CAT('c4', 'Delta', null, 3)];
  await withApp(browser, server, { categories: FOUR, replies: { category_list: Object.assign({}, rootsReply, { categories: FOUR }) } }, 'A2-15 / A2-36 picker', async (app) => {
    const { page } = app;
    await page.evaluate(() => openCategoryPicker({ title: 'Pick', initial: [], onSave: () => {} }));
    await waitVisible(page, '#pickerModal');
    await page.waitForTimeout(50);
    await page.keyboard.press('ArrowUp');
    check('A2-36 ArrowUp from the search box highlights the LAST category',
      await page.evaluate(() => (document.querySelector('#pickerTree .picker-row.active') || {}).dataset?.id || null), 'c4');
    await page.click('#pickerCancelBtn');

    await page.evaluate(() => switchView('connect'));
    await page.waitForTimeout(120);
    await page.evaluate(() => openKeyModal());
    await page.click('#genBrowseCategoriesBtn');
    await waitVisible(page, '#pickerModal');
    check('(set-up) the key dialog\'s picker lists key categories', await page.$$eval('#pickerTree .picker-row', (rs) => rs.map((r) => r.dataset.id)), ['c1', 'c2', 'c3', 'c4']);
    await page.click('#pickerCancelBtn');
    check('A2-15 closing the picker gives the sidebar its own scope back',
      await page.evaluate(() => [state.categoryScope, document.getElementById('catPanelTitle').textContent]), ['host', 'Server categories']);
    check('no page errors', app.errors, []);
  });

  const CYCLE = [CATEGORY, CAT('cy1', 'CycA', 'cy2', 1), CAT('cy2', 'CycB', 'cy1', 2)];
  const cycleReply = { categories: CYCLE, allKeyCategories: { k1: ['cy1'] }, orphans: true, hostOrphans: false };
  const cycleKeys = [Object.assign(KEY('k1', 'alpha'), { category_ids: ['cy1'] }), KEY('k2', 'beta')];
  await withApp(browser, server, { keys: cycleKeys, categories: CYCLE, replies: { category_list: cycleReply } }, 'A2-45 cycles: the grouped list', async (app) => {
    const { page } = app;
    const groups = await page.evaluate(() => [...document.querySelectorAll('#keyList .key-group')].map((g) => ({
      name: g.querySelector('.key-group-name') ? g.querySelector('.key-group-name').textContent : '',
      keys: [...g.querySelectorAll('.key-row')].map((r) => r.dataset.id),
    })));
    check('A2-45 a key filed only under a category cycle (no root) is listed under Uncategorized', groups,
      [{ name: 'Uncategorized', keys: ['k1', 'k2'] }]);
    check('no page errors', app.errors, []);
  });
  // These used to freeze the page for seconds and then throw: last, in their own page.
  await withApp(browser, server, { keys: cycleKeys, categories: CYCLE, replies: { category_list: cycleReply } }, 'A2-45 cycles: paths, palette, filter', async (app) => {
    const { page } = app;
    check('A2-45 the path of a category in a cycle is finite', await settled(page, () => catPathString('cy1'), null, 2500), 'CycB / CycA');
    await page.evaluate(() => openPalette());
    await page.fill('#paletteInput', 'cyc');
    await page.waitForTimeout(100);
    const rows = await page.$$eval('#paletteResults .palette-name', (ns) => ns.map((n) => n.textContent));
    yes('A2-45 the palette opens and lists them', rows.includes('CycB / CycA'), JSON.stringify(rows));
    await page.keyboard.press('Escape');
    check('A2-45 filtering by one lists its keys', await settled(page, () => { setActiveCategory('cy1'); return [...document.querySelectorAll('#keyList .key-row')].map((r) => r.dataset.id); }, null, 2500), ['k1']);
    check('no page errors', app.errors, []);
  });

  const HOSTS = [CATEGORY, CAT('h1', 'Hosts', null, 0, 'host'), CAT('h2', 'Edge', 'h1', 0, 'host')];
  const hostReply = { categories: HOSTS, allKeyCategories: {}, orphans: true, hostOrphans: false };
  const hostServers = [Object.assign(SERVER('s1', 'web-1'), { categoryId: 'h1' })];
  await withApp(browser, server, { categories: HOSTS, servers: hostServers,
    replies: { category_list: hostReply, category_delete: { ok: true, reassigned: ['h2'] } } }, 'A2-54 / A2-31 deleting a category', async (app) => {
    const { page } = app;
    await page.evaluate(() => switchView('connect'));
    await page.waitForTimeout(150);
    const listed = await app.count('server_list');
    await page.evaluate(() => { window.__del = deleteCategory('h1'); });
    await waitVisible(page, '#confirmModal');
    yes('A2-54 deleting a server category says where its servers go',
      /server/i.test((await text(page, '#confirmMessage')) || ''), await text(page, '#confirmMessage'));
    await answerConfirm(page, 'ok');
    await settled(page, () => window.__del, null, 1500);
    await page.waitForTimeout(100);
    check('A2-54 the servers are read again after a server category is deleted', (await app.count('server_list')) - listed >= 1, true);
    const t = await toasts(page);
    yes('A2-31 the toast counts the subcategories the backend moved', t.some((x) => /deleted/.test(x) && /\b1 sub/.test(x)), JSON.stringify(t));
    check('no page errors', app.errors, []);
  });
}

// ─── item 5: loaders (A2-29) ───────────────────────────────────────────────

const HOST_ROW = (host) => ({ host, fingerprintSha256: 'SHA256:' + host, firstSeen: '2026-01-01T00:00:00Z' });

async function scenarioLoaders(browser, server) {
  await withApp(browser, server, {}, 'known hosts', async (app) => {
    const { page } = app;
    await page.evaluate((rows) => {
      window.__replies.known_hosts_list = () => new Promise((r) => setTimeout(() => r({ hosts: rows }), 80));
    }, [HOST_ROW('h1.example')]);
    await page.evaluate(() => Promise.all([loadKnownHosts(), loadKnownHosts()]));
    check('A2-29 two loads at once leave one row per pinned host', await page.evaluate(() => document.querySelectorAll('#knownHostsBody tr').length), 1);

    await page.evaluate(() => {
      let n = 0;
      window.__replies.known_hosts_list = () => {
        n += 1;
        const rows = n === 1 ? [{ host: 'old.example', fingerprintSha256: 'x', firstSeen: null }] : [{ host: 'new.example', fingerprintSha256: 'y', firstSeen: null }];
        return new Promise((r) => setTimeout(() => r({ hosts: rows }), n === 1 ? 250 : 20));
      };
    });
    await page.evaluate(() => Promise.all([loadKnownHosts(), loadKnownHosts()]));
    check('A2-29 an older answer arriving late does not replace the newer one',
      await page.$$eval('#knownHostsBody tr td:first-child', (tds) => tds.map((t) => t.textContent)), ['new.example']);

    await page.evaluate(() => { window.__replies.known_hosts_list = { $reject: 'database is locked' }; });
    await page.evaluate(() => loadKnownHosts());
    await page.waitForTimeout(60);
    const t = await toasts(page);
    yes('A2-29 a failed load is reported', t.some((x) => /database is locked/.test(x)), JSON.stringify(t));
    check('A2-29 not as "No hosts pinned yet"', await page.evaluate(() => document.getElementById('knownHostsEmpty').hidden), true);
    yes('A2-29 the table says it could not load them', /could not load/i.test((await text(page, '#knownHostsBody')) || ''), await text(page, '#knownHostsBody'));
    check('no page errors', app.errors, []);
  });

  await withApp(browser, server, {}, 'one load per Settings visit', async (app) => {
    const { page } = app;
    const before = await app.count('known_hosts_list');
    await page.evaluate(() => switchView('settings'));
    await page.waitForTimeout(250);
    check('A2-29 opening Settings reads the pinned hosts once', (await app.count('known_hosts_list')) - before, 1);
    check('no page errors', app.errors, []);
  });

  await withApp(browser, server, {}, 'selectKey answers in order', async (app) => {
    const { page } = app;
    await page.evaluate(() => {
      const byId = Object.fromEntries(state.keys.map((k) => [k.id, k]));
      window.__replies.key_get = (a) => new Promise((r) => setTimeout(() => r(byId[a.id]), a.id === 'k1' ? 300 : 20));
      selectKey('k1');
      selectKey('k2');
    });
    await page.waitForTimeout(450);
    check('A2-29 the pane shows the key selected last, even when an earlier answer arrives later',
      await page.evaluate(() => [state.selectedId, document.getElementById('detailName').textContent]), ['k2', 'beta']);
    check('no page errors', app.errors, []);
  });

  await withApp(browser, server, {}, 'Bitwarden form', async (app) => {
    const { page } = app;
    await page.evaluate(() => {
      window.__replies.bitwarden_get_config = () => new Promise((r) => setTimeout(() => r({ server_url: 'https://vault.example' }), 60));
    });
    await page.evaluate(() => Promise.all([loadBitwardenConfig(), loadBitwardenConfig()]));
    check('A2-29 two loads at once build the Bitwarden form once', await page.evaluate(() => document.querySelectorAll('#bwGrid input').length), 5);
    check('no page errors', app.errors, []);
  });
}

// ─── item 6: the deploy sheet (R3) ─────────────────────────────────────────

const CONFIG_PATH = '/home/u/.config/sshspan/ssh/config';
const INCLUDE = 'Include "/home/u/.config/sshspan/ssh/config"';
const REFUSAL = 'Not deployed: /home/u/.ssh/sshspan_beta already exists and was not written by SSHSpan for "beta". Move or delete that file first if it should be replaced.';
const PARTIAL_WARNING = 'The key files were written, but /home/u/.config/sshspan/ssh/config could not be updated: permission denied';

/// A key_deploy_preview / key_deploy pair that answers like the backend: beta
/// is refused (a foreign file is in the way), alpha is planned and written.
async function stubDeploy(page) {
  await page.evaluate(({ configPath, include, refusal, warning }) => {
    const file = (id) => '/home/u/.ssh/sshspan_' + (id === 'k1' ? 'alpha' : 'beta');
    window.__previewText = (a) => [
      '# exactly what the backend writes',
      'Host ' + (a.hostAlias || 'alpha'),
      '  HostName "' + (a.hostname || '') + '"',
      '  User ' + (a.user || ''),
      '  Port ' + (a.port || ''),
      '  IdentityFile "' + file('k1') + '"',
      '  IdentitiesOnly yes',
      '',
    ].join('\n');
    window.__replies.key_deploy_preview = (a) => ({
      configPath, sshDir: '/home/u/.ssh', includeLine: include,
      keys: a.ids.map((id) => ({
        id, name: id === 'k1' ? 'alpha' : 'beta', alias: (a.hostAlias || 'alpha') + (id === 'k1' ? '' : '-beta'),
        file: file(id), pubFile: file(id) + '.pub',
        overwritesFile: id === 'k2', ownedByOtherKey: false, aliasOwnedByOtherKey: false,
        refusal: id === 'k2' ? refusal : null,
      })),
      configText: window.__previewText(a),
    });
    window.__replies.key_deploy = (a) => ({
      ok: true,
      keys: [{ id: 'k1', name: 'alpha', alias: a.hostAlias || 'alpha', file: file('k1'), pubFile: file('k1') + '.pub' }],
      errors: a.ids.includes('k2') ? [{ id: 'k2', name: 'beta', error: refusal }] : [],
      warnings: [warning], configPath, includeLine: include,
    });
  }, { configPath: CONFIG_PATH, include: INCLUDE, refusal: REFUSAL, warning: PARTIAL_WARNING });
}

async function openSheet(page, keyIds) {
  await page.evaluate((k) => { state.deploySelected = new Set(k); renderKeyList(); updateSelectionHint(); }, keyIds);
  await page.click('#selDeployBtn');
  await waitVisible(page, '#deployModal');
  await page.waitForTimeout(100);
}

/// Fill the sheet's host fields as a user would, then wait past the preview's
/// typing delay (150 ms, M7) so the backend has been asked about the result.
async function fillHostFields(page, f) {
  await fillIf(page, '#cfgHost', f.alias);
  await fillIf(page, '#cfgHostname', f.hostname);
  await fillIf(page, '#cfgUser', f.user);
  await fillIf(page, '#cfgPort', f.port);
  await page.waitForTimeout(260);
}

async function scenarioDeploy(browser, server) {
  await withApp(browser, server, {}, 'R3 preview and deploy', async (app) => {
    const { page } = app;
    await stubDeploy(page);
    await openSheet(page, ['k1', 'k2']);
    await fillHostFields(page, { alias: 'web', hostname: '10.0.0.5', user: 'deploy', port: '2222' });
    const asked = await lastArgs(app, 'key_deploy_preview');
    check('A2-05 the preview is asked of the backend with every field the sheet collects', asked,
      { ids: ['k1', 'k2'], hostAlias: 'web', hostname: '10.0.0.5', user: 'deploy', port: 2222, strictHostKey: true });
    check('A2-05 the sheet shows exactly the text the backend will write',
      await page.inputValue('#configPreview'), await page.evaluate((a) => window.__previewText(a || {}), asked));
    yes('A8-01 and no "managed" markers that nothing writes', !/SSHSpan managed/.test(await page.evaluate(() => document.getElementById('deployModal').textContent)));
    const plan = (await text(page, '#deployModal .deploy-preview')) || '';
    yes('A8-26 each key\'s real file and .pub are listed', plan.includes('/home/u/.ssh/sshspan_alpha') && plan.includes('/home/u/.ssh/sshspan_alpha.pub'), plan);
    yes('A2-46 a key the backend will refuse is shown with the reason', plan.includes(REFUSAL), plan);
    check('A5-05 the Include line is shown', await text(page, '#deployIncludeLine'), INCLUDE);
    check('the preview box fits inside the sheet (a leftover width rule pushed it past the edge)', await page.evaluate(() => {
      const t = document.getElementById('configPreview').getBoundingClientRect();
      const col = document.querySelector('#deployModal .deploy-preview').getBoundingClientRect();
      return t.left >= col.left && t.right <= col.right;
    }), true);
    yes('A5-05 with the managed file and where the line goes', plan.includes(CONFIG_PATH) && /top of ~\/\.ssh\/config/i.test(plan), plan);
    await part('copy the Include line', async () => {
      await page.click('#copyIncludeBtn');
      await page.waitForTimeout(80);
      check('A5-05 Copy puts the Include line on the clipboard', await page.evaluate(() => navigator.clipboard.readText()), INCLUDE);
    });

    await page.click('#deployConfigBtn');
    await waitVisible(page, '#confirmModal');
    const question = (await text(page, '#confirmMessage')) || '';
    yes('A8-26 the question names the real file it writes, and the key it will skip',
      question.includes('/home/u/.ssh/sshspan_alpha') && /beta/.test(question) && !/sshspan_<name>|\/ and update/.test(question), question);
    await answerConfirm(page, 'ok');
    await page.waitForTimeout(200);
    check('A2-05 key_deploy is sent the host fields the preview showed',
      await lastArgs(app, 'key_deploy'), { ids: ['k1', 'k2'], strictHostKey: true, hostAlias: 'web', hostname: '10.0.0.5', user: 'deploy', port: 2222 });
    const t = await toasts(page);
    yes('A2-46 a key the deploy refused is reported', t.some((x) => x.includes(REFUSAL)), JSON.stringify(t));
    yes('A2-05 so is a warning from a partial deploy', t.some((x) => x.includes(PARTIAL_WARNING)), JSON.stringify(t));
    check('the sheet closes after a deploy', await app.open('deployModal'), false);
    check('no page errors', app.errors, []);
  });

  await withApp(browser, server, {}, 'A2-33 validation before writing', async (app) => {
    const { page } = app;
    await stubDeploy(page);
    await openSheet(page, ['k1']);
    for (const port of ['70000', '0']) {
      await fillHostFields(page, { alias: 'web', hostname: '', user: 'deploy', port });
      check(`A2-33 port ${port} is refused in the sheet`, await text(page, '#deployFieldError'), 'Port must be between 1 and 65535.');
      check(`A2-33 in the error colour (port ${port})`, await page.evaluate(() => getComputedStyle(document.getElementById('deployFieldError')).color), 'rgb(244, 113, 125)');
      check(`A2-39 and never sent as a preview argument (port ${port})`,
        (await app.calls('key_deploy_preview')).some((c) => String(c.args.port) === port), false);
      await page.evaluate(() => { window.__d = deployConfig(); });
      await settled(page, () => window.__d, null, 1500);
      check(`A2-33 nothing is deployed with port ${port}`, [await app.count('key_deploy'), await app.open('confirmModal')], [0, false]);
    }
    await fillHostFields(page, { alias: '', hostname: '', user: '', port: '' });
    await page.evaluate(() => { const t = document.getElementById('deployRegisterToggle'); if (!t.checked) t.click(); });
    await page.evaluate(() => { window.__d = deployConfig(); });
    await settled(page, () => window.__d, null, 1500);
    check('A2-33 "Also save as servers" without a Host alias and User stops BEFORE anything is written',
      [await app.count('key_deploy'), await app.open('confirmModal'), await app.open('deployModal')], [0, false, true]);
    const said = [(await text(page, '#deployFieldError')) || '', ...(await toasts(page))].join(' | ');
    yes('A2-33 and says what is missing', /Host alias/.test(said) && /User/.test(said), said);
    check('no page errors', app.errors, []);
  });

  await withApp(browser, server, {}, 'A2-33 servers saved before the sheet closes', async (app) => {
    const { page } = app;
    await stubDeploy(page);
    await openSheet(page, ['k1']);
    await fillHostFields(page, { alias: 'web', hostname: '10.0.0.5', user: 'deploy', port: '2222' });
    await page.evaluate(() => { const t = document.getElementById('deployRegisterToggle'); if (!t.checked) t.click(); });
    await hold(page, 'server_save');
    await page.evaluate(() => { window.__d = deployConfig(); });
    await answerConfirm(page, 'ok');
    await page.waitForTimeout(150);
    check('A2-33 the server is saved while the sheet is still open', [await app.count('server_save'), await app.open('deployModal')], [1, true]);
    await letGo(page, 'server_save');
    await settled(page, () => window.__d, null, 1500);
    await page.waitForTimeout(80);
    const saved = (await lastArgs(app, 'server_save')) || {};
    check('A2-33 with the fields of the deploy', [saved.name, saved.host, saved.port, saved.username, saved.authMethod, saved.pemPath],
      ['web', '10.0.0.5', 2222, 'deploy', 'publickey', '/home/u/.ssh/sshspan_alpha']);
    check('and then the sheet closes', await app.open('deployModal'), false);
    check('no page errors', app.errors, []);
  });

  await withApp(browser, server, {}, 'A2-33 server_save errors are shown', async (app) => {
    const { page } = app;
    await stubDeploy(page);
    await page.evaluate(() => { window.__replies.server_save = { $reject: 'Server host is required.' }; });
    await openSheet(page, ['k1']);
    await fillHostFields(page, { alias: 'web', hostname: '10.0.0.5', user: 'deploy', port: '22' });
    await page.evaluate(() => { const t = document.getElementById('deployRegisterToggle'); if (!t.checked) t.click(); window.__d = deployConfig(); });
    await answerConfirm(page, 'ok');
    await settled(page, () => window.__d, null, 1500);
    await page.waitForTimeout(80);
    const t = await toasts(page);
    yes('A2-33 a server that could not be saved is reported, with the reason', t.some((x) => /Server host is required\./.test(x)), JSON.stringify(t));
    check('no page errors', app.errors, []);
  });

  await withApp(browser, server, {}, 'A7-32 passphrase and servers', async (app) => {
    const { page } = app;
    await stubDeploy(page);
    await openSheet(page, ['k1']);
    await page.evaluate(() => { const t = document.getElementById('deployRegisterToggle'); if (!t.checked) t.click(); });
    await page.evaluate(() => document.getElementById('keyPassphraseToggle').click());
    await page.waitForTimeout(60);
    check('A7-32 with a deploy passphrase, "Also save as servers" is off and disabled',
      await page.evaluate(() => [document.getElementById('deployRegisterToggle').checked, document.getElementById('deployRegisterToggle').disabled]), [false, true]);
    yes('A7-32 and it says why', /passphrase/i.test((await text(page, '#deployRegisterHint')) || ''), await text(page, '#deployRegisterHint'));
    await page.evaluate(() => document.getElementById('keyPassphraseToggle').click());
    await page.waitForTimeout(60);
    check('A7-32 without the passphrase it can be used again', await page.evaluate(() => document.getElementById('deployRegisterToggle').disabled), false);
    check('no page errors', app.errors, []);
  });

  const longKeys = [KEY('k1', 'a-very-long-key-name-for-the-production-deployment-pipeline-runner'), KEY('k2', 'gamma')];
  await withApp(browser, server, { keys: longKeys }, 'the sheet\'s form at 1100x720', async (app) => {
    const { page } = app;
    await page.setViewportSize({ width: 1100, height: 720 });
    await openSheet(page, ['k1', 'k2']);
    check('the key chips keep their height (the taller form squeezed them under the first field)', await page.evaluate(() => {
      const chips = document.getElementById('deployKeyChips');
      const next = chips.nextElementSibling.getBoundingClientRect();
      return chips.scrollHeight <= chips.clientHeight + 1 && chips.getBoundingClientRect().bottom <= next.top;
    }), true);
    check('no page errors', app.errors, []);
  });

  const winPaths = { system_paths: { database: 'C:\\Users\\u\\AppData\\Roaming\\sshspan\\sshspan.db', sshConfig: 'C:\\Users\\u\\AppData\\Roaming\\sshspan\\config\\ssh\\config', deployDir: 'C:\\Users\\u\\.ssh' } };
  await withApp(browser, server, { replies: winPaths }, 'A8-26 paths and copy', async (app) => {
    const { page } = app;
    await openSheet(page, ['k1']);
    check('A8-26 the key path is joined with the separator the platform uses', await text(page, '#deployDirHint'), 'C:\\Users\\u\\.ssh\\sshspan_<name>');
    await page.keyboard.press('Escape');
    await page.evaluate(() => { state.deploySelected.clear(); return copyConfig(); });
    await page.waitForTimeout(60);
    const t = await toasts(page);
    yes('A2-34 Copy config with nothing selected says what to do, not "preview first"',
      t.some((x) => /select at least one key/i.test(x)) && !t.some((x) => /preview first/i.test(x)), JSON.stringify(t));
    check('no page errors', app.errors, []);
  });
}

// ─── item 7: removing a deployed copy (A7-22 / A5-43 / A8-16) ──────────────

async function scenarioUndeploy(browser, server) {
  const keys = [DEPLOYED('k1', 'alpha'), KEY('k2', 'beta')];
  const removed = { ok: true, removed: ['/home/u/.ssh/sshspan_alpha', '/home/u/.ssh/sshspan_alpha.pub'], removedHosts: ['web'], warnings: ['Could not update /cfg/ssh/config: permission denied'] };
  await withApp(browser, server, { keys, replies: { key_remove_deployed: removed } }, 'Remove deployed copy', async (app) => {
    const { page } = app;
    await page.click('#keyList .key-row[data-id="k2"]');
    await page.waitForTimeout(80);
    check('A5-43 a key that is not deployed offers no "Remove deployed copy"', await shown(page, '#detailUndeployBtn'), false);
    await page.click('#keyList .key-row[data-id="k1"]');
    await page.waitForTimeout(80);
    check('A5-43 a deployed key does', await shown(page, '#detailUndeployBtn'), true);
    await part('remove it', async () => {
      await page.click('#detailUndeployBtn');
      yes('A7-22 it asks first', await answerConfirm(page, 'cancel'));
      check('A7-22 Cancel removes nothing', await app.count('key_remove_deployed'), 0);
      const listed = await app.count('key_list');
      await page.click('#detailUndeployBtn');
      await answerConfirm(page, 'ok');
      await page.waitForTimeout(200);
      check('A7-22 OK removes the deployed copy of that key', await lastArgs(app, 'key_remove_deployed'), { id: 'k1' });
      const t = await toasts(page);
      yes('A7-22 the toast names the files and the Host blocks removed',
        t.some((x) => x.includes('/home/u/.ssh/sshspan_alpha') && /web/.test(x)), JSON.stringify(t));
      yes('A7-22 and a warning the backend returned', t.some((x) => /permission denied/.test(x)), JSON.stringify(t));
      check('A7-22 the key list is read again (the Deployed chip goes)', (await app.count('key_list')) - listed >= 1, true);
    });
    check('no page errors', app.errors, []);
  });

  const order = async (app) => (await app.calls()).filter((c) => c.cmd === 'key_remove_deployed' || c.cmd === 'key_delete').map((c) => c.cmd);
  await withApp(browser, server, { keys, replies: { key_remove_deployed: removed } }, 'delete a deployed key', async (app) => {
    const { page } = app;
    await page.click('#keyList .key-row[data-id="k1"]');
    await page.waitForTimeout(80);
    await page.click('#detailDeleteBtn');
    await waitVisible(page, '#confirmModal');
    check('A5-43 deleting a deployed key offers to remove its deployed files, ticked',
      [await shown(page, '#confirmOption'), await page.evaluate(() => !!(document.getElementById('confirmOption') || {}).checked)], [true, true]);
    yes('A5-43 and says what that removes', /deployed/i.test((await text(page, '#confirmOptionRow')) || ''), await text(page, '#confirmOptionRow'));
    await answerConfirm(page, 'ok');
    await page.waitForTimeout(200);
    check('A5-43 OK removes the deployed copy first, then deletes the key', await order(app), ['key_remove_deployed', 'key_delete']);
    check('no page errors', app.errors, []);
  });

  await withApp(browser, server, { keys }, 'delete a deployed key, keep its files', async (app) => {
    const { page } = app;
    await page.click('#keyList .key-row[data-id="k1"]');
    await page.waitForTimeout(80);
    await page.click('#detailDeleteBtn');
    await waitVisible(page, '#confirmModal');
    await page.evaluate(() => { const o = document.getElementById('confirmOption'); if (o && o.checked) o.click(); });
    await answerConfirm(page, 'ok');
    await page.waitForTimeout(200);
    check('A5-43 unticked, only the key is deleted', await order(app), ['key_delete']);
    check('no page errors', app.errors, []);
  });

  await withApp(browser, server, { keys, replies: { key_remove_deployed: { $reject: 'Could not remove /home/u/.ssh/sshspan_alpha: busy. The key is still marked as deployed.' } } }, 'removal fails', async (app) => {
    const { page } = app;
    await page.click('#keyList .key-row[data-id="k1"]');
    await page.waitForTimeout(80);
    await page.click('#detailDeleteBtn');
    await waitVisible(page, '#confirmModal');
    await answerConfirm(page, 'ok');
    await page.waitForTimeout(200);
    check('A5-43 when the deployed file cannot be removed, the key is not deleted', await order(app), ['key_remove_deployed']);
    const t = await toasts(page);
    yes('A5-43 and the reason is shown', t.some((x) => /still marked as deployed/.test(x)), JSON.stringify(t));
    check('no page errors', app.errors, []);
  });
}

// ─── review leftovers: the row's Connect menu, the drawer, the tree on lock ─

async function scenarioLeftovers(browser, server) {
  await withApp(browser, server, {}, 'Connect menu anchor', async (app) => {
    const { page } = app;
    await page.hover('#keyList .key-row[data-id="k2"]');
    await page.waitForTimeout(150);
    const btn = await page.evaluate(() => {
      const r = document.querySelector('#keyList .key-row[data-id="k2"] .row-btn').getBoundingClientRect();
      return { left: Math.round(r.left), bottom: Math.round(r.bottom) };
    });
    await page.click('#keyList .key-row[data-id="k2"] .row-btn');
    await page.waitForTimeout(100);
    const menu = await page.evaluate(() => {
      const m = document.getElementById('keyConnectMenu');
      if (!m) return null;
      const r = m.getBoundingClientRect();
      return { left: Math.round(r.left), top: Math.round(r.top) };
    });
    yes('the key row\'s Connect menu opens under its button, not in the window\'s corner',
      !!menu && Math.abs(menu.left - btn.left) <= 2 && Math.abs(menu.top - (btn.bottom + 4)) <= 2, JSON.stringify({ btn, menu }));
    check('no page errors', app.errors, []);
  });

  await withApp(browser, server, { unlocked: false }, 'drawer while locked', async (app) => {
    const { page } = app;
    check('the category drawer toggles are disabled at boot while the vault is locked, and say why',
      await page.evaluate(() => [...document.querySelectorAll('.cat-drawer-btn')].map((b) => [b.disabled, b.title])),
      [[true, 'Unlock the vault to see categories'], [true, 'Unlock the vault to see categories']]);
  });
  await withApp(browser, server, { hasVault: false, unlocked: false }, 'drawer with no vault', async (app) => {
    const { page } = app;
    const states = await page.evaluate(() => [...document.querySelectorAll('.cat-drawer-btn')].map((b) => [b.disabled, b.title]));
    yes('with no vault they are disabled too, and say a vault comes first',
      states.length === 2 && states.every(([d, t]) => d && /create a vault/i.test(t)), JSON.stringify(states));
  });

  await withApp(browser, server, { categories: CATS, replies: { category_list: CAT_REPLY({ k1: ['c1'] }) } }, 'the tree on lock', async (app) => {
    const { page } = app;
    await page.setViewportSize({ width: 880, height: 560 });
    await page.waitForTimeout(100);
    await page.click('#catDrawerBtn');
    await page.waitForTimeout(100);
    await page.click('#catTree .cat-node[data-id="c1"] .cat-actions-btn');
    await page.waitForTimeout(80);
    check('(set-up) the drawer and a category menu are open',
      await page.evaluate(() => [document.getElementById('app').classList.contains('cat-drawer-open'), !!document.getElementById('keyConnectMenu')]), [true, true]);
    await page.evaluate(() => lockNow());
    await page.waitForTimeout(200);
    check('locking leaves no category names in the sidebar',
      await page.evaluate(() => [...document.querySelectorAll('#catTree .cat-node')].map((n) => n.textContent)), []);
    check('and closes the drawer and the menu',
      await page.evaluate(() => [document.getElementById('app').classList.contains('cat-drawer-open'), !!document.getElementById('keyConnectMenu')]), [false, false]);
    check('the drawer toggle says why it is off', await page.evaluate(() => [document.getElementById('catDrawerBtn').disabled, document.getElementById('catDrawerBtn').title]),
      [true, 'Unlock the vault to see categories']);
    check('no page errors', app.errors, []);
  });
}

// ─── fix1: focus, secrets, restored cycles, bulk cleanup and preview races ──

async function scenarioFixFocus(browser, server) {
  for (const importing of [false, true]) {
    await withApp(browser, server, {}, 'focus after key submit failure', async (app) => {
      const { page } = app;
      const cmd = importing ? 'key_import' : 'key_create_with_categories';
      await page.focus('#newKeyBtn');
      await page.keyboard.press('Enter');
      await waitVisible(page, '#modalBackdrop');
      if (importing) {
        await page.click('#tabBtn-import');
        await page.fill('#importPem', OPENSSH_PEM);
      }
      await page.evaluate((c) => { window.__replies[c] = { $reject: 'Another vault operation is still running.' }; }, cmd);
      await hold(page, cmd);
      await page.focus('#modalPrimary');
      await page.keyboard.press('Enter');
      await page.waitForFunction((c) => window.__calls.some((x) => x.cmd === c), cmd);
      await letGo(page, cmd);
      await page.waitForFunction(() => !document.getElementById('modalPrimary').hasAttribute('aria-busy'));
      check(`I1 ${importing ? 'Import' : 'Create'} failure returns focus to the re-enabled button`, await app.focused(), 'modalPrimary');
      check('no page errors', app.errors, []);
    });
  }

  await withApp(browser, server, {}, 'export focus', async (app) => {
    const { page } = app;
    await openExportTab(page);
    await page.evaluate(() => { window.__replies.key_export_to_file = { $reject: 'Save failed.' }; });
    await hold(page, 'key_export_to_file');
    await page.focus('#detailExportBtn');
    await page.keyboard.press('Enter');
    await page.waitForFunction(() => window.__calls.some((x) => x.cmd === 'key_export_to_file'));
    await letGo(page, 'key_export_to_file');
    await page.waitForFunction(() => !document.getElementById('detailExportBtn').hasAttribute('aria-busy'));
    check('I1 export failure returns focus to Export', await app.focused(), 'detailExportBtn');

    // A meaningful focus change during the request must not be undone.
    await hold(page, 'key_export_to_file');
    await page.focus('#detailExportBtn');
    await page.keyboard.press('Enter');
    await page.focus('#searchInput');
    await letGo(page, 'key_export_to_file');
    await page.waitForFunction(() => !document.getElementById('detailExportBtn').hasAttribute('aria-busy'));
    check('I1 a user who moved to the search box keeps the focus there', await app.focused(), 'searchInput');
    check('no page errors', app.errors, []);
  });

  await withApp(browser, server, { keys: [DEPLOYED('k1', 'alpha'), KEY('k2', 'beta')] }, 'undeploy focus', async (app) => {
    const { page } = app;
    await page.evaluate(() => { window.__replies.key_remove_deployed = { $reject: 'File is busy.' }; });
    await hold(page, 'key_remove_deployed');
    await page.focus('#detailUndeployBtn');
    await page.keyboard.press('Enter');
    await answerConfirm(page, 'ok');
    await page.waitForFunction(() => window.__calls.some((x) => x.cmd === 'key_remove_deployed'));
    await letGo(page, 'key_remove_deployed');
    await page.waitForFunction(() => !document.getElementById('detailUndeployBtn').hasAttribute('aria-busy'));
    check('I1 a removal failure returns focus to Remove deployed copy', await app.focused(), 'detailUndeployBtn');
    await page.evaluate(() => {
      window.__replies.key_remove_deployed = () => {
        const keys = state.keys.map((k) => ({ ...k, deployed: false, deploy_path: null }));
        window.__replies.key_list = { keys };
        window.__replies.key_get = (a) => keys.find((k) => k.id === a.id);
        return { removed: ['/home/u/.ssh/sshspan_alpha'], removedHosts: ['web'], warnings: [] };
      };
    });
    await page.focus('#detailUndeployBtn');
    await page.keyboard.press('Enter');
    await answerConfirm(page, 'ok');
    await page.waitForFunction(() => document.getElementById('detailUndeployBtn').hidden);
    await page.waitForTimeout(60);
    check('I1 when success hides the removal button, focus goes to a stable search target', await app.focused(), 'searchInput');
    check('no page errors', app.errors, []);
  });

  await withApp(browser, server, { settings: { confirmDelete: 'false' } }, 'delete focus', async (app) => {
    const { page } = app;
    await page.evaluate(() => { window.__replies.key_list = { keys: state.keys.filter((k) => k.id !== 'k1') }; });
    await page.focus('#detailDeleteBtn');
    await page.keyboard.press('Enter');
    await page.waitForFunction(() => document.getElementById('detailPane').hidden);
    await page.waitForTimeout(60);
    check('I1 deleting the open key leaves focus on search, not body', await app.focused(), 'searchInput');
  });

  await withApp(browser, server, {}, 'deploy focus', async (app) => {
    const { page } = app;
    await stubDeploy(page);
    await openSheet(page, ['k1']);
    await page.evaluate(() => { window.__replies.key_deploy = { $reject: 'Deploy failed.' }; });
    await hold(page, 'key_deploy');
    await page.focus('#deployConfigBtn');
    await page.keyboard.press('Enter');
    await answerConfirm(page, 'ok');
    await page.waitForFunction(() => window.__calls.some((x) => x.cmd === 'key_deploy'));
    await letGo(page, 'key_deploy');
    await page.waitForFunction(() => !document.getElementById('deployConfigBtn').hasAttribute('aria-busy'));
    check('I1 a deploy failure returns focus to Deploy after the confirmation closes', await app.focused(), 'deployConfigBtn');
    check('no page errors', app.errors, []);
  });

  await withApp(browser, server, {}, 'A5-23 New key opener', async (app) => {
    const { page } = app;
    for (const how of ['escape', 'cancel']) {
      await page.focus('#newKeyBtn');
      await page.keyboard.press('Enter');
      await waitVisible(page, '#modalBackdrop');
      if (how === 'escape') await page.keyboard.press('Escape');
      else await page.click('#modalBackdrop .modal-footer [data-close]');
      await page.waitForTimeout(80);
      check(`A5-23 ${how} returns focus to New key (not a now-hidden genName)`, await app.focused(), 'newKeyBtn');
    }
    check('no page errors', app.errors, []);
  });
}

async function scenarioFixState(browser, server) {
  await withApp(browser, server, {}, 'filtered export secret', async (app) => {
    const { page } = app;
    await openExportTab(page);
    await page.fill('#detailExportPass', 'do-not-retain');
    await page.fill('#searchInput', 'beta');
    check('M1 filtering out the key wipes its export passphrase and switches to Overview',
      await page.evaluate(() => [document.getElementById('detailExportPass').value,
        document.getElementById('detailPanel-export').hidden, document.getElementById('detailPane').hidden]), ['', true, true]);
  });
  for (const how of ['remove', 'keep', 'no-confirm']) {
    const keys = [DEPLOYED('k1', 'alpha'), DEPLOYED('k2', 'beta'), KEY('k3', 'gamma')];
    await withApp(browser, server, { keys, settings: { confirmDelete: how === 'no-confirm' ? 'false' : 'true' } }, 'bulk deployed delete', async (app) => {
      const { page } = app;
      await page.evaluate(() => {
        state.deploySelected = new Set(state.keys.map((k) => k.id)); renderKeyList(); updateSelectionHint();
        window.__replies.key_remove_deployed = (a) => ({ removed: ['/home/u/.ssh/' + a.id], removedHosts: [a.id], warnings: [] });
        window.__replies.key_delete = (a) => {
          window.__replies.key_list = { keys: state.keys.filter((k) => k.id !== a.id) };
          return { ok: true };
        };
      });
      await page.focus('#selDeleteBtn');
      await page.keyboard.press('Enter');
      if (how !== 'no-confirm') {
        await waitVisible(page, '#confirmModal');
        check('M6 bulk delete offers deployed-copy cleanup', await shown(page, '#confirmOption'), true);
        if (how === 'keep') await page.evaluate(() => document.getElementById('confirmOption').click());
        await answerConfirm(page, 'ok');
      }
      await page.waitForFunction(() => window.__calls.filter((c) => c.cmd === 'key_delete').length === 3);
      await page.waitForTimeout(100);
      const effects = (await app.calls()).filter((c) => ['key_remove_deployed', 'key_delete'].includes(c.cmd)).map((c) => [c.cmd, c.args.id]);
      check(`M6 bulk deletion ${how} removes files before their vault records only when selected`, effects, how === 'remove'
        ? [['key_remove_deployed', 'k1'], ['key_delete', 'k1'], ['key_remove_deployed', 'k2'], ['key_delete', 'k2'], ['key_delete', 'k3']]
        : [['key_delete', 'k1'], ['key_delete', 'k2'], ['key_delete', 'k3']]);
      if (how !== 'remove') yes(`M2 ${how} counts the two deployed copies intentionally left on disk`,
        (await toasts(page)).some((t) => /2 deployed copies.*(?:left|still) on disk/i.test(t)), JSON.stringify(await toasts(page)));
      check('no page errors', app.errors, []);
    });
  }

  await withApp(browser, server, {}, 'disabled register style', async (app) => {
    const { page } = app;
    await stubDeploy(page);
    await openSheet(page, ['k1']);
    await page.evaluate(() => document.getElementById('keyPassphraseToggle').click());
    const style = await page.evaluate(() => {
      const row = document.getElementById('deployRegisterToggle').closest('.opt-row');
      const s = getComputedStyle(row);
      return { opacity: Number(s.opacity), cursor: s.cursor };
    });
    yes('M3 the disabled server option is dimmed and uses the disabled cursor', style.opacity < 1 && style.cursor === 'not-allowed', JSON.stringify(style));
  });

  const cycle = [CAT('root', 'Outside', null, 0), CAT('ca', 'CycA', 'cb', 1), CAT('cb', 'CycB', 'ca', 2),
    CAT('cc', 'CycC', 'cd', 3), CAT('cd', 'CycD', 'cc', 4), CAT('self', 'Self', 'self', 5)];
  await withApp(browser, server, { keys: [Object.assign(KEY('k1', 'alpha'), { category_ids: ['ca'] })], categories: cycle,
    replies: { category_list: { categories: cycle, allKeyCategories: { k1: ['ca'] }, orphans: false, hostOrphans: false } } }, 'restored category cycles', async (app) => {
    const { page } = app;
    check('M4 one member of each cycle is a UI root, including a self-cycle',
      await page.evaluate(() => childrenOf(null).map((c) => c.id)), ['root', 'ca', 'cc', 'self']);
    check('M4 rebuilding the index never changes the persisted parent links',
      await page.evaluate(() => state.categories.map((c) => [c.id, c.parent_id])), cycle.map((c) => [c.id, c.parent_id]));
    check('M4 the boot tree includes Uncategorized for keys only under cycles', await shown(page, '#catTree .uncategorized'), true);
    check('M4 every cycle member is in the tree once (no recursive loop)', await page.$$eval('#catTree .cat-node:not(.uncategorized)', (ns) => ns.map((n) => n.dataset.id).sort()), cycle.map((c) => c.id).sort());
    await part('move a cycle member', async () => {
      await page.click('#catTree .cat-node[data-id="ca"] .cat-actions-btn');
      await page.click('#keyConnectMenu .ctx-item:has-text("Move to")');
      await waitVisible(page, '#pickerModal');
      // fix2 (N1): loop members are never offered as a destination; the top
      // level and categories outside loops are.
      check('M4 Move to... for a loop member offers the top level and categories outside loops only',
        await page.$$eval('#pickerTree .picker-row', (ns) => ns.map((n) => n.dataset.id)), ['', 'root']);
      await page.evaluate(() => {
        window.__replies.category_reparent = (a) => {
          window.__replies.category_list = { ...window.__replies.category_list,
            categories: state.categories.map((c) => c.id === a.id ? { ...c, parent_id: a.newParentId } : c) };
          return { ok: true };
        };
      });
      await page.click('#pickerTree .picker-row[data-id="root"]');
      await page.waitForTimeout(100);
      check('M4 Move to can break the persisted cycle', await lastArgs(app, 'category_reparent'), { id: 'ca', newParentId: 'root' });
      check('M4 read-back has the repaired parent, not the promoted UI parent', await page.evaluate(() => catById('ca').parent_id), 'root');
    });
    check('no page errors', app.errors, []);
  });
}

async function scenarioFixPreview(browser, server) {
  await withApp(browser, server, {}, 'preview order and failures', async (app) => {
    const { page } = app;
    await stubDeploy(page);
    await openSheet(page, ['k1']);
    await page.evaluate(() => {
      const reply = window.__replies.key_deploy_preview;
      window.__replies.key_deploy_preview = (a) => new Promise((resolve) => setTimeout(() => resolve(reply(a)), a.hostAlias === 'slow' ? 240 : 10));
      document.getElementById('cfgHost').value = 'slow'; window.__slow = previewConfig();
      document.getElementById('cfgHost').value = 'fast'; window.__fast = previewConfig();
    });
    await page.evaluate(() => Promise.all([window.__slow, window.__fast]));
    yes('M6 a late preview cannot replace the newer fields', /Host fast\n/.test(await page.inputValue('#configPreview')));
    await page.evaluate((m) => { window.__replies.key_deploy_preview = { $reject: m }; return previewConfig(); }, 'Host alias cannot contain *, ? or !.');
    check('M6 a preview rejection stays in the field error with no stale config',
      [await text(page, '#deployFieldError'), await page.inputValue('#configPreview'), await page.isDisabled('#deployConfigBtn')],
      ['Host alias cannot contain *, ? or !.', '', true]);
    await page.evaluate(() => {
      window.__replies.key_deploy_preview = { configPath: '/cfg/config', includeLine: 'Include "/cfg/config"', configText: '',
        keys: [{ id: 'k1', name: 'alpha', file: '/ssh/alpha', aliasOwnedByOtherKey: true, refusal: 'Not deployed: this alias belongs to beta.' }] };
      return previewConfig();
    });
    check('M6 an all-refused plan disables Deploy', await page.isDisabled('#deployConfigBtn'), true);
    yes('M6 alias-ownership refusal is visible before any deploy', ((await text(page, '#deployPlan')) || '').includes('this alias belongs to beta'));
    check('no writes for a refused preview', await app.count('key_deploy'), 0);
    check('no page errors', app.errors, []);
  });

  await withApp(browser, server, {}, 'debounced preview', async (app) => {
    const { page } = app;
    await stubDeploy(page);
    await openSheet(page, ['k1']);
    const before = await app.count('key_deploy_preview');
    await page.evaluate(() => {
      const input = document.getElementById('cfgHost');
      for (const v of ['a', 'ab', 'abc']) { input.value = v; input.dispatchEvent(new Event('input', { bubbles: true })); }
    });
    check('M7 typing schedules a preview instead of one IPC per keystroke', (await app.count('key_deploy_preview')) - before, 0);
    await page.waitForTimeout(210);
    check('M7 the burst asks for just the latest value once', (await app.calls('key_deploy_preview')).slice(before).map((c) => c.args.hostAlias), ['abc']);
    const ready = await app.count('key_deploy_preview');
    await page.evaluate(() => {
      const input = document.getElementById('cfgHost');
      input.value = 'fresh'; input.dispatchEvent(new Event('input', { bubbles: true }));
      window.__deploy = deployConfig();
    });
    await waitVisible(page, '#confirmModal');
    check('M7 the final deploy check bypasses the debounce and uses fresh fields', (await app.calls('key_deploy_preview')).slice(ready).map((c) => c.args.hostAlias), ['fresh']);
    await answerConfirm(page, 'cancel');
    await page.waitForTimeout(210);
    check('M7 no obsolete scheduled request runs after that fresh check', (await app.count('key_deploy_preview')) - ready, 1);
    check('no page errors', app.errors, []);
  });
}

async function scenarioFixCopy(browser, server) {
  await withApp(browser, server, {}, 'key dialog copy', async (app) => {
    const { page } = app;
    await page.evaluate(() => openKeyModal());
    check('A8-25 Generate title is sentence case', await text(page, '#modalTitle'), 'New key');
    await page.evaluate(() => switchTab('import'));
    check('A8-25 Import title is sentence case', await text(page, '#modalTitle'), 'Import key');
    await page.evaluate((pemText) => { window.__replies.system_select_file = { text: pemText, name: 'alpha.key' }; return browseForImport(); }, OPENSSH_PEM);
    check('A8-25 import hint uses the project dash style', await text(page, '#importFileHint'), 'Loaded alpha.key - press Import to add it.');
    await page.evaluate(() => { switchTab('generate'); document.getElementById('genType').value = 'rsa'; onGenTypeChange(); });
    yes('A5-12(d) RSA 4096/8192 duration is explained beside Bits',
      /4096/.test((await text(page, '#genBitsHint')) || '') && /8192/.test((await text(page, '#genBitsHint')) || '')
      && /minute/i.test((await text(page, '#genBitsHint')) || ''), await text(page, '#genBitsHint'));
    const hintFor = async (type) => {
      await page.evaluate((t) => { document.getElementById('genType').value = t; onGenTypeChange(); }, type);
      return shown(page, '#genBitsHint');
    };
    // Both halves (fix2 item 2): a hint left visible for every type passed the
    // RSA-only assertion this used to be.
    check('A5-12(d) the RSA duration hint is shown only for RSA (rsa, ed25519, ecdsa)',
      [await hintFor('rsa'), await hintFor('ed25519'), await hintFor('ecdsa')], [true, false, false]);
  });
}

// ─── fix2 (N1): a restored category loop must never be a move destination ──
//
// category_reparent walks the new parent's saved chain upwards looking for the
// moved id, with no visited set and on the main thread: a destination whose
// chain runs in a loop that does not contain the moved category never ends,
// and the app freezes. Every refused move below must send NO category_reparent.

const LOOPS = [CAT('root', 'Outside', null, 0), CAT('ca', 'CycA', 'cb', 1), CAT('cb', 'CycB', 'ca', 2),
  CAT('cc', 'CycC', 'cd', 3), CAT('cd', 'CycD', 'cc', 4), CAT('self', 'Self', 'self', 5)];
const LOOP_REFUSAL = 'That category is part of a loop - move one of its categories to the top level first.';
const loopOpts = () => ({
  keys: [Object.assign(KEY('k1', 'alpha'), { category_ids: ['ca'] })], categories: LOOPS,
  replies: { category_list: { categories: LOOPS, allKeyCategories: { k1: ['ca'] }, orphans: false, hostOrphans: false } },
});
const reparents = async (app) => (await app.calls('category_reparent')).map((c) => c.args);
const orders = async (app) => (await app.calls('category_set_order')).map((c) => c.args);
/// Reparents and orders that the stub applies to the next category_list, like
/// the backend. category_set_order as commands/mod.rs category_set_order_in
/// runs it: the WHOLE list of one parent - at the top level that includes
/// every category whose parent is missing or whose chain of parents never
/// reaches the top (a loop member, or one below a loop) - numbered 0, 1, 2 in
/// that order; a partial list, a mixed one or an unknown id is refused.
const applyReparents = (page) => page.evaluate(() => {
  const list = () => window.__replies.category_list;
  const put = (categories) => { window.__replies.category_list = { ...list(), categories }; };
  window.__replies.category_reparent = (a) => {
    put(list().categories.map((c) => c.id === a.id
      ? { ...c, parent_id: a.newParentId, sort_index: a.sortIndex == null ? c.sort_index : a.sortIndex } : c));
    return { ok: true };
  };
  window.__replies.category_set_order = (a) => {
    const all = list().categories;
    const byId = new Map(all.map((c) => [c.id, c]));
    const rooted = (c) => {
      const seen = new Set();
      for (let cur = c; cur; cur = byId.get(cur.parent_id)) {
        if (seen.has(cur.id)) return false;
        seen.add(cur.id);
        if (!cur.parent_id || !byId.has(cur.parent_id)) return true;
      }
      return true;
    };
    const atTop = (c) => !c.parent_id || !byId.has(c.parent_id) || !rooted(c);
    const inList = (c) => (a.parentId == null ? atTop(c) : c.parent_id === a.parentId);
    const named = a.orderedIds.map((id) => byId.get(id));
    if (named.some((c) => !c)) throw 'That category no longer exists.';
    if (new Set(a.orderedIds).size !== a.orderedIds.length) throw 'The list names a category twice.';
    const scope = named.length ? named[0].scope : null;
    if (!named.every((c) => c.scope === scope && inList(c))) throw 'Those categories do not share a parent - reload the categories and try again.';
    if (scope && all.some((c) => c.scope === scope && inList(c) && !a.orderedIds.includes(c.id))) {
      throw 'The new order must name every category under that parent - reload the categories and try again.';
    }
    put(all.map((c) => (a.orderedIds.includes(c.id) ? { ...c, sort_index: a.orderedIds.indexOf(c.id) } : c)));
    return { ok: true };
  };
});
/// The backend's refusals of a category order the renderer got wrong.
const ORDER_REFUSALS = /must name every category|do not share a parent|names a category twice|no longer exists/;

async function scenarioFix2Loops(browser, server) {
  for (const [title, from, to, frac] of [
    ['drag Outside into CycA', 'root', 'ca', 0.5],
    ['drag Outside into the self-loop Self', 'root', 'self', 0.5],
  ]) {
    await withApp(browser, server, loopOpts(), title, async (app) => {
      const { page } = app;
      await dragCategory(page, from, to, frac);
      await page.waitForTimeout(150);
      check(`N1 ${title}: refused, no category_reparent is sent`, await reparents(app), []);
      yes(`N1 ${title}: and the toast says why`, (await toasts(page)).includes(LOOP_REFUSAL), JSON.stringify(await toasts(page)));
      check('no page errors', app.errors, []);
    });
  }

  await withApp(browser, server, loopOpts(), 'drop above a promoted loop member', async (app) => {
    const { page } = app;
    await dragCategory(page, 'root', 'ca', 0.1);
    await page.waitForTimeout(150);
    check('N1 a drop on the top edge of CycA (shown at top level) writes no parent: the promoted roots CycA, CycC and Self keep theirs',
      await reparents(app), []);
    check('the top level is numbered as shown, the loop members it shows nested after it',
      await orders(app), [{ parentId: null, orderedIds: ['root', 'ca', 'cc', 'self', 'cb', 'cd'] }]);
    check('no page errors', app.errors, []);
  });

  await withApp(browser, server, loopOpts(), 'Move to... targets', async (app) => {
    const { page } = app;
    await page.click('#catTree .cat-node[data-id="root"] .cat-actions-btn');
    await page.click('#keyConnectMenu .ctx-item:has-text("Move to")');
    await waitVisible(page, '#pickerModal');
    check('N1 Move to... for Outside offers the top level and no loop member',
      await page.$$eval('#pickerTree .picker-row', (ns) => ns.map((n) => n.dataset.id)), ['']);
    // A destination that still reaches the picker's callback is refused too.
    await page.evaluate(() => state.pickerCallback(['cb']));
    await page.waitForTimeout(100);
    check('N1 Move to... Outside -> CycB: refused, no category_reparent is sent', await reparents(app), []);
    yes('N1 and the toast says why', (await toasts(page)).includes(LOOP_REFUSAL), JSON.stringify(await toasts(page)));
    check('no page errors', app.errors, []);
  });

  await withApp(browser, server, loopOpts(), 'repair by Move to... top level', async (app) => {
    const { page } = app;
    await applyReparents(page);
    await page.click('#catTree .cat-node[data-id="ca"] .cat-actions-btn');
    await page.click('#keyConnectMenu .ctx-item:has-text("Move to")');
    await waitVisible(page, '#pickerModal');
    check('N1 Move to... for a loop member offers the top level and categories outside loops',
      await page.$$eval('#pickerTree .picker-row', (ns) => ns.map((n) => n.dataset.id)), ['', 'root']);
    await page.click('#pickerTree .picker-row[data-id=""]');
    await page.waitForTimeout(150);
    check('N1 the repair: a loop member can still be moved to the top level', await reparents(app), [{ id: 'ca', newParentId: null }]);
    check('N1 after the repair the loop is gone: CycA is a real root and CycB sits under it',
      await page.evaluate(() => [catById('ca').parent_id, childrenOf(null).map((c) => c.id), childrenOf('ca').map((c) => c.id)]),
      [null, ['root', 'ca', 'cc', 'self'], ['cb']]);
    check('no page errors', app.errors, []);
  });

  await withApp(browser, server, loopOpts(), 'repair by drag to the top level', async (app) => {
    const { page } = app;
    await applyReparents(page);
    await dragCategory(page, 'cb', 'root', 0.1);
    await page.waitForTimeout(250);
    check('N1 dragging loop member CycB above Outside moves it to the top level: its parent is the one written',
      await reparents(app), [{ id: 'cb', newParentId: null }]);
    check('N1 then the top level, as the repair left it, is numbered with CycB above Outside',
      [await topOrder(page), await page.evaluate(() => childrenOf('cb').map((c) => c.id))], [['CycB', 'Outside', 'CycC', 'Self'], ['ca']]);
    check('every write was taken', (await toasts(page)).filter((t) => ORDER_REFUSALS.test(t)), []);
    check('no page errors', app.errors, []);
  });
}

// ─── JU6b: pointer drags in the tree (Task 16 / A3-23 / SC 2.5.7) ──────────

/// The top level as the tree shows it, after the stub applied every move.
const topOrder = (page) => page.evaluate(() => childrenOf(null).map((c) => c.name));

async function scenarioPointerCategories(browser, server) {
  const ROOTS = [CAT('c1', 'Alpha', null, 0), CAT('c2', 'Beta', null, 1), CAT('c3', 'Gamma', null, 2)];
  const reply = { categories: ROOTS, allKeyCategories: {}, orphans: false, hostOrphans: false };
  await withApp(browser, server, { categories: ROOTS, replies: { category_list: reply } }, 'A3-23 a category dragged with the mouse', async (app) => {
    const { page } = app;
    const seen = await dragCategory(page, 'c3', 'c1', 0.5, {
      during: () => page.evaluate(() => {
        const g = document.querySelector('.drag-ghost');
        return {
          ghost: g ? g.textContent : null,
          into: [...document.querySelectorAll('#catTree .cat-node.drop-into')].map((n) => n.dataset.id),
          dragging: [...document.querySelectorAll('#catTree .cat-node.dragging')].map((n) => n.dataset.id),
        };
      }),
    });
    check('A3-23 a ghost names the category being dragged', seen && seen.ghost, 'Gamma');
    check('A3-23 the row under the pointer shows where it would go (into Alpha)', seen && seen.into, ['c1']);
    check('A3-23 the dragged row is marked', seen && seen.dragging, ['c3']);
    await page.waitForTimeout(200);
    check('A3-23 released on the middle of Alpha it is re-parented under Alpha',
      [await reparents(app), await orders(app)], [[{ id: 'c3', newParentId: 'c1' }], [{ parentId: 'c1', orderedIds: ['c3'] }]]);
    check('the ghost and the marks are gone',
      await page.evaluate(() => document.querySelectorAll('.drag-ghost, .cat-node.dragging, .cat-node.drop-into, .cat-node.drop-before, .cat-node.drop-after').length), 0);
    check('A3-23 the release is not also a click that filters the list', await page.evaluate(() => activeCategoryId()), 'all');

    const before = (await reparents(app)).length;
    const mid = await dragCategory(page, 'c1', 'c3', 0.9, {
      escape: true,
      during: () => page.evaluate(() => !!document.querySelector('.drag-ghost')),
    });
    await page.waitForTimeout(200);
    yes('(set-up) a drag was under way when Escape was pressed', mid === true);
    check('A3-23 Escape mid-drag posts nothing', (await reparents(app)).length - before, 0);
    check('A3-23 and leaves no ghost or highlight behind',
      await page.evaluate(() => document.querySelectorAll('.drag-ghost, .cat-node.dragging, .cat-node.drop-into, .cat-node.drop-before, .cat-node.drop-after').length), 0);
    check('the release after Escape does not filter the list either', await page.evaluate(() => activeCategoryId()), 'all');

    // Dragged away and brought back onto its own row: nowhere to go, and the
    // release there is not a click on the row (the browser sends one when the
    // press and the release are on the same element).
    const before2 = (await reparents(app)).length;
    const back = await dragCategory(page, 'c2', 'c2', 0.5, { during: () => page.evaluate(() => !!document.querySelector('.drag-ghost')) });
    await page.waitForTimeout(200);
    yes('(set-up) a drag was under way over its own row', back === true);
    check('A3-23 a drag released on its own row moves nothing', (await reparents(app)).length - before2, 0);
    check('A3-23 and does not filter by it either', await page.evaluate(() => activeCategoryId()), 'all');

    await page.click('#catTree .cat-node[data-id="c2"] .cat-label');
    check('a plain click (no drag) still filters by the category', await page.evaluate(() => activeCategoryId()), 'c2');
    await page.click('#catTree .cat-node[data-id="c2"] .cat-actions-btn');
    check('SC 2.5.7 the row menu keeps Move to... (the same without dragging)',
      await page.evaluate(() => [...document.querySelectorAll('#keyConnectMenu .ctx-item')].map((b) => b.textContent.trim()).includes('Move to...')), true);
    check('no page errors', app.errors, []);
  });

  // The JU4 review's order probes: a drop AFTER a promoted loop root, or after
  // a row whose parent no longer exists, used to land one place early - and
  // a second try changed nothing.
  for (const [title, from, to, want] of [
    ['Outside after CycC', 'root', 'cc', ['CycA', 'CycC', 'Outside', 'Self']],
    ['Outside after Self', 'root', 'self', ['CycA', 'CycC', 'Self', 'Outside']],
  ]) {
    await withApp(browser, server, loopOpts(), `JU4 order probe: ${title}`, async (app) => {
      const { page } = app;
      await applyReparents(page);
      await dragCategory(page, from, to, 0.9);
      await page.waitForTimeout(250);
      check(`JU4 probe ${title}: the order read back`, await topOrder(page), want);
      check(`JU4 probe ${title}: no promoted loop root was rewritten`,
        (await reparents(app)).filter((a) => ['ca', 'cb', 'cc', 'cd', 'self'].includes(a.id)), []);
      check('no page errors', app.errors, []);
    });
  }

  const DANGLING = [CAT('a', 'Alpha', null, 0), CAT('b', 'Bravo', 'gone', 1), CAT('c', 'Charlie', null, 2), CAT('d', 'Delta', 'missing', 3)];
  const danglingOpts = () => ({ categories: DANGLING,
    replies: { category_list: { categories: DANGLING, allKeyCategories: {}, orphans: false, hostOrphans: false } } });
  for (const [title, from, want] of [
    ['Alpha after Delta', 'a', ['Bravo', 'Charlie', 'Delta', 'Alpha']],
    ['Bravo after Delta', 'b', ['Alpha', 'Charlie', 'Delta', 'Bravo']],
  ]) {
    await withApp(browser, server, danglingOpts(), `JU4 order probe: ${title}`, async (app) => {
      const { page } = app;
      await applyReparents(page);
      check('(set-up) the rows whose parent is gone are shown at the top level', await topOrder(page), ['Alpha', 'Bravo', 'Charlie', 'Delta']);
      await dragCategory(page, from, 'd', 0.9);
      await page.waitForTimeout(250);
      check(`JU4 probe ${title}: the order read back`, await topOrder(page), want);
      await dragCategory(page, from, 'd', 0.9);
      await page.waitForTimeout(250);
      check(`JU4 probe ${title}: dropping it there again keeps it there`, await topOrder(page), want);
      check('no page errors', app.errors, []);
    });
  }
}

// ─── JU6b fix round: reordering without dragging, the drag's gates ──────────

/// The category menu's items for `id`, with their disabled state.
const catMenu = async (page, id) => {
  await page.click(`#catTree .cat-node[data-id="${id}"] .cat-actions-btn`);
  return page.evaluate(() => [...document.querySelectorAll('#keyConnectMenu .ctx-item')]
    .map((b) => [b.textContent.trim(), b.disabled]));
};

async function scenarioCategoryOrderNoDrag(browser, server) {
  const ROOTS = [CAT('c1', 'Alpha', null, 0), CAT('c2', 'Beta', null, 1), CAT('c3', 'Gamma', null, 2)];
  const opts = () => ({ categories: ROOTS, replies: { category_list: { categories: ROOTS, allKeyCategories: {}, orphans: false, hostOrphans: false } } });
  await withApp(browser, server, opts(), 'M2 Move up and Move down', async (app) => {
    const { page } = app;
    await applyReparents(page);
    const first = await catMenu(page, 'c1');
    check('M2 the category menu offers Move up and Move down (SC 2.5.7: reordering without a drag)',
      first.map(([l]) => l), ['Rename', 'New subcategory', 'Move to...', 'Move up', 'Move down', 'Delete']);
    check('M2 the first category cannot move up', first.filter(([l]) => /^Move (up|down)$/.test(l)), [['Move up', true], ['Move down', false]]);
    check('M2 both show a drawn arrow (not an empty icon slot)', await page.evaluate(() => [...document.querySelectorAll('#keyConnectMenu .ctx-item')]
      .filter((b) => /^Move (up|down)$/.test(b.textContent.trim())).map((b) => b.querySelectorAll('svg path').length > 0)), [true, true]);
    await page.keyboard.press('Escape');
    const last = await catMenu(page, 'c3');
    check('M2 the last category cannot move down', last.filter(([l]) => /^Move (up|down)$/.test(l)), [['Move up', false], ['Move down', true]]);
    await page.keyboard.press('Escape');
    await catMenu(page, 'c1');
    await page.click('#keyConnectMenu .ctx-item:has-text("Move down")');
    await page.waitForTimeout(250);
    check('M2 Move down puts it one place lower', await topOrder(page), ['Beta', 'Alpha', 'Gamma']);
    await catMenu(page, 'c3');
    await page.click('#keyConnectMenu .ctx-item:has-text("Move up")');
    await page.waitForTimeout(250);
    check('M2 Move up one place higher', await topOrder(page), ['Beta', 'Gamma', 'Alpha']);
    await page.focus('#catTree .cat-node[data-id="c2"]');
    await page.keyboard.press('Alt+ArrowDown');
    await page.waitForTimeout(250);
    check('M2 Alt+ArrowDown on a focused category moves it down', await topOrder(page), ['Gamma', 'Beta', 'Alpha']);
    check('M2 and the focus stays on it', await page.evaluate(() => document.activeElement && document.activeElement.dataset.id), 'c2');
    await page.keyboard.press('Alt+ArrowUp');
    await page.waitForTimeout(250);
    check('M2 Alt+ArrowUp moves it back up', await topOrder(page), ['Beta', 'Gamma', 'Alpha']);
    check('M2 a move among siblings writes no parent', await reparents(app), []);
    const sent = (await orders(app)).length;
    await page.keyboard.press('Alt+ArrowUp');
    await page.waitForTimeout(250);
    check('M2 at the top Alt+ArrowUp does nothing', [await topOrder(page), (await orders(app)).length - sent], [['Beta', 'Gamma', 'Alpha'], 0]);
    check('no page errors', app.errors, []);
  });

  await withApp(browser, server, opts(), 'L7 the drag\'s lock gates', async (app) => {
    const { page } = app;
    await page.evaluate(() => { document.querySelector('#catTree .cat-node[data-id="c3"]').dataset.draggable = 'false'; });
    const seen = await dragCategory(page, 'c3', 'c1', 0.5, { during: () => page.evaluate(() => !!document.querySelector('.drag-ghost')) });
    await page.waitForTimeout(200);
    check('L7 a row the lock gate marks undraggable does not drag', [seen, (await reparents(app)).length, (await orders(app)).length], [false, 0, 0]);
    const seen2 = await dragCategory(page, 'c2', 'c1', 0.5, {
      during: async () => {
        const g = await page.evaluate(() => !!document.querySelector('.drag-ghost'));
        // The vault locks while the drag is held.
        await page.evaluate(() => { state.unlocked = false; });
        return g;
      },
    });
    await page.waitForTimeout(200);
    yes('(set-up) the second drag was under way', seen2 === true);
    check('L7 a drop after the vault locked moves nothing', [(await reparents(app)).length, (await orders(app)).length], [0, 0]);
    yes('L7 and says why', (await toasts(page)).includes('Unlock the vault to change categories.'), JSON.stringify(await toasts(page)));
    check('no page errors', app.errors, []);
  });
}

async function scenarioFix2Focus(browser, server) {
  // fix2 item 3: what withBusy does when the user moves the focus while an
  // action runs. Moved to another control: it stays there. Moved to a
  // control the action then removes (the sheet's Cancel, closed by a
  // successful deploy): focus is not left on body - the stable fallback.
  await withApp(browser, server, {}, 'focus moved during a slow deploy', async (app) => {
    const { page } = app;
    await stubDeploy(page);
    await openSheet(page, ['k1']);
    await hold(page, 'key_deploy');
    await page.focus('#deployConfigBtn');
    await page.keyboard.press('Enter');
    await answerConfirm(page, 'ok');
    await page.waitForFunction(() => window.__calls.some((x) => x.cmd === 'key_deploy'));
    await page.focus('#deployModal .modal-footer [data-close]');
    await letGo(page, 'key_deploy');
    await page.waitForFunction(() => document.getElementById('deployModal').hidden && !document.getElementById('deployConfigBtn').hasAttribute('aria-busy'));
    await page.waitForTimeout(60);
    check('I1 focus moved to a control the action removes ends on the stable search target, not body', await app.focused(), 'searchInput');
    check('no page errors', app.errors, []);
  });
}

// ─── the deploy preview's warnings and the user's own Host lines ───────────

const LEGACY_FILE = '/home/u/.ssh/config';
const DEPLOY_WARNINGS = [
  `${LEGACY_FILE}, line 3: "Host bob's-key" names the host of key "alpha" and cannot be read by ssh (an unbalanced quote), so every ssh command fails while it is there. An older SSHSpan wrote it; SSHSpan never edits this file - remove or fix the line yourself.`,
  'The managed config path contains a % sign. <img src=x onerror="window.__xss=1"> Write the Include line with a single %.',
];
const LEGACY_LINES = [
  { file: LEGACY_FILE, line: 3, text: "Host bob's-key", key: 'alpha', unreadable: true, writtenBySshspan: true },
  { file: LEGACY_FILE, line: 7, text: 'Host web', key: 'alpha', unreadable: false, writtenBySshspan: false },
  { file: LEGACY_FILE, line: 9, text: 'Host alpha', key: 'alpha', unreadable: false, writtenBySshspan: true },
];

async function scenarioDeployWarnings(browser, server) {
  await withApp(browser, server, {}, 'A2-05 warnings and Host lines in the deploy sheet', async (app) => {
    const { page } = app;
    await stubDeploy(page);
    await page.evaluate(({ warnings, legacy }) => {
      const plan = window.__replies.key_deploy_preview;
      window.__replies.key_deploy_preview = (a) => Object.assign(plan(a), { warnings, legacyHostLines: legacy });
    }, { warnings: DEPLOY_WARNINGS, legacy: LEGACY_LINES });
    await openSheet(page, ['k1']);
    await fillHostFields(page, { alias: 'web', hostname: '10.0.0.5', user: 'deploy', port: '' });
    const items = (sel) => page.evaluate((s) => [...document.querySelectorAll(s)].map((li) => li.textContent.replace(/\s+/g, ' ').trim()), sel);
    check('every warning of the preview is listed under the plan, word for word', await items('#deployWarningList li'), DEPLOY_WARNINGS);
    check('as text: markup in a warning stays text', await page.evaluate(() => [document.querySelectorAll('#deployModal img').length, window.__xss || 0]), [0, 0]);
    check('each Host line of the user\'s own config is listed as file:line - text, saying what it is', await items('#deployLegacyList li'), [
      `${LEGACY_FILE}:3 - Host bob's-key - Breaks ssh: ssh cannot read this line, so every ssh command fails until it is fixed. An older SSHSpan wrote it.`,
      `${LEGACY_FILE}:7 - Host web - Your own entry.`,
      `${LEGACY_FILE}:9 - Host alpha - An older SSHSpan wrote it.`,
    ]);
    check('both lists are on screen', [await shown(page, '#deployWarningList'), await shown(page, '#deployLegacyList')], [true, true]);
    await page.click('#deployConfigBtn');
    yes('(set-up) the Deploy question opens', await waitVisible(page, '#confirmModal'));
    const question = (await page.textContent('#confirmMessage')) || '';
    yes('the Deploy question repeats every warning', DEPLOY_WARNINGS.every((w) => question.includes(w)), question);
    await answerConfirm(page, 'cancel');
    check('Cancel deploys nothing', await app.count('key_deploy'), 0);
    // Fields whose plan has nothing to warn about: the lists go.
    await page.evaluate(() => {
      const plan = window.__replies.key_deploy_preview;
      window.__replies.key_deploy_preview = (a) => Object.assign(plan(a), { warnings: [], legacyHostLines: [] });
    });
    await fillHostFields(page, { alias: 'web2', hostname: '10.0.0.5', user: 'deploy', port: '' });
    check('nothing to warn about: neither list is shown', [await shown(page, '#deployWarningList'), await shown(page, '#deployLegacyList')], [false, false]);
    await page.click('#deployConfigBtn');
    yes('(set-up) asked again', await waitVisible(page, '#confirmModal'));
    yes('and the question has no warning part then', !/Before you deploy/.test((await page.textContent('#confirmMessage')) || ''), await page.textContent('#confirmMessage'));
    await answerConfirm(page, 'cancel');
    check('no page errors', app.errors, []);
  });
  // A Host line is the user's own text, and a warning quotes one: a direction
  // override in it must not turn SSHSpan's verdict around, and a line of
  // 50,000 characters is not shown whole - in the sheet or in the question.
  const RLO = '\u{202E}';
  const ODD_LINES = [
    { file: LEGACY_FILE, line: 4, text: `Host evil${RLO}yek-s'bob`, key: 'alpha', unreadable: true, writtenBySshspan: false },
    { file: LEGACY_FILE, line: 5, text: 'Host ' + 'x'.repeat(50000), key: 'alpha', unreadable: false, writtenBySshspan: false },
  ];
  const ODD_WARNINGS = [`A Host line ${RLO}desrever si txet siht`, 'W' + 'w'.repeat(50000)];
  await withApp(browser, server, {}, 'L1 notes that are not what they show, or too long', async (app) => {
    const { page } = app;
    await stubDeploy(page);
    await page.evaluate(({ warnings, legacy }) => {
      const plan = window.__replies.key_deploy_preview;
      window.__replies.key_deploy_preview = (a) => Object.assign(plan(a), { warnings, legacyHostLines: legacy });
    }, { warnings: ODD_WARNINGS, legacy: ODD_LINES });
    await openSheet(page, ['k1']);
    await fillHostFields(page, { alias: 'web', hostname: '10.0.0.5', user: 'deploy', port: '' });
    const lines = await page.evaluate(() => [...document.querySelectorAll('#deployLegacyList li')].map((li) => ({
      text: li.textContent,
      parts: [...li.querySelectorAll('bdi')].map((b) => b.textContent),
      what: (li.querySelector('.deploy-legacy-what') || {}).textContent,
    })));
    check('L1 no direction character reaches the Host line list', lines.some((l) => l.text.includes(RLO)), false);
    check('L1 the file, the line and the text each sit in a <bdi> of their own, spelled out', lines[0] && lines[0].parts,
      [LEGACY_FILE, '4', 'Host evil<U+202E>yek-s\'bob']);
    check('L1 the verdict stays as SSHSpan words it', lines[0] && lines[0].what,
      'Breaks ssh: ssh cannot read this line, so every ssh command fails until it is fixed. Your own entry.');
    // 300 for a Host line: the backend cuts one there too (and adds "…").
    // 800 for a warning: the backend's own run to some 600 (a sentence, the
    // file and a quoted line of up to 301), and none of them is cut.
    const long = (lines[1] && lines[1].parts[2]) || '';
    check('L1 a 50,000-character line is cut to 300 characters and an ellipsis', [Array.from(long).length, long.endsWith('…'), long.startsWith('Host xxx')],
      [301, true, true]);
    const warns = await page.evaluate(() => [...document.querySelectorAll('#deployWarningList li')].map((li) => li.textContent));
    check('L1 a warning is spelled out too', warns[0], 'A Host line <U+202E>desrever si txet siht');
    check('L1 and a 50,000-character warning is cut to 800 and an ellipsis', [Array.from(warns[1] || '').length, (warns[1] || '').endsWith('…')], [801, true]);
    await page.click('#deployConfigBtn');
    yes('(set-up) the Deploy question opens', await waitVisible(page, '#confirmModal'));
    const q = (await page.textContent('#confirmMessage')) || '';
    check('L1 the Deploy question repeats them spelled out and cut',
      [q.includes(RLO), q.includes('- A Host line <U+202E>desrever si txet siht'), q.length < 2000], [false, true, true]);
    // A warning the backend writes about a 300-character line stays whole.
    const real = `${LEGACY_FILE}, line 3: "${'Host ' + 'y'.repeat(295)}…" is your own entry for the host of key "alpha", and ssh cannot read it (an unbalanced quote), so every ssh command fails while it is there. SSHSpan never edits this file - fix the quoting of that line yourself.`;
    await answerConfirm(page, 'cancel');
    await page.evaluate((w) => {
      const plan = window.__replies.key_deploy_preview;
      window.__replies.key_deploy_preview = (a) => Object.assign(plan(a), { warnings: [w], legacyHostLines: [] });
    }, real);
    await fillHostFields(page, { alias: 'web3', hostname: '10.0.0.5', user: 'deploy', port: '' });
    check('L1 a real warning quoting a 300-character line is shown whole', await page.evaluate(() =>
      [...document.querySelectorAll('#deployWarningList li')].map((li) => li.textContent)), [real]);
    await page.click('#deployConfigBtn');
    yes('(set-up) asked again', await waitVisible(page, '#confirmModal'));
    await answerConfirm(page, 'cancel');
    check('no page errors', app.errors, []);
  });
}

// ─── the Keys view while the vault is locked ───────────────────────────────

async function scenarioLockedKeysView(browser, server) {
  const card = (page) => page.evaluate(() => {
    const s = document.getElementById('emptyState');
    const btn = (id) => { const b = document.getElementById(id); return b && !b.hidden && !b.closest('[hidden]') ? [b.textContent.trim(), b.disabled] : null; };
    return { shown: !!s && !s.hidden, title: (s.querySelector('h3') || {}).textContent, newKey: btn('emptyNewBtn'), unlock: btn('emptyUnlockBtn') };
  });
  await withApp(browser, server, { unlocked: false }, 'a locked vault: the empty Keys view says so, with Unlock', async (app) => {
    const { page } = app;
    await page.waitForTimeout(150);
    if (await app.open('vaultModal')) await page.click('#vaultCancelBtn');
    check('locked: the Keys view says the vault is locked and offers Unlock, not the first-run card', await card(page),
      { shown: true, title: 'The vault is locked', newKey: null, unlock: ['Unlock', false] });
    check('+ New key is lock-gated like its neighbours', await page.evaluate(() => [el('emptyNewBtn').disabled, el('emptyNewBtn').title]),
      [true, 'Unlock the vault to create or import keys.']);
    await page.click('#emptyUnlockBtn');
    yes('Unlock opens the unlock dialog', await waitVisible(page, '#vaultModal'));
    check('in its unlock form', await page.evaluate(() => state.vaultMode), 'unlock');
    check('no page errors', app.errors, []);
  });
  await withApp(browser, server, { hasVault: false, unlocked: false }, 'no vault yet: the empty Keys view offers to create one', async (app) => {
    const { page } = app;
    await page.waitForTimeout(150);
    if (await app.open('vaultModal')) await page.click('#vaultCancelBtn');
    check('no vault: the card says so and offers Create vault', await card(page),
      { shown: true, title: 'No vault yet', newKey: null, unlock: ['Create vault', false] });
    await page.click('#emptyUnlockBtn');
    yes('Create vault opens the create dialog', await waitVisible(page, '#vaultModal'));
    check('in its create form', await page.evaluate(() => state.vaultMode), 'create');
    check('no page errors', app.errors, []);
  });
  await withApp(browser, server, { keys: [] }, 'unlocked, no keys: the first-run card', async (app) => {
    const { page } = app;
    await page.waitForTimeout(150);
    check('unlocked with no keys: "No keys yet" and + New key', await card(page),
      { shown: true, title: 'No keys yet', newKey: ['+ New key', false], unlock: null });
    await page.evaluate(() => { window.__backend.unlocked = false; return refreshVaultStatus(); });
    await page.waitForTimeout(120);
    if (await app.open('vaultModal')) await page.click('#vaultCancelBtn');
    check('after a lock: the locked card', await card(page),
      { shown: true, title: 'The vault is locked', newKey: null, unlock: ['Unlock', false] });
    check('no page errors', app.errors, []);
  });
}

// ─── category order next to promoted loop roots (category_set_order) ───────

async function scenarioCategoryOrderBesideLoops(browser, server) {
  const LOOP_IDS = ['ca', 'cb', 'cc', 'cd', 'self'];
  // The reviewer's four probes: each drop lands where it was dropped, every
  // other row keeps its place, only a real parent change writes a parent, and
  // the same drop again changes nothing.
  for (const [title, extra, from, to, frac, want, parentWrites] of [
    ['Beta at index 6 dropped above Outside', CAT('beta', 'Beta', null, 6), 'beta', 'root', 0.1,
      ['Beta', 'Outside', 'CycA', 'CycC', 'Self'], []],
    ['Kid dropped on Outside\'s lower edge', CAT('kid', 'Kid', 'root', 0), 'kid', 'root', 0.9,
      ['Outside', 'Kid', 'CycA', 'CycC', 'Self'], [{ id: 'kid', newParentId: null }]],
    ['Zed at index 1 dropped after CycA', CAT('zed', 'Zed', null, 1), 'zed', 'ca', 0.9,
      ['Outside', 'CycA', 'Zed', 'CycC', 'Self'], []],
    ['Apple at index 1 dropped before CycA', CAT('apple', 'Apple', null, 1), 'apple', 'ca', 0.1,
      ['Outside', 'Apple', 'CycA', 'CycC', 'Self'], []],
  ]) {
    const cats = [...LOOPS, extra];
    const opts = { keys: [KEY('k1', 'alpha')], categories: cats,
      replies: { category_list: { categories: cats, allKeyCategories: {}, orphans: false, hostOrphans: false } } };
    await withApp(browser, server, opts, `M1 probe: ${title}`, async (app) => {
      const { page } = app;
      await applyReparents(page);
      await dragCategory(page, from, to, frac);
      await page.waitForTimeout(300);
      check(`M1 ${title}: the order read back`, await topOrder(page), want);
      check(`M1 ${title}: a parent is written only for a real parent change`, await reparents(app), parentWrites);
      check(`M1 ${title}: no loop member's parent is written`, (await reparents(app)).filter((a) => LOOP_IDS.includes(a.id)), []);
      check(`M1 ${title}: the loops are shown as before`,
        await page.evaluate(() => [childrenOf('ca').map((c) => c.id), childrenOf('cc').map((c) => c.id)]), [['cb'], ['cd']]);
      check(`M1 ${title}: every write was taken (the whole list each time)`, (await toasts(page)).filter((t) => ORDER_REFUSALS.test(t)), []);
      await dragCategory(page, from, to, frac);
      await page.waitForTimeout(300);
      check(`M1 ${title}: dropping it there again keeps it there`, await topOrder(page), want);
      check(`M1 ${title}: and writes no parent again`, await reparents(app), parentWrites);
      check('no page errors', app.errors, []);
    });
  }
  const loopProbeOpts = () => ({ keys: [KEY('k1', 'alpha')], categories: LOOPS,
    replies: { category_list: { categories: LOOPS, allKeyCategories: {}, orphans: false, hostOrphans: false } } });
  // A loop member dragged out beside its own loop's promoted root - the way to
  // repair the loop: its parent becomes the top level, which nests the root
  // under it, so the root is no longer a row to drop beside. It lands where
  // the root was shown (it landed last).
  for (const [edge, frac] of [['top', 0.1], ['bottom', 0.9]]) {
    await withApp(browser, server, loopProbeOpts(), `M1 probe: CycB dropped on CycA's ${edge} edge`, async (app) => {
      const { page } = app;
      await applyReparents(page);
      await dragCategory(page, 'cb', 'ca', frac);
      await page.waitForTimeout(300);
      const at = `M1 CycB on CycA's ${edge} edge`;
      check(`${at}: its parent is written once - the top level`, await reparents(app), [{ id: 'cb', newParentId: null }]);
      check(`${at}: the order written puts it where CycA was shown`, (await orders(app)).map((o) => o.orderedIds),
        [['root', 'cb', 'cc', 'self', 'cd']]);
      check(`${at}: the order read back`, await topOrder(page), ['Outside', 'CycB', 'CycC', 'Self']);
      check(`${at}: CycA is under CycB now, the other loop as before`,
        await page.evaluate(() => [childrenOf('cb').map((c) => c.id), childrenOf('cc').map((c) => c.id)]), [['ca'], ['cd']]);
      check(`${at}: every write was taken`, (await toasts(page)).filter((t) => ORDER_REFUSALS.test(t)), []);
      check('no page errors', app.errors, []);
    });
  }
  // A promoted loop root dragged itself: it is shown at the top level, so a
  // drop beside a top-level row writes no parent - its saved parent (CycB)
  // is not the one it is shown under.
  await withApp(browser, server, loopProbeOpts(), 'M1 probe: CycA (a promoted loop root) dropped above Outside', async (app) => {
    const { page } = app;
    await applyReparents(page);
    await dragCategory(page, 'ca', 'root', 0.1);
    await page.waitForTimeout(300);
    check('M1 CycA above Outside: no parent is written', await reparents(app), []);
    check('M1 CycA above Outside: the whole top level in its new order', (await orders(app)).map((o) => o.orderedIds),
      [['ca', 'root', 'cc', 'self', 'cb', 'cd']]);
    check('M1 CycA above Outside: the order read back', await topOrder(page), ['CycA', 'Outside', 'CycC', 'Self']);
    check('M1 CycA above Outside: the loops are shown as before',
      await page.evaluate(() => [childrenOf('ca').map((c) => c.id), childrenOf('cc').map((c) => c.id)]), [['cb'], ['cd']]);
    check('no page errors', app.errors, []);
  });
}

// ─── a change whose audit row could not be written (B1) ────────────────────

async function scenarioAuditWarnings(browser, server) {
  const W = (what) => `The ${what}, but its audit row could not be written: disk I/O error`;
  const keys = [Object.assign(KEY('k1', 'alpha'), { category_ids: ['c1'] }), KEY('k2', 'beta')];
  await withApp(browser, server, { keys, categories: CATS, replies: {
    category_list: CAT_REPLY({ k1: ['c1'] }),
    category_create: { id: 'c9', name: 'New', parent_id: null, scope: 'key', sort_index: 9, color: null, warning: W('category was created') },
    category_delete: { ok: true, reassigned: [], warning: W('category was deleted') },
    key_set_categories: { ok: true, warning: W("key's categories were saved") },
    key_rename: { ok: true, name: 'alpha2', warning: W('key was renamed') },
    key_delete: { ok: true, warning: W('key was deleted') },
    key_create_with_categories: { ok: true, id: 'k9', fingerprint: 'SHA256:k9', warning: W('key was created') },
  } }, 'B1 a change whose audit row failed is said as a warning', async (app) => {
    const { page } = app;
    const warned = async (w) => (await page.evaluate(() =>
      [...document.querySelectorAll('#toast .toast-item.warn .toast-text')].map((n) => n.textContent))).includes(w);
    await page.evaluate(() => createCategory('New', null, null));
    await page.waitForTimeout(100);
    yes('category_create: its warning is shown', await warned(W('category was created')));
    await page.evaluate(() => { window.__d = deleteCategory('c2'); });
    await answerConfirm(page, 'ok');
    await page.waitForTimeout(150);
    yes('category_delete: its warning is shown', await warned(W('category was deleted')));
    await page.evaluate(() => selectKey('k1'));
    await page.waitForTimeout(150);
    await page.click('#detailCategories .cat-chip .cat-chip-x');
    await page.waitForTimeout(150);
    yes('key_set_categories: its warning is shown', await warned(W("key's categories were saved")));
    await page.click('#detailRenameBtn');
    yes('(set-up) the rename prompt opens', await waitVisible(page, '#promptModal'));
    await page.fill('#promptInput', 'alpha2');
    await page.click('#promptOkBtn');
    await page.waitForTimeout(150);
    yes('key_rename: its warning is shown', await warned(W('key was renamed')));
    await page.evaluate(() => selectKey('k2'));
    await page.waitForTimeout(100);
    await page.click('#detailDeleteBtn');
    await answerConfirm(page, 'ok');
    await page.waitForTimeout(150);
    yes('key_delete: its warning is shown', await warned(W('key was deleted')));
    await page.evaluate(() => openKeyModal());
    await waitVisible(page, '#modalBackdrop');
    await page.fill('#genName', 'gamma');
    await page.click('#modalPrimary');
    await page.waitForTimeout(200);
    yes('key_create_with_categories: its warning is shown', await warned(W('key was created')));
    check('each was done once: a warning is not a reason to retry', await page.evaluate(() =>
      ['category_create', 'category_delete', 'key_rename', 'key_delete', 'key_create_with_categories'].map((c) => window.__calls.filter((x) => x.cmd === c).length)),
    [1, 1, 1, 1, 1]);
    check('no page errors', app.errors, []);
  });
  // Several keys deleted at once, each answering the same warning: it is said
  // once, as the bulk "add to categories" says its warnings.
  await withApp(browser, server, { keys: [KEY('k1', 'alpha'), KEY('k2', 'beta'), KEY('k3', 'gamma')], replies: {
    key_delete: { ok: true, warning: W('key was deleted') },
  } }, 'B1 a bulk delete says a repeated warning once', async (app) => {
    const { page } = app;
    await page.evaluate(() => deleteKeyBatch(['k1', 'k2', 'k3'], [], false));
    await page.waitForTimeout(150);
    const said = (await page.evaluate(() => [...document.querySelectorAll('#toast .toast-item.warn .toast-text')].map((n) => n.textContent))).join('\n');
    check('B1 three keys deleted with one audit warning: it is said once', [await app.count('key_delete'), said.split(W('key was deleted')).length - 1], [3, 1]);
    check('no page errors', app.errors, []);
  });
}

// ─── static checks ─────────────────────────────────────────────────────────

const read = (rel) => fs.readFileSync(path.join(RENDERER, rel), 'utf8');

const STATIC = [
  ['fix1 R9 full format contract', () => {
    const rust = fs.readFileSync(path.join(ROOT, 'src-tauri', 'src', 'crypto', 'keys.rs'), 'utf8');
    const body = rust.slice(rust.indexOf('pub fn unsupported_import_message'), rust.indexOf('fn looks_like_openssh_public_line'));
    const pairs = [...body.matchAll(/\(\s*"([^"]+)"\s*,\s*"([^"]+)"\s*,\s*(true|false)\s*,?\s*\)/g)]
      .map((m) => [m[1], m[2], m[3] === 'true']);
    const expected = [
      ['-----BEGIN RSA PRIVATE KEY-----', 'a PKCS#1 RSA private key', true],
      ['-----BEGIN EC PRIVATE KEY-----', 'a SEC1 EC private key', true],
      ['-----BEGIN ENCRYPTED PRIVATE KEY-----', 'an encrypted PKCS#8 private key', false],
      ['-----BEGIN PRIVATE KEY-----', 'a PKCS#8 private key', false],
    ];
    check('fix1 R9 backend header, detected kind and PuTTYgen-guidance pairs stay aligned', pairs, expected);
    const app = read('app.js');
    const table = app.slice(app.indexOf('const IMPORT_PRIVATE_PEM'), app.indexOf('function unsupportedImportMessage'));
    const jsPairs = [...table.matchAll(/\['([^']+)',\s*'([^']+)',\s*(true|false)\]/g)]
      .map((m) => [m[1], m[2], m[3] === 'true']);
    check('fix1 R9 renderer header/kind/guidance pairs match the backend', jsPairs, expected);
    const publicPairs = [...body.matchAll(/text\.contains\("([^"]+)"\)\s*\{\s*Some\("([^"]+)"\)/g)].map((m) => [m[1], m[2]]);
    check('fix1 R9 public header/label pairs are pinned too', publicPairs, [
      ['-----BEGIN PUBLIC KEY-----', 'an SPKI public key (-----BEGIN PUBLIC KEY-----)'],
      ['---- BEGIN SSH2 PUBLIC KEY ----', 'an RFC 4716 public key (---- BEGIN SSH2 PUBLIC KEY ----)'],
    ]);
    check('fix1 R9 the OpenSSH public-line branch uses its own public label',
      /looks_like_openssh_public_line\(text\)\s*\{\s*Some\("an OpenSSH public key line \(authorized_keys \/ \.pub\)"\)/.test(body), true);
  }],
  ['fix1 orphan-sweep dead inputs and sentence case', () => {
    const app = read('app.js');
    check('A2-34 no unused activeCategoryId state property or groupKeys parameter',
      { property: /\bactiveCategoryId\s*:/.test(app), param: /function keyRowEl\(k,\s*groupKeys\)/.test(app), call: /keyRowEl\(k,\s*g\.keys\)/.test(app) },
      { property: false, param: false, call: false });
    check('A8-25 the empty-state action is sentence case', /id="emptyNewBtn"[^>]*>\+ New key<\/button>/.test(read('index.html')), true);
  }],
  ['R9 the renderer\'s import guidance is the backend\'s', () => {
    const rust = fs.readFileSync(path.join(ROOT, 'src-tauri', 'src', 'crypto', 'keys.rs'), 'utf8').replace(/\\"/g, '"');
    const app = read('app.js');
    const parts = { SUPPORTED, CONVERT, PUTTYGEN: PUTTYGEN.trim(), PUBLIC_HALF };
    check('R9 keys.rs still says what this suite expects (else update both sides)',
      Object.keys(Object.assign({ UNKNOWN_FORMAT }, parts)).filter((k) => !rust.includes(Object.assign({ UNKNOWN_FORMAT }, parts)[k])), []);
    // Unrecognised text is left to the backend, so app.js needs no copy of that one.
    check('R9 app.js carries the same wording', Object.keys(parts).filter((k) => !app.includes(parts[k])), []);
  }],
  ['A2-42 no blob downloads', () => {
    check('A2-42 nothing in app.js writes a file through a blob link', /URL\.createObjectURL/.test(read('app.js')), false);
  }],
  ['A2-05 / A8-26 deploy copy', () => {
    const html = read('index.html');
    const app = read('app.js');
    check('A8-01 no "SSHSpan managed" markers are promised (none are written)', /SSHSpan managed/.test(html + app), false);
    check('A8-26 no "preview first" (the preview is always live)', /preview first/i.test(app), false);
  }],
];

function runStatic() {
  console.log('static checks');
  for (const [title, fn] of STATIC) {
    try { fn(); } catch (e) { check(title + ' (threw: ' + String(e.message || e).split('\n')[0] + ')', false, true); }
  }
}

// ─── runner ─────────────────────────────────────────────────────────────────

const SCENARIOS = [
  ['item 1: creating keys - curves, a fresh dialog, the filter, one submit', scenarioCreate],
  ['item 1: exporting keys - passphrases, the real format, public files, one submit', scenarioExport],
  ['item 2: import - the two formats, every other one recognised, duplicate names', scenarioImport],
  ['item 3: key list - no match, counts, avatars, collapse, names, the pane, selection', scenarioKeyList],
  ['item 4: categories - drag and drop, picker scope and keys, cycles, deletes', scenarioCategories],
  ['item 5: loaders - no duplicate rows, no stale key, failures said', scenarioLoaders],
  ['item 6: deploy sheet - backend preview, fields, Include line, validation, servers', scenarioDeploy],
  ['item 7: undeploy - remove a deployed copy, delete with its files', scenarioUndeploy],
  ['leftovers: Connect menu anchor, drawer while locked, tree on lock', scenarioLeftovers],
  ['fix1 focus: busy buttons, deletion targets and the New key opener', scenarioFixFocus],
  ['fix1 state: hidden secrets, bulk cleanup, disabled option and restored cycles', scenarioFixState],
  ['fix1 preview: late answers, failures, refusals and debounce', scenarioFixPreview],
  ['fix1 copy: sentence case and RSA duration hint', scenarioFixCopy],
  ['fix2 loops: no loop member as a move destination, repairs still work', scenarioFix2Loops],
  ['fix2 focus: moving the focus while an action runs', scenarioFix2Focus],
  ['JU6b pointer drags in the tree and the order probes (Task 16 A3-23 JU4 review)', scenarioPointerCategories],
  ['JU6b fix round: reordering without a drag, the drag\'s lock gates (M2 L7)', scenarioCategoryOrderNoDrag],
  ['deploy warnings: the preview\'s warnings and the user\'s own Host lines', scenarioDeployWarnings],
  ['locked keys view: the empty card and its gated buttons', scenarioLockedKeysView],
  ['loop order: drops next to promoted loop roots (category_set_order)', scenarioCategoryOrderBesideLoops],
  ['audit warnings: changes whose audit row could not be written', scenarioAuditWarnings],
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
    console.error(`\n${failures.length} keys UI check(s) failed.`);
    process.exit(1);
  }
  console.log('\nAll keys UI checks passed.');
})().catch((e) => { console.error(e); process.exit(1); });
