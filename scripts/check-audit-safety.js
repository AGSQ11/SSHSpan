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
 * And for unit JU2 (the renderer half of the Rust-core fixes):
 *   - backups are written and read by Rust (vault_backup_export_to_file /
 *     vault_backup_restore_from_file): the restore confirms first, a backup
 *     under another master password round-trips through the masked prompt,
 *     and keys, servers AND settings are reloaded afterwards;
 *   - the .pem browse asks for a path only; Settings shows the values in
 *     effect and puts a control back when the backend refuses its save;
 *   - controls whose command is refused while locked are disabled, with the
 *     reason; the master-password change cannot be dismissed while it runs
 *     and survives a lock in the middle;
 *   - the audit CSV neutralises formulas; one failing call at boot no longer
 *     stops the wiring; failed loads show a card with Retry, not an empty
 *     state; a repeated toast is counted instead of stacked.
 *
 * Run with `npm run test:safety`. Needs playwright, which is not a
 * devDependency (see check-renderer-ui.js):
 *
 *     npm install --no-save playwright@1.56.1 && npx playwright install chromium
 *
 * Without it the browser checks are skipped, but the static checks below need
 * no browser and always run first: the exit code is then 1 if any static check
 * failed, else 0. Optional: `--only <text>` runs the scenarios whose
 * title contains <text>; SSHSPAN_RENDERER_DIR points the run at another copy of
 * the renderer (for example a pristine `git archive` of an older commit, to
 * watch these checks fail where they should).
 */
'use strict';

const fs = require('fs');
const path = require('path');
// The reporter, the Playwright lookup, the static server, the in-page stub
// backend and the app helpers live in scripts/lib/renderer-harness.js, shared
// with the other renderer suites.
const {
  failures, check, yes, loadChromium, rendererDir, serve, part,
  PASSWORD, KEY, SERVER, withApp, settled, waitVisible, focusIs, answerConfirm,
  openLiveTab, bytesOf, sends, toasts, hold, letGo,
} = require('./lib/renderer-harness');

// ─── static guard: no native confirm() left in the renderer ────────────────
//
// Runs first and needs no browser, so it still runs where Playwright is not
// installed (like the MCP contract block in check-renderer-ui.js).

const RENDERER = rendererDir();
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

const chromium = loadChromium();
if (!chromium) {
  console.log('playwright not installed - skipping the browser checks.');
  if (failures.length) console.error(`\n${failures.length} audit safety check(s) failed.`);
  process.exit(failures.length ? 1 : 0);
}

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
  // N1: the second click of a double-click is no answer. A question can open
  // under the pointer within milliseconds of the click that asked it (a menu
  // item under the dialog's OK button); the double-click's second half then
  // lands on OK. A click with detail 2 is ignored; a single click and the
  // keyboard (a click with detail 0) answer as before.
  await withApp(browser, server, {}, 'N1 a double-click is no yes', async (app) => {
    const { page } = app;
    const clickOk = (detail) => page.evaluate((d) => document.getElementById('confirmOkBtn')
      .dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true, detail: d })), detail);
    await page.evaluate(() => { window.__h = confirmModal('Delete keys', 'Delete 2 keys?', 'Delete'); });
    yes('(set-up) the question is open', await waitVisible(page, '#confirmModal'));
    await clickOk(2);
    check('N1 a click with detail 2 on OK confirms nothing', await settled(page, () => window.__h, null, 300), 'PENDING');
    yes('N1 and the question stays open', await app.open('confirmModal'));
    await clickOk(1);
    check('N1 a later single click confirms', await settled(page, () => window.__h, null, 800), true);
    await page.evaluate(() => { window.__i = confirmModal('Delete keys', 'Delete 2 keys?', 'Delete'); });
    yes('(set-up) asked again', await waitVisible(page, '#confirmModal'));
    await page.focus('#confirmOkBtn');
    await page.keyboard.press('Enter');
    check('N1 the keyboard on OK (a click with detail 0) still confirms', await settled(page, () => window.__i, null, 800), true);
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
      // The restore reads its file in Rust, behind its own dialog (R5).
      vault_backup_restore_from_file: { ok: true, counts: { keys: 0, categories: 0, servers: 0, knownHosts: 0 } },
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
    await page.evaluate(() => {
      state.sessions.set('tm', { tabId: 'tm', sessionId: 'sess-move', serverId: 's1', serverName: 'files', host: '10.0.0.1', port: 22, mode: 'sftp', sftpReady: true, sftpPath: '/srv', ended: false });
      const panel = buildSftpPanel('tm');
      document.getElementById('sftpBody').appendChild(panel);
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
        effect: (c) => c.cmd === 'vault_backup_restore_from_file',
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
          // What a pointer drag of /srv/file.txt released on the folder row
          // "dest" resolves to (Task 16: drags are pointer events now - the
          // gesture itself is driven with the mouse in check-sftp-ui.js).
          window.__action = sftpDropDragged(
            { tabId: 'tm', side: 'remote', items: [{ path: '/srv/file.txt', name: 'file.txt', isDir: false }] },
            { side: 'remote', dir: '/srv/dest' });
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

  // A lock by hand with a live shell asks first, naming what it ends (A5-09,
  // plan ruling R2 - JU5); OK locks and tears the shell down. (Nothing live:
  // no question - check-servers-ui.js.)
  await withApp(browser, server, {}, 'manual lock with a live session', async (app) => {
    await openLiveTab(app);
    await app.page.waitForTimeout(150);
    await app.page.click('#vaultStatus');
    await app.page.click('#keyConnectMenu .ctx-item:has-text("Lock now")');
    const asked = await waitVisible(app.page, '#confirmModal', 800);
    check('Lock now with a live session open asks before it locks',
      { asked, locks: await app.count('vault_lock') }, { asked: true, locks: 0 });
    if (asked) await answerConfirm(app.page, 'ok');
    await app.page.waitForTimeout(150);
    check('and OK locks', await app.count('vault_lock'), 1);
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
  await withApp(browser, server, {}, 'backup password prompt', async (app) => {
    const { page } = app;
    await page.evaluate(() => {
      // vault_backup_restore_from_file (R5): the file is picked and read in
      // Rust; a backup sealed under another master password comes back as
      // needsPassword with the path granted for one retry.
      window.__replies.vault_backup_restore_from_file = (a) => {
        if (a.backupPassword == null) return { needsPassword: true, path: '/tmp/b.json' };
        return { ok: true, counts: { keys: 1, categories: 0, servers: 0, knownHosts: 0 } };
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
      (await app.calls('vault_backup_restore_from_file')).map((c) => c.args.backupPassword), [undefined, '  spaced pw  ']);
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

/// The SFTP delete, chmod, conflict and edit-conflict dialogs have no Escape
/// handler of their own: the central one closes them, and so does a vault
/// lock, and each settles whatever it was holding.
async function scenarioSftpDialogs(browser, server) {
  const modalId = { delete: 'deleteModal', chmod: 'chmodModal', conflict: 'conflictModal', editConflict: 'editConflictModal' };
  const opener = {
    delete: () => { window.__yes = 0; sftpConfirmDelete('Delete 1 item?', () => { window.__yes += 1; }); },
    chmod: () => { openChmodDialog('tm', ['/srv/a.txt'], { name: 'a.txt' }); },
    conflict: () => {
      window.__batch = resolveBatchConflicts('tm', 'upload',
        [{ local: '/home/u/a.txt', remote: '/srv/a.txt', destEntry: { size: 1, modifiedMs: 1 } }]);
    },
    // A file open in an editor changed on the server (A7-19, RU6a contract).
    editConflict: () => {
      window.__emit('sftp-edit-sync', { sessionId: 'sess-sftp', editId: 'e1', remote: '/srv/app.conf', ok: false, conflict: true,
        conflictId: 'c1', reason: 'changed', error: 'app.conf changed on the server since you opened it - choose Overwrite or Reload.',
        remoteSize: 10, remoteModifiedMs: 1700000000000 });
    },
  };
  for (const kind of ['delete', 'chmod', 'conflict', 'editConflict']) {
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
        if (kind === 'editConflict') check(`editConflict: ${how} settles nothing on the server`, await app.count('sftp_edit_resolve'), 0);
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
    // A session is live, so Ctrl+L first asks whether to lock (A5-09, JU5).
    if (await waitVisible(page, '#confirmModal', 800)) await answerConfirm(page, 'ok');
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

// ─── unit JU2: backups, settings, lock-aware controls, boot ─────────────────
// (toasts, hold and letGo come from scripts/lib/renderer-harness.js.)

const buttonState = (page, id) => page.evaluate((i) => {
  const b = document.getElementById(i);
  return { disabled: b.disabled, ariaBusy: b.getAttribute('aria-busy'), label: b.textContent.trim() };
}, id);

/// A Settings row by its title, as the page renders it.
const settingsRow = (page, title) => page.locator('#settingsRows .settings-row').filter({
  has: page.locator('.settings-row-title', { hasText: title }),
});

/// A6-03 / A2-48 / R5 / A2-18: a backup is written by Rust; the page only
/// asks for it, shows that it is working, and reports where it went.
async function scenarioBackupCreate(browser, server) {
  const counts = { keys: 2, categories: 1, servers: 1, knownHosts: 3, sftpBookmarks: 1 };
  await withApp(browser, server, {}, 'backup create', async (app) => {
    const { page } = app;
    await page.evaluate((c) => {
      window.__replies.vault_backup_export_to_file = {
        ok: true, canceled: false, path: '/home/u/backups/sshspan-backup.json', counts: c,
      };
    }, counts);
    await hold(page, 'vault_backup_export_to_file');
    await page.evaluate(() => { window.__action = backupCreate(); });
    await page.waitForTimeout(60);
    const busy = await buttonState(page, 'backupExportBtn');
    check('A2-18 the backup button is busy while the backup is written',
      { disabled: busy.disabled, ariaBusy: busy.ariaBusy }, { disabled: true, ariaBusy: 'true' });
    yes('A2-18 and says what it is doing', /saving/i.test(busy.label), busy.label);
    await page.evaluate(() => { backupCreate(); document.getElementById('backupExportBtn').click(); });
    await page.waitForTimeout(60);
    check('A2-18 a second request while it runs starts nothing', await app.count('vault_backup_export_to_file'), 1);
    await letGo(page, 'vault_backup_export_to_file');
    await settled(page, () => window.__action, null, 1200);
    await page.waitForTimeout(60);
    check('R5 the vault never comes back to the page to be saved',
      {
        oldCreate: await app.count('vault_backup_create'),
        pick: await app.count('system_pick_save_path'),
        write: await app.count('system_write_text_file'),
      }, { oldCreate: 0, pick: 0, write: 0 });
    check('R5 Rust opens the save dialog itself (no arguments)',
      (await app.calls('vault_backup_export_to_file')).map((c) => c.args), [{}]);
    const said = (await toasts(page)).join(' | ');
    yes('A6-03 the toast names the file', said.includes('/home/u/backups/sshspan-backup.json'), said);
    yes('A6-03 and what went into it', /2 keys/.test(said) && /3 known hosts/.test(said), said);
    yes('the status line names the file too',
      (await page.textContent('#backupStatus')).includes('/home/u/backups/sshspan-backup.json'));
    check('the button is itself again afterwards', await buttonState(page, 'backupExportBtn'),
      { disabled: false, ariaBusy: null, label: 'Create backup...' });
    check('no page errors', app.errors, []);
  });

  await withApp(browser, server, { replies: { vault_backup_export_to_file: { canceled: true } } }, 'backup create cancelled', async (app) => {
    const { page } = app;
    const status = await page.textContent('#backupStatus');
    await page.evaluate(() => backupCreate());
    await page.waitForTimeout(80);
    check('a dismissed save dialog says nothing', (await toasts(page)).filter((t) => /backup/i.test(t)), []);
    check('and leaves the status line alone', await page.textContent('#backupStatus'), status);
  });

  await withApp(browser, server, {
    replies: { vault_backup_export_to_file: { $reject: 'Writing into a system directory is not allowed.' } },
  }, 'backup create refused', async (app) => {
    await app.page.evaluate(() => backupCreate());
    await app.page.waitForTimeout(80);
    yes('a refused write shows the backend\'s reason as it is',
      (await toasts(app.page)).includes('Writing into a system directory is not allowed.'), JSON.stringify(await toasts(app.page)));
    check('and the button is usable again', (await buttonState(app.page, 'backupExportBtn')).disabled, false);
  });

  await withApp(browser, server, {
    replies: { vault_backup_export_to_file: { $reject: 'Vault was locked while the operation was in progress.' } },
  }, 'backup create interrupted by a lock', async (app) => {
    await app.page.evaluate(() => backupCreate());
    await app.page.waitForTimeout(80);
    yes('a lock before the backup was written is reported as no file saved',
      (await toasts(app.page)).some((t) => /no file was saved/i.test(t)), JSON.stringify(await toasts(app.page)));
  });

  await withApp(browser, server, { unlocked: false }, 'backup create while locked', async (app) => {
    const { page } = app;
    await page.click('#vaultCancelBtn');
    await page.evaluate(() => backupCreate());
    await page.waitForTimeout(80);
    check('a locked vault is not asked for a backup', await app.count('vault_backup_export_to_file'), 0);
    yes('the user is told to unlock first', (await toasts(page)).some((t) => /unlock/i.test(t)));
  });
}

/// R5 / A2-13 / A2-30 / C1: the restore confirms first, Rust picks and reads
/// the file, a different master password round-trips through the masked
/// prompt, and everything that reads settings is reloaded afterwards.
async function scenarioBackupRestore(browser, server) {
  const restored = {
    ok: true, passwordReLinked: true, resealFailures: 0,
    counts: {
      keys: 3, categories: 1, keyCategoryLinks: 2, servers: 2, knownHosts: 1, knownHostsImported: 0,
      knownHostsConflicts: 0, settings: 3, mcpServers: 1, sftpBookmarks: 1, settingsDropped: 0,
    },
  };
  await withApp(browser, server, { settings: { autoLockMinutes: '30', confirmDelete: 'true' } }, 'backup restore', async (app) => {
    const { page } = app;
    await page.evaluate((r) => {
      window.__replies.vault_backup_restore_from_file = (a) => {
        if (!a.path) return { needsPassword: true, path: '/home/u/old-backup.json' };
        if (a.backupPassword !== '  old pw  ') throw 'Backup password is incorrect.';
        // What the restore wrote: the backup's settings replace these.
        window.__backend.settings = { autoLockMinutes: '0', confirmDelete: 'false', uiScale: '125' };
        return r;
      };
      window.__action = backupRestore();
    }, restored);
    yes('R5 restoring asks first', await waitVisible(page, '#confirmModal'));
    check('R5 and nothing is picked or read before the answer',
      {
        restore: await app.count('vault_backup_restore_from_file'),
        select: await app.count('system_select_file'),
        old: await app.count('vault_backup_restore'),
      }, { restore: 0, select: 0, old: 0 });
    await answerConfirm(page, 'ok');
    yes('A2-13 a backup sealed under another password asks for that password', await waitVisible(page, '#promptModal'));
    check('A2-13 in a masked field', await page.getAttribute('#promptInput', 'type'), 'password');
    check('R5 the first call lets Rust open the file dialog: no path, no password',
      (await app.calls('vault_backup_restore_from_file')).map((c) => c.args), [{}]);
    await settled(page, () => window.__action, null, 1200);
    const settingsReads = await app.count('settings_get');
    const keyReads = await app.count('key_list');
    const serverReads = await app.count('server_list');
    await page.fill('#promptInput', '  old pw  ');
    await page.click('#promptOkBtn');
    await page.waitForFunction((n) => window.__calls.filter((c) => c.cmd === 'settings_get').length > n, settingsReads)
      .catch(() => {});
    await page.waitForTimeout(150);
    check('R5 the retry names the file Rust offered and carries the password untrimmed',
      (await app.calls('vault_backup_restore_from_file')).slice(1).map((c) => c.args),
      [{ path: '/home/u/old-backup.json', backupPassword: '  old pw  ' }]);
    check('A2-13 the prompt is emptied and plain text again',
      [await page.inputValue('#promptInput'), await page.getAttribute('#promptInput', 'type')], ['', 'text']);
    check('A2-30 the restored settings are read back',
      await page.evaluate(() => [state.settings.autoLockMinutes, state.settings.confirmDelete, state.settings.uiScale]),
      ['0', 'false', '125']);
    check('A2-30 auto-lock follows them at once (0 = off)', await page.textContent('#vaultSub'), 'auto-lock off');
    yes('A2-30 keys and servers are reloaded too',
      (await app.count('key_list')) > keyReads && (await app.count('server_list')) > serverReads);
    yes('the restore is reported', (await toasts(page)).includes('Backup restored.'), JSON.stringify(await toasts(page)));
    yes('with what came back', /3 keys/.test(await page.textContent('#backupStatus')));
    check('no page errors', app.errors, []);
  });

  await withApp(browser, server, {}, 'backup restore wrong password', async (app) => {
    const { page } = app;
    await page.evaluate(() => {
      window.__replies.vault_backup_restore_from_file = (a) => {
        if (!a.path) return { needsPassword: true, path: '/home/u/old-backup.json' };
        throw 'Backup password is incorrect.';
      };
      window.__action = backupRestore();
    });
    await answerConfirm(page, 'ok');
    await waitVisible(page, '#promptModal');
    await page.fill('#promptInput', 'not it');
    await page.click('#promptOkBtn');
    await page.waitForTimeout(150);
    const said = (await toasts(page)).join(' | ');
    yes('a wrong backup password is reported', said.includes('Backup password is incorrect'), said);
    yes('with the way on: the grant is used up, so start the restore again', /again/i.test(said), said);
    check('and nothing is retried behind the user\'s back', await app.count('vault_backup_restore_from_file'), 2);
    yes('nor is the prompt reopened', !(await app.open('promptModal')));
  });

  await withApp(browser, server, {}, 'backup restore cancelled', async (app) => {
    const { page } = app;
    await page.evaluate(() => { window.__action = backupRestore(); });
    await answerConfirm(page, 'cancel');
    await settled(page, () => window.__action, null, 1200);
    check('Cancel on the question opens no file dialog', await app.count('vault_backup_restore_from_file'), 0);
    await page.evaluate(() => { window.__replies.vault_backup_restore_from_file = { canceled: true }; window.__action = backupRestore(); });
    await answerConfirm(page, 'ok');
    await settled(page, () => window.__action, null, 1200);
    const keyReads = await app.count('key_list');
    await page.waitForTimeout(80);
    check('a dismissed file dialog restores nothing and says nothing',
      { toasts: (await toasts(page)).filter((t) => /restor/i.test(t)), reloads: (await app.count('key_list')) - keyReads },
      { toasts: [], reloads: 0 });
  });

  await withApp(browser, server, {
    replies: { vault_backup_restore_from_file: { $reject: 'The vault is being re-encrypted - try again when it finishes.' } },
  }, 'backup restore during a password change', async (app) => {
    const { page } = app;
    await page.evaluate(() => { window.__action = backupRestore(); });
    await answerConfirm(page, 'ok');
    await settled(page, () => window.__action, null, 1200);
    await page.waitForTimeout(60);
    yes('C1 the re-encryption refusal is shown as it is',
      (await toasts(page)).includes('The vault is being re-encrypted - try again when it finishes.'), JSON.stringify(await toasts(page)));
    check('and the restore button is usable again', (await buttonState(page, 'backupImportBtn')).disabled, false);

    // A lock while Rust re-seals the backup's records aborts the restore.
    await page.evaluate(() => {
      window.__replies.vault_backup_restore_from_file = { $reject: 'Vault was locked while the operation was in progress.' };
      window.__action = backupRestore();
    });
    await answerConfirm(page, 'ok');
    await settled(page, () => window.__action, null, 1200);
    await page.waitForTimeout(60);
    yes('a lock during the restore is reported as nothing restored',
      (await toasts(page)).some((t) => /nothing was restored/i.test(t)), JSON.stringify(await toasts(page)));
  });

  await withApp(browser, server, { unlocked: false }, 'backup restore while locked', async (app) => {
    const { page } = app;
    await page.click('#vaultCancelBtn');
    await page.evaluate(() => { window.__action = backupRestore(); });
    await page.waitForTimeout(150);
    check('a locked vault is not offered a restore', [await app.open('confirmModal'), await app.count('vault_backup_restore_from_file')], [false, 0]);
    yes('the user is told to unlock first', (await toasts(page)).some((t) => /unlock/i.test(t)));
  });

  await withApp(browser, server, {}, 'backup card copy', async (app) => {
    const sub = await app.page.textContent('section[data-section="backup"] .card-sub');
    yes('A7-41 the card lists what a backup holds, SFTP bookmarks and MCP servers included',
      /SFTP bookmarks/.test(sub) && /MCP servers/.test(sub) && /known hosts/.test(sub), sub);
    yes('A7-41 and what it does not: Bitwarden sync and AI-assistant settings',
      /Not included/i.test(sub) && /Bitwarden/.test(sub) && /assistant/i.test(sub), sub);
    yes('A7-41 it no longer claims to be the entire vault', !/entire vault/i.test(sub), sub);
  });
}

/// A6-04 / A2-19: the server form's .pem browse asks for a path, never a read.
async function scenarioPemPicker(browser, server) {
  const replies = { system_pick_file_path: { canceled: false, path: '/home/u/.ssh/web.pem', name: 'web.pem' } };
  await withApp(browser, server, { replies }, '.pem browse', async (app) => {
    const { page } = app;
    await page.evaluate(() => openServerModal({}));
    await page.click('#srvBrowsePemBtn');
    await page.waitForTimeout(100);
    check('A6-04 the .pem browse fills in the chosen path', await page.inputValue('#srvPemPath'), '/home/u/.ssh/web.pem');
    check('A6-04 by asking for a path only: the key file is never read into this window',
      { pathOnly: await app.count('system_pick_file_path'), read: await app.count('system_select_file') },
      { pathOnly: 1, read: 0 });
    check('no page errors', app.errors, []);
  });
}

/// A8-14 / A2-14: the Settings rows show the values in effect.
async function scenarioSettingsDefaults(browser, server) {
  await withApp(browser, server, { settings: {} }, 'settings defaults', async (app) => {
    const { page } = app;
    const parallelShown = async (stored) => {
      await page.evaluate((s) => { window.__backend.settings = s; }, stored);
      await page.evaluate(() => switchView('settings'));
      return settingsRow(page, 'Parallel file transfers').locator('input').inputValue();
    };
    check('A8-14 nothing stored: parallel transfers shows the 4 the queue runs', await parallelShown({}), '4');
    check('A8-14 the backend\'s own default is shown as it is', await parallelShown({ sftpParallel: '4' }), '4');
    check('A8-14 a stored value is shown', await parallelShown({ sftpParallel: '3' }), '3');
    check('A8-14 junk reads as the queue reads it: 4', await parallelShown({ sftpParallel: 'junk' }), '4');
    check('A8-14 out of range is clamped like the queue clamps it', await parallelShown({ sftpParallel: '9' }), '4');
    check('A2-14 the auto-lock row shows the 15 minutes the backend applies',
      await page.evaluate(() => { window.__backend.settings = { autoLockMinutes: '15' }; return switchView('settings'); })
        .then(() => settingsRow(page, 'Lock the vault when idle').locator('input').inputValue()), '15');
    check('no page errors', app.errors, []);
  });
}

/// A5-32: a control whose save the backend refuses goes back to the value in
/// effect, and the backend's message is shown.
async function scenarioSettingsRevert(browser, server) {
  const settings = {
    confirmDelete: 'true', autoLockMinutes: '20', sftpParallel: '3', terminalBell: 'visual',
    sftpConflictUpload: 'ask', uiScale: '100', sftpMaxBps: '1048576',
  };
  await withApp(browser, server, { settings }, 'settings revert', async (app) => {
    const { page } = app;
    await page.evaluate(() => switchView('settings'));
    await page.evaluate(() => { window.__replies.settings_set = () => { throw 'Disk is read-only.'; }; });
    const attempts = async (key) => (await app.calls('settings_set')).filter((c) => c.args.key === key).map((c) => c.args.value);
    const blur = async () => { await page.keyboard.press('Tab'); await page.waitForTimeout(80); };

    await settingsRow(page, 'Confirm before deleting a key').locator('.toggle-box').click();
    await page.waitForTimeout(80);
    check('A5-32 the save was attempted', await attempts('confirmDelete'), ['false']);
    check('A5-32 a refused toggle flips back', await settingsRow(page, 'Confirm before deleting a key').locator('input').isChecked(), true);
    check('A5-32 and the setting in effect is unchanged', await page.evaluate(() => state.settings.confirmDelete), 'true');

    await settingsRow(page, 'Lock the vault when idle').locator('input').fill('30');
    await blur();
    check('A5-32 the auto-lock save was attempted', await attempts('autoLockMinutes'), ['30']);
    check('A5-32 a refused auto-lock value goes back', await settingsRow(page, 'Lock the vault when idle').locator('input').inputValue(), '20');
    yes('A5-32 and the countdown keeps the minutes in effect', /^locks in (19|20):\d\d$/.test(await page.textContent('#vaultSub')),
      await page.textContent('#vaultSub'));

    await settingsRow(page, 'Parallel file transfers').locator('input').fill('2');
    await blur();
    check('A5-32 a refused number goes back', [await attempts('sftpParallel'), await settingsRow(page, 'Parallel file transfers').locator('input').inputValue()], [['2'], '3']);

    await settingsRow(page, 'Terminal bell').locator('select').selectOption('sound');
    await page.waitForTimeout(80);
    check('A5-32 a refused choice goes back', [await attempts('terminalBell'), await settingsRow(page, 'Terminal bell').locator('select').inputValue()], [['sound'], 'visual']);

    await settingsRow(page, 'When an upload would overwrite a file').locator('select').selectOption('overwrite');
    await page.waitForTimeout(80);
    check('A5-32 a refused conflict default goes back, and the transfer code keeps the old one',
      [await settingsRow(page, 'When an upload would overwrite a file').locator('select').inputValue(),
        await page.evaluate(() => window.sftpConflictDefaults.sftpConflictUpload)], ['ask', 'ask']);

    await settingsRow(page, 'Interface scale').locator('select').selectOption('150');
    await page.waitForTimeout(80);
    check('A5-32 a refused scale goes back', [await attempts('uiScale'), await settingsRow(page, 'Interface scale').locator('select').inputValue()], [['150'], '100']);

    const bw = settingsRow(page, 'Bandwidth limit');
    await bw.locator('input[type="number"]').fill('2');
    await blur();
    check('A5-32 a refused bandwidth limit goes back to the limit in effect',
      [await attempts('sftpMaxBps'), await bw.locator('input[type="number"]').inputValue(), await bw.locator('select').inputValue()],
      [['2097152'], '1', '1048576']);
    check('A5-32 and is not pushed to running transfers', await app.count('sftp_queue_set_rate_limit'), 0);

    yes('A5-32 the backend\'s message is shown', (await toasts(page)).some((t) => t === 'Disk is read-only.'), JSON.stringify(await toasts(page)));

    await page.evaluate(() => { delete window.__replies.settings_set; });
    await settingsRow(page, 'Confirm before deleting a key').locator('.toggle-box').click();
    await page.waitForTimeout(80);
    check('a save that goes through sticks', [await settingsRow(page, 'Confirm before deleting a key').locator('input').isChecked(),
      await page.evaluate(() => state.settings.confirmDelete)], [false, 'false']);
    check('no page errors', app.errors, []);
  });
}

/// A6-08 (renderer half) / A2-14: the controls whose command the backend
/// refuses while locked are disabled, with the reason, and come back on unlock.
async function scenarioLockGates(browser, server) {
  const opts = {
    settings: { autoLockMinutes: '0' },
    replies: {
      known_hosts_list: { hosts: [{ host: 'example.org', fingerprintSha256: 'SHA256:abc', firstSeen: '2026-01-01T00:00:00Z' }] },
      audit_list: { rows: [{ ts: '2026-01-01T00:00:00Z', event: 'vault.unlock', detail: '' }], total: 1 },
    },
  };
  await withApp(browser, server, opts, 'lock gates', async (app) => {
    const { page } = app;
    const GATED = ['Lock the vault when idle', 'Confirm before deleting a key', 'Confirm multi-line pastes into the terminal', 'Check GitHub for new releases'];
    const gatedRows = async () => {
      const out = [];
      for (const t of GATED) {
        const row = settingsRow(page, t);
        const hint = row.locator('.settings-row-locked');
        const shown = (await hint.count()) > 0 && await hint.isVisible()
          && /Unlock the vault to change this/.test(await hint.textContent());
        out.push({ disabled: await row.locator('input').isDisabled(), hint: shown });
      }
      return out;
    };
    const categoryControls = () => page.evaluate(() => ({
      add: document.getElementById('catAddRootBtn').disabled,
      addTitle: document.getElementById('catAddRootBtn').title,
      menus: [...document.querySelectorAll('#catTree .cat-actions-btn')].map((b) => [b.disabled, b.title]),
      // Rows drag by pointer events now (Task 16); the gate is their
      // data-draggable flag, which applyLockGates keeps in step with the vault.
      drag: [...document.querySelectorAll('#catTree .cat-node:not(.uncategorized)')].map((n) => n.dataset.draggable === 'true'),
    }));
    const otherControls = () => page.evaluate(() => ({
      clear: [document.getElementById('auditClearBtn').disabled, document.getElementById('auditClearBtn').title],
      forget: [...document.querySelectorAll('#knownHostsBody .ghost-btn')].map((b) => [b.disabled, b.title]),
    }));

    check('unlocked: the category controls work', await categoryControls(),
      { add: false, addTitle: 'New top-level category', menus: [[false, 'Category actions']], drag: [true] });

    await page.keyboard.press('Control+l');
    await page.waitForTimeout(150);
    await page.click('#vaultCancelBtn');
    const locked = await categoryControls();
    check('A6-08 locked: New category is disabled', locked.add, true);
    yes('A6-08 with a tooltip that says why', /unlock the vault/i.test(locked.addTitle), locked.addTitle);
    // Since JU4 a lock empties the tree (category names are vault content):
    // no category row is left to drag and no "..." menu to open.
    check('A6-08 locked: no category menu or row is left to use', [locked.menus, locked.drag], [[], []]);

    await page.evaluate(() => switchView('settings'));
    const lockedOther = await otherControls();
    check('A6-08 locked: Clear log is disabled', lockedOther.clear[0], true);
    yes('A6-08 with the reason', /unlock the vault/i.test(lockedOther.clear[1]), lockedOther.clear[1]);
    check('A6-08 every Forget is disabled, with the reason',
      lockedOther.forget.map(([d, t]) => d && /unlock the vault/i.test(t)), [true]);
    check('A2-14 locked: the four security settings are disabled and say why', await gatedRows(),
      GATED.map(() => ({ disabled: true, hint: true })));
    check('A2-14 the other settings stay usable',
      [await settingsRow(page, 'Interface scale').locator('select').isDisabled(),
        await settingsRow(page, 'Parallel file transfers').locator('input').isDisabled()], [false, false]);

    // Nothing a locked user can reach turns into the backend's bare refusal.
    await page.evaluate(() => {
      document.getElementById('auditClearBtn').click();
      document.querySelector('#knownHostsBody .ghost-btn').click();
      window.__a = auditClear();
      window.__b = deleteCategory('c1');
      addCategoryPrompt(null);
      renameCategory('c1');
    });
    await page.waitForTimeout(200);
    const sent = [];
    for (const c of ['audit_clear', 'known_hosts_forget', 'category_delete', 'category_create', 'category_rename']) {
      sent.push(await app.count(c));
    }
    check('A6-08 locked: nothing is asked and nothing is sent',
      { dialogs: await app.openIds(), sent }, { dialogs: [], sent: [0, 0, 0, 0, 0] });
    check('A6-08 and no "Vault is locked." reaches the user', (await toasts(page)).filter((t) => /Vault is locked/.test(t)), []);

    await page.evaluate(() => requestVaultModal('unlock'));
    await page.fill('#vaultPassword', PASSWORD);
    await page.click('#vaultPrimary');
    await page.waitForTimeout(250);
    check('unlocked again: the security settings work again', await gatedRows(),
      GATED.map(() => ({ disabled: false, hint: false })));
    check('and Clear log and Forget', await otherControls(),
      { clear: [false, ''], forget: [[false, '']] });
    await page.evaluate(() => switchView('keys'));
    check('and the category controls, with their own tooltips back', await categoryControls(),
      { add: false, addTitle: 'New top-level category', menus: [[false, 'Category actions']], drag: [true] });
    check('no page errors', app.errors, []);
  });
}

/// A2-18 / RU1 C1: changing the master password re-seals every record and can
/// take seconds per key. The dialog shows it, cannot be closed under it, and
/// a lock in the middle leaves a usable unlock gate and a true account of
/// which password now opens the vault.
async function scenarioPasswordChange(browser, server) {
  const fillChange = async (page) => {
    await page.evaluate(() => requestVaultModal('change'));
    await page.fill('#vaultPasswordCurrent', 'old-password-1');
    await page.fill('#vaultPassword', 'new-password-2');
    await page.fill('#vaultPasswordConfirm', 'new-password-2');
  };
  const dialog = (page) => page.evaluate(() => ({
    title: document.getElementById('vaultModalTitle').textContent,
    text: document.getElementById('vaultModalText').textContent,
    primary: document.getElementById('vaultPrimary').textContent,
    primaryDisabled: document.getElementById('vaultPrimary').disabled,
    cancelDisabled: document.getElementById('vaultCancelBtn').disabled,
  }));

  await withApp(browser, server, { clock: true, settings: { autoLockMinutes: '0' } }, 'password change runs', async (app) => {
    const { page } = app;
    await fillChange(page);
    await hold(page, 'vault_change_password');
    await page.click('#vaultPrimary');
    await page.waitForTimeout(60);
    const busy = await dialog(page);
    yes('A2-18 the button shows the change is running', /re-encrypting/i.test(busy.primary) && busy.primaryDisabled, JSON.stringify(busy));
    yes('C1 the dialog says the vault is being re-encrypted', /re-encrypting your vault/i.test(busy.text), busy.text);
    check('C1 Cancel is disabled while it runs', busy.cancelDisabled, true);
    await page.keyboard.press('Escape');
    yes('C1 Escape does not close it mid-change', await app.open('vaultModal'));
    await page.evaluate(() => document.getElementById('vaultModal').click());
    yes('C1 nor a click on the backdrop', await app.open('vaultModal'));
    await page.evaluate(() => document.getElementById('vaultCancelBtn').click());
    yes('C1 nor Cancel', await app.open('vaultModal'));
    await app.tick(35 * 1000);
    yes('C1 nor the status polls', await app.open('vaultModal'));
    await page.evaluate(() => { document.getElementById('vaultPrimary').click(); submitVaultModal(); });
    check('A2-18 a second submit while it runs sends nothing', await app.count('vault_change_password'), 1);
    await letGo(page, 'vault_change_password');
    await page.waitForTimeout(150);
    yes('it closes when the change is done', !(await app.open('vaultModal')));
    yes('and says so', (await toasts(page)).some((t) => /master password changed/i.test(t)));
    await page.evaluate(() => requestVaultModal('change'));
    const again = await dialog(page);
    check('reopened, the dialog is idle again',
      [again.primary, again.primaryDisabled, again.cancelDisabled, /re-encrypting your vault/i.test(again.text)],
      ['Change password', false, false, false]);
    check('no page errors', app.errors, []);
  });

  await withApp(browser, server, { clock: true, settings: { autoLockMinutes: '0' } }, 'lock during a password change', async (app) => {
    const { page } = app;
    await fillChange(page);
    await hold(page, 'vault_change_password');
    await page.click('#vaultPrimary');
    await page.waitForTimeout(60);
    await page.keyboard.press('Control+l');
    await page.waitForTimeout(150);
    check('a lock still goes through mid-change', await app.count('vault_lock'), 1);
    const gate = await dialog(page);
    check('the unlock gate replaces the change dialog, idle and dismissable',
      [gate.title, gate.primary, gate.primaryDisabled, gate.cancelDisabled], ['Unlock vault', 'Unlock', false, false]);
    await page.fill('#vaultPassword', 'typed so far');
    await page.evaluate(() => {
      window.__replies.vault_change_password = () => { throw 'Vault was locked while the operation was in progress.'; };
    });
    await letGo(page, 'vault_change_password');
    await page.waitForTimeout(150);
    const said = (await toasts(page)).join(' | ');
    yes('the user is told nothing was changed, so the current password still opens the vault',
      /nothing was changed/i.test(said) && /current/i.test(said), said);
    check('the late answer leaves the unlock gate alone',
      [await app.open('vaultModal'), await page.inputValue('#vaultPassword'), (await dialog(page)).primary], [true, 'typed so far', 'Unlock']);
    await page.fill('#vaultPassword', PASSWORD);
    await page.click('#vaultPrimary');
    await page.waitForTimeout(150);
    check('and unlocking works', [await app.count('vault_unlock'), await page.evaluate(() => state.unlocked)], [1, true]);
    check('no page errors', app.errors, []);
  });

  await withApp(browser, server, { clock: true, settings: { autoLockMinutes: '0' } }, 'lock after the change committed', async (app) => {
    const { page } = app;
    await fillChange(page);
    await hold(page, 'vault_change_password');
    await page.click('#vaultPrimary');
    await page.waitForTimeout(60);
    // The tray or the idle watchdog locks after the rotation committed: the
    // backend keeps the vault locked, and only the NEW password opens it.
    await page.evaluate(() => { window.__backend.unlocked = false; });
    await letGo(page, 'vault_change_password');
    await page.waitForTimeout(200);
    yes('the vault is shown locked', await page.evaluate(() => !state.unlocked) && await app.open('vaultModal'));
    yes('and the user is told the NEW password is the one that opens it',
      (await toasts(page)).some((t) => /new master password/i.test(t)), JSON.stringify(await toasts(page)));
  });
}

/// A2-32: the audit CSV cannot smuggle a formula into a spreadsheet.
async function scenarioAuditCsv(browser, server) {
  const replies = { system_pick_save_path: { canceled: false, path: '/home/u/audit.csv' } };
  await withApp(browser, server, { replies }, 'audit csv', async (app) => {
    const { page } = app;
    await page.evaluate(() => {
      window.__replies.audit_list = {
        total: 5,
        rows: [
          { ts: '2026-01-01T00:00:00Z', event: '=HYPERLINK("http://x","y")', keyId: null, detail: 'plain' },
          { ts: '2026-01-01T00:00:00Z', event: 'key.created', keyId: '+cmd', detail: '-2+3' },
          { ts: '2026-01-01T00:00:00Z', event: 'key.created', keyId: '@SUM(A1)', detail: '\tTAB' },
          { ts: '2026-01-01T00:00:00Z', event: 'key.created', keyId: 'k1', detail: '\rCR' },
          { ts: '2026-01-01T00:00:00Z', event: 'key.created', keyId: 'k2', detail: 'a=b, "quoted"' },
        ],
      };
    });
    await page.evaluate(() => auditExport());
    await page.waitForTimeout(80);
    const csv = ((await app.calls('system_write_text_file'))[0] || { args: {} }).args.contents || '';
    check('A2-32 cells that start a formula are neutralised with a leading quote',
      ['"\'=HYPERLINK(""http://x"",""y"")"', '"\'+cmd"', '"\'-2+3"', '"\'@SUM(A1)"', '"\'\tTAB"', '"\'\rCR"']
        .map((cell) => csv.includes(cell)), [true, true, true, true, true, true]);
    check('A2-32 other cells are unchanged', ['"plain"', '"a=b, ""quoted"""', '"key.created"'].map((cell) => csv.includes(cell)), [true, true, true]);
    check('A2-32 csvField itself', await page.evaluate(() => [csvField('=1+2'), csvField('ok'), csvField(null), csvField('-')]),
      ['"\'=1+2"', '"ok"', '""', '"\'-"']);
  });
  await withApp(browser, server, { replies }, 'audit export busy', async (app) => {
    const { page } = app;
    await page.evaluate(() => {
      window.__replies.audit_list = { total: 1, rows: [{ ts: '2026-01-01T00:00:00Z', event: 'key.created', keyId: 'k1', detail: 'x' }] };
      switchView('settings'); showSettingsSection('audit');
    });
    await page.waitForTimeout(150); // the section's own list load
    const listed = await app.count('audit_list');
    await hold(page, 'system_pick_save_path');
    await page.evaluate(() => { el('auditExportBtn').click(); el('auditExportBtn').click(); });
    await page.waitForTimeout(100);
    check('A2-18 Export as CSV is busy while it runs: a second click starts no second export',
      [(await app.count('audit_list')) - listed, await page.evaluate(() => [el('auditExportBtn').disabled, el('auditExportBtn').getAttribute('aria-busy')])],
      [1, [true, 'true']]);
    await letGo(page, 'system_pick_save_path');
    await page.waitForTimeout(150);
    check('and it comes back when the export is done', await page.evaluate(() => [el('auditExportBtn').disabled, el('auditExportBtn').getAttribute('aria-busy')]), [false, null]);
    check('one file written', await app.count('system_write_text_file'), 1);
  });
}

/// A8-11: the create dialog names the KDF the vault really uses.
async function scenarioCreateCopy(browser, server) {
  await withApp(browser, server, { hasVault: false, unlocked: false }, 'create copy', async (app) => {
    const text = await app.page.textContent('#vaultModalText');
    yes('A8-11 the create dialog says Argon2id', /Argon2id/.test(text), text);
    yes('A8-11 and no longer says scrypt', !/scrypt/i.test(text), text);
  });
}

/// A2-20: one failing call at boot must not leave the app half-initialised.
async function scenarioBoot(browser, server) {
  const opts = {
    clock: true, bootCmd: 'vault_status',
    settings: { autoLockMinutes: '0' },
    replies: { category_list: { $reject: 'Category table is busy.' } },
  };
  await withApp(browser, server, opts, 'boot with a failing category load', async (app) => {
    const { page } = app;
    await page.waitForTimeout(300);
    yes('A2-20 the failed category load is reported', (await toasts(page)).some((t) => t.includes('Category table is busy.')),
      JSON.stringify(await toasts(page)));
    check('A2-20 boot still reads the stored settings', await app.count('settings_get'), 1);
    check('A2-20 and applies them (auto-lock 0 = off)', await page.textContent('#vaultSub'), 'auto-lock off');
    check('A2-20 the keys still show', await page.evaluate(() => document.querySelectorAll('#keyList .key-row').length), 2);
    const polls = await app.count('vault_status');
    await app.tick(10 * 1000 + 200);
    yes('A2-20 the 10 s status poll is running', (await app.count('vault_status')) > polls);
    const beats = await app.count('heartbeat');
    await page.keyboard.press('a');
    yes('A2-20 and real input is still watched (heartbeat)', (await app.count('heartbeat')) > beats);
    check('no page errors', app.errors, []);
  });

  // The guard around main()'s first refreshVaultStatus(): vault_status itself
  // failing at boot must not stop the wiring after it (JU2 review).
  const down = {
    clock: true, bootCmd: 'vault_status',
    settings: { autoLockMinutes: '0' },
    replies: { vault_status: { $reject: 'Vault service unavailable.' } },
  };
  await withApp(browser, server, down, 'boot with vault_status failing', async (app) => {
    const { page } = app;
    await page.waitForTimeout(300);
    yes('A2-20 a failing first vault_status is reported', (await toasts(page)).some((t) => t.includes('Vault service unavailable.')),
      JSON.stringify(await toasts(page)));
    yes('A2-20 and logged for diagnosis', await page.evaluate(() =>
      (window.__bootErrors || []).some((m) => /first vault refresh failed/.test(m))));
    check('A2-20 boot goes on to read the stored settings', await app.count('settings_get'), 1);
    const polls = await app.count('vault_status');
    await app.tick(10 * 1000 + 200);
    yes('A2-20 the 10 s status poll is running', (await app.count('vault_status')) > polls);
    const beats = await app.count('heartbeat');
    await page.keyboard.press('a');
    yes('A2-20 real input is watched (heartbeat)', (await app.count('heartbeat')) > beats);
    // The backend comes back: the next poll picks the vault state up.
    await page.evaluate(() => { delete window.__replies.vault_status; });
    await app.tick(10 * 1000 + 200);
    await page.waitForTimeout(200);
    check('A2-20 once vault_status answers, the next poll applies it', await page.evaluate(() =>
      [state.unlocked, document.querySelectorAll('#keyList .key-row').length]), [true, 2]);
    check('no page errors', app.errors, []);
  });

  await withApp(browser, server, {}, 'new category refused', async (app) => {
    const { page } = app;
    await page.evaluate(() => {
      window.__replies.category_create = () => { throw 'A category parent must use the same key/host scope.'; };
      addCategoryPrompt(null);
    });
    await waitVisible(page, '#promptModal');
    await page.fill('#promptInput', 'Ops');
    await page.click('#promptOkBtn');
    await page.waitForTimeout(120);
    yes('A2-20 a refused new category is reported',
      (await toasts(page)).includes('A category parent must use the same key/host scope.'), JSON.stringify(await toasts(page)));
    check('A2-20 not left as an unhandled rejection',
      await page.evaluate(() => (window.__bootErrors || []).filter((m) => /unhandled/.test(m))), []);
  });
}

/// A5-21: a list that failed to load says so, with a Retry - it is not the
/// first-run empty state - and a repeated toast is counted, not stacked.
async function scenarioLoadErrors(browser, server) {
  const card = (page, host) => page.evaluate((h) => {
    const c = document.querySelector(h + ' .load-error');
    return c ? { text: c.textContent, retry: [...c.querySelectorAll('button')].some((b) => /retry/i.test(b.textContent)) } : null;
  }, host);

  await withApp(browser, server, { replies: { key_list: { $reject: 'Backend unavailable.' } } }, 'keys fail to load', async (app) => {
    const { page } = app;
    const c = await card(page, '#keyList');
    yes('A5-21 the key list says the keys could not be loaded, with the reason', c && c.text.includes('Backend unavailable.'), JSON.stringify(c));
    yes('A5-21 with a Retry', c && c.retry);
    check('A5-21 and not "No keys yet"', await page.evaluate(() => document.getElementById('emptyState').hidden), true);
    await page.evaluate(() => { delete window.__replies.key_list; });
    await page.click('#keyList .load-error button');
    await page.waitForTimeout(150);
    check('A5-21 Retry loads them', [await card(page, '#keyList'), await page.evaluate(() => document.querySelectorAll('#keyList .key-row').length)], [null, 2]);
  });

  await withApp(browser, server, { replies: { server_list: { $reject: 'Backend unavailable.' } } }, 'servers fail to load', async (app) => {
    const { page } = app;
    await page.evaluate(() => switchView('connect'));
    const c = await card(page, '#serverList');
    yes('A5-21 the server list says the servers could not be loaded', c && c.text.includes('Backend unavailable.') && c.retry, JSON.stringify(c));
    check('A5-21 and not "No saved servers yet"', await page.evaluate(() => document.getElementById('serverEmpty').hidden), true);
    await page.evaluate(() => { delete window.__replies.server_list; });
    await page.click('#serverList .load-error button');
    await page.waitForTimeout(150);
    check('A5-21 Retry loads them', [await card(page, '#serverList'), await page.evaluate(() => document.querySelectorAll('#serverList .server-row').length)], [null, 1]);
  });

  await withApp(browser, server, { settings: { autoLockMinutes: '0' } }, 'settings fail to load', async (app) => {
    const { page } = app;
    await page.evaluate(() => { window.__replies.settings_get = () => { throw 'Database is busy.'; }; });
    await page.evaluate(() => switchView('settings'));
    const c = await card(page, '#settingsRows');
    yes('A5-21 Settings says the settings could not be loaded, with a Retry', c && c.text.includes('Database is busy.') && c.retry, JSON.stringify(c));
    check('A5-21 and keeps the settings in effect instead of resetting them',
      [await page.evaluate(() => state.settings.autoLockMinutes), await page.textContent('#vaultSub')], ['0', 'auto-lock off']);
    await page.evaluate(() => { delete window.__replies.settings_get; });
    await page.click('#settingsRows .load-error button');
    await page.waitForTimeout(150);
    yes('A5-21 Retry brings the rows', (await card(page, '#settingsRows')) === null
      && await page.evaluate(() => document.querySelectorAll('#settingsRows .settings-row').length > 5));
  });

  await withApp(browser, server, {}, 'repeated toasts', async (app) => {
    const { page } = app;
    await page.evaluate(() => {
      toast('Backend unavailable.', 'err'); toast('Backend unavailable.', 'err'); toast('Backend unavailable.', 'err');
      toast('Something else.', 'err');
      toast('Backend unavailable.', 'info');
    });
    const items = await page.evaluate(() => [...document.querySelectorAll('#toast .toast-item')].map((n) => ({
      text: n.querySelector('.toast-text').textContent,
      count: n.querySelector('.toast-count') ? n.querySelector('.toast-count').textContent : null,
    })));
    check('A5-21 an identical toast while one is up is counted, not stacked',
      items.filter((i) => i.text === 'Backend unavailable.').length, 2);
    check('A5-21 the count is shown on it', items.map((i) => i.count).filter(Boolean), ['×3']);
    check('A5-21 other messages still get their own toast', items.length, 3);
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
  ['backup: written by Rust, busy button, path and counts reported', scenarioBackupCreate],
  ['restore: confirm first, password round-trip, everything reloaded', scenarioBackupRestore],
  ['server form: the .pem browse picks a path only', scenarioPemPicker],
  ['settings: the values in effect are shown', scenarioSettingsDefaults],
  ['settings: a refused save puts the control back', scenarioSettingsRevert],
  ['lock: controls the backend refuses while locked are disabled', scenarioLockGates],
  ['master password change: busy, not dismissable, safe across a lock', scenarioPasswordChange],
  ['audit CSV: formula cells are neutralised', scenarioAuditCsv],
  ['create dialog: names the real KDF', scenarioCreateCopy],
  ['boot: one failing call does not stop the wiring', scenarioBoot],
  ['load errors: a card with Retry, repeated toasts counted', scenarioLoadErrors],
];

(async () => {
  const only = process.argv.includes('--only') ? process.argv[process.argv.indexOf('--only') + 1] : null;
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
    console.error(`\n${failures.length} audit safety check(s) failed.`);
    process.exit(1);
  }
  console.log('\nAll audit safety checks passed.');
})().catch((e) => { console.error(e); process.exit(1); });
