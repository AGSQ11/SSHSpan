#!/usr/bin/env node
/*
 * Accessibility, keyboard, menu, palette and settings polish checks for the
 * renderer, driven through the REAL page (index.html and every script it
 * loads) in headless Chromium against the stub Tauri IPC in
 * scripts/lib/renderer-harness.js.
 *
 * Nothing here re-implements production logic: every assertion is about what
 * the page shows, where the focus is, or which IPC commands it sends.
 *
 * What it pins (flaw audit 2026-10-09, unit JU6a - finding ids in each title):
 *   - no control sits inside a <label> that also forwards clicks to it: one
 *     click on the bandwidth "Unlimited" pill writes once, a caption click
 *     changes nothing, blank space in the server form's auth row does nothing;
 *   - one menu helper: role=menu, focus on the first item, arrow keys,
 *     Escape and outside clicks, focus back to the opener, kept on screen;
 *   - a visible focus ring everywhere, and key rows, category rows, chevrons
 *     and session tabs that work from the keyboard;
 *   - text and selected-segment contrast, the narrow-window category drawer,
 *     dialogs whose buttons stay on screen, tabs/radios/listbox ARIA, the
 *     command palette's matching and ranking, the audit log filters and
 *     paging, show/hide on every password field;
 *   - static: the dead CSS and JS the audit listed stay deleted, and the CI
 *     checks cover assistant.js and mcp.js.
 *
 * Run with `npm run test:polish`. Needs playwright (see check-renderer-ui.js);
 * without it only the static checks run. `--only <text>` runs the scenarios
 * whose title contains <text>; SSHSPAN_RENDERER_DIR points the run at another
 * copy of the renderer (a pristine `git archive` of an older commit, to watch
 * these checks fail where they should).
 */
'use strict';

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const {
  failures, check, yes, loadChromium, rendererDir, serve, part,
  KEY, SERVER, CATEGORY, withApp, waitVisible, openLiveTab,
} = require('./lib/renderer-harness');

const ROOT = path.resolve(__dirname, '..');
const RENDERER = rendererDir();

// ─── helpers ────────────────────────────────────────────────────────────────

/// A Settings row by its title, as the page renders it.
const settingsRow = (page, title) => page.locator('#settingsRows .settings-row').filter({
  has: page.locator('.settings-row-title', { hasText: title }),
});

/// The open menu: its role, its items' roles and labels, and which item (by
/// index among the menu items) has the focus (-1: none).
const menuState = (page) => page.evaluate(() => {
  const m = document.getElementById('keyConnectMenu');
  if (!m) return null;
  const items = [...m.querySelectorAll('.ctx-item')];
  const r = m.getBoundingClientRect();
  return {
    role: m.getAttribute('role'),
    itemRoles: items.map((b) => b.getAttribute('role')),
    labels: items.map((b) => b.textContent.trim()),
    icons: items.map((b) => !!b.querySelector('svg')),
    focused: items.indexOf(document.activeElement),
    inViewport: r.left >= 0 && r.top >= 0 && r.right <= window.innerWidth && r.bottom <= window.innerHeight,
  };
});

const attr = (page, sel, name) => page.evaluate(({ s, n }) => {
  const e = document.querySelector(s);
  return e ? e.getAttribute(n) : null;
}, { s: sel, n: name });

/// What has the focus, as "#id" or "tag.class".
const focusedDesc = (page) => page.evaluate(() => {
  const a = document.activeElement;
  if (!a || a === document.body) return 'body';
  return a.id ? '#' + a.id : a.tagName.toLowerCase() + '.' + String(a.className).split(' ')[0];
});

/// WCAG 2.x contrast ratio of two CSS colours ("#rrggbb" or "rgb(r, g, b)").
function contrast(a, b) {
  const rgb = (c) => {
    c = String(c).trim();
    if (c.startsWith('#')) return [1, 3, 5].map((i) => parseInt(c.slice(i, i + 2), 16));
    return c.match(/[\d.]+/g).slice(0, 3).map(Number);
  };
  const lum = (v) => {
    const [r, g, bl] = v.map((x) => { x /= 255; return x <= 0.03928 ? x / 12.92 : Math.pow((x + 0.055) / 1.055, 2.4); });
    return 0.2126 * r + 0.7152 * g + 0.0722 * bl;
  };
  const [hi, lo] = [lum(rgb(a)), lum(rgb(b))].sort((x, y) => y - x);
  return Math.round(((hi + 0.05) / (lo + 0.05)) * 100) / 100;
}

const KEYS4 = [KEY('k1', 'alpha'), KEY('k2', 'beta'), KEY('k3', 'gamma'), KEY('k4', 'delta')];
const CATS = [CATEGORY, { id: 'c2', name: 'EU', parent_id: 'c1', scope: 'key', sort_index: 0, color: null }];
const CAT_REPLY = { categories: CATS, allKeyCategories: { k1: ['c1'], k2: ['c2'] }, orphans: true, hostOrphans: false };

// ─── item 1: no control nested in a forwarding <label> (A1-05, A2-16) ─────

async function scenarioLabels(browser, server) {
  await withApp(browser, server, { settings: { sftpMaxBps: '0' } }, 'settings rows', async (app) => {
    const { page } = app;
    await page.evaluate(() => switchView('settings'));
    const rows = await page.evaluate(() => [...document.querySelectorAll('#settingsRows .settings-row')].map((r) => {
      const title = r.querySelector('.settings-row-title');
      const field = r.querySelector('.settings-row-control input, .settings-row-control select');
      return {
        tag: r.tagName,
        title: title.textContent,
        // A row with a form field names it with <label for>; a row whose
        // control is a button or plain text has a caption that labels nothing.
        ok: field ? (title.tagName === 'LABEL' && !!title.control && r.contains(title.control))
          : !(title.control),
      };
    }));
    check('A1-05 every Settings row is a <div>, not a <label>', [...new Set(rows.map((r) => r.tag))], ['DIV']);
    check('A1-05 each caption labels its own field and nothing else', rows.filter((r) => !r.ok).map((r) => r.title), []);

    const bw = settingsRow(page, 'Bandwidth limit');
    const writes = async () => (await app.calls('settings_set')).filter((c) => c.args.key === 'sftpMaxBps').map((c) => c.args.value);
    const pushes = async () => (await app.calls('sftp_queue_set_rate_limit')).map((c) => c.args.bytesPerSec);
    await bw.locator('.settings-combo-tag').click();
    await page.waitForTimeout(150);
    check('A2-16 one click on Unlimited sets the limit once', await writes(), ['524288']);
    check('A2-16 and pushes it to running transfers once', await pushes(), [524288]);
    check('A2-16 the pill then shows Unlimited off', await bw.locator('.settings-combo-tag').evaluate((n) => n.classList.contains('active')), false);
    await bw.locator('.settings-combo-tag').click();
    await page.waitForTimeout(150);
    check('A2-16 a second click removes the limit, once', await writes(), ['524288', '0']);
    // force: the caption now names the number field, which Unlimited has
    // disabled, and Playwright would wait for it to be enabled - a real mouse
    // click on the caption is exactly what is being tested.
    await bw.locator('.settings-row-title').click({ force: true });
    await page.waitForTimeout(150);
    check('A1-05 a click on the "Bandwidth limit" caption changes nothing', [await writes(), await pushes()], [['524288', '0'], [524288, 0]]);
    check('A1-05 the bandwidth number and unit have names',
      await bw.evaluate((r) => [...r.querySelectorAll('input[type="number"], select')]
        .map((n) => !!(n.getAttribute('aria-label') || (n.labels && n.labels.length)))), [true, true]);

    const checks = await app.count('update_check');
    await settingsRow(page, 'Check for an update now').locator('.settings-row-title').click();
    await page.waitForTimeout(150);
    check('A1-05 a click on the "Check for an update now" caption checks nothing', await app.count('update_check'), checks);
    check('no page errors', app.errors, []);
  });

  await withApp(browser, server, {}, 'server form auth row', async (app) => {
    const { page } = app;
    await page.evaluate(() => { openServerModal({}); setConnectAuthMethod('password'); });
    await page.waitForTimeout(80);
    const where = await page.evaluate(() => {
      const row = document.querySelector('#serverModal .auth-method-row');
      const seg = row.querySelector('.seg');
      const r = row.getBoundingClientRect();
      const s = seg.getBoundingClientRect();
      return { x: Math.round(Math.min(r.right - 8, s.right + 60)), y: Math.round(s.top + s.height / 2), tag: row.tagName, role: row.getAttribute('role') };
    });
    await page.mouse.click(where.x, where.y);
    await page.waitForTimeout(80);
    check('A1-05 a click on blank space in the auth-method row leaves the method alone', await page.evaluate(() => state.connectAuthMethod), 'password');
    check('A1-05 the auth-method row is a radio group, not a label',
      { label: where.tag === 'LABEL', group: where.role === 'radiogroup' || where.tag === 'FIELDSET' }, { label: false, group: true });
    check('no page errors', app.errors, []);
  });
}

// ─── item 2: one menu helper (A2-50, A1-26, A2-21, A1-04, A1-28, A2-27) ──

async function scenarioMenus(browser, server) {
  await withApp(browser, server, {}, 'vault menu', async (app) => {
    const { page } = app;
    await page.focus('#vaultStatus');
    await page.keyboard.press('Enter');
    await page.waitForTimeout(80);
    let m = await menuState(page);
    check('A2-50 the vault menu is a menu of menu items', m && [m.role, m.itemRoles], ['menu', ['menuitem', 'menuitem', 'menuitem', 'menuitem']]);
    check('A2-50 with the same items as before, and Quit (R11, JU5)', m && m.labels,
      ['Lock now  (Ctrl+L)', 'Change master password...', 'Auto-lock settings...', 'Quit SSHSpan  (Ctrl+Q)']);
    check('A1-26 the first item has the focus', m && m.focused, 0);
    check('A2-50 the vault button says it is expanded', await attr(page, '#vaultStatus', 'aria-expanded'), 'true');
    const moves = [];
    for (const k of ['ArrowDown', 'End', 'Home', 'ArrowUp']) {
      await page.keyboard.press(k);
      moves.push((await menuState(page)).focused);
    }
    check('A2-50 ArrowDown, End, Home and ArrowUp (wrapping) move the focus', moves, [1, 3, 0, 3]);
    await page.keyboard.press('Escape');
    await page.waitForTimeout(60);
    check('A2-50 Escape closes it', await menuState(page), null);
    check('A1-26 and gives the focus back to the vault button', await focusedDesc(page), '#vaultStatus');
    check('A2-50 which is no longer expanded', await attr(page, '#vaultStatus', 'aria-expanded'), 'false');

    await page.click('#vaultStatus');
    await page.click('#keyConnectMenu .ctx-item:has-text("Auto-lock settings")');
    await page.waitForTimeout(80);
    check('A2-50 choosing an item resets aria-expanded', await attr(page, '#vaultStatus', 'aria-expanded'), 'false');
    await page.evaluate(() => switchView('keys'));

    await page.click('#vaultStatus');
    await page.waitForTimeout(60);
    await page.click('#vaultStatus');
    await page.waitForTimeout(60);
    check('A2-50 a second click on the vault button closes its menu', await menuState(page), null);
    await page.click('#vaultStatus');
    await page.mouse.click(700, 400);
    await page.waitForTimeout(60);
    check('A2-50 a click outside closes it', [await menuState(page), await attr(page, '#vaultStatus', 'aria-expanded')], [null, 'false']);
    check('no page errors', app.errors, []);
  });

  await withApp(browser, server, { categories: CATS, replies: { category_list: CAT_REPLY } }, 'category menu', async (app) => {
    const { page } = app;
    const btn = '#catTree .cat-node[data-id="c1"] .cat-actions-btn';
    await page.hover('#catTree .cat-node[data-id="c1"]');
    await page.click(btn);
    await page.waitForTimeout(80);
    const m = await menuState(page);
    check('A2-50 the category menu uses the shared menu', m && m.role, 'menu');
    check('A2-50 with the same items as before', m && m.labels, ['Rename', 'New subcategory', 'Move to...', 'Delete']);
    check('A2-27 every item shows its icon', m && m.icons, [true, true, true, true]);
    check('A1-26 the first item has the focus', m && m.focused, 0);
    await page.keyboard.press('Escape');
    await page.waitForTimeout(60);
    check('A1-26 Escape gives the focus back to the "..." button',
      await page.evaluate((s) => document.activeElement === document.querySelector(s), btn), true);
    await page.click(btn);
    await page.click('#keyConnectMenu .ctx-item:has-text("Rename")');
    yes('A2-50 its actions still run (Rename asks for the new name)', await waitVisible(page, '#promptModal'));
    check('no page errors', app.errors, []);
  });

  await withApp(browser, server, {}, 'key and server menus', async (app) => {
    const { page } = app;
    const size = await page.evaluate(() => [window.innerWidth, window.innerHeight]);
    await page.evaluate(([w, h]) => {
      document.querySelector('#keyList .key-row').dispatchEvent(
        new MouseEvent('contextmenu', { bubbles: true, cancelable: true, clientX: w - 3, clientY: h - 3 }));
    }, size);
    await page.waitForTimeout(80);
    let m = await menuState(page);
    check('A2-21 a key menu opened at the bottom-right corner stays on screen', m && m.inViewport, true);
    check('A2-50 it is a menu with the same item', m && [m.role, m.labels], ['menu', ['Use this key to connect...']]);
    await page.keyboard.press('Escape');

    await page.evaluate(() => switchView('connect'));
    await page.waitForSelector('#serverList .server-row');
    await page.evaluate(([w, h]) => {
      document.querySelector('#serverList .server-row').dispatchEvent(
        new MouseEvent('contextmenu', { bubbles: true, cancelable: true, clientX: w - 3, clientY: h - 3 }));
    }, size);
    await page.waitForTimeout(80);
    m = await menuState(page);
    check('A1-04 a server menu opened at the bottom-right corner stays on screen', m && m.inViewport, true);
    // "Test connection" joined the server menu in JU5 fix round 1 (item 12).
    check('A2-50 it keeps its items and has the focus', m && [m.role, m.labels, m.focused], ['menu', ['Connect', 'Test connection', 'Edit', 'Delete'], 0]);
    await page.keyboard.press('ArrowDown');
    await page.keyboard.press('ArrowDown');
    await page.keyboard.press('Enter');
    yes('A2-50 Enter on an item runs it (Edit opens the server form)', await waitVisible(page, '#serverModal'));
    check('no page errors', app.errors, []);
  });

  await withApp(browser, server, {}, 'terminal menu', async (app) => {
    const { page } = app;
    const tab = await openLiveTab(app);
    await page.evaluate((t) => openTerminalContextMenu(window.innerWidth - 2, window.innerHeight - 2, t), tab);
    await page.waitForTimeout(80);
    const m = await menuState(page);
    check('A1-04 the terminal menu opened at the bottom-right corner stays on screen', m && m.inViewport, true);
    // No "Duplicate session" (it was "New session" twice - A5-33) and the mode
    // item says where it goes (A3-31) - JU5.
    check('A2-50 it keeps its items', m && m.labels, ['Copy', 'Copy all to clipboard', 'Paste', 'Clear scrollback',
      'Reset terminal', 'New session', 'Restart session', 'Open file browser']);
    check('A1-28 Paste, Clear scrollback and Reset terminal show their icons', m && [m.icons[2], m.icons[3], m.icons[4]], [true, true, true]);
    check('A1-28 its separators are thin rules with no inset border', await page.evaluate(() =>
      [...document.querySelectorAll('#keyConnectMenu .ctx-sep')].map((s) => [getComputedStyle(s).borderTopWidth, s.getBoundingClientRect().height])),
    [['0px', 1], ['0px', 1]]);
    check('A1-28 an unknown icon name still takes an icon\'s width', await page.evaluate(() => {
      const b = document.createElement('button');
      b.className = 'ctx-item';
      b.innerHTML = ico('no-such-icon') + '<span>x</span>';
      document.getElementById('keyConnectMenu').appendChild(b);
      const w = b.firstElementChild && b.firstElementChild.tagName.toLowerCase() === 'svg' ? b.firstElementChild.getBoundingClientRect().width : 0;
      b.remove();
      return w;
    }), 14);
    await page.mouse.click(300, 300);
    check('a click elsewhere closes it', await menuState(page), null);
    check('no page errors', app.errors, []);
  });
}

// ─── item 3: focus ring, keyboard-operable rows and tabs (A1-10, A1-11) ──

async function scenarioKeyboard(browser, server) {
  await withApp(browser, server, { categories: CATS, replies: { category_list: CAT_REPLY } }, 'focus ring and key rows', async (app) => {
    const { page } = app;
    // Keyboard modality first: focus moved by script after a Tab counts as
    // keyboard focus, which is when :focus-visible applies.
    await page.keyboard.press('Tab');
    const rings = {};
    for (const sel of ['#detailRenameBtn', '.nav-item[data-view="settings"]', '#paletteBtn', '#vaultStatus',
      '#newKeyBtn', '.detail-tab[data-detail-tab="export"]', '#catAddRootBtn', '.key-group-head .icon-btn']) {
      rings[sel] = await page.evaluate((s) => {
        const n = document.querySelector(s);
        n.focus();
        const cs = getComputedStyle(n);
        return n.matches(':focus-visible') && cs.outlineStyle !== 'none' && parseFloat(cs.outlineWidth) >= 2;
      }, sel);
    }
    check('A1-10 every control shows a focus ring when focused from the keyboard',
      Object.entries(rings).filter(([, v]) => !v).map(([k]) => k), []);

    const row = (id) => `#keyList .key-row[data-id="${id}"]`;
    check('A1-11 key rows are reachable with Tab and say what they are',
      await page.evaluate((s) => { const n = document.querySelector(s); return [n.tabIndex, n.getAttribute('role')]; }, row('k2')), [0, 'button']);
    await page.focus(row('k2'));
    await page.keyboard.press('Enter');
    await page.waitForTimeout(120);
    check('A1-11 Enter on a key row opens it', await page.evaluate(() => state.selectedId), 'k2');
    check('A1-26 and the focus stays on that row after the list redraws',
      await page.evaluate(() => { const r = document.activeElement && document.activeElement.closest('.key-row'); return r ? r.dataset.id : null; }), 'k2');
    await page.focus(row('k1'));
    await page.keyboard.press(' ');
    await page.waitForTimeout(120);
    check('A1-11 Space opens it too', await page.evaluate(() => state.selectedId), 'k1');

    const node = '#catTree .cat-node[data-id="c1"]';
    check('A1-11 category rows are reachable with Tab and say what they are',
      await page.evaluate((s) => { const n = document.querySelector(s); return [n.tabIndex, n.getAttribute('role')]; }, node), [0, 'button']);
    await page.focus(node);
    await page.waitForTimeout(200); // the button fades in over 0.1 s
    check('A1-11 a focused category row shows its actions button',
      await page.evaluate((s) => getComputedStyle(document.querySelector(s + ' .cat-actions-btn')).opacity, node), '1');
    await page.keyboard.press('Enter');
    await page.waitForTimeout(120);
    check('A1-11 Enter on a category row filters by it', await page.evaluate(() => activeCategoryId()), 'c1');
    check('A1-26 and the focus stays on that row',
      await page.evaluate(() => { const r = document.activeElement && document.activeElement.closest('.cat-node'); return r ? r.dataset.id : null; }), 'c1');
    const chev = node + ' .cat-chevron';
    check('A1-11 the expand chevron is a control of its own',
      await page.evaluate((s) => { const n = document.querySelector(s); return [n.tabIndex >= 0, n.getAttribute('aria-expanded'), !!n.getAttribute('aria-label')]; }, chev),
      [true, 'false', true]);
    await page.focus(chev);
    await page.keyboard.press('Enter');
    await page.waitForTimeout(120);
    check('A1-11 Enter on the chevron expands the category, and the focus stays on it',
      await page.evaluate((s) => [state.expandedCatIds.has('c1'), document.activeElement === document.querySelector(s), document.querySelector(s).getAttribute('aria-expanded')], chev),
      [true, true, 'true']);
    check('no page errors', app.errors, []);
  });

  await withApp(browser, server, {}, 'session tabs', async (app) => {
    const { page } = app;
    await openLiveTab(app);
    await page.evaluate((s) => openSessionTab(s), SERVER('s1', 'web-1'));
    await page.waitForFunction(() => [...state.sessions.keys()].filter((id) => window.tabSessionLive(id)).length === 2, null, { polling: 25 });
    const tabs = await page.evaluate(() => [...document.querySelectorAll('#termTabs .term-tab')].map((t) => ({
      tabIndex: t.tabIndex, role: t.getAttribute('role'),
      close: (() => { const c = t.querySelector('.term-tab-close'); return c ? [c.tagName, !!c.getAttribute('aria-label')] : null; })(),
    })));
    check('A1-11 session tabs are reachable with Tab and say what they are', tabs.map((t) => [t.tabIndex, t.role]), [[0, 'button'], [0, 'button']]);
    check('A1-11 their close control is a named button', tabs.map((t) => t.close), [['BUTTON', true], ['BUTTON', true]]);
    const first = await page.evaluate(() => [...state.sessions.keys()][0]);
    // No waiting for the second tab's deferred terminal focus: since JU5 it
    // never takes the keyboard from a control the user moved to meanwhile.
    await page.focus('#termTabs .term-tab');
    await page.keyboard.press('Enter');
    await page.waitForTimeout(100);
    check('A1-11 Enter on a session tab switches to it', await page.evaluate(() => state.activeTabId), first);
    check('A1-11 the "+" tab is a named button',
      await page.evaluate(() => { const b = document.getElementById('termTabAdd'); return [b.tagName, !!(b.getAttribute('aria-label') || b.title)]; }), ['BUTTON', true]);
    check('no page errors', app.errors, []);
  });
}

// ─── item 4: contrast (A1-13, A1-14) ────────────────────────────────────────

async function scenarioContrast(browser, server) {
  await withApp(browser, server, {}, 'contrast', async (app) => {
    const { page } = app;
    const tokens = await page.evaluate(() => {
      const cs = getComputedStyle(document.documentElement);
      return ['--text-faint', '--bg', '--bg-elev', '--panel', '--panel-2', '--panel-3'].map((t) => cs.getPropertyValue(t).trim());
    });
    const [faint, ...surfaces] = tokens;
    check('A1-13 --text-faint reaches 4.5:1 on --bg', contrast(faint, surfaces[0]) >= 4.5, true);
    check('A1-13 and on every panel surface it is used on',
      surfaces.map((s) => contrast(faint, s) >= 4.5), [true, true, true, true, true]);
    await page.evaluate(() => { openServerModal({}); setConnectAuthMethod('publickey'); });
    const seg = await page.evaluate(() => {
      const b = document.querySelector('#serverModal .seg-btn.active');
      const cs = getComputedStyle(b);
      return [cs.color, cs.backgroundColor];
    });
    check('A1-14 the selected auth segment\'s label reaches 4.5:1', contrast(seg[0], seg[1]) >= 4.5, true);
    const badge = await page.evaluate(() => {
      const b = document.getElementById('assistantYoloBadge');
      b.hidden = false;
      const cs = getComputedStyle(b);
      const out = [cs.color, cs.backgroundColor];
      b.hidden = true;
      return out;
    });
    check('A1-14 the YOLO badge\'s label reaches 4.5:1', contrast(badge[0], badge[1]) >= 4.5, true);
  });
}

// ─── item 5: the narrow window (A1-06, A5-13, A1-19) ─────────────────────

async function scenarioNarrow(browser, server) {
  await withApp(browser, server, { categories: CATS, replies: { category_list: CAT_REPLY } }, 'categories at 880px', async (app) => {
    const { page } = app;
    await page.setViewportSize({ width: 880, height: 560 });
    await page.waitForTimeout(150);
    const shown = (sel) => page.evaluate((s) => {
      const n = document.querySelector(s);
      if (!n) return false;
      const r = n.getBoundingClientRect();
      return getComputedStyle(n).display !== 'none' && r.width > 0 && r.height > 0;
    }, sel);
    check('A1-06 at 880px the Keys toolbar has a Categories button', await shown('#catDrawerBtn'), true);
    await page.click('#catDrawerBtn');
    await page.waitForTimeout(150);
    check('A1-06 it opens the category tree, with New category',
      [await shown('#catPanel'), await shown('#catAddRootBtn'), await attr(page, '#catDrawerBtn', 'aria-expanded')], [true, true, 'true']);
    await page.hover('#catTree .cat-node[data-id="c1"]');
    await page.click('#catTree .cat-node[data-id="c1"] .cat-actions-btn');
    await page.waitForTimeout(80);
    check('A5-13 rename, move and delete are reachable from it',
      (await menuState(page) || { labels: [] }).labels, ['Rename', 'New subcategory', 'Move to...', 'Delete']);
    await page.keyboard.press('Escape');
    await page.click('#catTree .cat-node[data-id="c1"]');
    await page.waitForTimeout(150);
    check('A5-13 choosing a category filters the list and closes the drawer',
      [await page.evaluate(() => activeCategoryId()), await shown('#catPanel'), await attr(page, '#catDrawerBtn', 'aria-expanded')], ['c1', false, 'false']);
    await page.click('#catDrawerBtn');
    await page.waitForTimeout(100);
    await page.keyboard.press('Escape');
    await page.waitForTimeout(100);
    check('A1-06 Escape closes the drawer and puts the focus back on its button',
      [await shown('#catPanel'), await focusedDesc(page)], [false, '#catDrawerBtn']);

    await page.evaluate(() => switchView('connect'));
    await page.waitForTimeout(150);
    check('A5-13 the Servers list has one too', await shown('#serverCatDrawerBtn'), true);

    await page.setViewportSize({ width: 1100, height: 720 });
    await page.evaluate(() => switchView('keys'));
    await page.waitForTimeout(150);
    check('A1-06 wider than 900px the tree is in the sidebar and the button is gone',
      [await shown('#catPanel'), await shown('#catDrawerBtn')], [true, false]);
    check('no page errors', app.errors, []);
  });

  await withApp(browser, server, { settings: { autoLockMinutes: '15' } }, 'compact chrome at 880px', async (app) => {
    const { page } = app;
    await page.setViewportSize({ width: 880, height: 560 });
    await page.waitForTimeout(1100);
    const v = await page.evaluate(() => {
      const b = document.getElementById('vaultStatus');
      return {
        text: getComputedStyle(b.querySelector('.vault-text')).display,
        caret: getComputedStyle(document.getElementById('vaultCaret')).display,
        name: b.getAttribute('aria-label') || '',
        title: b.title,
      };
    });
    check('A1-19 the compact vault control shows its icon only', [v.text, v.caret], ['none', 'none']);
    yes('A1-19 its state and countdown are in its name and tooltip',
      /unlocked/i.test(v.name) && /locks in \d+:\d\d/.test(v.name) && /locks in \d+:\d\d/.test(v.title), JSON.stringify(v));
    const nk = await page.evaluate(() => {
      const b = document.getElementById('newKeyBtn');
      const before = getComputedStyle(b, '::before').content;
      return {
        pluses: b.querySelectorAll('svg').length + (before && before !== 'none' && before !== 'normal' ? 1 : 0),
        name: b.getAttribute('aria-label') || b.textContent.trim(),
      };
    });
    check('A1-19 New key shows one plus', nk.pluses, 1);
    check('A1-19 and keeps "New key" as its name', nk.name, 'New key');
  });
}

// ─── item 6: dialogs keep their buttons on screen; Enter submits (A1-22, A5-15)

async function scenarioDialogs(browser, server) {
  await withApp(browser, server, {}, 'dialogs at 880x560', async (app) => {
    const { page } = app;
    await page.setViewportSize({ width: 880, height: 560 });
    // On screen AND the top-most thing at its centre: a button scrolled out of
    // the dialog or under its edge fails either way.
    const usable = (id) => page.evaluate((i) => {
      const b = document.getElementById(i);
      const r = b.getBoundingClientRect();
      const hit = document.elementFromPoint(r.left + r.width / 2, r.top + r.height / 2);
      return r.top >= 0 && r.bottom <= window.innerHeight && !!hit && (hit === b || b.contains(hit));
    }, id);
    await page.evaluate(() => { openKeyModal(); document.getElementById('genType').value = 'rsa'; onGenTypeChange(); });
    await page.waitForTimeout(250);
    check('A1-22 New key (RSA): Create is on screen without scrolling the dialog', await usable('modalPrimary'), true);
    await page.evaluate(() => switchTab('import'));
    await page.waitForTimeout(100);
    check('A1-22 Import key: Import is on screen', await usable('modalPrimary'), true);
    check('A1-22 the dialog body scrolls, not the whole dialog', await page.evaluate(() => {
      const body = document.querySelector('#modalBackdrop .modal-body');
      return getComputedStyle(body).overflowY !== 'visible' && body.scrollHeight > body.clientHeight;
    }), true);
    await page.evaluate(() => { closeKeyModal(); openServerModal({}); setConnectAuthMethod('password'); });
    await page.waitForTimeout(250);
    check('A1-22 New server (password): Save is on screen', await usable('srvSaveBtn'), true);
    await page.evaluate(() => closeServerModal());

    await page.evaluate(() => { openKeyModal(); switchTab('generate'); });
    await page.fill('#genName', 'enter-key');
    await page.press('#genName', 'Enter');
    await page.waitForTimeout(150);
    check('A5-15 Enter in the Name field creates the key', await app.count('key_create_with_categories'), 1);
    await page.evaluate(() => { openKeyModal(); switchTab('import'); });
    await page.fill('#importPem', '-----BEGIN OPENSSH PRIVATE KEY-----');
    await page.press('#importPem', 'Enter');
    await page.waitForTimeout(100);
    check('A5-15 Enter in the pasted key is a new line, not a submit', await app.count('key_import'), 0);
    await page.fill('#importName', 'pasted');
    await page.press('#importName', 'Enter');
    await page.waitForTimeout(150);
    check('A5-15 Enter in a single-line field of the import tab imports', await app.count('key_import'), 1);
    check('no page errors', app.errors, []);
  });
}

// ─── item 7: layout and field details (A1-08 A1-18 A1-35 A1-37 A1-32 A1-33 A1-34)

const LONG_HOSTS = { hosts: [
  { host: '10.0.0.1:22', fingerprintSha256: 'SHA256:abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJK', firstSeen: '2026-09-01T10:00:00Z' },
  { host: 'db-replica-1.eu-west-1.internal.example.com:22', fingerprintSha256: 'SHA256:zyxwvutsrqponmlkjihgfedcba9876543210KJIHGFEDCBA', firstSeen: '2026-09-02T11:30:00Z' },
] };

async function scenarioDetails(browser, server) {
  const keys = KEYS4.map((k) => Object.assign({}, k, {
    comment: k.name + '-a-rather-long-comment-for-the-row@build-runner-07.internal.example.com',
    fingerprint_sha256: 'SHA256:' + k.id + 'abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJK',
  }));
  const servers = [SERVER('s1', 'a-very-long-server-name-for-production-database-replica-eu-west')];
  await withApp(browser, server, { keys, servers, replies: { known_hosts_list: LONG_HOSTS } }, 'layout at 1100x720', async (app) => {
    const { page } = app;
    await page.setViewportSize({ width: 1100, height: 720 });
    check('A1-37 the page tells the engine it is dark', await page.evaluate(() => getComputedStyle(document.documentElement).colorScheme), 'dark');

    await page.evaluate(() => { state.deploySelected = new Set(state.keys.map((k) => k.id)); renderKeyList(); updateSelectionHint(); });
    await page.waitForTimeout(100);
    check('A1-18 the selection bar keeps every action inside itself', await page.evaluate(() => {
      const bar = document.getElementById('selectionBar').getBoundingClientRect();
      return ['selCategoryBtn', 'selDeleteBtn', 'selDeployBtn', 'selClearBtn'].every((id) => {
        const r = document.getElementById(id).getBoundingClientRect();
        return r.left >= bar.left - 0.5 && r.right <= bar.right + 0.5;
      });
    }), true);

    const titles = await page.evaluate(() => {
      const sub = document.querySelector('#keyList .key-row .key-row-sub');
      const fp = document.getElementById('detailFingerprint');
      return {
        sub: sub.title === sub.textContent,
        fingerprint: fp.title === fp.textContent || getComputedStyle(fp).whiteSpace !== 'nowrap',
        fingerprintWhole: fp.scrollWidth <= fp.clientWidth + 1,
      };
    });
    check('A1-35 a key row\'s comment can be read in full (title)', titles.sub, true);
    check('A1-35 the fingerprint is shown whole: it wraps instead of ending in "..."', [titles.fingerprint, titles.fingerprintWhole], [true, true]);
    await page.evaluate(() => switchView('connect'));
    await page.waitForSelector('#serverList .server-name');
    check('A1-35 a server name can be read in full (title)', await page.evaluate(() => {
      const n = document.querySelector('#serverList .server-name');
      return n.title === n.textContent;
    }), true);
    await page.evaluate(() => openPalette());
    await page.waitForTimeout(150);
    check('A1-35 the palette\'s subtext can be read in full (title)', await page.evaluate(() => {
      const n = document.querySelector('#paletteResults .palette-sub');
      return !!n && n.title === n.textContent;
    }), true);
    await page.keyboard.press('Escape');

    await page.evaluate(() => { switchView('settings'); showSettingsSection('hosts'); });
    await page.waitForTimeout(200);
    check('A1-08 Settings is not clamped to 780px', await page.evaluate(() => getComputedStyle(document.querySelector('.settings-view')).maxWidth), 'none');
    check('A1-08 the known-hosts table fits: Forget is on screen without scrolling sideways', await page.evaluate(() => {
      const wrap = document.querySelector('[data-section="hosts"] .table-wrap');
      const forget = document.querySelector('#knownHostsBody .ghost-btn').getBoundingClientRect();
      return wrap.scrollWidth <= wrap.clientWidth + 1 && forget.right <= window.innerWidth;
    }), true);

    await page.evaluate(() => { switchView('connect'); document.getElementById('assistantPanel').hidden = false; });
    await page.focus('#assistantInput');
    await page.waitForTimeout(250); // fields fade their border over 0.12 s
    check('A1-32 the focused assistant input has the accent border',
      await page.evaluate(() => [document.activeElement.id, getComputedStyle(document.getElementById('assistantInput')).borderTopColor]),
      ['assistantInput', 'rgb(110, 168, 255)']);
    await page.evaluate(() => { document.getElementById('assistantPanel').hidden = true; switchView('settings'); });

    check('A1-33 the SFTP delete dialog\'s "don\'t ask again" is a toggle like the others', await page.evaluate(() => {
      const box = document.getElementById('deleteSkipSession');
      const label = box.closest('label');
      return [!!label && label.classList.contains('toggle-chip'), !!(label && label.querySelector('.toggle-box'))];
    }), [true, true]);
    check('no page errors', app.errors, []);
  });

  await withApp(browser, server, {}, 'field hints', async (app) => {
    const { page } = app;
    await page.evaluate(() => switchView('settings'));
    await page.waitForSelector('#bw_server_url', { state: 'attached' });
    const hints = await page.evaluate(() => {
      const plain = ['genName', 'genComment', 'importName', 'cfgHost', 'cfgUser', 'srvName', 'srvHost', 'srvUser', 'srvPemPath',
        'promptInput', 'chmodOctal', 'bw_server_url', 'bw_email', 'bw_folder_name', 'bw_servers_folder_name'];
      const secret = ['importPass', 'detailExportPass', 'keyPassphraseInput', 'bw_master_password'];
      const bad = [];
      for (const id of plain) {
        const n = document.getElementById(id);
        if (!n || n.getAttribute('spellcheck') !== 'false' || n.getAttribute('autocomplete') !== 'off') bad.push(id);
      }
      for (const id of secret) {
        const n = document.getElementById(id);
        if (!n || !['off', 'new-password'].includes(n.getAttribute('autocomplete'))) bad.push(id);
      }
      return bad;
    });
    check('A1-34 host, user, path and name fields have spellcheck and autofill off; secret fields are not autofilled', hints, []);
  });
}

// ─── item 8: ARIA patterns, labels, reduced motion, hit areas (A1-36) ────

/// A tab or radio group: roles, which item is the single tab stop, what the
/// state attribute says, and what each tab controls.
const groupState = (page, sel) => page.evaluate((s) => {
  const g = document.querySelector(s);
  const items = [...g.querySelectorAll('[role="tab"], [role="radio"]')];
  return {
    role: g.getAttribute('role'),
    tabStops: items.filter((b) => b.tabIndex === 0).map((b) => b.textContent.trim()),
    on: items.filter((b) => (b.getAttribute('aria-selected') || b.getAttribute('aria-checked')) === 'true').map((b) => b.textContent.trim()),
    controls: items.map((b) => {
      const id = b.getAttribute('aria-controls');
      const p = id && document.getElementById(id);
      return p ? p.getAttribute('role') : null;
    }),
  };
}, sel);

async function scenarioAria(browser, server) {
  await withApp(browser, server, {}, 'tabs and radios', async (app) => {
    const { page } = app;
    let g = await groupState(page, '.detail-tabs');
    check('A1-36 the detail tabs are a full tab pattern', g,
      { role: 'tablist', tabStops: ['Overview'], on: ['Overview'], controls: ['tabpanel', 'tabpanel'] });
    await page.focus('.detail-tab[data-detail-tab="overview"]');
    await page.keyboard.press('ArrowRight');
    await page.waitForTimeout(80);
    g = await groupState(page, '.detail-tabs');
    check('A1-36 ArrowRight moves to Export and shows it', [g.on, g.tabStops,
      await page.evaluate(() => document.activeElement.dataset.detailTab),
      await page.evaluate(() => !document.getElementById('detailPanel-export').hidden)], [['Export'], ['Export'], 'export', true]);

    await page.evaluate(() => openKeyModal());
    g = await groupState(page, '#modalBackdrop .tabs');
    check('A1-36 the key dialog\'s Generate/Import is a tab pattern', g,
      { role: 'tablist', tabStops: ['Generate'], on: ['Generate'], controls: ['tabpanel', 'tabpanel'] });
    await page.focus('#modalBackdrop .tab[data-tab="generate"]');
    await page.keyboard.press('ArrowRight');
    await page.waitForTimeout(80);
    check('A1-36 ArrowRight switches it to Import', (await groupState(page, '#modalBackdrop .tabs')).on, ['Import']);
    await page.evaluate(() => closeKeyModal());

    await page.evaluate(() => openServerModal({}));
    g = await groupState(page, '#serverModal .auth-method-row');
    check('A1-36 the auth method is a radio group with one tab stop', [g.role, g.tabStops, g.on], ['radiogroup', ['Key'], ['Key']]);
    await page.focus('#serverModal .seg-btn[data-auth="publickey"]');
    await page.keyboard.press('ArrowRight');
    await page.waitForTimeout(80);
    check('A1-36 ArrowRight chooses Password', [await page.evaluate(() => state.connectAuthMethod), (await groupState(page, '#serverModal .auth-method-row')).on],
      ['password', ['Password']]);
    await page.evaluate(() => closeServerModal());

    check('A1-36 the Shell/Files/Split switch names what it controls and has one tab stop', await page.evaluate(() => {
      const items = [...document.querySelectorAll('#termModeSeg .seg-btn')];
      return [items.every((b) => b.getAttribute('aria-controls') === 'sessionSurface'), items.filter((b) => b.tabIndex === 0).length];
    }), [true, 1]);
    check('no page errors', app.errors, []);
  });

  await withApp(browser, server, {}, 'palette and labels', async (app) => {
    const { page } = app;
    await page.evaluate(() => openPalette());
    await page.waitForTimeout(150);
    const ad = () => page.evaluate(() => {
      const input = document.getElementById('paletteInput');
      const id = input.getAttribute('aria-activedescendant');
      const row = id && document.getElementById(id);
      return { points: !!row && row.classList.contains('active'), expanded: input.getAttribute('aria-expanded') };
    });
    check('A1-36 the palette input points at the highlighted result', await ad(), { points: true, expanded: 'true' });
    await page.keyboard.press('ArrowDown');
    check('A1-36 and follows the arrow keys', (await ad()).points, true);
    await page.fill('#paletteInput', 'zzzz-nothing');
    await page.waitForTimeout(80);
    check('A1-36 with no results the listbox is not "expanded"', (await ad()).expanded, 'false');
    await page.keyboard.press('Escape');

    check('A1-36 every <label> labels a control', await page.evaluate(() =>
      [...document.querySelectorAll('label')].filter((l) => !l.control).map((l) => l.textContent.trim().slice(0, 30))), []);
    check('A1-36 the export passphrase has a name', await page.evaluate(() => document.getElementById('detailExportPass').labels.length > 0), true);
  });

  await withApp(browser, server, {}, 'reduced motion', async (app) => {
    const { page } = app;
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await page.evaluate(() => openKeyModal());
    check('A1-36 with reduced motion asked for, dialogs do not animate', await page.evaluate(() =>
      [getComputedStyle(document.querySelector('#modalBackdrop')).animationName, getComputedStyle(document.querySelector('#modalBackdrop .modal')).animationName]),
    ['none', 'none']);
    await page.evaluate(() => closeKeyModal());
    check('A1-36 and the pulsing status dots stand still', await page.evaluate(() => {
      const s = document.getElementById('bwStatus');
      s.classList.add('syncing');
      const name = getComputedStyle(s, '::before').animationName;
      s.classList.remove('syncing');
      return name;
    }), 'none');
  });

  await withApp(browser, server, { categories: CATS, replies: { category_list: CAT_REPLY } }, 'hit areas', async (app) => {
    const { page } = app;
    const box = (sel) => page.evaluate((s) => {
      const n = document.querySelector(s);
      if (!n) return null;
      const r = n.getBoundingClientRect();
      return Math.round(r.width) >= 24 && Math.round(r.height) >= 24;
    }, sel);
    await openLiveTab(app);
    const tabClose = await box('#termTabs .term-tab-close');
    await page.evaluate(() => switchView('keys'));
    await page.evaluate(() => { toast('Something happened.', 'info'); });
    await page.evaluate(() => openCategoryPicker({ title: 't', initial: ['c1'], onSave: () => {} }));
    await page.waitForTimeout(100);
    const sizes = {
      catActions: await box('#catTree .cat-actions-btn'),
      chevron: await box('#catTree .cat-chevron:not(.leaf)'),
      tabClose,
      chipRemove: await box('#pickerSelection .picker-chip-remove'),
      toastDismiss: await box('#toast .toast-dismiss'),
    };
    check('A1-36 the small controls are at least 24x24 px to click', sizes,
      { catActions: true, chevron: true, tabClose: true, chipRemove: true, toastDismiss: true });
  });
}

// ─── item 9: command palette (A5-17, A3-35) ──────────────────────────────

/// The palette's results for a query, in order: [group, name].
async function paletteFor(page, q) {
  await page.evaluate(() => { if (document.getElementById('paletteModal').hidden) openPalette(); });
  await page.waitForTimeout(80);
  await page.fill('#paletteInput', q);
  await page.waitForTimeout(60);
  return page.evaluate(() => {
    let group = '';
    const out = [];
    for (const n of document.querySelectorAll('#paletteResults > *')) {
      if (n.classList.contains('palette-group')) group = n.textContent;
      else if (n.classList.contains('palette-row')) out.push([group, n.querySelector('.palette-name').textContent]);
    }
    return out;
  });
}

async function scenarioPalette(browser, server) {
  const keys = ['prod-web', 'web-a', 'db-web', 'cobweb', 'deadlock-test', 'prod-deploy'].map((n, i) => KEY('k' + i, n));
  const servers = [SERVER('s1', 'web-00.eu1'), SERVER('s2', 'mail-1')];
  await withApp(browser, server, { keys, servers }, 'matching and ranking', async (app) => {
    const { page } = app;
    const names = (rows) => rows.map((r) => r[1]);
    check('A5-17 "prod web" finds prod-web: every word must match, "-" separates words',
      names(await paletteFor(page, 'prod web')).includes('prod-web'), true);
    check('A5-17 "eu1 web" finds web-00.eu1: "." separates words too',
      names(await paletteFor(page, 'eu1 web')).includes('web-00.eu1'), true);
    check('A5-17 every word must match: "prod mail" finds nothing', await paletteFor(page, 'prod mail'), []);
    check('A5-17 a name starting with the word ranks above a word inside it, above a plain substring',
      (await paletteFor(page, 'web')).filter((r) => r[0] === 'Keys').map((r) => r[1]), ['web-a', 'prod-web', 'db-web', 'cobweb']);
    check('A5-17 an action the query names exactly comes first ("lock")', (await paletteFor(page, 'lock'))[0], ['Actions', 'Lock the vault']);
    check('A5-17 ... and "deploy"', ((await paletteFor(page, 'deploy'))[0] || [])[0], 'Actions');
    const reach = {};
    for (const q of ['known hosts', 'backup', 'bitwarden', 'password', 'update', 'audit', 'assistant']) {
      reach[q] = (await paletteFor(page, q)).filter((r) => r[0] === 'Actions').map((r) => r[1]);
    }
    check('A5-17 every Settings section and the vault/update actions can be found', reach, {
      'known hosts': ['Settings: Known hosts'],
      backup: ['Settings: Backup & restore'],
      bitwarden: ['Settings: Bitwarden sync'],
      password: ['Change master password...', 'Settings: Vault & password'],
      update: ['Check for updates'],
      audit: ['Settings: Audit log'],
      assistant: ['Settings: AI assistant'],
    });
    await paletteFor(page, 'known hosts');
    await page.keyboard.press('Enter');
    await page.waitForTimeout(150);
    check('A5-17 running a Settings entry opens that section', await page.evaluate(() =>
      [state.view, !document.querySelector('.settings-section[data-section="hosts"]').hidden]), ['settings', true]);
    await paletteFor(page, 'zzzz');
    const empty = await page.textContent('#paletteResults');
    yes('A5-17 no results says what to try next', /nothing matches/i.test(empty) && /try/i.test(empty), empty);
    await page.keyboard.press('Escape');
    check('no page errors', app.errors, []);
  });

  await withApp(browser, server, {}, 'switch to session', async (app) => {
    const { page } = app;
    // Two tabs on web-1: the first one's session ended, the second is live.
    const dead = await openLiveTab(app);
    await page.evaluate((s) => openSessionTab(s), SERVER('s1', 'web-1'));
    await page.waitForFunction(() => [...state.sessions.keys()].filter((id) => window.tabSessionLive(id)).length === 2, null, { polling: 25 });
    const live = await page.evaluate(() => [...state.sessions.keys()][1]);
    await page.evaluate((t) => { window.setTabSession(t, null); state.sessions.get(t).ended = true; activateSessionTab(t); }, dead);
    const row = (await paletteFor(page, 'web-1')).findIndex((r) => r[1] === 'web-1');
    await page.evaluate((i) => runPaletteItem(i, false), row);
    await page.waitForTimeout(150);
    check('A3-35 "Switch to session" lands on the LIVE tab, not the first one', await page.evaluate(() => state.activeTabId), live);
    await page.evaluate((t) => { window.setTabSession(t, null); state.sessions.get(t).ended = true; }, live);
    const before = await app.count('terminal_connect');
    const row2 = (await paletteFor(page, 'web-1')).findIndex((r) => r[1] === 'web-1');
    await page.evaluate((i) => runPaletteItem(i, false), row2);
    await page.waitForTimeout(200);
    check('A3-35 with no live session it connects (a new session), instead of focusing a dead tab',
      (await app.count('terminal_connect')) - before, 1);
    check('no page errors', app.errors, []);
  });
}

// ─── item 10: audit log filters and paging (A5-16) ────────────────────────

async function scenarioAudit(browser, server) {
  await withApp(browser, server, {}, 'audit log', async (app) => {
    const { page } = app;
    // 350 rows, newest first; the stub honours the limit like the backend.
    await page.evaluate(() => {
      const all = [];
      for (let i = 0; i < 350; i++) {
        const ev = i % 3 === 0 ? 'key.created' : (i % 3 === 1 ? 'key.deployed' : 'vault.unlock');
        all.push({ ts: new Date(Date.UTC(2026, 8, 1, 0, 0, 350 - i)).toISOString(), event: ev, keyId: 'k' + i, detail: 'row ' + i + (i === 7 ? ' to /srv/deploy-target' : '') });
      }
      window.__replies.audit_list = (a) => ({ rows: all.slice(0, a.limit || 200), total: all.length });
    });
    await page.evaluate(() => { switchView('settings'); showSettingsSection('audit'); });
    await page.waitForSelector('#auditBody tr');
    const shown = () => page.evaluate(() => [...document.querySelectorAll('#auditBody tr')].filter((r) => r.querySelector('td.ev')).length);
    check('A5-16 the newest 200 are shown first', await shown(), 200);
    check('A5-16 there is an event-type filter, listing the events loaded',
      await page.evaluate(() => [...document.querySelectorAll('#auditEventFilter option')].map((o) => o.value)), ['', 'key.created', 'key.deployed', 'vault.unlock']);
    await page.selectOption('#auditEventFilter', 'key.deployed');
    await page.waitForTimeout(60);
    check('A5-16 choosing an event narrows the table to it', await page.evaluate(() =>
      [...new Set([...document.querySelectorAll('#auditBody td.ev')].map((td) => td.textContent))]), ['key.deployed']);
    await page.selectOption('#auditEventFilter', '');
    await page.fill('#auditTextFilter', 'deploy-target');
    await page.waitForTimeout(60);
    check('A5-16 the text filter narrows it to matching rows', await page.evaluate(() =>
      [...document.querySelectorAll('#auditBody tr')].map((r) => r.textContent).filter((t) => /row 7 /.test(t)).length), 1);
    check('A5-16 ... and only those', await shown(), 1);
    check('A5-16 without sending anything', (await app.calls('audit_list')).length, 1);
    await page.fill('#auditTextFilter', '');
    check('A5-16 "Load older" is offered while older entries exist', await page.isVisible('#auditMoreBtn'), true);
    await page.click('#auditMoreBtn');
    await page.waitForTimeout(150);
    check('A5-16 it asks for more rows (the limit goes up)', (await app.calls('audit_list')).map((c) => c.args.limit), [200, 400]);
    check('A5-16 and shows them all once they are loaded', [await shown(), await page.isVisible('#auditMoreBtn')], [350, false]);
    check('no page errors', app.errors, []);
  });

  await withApp(browser, server, { replies: { audit_list: { $reject: 'Database is busy.' } } }, 'audit log fails to load', async (app) => {
    const { page } = app;
    await page.evaluate(() => { switchView('settings'); showSettingsSection('audit'); });
    await page.waitForTimeout(150);
    const err = await page.evaluate(() => {
      const row = document.querySelector('#auditBody .audit-error');
      return row ? { text: row.textContent, retry: !!row.querySelector('button') } : null;
    });
    yes('A5-16 a failed load says so in the table, with the reason', err && err.text.includes('Database is busy.'), JSON.stringify(err));
    yes('A5-16 with a Retry', err && err.retry);
    await page.evaluate(() => {
      window.__replies.audit_list = { rows: [{ ts: '2026-01-01T00:00:00Z', event: 'vault.unlock', keyId: null, detail: '' }], total: 1 };
    });
    await page.click('#auditBody .audit-error button');
    await page.waitForTimeout(150);
    check('A5-16 Retry loads the log', await page.evaluate(() => [...document.querySelectorAll('#auditBody td.ev')].map((td) => td.textContent)), ['vault.unlock']);
  });
}

// ─── item 11: breadcrumb, terms, shortcuts, show/hide (A2-17 A5-31 A8-18 A5-35)

async function scenarioChrome(browser, server) {
  const hostCat = { id: 'h1', name: 'Production hosts', parent_id: null, scope: 'host', sort_index: 0, color: null };
  const cats = [CATEGORY, hostCat];
  const servers = [Object.assign(SERVER('s1', 'web-1'), { categoryId: 'h1' })];
  await withApp(browser, server, { categories: cats, servers, replies: { category_list: { categories: cats, allKeyCategories: { k1: ['c1'] }, orphans: true, hostOrphans: false } } },
    'breadcrumb and terms', async (app) => {
      const { page } = app;
      const crumb = () => page.evaluate(() => {
        const b = document.getElementById('breadcrumb');
        return b.hidden ? null : [...b.querySelectorAll('a, .crumb-current')].map((n) => n.textContent);
      });
      await page.evaluate(() => setActiveCategory('c1'));
      check('the breadcrumb shows the Keys filter', await crumb(), ['Keys', 'Prod']);
      await page.evaluate(() => switchView('settings'));
      check('A2-17 Settings does not keep the Keys breadcrumb', await crumb(), null);
      await page.evaluate(() => switchView('connect'));
      check('A2-17 nor does Servers, which has no filter of its own yet', await crumb(), null);
      await page.evaluate(() => setActiveCategory('h1'));
      check('A5-31 the Servers breadcrumb starts at "Servers"', await crumb(), ['Servers', 'Production hosts']);
      check('A5-31 the tree there is titled "Server categories"', await page.textContent('#catPanelTitle'), 'Server categories');
      await page.evaluate(() => openServerModal({}));
      check('A5-31 the auth choice says Keyboard-interactive', await page.evaluate(() =>
        document.querySelector('#serverModal .seg-btn[data-auth="keyboard-interactive"]').textContent.trim()), 'Keyboard-interactive');
      await page.evaluate(() => closeServerModal());
      await page.keyboard.press('Control+l');
      await page.waitForTimeout(150);
      await page.click('#vaultCancelBtn');
      check('A5-31 the locked Servers nav item says what to do', await attr(page, '.nav-item[data-view="connect"]', 'title'), 'Unlock the vault to use Servers');
      check('no page errors', app.errors, []);
    });

  await withApp(browser, server, {}, 'Ctrl+Shift+digit', async (app) => {
    const { page } = app;
    await page.evaluate(() => {
      switchView('connect');
      state.activeTabId = 'any';
      window.__modes = [];
      window.setSessionMode = (m) => { window.__modes.push(m); };
      // What a real keyboard sends for Ctrl+Shift+1/2/3 on a US layout: Shift
      // turns the key into ! @ #, the physical key is still Digit1/2/3.
      for (const [key, code] of [['!', 'Digit1'], ['@', 'Digit2'], ['#', 'Digit3']]) {
        document.body.dispatchEvent(new KeyboardEvent('keydown', { key, code, ctrlKey: true, shiftKey: true, bubbles: true, cancelable: true }));
      }
    });
    check('A8-18 Ctrl+Shift+1/2/3 switch Shell/Files/Split by the physical key', await page.evaluate(() => window.__modes), ['ssh', 'sftp', 'split']);
  });

  await withApp(browser, server, {}, 'show and hide passwords', async (app) => {
    const { page } = app;
    await page.evaluate(() => switchView('settings'));
    await page.waitForSelector('#bw_master_password', { state: 'attached' });
    check('A5-35 every password field has a show/hide button', await page.evaluate(() =>
      [...document.querySelectorAll('input[type="password"]')].filter((i) => {
        const b = i.parentElement && i.parentElement.querySelector('.reveal-btn');
        return !b || b.getAttribute('aria-controls') !== i.id;
      }).map((i) => i.id)), []);
    await page.evaluate(() => switchView('keys'));
    await page.evaluate(() => requestVaultModal('change'));
    await page.fill('#vaultPassword', 'new-password-2');
    const btn = '#vaultModal .reveal-btn[aria-controls="vaultPassword"]';
    await page.click(btn);
    check('A5-35 it shows what was typed', [await attr(page, '#vaultPassword', 'type'), await attr(page, btn, 'aria-pressed')], ['text', 'true']);
    await page.click(btn);
    check('A5-35 and hides it again', await attr(page, '#vaultPassword', 'type'), 'password');
    await page.click(btn);
    await page.click('#vaultCancelBtn');
    await page.evaluate(() => requestVaultModal('change'));
    check('A5-35 a shown field is hidden again when its dialog closes (never kept)',
      [await attr(page, '#vaultPassword', 'type'), await attr(page, btn, 'aria-pressed')], ['password', 'false']);
    await page.evaluate(() => hideVaultModal());
    await page.evaluate(() => { openServerModal({}); setConnectAuthMethod('password'); });
    await page.fill('#srvPassword', 'server-pass');
    await page.click('#serverModal .reveal-btn[aria-controls="srvPassword"]');
    await page.keyboard.press('Control+l');
    await page.waitForTimeout(150);
    check('A5-35 a shown password is hidden and wiped by a lock',
      await page.evaluate(() => [document.getElementById('srvPassword').type, document.getElementById('srvPassword').value]), ['password', '']);
    check('no page errors', app.errors, []);
  });
}

// ─── review round 1 ───────────────────────────────────────────────────────

/// The accessible name the browser computes for one element, from its ARIA
/// snapshot ("- textbox "Name"").
async function axName(page, sel, role) {
  const snap = await page.locator(sel).ariaSnapshot();
  const m = snap.match(new RegExp(role + ' "([^"]*)"'));
  return m ? m[1] : snap;
}

/// fix1-1: a show/hide button inside a field's wrapping <label> must not end
/// up in the field's name ("Password ... Show password").
async function scenarioFieldNames(browser, server) {
  await withApp(browser, server, {}, 'password field names', async (app) => {
    const { page } = app;
    const names = {};
    await page.evaluate(() => { openServerModal({}); setConnectAuthMethod('password'); });
    names.srvPassword = await axName(page, '#srvPassword', 'textbox');
    await page.evaluate(() => { closeServerModal(); openKeyModal(); switchTab('import'); });
    names.importPass = await axName(page, '#importPass', 'textbox');
    await page.evaluate(() => { closeKeyModal(); switchView('settings'); showSettingsSection('assistant'); });
    names.aiApiKey = await axName(page, '#aiApiKey', 'textbox');
    await page.evaluate(() => {
      document.getElementById('mcpFormHost').hidden = false;
      document.getElementById('mcpSecretRow').hidden = false;
    });
    names.mcpAuthSecret = await axName(page, '#mcpAuthSecret', 'textbox');
    await page.evaluate(() => showSettingsSection('sync'));
    names.bwMasterPassword = await axName(page, '#bw_master_password', 'textbox');
    // Captions as JU5 left them: the server password's is no longer the untrue
    // "only used at connect time" (unsaved, a typed password was dropped), and
    // "Master password" is sentence case (A8-25).
    check('fix1-1 each password field is named by its caption alone, not "... Show password"', names, {
      srvPassword: 'Password (optional)',
      importPass: 'Passphrase (only if the pasted key is encrypted)',
      aiApiKey: 'API key',
      mcpAuthSecret: 'Secret',
      bwMasterPassword: 'Master password',
    });
    check('fix1-1 the eye button keeps its own name', await axName(page, '#bwGrid .reveal-btn', 'button'), 'Show password');
    await page.click('#bwGrid .reveal-btn');
    check('fix1-1 and showing the password changes the button\'s name only',
      [await axName(page, '#bw_master_password', 'textbox'), await axName(page, '#bwGrid .reveal-btn', 'button')],
      ['Master password', 'Hide password']);
    check('no page errors', app.errors, []);
  });
}

/// fix1-2/3: the category drawer closes when focus leaves it, and its button
/// does nothing - and says why - when there is no tree to show.
async function scenarioDrawerFocus(browser, server) {
  await withApp(browser, server, { categories: CATS, replies: { category_list: CAT_REPLY } }, 'drawer and focus', async (app) => {
    const { page } = app;
    await page.setViewportSize({ width: 880, height: 560 });
    await page.waitForTimeout(150);
    await page.click('#catDrawerBtn');
    await page.waitForTimeout(100);
    await page.hover('#catTree .cat-node[data-id="c1"]');
    await page.click('#catTree .cat-node[data-id="c1"] .cat-actions-btn');
    await page.waitForTimeout(80);
    check('fix1-2 a menu opened from the drawer keeps it open', await page.evaluate(() => catDrawerOpen()), true);
    await page.keyboard.press('Escape');
    await page.focus('#searchInput');
    await page.waitForTimeout(80);
    check('fix1-2 focus moving out of the drawer closes it (nothing focused hides under it)',
      [await page.evaluate(() => catDrawerOpen()), await attr(page, '#catDrawerBtn', 'aria-expanded')], [false, 'false']);
    check('no page errors', app.errors, []);
  });

  const empty = { keys: [], categories: [], replies: { category_list: { categories: [], allKeyCategories: {}, orphans: false, hostOrphans: false } } };
  await withApp(browser, server, empty, 'drawer with nothing to show', async (app) => {
    const { page } = app;
    await page.setViewportSize({ width: 880, height: 560 });
    await page.waitForTimeout(150);
    const btn = await page.evaluate(() => {
      const b = document.getElementById('catDrawerBtn');
      return { disabled: b.disabled, title: b.title };
    });
    check('fix1-3 with no categories and nothing to file, the Categories button is disabled', btn.disabled, true);
    yes('fix1-3 and says why', /no categor/i.test(btn.title), btn.title);
    await page.evaluate(() => setCatDrawer(true));
    check('fix1-3 and the drawer cannot be opened empty',
      [await page.evaluate(() => catDrawerOpen()), await attr(page, '#catDrawerBtn', 'aria-expanded')], [false, 'false']);
  });
}

/// fix1-6: focus comes back to the terminal from its menu, and Enter on a
/// control inside a row does that control's job only.
async function scenarioNestedKeys(browser, server) {
  await withApp(browser, server, {}, 'terminal menu focus', async (app) => {
    const { page } = app;
    const tab = await openLiveTab(app);
    // terminal.js focuses a new tab's terminal a few tens of ms after it
    // connects (terminalFocus); let that land before the menu opens.
    await page.waitForTimeout(400);
    const inTerminal = () => page.evaluate(() => !!document.activeElement && document.activeElement.classList.contains('xterm-helper-textarea'));
    await page.evaluate((t) => window.tabRecord(t).term.focus(), tab);
    check('the terminal has the focus', await inTerminal(), true);
    await page.evaluate((t) => openTerminalContextMenu(300, 300, t), tab);
    await page.waitForTimeout(60);
    // The menu really took the focus, so the next check is not met trivially.
    check('fix1-6 the open terminal menu has the focus', ((await menuState(page)) || {}).focused, 0);
    await page.keyboard.press('Escape');
    await page.waitForTimeout(60);
    check('fix1-6 Escape on the terminal menu gives the focus back to the terminal', await inTerminal(), true);
    await page.evaluate((t) => openTerminalContextMenu(300, 300, t), tab);
    await page.waitForTimeout(60);
    await page.click('#keyConnectMenu .ctx-item:has-text("Clear scrollback")');
    await page.waitForTimeout(60);
    check('fix1-6 and so does choosing one of its items', await inTerminal(), true);
    check('no page errors', app.errors, []);
  });

  await withApp(browser, server, { categories: CATS, replies: { category_list: CAT_REPLY } }, 'nested controls', async (app) => {
    const { page } = app;
    await page.evaluate(() => {
      window.__selects = 0;
      const orig = window.selectKey;
      window.selectKey = (id) => { window.__selects += 1; return orig(id); };
    });
    await page.focus('#keyList .key-row[data-id="k2"] .row-btn');
    await page.keyboard.press('Enter');
    await page.waitForTimeout(120);
    check('fix1-6 Enter on a row\'s Connect button runs Connect (its menu opens), not the row\'s Enter as well',
      [await page.evaluate(() => window.__selects), !!(await menuState(page))], [1, true]);
    await page.keyboard.press('Escape');

    await page.focus('#catTree .cat-node[data-id="c1"] .cat-chevron');
    await page.keyboard.press('Enter');
    await page.waitForTimeout(100);
    check('fix1-6 Enter on a category chevron expands it without also filtering by the category',
      await page.evaluate(() => [state.expandedCatIds.has('c1'), activeCategoryId()]), [true, 'all']);

    await openLiveTab(app);
    await page.evaluate((s) => openSessionTab(s), SERVER('s1', 'web-1'));
    await page.waitForFunction(() => [...state.sessions.keys()].filter((id) => window.tabSessionLive(id)).length === 2, null, { polling: 25 });
    const [first, second] = await page.evaluate(() => [...state.sessions.keys()]);
    await page.evaluate((t) => activateSessionTab(t), second);
    // activateSessionTab focuses that terminal 60 ms later - unless, as here,
    // the user has reached another control by then (JU5): no barrier needed.
    await page.focus(`#termTabs .term-tab[data-tab-id="${first}"] .term-tab-close`);
    await page.keyboard.press('Enter');
    await page.waitForTimeout(100);
    check('fix1-6 Enter on a tab\'s close button asks to close that session, without switching to it first',
      [await app.open('confirmModal'), await page.evaluate(() => state.activeTabId)], [true, second]);
    await page.click('#confirmCancelBtn');
    check('no page errors', app.errors, []);
  });
}

// ─── item 14: JU2 review leftovers ────────────────────────────────────────

/// (c) A control disabled for two reasons at once - the vault lock and a run
/// in progress - is re-enabled only when both are gone.
async function scenarioDisabledReasons(browser, server) {
  await withApp(browser, server, { settings: { autoLockMinutes: '0' } }, 'lock gate and busy', async (app) => {
    const { page } = app;
    const disabled = () => page.evaluate(() => document.getElementById('auditClearBtn').disabled);
    await page.evaluate(() => {
      window.__busy = withBusy(document.getElementById('auditClearBtn'), 'Working…',
        () => new Promise((r) => { window.__release = r; }));
    });
    await page.evaluate(() => applyLockGates()); // what every status refresh does
    check('JU2-c a status refresh does not re-enable a gated button that is still busy', await disabled(), true);
    await page.evaluate(() => { state.unlocked = false; applyLockGates(); window.__release(); return window.__busy; });
    check('JU2-c the end of the work does not re-enable a button the vault lock disabled meanwhile', await disabled(), true);
    await page.evaluate(() => { state.unlocked = true; applyLockGates(); });
    check('JU2-c unlocked and idle, it works again', await disabled(), false);
    check('JU2-c a button disabled for a reason of its own stays disabled across a lock and an unlock', await page.evaluate(() => {
      const b = document.createElement('button');
      b.disabled = true;
      document.body.appendChild(b);
      lockGate(b, 'audit');
      state.unlocked = false; applyLockGates();
      state.unlocked = true; applyLockGates();
      const out = b.disabled;
      b.remove();
      return out;
    }), true);
    check('no page errors', app.errors, []);
  });
}

// ─── runner ─────────────────────────────────────────────────────────────────

const SCENARIOS = [
  ['item 1: labels - one click, one write; captions forward nothing', scenarioLabels],
  ['item 2: menus - shared helper, keyboard, Escape, on screen, icons', scenarioMenus],
  ['item 3: keyboard - focus ring, key rows, category rows, session tabs', scenarioKeyboard],
  ['item 4: contrast - faint text, selected segment, YOLO badge', scenarioContrast],
  ['item 5: narrow window - category drawer, vault chip, New key', scenarioNarrow],
  ['item 6: dialogs - buttons stay on screen, Enter submits the key dialog', scenarioDialogs],
  ['item 7: details - settings width, selection bar, full text, dark widgets, field hints', scenarioDetails],
  ['item 8: aria - tabs, radios, palette listbox, labels, reduced motion, hit areas', scenarioAria],
  ['item 9: palette - every word matches, ranked, more destinations, live sessions', scenarioPalette],
  ['item 10: audit log - event and text filters, load older, error row with Retry', scenarioAudit],
  ['item 11: chrome - breadcrumb per view, Servers terms, Ctrl+Shift+digit, show/hide passwords', scenarioChrome],
  ['item 14: leftovers - a lock-gated control that is also busy', scenarioDisabledReasons],
  ['fix1: password field names stay their captions', scenarioFieldNames],
  ['fix1: category drawer - focus leaving closes it, nothing to show disables it', scenarioDrawerFocus],
  ['fix1: terminal menu focus, nested controls in rows', scenarioNestedKeys],
];

function runStatic() {
  console.log('static checks');
  for (const [title, fn] of STATIC) {
    try { fn(); } catch (e) { check(title + ' (threw: ' + String(e.message || e).split('\n')[0] + ')', false, true); }
  }
}

const read = (rel) => fs.readFileSync(path.join(RENDERER, rel), 'utf8');
/// styles.css with comments blanked, so prose cannot satisfy a selector check.
const cssCode = () => read('styles.css').replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, ' '));

const STATIC = [
  ['A1-06 the false "keeps its own filter button" comment and the dead .cat-filter-btn rules are gone', () => {
    const css = read('styles.css');
    check('A1-06 the false "keeps its own filter button" comment and the dead .cat-filter-btn rules are gone',
      { comment: /keeps its own "All categories" filter button/.test(css), rules: /\.cat-filter-btn|#catFilterLabel/.test(cssCode()) },
      { comment: false, rules: false });
  }],
  ['A1-29 dead selectors', () => {
    const css = cssCode();
    const dead = ['.sep', '.badge.ghost', '.export-row', '.config-view', '.deploy-options', '.config-actions',
      '.setting-row', '.setting-name', '.setting-desc', '.audit-view', '.settings-view > h2', '.partial', '.dimmed',
      '.sftp-upload-row', '.cat-menu'];
    const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/ /g, '\\s*');
    check('A1-29 the dead selectors the audit listed are gone',
      dead.filter((d) => new RegExp(esc(d) + '(?![\\w-])').test(css)), []);
  }],
  ['A1-29 shadowed duplicates', () => {
    const css = cssCode();
    const rules = (sel) => [...css.matchAll(new RegExp('(^|[}\\s])' + sel.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\s*\\{([^}]*)\\}', 'g'))].map((m) => m[2]);
    check('A1-29 each overridden first copy is gone (html height, .nav flex, .ctx-sep, .vault-status gap, server search)', {
      html: rules('html').length,
      navFlex: rules('.nav').filter((b) => /(^|;|\s)flex\s*:/.test(b)).length,
      ctxSep: rules('.ctx-sep').length,
      vaultGap: rules('.vault-status').filter((b) => /gap\s*:/.test(b)).length,
      serverSearch: rules('.server-list-head .search-wrap').length,
    }, { html: 0, navFlex: 1, ctxSep: 1, vaultGap: 1, serverSearch: 1 });
  }],
  ['A1-29 one monospace stack', () => {
    const lines = cssCode().split('\n').filter((l) => /JetBrains Mono|Menlo/.test(l) && !/^\s*--mono\s*:/.test(l));
    check('A1-29 monospace text uses var(--mono), not its own font stack', lines.map((l) => l.trim()), []);
  }],
  ['A1-29 no per-component [hidden] rules', () => {
    const own = [...cssCode().matchAll(/([.#][\w-]+(?:\s+[.#][\w-]+)*)\[hidden\]\s*\{[^}]*display\s*:\s*none/g)].map((m) => m[1]);
    check('A1-29 [hidden] is handled once, globally', own, []);
  }],
  ['A8-24 / A2-34 dead renderer code', () => {
    const app = read('app.js');
    const assistant = read('assistant.js');
    check('A8-24 / A2-34 the dead helpers, the no-op initTerminal call and the garbled comment are gone', {
      categoryIdsForScope: /function categoryIdsForScope\b/.test(app),
      keysInCategory: /function keysInCategory\(/.test(app),
      loadBitwardenSync: /loadBitwardenSync/.test(app),
      initTerminalCall: /\binitTerminal\(\)/.test(app),
      garbledComment: /context menus\/\/ ─/.test(app),
      AI_LEVEL_ORDER: /AI_LEVEL_ORDER/.test(assistant),
    }, { categoryIdsForScope: false, keysInCategory: false, loadBitwardenSync: false, initTerminalCall: false, garbledComment: false, AI_LEVEL_ORDER: false });
  }],
  ['JU2-e restore calls pass literal objects', () => {
    const app = read('app.js');
    const sites = [...app.matchAll(/call\('vault_backup_restore_from_file',\s*([^)]*)\)/g)].map((m) => m[1].trim());
    check('JU2-e every restore call passes an object literal, so check-ipc-args sees path and backupPassword',
      { literal: sites.length > 0 && sites.every((a) => a.startsWith('{')), keys: sites.some((a) => /\bpath\b/.test(a) && /\bbackupPassword\b/.test(a)) },
      { literal: true, keys: true });
  }],
  ['JU2-g boot and restore apply settings through one helper', () => {
    const app = read('app.js');
    const main = app.slice(app.indexOf('(async function main()'));
    const reload = app.slice(app.indexOf('async function reloadAfterRestore'), app.indexOf('// ─── known hosts'));
    check('JU2-g boot and restore put stored settings into effect through the same helper',
      [/applyStoredSettings\(/.test(main), /applyStoredSettings\(/.test(reload)], [true, true]);
  }],
  ['A8-17 CI checks cover assistant.js and mcp.js', () => {
    const run = (script) => {
      try {
        return { code: 0, out: execFileSync(process.execPath, [path.join(ROOT, 'scripts', script)], { encoding: 'utf8', stdio: 'pipe' }) };
      } catch (e) {
        return { code: e.status, out: String(e.stdout || '') + String(e.stderr || '') };
      }
    };
    const globals = run('check-renderer-globals.js');
    check('A8-17 the globals check reads all six renderer scripts', [globals.code, (globals.out.match(/Checked (\d+) renderer scripts/) || [])[1]], [0, '6']);
    const globalsSrc = fs.readFileSync(path.join(ROOT, 'scripts', 'check-renderer-globals.js'), 'utf8');
    check('A8-17 and treats ai*, mcp* and assistant* names as the project\'s own',
      ['ai', 'mcp', 'assistant'].every((p) => new RegExp('OWNED = /\\^\\([^)]*\\b' + p + '\\b').test(globalsSrc)), true);
    const ipc = run('check-ipc-args.js');
    const sites = Number((ipc.out.match(/Checked (\d+) call sites/) || [])[1] || 0);
    check('A8-17 the IPC check counts the assistant\'s aiCall sites too, and passes', [ipc.code, sites >= 133], [0, true]);
  }],
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
    console.error(`\n${failures.length} UI polish check(s) failed.`);
    process.exit(1);
  }
  console.log('\nAll UI polish checks passed.');
})().catch((e) => { console.error(e); process.exit(1); });
