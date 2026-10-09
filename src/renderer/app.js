/**
 * app.js - SSHSpan renderer controller (Tauri v2).
 * ---------------------------------------------------------------------------
 * Plain DOM + Tauri's invoke(). No Node, no require, no framework.
 * Every IPC call goes through invoke() which returns the Rust Result<T, String>.
 * Private key material enters this process on one path only: the explicit
 * key import, where the user pastes a key or picks a key file for it (see
 * docs/SECURITY.md). Private-key exports and vault backups are written to
 * disk by Rust behind its own save dialogs, a restore reads its file in Rust,
 * and the server form's .pem browse returns a path without reading the file.
 * ---------------------------------------------------------------------------
 */

'use strict';

// ─── Tauri IPC bridge ─────────────────────────────────────────────────────
// The Rust commands return Result<T, String>; invoke() resolves the Ok
// value directly (no { ok, data } wrapper).  We build a thin shim so the
// rest of the code can stay nearly identical to the Electron version.

const { invoke } = window.__TAURI__.core;
const { listen }   = window.__TAURI__.event;

/** Call a Tauri command, throw on error. */
async function call(cmd, args) {
  return await invoke(cmd, args ?? {});
}

// ─── tiny helpers ──────────────────────────────────────────────────────────

function el(id) { return document.getElementById(id); }

/// Boolean settings read. The backend's collect_settings returns every
/// value as a JSON string, so a stored false arrives as "false" - and the
/// strict comparisons this replaces ("!== false") never matched it, which
/// made the confirm-before-delete and update-check toggles impossible to
/// turn off. On means true, "true", "1", or unset; off means false, "false",
/// "0". Everything else is truthy-preserving.
function settingOn(v) {
  return v !== false && v !== 'false' && v !== '0' && v !== 0;
}

// Toasts stack instead of overwriting one another. A batch operation that
// reports several failures used to show only the last one, because a single
// #toast element had its text replaced each time.
//
// SECURITY: toast text routinely carries remote-controlled strings - SFTP
// error messages, server names, filenames from a listing. It is built with
// textContent and never innerHTML, so markup in any of them can never render.
const TOAST_TTL_MS = { err: 9000, warn: 6000, ok: 3800, info: 3800 };
const TOAST_MAX = 4;

function toast(msg, kind) {
  const host = el('toast');
  if (!host) return;
  kind = kind || 'info';
  // The same message again while it is still on screen - a load failing on
  // every poll, a batch failing the same way N times - counts on that toast
  // instead of stacking copies that push everything else out (A5-21).
  const same = [...host.children].find((n) => !n._done && n._kind === kind && n._text === String(msg));
  if (same) { same._repeat(); return; }
  const item = document.createElement('div');
  item.className = 'toast-item ' + kind;
  item._kind = kind;
  item._text = String(msg);
  item._count = 1;
  // role=alert for errors so a screen reader interrupts; status for the rest.
  item.setAttribute('role', kind === 'err' ? 'alert' : 'status');

  const text = document.createElement('span');
  text.className = 'toast-text';
  text.textContent = msg;           // never innerHTML - see SECURITY above
  item.appendChild(text);

  const dismiss = document.createElement('button');
  dismiss.className = 'toast-dismiss';
  dismiss.type = 'button';
  dismiss.title = 'Dismiss';
  dismiss.setAttribute('aria-label', 'Dismiss notification');
  dismiss.textContent = '×';
  item.appendChild(dismiss);

  const remove = () => {
    if (item._done) return;
    item._done = true;
    clearTimeout(item._timer);
    item.classList.add('leaving');
    setTimeout(() => item.remove(), 180);
  };
  dismiss.addEventListener('click', remove);
  // Errors linger longer than confirmations - they are the ones worth reading.
  const ttl = TOAST_TTL_MS[kind] || TOAST_TTL_MS.info;
  item._timer = setTimeout(remove, ttl);
  // Arrived again: show how many times, give it a fresh lifetime, and make it
  // the newest - it is the message being reacted to.
  item._repeat = () => {
    item._count += 1;
    let badge = item.querySelector('.toast-count');
    if (!badge) {
      badge = document.createElement('span');
      badge.className = 'toast-count';
      item.insertBefore(badge, dismiss);
    }
    badge.textContent = '×' + item._count;
    clearTimeout(item._timer);
    item._timer = setTimeout(remove, ttl);
    host.appendChild(item);
  };

  host.appendChild(item);
  // Cap the stack so a failing batch cannot bury the whole window; the oldest
  // goes first, since the newest message is the one being reacted to.
  while (host.children.length > TOAST_MAX) host.firstElementChild.remove();
}

/// Run `fn` while `button` shows that it is working: disabled, aria-busy,
/// relabelled when a label is given. A second click - or a second call -
/// while it runs is ignored instead of starting the work again (A2-18). The
/// button's own content and state come back afterwards.
async function withBusy(button, busyLabel, fn) {
  if (!button) return fn();
  if (button.getAttribute('aria-busy') === 'true') return undefined;
  const content = [...button.childNodes];
  button.setAttribute('aria-busy', 'true');
  setDisabledFor(button, 'busy', true);
  if (busyLabel) button.textContent = busyLabel;
  try {
    return await fn();
  } finally {
    button.removeAttribute('aria-busy');
    if (busyLabel) button.replaceChildren(...content);
    setDisabledFor(button, 'busy', false);
  }
}

/// A control can be disabled for more than one reason at once - the vault is
/// locked (lockGate) and its action is running (withBusy) - and each reason is
/// lifted on its own schedule. Each is recorded on the control
/// (data-disabled-for), the control is disabled while any is set, and it gets
/// back the state it had before the first: a status refresh no longer
/// re-enables a button that is still running, nor does the end of a run
/// re-enable one the lock disabled meanwhile.
function setDisabledFor(control, reason, on) {
  const reasons = new Set((control.dataset.disabledFor || '').split(' ').filter(Boolean));
  if (on && !reasons.size) control.dataset.disabledBase = control.disabled ? '1' : '';
  if (on) reasons.add(reason); else reasons.delete(reason);
  if (reasons.size) {
    control.dataset.disabledFor = [...reasons].join(' ');
    control.disabled = true;
  } else if (control.dataset.disabledFor !== undefined) {
    control.disabled = control.dataset.disabledBase === '1';
    delete control.dataset.disabledFor;
    delete control.dataset.disabledBase;
  }
}

/// A list that could not be loaded says so where the list would be - the
/// backend's own message and a Retry - instead of the first-run empty state,
/// which read as "your keys are gone" and invited re-creating them (A5-21).
/// Everything dynamic goes in through textContent.
function renderLoadError(host, title, message, retry) {
  const card = document.createElement('div');
  card.className = 'empty-state load-error';
  card.setAttribute('role', 'alert');
  const icon = document.createElement('div');
  icon.className = 'empty-ico';
  icon.innerHTML = ico('triangle-alert');
  const heading = document.createElement('h3');
  heading.textContent = title;
  const text = document.createElement('p');
  text.className = 'load-error-msg';
  text.textContent = message;
  const again = document.createElement('button');
  again.type = 'button';
  again.className = 'ghost-btn';
  again.innerHTML = `${ico('refresh-cw')}<span>Retry</span>`;
  again.addEventListener('click', () => withBusy(again, 'Retrying…', () => retry()));
  card.append(icon, heading, text, again);
  host.replaceChildren(card);
}

/// A tablist or radiogroup is ONE tab stop (A1-36): the selected item takes
/// Tab (its owner keeps tabindex 0 on it and -1 on the rest), and the arrow
/// keys, Home and End move along the group. By default the item reached is
/// pressed too (selection follows focus), so the group's own click handlers
/// do the switching; `manual` groups - where switching starts a connection -
/// only move the focus, and Enter or Space press the button.
function wireRovingGroup(container, itemSelector, manual) {
  if (!container) return;
  container.addEventListener('keydown', (ev) => {
    if (!['ArrowRight', 'ArrowDown', 'ArrowLeft', 'ArrowUp', 'Home', 'End'].includes(ev.key)) return;
    const items = [...container.querySelectorAll(itemSelector)].filter((b) => !b.disabled && b.offsetParent !== null);
    const i = items.indexOf(document.activeElement);
    if (i === -1) return;
    const n = items.length;
    const step = ev.key === 'ArrowRight' || ev.key === 'ArrowDown' ? 1 : -1;
    const next = ev.key === 'Home' ? items[0] : ev.key === 'End' ? items[n - 1] : items[(i + step + n) % n];
    ev.preventDefault();
    next.focus();
    if (!manual) next.click();
  });
}

// \u2500\u2500\u2500 modal focus management \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
//
// Every modal is a .modal-backdrop toggled by setting .hidden from ~15 call
// sites across app.js and sftp.js. Rather than touch each one (and rely on
// every future modal remembering to opt in), a MutationObserver watches the
// `hidden` attribute and applies the behaviour centrally:
//
//   - focus moves into the dialog when it opens, and returns to whatever
//     opened it when it closes;
//   - Tab and Shift+Tab cycle within the topmost dialog instead of walking
//     out into the page behind it, which they previously did after ~13 tabs.
//
// The stack is keyed on open order, so a dialog opened on top of another (the
// category picker over the host form) traps first and hands control back when
// it closes.

const modalStack = [];

// Every dialog that can be dismissed registers HOW, so two things can settle
// it without knowing what it holds: Escape (topmost layer only) and a vault
// lock. A closer must leave nothing pending - it resolves the dialog's promise
// or callback with the "no" answer and blanks any secret field. A dialog that
// has no closer is left to handle its own Escape.
const modalClosers = new Map();

function registerModalCloser(node, fn) {
  if (node && typeof fn === 'function') modalClosers.set(node, fn);
}

function unregisterModalCloser(node) {
  modalClosers.delete(node);
}

/// Stacking follows open order, not document order. Every .modal-backdrop used
/// to share z-index 50, so whichever was declared last in index.html painted on
/// top: a vault gate or palette opened over the server form rendered BEHIND it
/// while still taking the keyboard focus. Renumbered after every open and
/// close, so a layer opened after a lower one closed can never tie with one
/// that is still up.
function layerModals() {
  modalStack.forEach((m, i) => { m.node.style.zIndex = String(50 + i); });
}

/// Escape closes the topmost dialog and nothing else, wherever focus is inside
/// it. Capture phase on the document so it runs before a dialog's own handlers
/// and before the page-level shortcuts; a layer without a closer is left alone.
function onModalEscapeKey(ev) {
  if (ev.key !== 'Escape' || ev.isComposing || !modalStack.length) return;
  const top = modalStack[modalStack.length - 1].node;
  const close = modalClosers.get(top);
  if (!close) return;
  ev.preventDefault();
  ev.stopPropagation();
  ev.stopImmediatePropagation();
  try {
    close();
  } catch (e) {
    // Never trap the user in a dialog because its closer is broken - but say so.
    console.warn('[sshspan] a dialog closer threw; hiding the dialog instead:', e);
    top.hidden = true;
  }
}

const FOCUSABLE = [
  'a[href]', 'button:not([disabled])', 'input:not([disabled]):not([type="hidden"])',
  'select:not([disabled])', 'textarea:not([disabled])', '[tabindex]:not([tabindex="-1"])',
].join(',');

function modalFocusable(root) {
  return [...root.querySelectorAll(FOCUSABLE)].filter((n) => {
    if (n.closest('[hidden]') !== null && n.closest('[hidden]') !== root) return false;
    // offsetParent is null for display:none subtrees; position:fixed elements
    // report null too, so fall back to a rect check for those.
    return n.offsetParent !== null || n.getBoundingClientRect().width > 0;
  });
}

function onModalTabKey(ev) {
  if (ev.key !== 'Tab' || !modalStack.length) return;
  const top = modalStack[modalStack.length - 1];
  const items = modalFocusable(top.node);
  if (!items.length) return;
  const first = items[0];
  const last = items[items.length - 1];
  const active = document.activeElement;
  // Focus outside the dialog (or on the backdrop itself) means the previous
  // Tab already escaped \u2014 pull it back to the appropriate edge.
  if (!top.node.contains(active)) {
    ev.preventDefault();
    (ev.shiftKey ? last : first).focus();
    return;
  }
  if (ev.shiftKey && active === first) { ev.preventDefault(); last.focus(); }
  else if (!ev.shiftKey && active === last) { ev.preventDefault(); first.focus(); }
}

function modalDidOpen(node) {
  if (modalStack.some((m) => m.node === node)) return;
  const opener = document.activeElement;
  modalStack.push({ node, opener: opener && opener !== document.body ? opener : null });
  layerModals();
  // Only take focus if the dialog's own open path has not already placed it
  // somewhere deliberate (the picker focuses its search box, the delete
  // prompt focuses Cancel) \u2014 a rAF lets those run first.
  requestAnimationFrame(() => {
    if (node.hidden || node.contains(document.activeElement)) return;
    const items = modalFocusable(node);
    if (items.length) items[0].focus();
  });
}

function modalDidClose(node) {
  const i = modalStack.findIndex((m) => m.node === node);
  if (i === -1) return;
  const [entry] = modalStack.splice(i, 1);
  node.style.zIndex = '';
  layerModals();
  // A password shown in this dialog is masked again for next time (A5-35).
  remaskSecrets(node);
  // Restore focus to the control that opened the dialog, so keyboard users
  // are not dropped at the top of the document. Skipped when something else
  // has already claimed focus inside a dialog still on the stack.
  const top = modalStack[modalStack.length - 1];
  if (top && top.node.contains(document.activeElement)) return;
  if (entry.opener && document.contains(entry.opener)) entry.opener.focus();
}

function initModalFocusManagement() {
  document.addEventListener('keydown', onModalTabKey, true);
  document.addEventListener('keydown', onModalEscapeKey, true);
  const obs = new MutationObserver((records) => {
    for (const r of records) {
      const node = r.target;
      if (!node.classList || !node.classList.contains('modal-backdrop')) continue;
      if (node.hidden) modalDidClose(node);
      else modalDidOpen(node);
    }
  });
  for (const m of document.querySelectorAll('.modal-backdrop')) {
    obs.observe(m, { attributes: true, attributeFilter: ['hidden'] });
    if (!m.hidden) modalDidOpen(m);
  }
}

// \u2500\u2500\u2500 interface scale \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
//
// The default 13px base is too small on a lot of 1080p displays and the
// stylesheet has no relative sizing to lean on, so scaling is done with the
// webview's own zoom \u2014 the same mechanism as Ctrl+= \u2014 which scales layout and
// text together. Stored as a percentage under the `uiScale` setting.

const UI_SCALE_MIN = 75;
const UI_SCALE_MAX = 200;

function clampUiScale(v) {
  const n = parseInt(v, 10);
  if (!Number.isFinite(n)) return 100;
  return Math.max(UI_SCALE_MIN, Math.min(UI_SCALE_MAX, n));
}

function currentUiScale() {
  return clampUiScale(state.settings && state.settings.uiScale ? state.settings.uiScale : 100);
}

/// Apply a scale percentage to the live window. Best-effort: if the webview
/// zoom API is unavailable the UI simply stays at 100% rather than throwing
/// during boot.
function applyUiScale(pct) {
  const factor = clampUiScale(pct) / 100;
  try {
    const wv = window.__TAURI__ && window.__TAURI__.webviewWindow;
    const win = wv && wv.getCurrentWebviewWindow && wv.getCurrentWebviewWindow();
    if (win && typeof win.setZoom === 'function') {
      const r = win.setZoom(factor);
      if (r && typeof r.catch === 'function') r.catch(() => {});
    }
  } catch {
    /* zoom unavailable \u2014 keep the default scale */
  }
}

function fmtTime(iso) {
  if (!iso) return '\u2014';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return String(iso);
  return d.toLocaleString();
}

function safeFileName(name) {
  return String(name || 'key').replace(/[^\w.\-]+/g, '-').slice(0, 64) || 'key';
}

function download(filename, text) {
  const blob = new Blob([text], { type: 'application/octet-stream' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 4000);
}

// Copy via Tauri's clipboard plugin first, the browser API second.
//
// Under WebKitGTK (every Linux build, and the AppImage in particular)
// navigator.clipboard.writeText rejects even when the text reaches the
// clipboard, so the old browser-only path reported "Clipboard unavailable"
// on copies that had in fact worked. tauri_plugin_clipboard_manager is
// already registered (src-tauri/src/lib.rs) and terminal.js already uses it;
// this path simply never did.
const clipboardPlugin = (window.__TAURI__ && window.__TAURI__.clipboardManager) || null;

async function copyText(text) {
  if (clipboardPlugin && typeof clipboardPlugin.writeText === 'function') {
    try {
      await clipboardPlugin.writeText(text);
      return true;
    } catch {
      // fall through to the browser API
    }
  }
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

// ─── branding ──────────────────────────────────────────────────────────────

function loadBrandIcon() {
  const img = el('brandIcon');
  if (!img) return;
  img.addEventListener('error', () => {
    img.remove();
    const fallback = document.createElement('div');
    fallback.className = 'logo';
    fallback.textContent = 'SSH';
    const brand = document.querySelector('.brand');
    if (brand) brand.insertBefore(fallback, brand.firstChild);
  });
  try {
    img.src = new URL('assets/icon-sidebar.png', document.baseURI).href;
  } catch {
    // leave the alt text in place
  }
}

/** Fill every [data-ico="name"] / [data-nav-ico="name"] element with an icon. */
function injectIcons() {
  for (const [ico, name] of Object.entries(ICONS)) {
    const targets = document.querySelectorAll('[data-ico="' + ico + '"], [data-nav-ico="' + ico + '"]');
    if (!targets.length) continue;
    for (const t of targets) if (name) t.innerHTML = name;
  }
  // close (x) buttons use data-ico-x (empty attr on a button)
  for (const b of document.querySelectorAll('[data-ico-x]')) {
    if (ICONS.x) b.innerHTML = ICONS.x;
  }
}

/** An icon's markup; never "undefined" text. A name ICONS does not have still
 *  takes an icon's place - an empty svg, sized by the same rules as a real one
 *  - so the row's text lines up with its neighbours instead of starting an
 *  icon's width further left (A1-28). */
function ico(name) {
  if (!name) return '';
  return ICONS[name] || '<svg aria-hidden="true" viewBox="0 0 24 24"></svg>';
}

/** 32-36px rounded key-type tile used by key rows and the detail pane. */
function keyAvatar(kind) {
  const map = { ed25519: 'ed25519', 'ed25519-sk': 'ed25519', rsa: 'rsa', ecdsa: 'ecdsa' };
  const k = map[kind] || '';
  const span = document.createElement('span');
  span.className = 'key-avatar';
  span.dataset.type = k;
  span.setAttribute('aria-hidden', 'true');
  span.innerHTML = ico('key-square');
  return span;
}

/** Short uppercase type label used for key-type badges (rsa → RSA). */
function typeBadge(kind) {
  const t = document.createElement('span');
  t.className = 'badge';
  const base = kind.split('-')[0];
  t.dataset.kind = base;
  t.textContent = kind.replace('-', ' ');
  return t;
}

/** <a data-vault-state=...> pill for the sidebar vault indicator. */
function vaultStatusHTML(unlocked, hasVault) {
  const s = unlocked ? 'unlocked' : (hasVault ? 'locked' : 'novault');
  return {
    state: s,
    icon: ico(unlocked ? 'lock-open' : 'lock'),
    label: unlocked ? 'Unlocked' : (hasVault ? 'Locked' : 'No vault'),
  };
}

// ─── category tree helpers ─────────────────────────────────────────────────

function currentCategoryScope() { return state.view === 'connect' ? 'host' : 'key'; }

function rebuildCategoryIndex() {
  state.catsById = new Map();
  state.childrenOf = new Map();
  for (const c of state.categories.filter(c => c.scope === state.categoryScope)) {
    state.catsById.set(c.id, c);
    const key = c.parent_id || ''; // empty string for roots
    if (!state.childrenOf.has(key)) state.childrenOf.set(key, []);
    state.childrenOf.get(key).push(c);
  }
  for (const list of state.childrenOf.values()) list.sort((a, b) => a.sort_index - b.sort_index || a.name.localeCompare(b.name));
}

function catById(id) { return state.catsById.get(id) || state.categories.find(c => c.id === id); }

function childrenOf(parentId) {
  return state.childrenOf.get(parentId || '') || [];
}

/// Children of a category in an explicitly named scope. The index that
/// childrenOf() reads is rebuilt for whichever scope the sidebar is currently
/// showing, so anything that has to walk the *other* scope's tree - the host
/// picker, which opens from the Keys view - reads state.categories directly.
function childrenOfScoped(parentId, scope) {
  return state.categories
    .filter(c => c.scope === scope && (c.parent_id || '') === (parentId || ''))
    .sort((a, b) => a.sort_index - b.sort_index || a.name.localeCompare(b.name));
}

function catPath(id) {
  const out = [];
  let cur = catById(id);
  while (cur) { out.push(cur.name); cur = cur.parent_id ? catById(cur.parent_id) : null; }
  out.reverse();
  return out;
}

function catPathString(id) { return catPath(id).join(' / '); }

function directKeyCount(catId) {
  let n = 0;
  for (const ids of Object.values(state.keyCategories)) if (ids.includes(catId)) n++;
  return n;
}

function directHostCount(catId) {
  return state.servers.filter(s => s.categoryId === catId).length;
}

function activeCategoryId() { return state.activeCategoryByScope[state.categoryScope] || 'all'; }

function categoryCount(catId) { return state.categoryScope === 'host' ? directHostCount(catId) : directKeyCount(catId); }

function totalKeyCountFor(catId) {
  // direct + descendants
  const stack = [catId];
  let n = 0;
  while (stack.length) {
    const id = stack.pop();
    for (const ids of Object.values(state.keyCategories)) if (ids.includes(id)) n++;
    for (const child of childrenOf(id)) stack.push(child.id);
  }
  return n;
}

function uncategorizedKeyCount() {
  let n = 0;
  for (const k of state.keys) if ((state.keyCategories[k.id] || []).length === 0) n++;
  return n;
}

function keysInCategoryRecursive(catId) {
  const ids = new Set();
  const stack = [catId];
  while (stack.length) {
    const id = stack.pop();
    for (const k of state.keys) if ((state.keyCategories[k.id] || []).includes(id)) ids.add(k.id);
    for (const child of childrenOf(id)) stack.push(child.id);
  }
  return state.keys.filter(k => ids.has(k.id));
}

/// The key list the UI renders: the active CATEGORY narrows the pool first,
/// then the search box and the type filter narrow it further.
///
/// There used to be a second `function filteredKeys()` further down this file
/// that applied only the search and type filters. Function declarations hoist,
/// so the later one silently replaced this one for the single caller
/// (renderKeyList) - and the category filter did nothing at all. Selecting a
/// category in the sidebar rendered every key in the vault, which also made
/// "All categories" and a specific category look identical.
function filteredKeys() {
  const q = el('searchInput').value.trim().toLowerCase();
  const type = el('typeFilter').value;
  let pool = state.keys;
  const activeCat = activeCategoryId();
  if (activeCat === 'uncategorized') {
    pool = state.keys.filter(k => (state.keyCategories[k.id] || []).length === 0);
  } else if (activeCat !== 'all') {
    pool = keysInCategoryRecursive(activeCat);
  }
  return pool.filter(k => {
    if (type && k.key_type !== type) {
      if (type !== 'ecdsa' || !k.key_type.startsWith('ecdsa')) return false;
    }
    if (!q) return true;
    const hay = [k.name, k.comment, k.fingerprint_sha256].filter(Boolean).join(' ').toLowerCase();
    return hay.includes(q);
  });
}

// ─── sidebar category tree render ──────────────────────────────────────────

function catNodeEl(cat, depth) {
  const wrap = document.createElement('div');
  const row = document.createElement('div');
  row.className = 'cat-node';
  row.dataset.id = cat.id;
  row.dataset.depth = String(depth);
  // A drop is category_reparent, which the backend refuses while the vault
  // is locked (A6-08); applyLockGates() keeps this in step afterwards.
  row.draggable = state.unlocked;
  if (activeCategoryId() === cat.id) row.classList.add('active');
  // Keyboard-operable (A1-11): a tab stop, Enter/Space filter by it. It is a
  // toggle - selecting the active category clears the filter - so it says
  // whether it is pressed.
  row.tabIndex = 0;
  row.setAttribute('role', 'button');
  row.setAttribute('aria-pressed', activeCategoryId() === cat.id ? 'true' : 'false');
  row.setAttribute('aria-label', cat.name);
  row.addEventListener('keydown', (ev) => {
    if (ev.target !== row || (ev.key !== 'Enter' && ev.key !== ' ')) return;
    ev.preventDefault();
    setActiveCategory(cat.id);
  });

  const kids = childrenOf(cat.id);
  // A real button when there is something to expand, so it is reachable and
  // named for the keyboard; a leaf keeps an empty spacer.
  const chev = document.createElement(kids.length ? 'button' : 'span');
  chev.className = 'cat-chevron';
  if (kids.length === 0) chev.classList.add('leaf');
  else {
    const open = state.expandedCatIds.has(cat.id);
    chev.type = 'button';
    chev.setAttribute('aria-expanded', open ? 'true' : 'false');
    chev.setAttribute('aria-label', (open ? 'Collapse ' : 'Expand ') + cat.name);
    chev.innerHTML = ico('chevron-right');
    if (open) chev.classList.add('expanded');
    chev.addEventListener('click', (e) => { e.stopPropagation(); toggleCatExpanded(cat.id); });
  }
  row.appendChild(chev);

  const catIco = document.createElement('span');
  catIco.className = 'cat-ico';
  catIco.innerHTML = ico(state.expandedCatIds.has(cat.id) ? 'folder-open' : 'folder');
  row.appendChild(catIco);

  const lbl = document.createElement('span');
  lbl.className = 'cat-label';
  lbl.textContent = cat.name;
  row.appendChild(lbl);

  const cnt = document.createElement('span');
  cnt.className = 'cat-count';
  const n = categoryCount(cat.id);
  cnt.textContent = n;
  row.appendChild(cnt);

  const menuBtn = document.createElement('button');
  menuBtn.className = 'cat-actions-btn';
  menuBtn.title = 'Category actions';
  menuBtn.setAttribute('aria-haspopup', 'menu');
  menuBtn.setAttribute('aria-expanded', 'false');
  menuBtn.innerHTML = ico('ellipsis');
  menuBtn.addEventListener('click', (e) => { e.stopPropagation(); openCatMenu(cat, menuBtn); });
  // Every item in that menu changes categories (A6-08).
  lockGate(menuBtn, 'categories');
  row.appendChild(menuBtn);

  row.addEventListener('click', () => { setActiveCategory(cat.id); });
  attachCatDnD(row, cat, depth);

  wrap.appendChild(row);

  if (kids.length) {
    const childWrap = document.createElement('div');
    childWrap.className = 'cat-children';
    if (!state.expandedCatIds.has(cat.id)) childWrap.hidden = true;
    for (const c of kids) childWrap.appendChild(catNodeEl(c, depth + 1));
    wrap.appendChild(childWrap);
  }
  return wrap;
}

function renderCategoryTree() {
  const tree = el('catTree');
  if (!tree) return;
  // The tree is rebuilt on every change. Whatever in it had the focus - a row,
  // its chevron, its "..." button - gets it back afterwards, or a keyboard user
  // is dropped at the top of the page after every expand or filter (A1-26).
  const had = tree.contains(document.activeElement) ? document.activeElement : null;
  const hadNode = had && had.closest('.cat-node');
  const refocus = hadNode && {
    id: hadNode.dataset.id,
    part: had.classList.contains('cat-chevron') ? '.cat-chevron' : (had.classList.contains('cat-actions-btn') ? '.cat-actions-btn' : null),
  };
  tree.innerHTML = '';
  const panel = el('catPanel');
  /// The tree filters the list you are looking at, so it belongs to Keys and
  /// Servers and nowhere else - it used to sit under Settings too, offering to
  /// filter a view with nothing in it to filter.
  const relevant = state.view === 'keys' || state.view === 'connect';
  const title = el('catPanelTitle');
  if (title) title.textContent = state.categoryScope === 'host' ? 'Server categories' : 'Key categories';
  if (panel) {
    panel.hidden = !relevant
      || (state.categories.filter(c => c.scope === state.categoryScope).length === 0 && !state.orphans);
    // The narrow-window drawer shows this same panel: with nothing in it, its
    // buttons are disabled and say why, and an open drawer closes.
    for (const b of document.querySelectorAll('.cat-drawer-btn')) {
      if (b.dataset.drawerTitle === undefined) b.dataset.drawerTitle = b.title;
      b.disabled = panel.hidden;
      b.title = !panel.hidden ? b.dataset.drawerTitle
        : 'No categories yet - add a ' + (state.categoryScope === 'host' ? 'server' : 'key') + ' first';
    }
    if (panel.hidden && catDrawerOpen()) setCatDrawer(false);
  }
  if (state.orphans) {
    const u = document.createElement('div');
    u.className = 'cat-node uncategorized';
    u.dataset.id = 'uncategorized';
    u.dataset.depth = '0';
    if (activeCategoryId() === 'uncategorized') u.classList.add('active');
    const chev = document.createElement('span'); chev.className = 'cat-chevron leaf'; u.appendChild(chev);
    const catIco = document.createElement('span'); catIco.className = 'cat-ico'; catIco.innerHTML = ico('folder'); u.appendChild(catIco);
    const lbl = document.createElement('span'); lbl.className = 'cat-label'; lbl.textContent = state.categoryScope === 'host' ? 'Uncategorized servers' : 'Uncategorized keys'; u.appendChild(lbl);
    const cnt = document.createElement('span'); cnt.className = 'cat-count'; cnt.textContent = state.categoryScope === 'host' ? state.servers.filter(s => !s.categoryId).length : uncategorizedKeyCount(); u.appendChild(cnt);
    u.addEventListener('click', () => setActiveCategory('uncategorized'));
    u.tabIndex = 0;
    u.setAttribute('role', 'button');
    u.setAttribute('aria-pressed', activeCategoryId() === 'uncategorized' ? 'true' : 'false');
    u.setAttribute('aria-label', lbl.textContent);
    u.addEventListener('keydown', (ev) => {
      if (ev.target !== u || (ev.key !== 'Enter' && ev.key !== ' ')) return;
      ev.preventDefault();
      setActiveCategory('uncategorized');
    });
    tree.appendChild(u);
  }
  for (const c of childrenOf(null)) tree.appendChild(catNodeEl(c, 0));
  if (refocus) {
    const node = [...tree.querySelectorAll('.cat-node')].find((n) => n.dataset.id === refocus.id);
    const target = node && (refocus.part ? node.querySelector(refocus.part) : node);
    if (target && target.offsetParent !== null) target.focus();
  }
}

/// Below 900px the category tree opens as a drawer over the page, from the
/// Keys toolbar or the server list (A1-06 / A5-13). Hiding it there took
/// filtering, creating, renaming, moving and deleting categories away at the
/// minimum window size - and at the default size with Interface scale 125%+.
function catDrawerOpen() { return el('app').classList.contains('cat-drawer-open'); }

function setCatDrawer(open, o) {
  if (open === catDrawerOpen()) return;
  // Nothing to show (renderCategoryTree hides the panel and disables the
  // buttons then): no empty drawer, no listener, no focus on a hidden node.
  if (open && el('catPanel').hidden) return;
  el('app').classList.toggle('cat-drawer-open', open);
  for (const b of document.querySelectorAll('.cat-drawer-btn')) b.setAttribute('aria-expanded', open ? 'true' : 'false');
  if (open) {
    document.addEventListener('mousedown', onCatDrawerOutside, true);
    const panel = el('catPanel');
    const first = panel.querySelector('.cat-node.active') || panel.querySelector('.cat-node') || el('catAddRootBtn');
    if (first) first.focus();
    return;
  }
  document.removeEventListener('mousedown', onCatDrawerOutside, true);
  if (o && o.focusButton) {
    const btn = el(state.view === 'connect' ? 'serverCatDrawerBtn' : 'catDrawerBtn');
    if (btn) btn.focus();
  }
}

/// A click outside the drawer closes it - but not one on its own toggle, on a
/// menu it opened or on a dialog one of its actions opened.
function onCatDrawerOutside(ev) {
  const t = ev.target;
  if (el('catPanel').contains(t) || (t.closest && t.closest('.cat-drawer-btn, .ctx-menu, .modal-backdrop'))) return;
  setCatDrawer(false);
}

function toggleCatExpanded(id) {
  if (state.expandedCatIds.has(id)) state.expandedCatIds.delete(id);
  else state.expandedCatIds.add(id);
  renderCategoryTree();
}

function setActiveCategory(id) {
  if (activeCategoryId() === id) id = 'all';
  state.activeCategoryByScope[state.categoryScope] = id;
  renderCategoryTree();
  updateBreadcrumb();
  if (state.categoryScope === 'host') renderServerList();
  else renderKeyList();
  updateSelectionHint();
}

// ─── category CRUD ─────────────────────────────────────────────────────────

async function loadCategories() {
  let res;
  try {
    res = await call('category_list');
  } catch (e) {
    // Reported here, not thrown (A2-20): through loadKeys() a rejection here
    // used to abort refreshVaultStatus() and, at boot, main() itself - no 10 s
    // poll, no idle-activity listeners, no stored settings. The tree keeps
    // what it had.
    toast('Could not load categories: ' + (e.message || String(e)), 'err');
    return;
  }
  state.categories = res.categories || [];
  state.categoryScope = currentCategoryScope();
  state.keyCategories = res.allKeyCategories || {};
  state.orphans = state.categoryScope === 'host' ? !!res.hostOrphans : !!res.orphans;
  rebuildCategoryIndex();
  renderCategoryTree();
  updateBreadcrumb();
}

async function createCategory(name, parentId, color) {
  if (!name) return null;
  const cat = await call('category_create', { name, parentId, color, scope: state.categoryScope });
  await loadCategories();
  return cat;
}

async function deleteCategory(id) {
  if (!lockGateOpen('categories')) return;
  const cat = catById(id);
  if (!cat) return;
  const ok = await confirmModal('Delete category',
    `Delete category "${cat.name}"? Children will be reassigned to its parent, and any keys using this category will become Uncategorized.`,
    'Delete');
  if (!ok) return;
  try {
    const res = await call('category_delete', { id });
    await loadCategories();
    if (activeCategoryId() === id) setActiveCategory('all');
    if (state.categoryScope === 'host') renderServerList(); else renderKeyList();
    toast(`Category "${cat.name}" deleted.` + (res.reassigned && res.reassigned.length ? ` ${res.reassigned.length} child(ren) reassigned.` : ''), 'ok');
  } catch (e) { toast(e.message || String(e), 'err'); }
}

async function renameCategory(id) {
  if (!lockGateOpen('categories')) return;
  const cat = catById(id); if (!cat) return;
  promptModal(`Rename category`, 'Enter a new name.', cat.name, async (newName) => {
    if (!newName || newName === cat.name) return;
    try { await call('category_rename', { id, name: newName }); await loadCategories(); toast('Renamed.', 'ok'); }
    catch (e) { toast(e.message || String(e), 'err'); }
  });
}

async function moveCategoryPrompt(id) {
  if (!lockGateOpen('categories')) return;
  // opens the picker in single-select mode for choosing a new parent
  openCategoryPicker({
    title: 'Move to...',
    scope: state.categoryScope,
    initial: [],
    single: true,
    onSave: async (parentIds) => {
      if (!parentIds.length) return;
      try { await call('category_reparent', { id, newParentId: parentIds[0] }); await loadCategories(); toast('Moved.', 'ok'); }
      catch (e) { toast(e.message || String(e), 'err'); }
    },
  });
}

async function addCategoryPrompt(parentId) {
  if (!lockGateOpen('categories')) return;
  promptModal('New category', 'Enter a name.', '', async (name) => {
    if (!name) return;
    // promptModal does not await this callback, so a rejection here was only
    // ever an "unhandled rejection" log line: a refused create looked like
    // nothing had happened (A2-20).
    try {
      const cat = await createCategory(name, parentId || null, null);
      if (cat) { state.expandedCatIds.add(parentId || ''); /* noop for roots */ if (parentId) state.expandedCatIds.add(parentId); renderCategoryTree(); toast(`Created "${cat.name}".`, 'ok'); }
    } catch (e) { toast(e.message || String(e), 'err'); }
  });
}

// ─── menus ────────────────────────────────────────────────────────────────
//
// The vault, category "...", key-connect, server and terminal right-click
// menus and the ssh-config import menu are built by openMenu(): role=menu of
// menuitems, the focus on the first item, ArrowUp/ArrowDown/Home/End, Escape
// and a click outside close it, the focus goes back where it came from, the
// opener's aria-expanded is reset, and the menu is kept on screen
// (positionCtxMenuAt). They used to be ad-hoc builders that ignored the
// keyboard, opened at the raw pointer position off the window's edge and left
// aria-expanded="true" behind (A2-50 / A1-26 / A2-21 / A1-04). The cascading
// host picker below and the sftp.js menus still build their own. All of them
// use the one #keyConnectMenu, so closeKeyConnectMenu() closes whichever is
// open, and only one menu is ever open.

/// The open menu's bookkeeping: { anchor, opener, onClose, cleanup }, or null.
let activeMenu = null;

/// items: { label, icon, sub, danger, disabled, onSelect } or 'sep'.
/// at: the anchor element (the menu opens below it; above with opts.above,
/// right-aligned with opts.alignRight) or a { x, y } point.
/// opts.label names the menu for assistive tech; opts.onClose runs once when
/// it closes, however it closes. Activating the same anchor again closes it.
function openMenu(at, items, opts) {
  opts = opts || {};
  const anchor = at instanceof Element ? at : null;
  if (anchor && activeMenu && activeMenu.anchor === anchor) { closeKeyConnectMenu(); return null; }
  closeKeyConnectMenu();
  const active = document.activeElement;
  const opener = active && active !== document.body ? active : null;
  const menu = document.createElement('div');
  menu.className = 'ctx-menu';
  menu.id = 'keyConnectMenu';
  menu.setAttribute('role', 'menu');
  if (opts.label) menu.setAttribute('aria-label', opts.label);
  for (const it of items) {
    if (it === 'sep') {
      const sep = document.createElement('div');
      sep.className = 'ctx-sep';
      sep.setAttribute('role', 'separator');
      menu.appendChild(sep);
      continue;
    }
    const b = document.createElement('button');
    b.type = 'button';
    b.className = 'ctx-item' + (it.danger ? ' danger' : '');
    b.setAttribute('role', 'menuitem');
    b.tabIndex = -1;
    b.disabled = !!it.disabled;
    b.innerHTML = ico(it.icon);
    const text = document.createElement('span');
    text.textContent = it.label;
    if (it.sub) {
      const small = document.createElement('small');
      small.textContent = it.sub;
      text.append(' ', small);
    }
    b.appendChild(text);
    b.addEventListener('click', () => {
      // Closed first, with the focus back where it was, so an action that
      // opens a dialog hands the focus on from there (and gets it back).
      closeKeyConnectMenu({ restoreFocus: true });
      it.onSelect();
    });
    menu.appendChild(b);
  }
  document.body.appendChild(menu);
  if (anchor) {
    const r = anchor.getBoundingClientRect();
    const x = opts.alignRight ? r.right - menu.offsetWidth : r.left;
    const y = opts.above ? r.top - menu.offsetHeight - 6 : r.bottom + 4;
    positionCtxMenuAt(menu, x, y);
    if (anchor.hasAttribute('aria-expanded')) anchor.setAttribute('aria-expanded', 'true');
  } else {
    positionCtxMenuAt(menu, at.x, at.y);
  }
  const enabledItems = () => [...menu.querySelectorAll('.ctx-item:not(:disabled)')];
  // Window, capture phase: ahead of the dialog Escape handler and the page
  // shortcuts, so Escape closes the menu and nothing under it.
  const onKey = (ev) => {
    if (ev.key === 'Escape') {
      ev.preventDefault();
      ev.stopImmediatePropagation();
      closeKeyConnectMenu({ restoreFocus: true });
      return;
    }
    if (!menu.contains(document.activeElement)) return;
    if (ev.key === 'Tab') {
      ev.preventDefault();
      closeKeyConnectMenu({ restoreFocus: true });
      return;
    }
    const list = enabledItems();
    const i = list.indexOf(document.activeElement);
    const next = { ArrowDown: list[(i + 1) % list.length], ArrowUp: list[(i - 1 + list.length) % list.length],
      Home: list[0], End: list[list.length - 1] }[ev.key];
    if (!next) return;
    ev.preventDefault();
    ev.stopImmediatePropagation();
    next.focus();
  };
  const onDown = (ev) => {
    if (menu.contains(ev.target)) return;
    // The opener's own click toggles the menu shut (see above); closing it
    // here on mousedown would make that click open it again.
    if (anchor && anchor.contains(ev.target)) return;
    closeKeyConnectMenu();
  };
  window.addEventListener('keydown', onKey, true);
  document.addEventListener('mousedown', onDown, true);
  activeMenu = {
    anchor, opener, onClose: opts.onClose,
    cleanup: () => {
      window.removeEventListener('keydown', onKey, true);
      document.removeEventListener('mousedown', onDown, true);
    },
  };
  const first = enabledItems()[0];
  if (first) first.focus();
  return menu;
}

// ─── cat row menu ─────────────────────────────────────────────────────────

function openCatMenu(cat, anchor) {
  openMenu(anchor, [
    { label: 'Rename', icon: 'pencil', onSelect: () => renameCategory(cat.id) },
    { label: 'New subcategory', icon: 'folder-plus', onSelect: () => addCategoryPrompt(cat.id) },
    { label: 'Move to...', icon: 'move', onSelect: () => moveCategoryPrompt(cat.id) },
    { label: 'Delete', icon: 'x', danger: true, onSelect: () => deleteCategory(cat.id) },
  ], { alignRight: true, label: 'Category actions' });
}

// ─── HTML5 drag-and-drop for the sidebar tree ─────────────────────────────

function attachCatDnD(row, cat, depth) {
  row.addEventListener('dragstart', (e) => {
    state.draggingCatId = cat.id;
    row.classList.add('dragging');
    e.dataTransfer.setData('text/plain', cat.id);
    e.dataTransfer.effectAllowed = 'move';
  });
  row.addEventListener('dragend', () => {
    state.draggingCatId = null;
    row.classList.remove('dragging');
    document.querySelectorAll('.cat-node').forEach(n => n.classList.remove('drop-before', 'drop-after', 'drop-into'));
  });
  row.addEventListener('dragover', (e) => {
    if (!state.draggingCatId || state.draggingCatId === cat.id) return;
    e.preventDefault();
    e.dataTransfer.dropEffect = 'move';
    const rect = row.getBoundingClientRect();
    const y = e.clientY - rect.top;
    row.classList.remove('drop-before', 'drop-after', 'drop-into');
    if (y < rect.height * 0.25) row.classList.add('drop-before');
    else if (y > rect.height * 0.75) row.classList.add('drop-after');
    else row.classList.add('drop-into');
  });
  row.addEventListener('dragleave', () => {
    row.classList.remove('drop-before', 'drop-after', 'drop-into');
  });
  row.addEventListener('drop', async (e) => {
    e.preventDefault();
    const draggedId = state.draggingCatId;
    state.draggingCatId = null;
    row.classList.remove('drop-before', 'drop-after', 'drop-into');
    if (!draggedId || draggedId === cat.id) return;
    // A drag that started before the vault locked.
    if (!lockGateOpen('categories')) return;
    const before = row.classList.contains('drop-before');
    const into = row.classList.contains('drop-into');
    let newParent, newSortIndex = null;
    if (into) {
      newParent = cat.id;
      // sort_index: max sibling + 1 within the new parent
      const sibs = childrenOf(newParent);
      newSortIndex = sibs.length ? Math.max(...sibs.map(s => s.sort_index)) + 1 : 0;
    } else {
      newParent = cat.parent_id || null;
      if (before) newSortIndex = cat.sort_index;
      else newSortIndex = cat.sort_index + 1;
    }
    try {
      await call('category_reparent', { id: draggedId, newParentId: newParent, sortIndex: newSortIndex });
      await loadCategories();
      renderKeyList();
    } catch (err) { toast(err.message || String(err), 'err'); }
  });
}

// ─── breadcrumb + toolbar cat-filter button ───────────────────────────────

function updateBreadcrumb() {
  const bc = el('breadcrumb'); if (!bc) return;
  if (state.view !== 'keys' && state.view !== 'connect') { bc.hidden = true; return; }
  let path = [];
  const activeCat = activeCategoryId();
  if (activeCat === 'uncategorized') path = [state.categoryScope === 'host' ? 'Uncategorized servers' : 'Uncategorized keys'];
  else if (activeCat !== 'all') {
    const segs = catPath(activeCat);
    path = segs;
  }
  if (!path.length) { bc.hidden = true; return; }
  bc.hidden = false;
  bc.innerHTML = '';
  const rootLink = document.createElement('a');
  // "Servers", the name the nav and the view use (A5-31).
  rootLink.href = '#'; rootLink.textContent = state.categoryScope === 'host' ? 'Servers' : 'Keys';
  rootLink.addEventListener('click', (e) => { e.preventDefault(); setActiveCategory('all'); });
  bc.appendChild(rootLink);
  // for normal category path, walk segments and add clickable ancestors
  if (activeCat === 'uncategorized') {
    const sep = document.createElement('span'); sep.className = 'crumb-sep'; sep.textContent = '/'; bc.appendChild(sep);
    const cur = document.createElement('span'); cur.className = 'crumb-current'; cur.textContent = state.categoryScope === 'host' ? 'Uncategorized servers' : 'Uncategorized keys'; bc.appendChild(cur);
  } else {
    const segs = catPath(activeCat);
    const ids = []; let cur = catById(activeCat);
    while (cur) { ids.unshift(cur.id); cur = cur.parent_id ? catById(cur.parent_id) : null; }
    for (let i = 0; i < segs.length; i++) {
      const sep = document.createElement('span'); sep.className = 'crumb-sep'; sep.textContent = '/'; bc.appendChild(sep);
      const isLast = i === segs.length - 1;
      if (isLast) {
        const sp = document.createElement('span'); sp.className = 'crumb-current'; sp.textContent = segs[i]; bc.appendChild(sp);
      } else {
        const a = document.createElement('a'); a.href = '#'; a.textContent = segs[i];
        a.addEventListener('click', (e) => { e.preventDefault(); setActiveCategory(ids[i]); });
        bc.appendChild(a);
      }
    }
  }
  const clear = document.createElement('button');
  clear.className = 'crumb-clear'; clear.textContent = 'Clear filter';
  clear.addEventListener('click', () => setActiveCategory('all'));
  bc.appendChild(clear);
}


// ─── multi-select picker (shared widget) ──────────────────────────────────

function openCategoryPicker({ title, initial, single, onSave, scope }) {
  if (scope) {
    state.categoryScope = scope;
    rebuildCategoryIndex();
  }
  state.pickerSelected = new Set(initial || []);
  state.pickerSingle = !!single;
  state.pickerCallback = onSave;
  state.pickerActive = -1;
  state.pickerTrigger = document.activeElement;
  el('pickerTitle').textContent = title || 'Categories';
  el('pickerSaveBtn').textContent = single ? 'Select' : 'Save';
  el('pickerSearch').value = '';
  el('pickerTree').setAttribute('aria-multiselectable', String(!single));
  renderPickerTree('');
  el('pickerModal').hidden = false;
  setTimeout(() => el('pickerSearch').focus(), 0);
}

function closeCategoryPicker() {
  el('pickerModal').hidden = true;
  state.pickerCallback = null;
  state.pickerSelected = new Set();
  state.pickerSingle = false;
  state.pickerActive = -1;
  if (state.pickerTrigger && document.contains(state.pickerTrigger)) state.pickerTrigger.focus();
  state.pickerTrigger = null;
}

function pickerToggle(id) {
  if (state.pickerSelected.has(id)) state.pickerSelected.delete(id);
  else {
    if (state.pickerSingle) state.pickerSelected.clear();
    state.pickerSelected.add(id);
  }
  if (state.pickerSingle) {
    const cb = state.pickerCallback;
    const ids = [...state.pickerSelected];
    closeCategoryPicker();
    if (cb) cb(ids);
    return;
  }
  renderPickerTree(el('pickerSearch').value);
}

function renderPickerSelection() {
  const host = el('pickerSelection');
  host.innerHTML = '';
  const ids = [...state.pickerSelected];
  host.hidden = ids.length === 0;
  if (!ids.length) return;
  const label = document.createElement('span');
  label.className = 'picker-selection-label';
  label.textContent = `${ids.length} selected`;
  host.appendChild(label);
  for (const id of ids) {
    const chip = document.createElement('span');
    chip.className = 'picker-chip';
    chip.title = catPathString(id);
    const text = document.createElement('span'); text.textContent = catPathString(id); chip.appendChild(text);
    const remove = document.createElement('button');
    remove.type = 'button'; remove.className = 'picker-chip-remove';
    remove.setAttribute('aria-label', `Remove ${catPathString(id)}`); remove.innerHTML = ico('x');
    remove.addEventListener('click', () => pickerToggle(id));
    chip.appendChild(remove); host.appendChild(chip);
  }
  const clear = document.createElement('button');
  clear.type = 'button'; clear.className = 'picker-clear'; clear.textContent = 'Clear';
  clear.addEventListener('click', () => { state.pickerSelected.clear(); renderPickerTree(el('pickerSearch').value); });
  host.appendChild(clear);
}

function renderPickerTree(filter) {
  const tree = el('pickerTree');
  tree.innerHTML = '';
  const lower = (filter || '').toLowerCase();
  const scopedCategories = state.categories.filter(c => c.scope === state.categoryScope);
  const rows = [];
  const matches = (name) => !lower || name.toLowerCase().includes(lower);
  const walk = (cat, depth) => {
    const visible = matches(cat.name) || (depth === 0 && lower === '');
    const anyDesc = !lower ? true : treeHasMatchingDescendant(cat.id, lower);
    if (!visible && !anyDesc) return;
    rows.push({ cat, depth });
    for (const c of childrenOf(cat.id)) walk(c, depth + 1);
  };
  for (const c of childrenOf(null)) walk(c, 0);
  if (scopedCategories.length === 0 || !rows.length) {
    tree.innerHTML = scopedCategories.length === 0
      ? '<div class="picker-empty">No categories yet. Create one in the sidebar.</div>'
      : '<div class="picker-empty">No matching categories.</div>';
    el('pickerSearch').setAttribute('aria-expanded', 'false'); // nothing listed (A1-36)
    renderPickerSelection(); return;
  }
  rows.forEach(({ cat, depth }, index) => {
    const row = document.createElement('div');
    row.className = 'picker-row' + (state.pickerSelected.has(cat.id) ? ' checked' : '');
    row.dataset.depth = String(depth); row.dataset.index = String(index); row.dataset.id = cat.id;
    row.id = `picker-option-${cat.id}`; row.setAttribute('role', 'option');
    row.setAttribute('aria-selected', String(state.pickerSelected.has(cat.id)));
    row.tabIndex = -1;
    if (index === state.pickerActive) row.classList.add('active');
    const indent = document.createElement('span'); indent.className = 'picker-indent'; indent.style.width = `${depth * 14}px`;
    const box = document.createElement('span'); box.className = 'picker-box';
    const name = document.createElement('span'); name.className = 'picker-name'; name.textContent = cat.name;
    row.append(indent, box, name);
    row.addEventListener('click', () => pickerToggle(cat.id));
    tree.appendChild(row);
  });
  renderPickerSelection();
  if (state.pickerActive >= rows.length) state.pickerActive = rows.length - 1;
  const active = tree.querySelector('.picker-row.active');
  el('pickerSearch').setAttribute('aria-activedescendant', active?.id || '');
  el('pickerSearch').setAttribute('aria-expanded', 'true'); // rows are listed (A1-36)
}

function treeHasMatchingDescendant(catId, lower) {
  for (const c of childrenOf(catId)) {
    if (c.name.toLowerCase().includes(lower)) return true;
    if (treeHasMatchingDescendant(c.id, lower)) return true;
  }
  return false;
}

// ─── prompt modal (rename / new category) ──────────────────────────────────

/// opts.secret marks the answer as a password (the backup restore). The field is
/// masked, the value is handed over exactly as typed - edge whitespace is part
/// of a password, so it is not trimmed - and the field is emptied and put back
/// to plain text whenever the prompt closes, however it closes.
function promptModal(title, message, initial, onOk, opts) {
  const secret = !!(opts && opts.secret);
  const input = el('promptInput');
  el('promptTitle').textContent = title;
  el('promptMessage').textContent = message || '';
  // Autofill and spellcheck are off in the markup for every use of the field
  // (names, and this password) (A1-34). The eye button shows only for a
  // password (A5-35).
  input.type = secret ? 'password' : 'text';
  if (secret) input.dataset.secret = '1'; else delete input.dataset.secret;
  const reveal = revealButtonFor(input);
  if (reveal) { reveal.hidden = !secret; paintRevealButton(reveal, false); }
  input.value = initial || '';
  state.promptCallback = onOk;
  state.promptSecret = secret;
  el('promptModal').hidden = false;
  setTimeout(() => input.focus(), 0);
}
function closePrompt() {
  const input = el('promptInput');
  input.value = '';
  input.type = 'text';
  delete input.dataset.secret;
  const reveal = revealButtonFor(input);
  if (reveal) { reveal.hidden = true; paintRevealButton(reveal, false); }
  state.promptCallback = null;
  state.promptSecret = false;
  el('promptModal').hidden = true;
}

// ─── generic confirm modal (promise-based) ─────────────────────────────────

// While the single shared confirmation dialog is up: the function that answers
// it. null otherwise.
let confirmPending = null;

/// Ask a yes/no question and resolve to the answer. This is THE confirmation
/// for the whole app: the native confirm() is not usable here. tauri-plugin-
/// dialog replaces window.confirm with an async function, so `confirm(...)`
/// returns a Promise - always truthy - and an `if (!confirm(...)) return;` guard
/// can never return; the dialog command is not granted either, so no dialog was
/// ever drawn and every guarded action simply ran. Always `await` this one.
///
/// Promise-based rather than callback-based because its callers are async and
/// branch on the answer inline. The SFTP delete dialog keeps its own modal:
/// that one carries a session-scoped "don't ask again" checkbox that this
/// deliberately does not offer.
///
/// Rules, all of them the safe way round:
///   - one question at a time. There is a single dialog element, so a second
///     question while one is open is refused (answered "no") instead of
///     rewriting the text under the user's cursor - or, as before, having one
///     click answer both.
///   - Cancel has the focus, so a reflexive Enter or Space is a "no".
///   - Cancel, Escape, a backdrop click and a vault lock all answer "no", and
///     the answer is given exactly once.
/// opts.danger: false for a confirmation that is not destructive (the button is
/// then the primary colour instead of red).
function confirmModal(title, message, okLabel, opts) {
  if (confirmPending) {
    if (!el('confirmModal').hidden) return Promise.resolve(false);
    // Something hid the dialog without answering it. Answer it "no" now, so
    // its caller is not left waiting and this question is not refused forever.
    confirmPending(false);
  }
  return new Promise((resolve) => {
    const modal = el('confirmModal');
    const okBtn = el('confirmOkBtn');
    const cancelBtn = el('confirmCancelBtn');
    el('confirmTitle').textContent = title;
    el('confirmMessage').textContent = message || '';
    okBtn.textContent = okLabel || 'Confirm';
    okBtn.className = opts && opts.danger === false ? 'primary-btn' : 'danger-btn';
    let settled = false;
    const settle = (answer) => {
      if (settled) return;
      settled = true;
      if (confirmPending === settle) confirmPending = null;
      unregisterModalCloser(modal);
      modal.hidden = true;
      okBtn.removeEventListener('click', onOk);
      cancelBtn.removeEventListener('click', onCancel);
      modal.removeEventListener('click', onBackdrop);
      resolve(answer);
    };
    const onOk = () => settle(true);
    const onCancel = () => settle(false);
    const onBackdrop = (ev) => { if (ev.target === modal) settle(false); };
    okBtn.addEventListener('click', onOk);
    cancelBtn.addEventListener('click', onCancel);
    modal.addEventListener('click', onBackdrop);
    confirmPending = settle;
    // Escape (topmost layer only) and the vault lock go through here.
    registerModalCloser(modal, () => settle(false));
    modal.hidden = false;
    // After the modal manager has noted what had the focus (it is the control
    // focus returns to), then onto the safe button.
    setTimeout(() => { if (!settled) cancelBtn.focus(); }, 0);
  });
}

// ─── category chip rendering (shared) ─────────────────────────────────────

function renderCategoryChips(targetEl, ids, { removable, onRemove, onClickPath } = {}) {
  targetEl.innerHTML = '';
  for (const id of ids) {
    const chip = document.createElement('span');
    chip.className = 'cat-chip' + (onClickPath ? ' cat-chip-path' : '');
    chip.title = catPathString(id);
    chip.textContent = catPathString(id);
    if (onClickPath) {
      chip.addEventListener('click', () => onClickPath(id));
    }
    if (removable) {
      const x = document.createElement('button');
      x.className = 'cat-chip-x';
      x.title = 'Remove from this category';
      x.innerHTML = ico('x');
      x.addEventListener('click', (e) => { e.stopPropagation(); onRemove(id); });
      chip.appendChild(x);
    }
    targetEl.appendChild(chip);
  }
}

// ─── app state ─────────────────────────────────────────────────────────────

const state = window.state = {
  hasVault: false,
  unlocked: false,
  vaultMode: 'unlock',
  // Which gate dialog the last status refresh asked for: 'create', 'unlock', or
  // null while unlocked (undefined until the first refresh). vaultDismissed is
  // set when the user cancels that gate and holds until they ask for it again
  // or the vault state changes - the 10 s poll must not re-open it.
  vaultGate: undefined,
  vaultDismissed: false,
  keys: [],
  // The backend's message when the last key/server list load failed, else
  // null: the list then shows an error card with Retry instead of the
  // first-run empty state (A5-21).
  keysLoadError: null,
  serversLoadError: null,
  selectedId: null,
  deploySelected: new Set(),
  settings: {},
  view: 'keys',
  // category tree
  categories: [],            // current-scope categories, ordered for tree display
  catsById: new Map(),       // id -> category
  childrenOf: new Map(),     // parent_id (string|null) -> [category]
  categoryScope: 'key',
  activeCategoryByScope: { key: 'all', host: 'all' },
  keyCategories: {},         // keyId -> [catId]
  orphans: false,            // true when at least one key has no categories
  activeCategoryId: 'all',   // 'all' | 'uncategorized' | categoryId
  expandedCatIds: new Set(), // sidebar expanded nodes
  groupExpanded: new Set(),  // key-list group ids the user COLLAPSED (absent = expanded)
  // picker
  pickerCallback: null,
  pickerSelected: new Set(),  // ids the user has ticked
  pickerActive: -1,
  pickerTrigger: null,
  // drag
  draggingCatId: null,
  // prompt
  promptCallback: null,
  promptSecret: false,
  // connect / saved servers
  servers: [],
  connectSelectedId: null,
  connectAuthMethod: 'publickey',
  _pendingConnectServer: null,  // server id set by openServerPickerForKey
  _pendingConnectKey: null,
  // multi-tab SSH sessions
  sessions: new Map(),   // tabId -> {tabId, sessionId, serverId, serverName, host, port, mode, sftpReady, sftpPath, ended}
  activeTabId: null,
};

// ─── vault gate ────────────────────────────────────────────────────────────

/// What the vault dialog says in each mode, and what it says while that
/// mode's request is running.
const VAULT_DIALOG_COPY = {
  create: {
    title: 'Create your vault',
    text: 'Choose a master password. It encrypts every private key at rest (Argon2id + AES-256-GCM). There is no recovery — if you lose it, the keys are gone.',
    primary: 'Create vault',
    busy: 'Creating vault…',
  },
  change: {
    title: 'Change master password',
    text: 'Every stored private key is re-encrypted with the new password before the vault accepts it.',
    primary: 'Change password',
    busy: 'Re-encrypting…',
    busyText: 'Re-encrypting your vault… This takes a few seconds per key; this dialog closes when it is done.',
  },
  unlock: {
    title: 'Unlock vault',
    text: 'Enter your master password to decrypt your keys for this session.',
    primary: 'Unlock',
    busy: 'Unlocking…',
  },
};

/// The submit that owns the vault dialog's busy state, and whether one is
/// running. A lock takes the dialog over in the middle of a request (see
/// closeDialogsForLock): it bumps the sequence, so the abandoned request's
/// late answer can neither close nor relabel the unlock gate that replaced it.
let vaultSubmitSeq = 0;
let vaultSubmitBusy = false;

/// Title, text and buttons for the current mode - and, while its request runs,
/// the busy state: the primary button says what is happening and takes no
/// second submit, and a master-password change cannot be cancelled (RU1 C1).
function paintVaultDialog() {
  const mode = state.vaultMode;
  const copy = VAULT_DIALOG_COPY[mode] || VAULT_DIALOG_COPY.unlock;
  const busy = vaultSubmitBusy;
  el('vaultModalTitle').textContent = copy.title;
  el('vaultModalText').textContent = busy && copy.busyText ? copy.busyText : copy.text;
  const primary = el('vaultPrimary');
  primary.textContent = busy ? copy.busy : copy.primary;
  primary.disabled = busy;
  if (busy) primary.setAttribute('aria-busy', 'true');
  else primary.removeAttribute('aria-busy');
  el('vaultCancelBtn').disabled = busy && mode === 'change';
}

/// A lock in the middle of a vault request: that request now belongs to a
/// vault that is locking, and its dialog is gone. Drop its busy state so the
/// unlock gate that follows is usable at once.
function releaseVaultSubmit() {
  if (!vaultSubmitBusy) return;
  vaultSubmitSeq += 1;
  vaultSubmitBusy = false;
  paintVaultDialog();
}

function showVaultModal(mode) {
  const backdrop = el('vaultModal');
  // refreshVaultStatus() runs on a 10s interval and calls straight back in
  // here while the dialog is already up. Clearing unconditionally therefore
  // wiped the master password every 10 seconds as the user typed it, which
  // made the vault impossible to create with anything longer than a short
  // password (and impossible to paste from a password manager). Only reset
  // the fields when the dialog is actually being opened, or switching mode.
  const reopening = backdrop.hidden || state.vaultMode !== mode;
  state.vaultMode = mode;
  const pw = el('vaultPassword');
  const confirmPw = el('vaultPasswordConfirm');
  const current = el('vaultPasswordCurrent');
  if (reopening) clearVaultFields();
  pw.hidden = false;
  confirmPw.hidden = mode !== 'create' && mode !== 'change';
  // The current password is re-typed instead of being cached in state, so the
  // master password is never retained in renderer memory after unlock.
  current.hidden = mode !== 'change';
  // In change mode the boxes run current, new, confirm (index.html keeps them
  // in that order) and say what they are. The first box used to be the NEW
  // password labelled "Master password", with "Current password" last - an easy
  // way to type the password you know into the wrong box, where a wrong guess
  // counts toward the unlock throttle.
  if (mode === 'change') {
    current.placeholder = 'Current master password';
    pw.placeholder = 'New master password';
    confirmPw.placeholder = 'Confirm new password';
  } else {
    current.placeholder = 'Current password';
    pw.placeholder = 'Master password';
    confirmPw.placeholder = 'Confirm password';
  }
  // The create copy names Argon2id, the KDF the vault really uses; it said
  // scrypt, at the one moment the user is told what protects the vault (A8-11).
  paintVaultDialog();
  backdrop.hidden = false;
  // Same reason as the field reset above: focusing on every poll would yank
  // the caret out of the confirm field back into the password field every
  // 10 seconds while the user is still filling the form in. In change mode the
  // first thing to type is the current password.
  if (reopening) (mode === 'change' ? current : pw).focus();
}

function clearVaultFields() {
  for (const id of ['vaultPassword', 'vaultPasswordConfirm', 'vaultPasswordCurrent']) el(id).value = '';
}

/// Close the vault dialog. Whatever was typed goes with it: a half-typed
/// master password must not sit in a hidden input.
function hideVaultModal() {
  clearVaultFields();
  el('vaultModal').hidden = true;
}

/// Cancel / Escape on the vault dialog. For the create and unlock gate this is
/// remembered (state.vaultDismissed): the status poll used to re-open the
/// dialog every 10 s and take the focus back, which made the app unusable
/// while locked and made the "Vault stays locked" toast a lie. The change-
/// password dialog is a deliberate request, not a gate, and just closes.
function dismissVaultModal() {
  // A master-password change that is running keeps its dialog (RU1 C1):
  // closing it mid-rotation is how the rest of the app came to write vault
  // data that was being re-sealed. Cancel is disabled meanwhile; this is the
  // Escape path. A lock still closes it (closeDialogsForLock).
  if (vaultSubmitBusy && state.vaultMode === 'change') return;
  const wasGate = state.vaultMode !== 'change';
  hideVaultModal();
  if (!wasGate) return;
  state.vaultDismissed = true;
  if (!state.unlocked) toast('Vault stays locked — unlock it any time.', 'info');
}

/// An explicit request to see the vault dialog (menu item, Ctrl+N, palette,
/// the Settings button). Unlike the automatic gate it always opens, and it
/// clears a dismissal: the user has asked again.
function requestVaultModal(mode) {
  state.vaultDismissed = false;
  showVaultModal(mode);
}

async function refreshVaultStatus(silent) {
  const s = await call('vault_status');
  const wasUnlocked = state.unlocked;
  const prevGate = state.vaultGate;
  state.hasVault = s.hasVault;
  state.unlocked = s.unlocked;

  const status = el('vaultStatus');
  const info = vaultStatusHTML(s.unlocked, s.hasVault);
  status.classList.remove('locked', 'unlocked', 'novault');
  status.classList.add(info.state);
  const vaultIcon = el('vaultIcon');
  if (vaultIcon) vaultIcon.innerHTML = info.icon;
  const lbl = el('vaultLabel');
  if (lbl) lbl.textContent = info.label;
  paintVaultChipName();
  const caret = el('vaultCaret');
  if (caret) caret.innerHTML = s.unlocked || s.hasVault ? ico('chevron-down') : '';
  el('newKeyBtn').disabled = !s.unlocked;
  applyNavLockState();
  applyLockGates();
  updateNavCounts();

  // The idle clock, BEFORE anything below that can wait or fail. Only a
  // TRANSITION touches it here: the poll runs every 10 s whatever the user is
  // doing, so letting it re-arm the timer (as this used to) pushed the deadline
  // out forever and the vault never auto-locked. And because the transition is
  // seen exactly once - the next poll finds the vault already unlocked - it must
  // not wait for the key load, which can take a while. When that load could
  // still reject (before loadCategories() caught its own failures), arming after
  // it left auto-lock off until Settings was opened.
  if (!s.unlocked) cancelAutoLockTimer();
  else if (!wasUnlocked) {
    noteUserActivity();   // unlocking is the user acting
    armAutoLockTimer();
  }

  // Which gate (if any) the vault state calls for. A CHANGE in that - the vault
  // locking, being created, being unlocked elsewhere - re-arms the dialog; the
  // same state seen again on the next poll must leave a dismissed one closed.
  const gate = !s.hasVault ? 'create' : (!s.unlocked ? 'unlock' : null);
  state.vaultGate = gate;
  if (wasUnlocked && !s.unlocked) onVaultLocked();
  if (gate !== prevGate) state.vaultDismissed = false;

  if (gate === 'create') {
    if (!state.vaultDismissed) showVaultModal('create');
  } else if (gate === 'unlock') {
    clearKeysUI();
    clearConnectView();
    if (!state.vaultDismissed) showVaultModal('unlock');
  } else {
    // Unlocked. The create/unlock gate has done its job and goes; the change-
    // password dialog is open on purpose and must outlive every poll (it used
    // to be closed under the user's hands within 10 s).
    if (state.vaultMode !== 'change') hideVaultModal();
    if (!wasUnlocked || !silent) await loadKeys();
  }
}

/// Counts beside the two nav destinations. The Servers count is deliberately
/// the number of LIVE sessions, not of saved servers: how many shells you have
/// open is the thing you lose track of, and it is the only number that changes
/// while you are not looking at that view.
function updateNavCounts() {
  const keyCount = el('navKeyCount');
  if (keyCount) {
    const n = state.keys.length;
    keyCount.hidden = !state.unlocked || n === 0;
    keyCount.textContent = String(n);
  }
  const live = el('navSessionCount');
  if (live) {
    let n = 0;
    for (const tabId of state.sessions.keys()) {
      if (window.tabSessionLive && window.tabSessionLive(tabId)) n += 1;
    }
    live.hidden = n === 0;
    live.textContent = String(n);
  }
}
window.updateNavCounts = updateNavCounts;

/// The vault menu: state, countdown and both vault actions in one control.
function openVaultMenu(anchor) {
  let items;
  if (!state.hasVault) {
    items = [{ label: 'Create a vault...', icon: 'lock', onSelect: () => requestVaultModal('create') }];
  } else if (!state.unlocked) {
    items = [{ label: 'Unlock vault...', icon: 'lock-open', onSelect: () => requestVaultModal('unlock') }];
  } else {
    items = [
      { label: 'Lock now  (Ctrl+L)', icon: 'lock', onSelect: lockNow },
      { label: 'Change master password...', icon: 'key-round', onSelect: () => requestVaultModal('change') },
      'sep',
      { label: 'Auto-lock settings...', icon: 'settings', onSelect: () => { switchView('settings'); showSettingsSection('general'); } },
    ];
  }
  // Anchored above the control: it sits at the bottom of the sidebar, so a
  // menu dropped below it would open off-screen.
  openMenu(anchor, items, { above: true, label: 'Vault' });
}

// Lock/unlock the nav buttons that require an unlocked vault (Servers).
function applyNavLockState() {
  for (const b of document.querySelectorAll('.nav-item[data-requires-unlock]')) {
    b.classList.toggle('locked', !state.unlocked);
    b.disabled = !state.unlocked;
    // A disabled item says why, not just its shortcut (A5-31).
    if (b.dataset.unlockedTitle === undefined) b.dataset.unlockedTitle = b.title;
    b.title = state.unlocked ? b.dataset.unlockedTitle : 'Unlock the vault to use ' + (b.getAttribute('aria-label') || 'this');
    if (!state.unlocked && b.classList.contains('active')) {
      switchView('keys');
    }
  }
}

/// Controls whose command the backend refuses while the vault is locked, with
/// a bare "Vault is locked." (A6-08): clearing the audit log, forgetting a
/// pinned host key, every category change, and the four security settings
/// (autoLockMinutes, confirmDelete, autoUpdateCheck, confirmMultiLinePaste).
/// Settings, the known hosts and the category tree all stay on screen while
/// locked, so these are disabled then, with a tooltip that says why, instead
/// of offering a click that can only fail.
const LOCK_GATE_HINTS = {
  audit: 'Unlock the vault to clear the audit log.',
  hosts: 'Unlock the vault to forget a pinned host key.',
  categories: 'Unlock the vault to change categories.',
  settings: 'Unlock the vault to change this.',
};

/// Mark `control` as needing an unlocked vault (`kind` picks the reason) and
/// set it for the current state. Its own tooltip comes back on unlock.
function lockGate(control, kind) {
  if (!control) return;
  control.dataset.lockGate = kind;
  if (control.dataset.unlockedTitle === undefined) control.dataset.unlockedTitle = control.title || '';
  applyLockGate(control);
}

function applyLockGate(control) {
  const locked = !state.unlocked;
  // One reason among others (setDisabledFor): unlocking lifts the lock's
  // reason only, so a control that is busy, or disabled for a reason of its
  // own, stays disabled.
  setDisabledFor(control, 'lock', locked);
  control.title = locked ? (LOCK_GATE_HINTS[control.dataset.lockGate] || '') : control.dataset.unlockedTitle;
}

/// Re-apply every gate after a vault state change. Run from every status
/// refresh, so a lock from the tray or the idle watchdog is picked up too.
function applyLockGates() {
  for (const n of document.querySelectorAll('[data-lock-gate]')) applyLockGate(n);
  for (const n of document.querySelectorAll('[data-lock-hint]')) n.hidden = state.unlocked;
  for (const n of document.querySelectorAll('#catTree .cat-node:not(.uncategorized)')) n.draggable = state.unlocked;
}

/// The same rule for the actions behind those controls, for a menu or a drag
/// begun before the lock: false (with the reason) while locked.
function lockGateOpen(kind) {
  if (state.unlocked) return true;
  toast(LOCK_GATE_HINTS[kind], 'info');
  return false;
}

// Called when the vault locks or while the connect view is shown without an unlocked vault.
function clearConnectView() {
  state.servers = [];
  state.serversLoadError = null;
  state.connectSelectedId = null;
  if (typeof window.terminalResetActive === 'function') window.terminalResetActive();
  const list = el('serverList'); if (list) list.innerHTML = '';
  const empty = el('serverEmpty'); if (empty) empty.hidden = true;
  el('termTitle').textContent = 'No connection';
  el('termBadge').hidden = true;
  el('termTestBtn').hidden = true;
  el('termReconnectBtn').hidden = true;
  el('termDisconnectBtn').hidden = true;
  el('termStrip').textContent = state.unlocked ? 'Ready.' : 'Unlock the vault to connect.';
  state._pendingConnectServer = null;
  state._pendingConnectKey = null;
  // Close every session tab.
  for (const tabId of [...state.sessions.keys()]) {
    const tab = state.sessions.get(tabId);
    if (tab && window.tabSessionLive(tabId)) {
      call('terminal_disconnect', { sessionId: tab.sessionId }).catch(() => {});
    }
    if (tab && tab.sftpReady) call('sftp_close', { sessionId: tab.sessionId || '' }).catch(() => {});
    window.destroyTabTerminal(tabId);
    state.sessions.delete(tabId);
    // Its assistant conversation, pending approval and access level go too.
    window.assistantClearTab?.(tabId);
  }
  state.activeTabId = null;
  const sbody = document.getElementById('sftpBody');
  if (sbody) {
    sbody.classList.remove('visible');
    // closeSessionTab removes a closing tab's SFTP panel; the lock path only
    // hid them, so one DOM subtree per session accumulated across every
    // lock/unlock cycle. Remove them here too.
    for (const child of [...sbody.querySelectorAll('[id^="sftpPanel-"]')]) child.remove();
  }
  const tbody = document.getElementById('terminalBody');
  if (tbody) tbody.style.display = 'flex';
  renderTermTabs();
}

/// The backend's answer when a lock lands while a master-password change, a
/// backup export or a restore is running and aborts it before anything is
/// committed or written.
const VAULT_LOCKED_MIDWAY = 'Vault was locked while the operation was in progress.';

async function submitVaultModal() {
  // Re-entrancy guard. The button was not disabled while the request was in
  // flight, so a double click - or Enter held down, which repeats - submitted
  // twice; a second vault_create answers "A vault already exists" right after
  // the success toast, and a second wrong guess counts toward the throttle.
  if (vaultSubmitBusy) return;
  const mode = state.vaultMode;
  const pwEl = el('vaultPassword');
  const currentEl = el('vaultPasswordCurrent');
  const pw = pwEl.value;
  const confirmPw = el('vaultPasswordConfirm').value;
  const current = currentEl.value;
  const seq = ++vaultSubmitSeq;
  // From here until the answer: busy button, no second submit, and in change
  // mode no Cancel - vault_change_password re-seals every record off the main
  // thread and can take seconds per key.
  const busy = () => { vaultSubmitBusy = true; paintVaultDialog(); };
  try {
    if (mode === 'create') {
      if (pw.length < 8) throw new Error('Master password must be at least 8 characters.');
      if (pw !== confirmPw) throw new Error('Passwords do not match.');
      busy();
      await call('vault_create', { password: pw });
      toast('Vault created. Welcome to SSHSpan.', 'ok');
    } else if (mode === 'change') {
      if (pw.length < 8) throw new Error('New password must be at least 8 characters.');
      if (pw !== confirmPw) throw new Error('Passwords do not match.');
      if (!current) throw new Error('Enter your current master password.');
      busy();
      await call('vault_change_password', { currentPassword: current, newPassword: pw });
      toast('Master password changed; all keys re-encrypted.', 'ok');
    } else {
      busy();
      await call('vault_unlock', { password: pw });
      toast('Vault unlocked.', 'ok');
    }
    // Never leave submitted passwords in the DOM inputs; this also closes the
    // dialog (the change-password dialog is not closed by the status refresh) -
    // unless a lock took the dialog over meanwhile: it is the unlock gate now.
    if (seq === vaultSubmitSeq) hideVaultModal();
    await refreshVaultStatus();
    if (mode === 'change' && !state.unlocked) {
      // The change committed, then a lock landed (tray, idle watchdog) before
      // the new password took over: the vault stays locked, and it is the NEW
      // password that opens it now.
      toast('The vault locked while the password was being changed - unlock it with the new master password.', 'info');
    }
  } catch (e) {
    const msg = e.message || String(e);
    if (msg === VAULT_LOCKED_MIDWAY) {
      toast('The vault was locked while the password was being changed, so nothing was changed - your current master password still unlocks it.', 'err');
      refreshVaultStatus().catch(() => {});
    } else {
      toast(msg, 'err');
    }
    // Put the caret on the box that was wrong: a bad current password is the
    // first box in change mode, everything else is the (new) password. Not
    // once a lock has replaced this dialog with the unlock gate.
    if (seq === vaultSubmitSeq && state.vaultMode === mode) {
      (mode === 'change' && /current/i.test(msg) ? currentEl : pwEl).select();
    }
  } finally {
    if (seq === vaultSubmitSeq) {
      vaultSubmitBusy = false;
      paintVaultDialog();
    }
  }
}

// ─── keys view ─────────────────────────────────────────────────────────────

function clearKeysUI() {
  state.keys = [];
  state.keysLoadError = null;
  state.selectedId = null;
  state.deploySelected.clear();
  el('keyList').innerHTML = '';
  el('detailPane').hidden = true;
  el('emptyState').hidden = false;
  state.keyCategories = {};
  state.orphans = false;
  updateSelectionHint();
  updateBreadcrumb();
}

function openTerminalContextMenu(x, y, tabId) {
  closeKeyConnectMenu();
  const tab = state.sessions.get(tabId);
  if (!tab) return;
  // After the action, hand the focus back to the terminal so the user can keep
  // typing without re-clicking the surface.
  const act = (fn) => () => {
    fn();
    try { window.tabRecord(tabId)?.term.focus(); } catch (e) {}
  };
  const server = () => state.servers.find(s => s.id === tab.serverId);
  openMenu({ x, y }, [
    { label: 'Copy', icon: 'copy', onSelect: act(() => window.terminalCopySelection(tabId)) },
    { label: 'Copy all to clipboard', icon: 'copy', onSelect: act(() => window.terminalCopyAll(tabId)) },
    { label: 'Paste', icon: 'clipboard', onSelect: act(async () => window.terminalPaste(tabId, await window.terminalReadClipboard())) },
    'sep',
    { label: 'Clear scrollback', icon: 'eraser', onSelect: act(() => window.terminalClearScrollback(tabId)) },
    { label: 'Reset terminal', icon: 'rotate-ccw', onSelect: act(() => window.terminalReset(tabId)) },
    'sep',
    { label: 'New session', icon: 'plus', onSelect: act(() => { const srv = server(); if (srv) openSessionTab(srv); }) },
    { label: 'Duplicate session', icon: 'copy', onSelect: act(() => { const srv = server(); if (srv) openSessionTab(srv); }) },
    { label: 'Restart session', icon: 'refresh-cw', onSelect: act(() => reconnectActiveTab()) },
    { label: tab.mode === 'sftp' ? 'Switch to terminal' : 'Switch to SFTP', icon: 'folder-tree',
      disabled: !window.tabSessionLive(tabId), onSelect: act(() => window.toggleSshSftpMode()) },
  ], { label: 'Terminal' });
}

function markTerminalBell(tabId) {
  const tab = state.sessions.get(tabId);
  if (!tab) return;
  tab.bell = true;
  renderTermTabs();
}
window.markTerminalBell = markTerminalBell;

/// The selection bar is the whole of what used to be the Deploy view's entry
/// point. It appears where the selection is, so no instruction to go and tick
/// boxes somewhere else is needed.
function updateSelectionHint() {
  const n = state.deploySelected.size;
  const bar = el('selectionBar');
  if (bar) bar.hidden = n === 0;
  const hint = el('selectionHint');
  if (hint) hint.textContent = n === 1 ? '1 key selected' : n + ' keys selected';
  const sub = el('viewSubtitle');
  if (sub && state.view === 'keys') {
    const total = state.keys.length;
    const deployed = state.keys.filter(k => k.deployed).length;
    sub.textContent = n > 0
      ? n + ' of ' + total + ' selected'
      : (total === 0 ? '' : total + (total === 1 ? ' key' : ' keys') + ' · ' + deployed + ' deployed');
  }
  updateNavCounts();
}

function renderKeyList() {
  const list = el('keyList');
  // Every row is rebuilt. The row that had the focus - or its checkbox or
  // Connect button - gets it back at the end, or a keyboard user lands at the
  // top of the page after every selection (A1-26).
  const had = list.contains(document.activeElement) ? document.activeElement : null;
  const hadRow = had && had.closest('.key-row');
  const refocus = hadRow && {
    id: hadRow.dataset.id,
    part: had.classList.contains('deploy-check') ? '.deploy-check' : (had.classList.contains('row-btn') ? '.row-btn' : null),
  };
  const restoreFocus = () => {
    if (!refocus) return;
    const row = [...list.querySelectorAll('.key-row')].find((r) => r.dataset.id === refocus.id);
    const target = row && (refocus.part ? row.querySelector(refocus.part) : row);
    if (target) target.focus();
  };
  list.innerHTML = '';
  if (state.keysLoadError) {
    // Not "No keys yet": the keys could not be read (A5-21).
    el('emptyState').hidden = true;
    const chip = el('keyCount');
    if (chip) chip.hidden = true;
    renderLoadError(list, 'Could not load your keys', state.keysLoadError, loadKeys);
    return;
  }
  const rows = filteredKeys();
  const total = state.keys.length;
  el('emptyState').hidden = total > 0;
  const countChip = el('keyCount');
  if (countChip) {
    if (total > 0) {
      countChip.hidden = false;
      countChip.textContent = total === 1 ? '1 key' : total + ' keys';
    } else {
      countChip.hidden = true;
    }
  }
  if (rows.length === 0) return;

  // When a category filter is active, render a single (un-grouped) flat list.
  if (activeCategoryId() !== 'all') {
    const flat = document.createElement('div');
    flat.className = 'key-group';
    for (const k of rows) flat.appendChild(keyRowEl(k));
    list.appendChild(flat);
    restoreFocus();
    return;
  }

  // Grouped: by category (or uncategorized if no cats).
  // First, build the group order: roots in sort_index order; for each, walk sub-tree.
  const groups = []; // { id: 'cat:<rootId>' | 'uncategorized', name, keys[] }
  const seen = new Set();
  /// state.keyCategories maps a key id to category *ids*, not to category
  /// objects. Resolving them is what makes the walk to the root ancestor work
  /// at all - reading .parent_id straight off a string yields undefined, which
  /// is how every categorized key used to end up in no group and so render
  /// nowhere in this view.
  const catsOf = (k) => (state.keyCategories[k.id] || []).map(catById).filter(Boolean);
  /// The root ancestor of a category, tolerating a parent chain that a
  /// restored or hand-edited vault left dangling or circular.
  const rootOf = (cat) => {
    let top = cat;
    const chain = new Set([top.id]);
    while (top.parent_id) {
      const parent = catById(top.parent_id);
      if (!parent || chain.has(parent.id)) break;
      chain.add(parent.id);
      top = parent;
    }
    return top;
  };
  const groupFor = (id, name) => {
    let g = groups.find(g => g.id === id);
    if (!g) { g = { id, name, keys: [] }; groups.push(g); }
    return g;
  };
  // Render groups in a stable order: roots in sort_index order; uncategorized
  // last. A category whose parent no longer exists is a root too, or the keys
  // filed under it would belong to no group and so render nowhere.
  const rootCats = state.categories
    .filter(c => c.scope === 'key' && (!c.parent_id || !catById(c.parent_id)))
    .sort((a, b) => a.sort_index - b.sort_index || a.name.localeCompare(b.name));
  /// `rows`, not state.keys: this walk used to read the full vault, so the
  /// search box and the type filter did nothing at all in the default grouped
  /// view - the only visible effect of a query was the all-or-nothing
  /// `rows.length === 0` bail above. With no filter active `rows` is the whole
  /// vault in the same order, so grouping and ordering are unchanged.
  for (const root of rootCats) {
    // A key appears once per root ancestor it has a category under - the
    // natural "EU DC1" vs "Asia DC1" grouping - and only once per root even
    // when several of its categories share one. The group is named for that
    // root, since naming it after one descendant would misdescribe what it
    // collects. Walking roots outer and keys inner is what keeps both the
    // group order and the order within each group stable.
    for (const k of rows) {
      if (!catsOf(k).some(c => rootOf(c).id === root.id)) continue;
      const id = 'cat:' + root.id;
      if (seen.has(id + ':' + k.id)) continue;
      seen.add(id + ':' + k.id);
      groupFor(id, catPathString(root.id)).keys.push(k);
    }
  }
  for (const k of rows) {
    if (!catsOf(k).length) groupFor('uncategorized', 'Uncategorized').keys.push(k);
  }

  for (const g of groups) {
    const grp = document.createElement('div');
    grp.className = 'key-group';
    grp.dataset.group = g.id;
    const head = document.createElement('div');
    head.className = 'key-group-head';
    const name = document.createElement('span');
    name.className = 'key-group-name';
    name.textContent = g.name;
    head.appendChild(name);
    const expandBtn = document.createElement('button');
    expandBtn.className = 'icon-btn';
    // The Set tracks COLLAPSED group ids (absent = expanded, the default).
    // The handler must write the toggle back into it: renderKeyList rebuilds
    // the whole list (search, select, category switch), and a choice kept
    // only on the old DOM node popped back open on the next render.
    const collapsed = state.groupExpanded.has(g.id);
    if (collapsed) {
      grp.classList.add('collapsed');
    }
    expandBtn.innerHTML = ico(collapsed ? 'plus' : 'minus');
    expandBtn.title = collapsed ? 'Expand group' : 'Collapse group';
    expandBtn.addEventListener('click', () => {
      const nowCollapsed = grp.classList.toggle('collapsed');
      if (nowCollapsed) state.groupExpanded.add(g.id);
      else state.groupExpanded.delete(g.id);
      expandBtn.innerHTML = ico(nowCollapsed ? 'plus' : 'minus');
      expandBtn.title = nowCollapsed ? 'Expand group' : 'Collapse group';
    });
    head.appendChild(expandBtn);
    grp.appendChild(head);
    for (const k of g.keys) grp.appendChild(keyRowEl(k, g.keys));
    list.appendChild(grp);
  }
  restoreFocus();
}

function keyRowEl(k, groupKeys) {
  const row = document.createElement('div');
  row.className = 'key-row' + (k.id === state.selectedId ? ' selected' : '');
  row.dataset.id = k.id;
  // Keyboard-operable (A1-11): a tab stop that opens the key on Enter/Space,
  // like the click - a public-only key has no other control on its row.
  row.tabIndex = 0;
  row.setAttribute('role', 'button');
  row.setAttribute('aria-label', (k.name || '(unnamed)') + ' - ' + k.key_type);
  if (k.id === state.selectedId) row.setAttribute('aria-current', 'true');
  row.addEventListener('keydown', (ev) => {
    if (ev.target !== row || (ev.key !== 'Enter' && ev.key !== ' ')) return;
    ev.preventDefault();
    selectKey(k.id);
  });

  const cb = document.createElement('input');
  cb.type = 'checkbox';
  cb.className = 'deploy-check';
  cb.checked = state.deploySelected.has(k.id);
  cb.title = 'Include in deploy';
  cb.addEventListener('click', (ev) => {
    ev.stopPropagation();
    if (cb.checked) state.deploySelected.add(k.id);
    else state.deploySelected.delete(k.id);
    updateSelectionHint();
  });
  row.appendChild(cb);
  row.appendChild(keyAvatar(k.key_type));

  const main = document.createElement('div');
  main.className = 'key-row-main';
  const name = document.createElement('div');
  name.className = 'key-row-name';
  name.textContent = k.name || '(unnamed)';
  if (!k.has_private) {
    const pub = document.createElement('span');
    pub.className = 'badge pub';
    pub.textContent = 'public only';
    name.appendChild(pub);
  }
  const cats = state.keyCategories[k.id] || [];
  if (cats.length > 1) {
    // "in N categories" badge - only show if this key appears in more than one category.
    // We only know the count locally; "appears in more than one group" depends on group structure.
    const distinctTop = new Set();
    for (const cid of cats) { let t = cid; while (true) { const c = catById(t); if (!c) break; if (!c.parent_id) { distinctTop.add(c.id); break; } t = c.parent_id; } }
    if (distinctTop.size > 1) {
      const b = document.createElement('span');
      b.className = 'badge dim';
      b.title = 'Belongs to ' + cats.length + ' categories';
      b.textContent = 'in ' + cats.length;
      name.appendChild(b);
    }
  }
  /// The row used to lead with the full SHA-256 fingerprint: 50-odd
  /// undifferentiated base64 characters, in mono, on every row. Nobody scans a
  /// list by fingerprint - they scan by what the key is for. The fingerprint is
  /// one click away in the detail pane, which is where you compare it anyway.
  const sub = document.createElement('div');
  sub.className = 'key-row-sub';
  sub.textContent = k.comment || '';
  sub.title = k.comment || ''; // the line ends in "..." when it is long (A1-35)
  sub.hidden = !k.comment;
  main.appendChild(name);
  main.appendChild(sub);
  row.appendChild(main);

  const actions = document.createElement('div');
  actions.className = 'key-row-actions';
  if (k.deployed) {
    const dep = document.createElement('span');
    dep.className = 'chip ok';
    dep.title = 'A copy of this key is deployed on this machine';
    dep.innerHTML = `${ico('check-circle')}<span>Deployed</span>`;
    actions.appendChild(dep);
  }
  if (k.has_private) {
    // Connecting with a key was reachable only by right-clicking the row, which
    // nothing on screen suggested. Same menu, now with an affordance.
    const conn = document.createElement('button');
    conn.className = 'ghost-btn row-btn';
    conn.title = 'Use this key to connect...';
    conn.innerHTML = `${ico('plug-zap')}<span>Connect</span>`;
    conn.addEventListener('click', (ev) => {
      ev.stopPropagation();
      selectKey(k.id);
      const r = conn.getBoundingClientRect();
      openKeyConnectMenu(r.left, r.bottom + 4, k);
    });
    actions.appendChild(conn);
  }
  row.appendChild(actions);
  row.appendChild(typeBadge(k.key_type));
  row.addEventListener('click', () => selectKey(k.id));
  row.addEventListener('contextmenu', (ev) => {
    if (!k.has_private) return; // can't connect with a public-only key
    ev.preventDefault();
    selectKey(k.id);
    openKeyConnectMenu(ev.clientX, ev.clientY, k);
  });
  return row;
}

// Tiny right-click menu: "Use this key to connect...".
function openKeyConnectMenu(x, y, key) {
  openMenu({ x, y }, [{
    label: 'Use this key to connect...', icon: 'plug-zap',
    onSelect: async () => {
      if (!state.unlocked) {
        toast('Unlock the vault to connect.', 'err');
        return;
      }
      // Pick one of the existing servers; the chosen server's saved username is
      // kept but its key is overridden with this one at connect time. The picker
      // loads the server list if the Connect view has never been opened, and
      // falls back to the new-server modal when there genuinely are none - the
      // emptiness check cannot happen out here, because state.servers is only
      // populated by switchView('connect').
      await openServerPickerForKey(key, x, y);
    },
  }], { label: 'Key' });
}
/// Close whatever menu is open. o.restoreFocus (Escape, a chosen item) puts
/// the focus back on what had it when the menu opened; a click elsewhere
/// leaves it where that click put it.
function closeKeyConnectMenu(o) {
  const menuState = activeMenu;
  activeMenu = null;
  if (menuState) {
    menuState.cleanup();
    if (menuState.anchor && menuState.anchor.hasAttribute('aria-expanded')) menuState.anchor.setAttribute('aria-expanded', 'false');
  }
  const m = document.getElementById('keyConnectMenu');
  if (m && m.parentNode) m.parentNode.removeChild(m);
  if (menuState) {
    const back = menuState.anchor || menuState.opener;
    if (o && o.restoreFocus && back && document.contains(back)) back.focus();
    if (typeof menuState.onClose === 'function') menuState.onClose();
  }
  // Host-picker flyouts are body-level elements rather than children of the
  // row that opened them, so removing the root menu alone would leave them
  // floating over the page.
  for (const sub of document.querySelectorAll('.ctx-submenu')) sub.remove();
  hostPickerCancelClose();
  if (hostPickerAwayHandler) {
    document.removeEventListener('mousedown', hostPickerAwayHandler);
    document.removeEventListener('keydown', hostPickerAwayHandler);
    hostPickerAwayHandler = null;
  }
}

async function loadKeys() {
  try {
    const res = await call('key_list');
    state.keys = (res.keys || []).map(k => ({ ...k, category_ids: k.category_ids || [] }));
    state.keysLoadError = null;
  } catch (e) {
    state.keys = [];
    state.keysLoadError = e.message || String(e);
    toast(state.keysLoadError, 'err');
  }
  // Never rejects: a failure is reported in a toast (A2-20).
  await loadCategories();
  renderKeyList();
  updateSelectionHint();
  if (state.selectedId && state.keys.some(k => k.id === state.selectedId)) {
    await selectKey(state.selectedId);
  } else if (state.keys.length > 0 && !state.selectedId) {
    await selectKey(state.keys[0].id);
  } else if (!state.selectedId) {
    el('detailPane').hidden = true;
  }
}

async function selectKey(id) {
  state.selectedId = id;
  renderKeyList();
  const pane = el('detailPane');
  try {
    const k = await call('key_get', { id });
    pane.hidden = false;
    // A different key means a different set of secrets: never carry the Export
    // tab (or a typed passphrase) across from the key you were just looking at.
    showDetailTab('overview');
    el('detailName').textContent = k.name || '(unnamed)';
    const dType = el('detailType');
    dType.dataset.kind = String(k.key_type || '').split('-')[0];
    dType.textContent = k.key_type + (k.has_private ? '' : ' \u00b7 public only');
    const avatar = el('detailAvatar');
    if (avatar) {
      avatar.dataset.type = String(k.key_type || '').split('-')[0];
      avatar.innerHTML = ico('key-square');
    }
    const meta = el('detailMeta');
    meta.innerHTML = '';
    const add = (label, value, mono) => {
      if (value === undefined || value === null || value === '') return;
      const dt = document.createElement('dt');
      dt.textContent = label;
      const dd = document.createElement('dd');
      dd.textContent = String(value);
      if (mono) dd.classList.add('mono');
      meta.appendChild(dt);
      meta.appendChild(dd);
    };
    add('Comment', k.comment);
    add('Created', fmtTime(k.created_at), true);
    add('Deployed', k.deployed ? k.deploy_path : 'no', true);
    add('Bitwarden sync', k.bitwarden_sync ? 'yes' : 'no');
    add('Private key', k.has_private ? 'sealed · AES-256-GCM' : 'not stored');
    // Categories
    const catIds = k.category_ids || [];
    state.keyCategories[k.id] = catIds;
    renderCategoryChips(el('detailCategories'), catIds, {
      removable: true,
      onRemove: async (catId) => {
        const next = catIds.filter(x => x !== catId);
        try { await call('key_set_categories', { keyId: k.id, categoryIds: next }); await loadKeys(); }
        catch (e) { toast(e.message || String(e), 'err'); }
      },
      onClickPath: (catId) => { setActiveCategory(catId); },
    });
    /// The "+" chip replaces a "Browse categories..." button that opened a modal
    /// over whatever you were doing. It is the same picker, reached from the
    /// chips it edits rather than from a button below them.
    const addChip = document.createElement('button');
    addChip.className = 'cat-chip add-chip';
    addChip.title = 'Add this key to a category';
    addChip.innerHTML = `${ico('plus')}<span>Add</span>`;
    addChip.addEventListener('click', () => openCategoryPicker({
      title: 'Assign categories',
      initial: catIds,
      onSave: async (ids) => {
        try { await call('key_set_categories', { keyId: k.id, categoryIds: ids }); await loadKeys(); toast('Categories updated.', 'ok'); }
        catch (e) { toast(e.message || String(e), 'err'); }
      },
    }));
    el('detailCategories').appendChild(addChip);

    el('detailFingerprint').textContent = k.fingerprint_sha256 || '\u2014';
    el('detailAuthorized').value = k.public_key || '';
    el('detailConnectBtn').disabled = !k.has_private;
    renderExportFormats(k);
  } catch (e) {
    pane.hidden = true;
    toast(e.message || String(e), 'err');
  }
}

async function deleteSelected() {
  if (!state.selectedId) return;
  // The key the user is asked about is the key that gets deleted, whatever
  // happens to the selection while the dialog is open.
  const id = state.selectedId;
  const k = state.keys.find(x => x.id === id);
  if (settingOn(state.settings.confirmDelete)) {
    const ok = await confirmModal('Delete key',
      'Delete key "' + (k ? k.name : id) + '" from the vault?\nDeployed copies on disk are not removed.',
      'Delete');
    if (!ok) return;
  }
  try {
    await call('key_delete', { id });
    state.deploySelected.delete(id);
    state.selectedId = null;
    toast('Key deleted.', 'ok');
    await loadKeys();
    updateSelectionHint();
  } catch (e) {
    toast(e.message || String(e), 'err');
  }
}

/// Bulk delete from the selection bar. Separate from deleteSelected(), which
/// acts on the one key open in the detail pane; the checkbox selection and the
/// detail selection are different things and conflating them would delete keys
/// the user was only looking at.
async function deleteSelectedKeys() {
  const ids = [...state.deploySelected];
  if (!ids.length) return;
  const names = ids.map(id => {
    const k = state.keys.find(x => x.id === id);
    return k ? (k.name || '(unnamed)') : id;
  });
  const listed = names.slice(0, 8).join('\n  ');
  const more = names.length > 8 ? `\n  ...and ${names.length - 8} more` : '';
  if (settingOn(state.settings.confirmDelete)) {
    const ok = await confirmModal('Delete keys',
      `Delete ${ids.length} key(s) from the vault?\n\n  ${listed}${more}\n\nDeployed copies on disk are not removed.`,
      'Delete');
    if (!ok) return;
  }
  let failed = 0;
  for (const id of ids) {
    try { await call('key_delete', { id }); } catch (e) { failed += 1; }
  }
  state.deploySelected.clear();
  if (ids.includes(state.selectedId)) {
    state.selectedId = null;
    el('detailPane').hidden = true;
  }
  await loadKeys();
  updateSelectionHint();
  toast(failed
    ? `${ids.length - failed} deleted, ${failed} failed.`
    : `${ids.length} key(s) deleted.`, failed ? 'err' : 'ok');
}

async function copyPublic() {
  if (!state.selectedId) return;
  try {
    const k = state.keys.find(x => x.id === state.selectedId);
    if (!k) return;
    const ok = await copyText(k.public_key || '');
    toast(ok ? 'Public key copied to clipboard.' : 'Clipboard unavailable.', ok ? 'ok' : 'err');
  } catch (e) {
    toast(e.message || String(e), 'err');
  }
}

const EXPORT_EXT = {
  'openssh-private': '',
  'ppk': '.ppk',
  'pkcs8': '.pem',
  'public-pem': '.pub',
  'authorized_keys': '.authorized_keys'
};

// Formats whose output is PRIVATE key material. These are exported through
// `key_export_to_file` - the backend serializes straight into a user-chosen
// file so the decrypted key never crosses the IPC boundary into the WebView.
const PRIVATE_EXPORT_FORMATS = ['openssh-private', 'ppk', 'pkcs8', 'pkcs8-encrypted'];

// Formats that wrap the private key in a passphrase. Only these show the
// passphrase field; it used to sit on screen permanently, including for the
// four formats that ignore it and the two that carry no private key at all.
const SEALED_EXPORT_FORMATS = ['pkcs8-encrypted'];

/// What each format actually hands you, in the terms that matter when you are
/// about to write it to a file someone else might read.
const EXPORT_FORMATS = [
  { id: 'openssh-private', name: 'OpenSSH private key', sub: 'The usual id_ed25519 file. Unprotected.', risk: 'secret' },
  { id: 'ppk', name: 'PuTTY private key (.ppk v3)', sub: 'For PuTTY, WinSCP and FileZilla on Windows.', risk: 'secret' },
  { id: 'pkcs8-encrypted', name: 'PKCS#8 PEM, encrypted', sub: 'Wrapped with a passphrase you choose below.', risk: 'sealed' },
  { id: 'pkcs8', name: 'PKCS#8 PEM, unencrypted', sub: 'Plain private key in PEM form.', risk: 'secret' },
  { id: 'public-pem', name: 'Public key PEM (SPKI)', sub: 'No private material. Safe to hand out.', risk: 'public' },
  { id: 'authorized_keys', name: 'authorized_keys line', sub: 'One line to paste on the remote host.', risk: 'public' },
];

const RISK_LABEL = { secret: 'Secret', sealed: 'Sealed', public: 'Public' };

/// Renders the Export tab's format list and keeps the hidden <select> (which
/// exportSelected() reads) in step with it.
function renderExportFormats(k) {
  const list = el('exportFormatList');
  if (!list) return;
  const sel = el('detailExportFormat');
  const available = EXPORT_FORMATS.filter(f =>
    k.has_private || PRIVATE_EXPORT_FORMATS.indexOf(f.id) === -1);
  if (!available.some(f => f.id === sel.value)) sel.value = available[0] ? available[0].id : '';

  list.innerHTML = '';
  for (const f of available) {
    const row = document.createElement('button');
    row.type = 'button';
    row.className = 'format-row' + (sel.value === f.id ? ' selected' : '');
    row.setAttribute('role', 'radio');
    row.setAttribute('aria-checked', sel.value === f.id ? 'true' : 'false');
    row.dataset.format = f.id;
    row.innerHTML =
      `<span class="format-radio"></span>` +
      `<span class="format-text"><span class="format-name">${escapeHtml(f.name)}</span>` +
      `<span class="format-sub">${escapeHtml(f.sub)}</span></span>` +
      `<span class="risk-chip ${f.risk}">${RISK_LABEL[f.risk]}</span>`;
    row.addEventListener('click', () => { sel.value = f.id; renderExportFormats(k); });
    list.appendChild(row);
  }
  syncExportControls();
}

/// The passphrase field appears only when the chosen format uses one, and the
/// button says what pressing it does - a private-key export opens a save dialog
/// in the Rust process; a public one downloads straight away.
function syncExportControls() {
  const format = el('detailExportFormat').value;
  const sealed = SEALED_EXPORT_FORMATS.indexOf(format) !== -1;
  el('detailExportPass').hidden = !sealed;
  el('exportPassLabel').hidden = !sealed;
  if (!sealed) el('detailExportPass').value = '';
  const isPrivate = PRIVATE_EXPORT_FORMATS.indexOf(format) !== -1;
  el('detailExportBtnLabel').textContent = isPrivate ? 'Choose where to save...' : 'Export';
  el('exportHint').textContent = isPrivate
    ? 'Private material is serialised in the Rust process and written straight to the file you pick - it never crosses into this window.'
    : 'This format carries no private key material.';
}

/// Overview / Export. Switching away from Export clears any typed passphrase:
/// leaving a secret in a field you cannot see is how it ends up in a screenshot.
function showDetailTab(tab) {
  for (const b of document.querySelectorAll('.detail-tab')) {
    const on = b.dataset.detailTab === tab;
    b.classList.toggle('active', on);
    b.setAttribute('aria-selected', on ? 'true' : 'false');
    b.tabIndex = on ? 0 : -1;
  }
  el('detailPanel-overview').hidden = tab !== 'overview';
  el('detailPanel-export').hidden = tab !== 'export';
  if (tab !== 'export') el('detailExportPass').value = '';
}

async function exportSelected() {
  if (!state.selectedId) return;
  const format = el('detailExportFormat').value;
  const passphrase = el('detailExportPass').value;
  const k = state.keys.find(x => x.id === state.selectedId);
  try {
    if (PRIVATE_EXPORT_FORMATS.indexOf(format) !== -1) {
      const r = await call('key_export_to_file', { id: state.selectedId, format, passphrase });
      if (r.canceled) { toast('Export cancelled.', 'info'); return; }
      toast('Exported ' + format + ' to ' + r.path, 'ok');
      return;
    }
    const out = await call('key_export', { id: state.selectedId, format, passphrase });
    const base = safeFileName(k ? k.name : state.selectedId);
    const ext = EXPORT_EXT[format] !== undefined ? EXPORT_EXT[format] : '.txt';
    download(base + ext, out.data);
    toast('Exported ' + format + '.', 'ok');
  } catch (e) {
    toast(e.message || String(e), 'err');
  } finally {
    el('detailExportPass').value = '';
  }
}

// ─── command palette ───────────────────────────────────────────────────────
//
// Keys, servers and categories each had their own search box, and every action
// beyond the five nav items had no keyboard path at all. This is one entry
// point for all of it. It never invents data: servers are loaded on demand,
// exactly as the key->host picker does, because nothing but the Servers view
// used to fetch them.

let paletteItems = [];
let paletteActive = 0;

async function openPalette() {
  const modal = el('paletteModal');
  if (!modal.hidden) return;
  modal.hidden = false;
  el('paletteInput').value = '';
  if (state.unlocked && state.servers.length === 0) {
    try { await loadServers(); } catch (e) { /* palette still works without them */ }
  }
  renderPalette('');
  el('paletteInput').focus();
}

function closePalette() {
  el('paletteModal').hidden = true;
  paletteItems = [];
  paletteActive = 0;
}

/// Everything the palette can reach, before filtering. Actions are listed with
/// the words someone would actually type ("lock", "deploy", "audit").
function paletteCandidates() {
  const out = [];
  for (const s of state.servers) {
    const live = [...state.sessions.values()].some(t => t.serverId === s.id && window.tabSessionLive(t.tabId));
    out.push({
      group: 'Servers', icon: 'server', name: s.name || '(unnamed)',
      sub: `${s.username || '?'}@${s.host || '?'}:${s.port || 22}` + (live ? ' · session open' : ''),
      hint: live ? 'Switch to session' : 'Connect', live,
      terms: [s.name, s.host, s.username, s.keyName],
      run: () => {
        switchView('connect');
        selectServer(s.id);
        // A LIVE tab of this server, else a new session. Any tab used to do -
        // the oldest first - so the entry that said "Switch to session" could
        // land on a dead terminal, and "Connect" never connected (A3-35).
        const open = [...state.sessions.values()].find(t => t.serverId === s.id && window.tabSessionLive(t.tabId));
        if (open) activateSessionTab(open.tabId); else openSessionTab(s);
      },
      runAlt: () => { switchView('connect'); selectServer(s.id); openSessionTab(s); },
    });
  }
  for (const k of state.keys) {
    const cats = (state.keyCategories[k.id] || []).map(catPathString).filter(Boolean);
    out.push({
      group: 'Keys', icon: 'key-round', name: k.name || '(unnamed)',
      sub: [k.key_type, k.comment, cats.join(', ')].filter(Boolean).join(' · '),
      hint: 'Open key',
      terms: [k.name, k.comment, k.fingerprint_sha256],
      run: () => { switchView('keys'); selectKey(k.id); },
    });
  }
  for (const c of state.categories) {
    out.push({
      group: 'Categories', icon: 'folder', name: catPathString(c.id),
      sub: c.scope === 'host' ? 'host category' : 'key category',
      hint: 'Filter',
      terms: [c.name],
      run: () => { switchView(c.scope === 'host' ? 'connect' : 'keys'); setActiveCategory(c.id); },
    });
  }
  const n = state.deploySelected.size;
  out.push(
    { group: 'Actions', icon: 'plus', name: 'New key...', terms: ['new', 'generate', 'import'], run: openKeyModal },
    { group: 'Actions', icon: 'server', name: 'New server...', terms: ['new', 'server', 'host'], run: () => { switchView('connect'); openServerModal({}); } },
    { group: 'Actions', icon: 'shield-check', name: n ? `Deploy ${n} selected key(s)...` : 'Deploy keys (select some first)',
      terms: ['deploy', 'ssh config'], run: () => { switchView('keys'); openDeploySheet(); } },
    { group: 'Actions', icon: 'lock', name: 'Lock the vault', terms: ['lock'], run: lockNow },
    { group: 'Actions', icon: 'key-round', name: 'Change master password...', terms: ['password', 'master password', 'vault'],
      run: () => requestVaultModal('change') },
    { group: 'Actions', icon: 'refresh-cw', name: 'Check for updates', terms: ['update', 'updates', 'version', 'release'],
      run: manualUpdateCheck },
  );
  // Every Settings section is a destination of its own (A5-17): the palette
  // used to reach only the first one and the audit log.
  for (const [section, title, icon, terms] of PALETTE_SETTINGS_SECTIONS) {
    out.push({ group: 'Actions', icon, name: 'Settings: ' + title, terms: ['settings', ...terms],
      run: () => { switchView('settings').then(() => showSettingsSection(section)); } });
  }
  return out;
}

/// [section, title, icon, words someone would type for it].
const PALETTE_SETTINGS_SECTIONS = [
  ['general', 'General', 'settings', ['preferences', 'options', 'auto-lock', 'idle', 'interface scale', 'transfers', 'bandwidth', 'terminal']],
  ['vault', 'Vault & password', 'lock', ['vault', 'master password', 'lock']],
  ['hosts', 'Known hosts', 'shield-check', ['known hosts', 'host keys', 'fingerprints', 'pinned']],
  ['backup', 'Backup & restore', 'download', ['backup', 'restore']],
  ['sync', 'Bitwarden sync', 'cloud-cog', ['bitwarden', 'vaultwarden', 'sync']],
  ['assistant', 'AI assistant', 'message-square', ['assistant', 'ai', 'mcp', 'model']],
  ['audit', 'Audit log', 'scroll-text', ['audit', 'log', 'history']],
];

/// The lower-case words of a string: spaces and - . _ / @ : , & all separate
/// words, so "prod web" finds prod-web and "eu1 web" finds web-00.eu1.
function paletteWords(s) {
  return String(s == null ? '' : s).toLowerCase().split(/[\s\-._/@:,&()]+/).filter(Boolean);
}

/// How well an item matches the query's words, 0 for no match. Every word
/// must match somewhere (A5-17): best in the name - its start (3), the start
/// of one of its words (2), anywhere in it (1) - else in the subtext or the
/// search terms (0.5). An action one of whose terms IS the query comes first.
function paletteScore(item, words, query) {
  const name = String(item.name || '').toLowerCase();
  const nameWords = paletteWords(item.name);
  const others = [item.sub, ...(item.terms || [])].filter(Boolean).map((t) => String(t).toLowerCase());
  let score = 0;
  for (const w of words) {
    const s = name.startsWith(w) ? 3
      : nameWords.some((x) => x.startsWith(w)) ? 2
        : name.includes(w) ? 1
          : others.some((o) => o.includes(w)) ? 0.5 : 0;
    if (!s) return 0;
    score += s;
  }
  const q = query.trim().toLowerCase();
  if (item.group === 'Actions' && (name === q || (item.terms || []).some((t) => String(t).toLowerCase() === q))) score += 100;
  return score;
}

function renderPalette(query) {
  const words = paletteWords(query);
  const all = state.unlocked ? paletteCandidates()
    : [{ group: 'Actions', icon: 'lock-open', name: 'Unlock the vault...', terms: ['unlock'], run: () => requestVaultModal(state.hasVault ? 'unlock' : 'create') }];
  if (!words.length) {
    paletteItems = all;
  } else {
    // Every word must match, best matches first (paletteScore); each group
    // stays together, the groups in the order of their best match (A5-17).
    const ranked = all.map((it, i) => ({ it, i, s: paletteScore(it, words, query) }))
      .filter((x) => x.s > 0)
      .sort((a, b) => b.s - a.s || a.i - b.i)
      .map((x) => x.it);
    const groups = [...new Set(ranked.map((it) => it.group))];
    paletteItems = groups.flatMap((g) => ranked.filter((it) => it.group === g));
  }
  if (paletteActive >= paletteItems.length) paletteActive = 0;

  const results = el('paletteResults');
  results.innerHTML = '';
  el('paletteCount').textContent = paletteItems.length
    ? paletteItems.length + (paletteItems.length === 1 ? ' result' : ' results') : '';
  // The combobox says whether its listbox has anything, and which row the
  // arrow keys have highlighted (focus stays in the input) (A1-36).
  const input = el('paletteInput');
  input.setAttribute('aria-expanded', paletteItems.length ? 'true' : 'false');
  input.removeAttribute('aria-activedescendant');
  if (!paletteItems.length) {
    const none = document.createElement('div');
    none.className = 'palette-empty';
    // Says what to do next (A5-17): every word has to match something.
    none.textContent = 'Nothing matches "' + query.trim() + '". Try fewer or shorter words - '
      + 'names, hosts, users, comments, categories and actions are all searched.';
    results.appendChild(none);
    return;
  }
  let lastGroup = null;
  paletteItems.forEach((it, i) => {
    if (it.group !== lastGroup) {
      lastGroup = it.group;
      const h = document.createElement('div');
      h.className = 'palette-group';
      h.textContent = it.group;
      results.appendChild(h);
    }
    const row = document.createElement('button');
    row.className = 'palette-row' + (i === paletteActive ? ' active' : '');
    row.id = 'palette-opt-' + i;
    row.setAttribute('role', 'option');
    row.setAttribute('aria-selected', i === paletteActive ? 'true' : 'false');
    row.innerHTML =
      (it.live ? '<span class="live-dot"></span>' : `<span class="palette-ico">${ico(it.icon)}</span>`) +
      // Both lines are ellipsised when long; the title shows the rest (A1-35).
      `<span class="palette-text"><span class="palette-name" title="${escapeHtml(it.name)}">${escapeHtml(it.name)}</span>` +
      (it.sub ? `<span class="palette-sub" title="${escapeHtml(it.sub)}">${escapeHtml(it.sub)}</span>` : '') + '</span>' +
      (it.hint ? `<span class="palette-hint">${escapeHtml(it.hint)}</span>` : '');
    row.addEventListener('click', () => runPaletteItem(i, false));
    row.addEventListener('mousemove', () => {
      if (paletteActive === i) return;
      paletteActive = i;
      renderPalette(el('paletteInput').value);
    });
    results.appendChild(row);
  });
  const active = results.querySelector('.palette-row.active');
  if (active) {
    active.scrollIntoView({ block: 'nearest' });
    input.setAttribute('aria-activedescendant', active.id);
  }
}

function runPaletteItem(i, alt) {
  const it = paletteItems[i];
  if (!it) return;
  closePalette();
  const fn = alt && it.runAlt ? it.runAlt : it.run;
  try { fn(); } catch (e) { toast(e.message || String(e), 'err'); }
}

function movePaletteActive(delta) {
  if (!paletteItems.length) return;
  paletteActive = (paletteActive + delta + paletteItems.length) % paletteItems.length;
  renderPalette(el('paletteInput').value);
}

// ─── new key modal ─────────────────────────────────────────────────────────

function openKeyModal() {
  if (!state.unlocked) { toast('Unlock the vault first.', 'err'); return; }
  el('modalBackdrop').hidden = false;
  el('genName').focus();
}

function closeKeyModal() {
  el('modalBackdrop').hidden = true;
  // A pasted private key and its passphrase must not outlive the dialog - not
  // after Cancel, Escape, a backdrop click or a vault lock. They used to be
  // cleared only after a SUCCESSFUL create/import, so backing out of an import
  // left the key sitting in the form for whoever opened it next.
  el('importPem').value = '';
  el('importPass').value = '';
  resetImportFileHint();
}

function switchTab(tab) {
  for (const b of document.querySelectorAll('.tab')) {
    const on = b.dataset.tab === tab;
    b.classList.toggle('active', on);
    b.setAttribute('aria-selected', on ? 'true' : 'false');
    b.tabIndex = on ? 0 : -1;
  }
  el('tab-generate').hidden = tab !== 'generate';
  el('tab-import').hidden = tab !== 'import';
  el('modalPrimary').textContent = tab === 'generate' ? 'Create' : 'Import';
  el('modalTitle').textContent = tab === 'generate' ? 'New Key' : 'Import Key';
}

function onGenTypeChange() {
  const t = el('genType').value;
  el('genBitsRow').hidden = t !== 'rsa';
  el('genCurveRow').hidden = t !== 'ecdsa';
}

async function browseForImport() {
  try {
    const res = await call('system_select_file', { title: 'Import SSH key' });
    if (!res || res.canceled || !res.text) return;
    const pem = res.text.trim();
    if (!pem) { toast('That file is empty.', 'err'); return; }
    const nameInput = el('importName');
    if (!nameInput.value.trim()) {
      nameInput.value = (res.name || 'imported-key').replace(/\.[^.]+$/, '');
    }
    el('importPem').value = pem;
    el('importFileHint').textContent = 'Loaded ' + res.name + ' \u2014 press Import to add it.';
    el('importPass').focus();
    toast('Loaded ' + res.name + '. Enter the passphrase if the key is encrypted, then Import.', 'info');
  } catch (e) {
    toast(e.message || String(e), 'err');
  }
}

function resetImportFileHint() {
  const hint = el('importFileHint');
  if (hint) hint.textContent = 'or paste the key material below';
}

async function submitKeyModal() {
  // Re-entrancy guard, same as the host form: key generation can take seconds
  // (RSA-4096), the button stayed live meanwhile, and a second click stored a
  // second identical key.
  if (submitKeyModal._busy) return;
  submitKeyModal._busy = true;
  const primary = el('modalPrimary');
  primary.disabled = true;
  const activeTab = document.querySelector('.tab.active').dataset.tab;
  try {
    if (activeTab === 'generate') {
      const cats = (state._pendingGenerateCategories && state._pendingGenerateCategories()) || [];
      await call('key_create_with_categories', {
        keyType: el('genType').value === 'ecdsa'
          ? `ecdsa-${el('genCurve').value || 'p256'}`
          : el('genType').value,
        bits: Number(el('genBits').value),
        name: el('genName').value.trim() || undefined,
        comment: el('genComment').value.trim() || undefined,
        categoryIds: cats,
      });
      toast('Key generated.', 'ok');
    } else {
      const pem = el('importPem').value;
      if (!pem.trim()) throw new Error('Paste key material first.');
      // key_import doesn't take categoryIds in our IPC; create first, then assign.
      const res = await call('key_import', {
        pem,
        name: el('importName').value.trim() || undefined,
        passphrase: el('importPass').value || undefined,
      });
      const cats = (state._pendingImportCategories && state._pendingImportCategories()) || [];
      if (res && res.id && cats.length) {
        try { await call('key_set_categories', { keyId: res.id, categoryIds: cats }); }
        catch (e) { /* assignment failed but key was created; surface but don't fail the create */ toast('Key imported, but category assignment failed: ' + (e.message || e), 'err'); }
      }
      toast('Key imported.', 'ok');
    }
    closeKeyModal();
    el('genName').value = ''; el('genComment').value = '';
    el('importName').value = '';
    await loadKeys();
  } catch (e) {
    toast(e.message || String(e), 'err');
  } finally {
    submitKeyModal._busy = false;
    primary.disabled = false;
  }
}

// ─── deploy view ───────────────────────────────────────────────────────────

/// Open the deploy sheet over whatever you are looking at, with the current
/// selection already in it. Deploy used to be a top-level view you navigated
/// to AFTER ticking checkboxes in Keys, and its own copy said so.
async function openDeploySheet() {
  if (!state.unlocked) { toast('Unlock the vault first.', 'err'); return; }
  const ids = [...state.deploySelected];
  if (ids.length === 0) { toast('Select at least one key first.', 'err'); return; }
  const chips = el('deployKeyChips');
  chips.innerHTML = '';
  for (const id of ids) {
    const k = state.keys.find(x => x.id === id);
    const chip = document.createElement('span');
    chip.className = 'cat-chip';
    chip.textContent = k ? (k.name || '(unnamed)') : id;
    chips.appendChild(chip);
  }
  el('deployModalTitle').textContent = ids.length === 1 ? 'Deploy 1 key' : 'Deploy ' + ids.length + ' keys';
  el('deployConfigBtnLabel').textContent = ids.length === 1 ? 'Deploy 1 key' : 'Deploy ' + ids.length + ' keys';
  await fillPathHints();
  el('deployModal').hidden = false;
  await previewConfig();
  el('cfgHost').focus();
}

function closeDeploySheet() {
  el('deployModal').hidden = true;
  const pass = el('keyPassphraseInput');
  if (pass) pass.value = '';
}

async function previewConfig() {
  const ids = [...state.deploySelected];
  if (ids.length === 0) { el('configPreview').value = ''; return; }
  const host = el('cfgHost').value.trim() || 'sshspan-host';
  const user = el('cfgUser').value.trim();
  const port = Number(el('cfgPort').value) || 22;
  const strict = el('strictHostKeyToggle')?.checked !== false;
  const encrypted = el('keyPassphraseToggle')?.checked === true;
  const selected = state.keys.filter(k => ids.includes(k.id));
  const blocks = selected.map((key) => {
    const alias = selected.length === 1 ? host : `${host}-${safeFileName(key.name)}`;
    const keyFile = `~/.ssh/sshspan_${safeFileName(key.name)}`;
    return [
      `Host ${alias}`,
      `  HostName ${alias}`,
      user ? `  User ${user}` : '',
      `  Port ${port}`,
      `  IdentityFile ${keyFile}`,
      '  IdentitiesOnly yes',
      `  StrictHostKeyChecking ${strict ? 'yes' : 'no'}`,
      encrypted ? '  # deployed private key is passphrase-protected' : '',
    ].filter(Boolean).join('\n');
  });
  /// These joins were '\\n' - an escaped backslash, so the preview rendered the
  /// two characters \n instead of a line break and the whole config came out as
  /// one unreadable line. deployConfig() a few lines down always used '\n'.
  el('configPreview').value =
    '# >>> SSHSpan managed >>>\n' + blocks.join('\n\n') + '\n# <<< SSHSpan managed <<<\n';
}

async function deployConfig() {
  const ids = [...state.deploySelected];
  if (ids.length === 0) { toast('Select at least one key first.', 'err'); return; }
  // Real paths, from the backend. This prompt used to say it updated
  // ~/.ssh/config; it does not - the managed config lives in the app config
  // dir, while the private key really does land in ~/.ssh. Someone ticking
  // "strict host key checking" here was told their system SSH was being
  // configured when it was not.
  const paths = await systemPaths();
  const sure = await confirmModal('Deploy keys',
    'Deploy ' + ids.length + ' key(s) to ' + paths.deployDir + '/ and update ' + paths.sshConfig + '?',
    'Deploy', { danger: false });
  if (!sure) return;
  try {
    const passphraseEnabled = el('keyPassphraseToggle')?.checked === true;
    const passphrase = passphraseEnabled ? (el('keyPassphraseInput')?.value || '') : undefined;
    if (passphraseEnabled && !passphrase) {
      toast('Enter a passphrase for encrypted deployed keys.', 'err');
      el('keyPassphraseInput')?.focus();
      return;
    }
    const strictHostKey = el('strictHostKeyToggle')?.checked !== false;
    const res = await call('key_deploy', { ids, passphrase, strictHostKey });
    el('configPreview').value = 'Deployed ' + res.keys.length + ' key(s)\n'
      + res.keys.map(k => '  ' + k.name + ' -> ' + k.file).join('\n');
    toast('Keys deployed.', 'ok');
    // The sheet has done its job; the Deployed chips on the rows behind it are
    // now the record, so reload them and get out of the way.
    closeDeploySheet();
    state.deploySelected.clear();
    await loadKeys();
    updateSelectionHint();

    // Optionally register the deployed keys as saved servers (Deploy ↔ Servers bridge).
    if (el('deployRegisterToggle')?.checked) {
      const alias = el('cfgHost').value.trim();
      const user = el('cfgUser').value.trim();
      if (!alias || !user) {
        toast('Enter a Host alias and User to register servers.', 'info');
        return;
      }
      const multi = res.keys.length > 1;
      let registered = 0;
      for (const k of res.keys) {
        try {
          await call('server_save', {
            id: null,
            name: multi ? `${alias} · ${k.name}` : alias,
            host: alias,
            port: parseInt(el('cfgPort').value, 10) || 22,
            username: user,
            authMethod: 'publickey',
            keyId: null,
            pemPath: k.file,
            savedPassword: null,
            categoryId: null,
            color: null,
          });
          registered += 1;
        } catch (e) { /* keep registering the rest */ }
      }
      if (registered) {
        await loadServers();
        toast(`${registered} server(s) saved under Servers.`, 'ok');
      }
    }
  } catch (e) {
    toast(e.message || String(e), 'err');
  }
}

// Import a Host block from ~/.ssh/config into the server-edit modal, prefilled.
async function importFromSshConfig(anchorEl) {
  try {
    const res = await call('ssh_config_list_hosts');
    const hosts = res.hosts || [];
    if (hosts.length === 0) { toast('No Host blocks found in ' + (await systemPaths()).sshConfig + '.', 'info'); return; }
    const items = hosts.map((h) => ({
      label: h.host, sub: `(${h.user || '?'}@${h.hostname || h.host}:${h.port || 22})`, icon: 'server',
      onSelect: () => {
        openServerModal({
          prefill: {
            name: h.host,
            host: h.hostname || h.host,
            port: h.port || 22,
            username: h.user || '',
            pemPath: h.identity_file || '',
          },
        });
        // SSHSpan's SSH client does not implement jump hosts or agent
        // forwarding: `proxy_jump` / `forward_agent` are parsed out of the
        // user's config and preserved on write, but nothing consults them when
        // connecting. Importing such a host and staying silent would leave the
        // user believing they are connecting through a bastion when the
        // connection goes direct - so name the directives that will be ignored.
        const ignored = [];
        if (h.proxy_jump) ignored.push('ProxyJump');
        if (h.forward_agent) ignored.push('ForwardAgent');
        if (h.extra && Object.keys(h.extra).some(k => k.toLowerCase() === 'proxycommand')) {
          ignored.push('ProxyCommand');
        }
        if (ignored.length) {
          toast(`${ignored.join(' and ')} from your SSH config ${ignored.length > 1 ? 'are' : 'is'} not supported - this connection goes direct.`, 'info');
        }
      },
    }));
    openMenu(anchorEl, items, { label: 'Hosts in your SSH config' });
  } catch (e) { toast(e.message || String(e), 'err'); }
}

async function copyConfig() {
  const text = el('configPreview').value;
  if (!text) { toast('Nothing to copy \u2014 preview first.', 'err'); return; }
  const ok = await copyText(text);
  toast(ok ? 'Config copied.' : 'Clipboard unavailable.', ok ? 'ok' : 'err');
}

// ─── bitwarden sync settings ───────────────────────────────────────────────

const BW_FIELDS = [
  { key: 'server_url',      label: 'Server URL',          type: 'url',      placeholder: 'https://vault.example.com', required: true },
  { key: 'email',           label: 'Email',               type: 'email',    placeholder: 'you@example.com',           required: true },
  { key: 'master_password', label: 'Master Password',     type: 'password', placeholder: 'Your Bitwarden master password', required: false },
  { key: 'folder_name',          label: 'Keys folder',    type: 'text', placeholder: 'SSHSpan_Keys',     required: false },
  { key: 'servers_folder_name', label: 'Servers folder', type: 'text', placeholder: 'SSHSpan_Servers', required: false },
];

function setBwStatus(text, cls) {
  const s = el('bwStatus');
  s.classList.remove('ok', 'err', 'info', 'syncing');
  if (cls) s.classList.add(cls);
  s.textContent = text;
}

async function loadBitwardenConfig() {
  const grid = el('bwGrid');
  grid.innerHTML = '';

  let config = {};
  try {
    config = await call('bitwarden_get_config');
  } catch {
    // first launch - no config yet
  }

  for (const f of BW_FIELDS) {
    const label = document.createElement('label');
    const span = document.createElement('span');
    span.textContent = f.label;
    const inp = document.createElement('input');
    inp.type = f.type;
    inp.id = 'bw_' + f.key;
    inp.placeholder = f.placeholder;
    // A URL, an address, folder names and a password: no spellcheck, no
    // autofill offering some other site's saved login (A1-34).
    inp.spellcheck = false;
    inp.setAttribute('autocomplete', 'off');
    if (config[f.key]) inp.value = config[f.key];
    if (f.key === 'master_password') inp.value = ''; // never pre-fill password
    label.appendChild(span);
    label.appendChild(inp);
    grid.appendChild(label);
  }
  wireRevealToggles(grid); // the master password's eye button (A5-35)

  // Sync status
  if (config.last_sync) {
    setBwStatus('Last synced: ' + fmtTime(config.last_sync), 'info');
  } else {
    setBwStatus('Not configured yet.');
  }
}

async function saveBitwardenConfig() {
  if (!state.unlocked) { toast('Unlock the vault first.', 'err'); return; }
  const payload = {
    serverUrl: el('bw_server_url').value.trim(),
    email: el('bw_email').value.trim(),
    masterPassword: el('bw_master_password').value || undefined,
    folderName: el('bw_folder_name').value.trim() || undefined,
    serversFolderName: el('bw_servers_folder_name') ? (el('bw_servers_folder_name').value.trim() || undefined) : undefined,
  };
  if (!payload.serverUrl) { toast('Server URL is required.', 'err'); el('bw_server_url').focus(); return; }
  if (!payload.email) { toast('Email is required.', 'err'); el('bw_email').focus(); return; }
  try {
    await call('bitwarden_save_config', payload);
    toast('Bitwarden config saved.', 'ok');
    el('bw_master_password').value = ''; // clear after save
    await loadBitwardenConfig();
  } catch (e) {
    toast(e.message || String(e), 'err');
  }
}

async function bwTest() {
  try {
    await call('bitwarden_test_connection');
    setBwStatus('Connection OK.', 'ok');
    toast('Connection OK.', 'ok');
  } catch (e) {
    setBwStatus(e.message || String(e), 'err');
    toast(e.message || String(e), 'err');
  }
}

async function bwSyncNow(allowRemoteOverwrite) {
  const btn = el('bwSyncNowBtn');
  btn.disabled = true;
  setBwStatus('Syncing\u2026', 'syncing');
  try {
    // camelCase: Tauri v2 converts a command's snake_case parameter to
    // camelCase by default, so `allow_remote_overwrite` never matched
    // `allowRemoteOverwrite`, deserialized to None, and unwrap_or(false)
    // applied. The "Apply them now?" approval was silently discarded and the
    // UI still reported "Sync complete."
    const s = await call('bitwarden_sync', { allowRemoteOverwrite: allowRemoteOverwrite === true });
    const skipped = (s.skippedOverwrites || 0) + (s.skippedNew || 0);
    if (skipped > 0 && !allowRemoteOverwrite) {
      const msg = [
        'Remote changes need your approval:',
        s.skippedOverwrites ? s.skippedOverwrites + ' local overwrite(s)' : null,
        s.skippedNew ? s.skippedNew + ' new remote item(s)' : null,
      ];
      const detail = msg.filter(Boolean).join(', ');
      const apply = await confirmModal('Apply remote changes', detail + '. Apply them now?', 'Apply');
      // The vault can lock while the dialog is open; a lock answers it "no",
      // and this keeps a late approval from reaching a vault that is sealed.
      if (apply && state.unlocked) {
        return await bwSyncNow(true);
      }
    }
    const parts = [];
    if (s.pushed) parts.push(s.pushed + ' pushed');
    if (s.pulled) parts.push(s.pulled + ' pulled');
    if (s.updatedRemote) parts.push(s.updatedRemote + ' updated remote');
    if (s.updatedLocal) parts.push(s.updatedLocal + ' updated local');
    if (s.linked) parts.push(s.linked + ' linked');
    if (s.conflicts) parts.push(s.conflicts + ' conflicts');
    setBwStatus(parts.length ? 'Sync: ' + parts.join(', ') : 'Nothing to sync.', 'ok');
    toast('Sync complete.', 'ok');
    await loadKeys();
  } catch (e) {
    setBwStatus(e.message || String(e), 'err');
    toast(e.message || String(e), 'err');
  } finally {
    btn.disabled = false;
  }
}

// ─── settings view ─────────────────────────────────────────────────────────

// Fill the three path hints from the backend. They were hard-coded and all
// three named a location the app does not actually use.
async function fillPathHints() {
  const p = await systemPaths();
  const set = (id, val) => { const n = el(id); if (n) n.textContent = val; };
  set('dataDirHint', p.database);
  set('sshConfigHint', p.sshConfig);
  set('deployDirHint', p.deployDir + '/sshspan_<name>');
}

/// Settings is one page with a section rail, not five destinations. Audit used
/// to be a top-level nav item beside your keys; it is a log you consult, so it
/// lives here with the other things you open once a month.
function showSettingsSection(section) {
  for (const b of document.querySelectorAll('.settings-nav-item')) {
    b.classList.toggle('active', b.dataset.section === section);
  }
  for (const s of document.querySelectorAll('.settings-section')) {
    s.hidden = s.dataset.section !== section;
  }
}
window.showSettingsSection = showSettingsSection;
window.switchView = switchView;

/// Parallel transfers in effect, read the way the transfer queue reads it
/// (sftp/queue.rs parallel_limit: trimmed, a whole number clamped to 1..4,
/// anything else 4). settings_get always returns the setting now; the old
/// `|| 2` showed a default the queue never used (A8-14).
const SFTP_PARALLEL_DEFAULT = 4;

function sftpParallelSetting() {
  const raw = state.settings ? state.settings.sftpParallel : undefined;
  const text = raw === undefined || raw === null ? '' : String(raw).trim();
  if (!/^\+?\d+$/.test(text)) return SFTP_PARALLEL_DEFAULT;
  return Math.min(4, Math.max(1, parseInt(text, 10)));
}

async function loadSettings() {
  fillPathHints();
  const grid = el('settingsRows');
  let loaded;
  try {
    loaded = await call('settings_get');
  } catch (e) {
    // Say so where the rows would be, with a Retry (A5-21). This used to
    // leave a blank page AND replace state.settings with {}, quietly putting
    // every setting back to its default for the rest of the session.
    const msg = e.message || String(e);
    renderLoadError(grid, 'Could not load settings', msg, loadSettings);
    toast(msg, 'err');
    return;
  }
  state.settings = loaded;
  // The stored minutes may differ from what the timer was armed with. Arming
  // measures from the last real input, so this cannot extend the idle time.
  armAutoLockTimer();
  grid.innerHTML = '';

  /// One row shape for every setting: what it is on the left, what it costs you
  /// underneath, the control on the right. A bare checkbox gets the same toggle
  /// the rest of the app uses - Settings rendered raw browser checkboxes while
  /// the deploy options one screen away used styled toggles, so the same control
  /// had two appearances depending on where you found it.
  ///
  /// opts.lockGated marks the four settings the backend refuses to change
  /// while the vault is locked (A6-08): the control is disabled then and the
  /// row says why, until the vault is unlocked (applyLockGates).
  ///
  /// The row is a <div>; its caption is a <label for> bound to the row's own
  /// field (opts.labelFor, else the control when it is a form field), so a
  /// click on the caption focuses - or, for a toggle, flips - that field and
  /// nothing else. The whole row used to be one <label>, and a click anywhere
  /// in it was forwarded to the first labelable thing inside: the bandwidth
  /// row's hidden "Unlimited" box (one pill click toggled it twice, a caption
  /// click set a limit) or the "Check now" button (A1-05 / A2-16). A row whose
  /// control is a button or plain text gets a caption that labels nothing.
  let fieldSeq = 0;
  const mkRow = (labelText, control, description, opts) => {
    const row = document.createElement('div');
    row.className = 'settings-row';
    const text = document.createElement('span');
    text.className = 'settings-row-text';
    const field = (opts && opts.labelFor) || (control.matches('input, select, textarea') ? control : null);
    const title = document.createElement(field ? 'label' : 'span');
    title.className = 'settings-row-title';
    title.textContent = labelText;
    if (field) {
      if (!field.id) field.id = 'settingsField' + (++fieldSeq);
      title.htmlFor = field.id;
    }
    text.appendChild(title);
    if (description) {
      const sub = document.createElement('span');
      sub.className = 'settings-row-sub';
      sub.textContent = description;
      if (field) {
        sub.id = field.id + 'Desc';
        field.setAttribute('aria-describedby', sub.id);
      }
      text.appendChild(sub);
    }
    if (opts && opts.lockGated) {
      const why = document.createElement('span');
      why.className = 'settings-row-locked';
      why.dataset.lockHint = '';
      why.textContent = LOCK_GATE_HINTS.settings;
      why.hidden = state.unlocked;
      text.appendChild(why);
      lockGate(control, 'settings');
    }
    row.appendChild(text);
    const ctl = document.createElement('span');
    ctl.className = 'settings-row-control';
    if (control.tagName === 'INPUT' && control.type === 'checkbox') {
      control.classList.add('toggle-input');
      // The switch is a <label> around just this box: a click on it flips the
      // box once (it no longer rides on a row-wide label).
      const sw = document.createElement('label');
      sw.className = 'settings-toggle';
      const box = document.createElement('span');
      box.className = 'toggle-box';
      sw.append(control, box);
      ctl.appendChild(sw);
    } else {
      ctl.appendChild(control);
    }
    row.appendChild(ctl);
    grid.appendChild(row);
  };

  /// Save one setting for a control that has already changed on screen. When
  /// the backend refuses it - a value outside that key's domain, a locked
  /// vault for the four security settings, a write error - `revert` puts the
  /// control back to the value still in effect (state.settings changes only
  /// after a save that went through) and the backend's own message is shown.
  /// The rows used to stay flipped on a failure, so the screen and the setting
  /// in effect disagreed (A5-32).
  const save = async (key, value, revert) => {
    try {
      await call('settings_set', { key, value });
    } catch (e) {
      revert();
      toast(e.message || String(e), 'err');
      return false;
    }
    state.settings[key] = value;
    return true;
  };

  /// A toggle for one setting. `isOn` reads the stored value the way that
  /// setting's consumer does; `on`/`off` are the exact spellings the key
  /// accepts (settings_set validates them per key).
  const toggleFor = (key, isOn, on, off) => {
    const box = document.createElement('input');
    box.type = 'checkbox';
    const shown = () => { box.checked = isOn(state.settings[key]); };
    shown();
    box.addEventListener('change', async () => {
      if (await save(key, box.checked ? on : off, shown)) toast('Saved.', 'ok');
    });
    return box;
  };

  /// A select for one setting; `fallback` is what an unset value - or one no
  /// option matches - shows.
  const selectFor = (key, optionsHtml, fallback, savedMessage) => {
    const sel = document.createElement('select');
    sel.innerHTML = optionsHtml;
    const shown = () => {
      sel.value = state.settings[key] || fallback;
      if (!sel.value) sel.value = fallback;
    };
    shown();
    sel.addEventListener('change', async () => {
      if (await save(key, sel.value, shown)) toast(savedMessage, 'ok');
    });
    return sel;
  };

  const autoLock = document.createElement('input');
  autoLock.type = 'number';
  autoLock.min = '0';
  autoLock.max = String(AUTO_LOCK_MAX_MINUTES);
  // What is shown is what is applied: absent means the default, and an explicit
  // 0 stays 0 (the old `|| 15` showed 15 for a stored number 0).
  autoLock.value = String(autoLockMinutes());
  autoLock.addEventListener('change', async () => {
    // Whole minutes only. Anything else used to be saved as typed - the backend
    // then fell back to 15 while the renderer used parseInt's reading of it.
    const typed = String(autoLock.value).trim();
    if (!/^\d+$/.test(typed)) {
      autoLock.value = String(autoLockMinutes());
      toast('Auto-lock needs a whole number of minutes (0 turns it off).', 'err');
      return;
    }
    const mins = Math.min(AUTO_LOCK_MAX_MINUTES, parseInt(typed, 10));
    autoLock.value = String(mins);
    const saved = await save('autoLockMinutes', String(mins), () => { autoLock.value = String(autoLockMinutes()); });
    if (!saved) return;
    armAutoLockTimer();
    toast('Auto-lock updated.', 'ok');
  });
  mkRow('Lock the vault when idle', autoLock,
    'Minutes without keyboard or mouse input before the vault locks. Locking closes open SSH sessions and pauses file transfers. Typing in a terminal counts as activity; output from a server does not. 0 turns auto-lock off.',
    { lockGated: true });

  // Interface scale. The stylesheet is written in px throughout, so a root
  // font-size would only resize text and leave every control the same size.
  // The webview's own zoom scales the whole layout the way Ctrl+= does in a
  // browser, and survives as a stored setting.
  const uiScale = document.createElement('select');
  for (const pct of [90, 100, 110, 125, 150, 175, 200]) {
    const o = document.createElement('option');
    o.value = String(pct);
    o.textContent = pct + '%';
    uiScale.appendChild(o);
  }
  uiScale.value = String(currentUiScale());
  uiScale.addEventListener('change', async () => {
    const pct = clampUiScale(uiScale.value);
    uiScale.value = String(pct);
    applyUiScale(pct);
    const saved = await save('uiScale', String(pct), () => {
      // Back to the scale in effect, in the list and in the window.
      uiScale.value = String(currentUiScale());
      applyUiScale(currentUiScale());
    });
    if (saved) toast('Interface scale set to ' + pct + '%.', 'ok');
  });
  mkRow('Interface scale', uiScale,
    'Scales the whole window, not just text - the layout is sized in pixels.');

  // state.settings mirrors every saved value (save() above): the delete guards
  // read this one, and collect_settings returns strings, so a stale undefined
  // there meant the guard could not see this session's change.
  const confirmDelete = toggleFor('confirmDelete', settingOn, 'true', 'false');
  mkRow('Confirm before deleting a key', confirmDelete,
    'Deletion is permanent. The audit log keeps a record either way.', { lockGated: true });

  const confirmPaste = toggleFor('confirmMultiLinePaste', (v) => v !== '0', '1', '0');
  mkRow('Confirm multi-line pastes into the terminal', confirmPaste,
    'A pasted newline runs the line. This catches a copied block before it executes.', { lockGated: true });

  const autoUpdate = toggleFor('autoUpdateCheck', settingOn, 'true', 'false');
  mkRow('Check GitHub for new releases', autoUpdate,
    'Fetches a version number only. Nothing about your vault leaves this machine.', { lockGated: true });

  const checkNow = document.createElement('button');
  checkNow.className = 'ghost-btn';
  checkNow.innerHTML = `${ico('refresh-cw')}<span>Check now</span>`;
  checkNow.addEventListener('click', manualUpdateCheck);
  mkRow('Check for an update now', checkNow,
    'Compares this build against the latest GitHub release.');

  const sftpParallel = document.createElement('input');
  sftpParallel.type = 'number';
  sftpParallel.min = '1';
  sftpParallel.max = '4';
  sftpParallel.value = String(sftpParallelSetting());
  sftpParallel.addEventListener('change', async () => {
    const typed = String(sftpParallel.value).trim();
    if (!/^\d+$/.test(typed)) {
      sftpParallel.value = String(sftpParallelSetting());
      toast('Parallel transfers needs a whole number from 1 to 4.', 'err');
      return;
    }
    const v = Math.max(1, Math.min(4, parseInt(typed, 10)));
    sftpParallel.value = String(v);
    const saved = await save('sftpParallel', String(v), () => { sftpParallel.value = String(sftpParallelSetting()); });
    if (saved) toast('Parallel transfers updated.', 'ok');
  });
  mkRow('Parallel file transfers', sftpParallel,
    'More streams help on fast links and hurt on congested ones. 1 to 4.');

  const sftpHidden = toggleFor('sftpShowHidden', (v) => v === '1', '1', '0');
  mkRow('Show hidden files in the file browser', sftpHidden,
    'Dotfiles are hidden by default; you can always toggle this per session.');

  // sftpMaxBps and sftpVerifyTransfers are in settings_get's (Rust) key
  // allowlist, so the persisted value comes back through `state.settings` like
  // every other row above. They used to be read through an optional
  // `sftpSettingCacheGet/Set` pair on `window` that nothing ever defined: the
  // calls silently fell through to the default, so a saved bandwidth limit or
  // verify toggle re-rendered as "Unlimited"/"off" on every launch while the
  // backend kept enforcing the real value.

  // Bandwidth throttle (Task 3): stored as whole bytes/sec (sftpMaxBps), but
  // shown as a magnitude + KB/s-or-MB/s unit with an explicit Unlimited
  // toggle - nobody thinks in raw bytes/sec.
  const bpsWrap = document.createElement('span');
  bpsWrap.className = 'settings-combo';
  const bpsUnlimited = document.createElement('input');
  bpsUnlimited.type = 'checkbox';
  bpsUnlimited.id = 'settingsBpsUnlimited';
  const bpsNum = document.createElement('input');
  bpsNum.type = 'number';
  bpsNum.min = '1';
  bpsNum.max = '1000000';
  const bpsUnit = document.createElement('select');
  bpsUnit.innerHTML = '<option value="1024">KB/s</option><option value="1048576">MB/s</option>';
  bpsUnit.setAttribute('aria-label', 'Bandwidth limit unit');
  // The pill is the box's own <label>: its activation flips the box exactly
  // once. It used to be a span with a click handler that flipped the box AND
  // sat inside the row's <label>, which flipped it back (A2-16).
  const bpsUnlimitedTag = document.createElement('label');
  bpsUnlimitedTag.className = 'settings-combo-tag';
  bpsUnlimitedTag.htmlFor = bpsUnlimited.id;
  bpsUnlimitedTag.textContent = 'Unlimited';
  /// The three controls for the stored limit: at first render, and to put
  /// them back when a save is refused.
  const showThrottle = () => {
    const bpsStored = parseInt(state.settings.sftpMaxBps || '0', 10) || 0;
    bpsUnlimited.checked = bpsStored === 0;
    if (bpsStored > 0 && bpsStored % 1048576 === 0) {
      bpsUnit.value = '1048576';
      bpsNum.value = bpsStored / 1048576;
    } else {
      bpsUnit.value = '1024';
      bpsNum.value = bpsStored > 0 ? Math.max(1, Math.round(bpsStored / 1024)) : 512;
    }
    bpsNum.disabled = bpsUnlimited.checked;
    bpsUnit.disabled = bpsUnlimited.checked;
    bpsUnlimitedTag.classList.toggle('active', bpsUnlimited.checked);
  };
  showThrottle();
  const applyThrottle = async () => {
    bpsNum.disabled = bpsUnlimited.checked;
    bpsUnit.disabled = bpsUnlimited.checked;
    bpsUnlimitedTag.classList.toggle('active', bpsUnlimited.checked);
    const mag = Math.max(1, Math.min(1000000, parseInt(bpsNum.value, 10) || 1));
    bpsNum.value = mag;
    const bytesPerSec = bpsUnlimited.checked ? 0 : mag * parseInt(bpsUnit.value, 10);
    if (!(await save('sftpMaxBps', String(bytesPerSec), showThrottle))) return;
    try {
      // Also push it live - settings_set alone only takes effect on the
      // NEXT transfer (restore_pending re-reads it at startup); workers
      // already running re-check rate_bps every chunk, so this applies the
      // change to them immediately instead of making the user wait.
      await call('sftp_queue_set_rate_limit', { bytesPerSec });
    } catch (e) {
      // Saved, so the next transfer uses it; only the running ones did not
      // get it. The control stays: it shows the stored limit.
      toast(e.message || String(e), 'err');
      return;
    }
    toast(bytesPerSec === 0
      ? 'Bandwidth limit removed.'
      : `Bandwidth limit set to ${mag} ${bpsUnit.value === '1048576' ? 'MB/s' : 'KB/s'}.`, 'ok');
  };
  bpsUnlimited.addEventListener('change', applyThrottle);
  bpsNum.addEventListener('change', applyThrottle);
  bpsUnit.addEventListener('change', applyThrottle);
  bpsWrap.appendChild(bpsUnlimited);
  bpsWrap.appendChild(bpsUnlimitedTag);
  bpsWrap.appendChild(bpsNum);
  bpsWrap.appendChild(bpsUnit);
  // The caption names the number field (a click on it focuses the number,
  // and does nothing while Unlimited has the field disabled).
  mkRow('Bandwidth limit', bpsWrap,
    'Shared across every transfer, not per file.', { labelFor: bpsNum });

  // Verify toggle (Task 4): off by default - the label states the actual
  // cost up front rather than burying it in a tooltip, since re-reading
  // both sides to hash them roughly doubles the traffic a transfer uses.
  const sftpVerify = toggleFor('sftpVerifyTransfers', (v) => v === 'true', 'true', 'false');
  mkRow('Verify transfers with SHA-256', sftpVerify,
    'Re-reads both sides to compare hashes - roughly doubles the traffic a transfer uses.');

  // Conflict default actions (the "Always use this action" checkbox in the
  // transfer conflict dialog writes the same keys). Values are mirrored
  // into window.sftpConflictDefaults so sftp.js sees them without a reload.
  const conflictOptions = '<option value="ask">Ask every time</option>' +
    '<option value="overwrite">Overwrite</option>' +
    '<option value="skip">Skip</option>' +
    '<option value="rename">Rename (auto)</option>' +
    '<option value="resume">Resume</option>';
  const mkConflictRow = (labelText, key, description) => {
    const sel = document.createElement('select');
    sel.innerHTML = conflictOptions;
    const shown = () => {
      sel.value = (state.settings && state.settings[key]) ||
        (window.sftpConflictDefaults && window.sftpConflictDefaults[key]) || 'ask';
    };
    shown();
    sel.addEventListener('change', async () => {
      const value = sel.value;
      if (!(await save(key, value, shown))) return;
      if (window.sftpConflictDefaults) window.sftpConflictDefaults[key] = value;
      toast('Saved.', 'ok');
    });
    mkRow(labelText, sel, description);
  };
  mkConflictRow('When an upload would overwrite a file', 'sftpConflictUpload',
    'The conflict dialog writes this same setting when you tick "always use this action".');
  mkConflictRow('When a download would overwrite a file', 'sftpConflictDownload',
    'Resume continues a part-finished transfer; rename keeps both copies.');

  // Fallback for transfers that never reach the conflict dialog (a batch whose
  // destinations are all new, and the Send-to path). The backend has always
  // read this key - `resolve_resume_mode` in commands/sftp.rs - but nothing in
  // the UI could set it, so it sat at "ask" forever.
  const resumeDefault = selectFor('sftpResumeDefault',
    '<option value="ask">Ask every time</option>' +
    '<option value="overwrite">Overwrite</option>' +
    '<option value="resume">Resume</option>',
    'ask', 'Saved.');
  mkRow('Default transfer mode when no conflict is detected', resumeDefault,
    'Applies when a transfer never reaches the conflict dialog. Resume continues a part-finished transfer.');

  const termScrollback = document.createElement('input');
  termScrollback.type = 'number';
  termScrollback.min = '1000';
  termScrollback.max = '50000';
  termScrollback.step = '1000';
  termScrollback.value = state.settings.terminalScrollback || 5000;
  termScrollback.addEventListener('change', async () => {
    const v = Math.max(1000, Math.min(50000, parseInt(termScrollback.value, 10) || 5000));
    termScrollback.value = v;
    const saved = await save('terminalScrollback', String(v), () => {
      termScrollback.value = state.settings.terminalScrollback || 5000;
    });
    if (!saved) return;
    if (typeof window.terminalApplySettings === 'function') window.terminalApplySettings();
    toast('Terminal scrollback updated.', 'ok');
  });
  mkRow('Terminal scrollback', termScrollback,
    'Lines of history kept per session. More costs memory in every open tab.');

  const termBell = selectFor('terminalBell',
    '<option value="visual">Visual</option><option value="sound">Sound</option><option value="silent">Silent</option>',
    'visual', 'Terminal bell updated.');
  mkRow('Terminal bell', termBell,
    'What happens when a remote program rings the bell. Visual flashes the tab.');

  const termBackspace = selectFor('terminalBackspace',
    '<option value="default">Delete (0x7f)</option><option value="backspace">Backspace (0x08)</option>',
    'default', 'Backspace compatibility updated; it applies to new terminals.');
  mkRow('Backspace key sends', termBackspace,
    'Change this only if Backspace prints ^H on a particular host. Applies to new terminals.');

  const termHomeEnd = selectFor('terminalHomeEnd',
    '<option value="default">xterm/Home+End standard</option><option value="rxvt">rxvt/Home+End compatibility</option>',
    'default', 'Home/End compatibility updated; it applies to new terminals.');
  mkRow('Home and End key mode', termHomeEnd,
    'Switch to rxvt if those keys misbehave on an older host. Applies to new terminals.');

  const termAppCursor = selectFor('terminalAppCursorKeys',
    '<option value="default">Allow application cursor keys</option><option value="disabled">Disable application cursor keys</option>',
    'default', 'Cursor-key compatibility updated; it applies to new terminals.');
  mkRow('Application cursor keys', termAppCursor,
    'Disable if arrow keys emit escape sequences inside an editor. Applies to new terminals.');

  const termAppKeypad = selectFor('terminalAppKeypad',
    '<option value="default">Allow application keypad</option><option value="disabled">Disable application keypad</option>',
    'default', 'Keypad compatibility updated; it applies to new terminals.');
  mkRow('Application keypad', termAppKeypad,
    'Disable if the numeric keypad types the wrong characters. Applies to new terminals.');

  // Keepalives moved to the SSH protocol layer (russh keepalive@openssh.com
  // every 30 s); the old per-second data-channel ping sent NUL bytes the
  // remote shell saw as Ctrl-@. Shown as read-only info, no setting.
  const keepaliveInfo = document.createElement('span');
  keepaliveInfo.className = 'hint';
  keepaliveInfo.textContent = 'Automatic - protocol-level, every 30 s';
  mkRow('SSH keepalive', keepaliveInfo,
    'Protocol-level, so it never sends bytes your remote shell can see.');

  loadKnownHosts();
}

// ─── vault backup / restore (Settings panel) ───────────────────────────────
//
// Both run in Rust, behind native dialogs (A6-03 / A2-48, ruling R5). The
// sealed vault used to come back to this window as JSON for the page to save,
// and a restore read the whole file into it - the exposure vault_export had
// been de-registered to prevent. The page now only asks, shows that it is
// working, and reports what happened.

/// "2 keys, 1 categories, ..." for the counts a backup or a restore returns.
function backupCountsText(c) {
  const n = (v) => Number(v) || 0;
  c = c || {};
  return `${n(c.keys)} keys, ${n(c.categories)} categories, ${n(c.servers)} servers, ` +
    `${n(c.knownHosts)} known hosts, SFTP bookmarks for ${n(c.sftpBookmarks)} server(s)`;
}

async function backupCreate() {
  if (!state.unlocked) { toast('Unlock the vault first.', 'err'); return; }
  await withBusy(el('backupExportBtn'), 'Saving backup…', async () => {
    try {
      const r = await call('vault_backup_export_to_file');
      if (!r || r.canceled) return; // the save dialog was dismissed
      const summary = backupCountsText(r.counts);
      el('backupStatus').textContent = `Backup saved to ${r.path}: ${summary}.`;
      toast(`Backup saved to ${r.path} - ${summary}.`, 'ok');
    } catch (e) {
      const msg = e.message || String(e);
      toast(msg === VAULT_LOCKED_MIDWAY ? 'The vault was locked before the backup was written, so no file was saved.' : msg, 'err');
    }
  });
}

async function backupRestore() {
  if (!state.unlocked) { toast('Unlock the vault first.', 'err'); return; }
  // Asked first: Rust opens the file dialog and reads the file itself, so
  // there is no later point at which this page could still say no.
  const go = await confirmModal('Restore backup',
    'Restoring adds or overwrites keys, categories, servers, known hosts, settings, MCP servers and SFTP bookmarks with the ones in the backup you choose next. Continue?',
    'Choose backup...');
  // A lock while the question was open answers it no; this also covers a lock
  // that landed right after the answer.
  if (!go || !state.unlocked) return;
  await runRestore();
}

/// One restore call. No arguments lets Rust open the file dialog; `path` and
/// `backupPassword` are the retry for a backup sealed under a different master
/// password, which Rust accepts only for the path it offered back - once,
/// within a few minutes. Both calls pass object literals, so check-ipc-args.js
/// checks their keys against the Rust signature (a variable hid them).
async function runRestore(path, backupPassword) {
  await withBusy(el('backupImportBtn'), 'Restoring…', async () => {
    let r;
    try {
      r = path === undefined
        ? await call('vault_backup_restore_from_file', {})
        : await call('vault_backup_restore_from_file', { path, backupPassword });
    } catch (e) {
      const msg = e.message || String(e);
      // A wrong password uses up the retry Rust granted for that file, so the
      // only way on is to pick the file again. A lock during the restore
      // aborts it before anything is written. Every other message - a busy
      // re-encryption included - is shown as the backend wrote it.
      if (/^Backup password is incorrect/.test(msg)) {
        toast('Backup password is incorrect. Start the restore again to choose the file and try another password.', 'err');
      } else if (msg === VAULT_LOCKED_MIDWAY) {
        toast('The vault was locked during the restore, so nothing was restored.', 'err');
      } else {
        toast(msg, 'err');
      }
      return;
    }
    if (!r || r.canceled) return; // the file dialog was dismissed
    if (r.needsPassword) { askBackupPassword(r.path); return; }
    await finishRestore(r);
  });
}

/// A secret prompt: masked, handed over exactly as typed (edge whitespace is
/// part of a password) and emptied however it closes. A lock closes it
/// without running the callback.
function askBackupPassword(path) {
  promptModal('Backup password',
    'This backup was sealed with a different master password. Enter the one that was current when it was taken:',
    '', (pw) => { if (pw) runRestore(path, pw); }, { secret: true });
}

async function finishRestore(r) {
  const c = r.counts || {};
  el('backupStatus').textContent =
    `Restored: ${backupCountsText(c)}, ${Number(c.settings) || 0} settings, ${Number(c.mcpServers) || 0} MCP servers.`;
  const conflicts = c.knownHostsConflicts || 0;
  const imported = c.knownHostsImported || 0;
  const skipped = r.resealFailures || 0;
  if (skipped > 0) {
    toast(`Backup restored, but ${skipped} entrie(s) could not be decrypted with the backup password and were SKIPPED (keys not imported, saved passwords cleared). Re-sync or re-add them manually.`, 'err');
  } else if (conflicts > 0) {
    toast(`Backup restored, but ${conflicts} host-key pin(s) were NOT overwritten (conflicting keys kept). Check Known Hosts.`, 'err');
  } else {
    toast('Backup restored.', 'ok');
  }
  if (imported > 0) {
    // Planted-trust defence: pins that arrived with the backup are marked
    // unconfirmed; the user re-confirms the fingerprint on first connection.
    toast(`${imported} host-key pin(s) came from the backup and are marked unconfirmed - you will be asked to confirm each fingerprint on its first connection.`, 'info');
  }
  if (c.settingsDropped > 0) {
    toast(`${c.settingsDropped} setting(s) in the backup were not recognised or not valid here and were left out.`, 'info');
  }
  await reloadAfterRestore();
}

/// After a restore everything read from the vault is stale - keys, servers,
/// and the settings the restore wrote: auto-lock, delete confirmation, update
/// check, interface scale, terminal options. Only keys and servers used to be
/// reloaded, so the app went on behaving per the old settings and the next
/// toggle wrote a stale value back (A2-30).
async function reloadAfterRestore() {
  // Neither rejects: a failure shows in its own list (A5-21).
  await loadKeys();
  await loadServers();
  let stored;
  try {
    stored = await call('settings_get');
  } catch (e) {
    toast('Restored, but the settings could not be read back: ' + (e.message || String(e)), 'err');
    return;
  }
  applyStoredSettings(stored);
  if (state.view === 'settings') await loadSettings();
}

/// Put stored settings into effect: the SFTP dual-pane default, the interface
/// scale, the idle timer (measured from the last real input, so this never
/// extends it) and the open terminals. Boot and a restore both do this, here,
/// so the two cannot drift apart.
function applyStoredSettings(stored) {
  state.settings = stored || {};
  state.sftpDualPane = state.settings.sftpDualPane === '1';
  applyUiScale(currentUiScale());
  armAutoLockTimer();
  if (typeof window.terminalApplySettings === 'function') window.terminalApplySettings();
}

// ─── known hosts (Settings panel) ──────────────────────────────────────────
async function loadKnownHosts() {
  const body = el('knownHostsBody');
  const empty = el('knownHostsEmpty');
  if (!body) return;
  body.innerHTML = '';
  try {
    const res = await call('known_hosts_list');
    const hosts = res.hosts || [];
    empty.hidden = hosts.length > 0;
    const chip = el('knownHostsCount');
    if (chip) {
      chip.hidden = hosts.length === 0;
      chip.textContent = hosts.length === 1 ? '1 pinned' : hosts.length + ' pinned';
    }
    for (const h of hosts) {
      const tr = document.createElement('tr');
      const tdHost = document.createElement('td');
      tdHost.textContent = h.host;
      const tdFp = document.createElement('td');
      const code = document.createElement('code');
      code.className = 'mono';
      code.textContent = h.fingerprintSha256 || '-';
      tdFp.appendChild(code);
      const tdSeen = document.createElement('td');
      tdSeen.textContent = fmtTime(h.firstSeen);
      const tdAct = document.createElement('td');
      const forget = document.createElement('button');
      forget.className = 'ghost-btn';
      forget.innerHTML = `${ico('trash-2')}<span>Forget</span>`;
      // known_hosts_forget is refused while the vault is locked (A6-08).
      lockGate(forget, 'hosts');
      forget.addEventListener('click', async () => {
        if (!lockGateOpen('hosts')) return;
        const forgetIt = await confirmModal('Forget host key',
          `Forget the pinned key for "${h.host}"?\n\nThe next connection will re-accept whatever key the server presents.`,
          'Forget');
        if (!forgetIt) return;
        try {
          await call('known_hosts_forget', { host: h.host });
          await loadKnownHosts();
          toast('Host forgotten.', 'ok');
        } catch (e) { toast(e.message || String(e), 'err'); }
      });
      tdAct.appendChild(forget);
      tr.appendChild(tdHost); tr.appendChild(tdFp); tr.appendChild(tdSeen); tr.appendChild(tdAct);
      body.appendChild(tr);
    }
  } catch (e) {
    empty.hidden = false;
    body.innerHTML = '';
  }
}

// ─── audit view ────────────────────────────────────────────────────────────

/// The audit table: a page of AUDIT_PAGE rows at first, AUDIT_PAGE more per
/// "Load older" (audit_list takes a limit only, so a bigger limit is the next
/// page), up to the retention cap. The event-type and text filters work on
/// the rows loaded so far, without asking the backend again (A5-16).
const AUDIT_PAGE = 200;
const AUDIT_RETENTION = 10000;
let auditLimit = AUDIT_PAGE;
let auditRows = [];
let auditTotal = 0;

/// `fromStart` goes back to the first page (opening Settings, after a clear).
async function loadAudit(fromStart) {
  if (fromStart === true) auditLimit = AUDIT_PAGE;
  let res;
  try {
    res = await call('audit_list', { limit: auditLimit });
  } catch (e) {
    // Say so in the table, with a Retry; it used to be an empty table and a
    // toast that faded.
    const msg = e.message || String(e);
    auditRows = [];
    const tr = document.createElement('tr');
    tr.className = 'audit-error';
    const td = document.createElement('td');
    td.colSpan = 3;
    const text = document.createElement('span');
    text.setAttribute('role', 'alert');
    text.textContent = 'Could not load the audit log: ' + msg;
    const again = document.createElement('button');
    again.type = 'button';
    again.className = 'ghost-btn';
    again.innerHTML = `${ico('refresh-cw')}<span>Retry</span>`;
    again.addEventListener('click', () => withBusy(again, 'Retrying…', () => loadAudit()));
    td.append(text, again);
    tr.appendChild(td);
    el('auditBody').replaceChildren(tr);
    el('auditMoreBtn').hidden = true;
    toast(msg, 'err');
    return;
  }
  auditRows = res.rows || [];
  // The table is capped in the backend (AUDIT_RETENTION_ROWS) and this call
  // asks for one page at a time, so say how many exist rather than letting the
  // visible page imply it is everything.
  auditTotal = typeof res.total === 'number' ? res.total : auditRows.length;
  const countChip = el('auditCount');
  if (countChip) {
    countChip.hidden = auditTotal === 0;
    countChip.textContent = auditTotal > auditRows.length
      ? `newest ${auditRows.length} of ${auditTotal}`
      : `${auditTotal} ${auditTotal === 1 ? 'entry' : 'entries'}`;
  }
  const capHint = el('auditCapHint');
  if (capHint) {
    capHint.textContent = auditTotal >= AUDIT_RETENTION
      ? 'The log keeps the newest 10,000 entries; older ones are discarded automatically.'
      : '';
  }
  // The event types of the rows loaded, keeping the one chosen if it is
  // still among them.
  const sel = el('auditEventFilter');
  const chosen = sel.value;
  const events = [...new Set(auditRows.map((r) => r.event).filter(Boolean))].sort();
  sel.replaceChildren(new Option('All events', ''), ...events.map((ev) => new Option(ev, ev)));
  sel.value = events.includes(chosen) ? chosen : '';
  el('auditMoreBtn').hidden = auditRows.length >= auditTotal || auditLimit >= AUDIT_RETENTION;
  renderAuditRows();
}

/// The loaded rows that pass both filters.
function renderAuditRows() {
  const body = el('auditBody');
  const event = el('auditEventFilter').value;
  const words = el('auditTextFilter').value.trim().toLowerCase().split(/\s+/).filter(Boolean);
  const rows = auditRows.filter((r) => {
    if (event && r.event !== event) return false;
    if (!words.length) return true;
    const hay = [fmtTime(r.ts), r.event, r.keyId, r.detail].filter((v) => v != null).join(' ').toLowerCase();
    return words.every((w) => hay.includes(w));
  });
  const filtering = !!event || words.length > 0;
  el('auditFilterHint').textContent = filtering
    ? `${rows.length} of the ${auditRows.length} loaded ${auditRows.length === 1 ? 'entry matches' : 'entries match'}`
    : '';
  const out = [];
  for (const r of rows) {
    const tr = document.createElement('tr');
    [fmtTime(r.ts), r.event, r.detail].forEach((v, i) => {
      const td = document.createElement('td');
      td.textContent = v === undefined || v === null ? '' : String(v);
      if (i === 0) td.className = 'ts';
      if (i === 1) td.className = 'ev';
      tr.appendChild(td);
    });
    out.push(tr);
  }
  if (!out.length) {
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 3;
    td.textContent = filtering
      ? (auditRows.length < auditTotal ? 'No loaded entry matches - load older entries to search further back.' : 'No entry matches.')
      : 'No audit events yet.';
    tr.appendChild(td);
    out.push(tr);
  }
  body.replaceChildren(...out);
}

/// RFC 4180 field escaping: wrap in quotes and double any embedded quote.
/// The detail column carries arbitrary strings (file paths, host names,
/// sanitized key names), so a comma or quote in one must not shift columns.
/// A cell that starts with = + - @, a TAB or a CR also gets a leading single
/// quote (OWASP's CSV-injection advice): Excel and LibreOffice evaluate such a
/// cell as a formula when the file is opened, and a key or server name like
/// `=HYPERLINK(...)` reaches this export verbatim (A2-32).
function csvField(value) {
  let s = value === undefined || value === null ? '' : String(value);
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
  return '"' + s.replace(/"/g, '""') + '"';
}

/// Export the audit log as CSV through a native save dialog. Pulls the full
/// retained set (not the 200-row page the table shows), so the export is
/// complete even when the view is truncated.
async function auditExport() {
  try {
    const res = await call('audit_list', { limit: 10000 });
    const rows = res.rows || [];
    if (!rows.length) { toast('Nothing to export yet.', 'info'); return; }
    const header = ['time', 'event', 'key_id', 'detail'].join(',');
    const lines = rows.map(r => [fmtTime(r.ts), r.event, r.keyId, r.detail].map(csvField).join(','));
    // Leading BOM so Excel opens UTF-8 correctly; the CSV is otherwise plain.
    const csv = '\ufeff' + header + '\r\n' + lines.join('\r\n') + '\r\n';
    const pick = await call('system_pick_save_path', {
      title: 'Export audit log',
      defaultName: `sshspan-audit-${new Date().toISOString().slice(0, 10)}.csv`,
    });
    if (pick.canceled) return;
    await call('system_write_text_file', { path: pick.path, contents: csv });
    toast(`Exported ${rows.length} entrie(s).`, 'ok');
  } catch (e) { toast((e && (e.message || e.error)) || String(e), 'err'); }
}

/// Clear the audit log after a confirmation. The backend records the clear
/// itself, so the log is never left with no trace that it was emptied.
async function auditClear() {
  // audit_clear is refused while the vault is locked (A6-08); the button is
  // disabled then too.
  if (!lockGateOpen('audit')) return;
  try {
    const res = await call('audit_list', { limit: 1 });
    const total = typeof res.total === 'number' ? res.total : 0;
    if (total === 0) { toast('The audit log is already empty.', 'info'); return; }
    const confirmed = await confirmModal(
      'Clear audit log',
      `Delete all ${total} recorded event(s)? This cannot be undone, and the log is your only local record of key and vault activity.`,
      'Clear log',
    );
    if (!confirmed) return;
    const out = await call('audit_clear');
    await loadAudit(true);
    toast(`Cleared ${out.removed} entrie(s).`, 'ok');
  } catch (e) { toast((e && (e.message || e.error)) || String(e), 'err'); }
}


// ─── navigation ────────────────────────────────────────────────────────────

const VIEW_TITLES = { keys: 'Keys', connect: 'Servers', settings: 'Settings' };
const VIEW_SUBS = {
  keys: '',
  connect: '',
  settings: 'Vault, transfers, sync and the audit trail',
};

async function switchView(view) {
  setCatDrawer(false);
  remaskSecrets(document); // a password shown in Settings is not left shown (A5-35)
  state.view = view;
  state.categoryScope = currentCategoryScope();
  // Terminal-maximized is a state of the Connect surface, not of the app:
  // under term-max every .view is overflow:hidden (the terminal must not
  // scroll), so leaving Connect while maximized left Settings/Keys clipped
  // at the viewport with no way to scroll - content below the fold was
  // simply unreachable.
  if (view !== 'connect' && el('app').classList.contains('term-max')) {
    toggleTermMax();
  }
  rebuildCategoryIndex();
  state.orphans = state.categoryScope === 'host' ? state.servers.some(s => !s.categoryId) : uncategorizedKeyCount() > 0;
  renderCategoryTree();
  // The breadcrumb lives in the shared top bar: redraw it for this view's
  // scope, or the Keys filter lingered in Settings and on Servers (A2-17).
  updateBreadcrumb();
  for (const b of document.querySelectorAll('.nav-item')) {
    b.classList.toggle('active', b.dataset.view === view);
  }
  for (const v of Object.keys(VIEW_TITLES)) {
    el('view-' + v).hidden = v !== view;
  }
  el('viewTitle').textContent = VIEW_TITLES[view];
  el('viewSubtitle').textContent = VIEW_SUBS[view] || '';
  if (view === 'settings') {
    await loadSettings();
    await loadBitwardenConfig();
    await loadKnownHosts();
    await loadAudit(true);
  }
  if (view === 'keys') {
    state.categoryScope = 'key'; rebuildCategoryIndex(); renderCategoryTree();
    renderKeyList();
    updateSelectionHint();
  }
  if (view === 'connect') {
    state.categoryScope = 'host'; rebuildCategoryIndex(); renderCategoryTree();
    applyNavLockState();
    if (state.unlocked) {
      await loadServers();
      el('termStrip').textContent = 'Ready. (build ' + (window.__SSHPAN_BUILD__ || 'unknown') + ')';
    } else {
      clearConnectView();
    }
  }
}

// ─── wiring ────────────────────────────────────────────────────────────────

function wire() {
  // The webview's own context menu (Back / Refresh / Save as / Print) is
  // browser chrome leaking into a desktop app - suppress it everywhere. Text
  // fields keep the native editing menu (cut/copy/paste), since the forms
  // have no other affordance for it. App context menus are unaffected:
  // preventDefault() here does not stop propagation, so their handlers still
  // run, and they call preventDefault() for their own area anyway. Capture
  // phase so an inner stopPropagation cannot let the native menu through.
  window.addEventListener('contextmenu', (ev) => {
    const t = ev.target;
    const editable = t instanceof HTMLElement
      && (t.isContentEditable || t instanceof HTMLTextAreaElement
          || (t instanceof HTMLInputElement
              && !/^(checkbox|radio|button|submit|reset|range|color|file|hidden)$/i.test(t.type)));
    if (!editable) ev.preventDefault();
  }, true);

  // How each dialog is dismissed, so Escape (topmost layer only) and a vault
  // lock can settle it without knowing what it holds. The dialogs that exist
  // only while a question is open (confirm, YOLO, the SFTP prompts) register
  // themselves when they open.
  registerModalCloser(el('vaultModal'), dismissVaultModal);
  registerModalCloser(el('modalBackdrop'), closeKeyModal);
  registerModalCloser(el('serverModal'), closeServerModal);
  registerModalCloser(el('deployModal'), closeDeploySheet);
  registerModalCloser(el('paletteModal'), closePalette);
  registerModalCloser(el('pickerModal'), closeCategoryPicker);
  registerModalCloser(el('promptModal'), closePrompt);
  registerModalCloser(el('connectPwModal'), () => closeConnectPwModal(null));

  // nav
  for (const b of document.querySelectorAll('.nav-item')) {
    b.addEventListener('click', () => switchView(b.dataset.view));
  }
  el('terminalBody').addEventListener('contextmenu', (ev) => {
    if (!state.activeTabId) return;
    ev.preventDefault();
    openTerminalContextMenu(ev.clientX, ev.clientY, state.activeTabId);
  });

  // topbar + vault control
  el('paletteBtn').addEventListener('click', () => openPalette());
  el('vaultStatus').addEventListener('click', (ev) => openVaultMenu(ev.currentTarget));

  // vault modal
  el('vaultPrimary').addEventListener('click', submitVaultModal);
  el('vaultCancelBtn').addEventListener('click', dismissVaultModal);
  for (const id of ['vaultPassword', 'vaultPasswordConfirm', 'vaultPasswordCurrent']) {
    el(id).addEventListener('keydown', (ev) => {
      if (ev.key === 'Enter') submitVaultModal();
    });
  }

  // keys view
  el('newKeyBtn').addEventListener('click', openKeyModal);
  const emptyNew = el('emptyNewBtn');
  if (emptyNew) emptyNew.addEventListener('click', openKeyModal);
  el('searchInput').addEventListener('input', renderKeyList);
  el('typeFilter').addEventListener('change', renderKeyList);
  el('catAddRootBtn').addEventListener('click', () => addCategoryPrompt(null));
  lockGate(el('catAddRootBtn'), 'categories');
  // The category drawer (narrow window): its toggles, and a category chosen in
  // it closes it - the list it filters is what the user wants to see next.
  for (const b of document.querySelectorAll('.cat-drawer-btn')) {
    b.addEventListener('click', () => setCatDrawer(!catDrawerOpen()));
  }
  el('catTree').addEventListener('click', (ev) => {
    if (!catDrawerOpen() || !ev.target.closest('.cat-node') || ev.target.closest('.cat-chevron, .cat-actions-btn')) return;
    setCatDrawer(false, { focusButton: true });
  });
  el('catTree').addEventListener('keydown', (ev) => {
    if (!catDrawerOpen() || (ev.key !== 'Enter' && ev.key !== ' ')) return;
    if (ev.target.classList && ev.target.classList.contains('cat-node')) setCatDrawer(false, { focusButton: true });
  });
  // Focus leaving the drawer closes it: whatever took the focus would
  // otherwise sit under it (WCAG 2.4.11). Not focus moving into a menu or a
  // dialog the drawer opened, onto its own toggle, or out of the window (no
  // relatedTarget).
  el('catPanel').addEventListener('focusout', (ev) => {
    const to = ev.relatedTarget;
    if (!catDrawerOpen() || !to || el('catPanel').contains(to)) return;
    if (to.closest && to.closest('.cat-drawer-btn, .ctx-menu, .modal-backdrop')) return;
    setCatDrawer(false);
  });

  // selection actions (what used to be the Deploy view's entry point)
  el('selDeployBtn').addEventListener('click', openDeploySheet);
  el('selDeleteBtn').addEventListener('click', deleteSelectedKeys);
  el('selClearBtn').innerHTML = ico('x');
  el('selClearBtn').addEventListener('click', () => {
    state.deploySelected.clear();
    renderKeyList();
    updateSelectionHint();
  });
  el('selCategoryBtn').addEventListener('click', () => {
    const ids = [...state.deploySelected];
    if (!ids.length) return;
    openCategoryPicker({
      title: 'Add ' + ids.length + ' key(s) to categories',
      initial: [],
      onSave: async (catIds) => {
        if (!catIds.length) return;
        try {
          for (const keyId of ids) {
            const merged = [...new Set([...(state.keyCategories[keyId] || []), ...catIds])];
            await call('key_set_categories', { keyId, categoryIds: merged });
          }
          await loadKeys();
          toast('Categories updated.', 'ok');
        } catch (e) { toast(e.message || String(e), 'err'); }
      },
    });
  });

  // detail pane tabs + export
  for (const b of document.querySelectorAll('.detail-tab')) {
    b.addEventListener('click', () => showDetailTab(b.dataset.detailTab));
  }
  // Tab groups and radio groups are one tab stop each; arrows move within
  // them (A1-36). Shell/Files/Split only moves the focus: opening Files
  // starts the SFTP subsystem, so Enter/Space decide.
  wireRovingGroup(document.querySelector('.detail-tabs'), '.detail-tab');
  wireRovingGroup(document.querySelector('#modalBackdrop .tabs'), '.tab');
  wireRovingGroup(document.querySelector('#serverModal .auth-method-row'), '.seg-btn');
  wireRovingGroup(el('termModeSeg'), '.seg-btn', true);
  el('detailCopyFprBtn').innerHTML = ico('copy');
  el('detailCopyFprBtn').addEventListener('click', async () => {
    const ok = await copyText(el('detailFingerprint').textContent || '');
    toast(ok ? 'Fingerprint copied.' : 'Clipboard unavailable.', ok ? 'ok' : 'err');
  });
  el('detailConnectBtn').addEventListener('click', (ev) => {
    const k = state.keys.find(x => x.id === state.selectedId);
    if (!k) return;
    const r = ev.currentTarget.getBoundingClientRect();
    openKeyConnectMenu(r.left, r.bottom + 4, k);
  });

  // deploy sheet
  el('deployModal').addEventListener('click', (ev) => {
    if (ev.target === el('deployModal')) closeDeploySheet();
  });
  for (const b of el('deployModal').querySelectorAll('[data-close]')) {
    b.addEventListener('click', closeDeploySheet);
  }
  // Live preview: the old one stayed empty until you pressed a Preview button,
  // so the first answer to "what will this write?" was nothing.
  for (const id of ['cfgHost', 'cfgUser', 'cfgPort']) {
    el(id).addEventListener('input', previewConfig);
  }
  for (const id of ['strictHostKeyToggle', 'keyPassphraseToggle']) {
    el(id).addEventListener('change', previewConfig);
  }

  // command palette
  el('paletteModal').addEventListener('click', (ev) => {
    if (ev.target === el('paletteModal')) closePalette();
  });
  el('paletteInput').addEventListener('input', (ev) => { paletteActive = 0; renderPalette(ev.target.value); });
  el('paletteInput').addEventListener('keydown', (ev) => {
    if (ev.key === 'ArrowDown') { ev.preventDefault(); movePaletteActive(1); }
    else if (ev.key === 'ArrowUp') { ev.preventDefault(); movePaletteActive(-1); }
    else if (ev.key === 'Enter') { ev.preventDefault(); runPaletteItem(paletteActive, ev.ctrlKey || ev.metaKey); }
  });

  // settings section rail
  for (const b of document.querySelectorAll('.settings-nav-item')) {
    b.addEventListener('click', () => showSettingsSection(b.dataset.section));
  }

  el('detailRenameBtn').addEventListener('click', () => {
    if (!state.selectedId) return;
    const k = state.keys.find(x => x.id === state.selectedId);
    if (!k) return;
    promptModal('Rename key', 'New name (no spaces - it is used as the Host alias in your SSH config):', k.name, async (name) => {
      const next = (name || '').trim();
      if (!next || next === k.name) return;
      try {
        await call('key_rename', { id: k.id, name: next });
        await loadKeys();
        selectKey(k.id);
        toast('Key renamed.', 'ok');
      } catch (e) { toast(e.message || String(e), 'err'); }
    });
  });
  el('detailCopyPublicBtn').addEventListener('click', copyPublic);
  el('detailDeleteBtn').addEventListener('click', deleteSelected);
  el('detailExportBtn').addEventListener('click', exportSelected);

  // new-key modal: category field
  const wireNewKeyCategories = (chipEl, btnEl, getCurrent, setCurrent) => {
    const render = () => renderCategoryChips(chipEl, getCurrent(), { removable: true, onRemove: (id) => setCurrent(getCurrent().filter(x => x !== id)) });
    btnEl.addEventListener('click', () => openCategoryPicker({
      title: 'Assign categories',
      scope: 'key',
      initial: getCurrent(),
      onSave: (ids) => { setCurrent(ids); render(); },
    }));
    render();
  };
  const genPicker = el('genBrowseCategoriesBtn');
  const impPicker = el('importBrowseCategoriesBtn');
  if (genPicker && impPicker) {
    const store = { generate: [], import: [] };
    wireNewKeyCategories(el('genCategories'), genPicker, () => store.generate, (v) => { store.generate = v; });
    wireNewKeyCategories(el('importCategories'), impPicker, () => store.import, (v) => { store.import = v; });
    // expose for submitKeyModal
    state._pendingGenerateCategories = () => store.generate;
    state._pendingImportCategories = () => store.import;
  }

  // key modal
  el('modalBackdrop').addEventListener('click', (ev) => {
    if (ev.target === el('modalBackdrop')) closeKeyModal();
  });
  for (const b of document.querySelectorAll('#modalBackdrop [data-close]')) {
    b.addEventListener('click', closeKeyModal);
  }
  for (const b of document.querySelectorAll('.tab')) {
    b.addEventListener('click', () => switchTab(b.dataset.tab));
  }
  el('modalPrimary').addEventListener('click', submitKeyModal);
  // Enter in a single-line field creates/imports, like the server form and
  // every other dialog here (A5-15). Not in the pasted key (a textarea, where
  // Enter is a new line), a checkbox or a select.
  el('modalBackdrop').addEventListener('keydown', (e) => {
    if (e.key !== 'Enter' || e.isComposing) return;
    const t = e.target;
    if (!(t instanceof HTMLInputElement) || t.type === 'checkbox') return;
    e.preventDefault();
    submitKeyModal();
  });
  el('genType').addEventListener('change', onGenTypeChange);
  el('importBrowseBtn').addEventListener('click', browseForImport);

  // deploy sheet actions (Preview is gone - the preview is always live now)
  el('deployConfigBtn').addEventListener('click', deployConfig);
  el('copyConfigBtn').addEventListener('click', copyConfig);

  // vault actions, now in Settings rather than the corner of every view
  el('lockBtn').addEventListener('click', lockNow);
  // Changing the password needs an unlocked vault; otherwise the useful dialog
  // is the one that unlocks (or creates) it.
  el('changePasswordBtn').addEventListener('click', () =>
    requestVaultModal(state.unlocked ? 'change' : (state.hasVault ? 'unlock' : 'create')));

  // bitwarden sync (settings view)
  el('bwSaveBtn').addEventListener('click', () => {
    if (!state.unlocked) { toast('Unlock the vault first.', 'err'); return; }
    saveBitwardenConfig();
  });
  el('bwTestBtn').addEventListener('click', () => {
    if (!state.unlocked) { toast('Unlock the vault first.', 'err'); return; }
    bwTest();
  });
  el('bwSyncNowBtn').addEventListener('click', () => {
    if (!state.unlocked) { toast('Unlock the vault first.', 'err'); return; }
    bwSyncNow();
  });

  // backup & restore (Settings)
  el('backupExportBtn').addEventListener('click', backupCreate);
  el('backupImportBtn').addEventListener('click', backupRestore);

  // audit log (Settings)
  el('auditExportBtn').addEventListener('click', auditExport);
  el('auditClearBtn').addEventListener('click', auditClear);
  lockGate(el('auditClearBtn'), 'audit');
  el('auditEventFilter').addEventListener('change', renderAuditRows);
  el('auditTextFilter').addEventListener('input', renderAuditRows);
  el('auditMoreBtn').addEventListener('click', (ev) => withBusy(ev.currentTarget, 'Loading…', () => {
    auditLimit = Math.min(AUDIT_RETENTION, auditLimit + AUDIT_PAGE);
    return loadAudit();
  }));

  // picker modal
  el('pickerCloseBtn').addEventListener('click', closeCategoryPicker);
  el('pickerCancelBtn').addEventListener('click', closeCategoryPicker);
  el('pickerSaveBtn').addEventListener('click', () => {
    const cb = state.pickerCallback;
    const ids = [...state.pickerSelected];
    closeCategoryPicker();
    if (cb) cb(ids);
  });
  el('pickerSearch').addEventListener('input', (e) => {
    state.pickerActive = -1;
    renderPickerTree(e.target.value);
  });
  el('pickerSearch').addEventListener('keydown', (e) => {
    const rows = [...el('pickerTree').querySelectorAll('.picker-row[role="option"]')];
    // Escape is not handled here: the central modal handler closes the picker
    // (and only the picker, even when it sits on top of the host/key form).
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault();
      if (!rows.length) return;
      const delta = e.key === 'ArrowDown' ? 1 : -1;
      state.pickerActive = (state.pickerActive + delta + rows.length) % rows.length;
      renderPickerTree(el('pickerSearch').value);
      el('pickerTree').querySelector(`[data-index="${state.pickerActive}"]`)?.scrollIntoView({ block: 'nearest' });
      return;
    }
    if ((e.key === 'Enter' || e.key === ' ') && state.pickerActive >= 0 && rows[state.pickerActive]) {
      e.preventDefault();
      pickerToggle(rows[state.pickerActive].dataset.id);
    }
  });
  el('pickerModal').addEventListener('click', (e) => {
    if (e.target === el('pickerModal')) closeCategoryPicker();
  });

  // prompt modal
  el('promptCancelBtn').addEventListener('click', closePrompt);
  el('promptOkBtn').addEventListener('click', () => {
    // A secret (the backup password) is handed over exactly as typed.
    const raw = el('promptInput').value;
    const v = state.promptSecret ? raw : raw.trim();
    const cb = state.promptCallback;
    closePrompt();
    if (cb) cb(v);
  });
  el('promptInput').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') { e.preventDefault(); el('promptOkBtn').click(); }
  });
  el('promptModal').addEventListener('click', (e) => {
    if (e.target === el('promptModal')) closePrompt();
  });

  // keyboard: Ctrl/Cmd shortcuts. Escape on a DIALOG is the central modal
  // handler's job (capture phase, topmost layer only, wherever focus is);
  // what is left here is the terminal-maximize toggle, and only when nothing
  // is open on top of it.
  document.addEventListener('keydown', (ev) => {
    if (ev.key === 'Escape') {
      if (modalStack.length) return;
      if (catDrawerOpen()) { setCatDrawer(false, { focusButton: true }); return; }
      if (el('app').classList.contains('term-max')) toggleTermMax();
      return;
    }
    // With a dialog open, the chords below would act on the page behind it:
    // Ctrl+N flipped the create-vault dialog to Unlock and wiped the typed
    // password, Ctrl+2 switched views under it, Ctrl+K stacked a palette over
    // it. Only Ctrl+L stays live (locking closes every dialog anyway).
    const dialogOpen = modalStack.length > 0;
    // Ctrl+Shift+1/2/3 switch the session surface (Shell/Files/Split) - the
    // mode buttons' tooltips advertise these. Must be handled BEFORE the
    // Ctrl+Shift-rejecting branch below, and only when a session surface is
    // actually active. Matched on the PHYSICAL key (ev.code): with Shift held,
    // ev.key is the shifted character - ! @ # on a US keyboard, other
    // symbols elsewhere - so comparing it with digits never fired (A8-18).
    const surfaceMode = { Digit1: 'ssh', Digit2: 'sftp', Digit3: 'split' }[ev.code];
    if ((ev.ctrlKey || ev.metaKey) && ev.shiftKey && !ev.altKey && surfaceMode) {
      if (dialogOpen) return;
      const view = el('view-connect');
      if (view && !view.hidden && state.activeTabId) {
        const mode = surfaceMode;
        if (typeof window.setSessionMode === 'function') {
          window.setSessionMode(mode);
          ev.preventDefault();
        }
      }
      return;
    }
    if (!(ev.ctrlKey || ev.metaKey) || ev.altKey || ev.shiftKey) return;
    const k = ev.key.toLowerCase();
    if (k === 'l') { ev.preventDefault(); lockNow(); return; }
    if (dialogOpen) return;
    if (k === '1') { switchView('keys'); ev.preventDefault(); }
    else if (k === '2') { switchView('connect'); ev.preventDefault(); }
    else if (k === '3') { switchView('settings'); ev.preventDefault(); }
    else if (k === ',') { switchView('settings'); ev.preventDefault(); }
    else if (k === 'k') { ev.preventDefault(); openPalette(); }
    else if (k === 'n') {
      ev.preventDefault();
      if (state.unlocked) openKeyModal();
      else {
        // A first run has no vault to unlock: ask for the dialog that exists.
        requestVaultModal(state.hasVault ? 'unlock' : 'create');
        toast(state.hasVault ? 'Unlock the vault first.' : 'Create a vault first.', 'info');
      }
    }
  });

  // Listen for vault-lock-requested from the tray menu
  listen('vault-lock-requested', () => { lockNow(); });

  // The backend idle watchdog locked the vault without us (nothing arrived
  // for autoLockMinutes). The renderer would otherwise find out at the next
  // 10 s poll, leaving keys and sessions on screen for up to that long.
  listen('vault-locked-by-watchdog', async () => {
    const wasUnlocked = state.unlocked;
    try { await refreshVaultStatus(); } catch (e) { return; }
    if (wasUnlocked && !state.unlocked) toast('Vault auto-locked after inactivity.', 'info');
  });

  // The "+" tab-strip chip: show the server list so the user can pick (or
  // add) the host for a new session. It previously had no handler at all -
  // hover styles and a title promising an action, doing nothing.
  const termAddBtn = el('termTabAdd');
  if (termAddBtn) termAddBtn.addEventListener('click', () => switchView('connect'));

  // ─── Connect view wiring ────────────────────────────────────────────────
  el('serverNewBtn').addEventListener('click', () => openServerModal({}));
  el('serverImportBtn').addEventListener('click', (ev) => importFromSshConfig(ev.currentTarget));
  el('serverSearch').addEventListener('input', renderServerList);
  el('termDisconnectBtn').addEventListener('click', disconnectActiveTab);
  const termMaxBtn = el('termMaxBtn');
  if (termMaxBtn) termMaxBtn.addEventListener('click', toggleTermMax);
  el('termReconnectBtn').addEventListener('click', () => {
    const srv = currentSelectedServer();
    if (srv) openSessionTab(srv);
  });
  el('termTestBtn').addEventListener('click', () => {
    const srv = currentSelectedServer();
    if (srv) testSelectedServer(srv);
  });
  const assistantToggleBtn = el('assistantToggleBtn');
  if (assistantToggleBtn) assistantToggleBtn.addEventListener('click', () => {
    if (typeof window.assistantToggle === 'function') window.assistantToggle();
    else toast('The assistant is still loading - try again in a moment.', 'err');
  });
  const modeSeg = el('termModeSeg');
  if (modeSeg) {
    for (const b of modeSeg.querySelectorAll('.seg-btn')) {
      b.addEventListener('click', () => {
        if (typeof window.setSessionMode === 'function') window.setSessionMode(b.dataset.mode);
        else toast('The file browser is still loading - try again in a moment.', 'err');
      });
    }
  }
  el('keyPassphraseToggle')?.addEventListener('change', (ev) => {
    const input = el('keyPassphraseInput');
    if (input) input.hidden = !ev.target.checked;
  });
  for (const b of document.querySelectorAll('#serverModal [data-close]')) {
    b.addEventListener('click', closeServerModal);
  }
  el('serverModal').addEventListener('click', (e) => {
    if (e.target === el('serverModal')) closeServerModal();
  });
  // Scoped to the server modal: '.seg-btn' alone also matches the Shell /
  // Files / Split view switch, and those buttons carry data-mode, not
  // data-auth - so every click on them called setConnectAuthMethod(undefined),
  // which lit up all three and corrupted the modal's auth state.
  for (const b of document.querySelectorAll('#serverModal .seg-btn')) {
    b.addEventListener('click', () => setConnectAuthMethod(b.dataset.auth));
  }
  el('srvBrowsePemBtn').addEventListener('click', async () => {
    // A path only: the file is not read. system_select_file read the private
    // key and shipped its text into this window just to fill in a path
    // (A6-04 / A2-19).
    try {
      const r = await call('system_pick_file_path', { title: 'Select .pem file' });
      if (r && !r.canceled) el('srvPemPath').value = r.path;
    } catch (e) { toast(e.message || String(e), 'err'); }
  });
  el('srvSaveBtn').addEventListener('click', submitServerModal);
  // Enter submits from any single-line field in the host form, the way a real
  // <form> would - this dialog is filled in dozens of times and previously
  // required reaching for the mouse. Textareas and the segmented auth buttons
  // are excluded so Enter keeps its normal meaning there.
  el('serverModal').addEventListener('keydown', (e) => {
    if (e.key !== 'Enter' || e.isComposing) return;
    const t = e.target;
    if (!(t instanceof HTMLInputElement) || t.type === 'checkbox') return;
    e.preventDefault();
    submitServerModal();
  });
  el('srvBrowseCategoryBtn').addEventListener('click', () => {
    openCategoryPicker({
      title: 'Server category',
      scope: 'host',
      initial: state._pendingServerCategory ? [state._pendingServerCategory] : [],
      single: true,
      onSave: (ids) => {
        state._pendingServerCategory = ids[0] || null;
        renderServerCategoryChips();
      },
    });
  });

  // Connect password modal
  el('connectPwOkBtn').addEventListener('click', () => {
    closeConnectPwModal(el('connectPwInput').value || '');
  });
  el('connectPwCancelBtn').addEventListener('click', () => closeConnectPwModal(null));
  el('connectPwInput').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') { e.preventDefault(); el('connectPwOkBtn').click(); }
  });
  el('connectPwModal').addEventListener('click', (e) => {
    if (e.target === el('connectPwModal')) closeConnectPwModal(null);
  });
}

/// Lock now, immediately: no confirmation, whatever is open.
async function lockNow() {
  // Settle every open dialog BEFORE the round trip. Between the lock request
  // and the status refresh a pending "Confirm" could otherwise still be
  // clicked, and its action would run against a vault that is already locking.
  if (state.unlocked) closeDialogsForLock();
  try {
    await call('vault_lock');
    await refreshVaultStatus();
    toast('Vault locked.', 'ok');
  } catch (e) { toast(e.message || String(e), 'err'); }
}

/// Everything that has to happen to the UI when the vault locks, however it
/// got locked (this window, the tray, the auto-lock timer, the backend
/// watchdog): settle and close every dialog, blank every secret field, stop
/// the idle timer.
function onVaultLocked() {
  closeDialogsForLock();
  cancelAutoLockTimer();
}

/// Close every open dialog through its own closer (so a pending confirmation,
/// connect-password prompt or YOLO opt-in is answered "no" rather than left
/// waiting for a click that could now act on a sealed vault), topmost first,
/// then wipe the places a secret can sit. The vault dialog itself is closed
/// without being marked dismissed: the unlock gate that follows must show.
function closeDialogsForLock() {
  const rank = (n) => modalStack.findIndex((m) => m.node === n);
  const open = [...document.querySelectorAll('.modal-backdrop')]
    .filter((n) => !n.hidden && n !== el('vaultModal'))
    .sort((a, b) => rank(b) - rank(a));
  for (const node of open) {
    const close = modalClosers.get(node);
    try {
      if (close) close();
    } catch (e) {
      // The dialog is hidden below regardless, so the lock is not held up - but
      // whatever it was holding may not have been settled, so say so.
      console.warn('[sshspan] a dialog closer threw during the vault lock:', e);
    }
    node.hidden = true;
  }
  hideVaultModal();
  // A master-password change still running belongs to the vault that is
  // locking now: its dialog is gone, so its busy state must not carry over
  // to the unlock gate that follows (a disabled Cancel, "Re-encrypting…").
  releaseVaultSubmit();
  clearSensitiveInputs();
}

/// Every field that can hold a typed or pasted secret, whichever dialog or
/// settings row it belongs to: all password inputs (including the ones built
/// at runtime, like the Bitwarden master password), the pasted private key,
/// the deploy preview and the prompt field.
function clearSensitiveInputs() {
  // data-secret: a password field shown with its eye button is type=text
  // right now, and must be wiped (and masked again) all the same.
  for (const input of document.querySelectorAll('input[type="password"], input[data-secret]')) input.value = '';
  remaskSecrets(document);
  for (const id of ['importPem', 'configPreview', 'promptInput']) {
    const n = el(id);
    if (n) n.value = '';
  }
  resetImportFileHint();
}

// ─── show / hide for password fields ──────────────────────────────────────
//
// Every password field has an eye button that shows what was typed (A5-35):
// a master password with no recovery was otherwise chosen blind. Nothing about
// it is kept - a field is masked again when its dialog closes, the view
// changes or the vault locks - and data-secret marks it as a secret field
// whichever type it has at that moment.

function revealButtonFor(input) {
  const wrap = input && input.parentElement;
  return wrap && wrap.classList.contains('secret-field') ? wrap.querySelector('.reveal-btn') : null;
}

function paintRevealButton(btn, shown) {
  btn.setAttribute('aria-pressed', shown ? 'true' : 'false');
  btn.setAttribute('aria-label', shown ? 'Hide password' : 'Show password');
  btn.title = shown ? 'Hide' : 'Show';
  btn.innerHTML = ico(shown ? 'eye-off' : 'eye');
}

function setRevealed(input, shown) {
  input.type = shown ? 'text' : 'password';
  const btn = revealButtonFor(input);
  if (btn) paintRevealButton(btn, shown);
}

/// Put the eye button beside `input` (wrapping both in .secret-field). Once.
function addRevealToggle(input) {
  if (!input || !input.id || revealButtonFor(input)) return revealButtonFor(input);
  const wrap = document.createElement('span');
  wrap.className = 'secret-field';
  input.parentNode.insertBefore(wrap, input);
  wrap.appendChild(input);
  const btn = document.createElement('button');
  btn.type = 'button';
  btn.className = 'reveal-btn';
  btn.setAttribute('aria-controls', input.id);
  btn.addEventListener('click', () => setRevealed(input, input.type === 'password'));
  wrap.appendChild(btn);
  paintRevealButton(btn, false);
  nameFieldFromCaption(input, wrap);
  return btn;
}

/// A field inside a wrapping <label> is named by that label's whole content -
/// which, with the eye button inside it too, ended in "Show password" (or
/// "Hide password"). Name the field from its caption alone - the label's
/// content before the field, wrapped in a span for the purpose - with
/// aria-labelledby. The label still focuses the field when clicked.
function nameFieldFromCaption(input, wrap) {
  const label = wrap.parentElement && wrap.parentElement.closest('label');
  if (!label || input.hasAttribute('aria-labelledby') || input.hasAttribute('aria-label')) return;
  const caption = [];
  for (const n of [...label.childNodes]) {
    if (n === wrap || (n.nodeType === Node.ELEMENT_NODE && n.contains(wrap))) break;
    caption.push(n);
  }
  if (!caption.some((n) => n.textContent.trim())) return;
  const span = document.createElement('span');
  span.className = 'field-caption';
  span.id = input.id + 'Caption';
  label.insertBefore(span, caption[0]);
  span.append(...caption);
  input.setAttribute('aria-labelledby', span.id);
}

/// Every password field under `root` gets its eye button.
function wireRevealToggles(root) {
  for (const input of root.querySelectorAll('input[type="password"]')) {
    input.dataset.secret = '1';
    addRevealToggle(input);
  }
}

/// Mask every shown secret field under `root` again.
function remaskSecrets(root) {
  for (const input of root.querySelectorAll('input[data-secret]')) {
    if (input.type !== 'password') setRevealed(input, false);
  }
}

// ─── Auto-lock (idle timer, honors the autoLockMinutes setting) ────────────

// The backend watchdog reads autoLockMinutes exactly the way autoLockMinutes()
// below does: absent, blank or not a plain whole number (a negative, "+5",
// "1.5") means 15, an explicit "0" means off, anything above
// AUTO_LOCK_MAX_MINUTES means that maximum, surrounding whitespace ignored.
// settings_get reports "15" when nothing is stored, and settings_set accepts
// only digits from 0 to 1440, so an out-of-range value can only be a legacy one
// (an older build, a hand-edited database) - and it reads the same on both
// sides. (A restore drops a value settings_set would refuse.)
const AUTO_LOCK_DEFAULT_MINUTES = 15;
// The Settings field's own maximum (a day). It also keeps the timeout well
// under setTimeout's 2^31 ms limit, past which a timer fires immediately.
const AUTO_LOCK_MAX_MINUTES = 1440;

let autoLockTimer = null;
let autoLockDeadline = 0;
let autoLockTicker = null;
// When the HUMAN last did something: a key, a click, the wheel, a touch.
// Remote output, polls and timers never move it.
let lastUserActivityAt = Date.now();

/// Effective auto-lock timeout in minutes; 0 means off. An explicit 0 is the
/// only way to switch it off. settings_get reports the default ("15") when
/// nothing is stored; absent here (settings not loaded) - like anything that
/// is not a whole non-negative number - also means the default, exactly as the
/// backend watchdog reads it (see AUTO_LOCK_DEFAULT_MINUTES). Absent used to
/// mean "off" here, so a new install advertised a lock it never performed.
function autoLockMinutes() {
  const raw = state.settings ? state.settings.autoLockMinutes : undefined;
  if (raw === undefined || raw === null) return AUTO_LOCK_DEFAULT_MINUTES;
  const text = String(raw).trim();
  if (!/^\d+$/.test(text)) return AUTO_LOCK_DEFAULT_MINUTES;
  return Math.min(AUTO_LOCK_MAX_MINUTES, parseInt(text, 10));
}

/// Stop the idle timer. Safe to call at any time, any number of times.
function cancelAutoLockTimer() {
  if (autoLockTimer) { clearTimeout(autoLockTimer); autoLockTimer = null; }
  autoLockDeadline = 0;
  renderVaultCountdown();
}

/// Arm exactly one timer for the current settings. The deadline is measured
/// from the last REAL input, never from "now": calling this from a status
/// poll, a settings reload or a state transition cannot give the user extra
/// idle time. (resetAutoLockTimer did measure from now, and the 10 s vault
/// poll called it, so the deadline kept running away and the vault never
/// auto-locked.)
function armAutoLockTimer() {
  if (autoLockTimer) { clearTimeout(autoLockTimer); autoLockTimer = null; }
  const mins = autoLockMinutes();
  if (!state.unlocked || mins <= 0) { autoLockDeadline = 0; renderVaultCountdown(); return; }
  autoLockDeadline = lastUserActivityAt + mins * 60 * 1000;
  renderVaultCountdown();
  autoLockTimer = setTimeout(onAutoLockTimer, Math.max(0, autoLockDeadline - Date.now()));
}

function onAutoLockTimer() {
  autoLockTimer = null;
  if (!state.unlocked || !autoLockDeadline) return;
  // Input since this timer was armed moved the deadline: sleep until the new one.
  const left = autoLockDeadline - Date.now();
  if (left > 0) { autoLockTimer = setTimeout(onAutoLockTimer, left); return; }
  toast('Vault auto-locked after inactivity.', 'info');
  lockNow();
}

/// The human did something. Restarts the idle clock and tells the backend
/// watchdog. Remote output must never call this: a busy server is not a user.
function noteUserActivity() {
  lastUserActivityAt = Date.now();
  const mins = autoLockMinutes();
  if (autoLockDeadline && mins > 0) autoLockDeadline = lastUserActivityAt + mins * 60 * 1000;
  queueActivityHeartbeat();
}
window.noteUserActivity = noteUserActivity;

const HUMAN_INPUT_EVENTS = ['keydown', 'mousedown', 'pointerdown', 'wheel', 'touchstart'];

/// Window-level listener for real input. Registered in the capture phase on
/// the window, so it runs before anything that can stop the event: xterm
/// cancels every key it handles, which hid terminal typing from the old
/// document-level bubble listeners (a user typing in a shell would have been
/// locked out, sessions and all, the moment the timer worked). Only trusted
/// events count, so a script or remote content cannot hold the vault open.
function onHumanInput(ev) {
  if (ev.isTrusted === false) return;
  noteUserActivity();
}

/// The countdown under the vault label. Auto-lock has always been a setting
/// with no feedback: you could not tell whether it was on, or how long you
/// had, until the vault locked under you mid-task.
function renderVaultCountdown() {
  const sub = el('vaultSub');
  if (!sub) return;
  if (!state.unlocked) { sub.hidden = true; sub.textContent = ''; }
  else if (!autoLockDeadline) { sub.hidden = false; sub.textContent = 'auto-lock off'; }
  else {
    const left = Math.max(0, autoLockDeadline - Date.now());
    const m = Math.floor(left / 60000);
    const s = Math.floor((left % 60000) / 1000);
    sub.hidden = false;
    sub.textContent = 'locks in ' + m + ':' + String(s).padStart(2, '0');
  }
  paintVaultChipName();
}

/// The vault control's name and tooltip carry the state and the countdown, so
/// they are still there when the narrow layout shows the icon alone (A1-19).
function paintVaultChipName() {
  const chip = el('vaultStatus');
  const label = el('vaultLabel');
  const sub = el('vaultSub');
  if (!chip || !label) return;
  const name = 'Vault: ' + label.textContent.toLowerCase()
    + (sub && !sub.hidden && sub.textContent ? ' - ' + sub.textContent : '');
  chip.setAttribute('aria-label', name);
  chip.title = name + '. Click for lock and password actions.';
}

if (!autoLockTicker) autoLockTicker = setInterval(renderVaultCountdown, 1000);

// Backend idle watchdog input. The Rust side locks the vault when no
// heartbeat has arrived for autoLockMinutes, which covers a hung or crashed
// webview where the timer above can never fire. It used to be fed on a fixed
// 30 s timer, so a renderer that was alive but whose user had walked away
// kept the watchdog quiet forever. It is now sent only when a human did
// something: at most once per HEARTBEAT_MIN_GAP_MS, with a trailing send so
// the last input of a burst is still reported.
const HEARTBEAT_MIN_GAP_MS = 5000;
let heartbeatLastSent = 0;
let heartbeatTimer = null;
let heartbeatPending = false;

function sendActivityHeartbeat() {
  heartbeatTimer = null;
  if (!heartbeatPending) return;
  heartbeatPending = false;
  heartbeatLastSent = Date.now();
  call('heartbeat').catch(() => {});
}

function queueActivityHeartbeat() {
  heartbeatPending = true;
  if (heartbeatTimer) return;
  const wait = Math.min(HEARTBEAT_MIN_GAP_MS, heartbeatLastSent + HEARTBEAT_MIN_GAP_MS - Date.now());
  if (wait <= 0) sendActivityHeartbeat();
  else heartbeatTimer = setTimeout(sendActivityHeartbeat, wait);
}

// ─── Update check (GitHub releases; manual + auto per setting) ─────────────

async function manualUpdateCheck() {
  try {
    const r = await call('update_check');
    if (r.available) {
      const install = await confirmModal('Update available',
        `A newer version is available: ${r.current} → ${r.version}\n\n` +
        `${r.notes ? r.notes.slice(0, 800) + '\n\n' : ''}` +
        `Download and run the installer for this OS?`,
        'Download and install', { danger: false });
      if (install) {
        toast('Downloading installer...', 'info');
        await call('update_download_and_run', { url: r.assetUrl, version: r.version, expectedSha256: r.assetDigest });
        // The app exits itself right after spawning the installer.
      }
    } else {
      toast(`You are on the latest version (${r.current}).`, 'ok');
    }
  } catch (e) {
    toast(e.message || String(e), 'err');
  }
}

async function autoUpdateCheckOnBoot() {
  if (!settingOn(state.settings.autoUpdateCheck)) return;
  try {
    const r = await call('update_check');
    if (r.available) {
      toast(`Update available: ${r.version} - Settings → "Check now" to install.`, 'info');
    }
  } catch (e) { /* offline or rate-limited: silently ignore on boot */ }
}

// ─── Connect: saved servers + SSH sessions ─────────────────────────────────

// Password prompt for connect - uses a custom modal instead of native prompt()
// which silently fails in Tauri's WebView.
function askConnectPassword(server, callback) {
  const modal = document.getElementById('connectPwModal');
  if (!modal) return callback(null); // fallback
  // One prompt at a time: a second request used to overwrite the first one's
  // callback, leaving that connect waiting for an answer that could never come.
  if (state._connectPwCallback) closeConnectPwModal(null);
  modal.hidden = false;
  const label = document.getElementById('connectPwLabel');
  if (label) label.textContent = `Password for ${server.username}@${server.host}:`;
  const inp = document.getElementById('connectPwInput');
  if (inp) { inp.value = ''; setTimeout(() => inp.focus(), 0); }
  state._connectPwCallback = callback;
}
function closeConnectPwModal(value) {
  const modal = document.getElementById('connectPwModal');
  if (modal) modal.hidden = true;
  // The password goes to the caller and nowhere else: empty the field however
  // the dialog was closed (OK reads it before getting here).
  const inp = document.getElementById('connectPwInput');
  if (inp) inp.value = '';
  const cb = state._connectPwCallback;
  state._connectPwCallback = null;
  if (cb) cb(value);
}

async function loadServers() {
  if (!state.unlocked) { clearConnectView(); return; }
  try {
    const res = await call('server_list');
    state.servers = res.servers || [];
    state.serversLoadError = null;
  } catch (e) {
    state.servers = [];
    state.serversLoadError = e.message || String(e);
    toast(state.serversLoadError, 'err');
  }
  renderServerList();
  if (state.view === 'connect') { state.orphans = state.servers.some(s => !s.categoryId); renderCategoryTree(); }
}

function currentSelectedServer() {
  return state.servers.find(s => s.id === state.connectSelectedId) || null;
}

function hostsInCategoryRecursive(catId) {
  const ids = new Set();
  const stack = [catId];
  while (stack.length) {
    const id = stack.pop();
    for (const s of state.servers) if (s.categoryId === id) ids.add(s.id);
    for (const child of childrenOf(id)) stack.push(child.id);
  }
  return state.servers.filter(s => ids.has(s.id));
}

function renderServerList() {
  const list = el('serverList');
  const empty = el('serverEmpty');
  const filter = (el('serverSearch').value || '').toLowerCase().trim();
  const activeCat = activeCategoryId();
  let categoryPool = state.servers;
  if (activeCat === 'uncategorized') categoryPool = state.servers.filter(s => !s.categoryId);
  else if (activeCat !== 'all') categoryPool = hostsInCategoryRecursive(activeCat);
  const filtered = !filter ? categoryPool : categoryPool.filter(s => {
    return [s.name, s.host, s.username, s.keyName].filter(Boolean)
      .some(v => v.toLowerCase().includes(filter));
  });
  list.innerHTML = '';
  if (state.serversLoadError) {
    // Not "No saved servers yet": the servers could not be read (A5-21).
    empty.hidden = true;
    list.hidden = false;
    renderLoadError(list, 'Could not load your servers', state.serversLoadError, loadServers);
    return;
  }
  if (state.servers.length === 0) {
    empty.hidden = false;
    list.hidden = true;
    return;
  }
  empty.hidden = true;
  list.hidden = false;
  for (const s of filtered) {
    const row = document.createElement('div');
    row.className = 'server-row' + (s.id === state.connectSelectedId ? ' selected' : '');
    row.dataset.id = s.id;
    row.tabIndex = 0;
    const head = document.createElement('div');
    head.className = 'server-row-head';
    /// Whether a session is open was only visible in the tab strip; the list
    /// you pick from said nothing, so you would reconnect to a host you were
    /// already on. The dot is the same state the tab chip shows.
    const openTab = [...state.sessions.values()].find(t => t.serverId === s.id);
    const isLive = !!(openTab && window.tabSessionLive(openTab.tabId));
    const dot = document.createElement('span');
    dot.className = 'server-dot' + (isLive ? ' live' : '');
    dot.title = isLive ? 'Session open' : 'Not connected';
    head.appendChild(dot);
    const name = document.createElement('span');
    name.className = 'server-name';
    name.textContent = s.name || '(unnamed)';
    name.title = name.textContent; // ellipsised when long (A1-35)
    head.appendChild(name);
    if (s.keyMissing) {
      const m = document.createElement('span');
      m.className = 'badge warn';
      m.textContent = 'key missing';
      head.appendChild(m);
    }
    row.appendChild(head);

    const sub = document.createElement('div');
    sub.className = 'server-row-sub';
    sub.textContent = `${s.username || '?'}@${s.host || '?'}:${s.port || 22}`;
    row.appendChild(sub);

    const auth = document.createElement('div');
    auth.className = 'server-row-auth';
    const authIcon = s.authMethod === 'password' ? 'key-round'
                    : s.authMethod === 'keyboard-interactive' ? 'message-square'
                    : 'key-round';
    const authLabel = s.authMethod === 'password' ? 'Password'
                     : s.authMethod === 'keyboard-interactive' ? 'Keyboard-interactive'
                     : (s.keyName ? `${s.keyName} (${s.keyType || '?'})` : 'Key');
    auth.innerHTML = `${ico(authIcon)}<span>${escapeHtml(authLabel)}</span>`;
    row.appendChild(auth);

    /// Connecting used to be a double-click and nothing else, with nothing on
    /// screen saying so. The button is the affordance; double-click and Enter
    /// still work for anyone who already knew.
    const go = document.createElement('button');
    go.className = 'server-go' + (isLive ? ' ghost-btn' : ' primary-btn');
    go.title = isLive ? 'Switch to the open session' : 'Connect to this server';
    go.innerHTML = `${ico(isLive ? 'terminal' : 'plug-zap')}<span>${isLive ? 'Open' : 'Connect'}</span>`;
    go.addEventListener('click', (ev) => {
      ev.stopPropagation();
      selectServer(s.id);
      if (isLive) activateSessionTab(openTab.tabId);
      else openSessionTab(s);
    });
    head.appendChild(go);

    row.addEventListener('click', () => selectServer(s.id));
    row.addEventListener('dblclick', () => openSessionTab(s));
    row.addEventListener('keydown', (ev) => {
      if (ev.key !== 'Enter') return;
      ev.preventDefault();
      selectServer(s.id);
      if (isLive) activateSessionTab(openTab.tabId);
      else openSessionTab(s);
    });
    row.addEventListener('contextmenu', (ev) => {
      ev.preventDefault();
      openServerContextMenu(ev.clientX, ev.clientY, s);
    });
    list.appendChild(row);
  }
}

function selectServer(id) {
  state.connectSelectedId = id;
  renderServerList();
  updateTerminalHead();
}

function openServerContextMenu(x, y, srv) {
  openMenu({ x, y }, [
    { label: 'Connect', icon: 'plug-zap', onSelect: () => openSessionTab(srv) },
    { label: 'Edit', icon: 'pencil', onSelect: () => openServerModal({ id: srv.id }) },
    { label: 'Delete', icon: 'trash-2', onSelect: async () => {
      if (!(await confirmModal('Delete server', `Delete server "${srv.name}"?`, 'Delete'))) return;
      try {
        await call('server_delete', { id: srv.id });
        if (state.connectSelectedId === srv.id) selectServer(null);
        await loadServers();
        toast('Server deleted.', 'ok');
      } catch (e) { toast(e.message || String(e), 'err'); }
    } },
  ], { label: 'Server' });
}

// ─── Server modal ───────────────────────────────────────────────────────────

function openServerModal({ id, keyId, prefill } = {}) {
  el('serverModal').hidden = false;
  el('serverModalTitle').textContent = id ? 'Edit Server' : 'New Server';
  // Populate key dropdown from cached state.keys
  const sel = el('srvKeyId');
  sel.innerHTML = '<option value="">- select a key -</option>';
  for (const k of state.keys) {
    if (!k.has_private) continue;
    const opt = document.createElement('option');
    opt.value = k.id;
    opt.textContent = `${k.name} (${k.key_type.toUpperCase()})`;
    sel.appendChild(opt);
  }
  if (keyId) sel.value = keyId;

  let srv = null;
  if (id) {
    srv = state.servers.find(s => s.id === id) || null;
    if (!srv) { toast('Server not found.', 'err'); closeServerModal(); return; }
  }
  el('srvName').value    = srv ? srv.name : (prefill?.name || '');
  el('srvHost').value    = srv ? srv.host : (prefill?.host || '');
  el('srvPort').value    = srv ? (srv.port || 22) : (prefill?.port || 22);
  el('srvUser').value    = srv ? srv.username : (prefill?.username || '');
  el('srvKeyId').value   = srv ? (srv.keyId || keyId || '') : (keyId || '');
  el('srvPemPath').value = srv ? (srv.pemPath || '') : (prefill?.pemPath || '');
  el('srvPassword').value = '';
  el('srvSavePw').checked = false;
  setConnectAuthMethod(srv ? srv.authMethod : (keyId ? 'publickey' : 'publickey'));
  // Category (single-select; schema is one category_id per server)
  state._pendingServerCategory = srv ? (srv.categoryId || null) : null;
  renderServerCategoryChips();
  state._editingServerId = id || null;
  setTimeout(() => el('srvName').focus(), 0);
}

function renderServerCategoryChips() {
  const ids = state._pendingServerCategory ? [state._pendingServerCategory] : [];
  renderCategoryChips(el('srvCategory'), ids, {
    removable: true,
    onRemove: () => { state._pendingServerCategory = null; renderServerCategoryChips(); },
  });
}

function closeServerModal() {
  el('serverModal').hidden = true;
  state._editingServerId = null;
  state._pendingServerCategory = null;
  // A typed server password does not stay behind in a hidden field.
  el('srvPassword').value = '';
}

function setConnectAuthMethod(method) {
  state.connectAuthMethod = method;
  // Only the modal's Key / Password / Keyboard-interactive buttons - the terminal's
  // Shell / Files / Split switch shares the .seg-btn class.
  for (const b of document.querySelectorAll('#serverModal .seg-btn')) {
    const on = b.dataset.auth === method;
    b.classList.toggle('active', on);
    b.setAttribute('aria-checked', on ? 'true' : 'false');
    b.tabIndex = on ? 0 : -1;
  }
  el('srvKeyRow').hidden = method !== 'publickey';
  el('srvPwRow').hidden = method === 'publickey';
}

async function submitServerModal() {
  const name = el('srvName').value.trim();
  const host = el('srvHost').value.trim();
  const port = parseInt(el('srvPort').value, 10) || 22;
  const username = el('srvUser').value.trim();
  const method = state.connectAuthMethod;
  if (!name) return toast('Name is required.', 'err');
  if (!host) return toast('Host is required.', 'err');
  if (!username) return toast('Username is required.', 'err');
  if (method === 'publickey' && !el('srvKeyId').value && !el('srvPemPath').value.trim()) {
    return toast('Choose a key or a .pem file.', 'err');
  }
  const args = {
    id: state._editingServerId,
    name, host, port, username,
    authMethod: method,
    keyId: method === 'publickey' ? (el('srvKeyId').value || null) : null,
    pemPath: method === 'publickey' ? (el('srvPemPath').value.trim() || null) : null,
    savedPassword: (method !== 'publickey' && el('srvSavePw').checked) ? el('srvPassword').value : null,
    categoryId: state._pendingServerCategory,
    color: null,
  };
  // Re-entrancy guard: Save was not disabled while the save was in flight, so
  // a double-click (or Enter held down, now that Enter submits) fired
  // server_save twice and created two rows for the same new host.
  if (submitServerModal._busy) return;
  submitServerModal._busy = true;
  const saveBtn = el('srvSaveBtn');
  saveBtn.disabled = true;
  try {
    const r = await call('server_save', args);
    closeServerModal();
    await loadServers();
    if (r && r.id) selectServer(r.id);
    toast('Server saved.', 'ok');
  } catch (e) { toast(e.message || String(e), 'err'); }
  finally {
    submitServerModal._busy = false;
    saveBtn.disabled = false;
  }
}

// ─── cascading host picker (key -> category -> ... -> host) ────────────────
//
// Opened by right-clicking a key, so it has to leave the user where they are.
// The flat version switched to Connect before drawing anything, purely because
// it anchored itself to that view's "New" button - an element with no layout
// box while its view is hidden, so without the switch the menu landed at 0,0.
// It now anchors at the cursor and lets openSessionTab() do the switching,
// once a host has actually been chosen.
//
// The menu mirrors the host category tree rather than listing every server in
// the vault flat, so a deep tree reads as category > subcategory > host.

let hostPickerCloseTimer = null;
let hostPickerAwayHandler = null;

function hostPickerCancelClose() {
  if (hostPickerCloseTimer !== null) {
    clearTimeout(hostPickerCloseTimer);
    hostPickerCloseTimer = null;
  }
}

/// Drop every flyout at `depth` or deeper. Depth 1 is the first flyout; the
/// root menu is depth 0 and is never removed here, so closing one branch to
/// open another does not close the menu itself.
function hostPickerCloseFrom(depth) {
  for (const sub of document.querySelectorAll('.ctx-submenu')) {
    if (Number(sub.dataset.depth) >= depth) sub.remove();
  }
}

/// Moving from a category row towards its flyout usually clips a sibling row
/// on the way. Closing the instant that happens would put the flyout out of
/// reach, so give the pointer a moment to land inside it first.
function hostPickerScheduleClose(depth) {
  hostPickerCancelClose();
  hostPickerCloseTimer = setTimeout(() => {
    hostPickerCloseTimer = null;
    hostPickerCloseFrom(depth);
  }, 180);
}

/// Keep a menu fully on screen: at the requested point where there is room,
/// pushed back inside the viewport where there is not.
function positionCtxMenuAt(menu, x, y) {
  const pad = 6;
  const r = menu.getBoundingClientRect();
  menu.style.left = Math.max(pad, Math.min(x, window.innerWidth - r.width - pad)) + 'px';
  menu.style.top = Math.max(pad, Math.min(y, window.innerHeight - r.height - pad)) + 'px';
}

/// A flyout sits against the right edge of the row that owns it, overlapping
/// by a couple of pixels so the pointer never crosses a gap, and flips to the
/// left when the right would run off screen.
function positionCtxFlyout(menu, anchorEl) {
  const pad = 6;
  const a = anchorEl.getBoundingClientRect();
  const r = menu.getBoundingClientRect();
  let left = a.right - 2;
  if (left + r.width > window.innerWidth - pad) left = a.left - r.width + 2;
  menu.style.left = Math.max(pad, Math.min(left, window.innerWidth - r.width - pad)) + 'px';
  menu.style.top = Math.max(pad, Math.min(a.top - 4, window.innerHeight - r.height - pad)) + 'px';
}

/// The host category tree, pruned to branches that actually contain a server.
/// Anything the walk does not reach - a server with no category, one pointing
/// at a deleted or key-scope category, one orphaned by a reparent cycle - is
/// returned in `loose` and shown at the top level, so no host is unreachable
/// through the picker no matter what the category table looks like.
function hostPickerTree() {
  const byCat = new Map();
  for (const s of state.servers) {
    if (!s.categoryId) continue;
    if (!byCat.has(s.categoryId)) byCat.set(s.categoryId, []);
    byCat.get(s.categoryId).push(s);
  }
  const byLabel = (a, b) => (a.name || a.host || '').localeCompare(b.name || b.host || '');
  const seen = new Set(); // a cycle in a restored vault must not hang the UI
  const build = (cat) => {
    if (seen.has(cat.id)) return null;
    seen.add(cat.id);
    const hosts = (byCat.get(cat.id) || []).slice().sort(byLabel);
    const children = [];
    for (const child of childrenOfScoped(cat.id, 'host')) {
      const node = build(child);
      if (node && node.total > 0) children.push(node);
    }
    return { cat, hosts, children, total: hosts.length + children.reduce((n, c) => n + c.total, 0) };
  };
  const roots = [];
  for (const cat of childrenOfScoped(null, 'host')) {
    const node = build(cat);
    if (node && node.total > 0) roots.push(node);
  }
  const placed = new Set();
  (function walk(nodes) {
    for (const n of nodes) {
      for (const h of n.hosts) placed.add(h.id);
      walk(n.children);
    }
  })(roots);
  return { roots, loose: state.servers.filter(s => !placed.has(s.id)).sort(byLabel) };
}

/// Render one level of the picker into `menu`: a row per category that opens
/// the next level, then a row per host that connects with `key` overriding
/// whatever key that server has saved - the point of this entry point.
function buildHostPickerLevel(menu, depth, nodes, hosts, key) {
  for (const node of nodes) {
    const b = document.createElement('button');
    b.className = 'ctx-item has-sub';
    b.innerHTML = `${ico('folder')}<span>${escapeHtml(node.cat.name)}</span>`
      + `<small class="ctx-count">${node.total}</small>${ico('chevron-right')}`;
    const openSub = () => {
      hostPickerCancelClose();
      const open = document.querySelector('.ctx-submenu[data-depth="' + (depth + 1) + '"]');
      if (open && open.dataset.owner === node.cat.id) return; // already showing
      hostPickerCloseFrom(depth + 1);
      const sub = document.createElement('div');
      sub.className = 'ctx-menu ctx-submenu';
      sub.dataset.depth = String(depth + 1);
      sub.dataset.owner = node.cat.id;
      buildHostPickerLevel(sub, depth + 1, node.children, node.hosts, key);
      sub.addEventListener('mouseenter', hostPickerCancelClose);
      document.body.appendChild(sub);
      positionCtxFlyout(sub, b);
    };
    b.addEventListener('mouseenter', openSub);
    b.addEventListener('click', openSub);
    menu.appendChild(b);
  }
  if (nodes.length && hosts.length) {
    const sep = document.createElement('div');
    sep.className = 'ctx-sep';
    menu.appendChild(sep);
  }
  for (const s of hosts) {
    const b = document.createElement('button');
    b.className = 'ctx-item';
    b.innerHTML = `${ico('server')}<span>${escapeHtml(s.name || s.host)} `
      + `<small>(${escapeHtml(s.username)}@${escapeHtml(s.host)})</small></span>`;
    b.addEventListener('mouseenter', () => hostPickerScheduleClose(depth + 1));
    b.addEventListener('click', () => {
      closeKeyConnectMenu();
      state._pendingConnectKey = key.id;
      // Set the selection directly rather than through selectServer(): the
      // server list is still rendering under the Keys view's category scope
      // here, and switchView('connect') inside openSessionTab re-renders it
      // against the host scope a moment later anyway.
      state.connectSelectedId = s.id;
      openSessionTab(s, { overrideKeyId: key.id });
    });
    menu.appendChild(b);
  }
}

// Pick an existing saved server and connect immediately using the chosen key.
async function openServerPickerForKey(key, x, y) {
  closeKeyConnectMenu();
  // Nothing but the Connect view loads the server list, so a user who has not
  // opened it yet this session would otherwise be told they have no servers.
  if (!state.servers.length) await loadServers();
  if (!state.servers.length) {
    openServerModal({ keyId: key.id });
    return;
  }
  const { roots, loose } = hostPickerTree();
  const menu = document.createElement('div');
  menu.className = 'ctx-menu';
  menu.id = 'keyConnectMenu';
  buildHostPickerLevel(menu, 0, roots, loose, key);
  const sep = document.createElement('div');
  sep.className = 'ctx-sep';
  menu.appendChild(sep);
  const newBtn = document.createElement('button');
  newBtn.className = 'ctx-item';
  newBtn.innerHTML = `${ico('plus')}<span>New server with this key...</span>`;
  newBtn.addEventListener('mouseenter', () => hostPickerScheduleClose(1));
  newBtn.addEventListener('click', () => {
    closeKeyConnectMenu();
    openServerModal({ keyId: key.id });
  });
  menu.appendChild(newBtn);
  document.body.appendChild(menu);
  positionCtxMenuAt(menu, x, y);
  // One handler for the whole chain: a click inside any menu in it - opening a
  // flyout, say - must not dismiss the menu, which the old per-menu {once:true}
  // listener got wrong (it was spent by the first click, inside or out).
  const away = (ev) => {
    if (ev.type === 'keydown') {
      if (ev.key === 'Escape') closeKeyConnectMenu();
      return;
    }
    if (ev.target.closest && ev.target.closest('.ctx-menu')) return;
    closeKeyConnectMenu();
  };
  hostPickerAwayHandler = away;
  setTimeout(() => {
    if (hostPickerAwayHandler !== away) return; // superseded before we armed
    document.addEventListener('mousedown', away);
    document.addEventListener('keydown', away);
  }, 0);
}

// ─── Connect / disconnect / test ───────────────────────────────────────────

async function testSelectedServer(srv) {
  if (!srv) return;
  terminalSetStatus(`Testing ${srv.host}:${srv.port || 22}...`);
  try {
    // Host-key consent is backend-owned: if the host is unpinned, the native
    // trust dialog (with the fingerprint) is raised by the Rust handler
    // during the handshake. The renderer deliberately passes no consent flag.
    const result = await call('server_test', { serverId: srv.id });
    if (result && result.ok === false) throw new Error(result.error || 'Connection test failed.');
    const ms = result && result.latencyMs != null ? ` (${result.latencyMs} ms)` : '';
    terminalSetStatus(`Connection OK${ms}`);
    toast(`Connection to ${srv.name} succeeded${ms}.`, 'ok');
  } catch (e) {
    terminalSetStatus('Connection test failed.');
    toast(e.message || String(e), 'err');
  }
}

function newTabId() {
  return 'tab-' + Date.now().toString(36) + Math.floor(Math.random() * 1e4);
}

/// Open a NEW session tab for a server (always a new tab - never replaces).
async function openSessionTab(srv, opts = {}) {
  if (typeof window.terminalConnectInTab !== 'function') {
    toast('terminal.js is missing - Connect cannot run.', 'err');
    return;
  }
  switchView('connect');
  const tabId = newTabId();
  const tab = {
    tabId,
    sessionId: null,
    serverId: srv.id,
    serverName: srv.name || srv.host,
    host: srv.host,
    port: srv.port || 22,
    mode: 'ssh',
    sftpReady: false,
    sftpPath: '/',
    ended: false,
  };
  state.sessions.set(tabId, tab);
  window.createTabTerminal(tabId);
  activateSessionSurface(tabId);
  el('termDisconnectBtn').hidden = true;
  el('termReconnectBtn').hidden = true;
  terminalSetStatus(`Connecting to ${srv.host}:${srv.port}...`);

  let pw = null;
  if (srv.authMethod !== 'publickey' && !srv.hasSavedPassword) {
    pw = await new Promise(resolve => askConnectPassword(srv, resolve));
    if (pw === null || pw === undefined) {
      terminalSetStatus('Cancelled.');
      closeSessionTab(tabId, { skipConfirm: true });
      return;
    }
  }

  try {
    const sessionId = await window.terminalConnectInTab(tabId, srv, { ...opts, promptPassword: pw });
    tab.sessionId = sessionId;
    renderTermTabs();
    updateTerminalHead();
    terminalSetStatus(`Connected to ${srv.host}:${srv.port} - streaming`);
  } catch (e) {
    tab.ended = true;
    renderTermTabs();
    updateTerminalHead();
    terminalSetStatus(`Failed: ${e.message || e}`);
    toast(e.message || String(e), 'err');
  }
}

/// Disconnect the active tab's live session (tab stays with [connection closed]).
async function disconnectActiveTab() {
  const tab = state.sessions.get(state.activeTabId);
  if (!tab || !window.tabSessionLive(tab.tabId)) return;
  try { await call('terminal_disconnect', { sessionId: tab.sessionId }); } catch (e) {}
  // The close-detection poll fires onSessionClosed, which finalizes tab state.
}

/// Toggle the terminal between the normal Connect layout and a full-app
/// "maximized" mode: sidebar/topbar/server-list hidden, terminal fills the
/// window, and a thin taskbar strip (status + restore button) remains.
function toggleTermMax() {
  const app = el('app');
  const btn = el('termMaxBtn');
  if (!app || !btn) return;
  const max = app.classList.toggle('term-max');
  btn.innerHTML = ico(max ? 'minimize-2' : 'maximize-2');
  btn.title = max ? 'Restore terminal size (<>)' : 'Expand terminal to full window';
  if (typeof terminalSetStatus === 'function') {
    terminalSetStatus(max ? 'Terminal maximized - press Esc or <> to restore.' : 'Restored.');
  }
  // Let the layout settle, then refit + push the new PTY size. Focus after
  // maximize is wanted (the terminal is the whole view); fitActiveTerminal
  // alone does not focus, so a window resize never steals keystrokes from a
  // modal or input.
  setTimeout(() => { if (typeof window.fitActiveTerminalAndFocus === 'function') window.fitActiveTerminalAndFocus(); }, 80);
  setTimeout(() => { if (typeof window.fitActiveTerminalAndFocus === 'function') window.fitActiveTerminalAndFocus(); }, 250);
}

/// Reconnect the active tab: new session in the SAME tab (keeps scrollback).
async function reconnectActiveTab() {
  const tab = state.sessions.get(state.activeTabId);
  if (!tab) return;
  const srv = state.servers.find(s => s.id === tab.serverId);
  if (!srv) { toast('Server no longer exists.', 'err'); return; }
  let pw = null;
  if (srv.authMethod !== 'publickey' && !srv.hasSavedPassword) {
    pw = await new Promise(resolve => askConnectPassword(srv, resolve));
    if (pw === null || pw === undefined) return;
  }
  terminalSetStatus(`Reconnecting to ${srv.host}:${srv.port}...`);
  el('termDisconnectBtn').hidden = true;
  el('termReconnectBtn').hidden = true;
  try {
    const sessionId = await window.terminalConnectInTab(tab.tabId, srv, { promptPassword: pw });
    tab.sessionId = sessionId;
    tab.ended = false;
    renderTermTabs();
    updateTerminalHead();
    terminalSetStatus(`Connected to ${srv.host}:${srv.port} - streaming`);
  } catch (e) {
    renderTermTabs();
    updateTerminalHead();
    terminalSetStatus(`Failed: ${e.message || e}`);
    toast(e.message || String(e), 'err');
  }
}

/// Activate the complete SSH/SFTP surface for one connection tab.
function activateSessionSurface(tabId) {
  const tab = state.sessions.get(tabId);
  if (!tab) return;
  window.__activeSessionSurface = tabId;
  tab.bell = false;
  state.activeTabId = tabId;
  if (typeof window.assistantOnTabSwitch === 'function') window.assistantOnTabSwitch(tabId);
  if (tab.mode === 'split') {
    if (typeof window.showSplitForTab !== 'function') return;
    window.showSplitForTab(tabId);
  } else if (tab.mode === 'sftp') {
    if (typeof window.showSftpForTab !== 'function') return;
    window.showSftpForTab(tabId);
  } else {
    if (typeof window.showSshForTab === 'function') window.showSshForTab(tabId);
    else if (typeof window.showTabTerminal === 'function') window.showTabTerminal(tabId);
    else return;
  }
  renderTermTabs();
  updateTerminalHead();
}

/// Close a tab: disconnect if live, dispose terminal, forget the session.
async function closeSessionTab(tabId, { skipConfirm = false } = {}) {
  const tab = state.sessions.get(tabId);
  if (!tab) return;
  let live = window.tabSessionLive(tabId);
  // Only a live shell is worth asking about. With nothing to ask (or skipConfirm)
  // nothing is awaited, so the whole close still runs synchronously, as before.
  if (live && !skipConfirm) {
    const ok = await confirmModal('Close session', `Close the session to ${tab.serverName}?`, 'Close session');
    if (!ok) return;
    // The dialog is modal, not frozen: the session can end, or the vault lock
    // and tear every tab down, while it is open. Act on what is true now.
    if (state.sessions.get(tabId) !== tab) return;
    live = window.tabSessionLive(tabId);
  }
  if (live) call('terminal_disconnect', { sessionId: tab.sessionId }).catch(() => {});
  if (tab.sftpReady) call('sftp_close', { sessionId: tab.sessionId || '' }).catch(() => {});
  window.destroyTabTerminal(tabId);
  const panel = document.getElementById('sftpPanel-' + tabId);
  if (panel) panel.remove();
  state.sessions.delete(tabId);
  // Its assistant conversation, pending approval and access level go too.
  window.assistantClearTab?.(tabId);
  if (state.activeTabId === tabId) {
    const nextId = state.sessions.keys().next().value || null;
    if (nextId) activateSessionSurface(nextId);
    else {
      state.activeTabId = null;
      const sbody = document.getElementById('sftpBody');
      if (sbody) {
        sbody.classList.remove('visible');
        for (const child of sbody.children) child.style.display = 'none';
      }
      const body = document.getElementById('terminalBody');
      if (body) body.style.display = 'flex';
      renderTermTabs();
      updateTerminalHead();
    }
  } else {
    renderTermTabs();
    updateTerminalHead();
  }
}

/// Activate a tab (click on its chip).
function activateSessionTab(tabId) {
  activateSessionSurface(tabId);
}

/// Tab strip: chips for each session + the persistent "+" button.
function renderTermTabs() {
  const strip = el('termTabs');
  if (!strip) return;
  // The chips are rebuilt; a focused chip (or its close button) gets the focus
  // back on its replacement (A1-26).
  const had = strip.contains(document.activeElement) ? document.activeElement.closest('.term-tab') : null;
  const refocus = had && { id: had.dataset.tabId, close: document.activeElement.classList.contains('term-tab-close') };
  strip.querySelectorAll('.term-tab').forEach(n => n.remove());
  const addBtn = el('termTabAdd');
  for (const [tabId, tab] of state.sessions) {
    const chip = document.createElement('div');
    chip.className = 'term-tab' + (tabId === state.activeTabId ? ' active' : '') + (tab.ended ? ' ended' : '') + (tab.bell ? ' bell' : '');
    chip.dataset.tabId = tabId;
    // Keyboard-operable (A1-11): a tab stop, Enter/Space switch to it.
    chip.tabIndex = 0;
    chip.setAttribute('role', 'button');
    if (tabId === state.activeTabId) chip.setAttribute('aria-current', 'true');
    chip.addEventListener('keydown', (ev) => {
      if (ev.target !== chip || (ev.key !== 'Enter' && ev.key !== ' ')) return;
      ev.preventDefault();
      activateSessionTab(tabId);
    });
    const dot = document.createElement('span');
    dot.className = 'term-tab-dot' + (window.tabSessionLive(tabId) ? ' live' : '');
    const name = document.createElement('span');
    name.className = 'term-tab-name';
    name.textContent = tab.serverName;
    name.title = `${tab.serverName} (${tab.host}:${tab.port})`;
    const close = document.createElement('button');
    close.type = 'button';
    close.className = 'term-tab-close';
    close.textContent = '×';
    close.title = 'Close session';
    close.setAttribute('aria-label', 'Close the session to ' + tab.serverName);
    close.addEventListener('click', (ev) => { ev.stopPropagation(); closeSessionTab(tabId); });
    chip.appendChild(dot);
    chip.appendChild(name);
    chip.appendChild(close);
    chip.addEventListener('click', () => activateSessionTab(tabId));
    chip.addEventListener('contextmenu', (ev) => {
      ev.preventDefault();
      activateSessionTab(tabId);
      openTerminalContextMenu(ev.clientX, ev.clientY, tabId);
    });
    strip.insertBefore(chip, addBtn);
  }
  if (refocus) {
    const chip = [...strip.querySelectorAll('.term-tab')].find((c) => c.dataset.tabId === refocus.id);
    if (chip) (refocus.close ? chip.querySelector('.term-tab-close') : chip).focus();
  }
  // The server list carries the same live/idle state on its rows, so it has to
  // be redrawn whenever the set of sessions changes.
  if (state.view === 'connect' && el('serverList')) renderServerList();
  updateNavCounts();
}

/// Head title + buttons follow the active tab, or the selected server.
function updateTerminalHead() {
  const tab = state.sessions.get(state.activeTabId);
  const srv = currentSelectedServer();
  el('termTestBtn').hidden = !srv;
  if (tab) {
    el('termTitle').textContent = tab.serverName;
    el('termBadge').textContent = `${tab.host}:${tab.port}`;
    el('termBadge').hidden = false;
    const live = window.tabSessionLive(tab.tabId);
    el('termDisconnectBtn').hidden = !live;
    el('termReconnectBtn').hidden = live;
    setModeSeg(live, tab.mode);
  } else if (srv) {
    el('termTitle').textContent = srv.name;
    el('termBadge').textContent = `${srv.host}:${srv.port}`;
    el('termBadge').hidden = false;
    el('termDisconnectBtn').hidden = true;
    el('termReconnectBtn').hidden = false;
    setModeSeg(false);
  } else {
    el('termTitle').textContent = 'No connection';
    el('termBadge').hidden = true;
    el('termDisconnectBtn').hidden = true;
    el('termReconnectBtn').hidden = true;
    setModeSeg(false);
  }
  updateNavCounts();
}

/// The surface control shows which of the three you are LOOKING AT. The button
/// it replaced was labelled with the mode you would switch to, so it read
/// "SFTP" while you were in the shell - unreadable in either direction.
function setModeSeg(visible, mode) {
  const seg = el('termModeSeg');
  if (!seg) return;
  seg.hidden = !visible;
  if (!visible) return;
  for (const b of seg.querySelectorAll('.seg-btn')) {
    const on = b.dataset.mode === (mode || 'ssh');
    b.classList.toggle('active', on);
    b.setAttribute('aria-selected', on ? 'true' : 'false');
    b.tabIndex = on ? 0 : -1;
  }
}

/// Called by terminal.js when a tab's SSH session ends (server side or drop).
function onSessionClosed(tabId) {
  const tab = state.sessions.get(tabId);
  if (!tab) return;
  tab.ended = true;
  if (tab.sftpReady) {
    call('sftp_close', { sessionId: tab.sessionId || '' }).catch(() => {});
    tab.sftpReady = false;
  }
  // Any non-shell mode falls back to the shell. Resetting only 'sftp' left a
  // split tab stranded: split re-activated the dead SFTP surface (every
  // navigation then toasted a list error) while setModeSeg(false) hid the
  // Shell/Files/Split control, so there was no visible way out.
  if (tab.mode !== 'ssh') tab.mode = 'ssh';
  tab.sessionId = null;
  if (tabId === state.activeTabId) {
    activateSessionSurface(tabId);
    terminalSetStatus('Connection closed.');
  }
  renderTermTabs();
  updateTerminalHead();
}
window.onSessionClosed = onSessionClosed;
window.activateSessionSurface = activateSessionSurface;

// ─── on-disk paths, HTML escaping ─────────────────────────────────────────

// Real on-disk locations, fetched once. Three UI strings used to hard-code
// these and all three were wrong; deriving them from the backend is what stops
// them drifting again. Falls back to honest placeholders rather than to a
// plausible-looking guess.
let _systemPaths = null;
async function systemPaths() {
  if (_systemPaths) return _systemPaths;
  try {
    _systemPaths = await call('system_paths');
  } catch (e) {
    _systemPaths = { database: '(unknown)', sshConfig: '(unknown)', deployDir: '(unknown)' };
  }
  return _systemPaths;
}

// The escaper for markup built from strings (menus, palette rows). It escapes
// for both text and attribute context. The apostrophe is included even though
// every interpolated attribute in this codebase currently uses double quotes:
// that is a property nothing enforces, and the first single-quoted attribute
// added later would silently become an injection point. Cheap here, invisible
// to catch there.
function escapeHtml(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// ─── boot ──────────────────────────────────────────────────────────────────

(async function main() {
  // Persistent boot-error log - readable via CDP even after the toast fades.
  window.__bootErrors = window.__bootErrors || [];
  window.addEventListener('error', (ev) => {
    const msg = 'JS error: ' + (ev.message || 'unknown');
    window.__bootErrors.push(msg + (ev.filename ? ' @ ' + ev.filename + ':' + ev.lineno : ''));
    toast(msg, 'err');
  });
  window.addEventListener('unhandledrejection', (ev) => {
    const r = ev.reason;
    window.__bootErrors.push('unhandled rejection: ' + (r && r.message ? r.message : String(r)));
  });

  window.__SSHPAN_BUILD__ = 'v14-tabs';;;
  document.title = 'SSHSpan (' + window.__SSHPAN_BUILD__ + ')';

  injectIcons();
  // Show/hide on every password field (A5-35); the prompt's only shows while
  // it asks for a password.
  wireRevealToggles(document);
  const promptReveal = addRevealToggle(el('promptInput'));
  if (promptReveal) promptReveal.hidden = true;
  // Before wire(): the observer must be watching every .modal-backdrop before
  // anything can open one.
  initModalFocusManagement();
  try {
    wire();
  } catch (e) {
    window.__bootErrors.push('wire() threw: ' + (e.stack || e.message || String(e)));
    toast('UI init failed: ' + e.message, 'err');
    throw e;
  }
  onGenTypeChange();
  switchTab('generate');
  updateSelectionHint();
  loadBrandIcon();

  // Load the terminal stack explicitly, in order, with loud per-file errors.
  // A statically-failed <script src> fires no window.onerror - it fails
  // silently, which cost us days of "blank terminal" debugging.
  const loadScript = (src) => new Promise((resolve) => {
    const s = document.createElement('script');
    s.src = src;
    s.onload = () => resolve({ src, ok: true });
    s.onerror = () => resolve({ src, ok: false });
    document.head.appendChild(s);
  });
  const results = [];
  for (const src of ['vendor/xterm.js', 'vendor/addon-fit.js', 'vendor/addon-web-links.js', 'terminal.js', 'sftp.js', 'assistant.js', 'mcp.js']) {
    const r = await loadScript(src);
    results.push(r);
    if (!r.ok) toast('Failed to load ' + src + ' - Connect will not work.', 'err');
  }

  // Build marker: visible in the sidebar brand on every screen (the window
  // title is owned by the OS window and does not follow document.title).
  const brandSub = document.querySelector('.brand-sub');
  if (brandSub) brandSub.textContent = 'KEYS & SESSIONS · ' + window.__SSHPAN_BUILD__;

  if (!window.__SSHPAN_TERMINAL_JS__) {
    toast('terminal.js loaded but did not initialize - Connect view will not work.', 'err');
  } else if (!window.Terminal) {
    toast('xterm.js did not expose window.Terminal - terminal rendering unavailable.', 'err');
  }

  // One failing call in here (vault_status itself, or a load behind an
  // unlocked vault) used to reject out of main() before anything below was
  // wired: no stored settings, no idle-activity listeners, no 10 s status
  // poll - an app that never noticed a lock (A2-20). It is reported instead;
  // the poll below tries again.
  try {
    await refreshVaultStatus();
  } catch (e) {
    const msg = (e && e.message) || String(e);
    window.__bootErrors.push('first vault refresh failed: ' + msg);
    toast(msg, 'err');
  }

  // Auto-lock idle clock: real input resets it (see onHumanInput); expiry
  // calls lockNow().
  for (const ev of HUMAN_INPUT_EVENTS) {
    window.addEventListener(ev, onHumanInput, { capture: true, passive: true });
  }
  // The persisted settings, in effect from boot (loadSettings only runs when
  // the Settings view is opened); this also arms the idle timer for the
  // stored minutes.
  let stored = {};
  try { stored = await call('settings_get'); } catch (e) { /* defaults */ }
  applyStoredSettings(stored);

  // Optional update check (only when the setting is ticked; never auto-installs).
  autoUpdateCheckOnBoot();

  // Catch auto-locks without user interaction.
  setInterval(() => {
    refreshVaultStatus(true).catch(() => {});
  }, 10000);
})().catch((e) => {
  toast(e.message || String(e), 'err');
});
