/**
 * app.js — SSHSpan renderer controller (Tauri v2).
 * ---------------------------------------------------------------------------
 * Plain DOM + Tauri's invoke(). No Node, no require, no framework.
 * Every IPC call goes through invoke() which returns the Rust Result<T, String>.
 * Private key material never reaches this process; exports are explicit
 * user-initiated downloads.
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

let toastTimer = null;
function toast(msg, kind) {
  const t = el('toast');
  t.textContent = msg;
  t.className = 'show ' + (kind || 'info');
  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.className = ''; }, 3800);
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

async function copyText(text) {
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

/** Guard: render an icon value only if it exists; never leak "undefined" text. */
function ico(name) {
  return ICONS[name] || '';
}

/** 32–36px rounded key-type tile used by key rows and the detail pane. */
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

/** <a data-vault-state=…> pill for the sidebar vault indicator. */
function vaultStatusHTML(unlocked, hasVault) {
  const s = unlocked ? 'unlocked' : (hasVault ? 'locked' : 'novault');
  return {
    state: s,
    icon: ico(unlocked ? 'lock-open' : 'lock'),
    label: unlocked ? 'Unlocked' : (hasVault ? 'Locked' : 'No vault'),
  };
}

// ─── category tree helpers ─────────────────────────────────────────────────

function rebuildCategoryIndex() {
  state.catsById = new Map();
  state.childrenOf = new Map();
  for (const c of state.categories) {
    state.catsById.set(c.id, c);
    const key = c.parent_id || ''; // empty string for roots
    if (!state.childrenOf.has(key)) state.childrenOf.set(key, []);
    state.childrenOf.get(key).push(c);
  }
  for (const list of state.childrenOf.values()) list.sort((a, b) => a.sort_index - b.sort_index || a.name.localeCompare(b.name));
}

function catById(id) { return state.catsById.get(id); }

function childrenOf(parentId) {
  return state.childrenOf.get(parentId || '') || [];
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

function keysInCategory(catId) {
  return state.keys.filter(k => (state.keyCategories[k.id] || []).includes(catId));
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

function filteredKeys() {
  const q = el('searchInput').value.trim().toLowerCase();
  const type = el('typeFilter').value;
  let pool = state.keys;
  if (state.activeCategoryId === 'uncategorized') {
    pool = state.keys.filter(k => (state.keyCategories[k.id] || []).length === 0);
  } else if (state.activeCategoryId !== 'all') {
    pool = keysInCategoryRecursive(state.activeCategoryId);
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
  row.draggable = true;
  if (state.activeCategoryId === cat.id) row.classList.add('active');

  const kids = childrenOf(cat.id);
  const chev = document.createElement('span');
  chev.className = 'cat-chevron';
  if (kids.length === 0) chev.classList.add('leaf');
  else {
    chev.innerHTML = ico('chevron-right');
    if (state.expandedCatIds.has(cat.id)) chev.classList.add('expanded');
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
  const n = directKeyCount(cat.id);
  cnt.textContent = n;
  row.appendChild(cnt);

  const menuBtn = document.createElement('button');
  menuBtn.className = 'cat-actions-btn';
  menuBtn.title = 'Category actions';
  menuBtn.innerHTML = ico('ellipsis');
  menuBtn.addEventListener('click', (e) => { e.stopPropagation(); openCatMenu(cat, menuBtn); });
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
  tree.innerHTML = '';
  const panel = el('catPanel');
  if (panel) panel.hidden = state.categories.length === 0 && !state.orphans;
  if (state.orphans) {
    const u = document.createElement('div');
    u.className = 'cat-node uncategorized';
    u.dataset.id = 'uncategorized';
    u.dataset.depth = '0';
    if (state.activeCategoryId === 'uncategorized') u.classList.add('active');
    const chev = document.createElement('span'); chev.className = 'cat-chevron leaf'; u.appendChild(chev);
    const catIco = document.createElement('span'); catIco.className = 'cat-ico'; catIco.innerHTML = ico('folder'); u.appendChild(catIco);
    const lbl = document.createElement('span'); lbl.className = 'cat-label'; lbl.textContent = 'Uncategorized'; u.appendChild(lbl);
    const cnt = document.createElement('span'); cnt.className = 'cat-count'; cnt.textContent = uncategorizedKeyCount(); u.appendChild(cnt);
    u.addEventListener('click', () => setActiveCategory('uncategorized'));
    tree.appendChild(u);
  }
  for (const c of childrenOf(null)) tree.appendChild(catNodeEl(c, 0));
}

function toggleCatExpanded(id) {
  if (state.expandedCatIds.has(id)) state.expandedCatIds.delete(id);
  else state.expandedCatIds.add(id);
  renderCategoryTree();
}

function setActiveCategory(id) {
  if (state.activeCategoryId === id) id = 'all';
  state.activeCategoryId = id;
  renderCategoryTree();
  updateBreadcrumb();
  renderKeyList();
  updateCatFilterButton();
  updateSelectionHint();
}

// ─── category CRUD ─────────────────────────────────────────────────────────

async function loadCategories() {
  const res = await call('category_list');
  state.categories = res.categories || [];
  state.keyCategories = res.allKeyCategories || {};
  state.orphans = !!res.orphans;
  rebuildCategoryIndex();
  renderCategoryTree();
  updateBreadcrumb();
  updateCatFilterButton();
}

async function createCategory(name, parentId, color) {
  if (!name) return null;
  const cat = await call('category_create', { name, parentId, color });
  await loadCategories();
  return cat;
}

async function deleteCategory(id) {
  const cat = catById(id);
  if (!cat) return;
  const ok = window.confirm(`Delete category "${cat.name}"? Children will be reassigned to its parent, and any keys using this category will become Uncategorized.`);
  if (!ok) return;
  try {
    const res = await call('category_delete', { id });
    await loadCategories();
    if (state.activeCategoryId === id) setActiveCategory('all');
    renderKeyList();
    toast(`Category "${cat.name}" deleted.` + (res.reassigned && res.reassigned.length ? ` ${res.reassigned.length} child(ren) reassigned.` : ''), 'ok');
  } catch (e) { toast(e.message || String(e), 'err'); }
}

async function renameCategory(id) {
  const cat = catById(id); if (!cat) return;
  promptModal(`Rename category`, 'Enter a new name.', cat.name, async (newName) => {
    if (!newName || newName === cat.name) return;
    try { await call('category_rename', { id, name: newName }); await loadCategories(); toast('Renamed.', 'ok'); }
    catch (e) { toast(e.message || String(e), 'err'); }
  });
}

async function moveCategoryPrompt(id) {
  // opens the picker in single-select mode for choosing a new parent
  openCategoryPicker({
    title: 'Move to…',
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
  promptModal('New category', 'Enter a name.', '', async (name) => {
    if (!name) return;
    const cat = await createCategory(name, parentId || null, null);
    if (cat) { state.expandedCatIds.add(parentId || ''); /* noop for roots */ if (parentId) state.expandedCatIds.add(parentId); renderCategoryTree(); toast(`Created "${cat.name}".`, 'ok'); }
  });
}

// ─── cat row menu ─────────────────────────────────────────────────────────

let openMenu = null;
function closeCatMenu() {
  if (openMenu) { openMenu.remove(); openMenu = null; }
  document.removeEventListener('mousedown', onMenuOutside, true);
}
function onMenuOutside(e) {
  if (openMenu && !openMenu.contains(e.target)) closeCatMenu();
}
function openCatMenu(cat, anchor) {
  closeCatMenu();
  const m = document.createElement('div');
  m.className = 'cat-menu';
  m.innerHTML =
    `<button data-act="rename"><span data-ico="pencil"></span>Rename</button>` +
    `<button data-act="addChild"><span data-ico="folder-plus"></span>New subcategory</button>` +
    `<button data-act="move"><span data-ico="move"></span>Move to…</button>` +
    `<button data-act="delete" class="danger"><span data-ico="x"></span>Delete</button>`;
  // position absolutely under the anchor; the sidebar isn't a positioning ancestor, so use fixed.
  const r = anchor.getBoundingClientRect();
  m.style.position = 'fixed';
  m.style.top = (r.bottom + 2) + 'px';
  m.style.left = Math.max(4, r.right - 170) + 'px';
  document.body.appendChild(m);
  openMenu = m;
  setTimeout(() => document.addEventListener('mousedown', onMenuOutside, true), 0);
  m.addEventListener('click', async (e) => {
    const btn = e.target.closest('button'); if (!btn) return;
    closeCatMenu();
    const act = btn.dataset.act;
    if (act === 'rename') renameCategory(cat.id);
    else if (act === 'addChild') addCategoryPrompt(cat.id);
    else if (act === 'move') moveCategoryPrompt(cat.id);
    else if (act === 'delete') deleteCategory(cat.id);
  });
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
  if (state.view !== 'keys') { bc.hidden = true; return; }
  let path = [];
  if (state.activeCategoryId === 'uncategorized') path = ['Uncategorized'];
  else if (state.activeCategoryId !== 'all') {
    const segs = catPath(state.activeCategoryId);
    path = segs;
  }
  if (!path.length) { bc.hidden = true; return; }
  bc.hidden = false;
  bc.innerHTML = '';
  const rootLink = document.createElement('a');
  rootLink.href = '#'; rootLink.textContent = 'Keys';
  rootLink.addEventListener('click', (e) => { e.preventDefault(); setActiveCategory('all'); });
  bc.appendChild(rootLink);
  // for normal category path, walk segments and add clickable ancestors
  if (state.activeCategoryId === 'uncategorized') {
    const sep = document.createElement('span'); sep.className = 'crumb-sep'; sep.textContent = '/'; bc.appendChild(sep);
    const cur = document.createElement('span'); cur.className = 'crumb-current'; cur.textContent = 'Uncategorized'; bc.appendChild(cur);
  } else {
    const segs = catPath(state.activeCategoryId);
    const ids = []; let cur = catById(state.activeCategoryId);
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

function updateCatFilterButton() {
  const btn = el('catFilterBtn'); if (!btn) return;
  btn.disabled = false;
  const lbl = el('catFilterLabel'); if (!lbl) return;
  if (state.activeCategoryId === 'all') {
    lbl.textContent = 'All categories';
    btn.classList.remove('active');
  } else if (state.activeCategoryId === 'uncategorized') {
    lbl.textContent = 'Uncategorized';
    btn.classList.add('active');
  } else {
    lbl.textContent = catPathString(state.activeCategoryId);
    btn.classList.add('active');
  }
}

// ─── multi-select picker (shared widget) ──────────────────────────────────

function openCategoryPicker({ title, initial, single, onSave }) {
  state.pickerSelected = new Set(initial || []);
  state.pickerSingle = !!single;
  state.pickerCallback = onSave;
  el('pickerTitle').textContent = title || 'Categories';
  el('pickerSaveBtn').textContent = single ? 'Select' : 'Save';
  el('pickerSearch').value = '';
  renderPickerTree('');
  el('pickerModal').hidden = false;
}

function closeCategoryPicker() {
  el('pickerModal').hidden = true;
  state.pickerCallback = null;
  state.pickerSelected = new Set();
  state.pickerSingle = false;
}

function renderPickerTree(filter) {
  const tree = el('pickerTree');
  tree.innerHTML = '';
  const lower = (filter || '').toLowerCase();
  const matches = (name) => !lower || name.toLowerCase().includes(lower);
  const walk = (cat, depth) => {
    const visible = matches(cat.name) || (depth === 0 && lower === '');
    // include if any descendant matches
    const anyDesc = !lower ? true : treeHasMatchingDescendant(cat.id, lower);
    if (!visible && !anyDesc) return;
    const row = document.createElement('div');
    row.className = 'picker-row';
    if (state.pickerSelected.has(cat.id)) row.classList.add('checked');
    row.dataset.depth = String(depth);
    const indent = document.createElement('span');
    indent.className = 'picker-indent';
    indent.style.width = (depth * 14) + 'px';
    row.appendChild(indent);
    const box = document.createElement('span'); box.className = 'picker-box'; row.appendChild(box);
    const name = document.createElement('span'); name.className = 'picker-name'; name.textContent = cat.name; row.appendChild(name);
    row.addEventListener('click', () => {
      if (state.pickerSelected.has(cat.id)) state.pickerSelected.delete(cat.id);
      else { if (state.pickerSingle) state.pickerSelected.clear(); state.pickerSelected.add(cat.id); }
      if (state.pickerSingle) {
        // commit immediately
        const cb = state.pickerCallback; closeCategoryPicker();
        if (cb) cb([...state.pickerSelected]);
        return;
      }
      renderPickerTree(lower);
    });
    tree.appendChild(row);
    for (const c of childrenOf(cat.id)) walk(c, depth + 1);
  };
  // uncategorized
  if (!lower || 'uncategorized'.includes(lower)) {
    const u = document.createElement('div');
    u.className = 'picker-row';
    u.dataset.depth = '0';
    const indent = document.createElement('span'); indent.className = 'picker-indent'; u.appendChild(indent);
    const box = document.createElement('span'); box.className = 'picker-box'; u.appendChild(box);
    const name = document.createElement('span'); name.className = 'picker-name'; name.textContent = 'Uncategorized'; u.appendChild(name);
    u.style.display = 'none';
    tree.appendChild(u);
  }
  for (const c of childrenOf(null)) walk(c, 0);
  if (state.categories.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'picker-row';
    empty.style.opacity = '0.6';
    empty.style.cursor = 'default';
    empty.innerHTML = '<span class="picker-name">No categories yet. Create one in the sidebar.</span>';
    tree.appendChild(empty);
  }
}

function treeHasMatchingDescendant(catId, lower) {
  for (const c of childrenOf(catId)) {
    if (c.name.toLowerCase().includes(lower)) return true;
    if (treeHasMatchingDescendant(c.id, lower)) return true;
  }
  return false;
}

// ─── prompt modal (rename / new category) ──────────────────────────────────

function promptModal(title, message, initial, onOk) {
  el('promptTitle').textContent = title;
  el('promptMessage').textContent = message || '';
  el('promptInput').value = initial || '';
  state.promptCallback = onOk;
  el('promptModal').hidden = false;
  setTimeout(() => el('promptInput').focus(), 0);
}
function closePrompt() { el('promptModal').hidden = true; state.promptCallback = null; }

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

const state = {
  hasVault: false,
  unlocked: false,
  vaultMode: 'unlock',
  keys: [],
  selectedId: null,
  deploySelected: new Set(),
  settings: {},
  view: 'keys',
  // category tree
  categories: [],            // flat list, ordered for tree display
  catsById: new Map(),       // id -> category
  childrenOf: new Map(),     // parent_id (string|null) -> [category]
  keyCategories: {},         // keyId -> [catId]
  orphans: false,            // true when at least one key has no categories
  activeCategoryId: 'all',   // 'all' | 'uncategorized' | categoryId
  expandedCatIds: new Set(), // sidebar expanded nodes
  groupExpanded: new Set(),  // key-list group headers
  // picker
  pickerCallback: null,
  pickerSelected: new Set(),  // ids the user has ticked
  // drag
  draggingCatId: null,
  // prompt
  promptCallback: null,
  // connect / saved servers
  servers: [],
  connectSelectedId: null,
  connectAuthMethod: 'publickey',
  _pendingConnectServer: null,  // server id set by openServerPickerForKey
  _pendingConnectKey: null,
};

// ─── vault gate ────────────────────────────────────────────────────────────

function showVaultModal(mode) {
  state.vaultMode = mode;
  const title = el('vaultModalTitle');
  const text = el('vaultModalText');
  const pw = el('vaultPassword');
  const confirm = el('vaultPasswordConfirm');
  const current = el('vaultPasswordCurrent');
  const primary = el('vaultPrimary');
  pw.value = ''; confirm.value = ''; current.value = '';
  pw.hidden = false;
  confirm.hidden = mode !== 'create' && mode !== 'change';
  current.hidden = true;
  if (mode === 'create') {
    title.textContent = 'Create your vault';
    text.textContent = 'Choose a master password. It encrypts every private key at rest (scrypt + AES-256-GCM). There is no recovery \u2014 if you lose it, the keys are gone.';
    primary.textContent = 'Create vault';
  } else if (mode === 'change') {
    title.textContent = 'Change master password';
    text.textContent = 'Every stored private key is re-encrypted with the new password before the vault accepts it.';
    primary.textContent = 'Change password';
  } else {
    title.textContent = 'Unlock vault';
    text.textContent = 'Enter your master password to decrypt your keys for this session.';
    primary.textContent = 'Unlock';
  }
  el('vaultModal').hidden = false;
  pw.focus();
}

function hideVaultModal() { el('vaultModal').hidden = true; }

async function refreshVaultStatus(silent) {
  const s = await call('vault_status');
  const wasUnlocked = state.unlocked;
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
  el('newKeyBtn').disabled = !s.unlocked;
  el('lockBtn').disabled = !s.unlocked;
  el('changePasswordBtn').disabled = !s.unlocked;
  applyNavLockState();

  if (!s.hasVault) {
    showVaultModal('create');
  } else if (!s.unlocked) {
    clearKeysUI();
    clearConnectView();
    showVaultModal('unlock');
  } else {
    hideVaultModal();
    if (!wasUnlocked || !silent) await loadKeys();
  }
}

// Lock/unlock the nav buttons that require an unlocked vault (Connect, Deploy).
function applyNavLockState() {
  for (const b of document.querySelectorAll('.nav-item[data-requires-unlock]')) {
    b.classList.toggle('locked', !state.unlocked);
    b.disabled = !state.unlocked;
    if (!state.unlocked && b.classList.contains('active')) {
      switchView('keys');
    }
  }
}

// Called when the vault locks or while the connect view is shown without an unlocked vault.
function clearConnectView() {
  state.servers = [];
  state.connectSelectedId = null;
  if (typeof terminalReset === 'function') terminalReset('Vault is locked.');
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
}

async function submitVaultModal() {
  const mode = state.vaultMode;
  const pw = el('vaultPassword').value;
  const confirm = el('vaultPasswordConfirm').value;
  try {
    if (mode === 'create') {
      if (pw.length < 8) throw new Error('Master password must be at least 8 characters.');
      if (pw !== confirm) throw new Error('Passwords do not match.');
      await call('vault_create', { password: pw });
      toast('Vault created. Welcome to SSHSpan.', 'ok');
    } else if (mode === 'change') {
      if (pw.length < 8) throw new Error('New password must be at least 8 characters.');
      if (pw !== confirm) throw new Error('Passwords do not match.');
      await call('vault_change_password', { currentPassword: state.currentPassword || '', newPassword: pw });
      toast('Master password changed; all keys re-encrypted.', 'ok');
    } else {
      await call('vault_unlock', { password: pw });
      state.currentPassword = pw;
      toast('Vault unlocked.', 'ok');
    }
    await refreshVaultStatus();
  } catch (e) {
    toast(e.message || String(e), 'err');
    el('vaultPassword').select();
  }
}

// ─── keys view ─────────────────────────────────────────────────────────────

function clearKeysUI() {
  state.keys = [];
  state.selectedId = null;
  state.deploySelected.clear();
  el('keyList').innerHTML = '';
  el('detailPane').hidden = true;
  el('emptyState').hidden = false;
  state.keyCategories = {};
  state.orphans = false;
  updateSelectionHint();
  updateBreadcrumb();
  updateCatFilterButton();
}

function updateSelectionHint() {
  const n = state.deploySelected.size;
  const hint = el('selectionHint');
  if (hint) hint.textContent = n > 0 ? n + ' selected for deploy' : '';
  const dHint = el('deploySelectionHint');
  if (dHint) dHint.textContent = n > 0
    ? n + ' key(s) will be deployed.'
    : 'Select keys to deploy using the checkboxes in the Keys view.';
  const chip = el('deployCount');
  if (chip) {
    chip.hidden = n === 0;
    chip.textContent = n === 1 ? '1 key ready' : n + ' keys ready';
  }
  const sub = el('viewSubtitle');
  if (sub) {
    sub.textContent = n > 0
      ? (n === 1 ? '1 key staged for deploy' : n + ' keys staged for deploy')
      : (state.keys.length === 1 ? '1 key in vault' : state.keys.length + ' keys in vault');
  }
}

function filteredKeys() {
  const q = el('searchInput').value.trim().toLowerCase();
  const type = el('typeFilter').value;
  return state.keys.filter(k => {
    if (type && k.key_type !== type) {
      // "ecdsa" filter matches any ecdsa-p256/p384/p521 variant
      if (type !== 'ecdsa' || !k.key_type.startsWith('ecdsa')) return false;
    }
    if (!q) return true;
    const hay = [k.name, k.comment, k.fingerprint_sha256].filter(Boolean).join(' ').toLowerCase();
    return hay.includes(q);
  });
}

function renderKeyList() {
  const list = el('keyList');
  list.innerHTML = '';
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
  if (state.activeCategoryId !== 'all') {
    const flat = document.createElement('div');
    flat.className = 'key-group';
    for (const k of rows) flat.appendChild(keyRowEl(k));
    list.appendChild(flat);
    return;
  }

  // Grouped: by category (or uncategorized if no cats).
  // First, build the group order: roots in sort_index order; for each, walk sub-tree.
  const groups = []; // { id|null (uncategorized) | categoryId, name, keys[] }
  const seen = new Set();
  const placeKey = (k) => {
    const cats = state.keyCategories[k.id] || [];
    if (!cats.length) { groups.push({ id: 'uncategorized', name: 'Uncategorized', keys: [k] }); return; }
    for (const c of cats) {
      // Each category the key belongs to: walk the chain to find the *root ancestor* so the key
      // appears once per root path. This is the natural "EU DC1" vs "Asia DC1" grouping.
      let top = c;
      while (top.parent_id) top = catById(top.parent_id);
      const key = 'cat:' + top.id;
      if (seen.has(key + ':' + k.id)) continue;
      seen.add(key + ':' + k.id);
      let g = groups.find(g => g.id === key);
      if (!g) { g = { id: key, name: catPathString(top.id) + ' / ' + c.name, _topId: top.id, _leafId: c.id, keys: [] }; groups.push(g); }
      g.keys.push(k);
    }
  };
  // Render groups in a stable order: roots in sort_index order; uncategorized last.
  const rootIds = state.categories.filter(c => !c.parent_id).map(c => c.id);
  for (const rootId of rootIds) {
    for (const k of state.keys) {
      const cats = state.keyCategories[k.id] || [];
      if (cats.some(c => { let t = c; while (t.parent_id) t = catById(t.parent_id); return t.id === rootId; })) placeKey(k);
    }
  }
  for (const k of state.keys) {
    const cats = state.keyCategories[k.id] || [];
    if (!cats.length) placeKey(k);
  }
  // Dedupe keys within each group (since placeKey runs multiple times in the loop above for the same key across multiple cats — we want each key once per top-level ancestor it appears in)
  for (const g of groups) g.keys = dedupeById(g.keys);

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
    const expanded = state.groupExpanded.has(g.id) === false; // default expanded
    if (!expanded) {
      grp.classList.add('collapsed');
    }
    expandBtn.innerHTML = ico(expanded ? 'minus' : 'plus');
    expandBtn.title = expanded ? 'Collapse group' : 'Expand group';
    expandBtn.addEventListener('click', () => {
      if (grp.classList.toggle('collapsed')) {
        expandBtn.innerHTML = ico('plus');
        expandBtn.title = 'Expand group';
      } else {
        expandBtn.innerHTML = ico('minus');
        expandBtn.title = 'Collapse group';
      }
    });
    head.appendChild(expandBtn);
    grp.appendChild(head);
    for (const k of g.keys) grp.appendChild(keyRowEl(k, g.keys));
    list.appendChild(grp);
  }
}

function dedupeById(arr) {
  const seen = new Set(); const out = [];
  for (const k of arr) { if (!seen.has(k.id)) { seen.add(k.id); out.push(k); } }
  return out;
}

function keyRowEl(k, groupKeys) {
  const row = document.createElement('div');
  row.className = 'key-row' + (k.id === state.selectedId ? ' selected' : '');
  row.dataset.id = k.id;

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
    // "in N categories" badge — only show if this key appears in more than one category.
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
  const sub = document.createElement('div');
  sub.className = 'key-row-sub';
  sub.textContent = k.fingerprint_sha256 || '';
  main.appendChild(name);
  main.appendChild(sub);
  row.appendChild(main);
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

// Tiny right-click menu: "Use this key to connect…".
function openKeyConnectMenu(x, y, key) {
  closeKeyConnectMenu();
  const menu = document.createElement('div');
  menu.className = 'ctx-menu';
  menu.id = 'keyConnectMenu';
  const btn = document.createElement('button');
  btn.className = 'ctx-item';
  btn.innerHTML = `${ico('plug-zap')}<span>Use this key to connect…</span>`;
  btn.addEventListener('click', async () => {
    closeKeyConnectMenu();
    if (!state.unlocked) {
      toast('Unlock the vault to connect.', 'err');
      return;
    }
    if (state.servers.length === 0) {
      // No saved servers yet — open the server modal with this key preselected.
      openServerModal({ keyId: key.id });
    } else {
      // Pick one of the existing servers; the chosen server's saved username
      // is overridden by the server's row username (kept) but its key is
      // overridden with this one at connect time.
      openServerPickerForKey(key);
    }
  });
  menu.appendChild(btn);
  menu.style.left = x + 'px';
  menu.style.top = y + 'px';
  document.body.appendChild(menu);
  const onAway = (ev) => {
    if (ev.target.closest && ev.target.closest('#keyConnectMenu')) return;
    closeKeyConnectMenu();
  };
  setTimeout(() => document.addEventListener('mousedown', onAway, { once: true }), 0);
}
function closeKeyConnectMenu() {
  const m = document.getElementById('keyConnectMenu');
  if (m && m.parentNode) m.parentNode.removeChild(m);
}

async function loadKeys() {
  try {
    const res = await call('key_list');
    state.keys = (res.keys || []).map(k => ({ ...k, category_ids: k.category_ids || [] }));
  } catch (e) {
    state.keys = [];
    toast(e.message || String(e), 'err');
  }
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
    add('Private key', k.has_private ? 'stored (AES-256-GCM encrypted)' : 'not stored');
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
    const browseBtn = el('detailBrowseCategoriesBtn');
    browseBtn.disabled = false;
    browseBtn.onclick = () => openCategoryPicker({
      title: 'Assign categories',
      initial: catIds,
      onSave: async (ids) => {
        try { await call('key_set_categories', { keyId: k.id, categoryIds: ids }); await loadKeys(); toast('Categories updated.', 'ok'); }
        catch (e) { toast(e.message || String(e), 'err'); }
      },
    });
    el('detailFingerprint').textContent = k.fingerprint_sha256 || '\u2014';
    el('detailAuthorized').value = k.public_key || '';
    el('detailExportFormat').disabled = !k.has_private;
    el('detailExportPass').disabled = !k.has_private;
    el('detailExportBtn').disabled = !k.has_private;
  } catch (e) {
    pane.hidden = true;
    toast(e.message || String(e), 'err');
  }
}

async function deleteSelected() {
  if (!state.selectedId) return;
  const k = state.keys.find(x => x.id === state.selectedId);
  if (state.settings.confirmDelete !== false) {
    const ok = window.confirm('Delete key "' + (k ? k.name : state.selectedId) + '" from the vault?\nDeployed copies on disk are not removed.');
    if (!ok) return;
  }
  try {
    await call('key_delete', { id: state.selectedId });
    state.deploySelected.delete(state.selectedId);
    state.selectedId = null;
    toast('Key deleted.', 'ok');
    await loadKeys();
    updateSelectionHint();
  } catch (e) {
    toast(e.message || String(e), 'err');
  }
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

async function exportSelected() {
  if (!state.selectedId) return;
  const format = el('detailExportFormat').value;
  const passphrase = el('detailExportPass').value;
  const k = state.keys.find(x => x.id === state.selectedId);
  try {
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

// ─── new key modal ─────────────────────────────────────────────────────────

function openKeyModal() {
  if (!state.unlocked) { toast('Unlock the vault first.', 'err'); return; }
  el('modalBackdrop').hidden = false;
  el('genName').focus();
}

function closeKeyModal() {
  el('modalBackdrop').hidden = true;
  resetImportFileHint();
}

function switchTab(tab) {
  for (const b of document.querySelectorAll('.tab')) {
    b.classList.toggle('active', b.dataset.tab === tab);
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
  const activeTab = document.querySelector('.tab.active').dataset.tab;
  try {
    if (activeTab === 'generate') {
      const cats = (state._pendingGenerateCategories && state._pendingGenerateCategories()) || [];
      await call('key_create_with_categories', {
        keyType: el('genType').value,
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
    el('importName').value = ''; el('importPem').value = ''; el('importPass').value = '';
    await loadKeys();
  } catch (e) {
    toast(e.message || String(e), 'err');
  }
}

// ─── deploy view ───────────────────────────────────────────────────────────

async function previewConfig() {
  const ids = [...state.deploySelected];
  if (ids.length === 0) { toast('Select at least one key in the Keys view.', 'err'); return; }
  try {
    const res = await call('ssh_config_read');
    el('configPreview').value = JSON.stringify(res.hosts, null, 2);
  } catch (e) {
    toast(e.message || String(e), 'err');
  }
}

async function deployConfig() {
  const ids = [...state.deploySelected];
  if (ids.length === 0) { toast('Select at least one key in the Keys view.', 'err'); return; }
  const sure = window.confirm('Deploy ' + ids.length + ' key(s) to ~/.ssh/ and update ~/.ssh/config?');
  if (!sure) return;
  try {
    const res = await call('key_deploy', { ids });
    el('configPreview').value = 'Deployed ' + res.keys.length + ' key(s)\n'
      + res.keys.map(k => '  ' + k.name + ' -> ' + k.file).join('\n');
    toast('Keys deployed.', 'ok');
  } catch (e) {
    toast(e.message || String(e), 'err');
  }
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
  { key: 'folder_name',     label: 'Sync Folder',         type: 'text',     placeholder: 'SSHSpan',                   required: false },
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
    // first launch — no config yet
  }

  for (const f of BW_FIELDS) {
    const label = document.createElement('label');
    const span = document.createElement('span');
    span.textContent = f.label;
    const inp = document.createElement('input');
    inp.type = f.type;
    inp.id = 'bw_' + f.key;
    inp.placeholder = f.placeholder;
    if (config[f.key]) inp.value = config[f.key];
    if (f.key === 'master_password') inp.value = ''; // never pre-fill password
    label.appendChild(span);
    label.appendChild(inp);
    grid.appendChild(label);
  }

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

async function loadBitwardenSync() {
  // status is now loaded by loadBitwardenConfig
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

async function bwSyncNow() {
  const btn = el('bwSyncNowBtn');
  btn.disabled = true;
  setBwStatus('Syncing\u2026', 'syncing');
  try {
    const s = await call('bitwarden_sync');
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

async function loadSettings() {
  try {
    state.settings = await call('settings_get');
  } catch (e) {
    state.settings = {};
    toast(e.message || String(e), 'err');
    return;
  }
  const grid = document.querySelector('.settings-grid');
  grid.innerHTML = '';

  const mkRow = (labelText, control) => {
    const label = document.createElement('label');
    const span = document.createElement('span');
    span.textContent = labelText;
    label.appendChild(span);
    label.appendChild(control);
    grid.appendChild(label);
  };

  const autoLock = document.createElement('input');
  autoLock.type = 'number';
  autoLock.min = '0';
  autoLock.max = '1440';
  autoLock.value = state.settings.autoLockMinutes || 15;
  autoLock.addEventListener('change', async () => {
    try {
      await call('settings_set', { key: 'autoLockMinutes', value: String(autoLock.value) });
      toast('Auto-lock updated.', 'ok');
    } catch (e) { toast(e.message || String(e), 'err'); }
  });
  mkRow('Auto-lock after (minutes)', autoLock);

  const confirmDelete = document.createElement('input');
  confirmDelete.type = 'checkbox';
  confirmDelete.checked = state.settings.confirmDelete !== false;
  confirmDelete.addEventListener('change', async () => {
    try {
      await call('settings_set', { key: 'confirmDelete', value: String(confirmDelete.checked) });
      toast('Saved.', 'ok');
    } catch (e) { toast(e.message || String(e), 'err'); }
  });
  mkRow('Confirm before deleting keys', confirmDelete);
}

// ─── audit view ────────────────────────────────────────────────────────────

async function loadAudit() {
  const body = el('auditBody');
  body.innerHTML = '';
  try {
    const res = await call('audit_list', { limit: 200 });
    const rows = res.rows || [];
    if (rows.length === 0) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 3;
      td.textContent = 'No audit events yet.';
      tr.appendChild(td);
      body.appendChild(tr);
      return;
    }
    for (const r of rows) {
      const tr = document.createElement('tr');
      const cells = [fmtTime(r.ts), r.event, r.detail].map((v, i) => {
        const td = document.createElement('td');
        td.textContent = v === undefined || v === null ? '' : String(v);
        if (i === 0) td.className = 'ts';
        if (i === 1) td.className = 'ev';
        return td;
      });
      cells.forEach(td => tr.appendChild(td));
      body.appendChild(tr);
    }
  } catch (e) {
    toast(e.message || String(e), 'err');
  }
}


// ─── navigation ────────────────────────────────────────────────────────────

const VIEW_TITLES = { keys: 'Keys', connect: 'Connect', config: 'Deploy', settings: 'Settings', audit: 'Audit Log' };
const VIEW_SUBS = {
  keys: '',
  connect: 'Saved servers + an interactive remote shell (vault-gated)',
  config: 'Deploy staged keys to ~/.ssh and manage your SSH config',
  settings: 'Vault preferences and Bitwarden / Vaultwarden sync',
  audit: 'A local record of every sensitive action',
};

async function switchView(view) {
  state.view = view;
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
  }
  if (view === 'audit') await loadAudit();
  if (view === 'keys') {
    renderKeyList();
    updateSelectionHint();
  }
  if (view === 'connect') {
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
  // nav
  for (const b of document.querySelectorAll('.nav-item')) {
    b.addEventListener('click', () => switchView(b.dataset.view));
  }

  // topbar
  el('lockBtn').addEventListener('click', lockNow);
  el('changePasswordBtn').addEventListener('click', () => showVaultModal('change'));

  // vault modal
  el('vaultPrimary').addEventListener('click', submitVaultModal);
  el('vaultCancelBtn').addEventListener('click', () => {
    hideVaultModal();
    if (!state.unlocked) toast('Vault stays locked \u2014 unlock it any time.', 'info');
  });
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
  el('catFilterBtn').addEventListener('click', () => {
    openCategoryPicker({
      title: 'Filter by category',
      initial: state.activeCategoryId !== 'all' && state.activeCategoryId !== 'uncategorized' ? [state.activeCategoryId] : [],
      single: true,
      onSave: (ids) => {
        if (ids.length) setActiveCategory(ids[0]);
        else setActiveCategory('all');
      },
    });
  });
  el('catAddRootBtn').addEventListener('click', () => addCategoryPrompt(null));
  el('detailCopyPublicBtn').addEventListener('click', copyPublic);
  el('detailDeleteBtn').addEventListener('click', deleteSelected);
  el('detailExportBtn').addEventListener('click', exportSelected);

  // new-key modal: category field
  const wireNewKeyCategories = (chipEl, btnEl, getCurrent, setCurrent) => {
    const render = () => renderCategoryChips(chipEl, getCurrent(), { removable: true, onRemove: (id) => setCurrent(getCurrent().filter(x => x !== id)) });
    btnEl.addEventListener('click', () => openCategoryPicker({
      title: 'Assign categories',
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
    // patch the modal close: reset pending categories.
    el('modalBackdrop').addEventListener('click', () => { store.generate = []; store.import = []; });
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
  el('genType').addEventListener('change', onGenTypeChange);
  el('importBrowseBtn').addEventListener('click', browseForImport);

  // deploy view
  el('previewConfigBtn').addEventListener('click', previewConfig);
  el('deployConfigBtn').addEventListener('click', deployConfig);
  el('copyConfigBtn').addEventListener('click', copyConfig);

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

  // picker modal
  el('pickerCloseBtn').addEventListener('click', closeCategoryPicker);
  el('pickerCancelBtn').addEventListener('click', closeCategoryPicker);
  el('pickerSaveBtn').addEventListener('click', () => {
    const cb = state.pickerCallback;
    const ids = [...state.pickerSelected];
    closeCategoryPicker();
    if (cb) cb(ids);
  });
  el('pickerSearch').addEventListener('input', (e) => renderPickerTree(e.target.value));
  el('pickerModal').addEventListener('click', (e) => {
    if (e.target === el('pickerModal')) closeCategoryPicker();
  });

  // prompt modal
  el('promptCancelBtn').addEventListener('click', closePrompt);
  el('promptOkBtn').addEventListener('click', () => {
    const v = el('promptInput').value.trim();
    const cb = state.promptCallback;
    closePrompt();
    if (cb) cb(v);
  });
  el('promptInput').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') { e.preventDefault(); el('promptOkBtn').click(); }
    else if (e.key === 'Escape') { e.preventDefault(); closePrompt(); }
  });
  el('promptModal').addEventListener('click', (e) => {
    if (e.target === el('promptModal')) closePrompt();
  });

  // keyboard: Escape closes modals; Ctrl/Cmd shortcuts
  document.addEventListener('keydown', (ev) => {
    if (ev.key === 'Escape') {
      if (!el('modalBackdrop').hidden) closeKeyModal();
      else if (!el('serverModal').hidden) closeServerModal();
      else if (el('app').classList.contains('term-max')) toggleTermMax();
      else if (!el('vaultModal').hidden && state.vaultMode === 'change') hideVaultModal();
      return;
    }
    if (!(ev.ctrlKey || ev.metaKey) || ev.altKey || ev.shiftKey) return;
    const k = ev.key.toLowerCase();
    if (k === '1') { switchView('keys'); ev.preventDefault(); }
    else if (k === '2') { switchView('connect'); ev.preventDefault(); }
    else if (k === '3') { switchView('config'); ev.preventDefault(); }
    else if (k === '4') { switchView('settings'); ev.preventDefault(); }
    else if (k === '5') { switchView('audit'); ev.preventDefault(); }
    else if (k === ',') { switchView('settings'); ev.preventDefault(); }
    else if (k === 'n') {
      ev.preventDefault();
      if (state.unlocked) openKeyModal();
      else { showVaultModal('unlock'); toast('Unlock the vault first.', 'info'); }
    }
    else if (k === 'l') { ev.preventDefault(); lockNow(); }
  });

  // Listen for vault-lock-requested from the tray menu
  listen('vault-lock-requested', () => { lockNow(); });

  // ─── Connect view wiring ────────────────────────────────────────────────
  el('serverNewBtn').addEventListener('click', () => openServerModal({}));
  el('serverSearch').addEventListener('input', renderServerList);
  el('termDisconnectBtn').addEventListener('click', disconnectActive);
  const termMaxBtn = el('termMaxBtn');
  if (termMaxBtn) termMaxBtn.addEventListener('click', toggleTermMax);
  el('termReconnectBtn').addEventListener('click', () => {
    const srv = currentSelectedServer();
    if (srv) connectToServer(srv);
  });
  el('termTestBtn').addEventListener('click', () => {
    const srv = currentSelectedServer();
    if (srv) testSelectedServer(srv);
  });
  // server modal
  for (const b of document.querySelectorAll('#serverModal [data-close]')) {
    b.addEventListener('click', closeServerModal);
  }
  el('serverModal').addEventListener('click', (e) => {
    if (e.target === el('serverModal')) closeServerModal();
  });
  for (const b of document.querySelectorAll('.seg-btn')) {
    b.addEventListener('click', () => setConnectAuthMethod(b.dataset.auth));
  }
  el('srvBrowsePemBtn').addEventListener('click', async () => {
    try {
      const r = await call('system_select_file', { title: 'Select .pem file' });
      if (!r.canceled) el('srvPemPath').value = r.path;
    } catch (e) { toast(e.message || String(e), 'err'); }
  });
  el('srvSaveBtn').addEventListener('click', submitServerModal);

  // Connect password modal
  el('connectPwOkBtn').addEventListener('click', () => {
    closeConnectPwModal(el('connectPwInput').value || '');
  });
  el('connectPwCancelBtn').addEventListener('click', () => closeConnectPwModal(null));
  el('connectPwInput').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') { e.preventDefault(); el('connectPwOkBtn').click(); }
    else if (e.key === 'Escape') { e.preventDefault(); closeConnectPwModal(null); }
  });
  el('connectPwModal').addEventListener('click', (e) => {
    if (e.target === el('connectPwModal')) closeConnectPwModal(null);
  });

  if (typeof initTerminal === 'function') initTerminal();
}

async function lockNow() {
  try {
    await call('vault_lock');
    await refreshVaultStatus();
    toast('Vault locked.', 'ok');
  } catch (e) { toast(e.message || String(e), 'err'); }
}

// ─── Connect: saved servers + SSH sessions ─────────────────────────────────

// Password prompt for connect — uses a custom modal instead of native prompt()
// which silently fails in Tauri's WebView.
function askConnectPassword(server, callback) {
  const modal = document.getElementById('connectPwModal');
  if (!modal) return callback(null); // fallback
  modal.hidden = false;
  const label = document.getElementById('connectPwLabel');
  if (label) label.textContent = `Password for ${server.username}@${server.host}:`;
  const inp = document.getElementById('connectPwInput');
  if (inp) { inp.value = ''; setTimeout(() => inp.focus(), 50); }
  state._connectPwCallback = callback;
}
function closeConnectPwModal(value) {
  const modal = document.getElementById('connectPwModal');
  if (modal) modal.hidden = true;
  const cb = state._connectPwCallback;
  state._connectPwCallback = null;
  if (cb) cb(value);
}

async function loadServers() {
  if (!state.unlocked) { clearConnectView(); return; }
  try {
    const res = await call('server_list');
    state.servers = res.servers || [];
  } catch (e) {
    state.servers = [];
    toast(e.message || String(e), 'err');
  }
  renderServerList();
}

function currentSelectedServer() {
  return state.servers.find(s => s.id === state.connectSelectedId) || null;
}

function renderServerList() {
  const list = el('serverList');
  const empty = el('serverEmpty');
  const filter = (el('serverSearch').value || '').toLowerCase().trim();
  const filtered = !filter ? state.servers : state.servers.filter(s => {
    return [s.name, s.host, s.username, s.keyName].filter(Boolean)
      .some(v => v.toLowerCase().includes(filter));
  });
  list.innerHTML = '';
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
    const head = document.createElement('div');
    head.className = 'server-row-head';
    const name = document.createElement('span');
    name.className = 'server-name';
    name.textContent = s.name || '(unnamed)';
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
                     : s.authMethod === 'keyboard-interactive' ? 'Kbd-int'
                     : (s.keyName ? `${s.keyName} (${s.keyType || '?'})` : 'Key');
    auth.innerHTML = `${ico(authIcon)}<span>${escapeHtml(authLabel)}</span>`;
    row.appendChild(auth);

    row.addEventListener('click', () => selectServer(s.id));
    row.addEventListener('dblclick', () => connectToServer(s));
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
  const srv = currentSelectedServer();
  el('termTitle').textContent = srv ? srv.name : 'No connection';
  el('termBadge').hidden = !srv;
  if (srv) {
    el('termBadge').textContent = srv.host + ':' + srv.port;
    el('termTestBtn').hidden = false;
    el('termReconnectBtn').hidden = !!state.connectSessionId;
  } else {
    el('termTestBtn').hidden = true;
    el('termReconnectBtn').hidden = true;
  }
  el('termDisconnectBtn').hidden = !state.connectSessionId;
}

function openServerContextMenu(x, y, srv) {
  closeKeyConnectMenu();
  const menu = document.createElement('div');
  menu.className = 'ctx-menu';
  menu.id = 'keyConnectMenu';
  const mk = (label, icon, fn) => {
    const b = document.createElement('button');
    b.className = 'ctx-item';
    b.innerHTML = `${ico(icon)}<span>${escapeHtml(label)}</span>`;
    b.addEventListener('click', () => { closeKeyConnectMenu(); fn(); });
    menu.appendChild(b);
    return b;
  };
  mk('Connect', 'plug-zap', () => connectToServer(srv));
  mk('Edit', 'pencil', () => openServerModal({ id: srv.id }));
  mk('Delete', 'trash-2', async () => {
    if (!confirm(`Delete server "${srv.name}"?`)) return;
    try {
      await call('server_delete', { id: srv.id });
      if (state.connectSelectedId === srv.id) selectServer(null);
      await loadServers();
      toast('Server deleted.', 'ok');
    } catch (e) { toast(e.message || String(e), 'err'); }
  });
  menu.style.left = x + 'px';
  menu.style.top = y + 'px';
  document.body.appendChild(menu);
  const onAway = (ev) => {
    if (ev.target.closest && ev.target.closest('#keyConnectMenu')) return;
    closeKeyConnectMenu();
  };
  setTimeout(() => document.addEventListener('mousedown', onAway, { once: true }), 0);
}

// ─── Server modal ───────────────────────────────────────────────────────────

function openServerModal({ id, keyId } = {}) {
  el('serverModal').hidden = false;
  el('serverModalTitle').textContent = id ? 'Edit Server' : 'New Server';
  // Populate key dropdown from cached state.keys
  const sel = el('srvKeyId');
  sel.innerHTML = '<option value="">— select a key —</option>';
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
  el('srvName').value    = srv ? srv.name : '';
  el('srvHost').value    = srv ? srv.host : '';
  el('srvPort').value    = srv ? (srv.port || 22) : 22;
  el('srvUser').value    = srv ? srv.username : '';
  el('srvKeyId').value   = srv ? (srv.keyId || keyId || '') : (keyId || '');
  el('srvPemPath').value = srv ? (srv.pemPath || '') : '';
  el('srvPassword').value = '';
  el('srvSavePw').checked = false;
  setConnectAuthMethod(srv ? srv.authMethod : (keyId ? 'publickey' : 'publickey'));
  state._editingServerId = id || null;
  setTimeout(() => el('srvName').focus(), 0);
}

function closeServerModal() {
  el('serverModal').hidden = true;
  state._editingServerId = null;
}

function setConnectAuthMethod(method) {
  state.connectAuthMethod = method;
  for (const b of document.querySelectorAll('.seg-btn')) {
    b.classList.toggle('active', b.dataset.auth === method);
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
    categoryId: null,
    color: null,
  };
  try {
    const r = await call('server_save', args);
    closeServerModal();
    await loadServers();
    if (r && r.id) selectServer(r.id);
    toast('Server saved.', 'ok');
  } catch (e) { toast(e.message || String(e), 'err'); }
}

// Pick an existing saved server and connect immediately using the chosen key.
function openServerPickerForKey(key) {
  closeKeyConnectMenu();
  switchView('connect');
  if (!state.servers.length) {
    openServerModal({ keyId: key.id });
    return;
  }
  const menu = document.createElement('div');
  menu.className = 'ctx-menu';
  menu.id = 'keyConnectMenu';
  for (const s of state.servers) {
    const b = document.createElement('button');
    b.className = 'ctx-item';
    b.innerHTML = `${ico('server')}<span>${escapeHtml(s.name)} <small>(${escapeHtml(s.username)}@${escapeHtml(s.host)})</small></span>`;
    b.addEventListener('click', () => {
      closeKeyConnectMenu();
      state._pendingConnectKey = key.id;
      selectServer(s.id);
      connectToServer(s, { overrideKeyId: key.id });
    });
    menu.appendChild(b);
  }
  const div = document.createElement('div');
  div.className = 'ctx-sep';
  menu.appendChild(div);
  const newBtn = document.createElement('button');
  newBtn.className = 'ctx-item';
  newBtn.innerHTML = `${ico('plus')}<span>New server with this key…</span>`;
  newBtn.addEventListener('click', () => {
    closeKeyConnectMenu();
    openServerModal({ keyId: key.id });
  });
  menu.appendChild(newBtn);
  const rect = el('serverNewBtn').getBoundingClientRect();
  menu.style.left = rect.left + 'px';
  menu.style.top = (rect.bottom + 4) + 'px';
  document.body.appendChild(menu);
  const onAway = (ev) => {
    if (ev.target.closest && ev.target.closest('#keyConnectMenu')) return;
    closeKeyConnectMenu();
  };
  setTimeout(() => document.addEventListener('mousedown', onAway, { once: true }), 0);
}

// ─── Connect / disconnect / test ───────────────────────────────────────────

async function connectToServer(srv, opts = {}) {
  // Hard requirement: terminal.js provides the xterm glue. Never skip silently.
  if (typeof terminalConnect !== 'function' || typeof ensureTerminalForSession !== 'function') {
    el('termStrip').textContent = 'terminal.js is missing — Connect cannot run.';
    toast('terminal.js is missing — reinstall the app.', 'err');
    return;
  }
  if (state.connectSessionId) {
    if (!confirm('A connection is already open. Disconnect it and start a new one?')) return;
    await disconnectActive();
  }
  // Build the xterm instance now that the view is visible. Doing this earlier
  // (during initTerminal) failed because the host element had zero size while
  // the connect view was hidden.
  ensureTerminalForSession();
  terminalReset();
  el('termTitle').textContent = srv.name;
  el('termBadge').textContent = srv.host + ':' + srv.port;
  el('termBadge').hidden = false;
  // Only show Disconnect once a session is actually open.
  el('termDisconnectBtn').hidden = true;
  el('termReconnectBtn').hidden = true;
  el('termTestBtn').hidden = true;
  if (el('serverList')) el('serverList').classList.add('connecting');

  let pw = null;
  if (srv.authMethod !== 'publickey' && !srv.hasSavedPassword) {
    // No password stored — ask at connect time via the custom modal (native
    // prompt() silently fails in Tauri webview).
    pw = await new Promise(resolve => askConnectPassword(srv, resolve));
    if (pw === null || pw === undefined) {
      terminalSetStatus('Cancelled.');
      if (el('serverList')) el('serverList').classList.remove('connecting');
      return;
    }
  }

  try {
    const sessionId = await terminalConnect(srv, { cols: 80, rows: 24, ...opts });
    state.connectSessionId = sessionId;
    state.connectServerId = srv.id;
    // Success — flip to the connected button set.
    el('termReconnectBtn').hidden = false;
    el('termDisconnectBtn').hidden = false;
    el('termTestBtn').hidden = false;
    if (el('serverList')) el('serverList').classList.remove('connecting');
  } catch (e) {
    const msg = e.message || String(e);
    state.connectSessionId = null;
    state.connectServerId = null;
    el('termDisconnectBtn').hidden = true;
    el('termReconnectBtn').hidden = false;
    el('termTestBtn').hidden = false;
    if (el('serverList')) el('serverList').classList.remove('connecting');
    terminalSetStatus(`Failed: ${msg}`);
    toast(msg, 'err');
  }
}

async function disconnectActive() {
  if (!state.connectSessionId) return;
  const id = state.connectSessionId;
  try { await call('terminal_disconnect', { sessionId: id }); } catch (e) {}
  state.connectSessionId = null;
  state.connectServerId = null;
  el('termDisconnectBtn').hidden = true;
  el('termReconnectBtn').hidden = false;
  el('termTestBtn').hidden = false;
  if (typeof terminalSetStatus === 'function') terminalSetStatus('Disconnected.');
}

// Toggle the terminal between the normal Connect layout and a full-app
// "maximized" mode: sidebar/topbar/server-list hidden, terminal fills the
// window, and a thin taskbar strip (status + this restore button) remains.
function toggleTermMax() {
  const app = el('app');
  const btn = el('termMaxBtn');
  if (!app || !btn) return;
  const max = app.classList.toggle('term-max');
  btn.innerHTML = ico(max ? 'minimize-2' : 'maximize-2');
  btn.title = max ? 'Restore terminal size (<>)' : 'Expand terminal to full window';
  if (typeof terminalSetStatus === 'function') {
    terminalSetStatus(max ? 'Terminal maximized — press Esc or <> to restore.' : 'Restored.');
  }
  // Let the layout settle, then refit + push the new PTY size.
  setTimeout(() => {
    if (typeof fitTerminalNow === 'function') fitTerminalNow();
  }, 80);
  setTimeout(() => {
    if (typeof fitTerminalNow === 'function') fitTerminalNow();
  }, 250);
}

async function testSelectedServer(srv) {
  let pw = null;
  if (srv.authMethod !== 'publickey' && !srv.hasSavedPassword) {
    pw = await new Promise(resolve => askConnectPassword(srv, resolve));
    if (pw === null || pw === undefined) return;
  }
  if (typeof terminalSetStatus === 'function') terminalSetStatus(`Testing ${srv.host}:${srv.port}…`);
  try {
    const r = await call('server_test', { serverId: srv.id, promptPassword: pw });
    if (r && r.ok) {
      if (typeof terminalSetStatus === 'function') terminalSetStatus(`OK — ${r.latencyMs} ms`);
      toast(`Reachable (${r.latencyMs} ms)`, 'ok');
    } else {
      if (typeof terminalSetStatus === 'function') terminalSetStatus(`Failed: ${r && r.error ? r.error : 'unknown'}`);
      toast(r && r.error ? r.error : 'Test failed', 'err');
    }
  } catch (e) {
    if (typeof terminalSetStatus === 'function') terminalSetStatus(`Failed: ${e.message || e}`);
    toast(e.message || String(e), 'err');
  }
}

// Called by terminal.js when the session ends on the Rust side.
function onTerminalClosed() {
  state.connectSessionId = null;
  state.connectServerId = null;
  el('termDisconnectBtn').hidden = true;
  el('termReconnectBtn').hidden = false;
  el('termTestBtn').hidden = false;
  if (typeof terminalSetStatus === 'function') terminalSetStatus('Connection closed.');
}
window.onTerminalClosed = onTerminalClosed;

// ─── tiny escaper used by context menus ────────────────────────────────────
function escapeHtml(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// ─── boot ──────────────────────────────────────────────────────────────────

(async function main() {
  // Surface any uncaught renderer error — in release builds there is no
  // devtools console, so silent failures look like "nothing happens".
  window.addEventListener('error', (ev) => {
    toast('JS error: ' + (ev.message || 'unknown'), 'err');
  });

  window.__SSHPAN_BUILD__ = 'v10-dynload';
  document.title = 'SSHSpan (' + window.__SSHPAN_BUILD__ + ')';

  injectIcons();
  wire();
  onGenTypeChange();
  switchTab('generate');
  updateSelectionHint();
  loadBrandIcon();

  // Load the terminal stack explicitly, in order, with loud per-file errors.
  // A statically-failed <script src> fires no window.onerror — it fails
  // silently, which cost us days of "blank terminal" debugging.
  const loadScript = (src) => new Promise((resolve) => {
    const s = document.createElement('script');
    s.src = src;
    s.onload = () => resolve({ src, ok: true });
    s.onerror = () => resolve({ src, ok: false });
    document.head.appendChild(s);
  });
  const results = [];
  for (const src of ['vendor/xterm.js', 'vendor/addon-fit.js', 'vendor/addon-web-links.js', 'terminal.js']) {
    const r = await loadScript(src);
    results.push(r);
    if (!r.ok) toast('Failed to load ' + src + ' — Connect will not work.', 'err');
  }

  // Build marker: visible in the sidebar brand on every screen (the window
  // title is owned by the OS window and does not follow document.title).
  const brandSub = document.querySelector('.brand-sub');
  if (brandSub) brandSub.textContent = 'KEY MANAGER · ' + window.__SSHPAN_BUILD__;

  if (!window.__SSHPAN_TERMINAL_JS__) {
    toast('terminal.js loaded but did not initialize — Connect view will not work.', 'err');
  } else if (!window.Terminal) {
    toast('xterm.js did not expose window.Terminal — terminal rendering unavailable.', 'err');
  }

  await refreshVaultStatus();

  // Catch auto-locks without user interaction.
  setInterval(() => {
    refreshVaultStatus(true).catch(() => {});
  }, 10000);
})().catch((e) => {
  toast(e.message || String(e), 'err');
});
