/**
 * app.js — SSHSpan renderer controller.
 * ---------------------------------------------------------------------------
 * Plain DOM + the frozen window.sshspan bridge. No Node, no require, no
 * framework. Every IPC call returns { ok: true, data } or { ok: false, error };
 * unwrap() normalises that into a thrown Error so call sites stay flat.
 * Private key material never reaches this process; exports are explicit
 * user-initiated downloads.
 * ---------------------------------------------------------------------------
 */

'use strict';

const api = window.sshspan;

// --------------------------------------------------------------------------
// tiny helpers
// --------------------------------------------------------------------------

function el(id) { return document.getElementById(id); }

function unwrap(res) {
  if (!res || res.ok !== true) {
    throw new Error((res && res.error) || 'Unknown error');
  }
  return res.data;
}

let toastTimer = null;
function toast(msg, kind) {
  const t = el('toast');
  t.textContent = msg;
  t.className = 'show ' + (kind || 'info');
  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.className = ''; }, 3800);
}

function fmtTime(ms) {
  if (!ms) return '\u2014';
  const d = new Date(Number(ms));
  if (Number.isNaN(d.getTime())) return String(ms);
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

// --------------------------------------------------------------------------
// app state
// --------------------------------------------------------------------------

const state = {
  hasVault: false,
  unlocked: false,
  vaultMode: 'unlock',        // create | unlock | change
  keys: [],
  selectedId: null,
  deploySelected: new Set(),
  settings: {},
  view: 'keys'
};

// --------------------------------------------------------------------------
// vault gate
// --------------------------------------------------------------------------

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
  current.hidden = true; // the main process verifies the session itself
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
  const s = unwrap(await api.vaultStatus());
  const wasUnlocked = state.unlocked;
  state.hasVault = s.hasVault;
  state.unlocked = s.unlocked;

  const status = el('vaultStatus');
  status.innerHTML = s.unlocked
    ? '<span class="dot unlocked"></span><span class="vault-label">Unlocked</span>'
    : (s.hasVault ? '<span class="dot locked"></span><span class="vault-label">Locked</span>'
                  : '<span class="dot locked"></span><span class="vault-label">No vault</span>');
  el('newKeyBtn').disabled = !s.unlocked;
  el('lockBtn').disabled = !s.unlocked;
  el('changePasswordBtn').disabled = !s.unlocked;

  if (!s.hasVault) {
    showVaultModal('create');
  } else if (!s.unlocked) {
    clearKeysUI();
    showVaultModal('unlock');
  } else {
    hideVaultModal();
    if (!wasUnlocked || !silent) await loadKeys();
  }
}

async function submitVaultModal() {
  const mode = state.vaultMode;
  const pw = el('vaultPassword').value;
  const confirm = el('vaultPasswordConfirm').value;
  try {
    if (mode === 'create') {
      if (pw.length < 8) throw new Error('Master password must be at least 8 characters.');
      if (pw !== confirm) throw new Error('Passwords do not match.');
      unwrap(await api.vaultCreate(pw));
      unwrap(await api.vaultUnlock(pw));
      toast('Vault created. Welcome to SSHSpan.', 'ok');
    } else if (mode === 'change') {
      if (pw.length < 8) throw new Error('New password must be at least 8 characters.');
      if (pw !== confirm) throw new Error('Passwords do not match.');
      unwrap(await api.vaultChangePassword(pw));
      toast('Master password changed; all keys re-encrypted.', 'ok');
    } else {
      unwrap(await api.vaultUnlock(pw));
      toast('Vault unlocked.', 'ok');
    }
    await refreshVaultStatus();
  } catch (e) {
    toast(e.message, 'err');
    el('vaultPassword').select();
  }
}

// --------------------------------------------------------------------------
// keys view
// --------------------------------------------------------------------------

function clearKeysUI() {
  state.keys = [];
  state.selectedId = null;
  state.deploySelected.clear();
  el('keyList').innerHTML = '';
  el('detailPane').hidden = true;
  el('emptyState').hidden = false;
  updateSelectionHint();
}

function updateSelectionHint() {
  const n = state.deploySelected.size;
  el('selectionHint').textContent = n > 0 ? n + ' selected for deploy' : '';
  el('deploySelectionHint').textContent = n > 0
    ? n + ' key(s) will be deployed.'
    : 'Select keys to deploy using the checkboxes in the Keys view.';
}

function filteredKeys() {
  const q = el('searchInput').value.trim().toLowerCase();
  const type = el('typeFilter').value;
  return state.keys.filter(k => {
    if (type && k.type !== type) return false;
    if (!q) return true;
    const hay = [k.name, k.comment, k.fingerprint].filter(Boolean).join(' ').toLowerCase();
    return hay.includes(q);
  });
}

function renderKeyList() {
  const list = el('keyList');
  list.innerHTML = '';
  const rows = filteredKeys();
  el('emptyState').hidden = state.keys.length > 0;
  for (const k of rows) {
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

    const main = document.createElement('div');
    main.className = 'key-row-main';
    const name = document.createElement('div');
    name.className = 'key-row-name';
    name.textContent = k.name || '(unnamed)';
    if (k.publicOnly) {
      const pub = document.createElement('span');
      pub.className = 'badge ghost';
      pub.textContent = 'public only';
      name.appendChild(pub);
    }
    const sub = document.createElement('div');
    sub.className = 'key-row-sub mono';
    sub.textContent = k.fingerprint || '';
    main.appendChild(name);
    main.appendChild(sub);

    const badge = document.createElement('span');
    badge.className = 'badge';
    badge.textContent = k.type + (k.bits ? ' ' + k.bits : '');

    row.appendChild(cb);
    row.appendChild(main);
    row.appendChild(badge);
    row.addEventListener('click', () => selectKey(k.id));
    list.appendChild(row);
  }
}

async function loadKeys() {
  try {
    state.keys = unwrap(await api.keysList()) || [];
  } catch (e) {
    state.keys = [];
    toast(e.message, 'err');
  }
  renderKeyList();
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
    const k = unwrap(await api.keysGet(id));
    pane.hidden = false;
    el('detailName').textContent = k.name || '(unnamed)';
    el('detailType').textContent = k.type + (k.publicOnly ? ' \u00b7 public only' : '');
    const meta = el('detailMeta');
    meta.innerHTML = '';
    const add = (label, value) => {
      if (value === undefined || value === null || value === '') return;
      const dt = document.createElement('dt');
      dt.textContent = label;
      const dd = document.createElement('dd');
      dd.textContent = String(value);
      meta.appendChild(dt);
      meta.appendChild(dd);
    };
    add('Key size', k.bits ? k.bits + (k.curve ? '' : ' bits') : (k.curve || ''));
    add('Curve', k.curve);
    add('Comment', k.comment);
    add('Created', fmtTime(k.createdAt));
    add('Updated', fmtTime(k.updatedAt));
    add('Private key', k.hasPrivate ? 'stored (AES-256-GCM encrypted)' : 'not stored');
    el('detailFingerprint').textContent = k.fingerprint || '\u2014';
    el('detailAuthorized').value = k.publicAuthorizedKey || '';
    el('detailExportFormat').disabled = !k.hasPrivate;
    el('detailExportPass').disabled = !k.hasPrivate;
    el('detailExportBtn').disabled = !k.hasPrivate;
  } catch (e) {
    pane.hidden = true;
    toast(e.message, 'err');
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
    unwrap(await api.keysDelete(state.selectedId));
    state.deploySelected.delete(state.selectedId);
    state.selectedId = null;
    toast('Key deleted.', 'ok');
    await loadKeys();
    updateSelectionHint();
  } catch (e) {
    toast(e.message, 'err');
  }
}

async function copyPublic() {
  if (!state.selectedId) return;
  try {
    unwrap(await api.clipboardWritePublic(state.selectedId));
    toast('Public key copied to clipboard.', 'ok');
  } catch (e) {
    toast(e.message, 'err');
  }
}

const EXPORT_EXT = {
  'openssh-private': '',
  'pkcs8': '.pem',
  'pkcs8-encrypted': '.enc.pem',
  'public-pem': '.pub',
  'authorized_keys': '.authorized_keys'
};

async function exportSelected() {
  if (!state.selectedId) return;
  const format = el('detailExportFormat').value;
  const passphrase = el('detailExportPass').value;
  const k = state.keys.find(x => x.id === state.selectedId);
  try {
    const out = unwrap(await api.keysExport(state.selectedId, format, { passphrase }));
    const base = safeFileName(k ? k.name : state.selectedId);
    const ext = EXPORT_EXT[format] !== undefined ? EXPORT_EXT[format] : '.txt';
    download(base + ext, out.data);
    toast('Exported ' + format + '.', 'ok');
  } catch (e) {
    toast(e.message, 'err');
  } finally {
    el('detailExportPass').value = '';
  }
}

// --------------------------------------------------------------------------
// new key modal
// --------------------------------------------------------------------------

function openKeyModal() {
  if (!state.unlocked) { toast('Unlock the vault first.', 'err'); return; }
  el('modalBackdrop').hidden = false;
  el('genName').focus();
}

function closeKeyModal() { el('modalBackdrop').hidden = true; }

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

async function submitKeyModal() {
  const activeTab = document.querySelector('.tab.active').dataset.tab;
  try {
    if (activeTab === 'generate') {
      const payload = {
        name: el('genName').value.trim(),
        type: el('genType').value,
        bits: Number(el('genBits').value),
        curve: el('genCurve').value,
        comment: el('genComment').value.trim()
      };
      unwrap(await api.keysCreate(payload));
      toast('Key generated.', 'ok');
    } else {
      const pem = el('importPem').value;
      if (!pem.trim()) throw new Error('Paste key material first.');
      unwrap(await api.keysImport(pem, {
        name: el('importName').value.trim(),
        passphrase: el('importPass').value
      }));
      toast('Key imported.', 'ok');
    }
    closeKeyModal();
    el('genName').value = ''; el('genComment').value = '';
    el('importName').value = ''; el('importPem').value = ''; el('importPass').value = '';
    await loadKeys();
  } catch (e) {
    toast(e.message, 'err');
  }
}

// --------------------------------------------------------------------------
// deploy view
// --------------------------------------------------------------------------

function deployOpts() {
  const opts = {
    host: el('cfgHost').value.trim() || undefined,
    user: el('cfgUser').value.trim() || undefined,
    strictHostKey: el('strictHostKeyToggle').checked
  };
  const port = el('cfgPort').value.trim();
  if (port) opts.port = Number(port);
  if (el('keyPassphraseToggle').checked) {
    opts.keyPassphrase = el('keyPassphraseInput').value;
  }
  return opts;
}

async function previewConfig() {
  const ids = [...state.deploySelected];
  if (ids.length === 0) { toast('Select at least one key in the Keys view.', 'err'); return; }
  try {
    const text = unwrap(await api.keysRenderConfig(ids, deployOpts()));
    el('configPreview').value = text;
  } catch (e) {
    toast(e.message, 'err');
  }
}

async function deployConfig() {
  const ids = [...state.deploySelected];
  if (ids.length === 0) { toast('Select at least one key in the Keys view.', 'err'); return; }
  const opts = deployOpts();
  if (el('keyPassphraseToggle').checked && !opts.keyPassphrase) {
    toast('Enter the deployed-key passphrase or untick "Encrypt deployed files".', 'err');
    return;
  }
  const sure = window.confirm('Deploy ' + ids.length + ' key(s) to ~/.sshspan/keys and update ~/.ssh/config?');
  if (!sure) return;
  try {
    const res = unwrap(await api.keysDeploy(ids, opts));
    el('configPreview').value = 'Deployed ' + res.keys.length + ' key(s) to ' + res.keysDir + '\n'
      + res.keys.map(k => '  ' + k.name + ' -> ' + k.file).join('\n') + '\n'
      + (res.configPath ? 'Updated ' + res.configPath + ' (' + res.configBytes + ' bytes)' : '');
    toast('Keys deployed.', 'ok');
  } catch (e) {
    toast(e.message, 'err');
  } finally {
    el('keyPassphraseInput').value = '';
  }
}

async function copyConfig() {
  const text = el('configPreview').value;
  if (!text) { toast('Nothing to copy \u2014 preview first.', 'err'); return; }
  const ok = await copyText(text);
  toast(ok ? 'Config copied.' : 'Clipboard unavailable.', ok ? 'ok' : 'err');
}

// --------------------------------------------------------------------------
// settings view
// --------------------------------------------------------------------------

async function loadSettings() {
  try {
    state.settings = unwrap(await api.settingsGet()) || {};
  } catch (e) {
    state.settings = {};
    toast(e.message, 'err');
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
  autoLock.value = state.settings.autoLockMinutes;
  autoLock.addEventListener('change', async () => {
    try {
      unwrap(await api.settingsSet('autoLockMinutes', Number(autoLock.value)));
      toast('Auto-lock updated.', 'ok');
    } catch (e) { toast(e.message, 'err'); }
  });
  mkRow('Auto-lock after (minutes)', autoLock);

  const confirmDelete = document.createElement('input');
  confirmDelete.type = 'checkbox';
  confirmDelete.checked = state.settings.confirmDelete !== false;
  confirmDelete.addEventListener('change', async () => {
    try {
      unwrap(await api.settingsSet('confirmDelete', confirmDelete.checked));
      toast('Saved.', 'ok');
    } catch (e) { toast(e.message, 'err'); }
  });
  mkRow('Confirm before deleting keys', confirmDelete);

  if (state.settings.sshKeysDir) {
    const dir = document.createElement('input');
    dir.type = 'text';
    dir.value = state.settings.sshKeysDir;
    dir.readOnly = true;
    mkRow('Deployed keys directory', dir);
  }
  if (state.settings.sshConfigPath) {
    const cfg = document.createElement('input');
    cfg.type = 'text';
    cfg.value = state.settings.sshConfigPath;
    cfg.readOnly = true;
    mkRow('SSH config file', cfg);
  }
}

// --------------------------------------------------------------------------
// audit view
// --------------------------------------------------------------------------

async function loadAudit() {
  const body = el('auditBody');
  body.innerHTML = '';
  try {
    const rows = unwrap(await api.auditList(200)) || [];
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
      for (const val of [fmtTime(r.ts || r.createdAt), r.event, r.detail]) {
        const td = document.createElement('td');
        td.textContent = val === undefined || val === null ? '' : String(val);
        tr.appendChild(td);
      }
      body.appendChild(tr);
    }
  } catch (e) {
    toast(e.message, 'err');
  }
}

// --------------------------------------------------------------------------
// navigation
// --------------------------------------------------------------------------

const VIEW_TITLES = { keys: 'Keys', config: 'Deploy', settings: 'Settings', audit: 'Audit Log' };

async function switchView(view) {
  state.view = view;
  for (const b of document.querySelectorAll('.nav-item')) {
    b.classList.toggle('active', b.dataset.view === view);
  }
  for (const v of Object.keys(VIEW_TITLES)) {
    el('view-' + v).hidden = v !== view;
  }
  el('viewTitle').textContent = VIEW_TITLES[view];
  if (view === 'settings') await loadSettings();
  if (view === 'audit') await loadAudit();
  if (view === 'keys') renderKeyList();
}

// --------------------------------------------------------------------------
// wiring
// --------------------------------------------------------------------------

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
  el('searchInput').addEventListener('input', renderKeyList);
  el('typeFilter').addEventListener('change', renderKeyList);
  el('detailCopyPublicBtn').addEventListener('click', copyPublic);
  el('detailDeleteBtn').addEventListener('click', deleteSelected);
  el('detailExportBtn').addEventListener('click', exportSelected);

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

  // deploy view
  el('previewConfigBtn').addEventListener('click', previewConfig);
  el('deployConfigBtn').addEventListener('click', deployConfig);
  el('copyConfigBtn').addEventListener('click', copyConfig);
  el('keyPassphraseToggle').addEventListener('change', () => {
    el('keyPassphraseInput').hidden = !el('keyPassphraseToggle').checked;
  });

  // keyboard: Escape closes modals; Ctrl/Cmd shortcuts for navigation + actions
  document.addEventListener('keydown', (ev) => {
    if (ev.key === 'Escape') {
      if (!el('modalBackdrop').hidden) closeKeyModal();
      else if (!el('vaultModal').hidden && state.vaultMode === 'change') hideVaultModal();
      return;
    }
    if (!(ev.ctrlKey || ev.metaKey) || ev.altKey || ev.shiftKey) return;
    const k = ev.key.toLowerCase();
    if (k === '1') { switchView('keys'); ev.preventDefault(); }
    else if (k === '2') { switchView('config'); ev.preventDefault(); }
    else if (k === '3') { switchView('settings'); ev.preventDefault(); }
    else if (k === '4') { switchView('audit'); ev.preventDefault(); }
    else if (k === ',') { switchView('settings'); ev.preventDefault(); }
    else if (k === 'n') {
      ev.preventDefault();
      if (state.unlocked) openKeyModal();
      else { showVaultModal('unlock'); toast('Unlock the vault first.', 'info'); }
    }
    else if (k === 'l') { ev.preventDefault(); lockNow(); }
  });
}

async function lockNow() {
  try {
    unwrap(await api.vaultLock());
    await refreshVaultStatus();
    toast('Vault locked.', 'ok');
  } catch (e) { toast(e.message, 'err'); }
}

// --------------------------------------------------------------------------
// boot
// --------------------------------------------------------------------------

(async function main() {
  wire();
  onGenTypeChange();
  switchTab('generate');
  updateSelectionHint();
  await refreshVaultStatus();

  // Catch auto-locks (session timer) without user interaction.
  setInterval(() => {
    refreshVaultStatus(true).catch(() => {});
  }, 10000);
})().catch((e) => {
  toast(e.message || String(e), 'err');
});
