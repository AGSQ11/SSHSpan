/**
 * sshspan.js
 * ---------------------------------------------------------------------------
 * Application service aggregator ("the app object"). Wires together the
 * database, key, session, settings and ssh-config services and exposes one
 * API surface to the main process / IPC layer.
 *
 * Security rules enforced here:
 *   - Private key material is ALWAYS encrypted with the master password
 *     before it reaches the database (AES-256-GCM via cryptoService).
 *   - Private material never leaves this module unencrypted except through
 *     an explicit export/deploy call while the vault is unlocked.
 *   - listKeys()/getKey() return sanitized records (no private keys).
 *   - changePassword() re-encrypts every stored key with the NEW password
 *     BEFORE the master verification hash is updated, so a failure can
 *     never strand the vault.
 * ---------------------------------------------------------------------------
 */

'use strict';

const path = require('path');
const os = require('os');
const fs = require('fs');
const { spawnSync } = require('child_process');
const { Database } = require('./database');
const { Settings } = require('./settingsService');
const Session = require('./sessionService');
const keyService = require('./keyService');
const sshConfigService = require('./sshConfigService');
const cryptoService = require('./cryptoService');
const { BitwardenSync } = require('./bitwardenSyncService');

const MIN_PASSWORD_LEN = 8;

/** Largest file we will read through the import dialog. */
const MAX_IMPORT_BYTES = 512 * 1024;

class SshSpan {
  constructor() {
    this.db = null;
    this.settings = null;
    this.session = new Session();
    this.bitwardenSync = new BitwardenSync(this);
    // Vault lock (manual or idle timer) must stop the auto-sync timer.
    this.session.onIdle(() => this.bitwardenSync.stopAutoSync());
  }

  async init(dbPath) {
    this.db = new Database(dbPath);
    await this.db.init();
    this.settings = new Settings(this.db);
    this.session.setTimeout(Number(this.settings.get('autoLockMinutes', 15)) * 60 * 1000);
    return this;
  }

  // ---- vault lifecycle ------------------------------------------------------

  hasVault() {
    return this.session.hasVault(this.db);
  }

  createVault(password) {
    if (this.hasVault()) throw new Error('A vault already exists on this machine.');
    if (!password || String(password).length < MIN_PASSWORD_LEN) {
      throw new Error('Master password must be at least ' + MIN_PASSWORD_LEN + ' characters.');
    }
    this.session.setup(String(password), this.db);
    this.settings.set('vault.created', Date.now());
    this.db.audit('vault.created');
    this.bitwardenSync.refreshAutoSync();
    return { unlocked: true };
  }

  unlock(password) {
    const hash = this.db.getConfig('master.hash');
    const salt = this.db.getConfig('master.salt');
    if (!hash || !salt) throw new Error('No vault exists. Create one first.');
    try {
      this.session.unlock(String(password), hash, salt);
      this.db.audit('vault.unlock');
    } catch (e) {
      this.db.audit('vault.unlock_failed');
      throw e;
    }
    this.bitwardenSync.refreshAutoSync();
    return { unlocked: true };
  }

  lock() {
    if (this.session.isUnlocked()) {
      this.session.lock();
      this.db.audit('vault.lock');
    }
  }

  /** Register a callback fired whenever the session locks (incl. auto-lock). */
  onLock(cb) {
    this.session.onIdle(cb);
  }

  /**
   * Change the master password.
   * ORDER IS SECURITY-CRITICAL:
   *   1. verify current password
   *   2. re-encrypt every encrypted key with the NEW password
   *   3. only then swap the master verification hash/salt
   * If step 2 fails, the old password still unlocks everything.
   */
  changePassword(currentPassword, newPassword) {
    if (!this.session.isUnlocked()) throw new Error('Vault is locked.');
    if (!newPassword || String(newPassword).length < MIN_PASSWORD_LEN) {
      throw new Error('New master password must be at least ' + MIN_PASSWORD_LEN + ' characters.');
    }
    const hash = this.db.getConfig('master.hash');
    const salt = this.db.getConfig('master.salt');
    if (!cryptoService.verifyPassword(String(currentPassword), hash, salt)) {
      this.db.audit('vault.change_password_failed');
      throw new Error('Current master password is incorrect.');
    }
    const keys = this.db.listKeys();
    for (const k of keys) {
      if (!k.privateKeyPem) continue; // public-only record
      const plaintext = k.encrypted
        ? cryptoService.decrypt(k.privateKeyPem, String(currentPassword))
        : k.privateKeyPem;
      const reEncrypted = cryptoService.encrypt(plaintext, String(newPassword));
      this.db.updateKey(k.id, { privateKeyPem: reEncrypted, encrypted: 1 });
    }
    // The stored Bitwarden master password (if any) is sealed with the vault
    // password — re-encrypt it alongside the keys.
    const bwEncRaw = this.db.getConfig('bwSync.password');
    if (bwEncRaw) {
      let blob = bwEncRaw;
      try { blob = JSON.parse(bwEncRaw); } catch (e) { /* legacy raw blob */ }
      const bwPlain = cryptoService.decrypt(blob, String(currentPassword));
      this.db.setConfig('bwSync.password',
        JSON.stringify(cryptoService.encrypt(bwPlain, String(newPassword))));
    }
    this.session.changePassword(String(newPassword), this.db);
    this.db.audit('vault.password_changed');
    return { changed: true, keysReEncrypted: keys.filter(k => k.privateKeyPem).length };
  }

  // ---- keys ------------------------------------------------------------------

  /** Strip anything secret before a record crosses to the renderer. */
  _sanitize(row) {
    if (!row) return null;
    const out = { ...row };
    delete out.privateKeyPem;
    delete out.passphrase;
    try { out.tags = JSON.parse(out.tags || '[]'); } catch { out.tags = []; }
    try { out.sshConfig = JSON.parse(out.sshConfig || '[]'); } catch { out.sshConfig = []; }
    out.publicOnly = !row.privateKeyPem;
    // ECDSA curve is derivable from the bit size; expose it for the renderer.
    if (row.type === 'ecdsa') {
      out.curve = { 256: 'nistp256', 384: 'nistp384', 521: 'nistp521' }[row.bits] || null;
    }
    return out;
  }

  listKeys() {
    return this.db.listKeys().map(r => this._sanitize(r));
  }

  getKey(id) {
    return this._sanitize(this.db.getKey(id));
  }

  _requireUnlocked() {
    if (!this.session.isUnlocked()) throw new Error('Vault is locked. Unlock it first.');
  }

  _storeKey(record, opts = {}) {
    // duplicate protection by fingerprint
    const existing = this.db.listKeys().find(k => k.fingerprint === record.fingerprint);
    if (existing) {
      throw new Error('This key already exists in the vault as "' + existing.name + '".');
    }
    const now = Date.now();
    const row = {
      id: record.id,
      name: String(opts.name || record.comment || record.type + '-' + new Date(now).toISOString().slice(0, 10)).trim() || record.type,
      type: record.type,
      bits: record.bits,
      comment: String(opts.comment !== undefined ? opts.comment : record.comment || ''),
      fingerprint: record.fingerprint,
      privateKeyPem: record.privateKeyPem,
      publicKeyPem: record.publicKeyPem,
      publicAuthorizedKey: record.publicAuthorizedKey,
      encrypted: 0,
      passphrase: null,
      createdAt: now,
      updatedAt: now,
      tags: opts.tags || [],
      sshConfig: [],
      bitwardenId: opts.bitwardenId || null,
      bitwardenRevision: opts.bitwardenRevision || null,
      bitwardenUpdatedAt: opts.bitwardenUpdatedAt || null
    };
    if (row.privateKeyPem) {
      this._requireUnlocked();
      row.privateKeyPem = cryptoService.encrypt(row.privateKeyPem, this.session.getPassword());
      row.encrypted = 1;
    }
    this.db.insertKey(row);
    return this._sanitize(this.db.getKey(row.id));
  }

  /**
   * Insert a key pulled from the Bitwarden vault, already linked to its
   * remote cipher. Same encryption/dedup rules as a local import.
   */
  storeSyncedKey(record, opts = {}) {
    return this._storeKey(record, opts);
  }

  /** Plaintext (PKCS#8) private key PEM for a row; vault must be unlocked. */
  getDecryptedPrivateKeyPem(id) {
    const row = this.db.getKey(id);
    if (!row) throw new Error('Key not found: ' + id);
    return this._decryptedPrivatePem(row);
  }

  createKey(opts = {}) {
    this._requireUnlocked();
    const record = keyService.generate(opts);
    return this._storeKey(record, opts);
  }

  /**
   * Import key material. Synchronous for every format except PuTTY .ppk,
   * whose Argon2 KDF makes parsing async - use importKeyAsync (the IPC path)
   * when .ppk support is required.
   */
  importKey(text, opts = {}) {
    const pem = String(text || '').trim();
    let record;
    if (/-----BEGIN OPENSSH PRIVATE KEY-----/.test(pem)) {
      record = keyService.parseOpenSshFile(pem, opts.passphrase);
    } else if (keyService.isPuttyKey(pem)) {
      throw new Error('PuTTY .ppk import is asynchronous - call importKeyAsync() for this format.');
    } else {
      record = keyService.parsePem(pem, opts.passphrase);
    }
    return this._storeKey(record, opts);
  }

  /** Import any supported format, including PuTTY .ppk (async). */
  async importKeyAsync(text, opts = {}) {
    const pem = String(text || '').trim();
    if (keyService.isPuttyKey(pem)) {
      const record = await keyService.parsePuttyFile(pem, opts.passphrase);
      return this._storeKey(record, opts);
    }
    return this.importKey(pem, opts);
  }

  updateKey(id, patch = {}) {
    // IPC callers may only touch cosmetic fields — never key material.
    const safe = {};
    for (const f of ['name', 'comment', 'tags', 'sshConfig']) {
      if (patch[f] !== undefined) safe[f] = patch[f];
    }
    return this._sanitize(this.db.updateKey(id, safe));
  }

  deleteKey(id) {
    const existed = this.db.deleteKey(id);
    return existed;
  }

  // ---- export ------------------------------------------------------------------

  _decryptedPrivatePem(row) {
    if (!row || !row.privateKeyPem) throw new Error('This record has no private key.');
    this._requireUnlocked();
    return row.encrypted
      ? cryptoService.decrypt(row.privateKeyPem, this.session.getPassword())
      : row.privateKeyPem;
  }

  exportKey(id, format, opts = {}) {
    const row = this.db.getKey(id);
    if (!row) throw new Error('Key not found: ' + id);
    switch (format) {
      case 'public-pem':
        return row.publicKeyPem;
      case 'authorized_keys':
        return keyService.toAuthorizedKey(row.publicKeyPem, row.comment);
      case 'openssh-private': {
        const pem = this._decryptedPrivatePem(row);
        return keyService.toOpenSSHPrivateKey(pem, {
          comment: opts.comment || row.comment,
          passphrase: opts.passphrase || ''
        });
      }
      case 'pkcs8': {
        const pem = this._decryptedPrivatePem(row);
        return keyService.toPkcs8PrivateKey(pem, '');
      }
      case 'pkcs8-encrypted': {
        if (!opts.passphrase) throw new Error('A passphrase is required for encrypted PKCS#8 export.');
        const pem = this._decryptedPrivatePem(row);
        return keyService.toPkcs8PrivateKey(pem, String(opts.passphrase));
      }
      case 'ppk': {
        // PuTTY .ppk (version 3); encrypts when a passphrase is supplied.
        const pem = this._decryptedPrivatePem(row);
        return keyService.toPuttyPrivateKey(pem, {
          comment: opts.comment || row.comment,
          passphrase: opts.passphrase || ''
        });
      }
      default:
        throw new Error('Unknown export format: ' + format);
    }
  }

  // ---- deployment ----------------------------------------------------------------

  keysDir() {
    return this.settings.get('sshKeysDir') || path.join(os.homedir(), '.sshspan', 'keys');
  }

  /**
   * File path for a deployed key. Row ids become file names under keysDir(),
   * so the id must match our UUID whitelist exactly and the resolved target
   * must stay inside the keys directory before anything is written.
   */
  _deployFileFor(rowId, dir) {
    const match = String(rowId).match(
      /^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/i);
    if (!match) {
      throw new Error('Refusing to deploy: key id "' + rowId + '" is not a valid UUID.');
    }
    const target = path.resolve(dir, match[1]);
    if (!target.startsWith(path.resolve(dir) + path.sep)) {
      throw new Error('Refusing to deploy: resolved path escapes the keys directory.');
    }
    return target;
  }

  /** Restrict a deployed key file to the current user only. */
  _lockDownFile(file) {
    if (process.platform !== 'win32') {
      fs.chmodSync(file, 0o600);
      return;
    }
    // OpenSSH on Windows refuses keys readable by other users; chmod is not
    // enough on NTFS, so strip inheritance and grant full control to ourselves.
    const user = os.userInfo().username;
    const res = spawnSync('icacls', [file, '/inheritance:r', '/grant:r', user + ':(F)'], { stdio: 'ignore' });
    if (res.status !== 0) {
      throw new Error('Failed to restrict permissions on ' + file + ' (icacls exit ' + res.status + ').');
    }
  }

  /**
   * Deploy keys as OpenSSH private-key files into ~/.sshspan/keys and write
   * the managed Host blocks into ~/.ssh/config.
   * @param {string[]|string} ids
   * @param {{keyPassphrase?: string, writeSshConfig?: boolean, path?: string, strictHostKey?: boolean}} opts
   */
  deployKeys(ids, opts = {}) {
    this._requireUnlocked();
    const idList = Array.isArray(ids) ? ids : [ids];
    const dir = this.keysDir();
    fs.mkdirSync(dir, { recursive: true });
    const written = [];
    for (const id of idList) {
      const row = this.db.getKey(id);
      if (!row) throw new Error('Key not found: ' + id);
      const pem = this._decryptedPrivatePem(row);
      const opensshPem = keyService.toOpenSSHPrivateKey(pem, {
        comment: row.comment,
        passphrase: opts.keyPassphrase || ''
      });
      const file = this._deployFileFor(row.id, dir);
      fs.writeFileSync(file, opensshPem + '\n', { mode: 0o600 });
      this._lockDownFile(file);
      const pubFile = file + '.pub';
      fs.writeFileSync(pubFile, row.publicAuthorizedKey + '\n', { mode: 0o644 });
      written.push({ id: row.id, name: row.name, file });
    }
    let configResult = null;
    if (opts.writeSshConfig !== false) {
      const rows = idList.map(id => this.db.getKey(id)).filter(Boolean);
      configResult = sshConfigService.writeConfig(rows, this._configOpts(opts, dir));
    }
    this.db.audit('keys.deploy', idList.length + ' key(s)');
    return {
      files: written.map(w => w.file),
      keys: written,
      keysDir: dir,
      configPath: configResult ? configResult.path : null,
      configBytes: configResult ? configResult.bytes : 0
    };
  }

  renderConfig(ids, opts = {}) {
    const idList = Array.isArray(ids) ? ids : [ids];
    const rows = idList.map(id => this.db.getKey(id)).filter(Boolean);
    return sshConfigService.renderFullConfig(rows, this._configOpts(opts, this.keysDir()));
  }

  /**
   * Shared ssh-config generation options. IdentityFile always points at the
   * real deployed key location (forward slashes so Windows paths work too).
   */
  _configOpts(opts, dir) {
    return {
      path: opts.path || this.settings.get('sshConfigPath') || undefined,
      strictHostKey: opts.strictHostKey,
      host: opts.host,
      hostName: opts.hostName,
      user: opts.user,
      port: opts.port,
      identityFileFor: (k) => path.join(dir, k.id).replace(/\\/g, '/')
    };
  }

  // ---- audit / settings ----------------------------------------------------------

  audit(event, detail) { this.db.audit(event, detail); }
  listAudit(limit = 100) { return this.db.listAudit(limit); }

  getSettings() { return this.settings.getAll(); }
  setSetting(key, value) {
    // Bitwarden sync settings have their own validated IPC channel
    // (sync:save-config) — the generic path must not be able to write them.
    if (String(key).startsWith('bwSync.')) {
      throw new Error('Bitwarden sync settings must be changed via the sync settings dialog.');
    }
    this.settings.set(key, value);
    if (key === 'autoLockMinutes') {
      this.session.setTimeout(Number(value) * 60 * 1000);
    }
    this.db.audit('settings.changed', key);
  }

  // ---- file dialogs ------------------------------------------------------

  /**
   * Show an Open dialog and return the chosen file's text content.
   * Reading happens in the main process; the renderer never touches fs.
   */
  async readTextFileFromDialog(opts = {}) {
    const { dialog, BrowserWindow } = require('electron');
    const win = BrowserWindow.getFocusedWindow() || null;
    const res = await dialog.showOpenDialog(win, {
      title: opts.title || 'Import key file',
      defaultPath: opts.defaultPath || os.homedir(),
      properties: ['openFile', 'showHiddenFiles'],
      filters: opts.filters && opts.filters.length
        ? opts.filters
        : [
            { name: 'SSH keys', extensions: ['ppk', 'pem', 'key', 'pub', 'txt', ''] },
            { name: 'All files', extensions: ['*'] }
          ]
    });
    if (res.canceled || !res.filePaths || res.filePaths.length === 0) {
      return { canceled: true };
    }
    const file = res.filePaths[0];
    const maxBytes = Number(opts.maxBytes) > 0 ? Number(opts.maxBytes) : MAX_IMPORT_BYTES;
    const size = fs.statSync(file).size;
    if (size > maxBytes) {
      throw new Error('That file is ' + Math.ceil(size / 1024) + ' KB — too large to be a key (limit ' +
        Math.floor(maxBytes / 1024) + ' KB).');
    }
    return {
      canceled: false,
      path: file,
      name: path.basename(file),
      text: fs.readFileSync(file, 'utf8')
    };
  }

  /**
   * Show a Save dialog and write `text` to the chosen path.
   * Returns the saved path (or canceled) so the caller can report it.
   */
  async saveTextFileViaDialog(opts = {}) {
    const { dialog, BrowserWindow } = require('electron');
    const win = BrowserWindow.getFocusedWindow() || null;
    const res = await dialog.showSaveDialog(win, {
      title: opts.title || 'Export key',
      defaultPath: opts.defaultPath || (path.join(os.homedir(), opts.fileName || 'key')),
      filters: opts.filters && opts.filters.length ? opts.filters : undefined
    });
    if (res.canceled || !res.filePath) return { canceled: true };
    const target = path.resolve(res.filePath);
    fs.writeFileSync(target, String(opts.text || ''), { mode: 0o600 });
    this._lockDownFile(target);
    return { canceled: false, path: target };
  }

  // ---- Bitwarden sync -------------------------------------------------------

  syncGetConfig() { return this.bitwardenSync.getConfig(); }
  syncSaveConfig(patch) { return this.bitwardenSync.saveConfig(patch); }
  syncTest() { return this.bitwardenSync.testConnection(); }
  syncNow(opts) { return this.bitwardenSync.syncNow(opts); }

  close() {
    this.bitwardenSync.stopAutoSync();
    if (this.db) this.db.close();
  }
}

module.exports = SshSpan;
