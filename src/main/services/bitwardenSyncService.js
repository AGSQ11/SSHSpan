/**
 * bitwardenSyncService.js
 * ---------------------------------------------------------------------------
 * Two-way sync between the SSHSpan vault and the SSH key items (cipher
 * type 5) of a Bitwarden-compatible account (Bitwarden cloud / Vaultwarden).
 *
 * Configuration lives in the app config table under "bwSync.*":
 *   serverUrl, email, folderName (default "SSHSpan"), autoSync,
 *   autoSyncMinutes, deviceId and the account master password — the latter
 *   is stored encrypted with the SSHSpan vault master password, so it is
 *   only readable while the vault is unlocked and never exists in
 *   plaintext on disk.
 *
 * Sync model (per row, newest side wins):
 *   - a local key with no remote counterpart is created remotely ("pushed")
 *   - a remote SSH item with no local counterpart is imported ("pulled")
 *   - rows linked by cipher id (or fingerprint on first contact) are
 *     compared: local updatedAt vs bitwardenUpdatedAt decides the local
 *     side; remote revisionDate vs the stored bitwardenRevision decides
 *     the remote side. If both moved, the local copy wins and the case is
 *     reported as a conflict.
 *   - deletions are NEVER propagated automatically; remote deletions are
 *     only reported.
 *
 * The transport (BitwardenClient) is injectable for headless tests.
 * ---------------------------------------------------------------------------
 */

'use strict';

const crypto = require('crypto');
const keyService = require('./keyService');
const { BitwardenClient } = require('./bitwardenClient');
const cryptoService = require('./cryptoService');

const FOLDER_DEFAULT = 'SSHSpan';
const AUTO_SYNC_MIN = 5;
const AUTO_SYNC_MAX = 1440;

function ms(iso) {
  const t = Date.parse(iso);
  return Number.isNaN(t) ? 0 : t;
}

class BitwardenSync {
  /**
   * @param {import('./sshspan')} app  the app service (db, settings, session)
   * @param {{ createTransport?: Function }} [opts]
   */
  constructor(app, opts = {}) {
    this.app = app;
    this.lookup = opts.lookup || null; // injectable DNS resolver (tests)
    this.createTransport = opts.createTransport || ((cfg) => new BitwardenClient({
      serverUrl: cfg.serverUrl,
      email: cfg.email,
      masterPassword: cfg.masterPassword,
      deviceId: cfg.deviceId,
      lookup: this.lookup || undefined
    }));
    this._timer = null;
    this._running = false;
  }

  // ---- configuration -------------------------------------------------------

  _cfgGet(key, fallback) {
    const v = this.app.db.getConfig(key);
    if (v === null || v === undefined) return fallback;
    try { return JSON.parse(v); } catch (e) { return v; }
  }

  _cfgSet(key, value) {
    this.app.db.setConfig(key, JSON.stringify(value));
  }

  /** Sanitized view for the renderer — never includes the master password. */
  getConfig() {
    const serverUrl = this._cfgGet('bwSync.serverUrl', '');
    const email = this._cfgGet('bwSync.email', '');
    return {
      configured: !!(serverUrl && email),
      serverUrl,
      email,
      folderName: this._cfgGet('bwSync.folderName', FOLDER_DEFAULT),
      autoSync: !!this._cfgGet('bwSync.autoSync', false),
      autoSyncMinutes: this._cfgGet('bwSync.autoSyncMinutes', 15),
      lastSyncAt: this._cfgGet('bwSync.lastSyncAt', null),
      lastResult: this._cfgGet('bwSync.lastResult', null),
      hasStoredPassword: !!this.app.db.getConfig('bwSync.password')
    };
  }

  /** Full config including the decrypted Bitwarden master password. */
  _secretConfig() {
    const cfg = this.getConfig();
    this.app._requireUnlocked();
    const stored = this.app.db.getConfig('bwSync.password');
    if (!stored) throw new Error('No Bitwarden master password stored. Re-save the sync settings.');
    let masterPassword;
    try {
      const blob = JSON.parse(stored); // stored JSON-encoded via _cfgSet
      masterPassword = cryptoService.decrypt(blob, this.app.session.getPassword());
    } catch (e) {
      throw new Error('The stored Bitwarden password could not be decrypted with this vault. Re-save the sync settings.');
    }
    return { ...cfg, masterPassword, deviceId: this._deviceIdentifier() };
  }

  _deviceIdentifier() {
    let id = this.app.db.getConfig('bwSync.deviceId');
    if (!id) {
      id = crypto.randomUUID();
      this.app.db.setConfig('bwSync.deviceId', JSON.stringify(id));
    }
    try { return JSON.parse(id); } catch (e) { return id; }
  }

  /**
   * Validate + persist settings. `masterPassword` empty/undefined keeps the
   * previously stored one (if any). Requires an unlocked vault. The server
   * URL goes through the same SSRF guard the client uses (scheme, literal
   * IP ranges and DNS resolution), so bad values are rejected at save time.
   */
  async saveConfig(patch = {}) {
    this.app._requireUnlocked();
    const updates = {};
    if (patch.serverUrl !== undefined) {
      const { resolveSafeServerUrl } = require('./bitwardenClient');
      updates.serverUrl = await resolveSafeServerUrl(patch.serverUrl, this.lookup || undefined);
    }
    if (patch.email !== undefined) {
      const email = String(patch.email).trim();
      if (!email.includes('@')) throw new Error('Enter the account email of your vault.');
      updates.email = email;
    }
    if (patch.folderName !== undefined) {
      const name = String(patch.folderName).trim();
      updates.folderName = name || FOLDER_DEFAULT;
    }
    if (patch.autoSync !== undefined) updates.autoSync = !!patch.autoSync;
    if (patch.autoSyncMinutes !== undefined) {
      let n = Math.round(Number(patch.autoSyncMinutes));
      if (!Number.isFinite(n)) n = 15;
      updates.autoSyncMinutes = Math.min(AUTO_SYNC_MAX, Math.max(AUTO_SYNC_MIN, n));
    }
    if (patch.masterPassword) {
      this._cfgSet('bwSync.password',
        cryptoService.encrypt(String(patch.masterPassword), this.app.session.getPassword()));
    }
    for (const [k, v] of Object.entries(updates)) this._cfgSet('bwSync.' + k, v);
    this.app.db.audit('sync.config', Object.keys(updates).join(','));
    this.refreshAutoSync();
    return this.getConfig();
  }

  // ---- connectivity --------------------------------------------------------

  /** Log in and read the vault without writing anything. */
  async testConnection() {
    const cfg = this._secretConfig();
    const client = this.createTransport(cfg);
    try {
      const kdf = await client.connect();
      const remote = await client.sync();
      const sshItems = remote.ciphers.filter(c => c.type === 5 && !c.deletedDate);
      return {
        ok: true,
        server: client.baseUrl,
        account: remote.profile ? (remote.profile.email || cfg.email) : cfg.email,
        kdf,
        sshItemCount: sshItems.length,
        folders: remote.folders.map(f => f.name),
        version: null
      };
    } finally {
      client.close();
    }
  }

  // ---- sync ----------------------------------------------------------------

  /** Build the cipher type-5 request body for a local key row. */
  async _buildCipherItem(row, folderId, client) {
    const pem = this.app.getDecryptedPrivateKeyPem(row.id);
    const ossh = keyService.toOpenSSHPrivateKey(pem, { comment: row.comment });
    const pub = keyService.toAuthorizedKey(row.publicKeyPem, '');
    return {
      type: 5,
      organizationId: null,
      folderId: folderId || null,
      name: await client.encryptField(row.name),
      notes: null,
      favorite: false,
      reprompt: 0,
      key: null,
      fields: null,
      passwordHistory: null,
      sshKey: {
        privateKey: await client.encryptField(ossh),
        publicKey: await client.encryptField(pub),
        keyFingerprint: await client.encryptField(row.fingerprint)
      }
    };
  }

  /** Fingerprint of a remote cipher, from its decrypted key material. */
  async _remoteFingerprint(client, cipher) {
    try {
      const ssh = cipher.sshKey || {};
      const fpEnc = ssh.keyFingerprint;
      if (fpEnc) return await client.decryptField(fpEnc);
      if (ssh.publicKey) {
        const pub = await client.decryptField(ssh.publicKey);
        const rec = keyService.parsePem(pub);
        return rec.fingerprint;
      }
    } catch (e) { /* fall through */ }
    return null;
  }

  async syncNow(opts = {}) {
    if (this._running) throw new Error('A sync is already in progress.');
    this._running = true;
    const started = Date.now();
    const summary = {
      ok: true,
      reason: opts.reason || 'manual',
      pushed: 0, updatedRemote: 0, pulled: 0, updatedLocal: 0,
      linked: 0, conflicts: 0, remoteDeleted: 0,
      skipped: [], errors: []
    };
    try {
      this.app._requireUnlocked();
      const cfg = this._secretConfig();
      const client = this.createTransport(cfg);
      try {
        await client.connect();
        const remote = await client.sync();

        // --- folder -------------------------------------------------------
        const folderName = cfg.folderName || FOLDER_DEFAULT;
        let folder = remote.folders.find(f => f.name.trim().toLowerCase() === folderName.toLowerCase());
        if (!folder) folder = await client.createFolder(folderName);
        summary.folderId = folder.id;

        // --- remote SSH items (personal vault only) ------------------------
        const remoteSsh = (remote.ciphers || []).filter(c =>
          c.type === 5 && !c.deletedDate && !c.organizationId);
        for (const c of (remote.ciphers || [])) {
          if (c.type === 5 && c.organizationId) {
            summary.skipped.push({ name: 'organization SSH item', reason: 'organization vault items are not synced' });
          }
        }
        const byId = new Map(remoteSsh.map(c => [c.id, c]));
        const fpByCipher = new Map(await Promise.all(
          remoteSsh.map(async c => [c, await this._remoteFingerprint(client, c)])
        ));

        const rows = this.app.db.listKeys();
        const matchedRemotely = new Set();

        // --- pass 1: local -> remote --------------------------------------
        for (const row of rows) {
          try {
            if (!row.privateKeyPem) {
              summary.skipped.push({ name: row.name, reason: 'public-only record' });
              continue;
            }
            let cipher = row.bitwardenId ? byId.get(row.bitwardenId) : null;
            if (!cipher && row.fingerprint) {
              cipher = remoteSsh.find(c => fpByCipher.get(c) === row.fingerprint) || null;
            }
            if (!cipher) {
              const item = await this._buildCipherItem(row, folder.id, client);
              const created = await client.createCipher(item);
              this.app.db.updateKeyFromSync(row.id, {
                bitwardenId: created.id,
                bitwardenRevision: created.revisionDate || null,
                bitwardenUpdatedAt: Date.now()
              });
              summary.pushed++;
              this.app.db.audit('sync.push', row.name);
              continue;
            }
            matchedRemotely.add(cipher.id);
            if (row.bitwardenId !== cipher.id) {
              // first contact through fingerprint match: adopt the link
              this.app.db.updateKeyFromSync(row.id, {
                bitwardenId: cipher.id,
                bitwardenRevision: cipher.revisionDate || null,
                bitwardenUpdatedAt: Date.now()
              });
              summary.linked++;
              continue;
            }
            const localChanged = row.updatedAt > (row.bitwardenUpdatedAt || 0);
            const remoteChanged = ms(cipher.revisionDate) > ms(row.bitwardenRevision);
            if (!localChanged && !remoteChanged) continue;
            if (localChanged) {
              if (remoteChanged) summary.conflicts++; // local wins; remote change is overwritten
              const item = await this._buildCipherItem(row, folder.id, client);
              item.lastKnownRevisionDate = cipher.revisionDate || undefined;
              const updated = await client.updateCipher(cipher.id, item);
              this.app.db.updateKeyFromSync(row.id, {
                bitwardenRevision: updated.revisionDate || cipher.revisionDate || null,
                bitwardenUpdatedAt: Date.now()
              });
              summary.updatedRemote++;
              this.app.db.audit('sync.push', row.name);
            } else {
              await this._pullIntoRow(row, cipher, client);
              summary.updatedLocal++;
              this.app.db.audit('sync.pull', row.name);
            }
          } catch (e) {
            summary.errors.push({ name: row.name, error: e.message || String(e) });
          }
        }

        // --- pass 2: remote -> local --------------------------------------
        for (const cipher of remoteSsh) {
          if (matchedRemotely.has(cipher.id)) continue;
          try {
            const record = await this._parseRemotePrivateKey(client, cipher);
            const name = (await this._remoteName(client, cipher)) || record.comment || 'imported key';
            const stored = this.app.storeSyncedKey(record, {
              name,
              bitwardenId: cipher.id,
              bitwardenRevision: cipher.revisionDate || null
            });
            matchedRemotely.add(cipher.id);
            summary.pulled++;
            this.app.db.audit('sync.pull', name);
          } catch (e) {
            summary.errors.push({ name: 'remote SSH item', error: e.message || String(e) });
          }
        }

        // --- deletions: report only, never propagate ----------------------
        for (const row of rows) {
          if (row.bitwardenId && !byId.has(row.bitwardenId)) summary.remoteDeleted++;
        }
      } finally {
        client.close();
      }

      summary.durationMs = Date.now() - started;
      this._cfgSet('bwSync.lastSyncAt', Date.now());
      this._cfgSet('bwSync.lastResult', summary);
      this.app.db.audit('sync.run', JSON.stringify({
        pushed: summary.pushed, updatedRemote: summary.updatedRemote,
        pulled: summary.pulled, updatedLocal: summary.updatedLocal,
        linked: summary.linked, errors: summary.errors.length
      }));
      return summary;
    } catch (e) {
      summary.ok = false;
      summary.error = e.message || String(e);
      this._cfgSet('bwSync.lastResult', summary);
      this.app.db.audit('sync.error', summary.error.slice(0, 200));
      return summary;
    } finally {
      this._running = false;
    }
  }

  /** Decrypt a remote item's private key into a local key record. */
  async _parseRemotePrivateKey(client, cipher) {
    const ssh = cipher.sshKey || {};
    if (!ssh.privateKey) throw new Error('remote item has no private key');
    const priv = await client.decryptField(ssh.privateKey);
    if (/-----BEGIN OPENSSH PRIVATE KEY-----/.test(priv)) {
      return keyService.parseOpenSshFile(priv);
    }
    return keyService.parsePem(priv);
  }

  async _remoteName(client, cipher) {
    try {
      if (cipher.name) return await client.decryptField(cipher.name);
    } catch (e) { /* corrupted name — fall back */ }
    return null;
  }

  /** Overwrite a local row with newer remote material. */
  async _pullIntoRow(row, cipher, client) {
    const ssh = cipher.sshKey || {};
    const record = await this._parseRemotePrivateKey(client, cipher);
    const name = (await this._remoteName(client, cipher)) || row.name;
    const patch = {
      name,
      comment: record.comment || row.comment,
      privateKeyPem: record.privateKeyPem
        ? cryptoService.encrypt(record.privateKeyPem, this.app.session.getPassword())
        : '',
      encrypted: record.privateKeyPem ? 1 : 0,
      publicKeyPem: record.publicKeyPem,
      publicAuthorizedKey: record.publicAuthorizedKey,
      fingerprint: record.fingerprint,
      bitwardenRevision: cipher.revisionDate || null,
      bitwardenUpdatedAt: Date.now()
    };
    this.app.db.updateKeyFromSync(row.id, patch);
  }

  // ---- auto sync -----------------------------------------------------------

  /** Start or stop the auto-sync timer based on current settings + session. */
  refreshAutoSync() {
    const cfg = this.getConfig();
    if (cfg.autoSync && this.app.session.isUnlocked() && cfg.serverUrl && cfg.email) {
      const minutes = Math.min(AUTO_SYNC_MAX, Math.max(AUTO_SYNC_MIN, Number(cfg.autoSyncMinutes) || 15));
      if (this._timer) clearInterval(this._timer);
      this._timer = setInterval(() => {
        this.syncNow({ reason: 'auto' }).catch(() => { /* audited inside */ });
      }, minutes * 60 * 1000);
      if (typeof this._timer.unref === 'function') this._timer.unref();
    } else {
      this.stopAutoSync();
    }
  }

  stopAutoSync() {
    if (this._timer) { clearInterval(this._timer); this._timer = null; }
  }
}

module.exports = { BitwardenSync, FOLDER_DEFAULT };
