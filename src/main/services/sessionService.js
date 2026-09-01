/**
 * sessionService.js
 * ---------------------------------------------------------------------------
 * Master-password session management. The password is held in memory only
 * and auto-expires after a configurable idle timeout.
 * ---------------------------------------------------------------------------
 */

'use strict';

const cryptoService = require('./cryptoService');

class Session {
  constructor() {
    this._unlocked = false;
    this._password = null;
    this._timer = null;
    this._timeoutMs = 15 * 60 * 1000;
    this._listeners = [];
  }

  isUnlocked() { return this._unlocked; }

  setTimeout(ms) { this._timeoutMs = ms; }

  onIdle(cb) { this._listeners.push(cb); }

  _armTimer() {
    if (this._timer) clearTimeout(this._timer);
    this._timer = setTimeout(() => this.lock(), this._timeoutMs);
    // The idle timer must never keep the process alive on its own —
    // Electron/owning code manages lifecycle; tests exit naturally.
    if (this._timer && typeof this._timer.unref === 'function') this._timer.unref();
  }

  _notifyIdle() {
    for (const cb of this._listeners) { try { cb(); } catch (e) {} }
  }

  /**
   * Attempt to unlock with a password against stored verification hash.
   */
  unlock(password, storedHash, storedSalt) {
    if (!cryptoService.verifyPassword(password, storedHash, storedSalt)) {
      throw new Error('Incorrect master password.');
    }
    this._password = password;
    this._unlocked = true;
    this._armTimer();
    return true;
  }

  touch() {
    if (this._unlocked) this._armTimer();
  }

  /**
   * Set up a fresh vault: store verification hash + salt.
   */
  setup(password, db) {
    const v = cryptoService.createVerification(password);
    db.setConfig('master.hash', v.hash);
    db.setConfig('master.salt', v.salt);
    this._password = password;
    this._unlocked = true;
    this._armTimer();
    return v;
  }

  hasVault(db) {
    return !!(db.getConfig('master.hash'));
  }

  changePassword(newPassword, db) {
    if (!this._unlocked) throw new Error('Vault is locked.');
    const v = cryptoService.createVerification(newPassword);
    db.setConfig('master.hash', v.hash);
    db.setConfig('master.salt', v.salt);
    this._password = newPassword;
    this._armTimer();
  }

  getPassword() {
    if (!this._unlocked) throw new Error('Vault is locked.');
    return this._password;
  }

  lock() {
    this._unlocked = false;
    this._password = null;
    if (this._timer) { clearTimeout(this._timer); this._timer = null; }
    this._notifyIdle();
  }
}

module.exports = Session;
