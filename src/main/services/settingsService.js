/**
 * settingsService.js
 * ---------------------------------------------------------------------------
 * User preferences persisted in the SQLite config table.
 * ---------------------------------------------------------------------------
 */

'use strict';

const DEFAULTS = {
  theme: 'dark',
  accent: '#6ea8ff',
  sidebarWidth: 260,
  showFingerprint: true,
  autoLockMinutes: 15,
  sshConfigPath: null, // null => ~/.ssh/config
  sshKeysDir: null,    // null => ~/.sshspan/keys
  editorFont: 'Consolas',
  editorFontSize: 13,
  copyOnImport: true,
  confirmDelete: true,
  confirmDeploy: true
};

class Settings {
  constructor(db) {
    this.db = db;
  }

  get(key, fallback) {
    const v = this.db.getConfig(key);
    if (v === null || v === undefined) return DEFAULTS[key] !== undefined ? DEFAULTS[key] : fallback;
    try {
      return JSON.parse(v);
    } catch (e) {
      return v;
    }
  }

  set(key, value) {
    this.db.setConfig(key, JSON.stringify(value));
  }

  getAll() {
    const out = {};
    for (const k of Object.keys(DEFAULTS)) out[k] = this.get(k);
    return out;
  }

  reset() {
    for (const k of Object.keys(DEFAULTS)) this.set(k, DEFAULTS[k]);
  }
}

module.exports = { Settings, DEFAULTS };
