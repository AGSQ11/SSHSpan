/**
 * database.js
 * ---------------------------------------------------------------------------
 * sql.js-backed persistence for SSHSpan (pure WebAssembly SQLite — no native
 * compilation required, works on Windows, macOS and Linux inside Electron).
 *
 * Notes:
 *  - sql.js is a *factory*: `require('sql.js')` returns an init function that
 *    must be invoked to obtain the SQL module.
 *  - Statements return arrays from `.get()`; we always use `.getAsObject()`.
 *  - WAL / busy_timeout pragmas do not exist in sql.js (single in-memory
 *    connection persisted to disk by us) — persistence is handled by an
 *    atomic tmp-file + rename with a debounce timer.
 *
 * Schema:
 *   - meta   : key/value app metadata (schema version, etc.)
 *   - keys   : SSH key metadata + encrypted private-key blob
 *   - config : user settings (theme, ssh config path, auto-lock, ...)
 *   - audit  : append-only security event log
 * ---------------------------------------------------------------------------
 */

'use strict';

const path = require('path');
const os = require('os');

let SQL = null;
async function initSqlJs() {
  if (SQL) return SQL;
  // sql.js exports an async factory in CommonJS.
  const init = require('sql.js');
  SQL = await init();
  return SQL;
}

const SCHEMA = [
  `CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS keys (
     id TEXT PRIMARY KEY,
     name TEXT NOT NULL,
     type TEXT NOT NULL CHECK (type IN ('rsa','ed25519','ecdsa')),
     bits INTEGER NOT NULL,
     comment TEXT NOT NULL DEFAULT '',
     fingerprint TEXT NOT NULL,
     privateKeyPem TEXT NOT NULL,
     publicKeyPem TEXT NOT NULL,
     publicAuthorizedKey TEXT NOT NULL,
     encrypted INTEGER NOT NULL DEFAULT 0,
     passphrase TEXT,
     createdAt INTEGER NOT NULL,
     updatedAt INTEGER NOT NULL,
     tags TEXT NOT NULL DEFAULT '[]',
     sshConfig TEXT NOT NULL DEFAULT '[]'
  )`,
  `CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS audit (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     ts INTEGER NOT NULL,
     event TEXT NOT NULL,
     detail TEXT NOT NULL DEFAULT ''
  )`,
  `CREATE INDEX IF NOT EXISTS idx_keys_type ON keys(type)`,
  `CREATE INDEX IF NOT EXISTS idx_keys_fp ON keys(fingerprint)`,
  `CREATE INDEX IF NOT EXISTS idx_keys_name ON keys(name)`,
  `CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit(ts)`
];

/** Whitelisted columns for updateKey() — prevents arbitrary column writes. */
const UPDATABLE_KEY_FIELDS = [
  'name', 'comment', 'tags', 'sshConfig', 'passphrase',
  'privateKeyPem', 'encrypted', 'updatedAt'
];

function defaultDbPath() {
  return path.join(os.homedir(), '.sshspan', 'sshspan.db');
}

class Database {
  constructor(dbPath) {
    this.dbPath = dbPath || defaultDbPath();
    this._ready = false;
    this._saveTimer = null;
  }

  async init() {
    if (this._ready) return this;
    await initSqlJs();
    const fs = require('fs');
    const dir = path.dirname(this.dbPath);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    let data = null;
    if (fs.existsSync(this.dbPath)) {
      data = new Uint8Array(fs.readFileSync(this.dbPath));
    }
    this.db = new SQL.Database(data || undefined);
    for (const stmt of SCHEMA) this.db.run(stmt);
    if (!this._get('SELECT value FROM meta WHERE key = ?', ['schema_version'])) {
      this._run('INSERT INTO meta (key, value) VALUES (?, ?)', ['schema_version', '1']);
    }
    this._ready = true;
    return this;
  }

  /** Debounced persistence: coalesce rapid writes, then flush atomically. */
  _scheduleSave() {
    if (this._saveTimer) return;
    this._saveTimer = setTimeout(() => {
      this._saveTimer = null;
      try { this.save(); } catch (e) { /* surfaced on next explicit save/close */ }
    }, 500);
    if (typeof this._saveTimer.unref === 'function') this._saveTimer.unref();
  }

  /** Atomic write: dump to tmp file, then rename over the target. */
  save() {
    if (!this._ready) return;
    const fs = require('fs');
    const dir = path.dirname(this.dbPath);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    const binary = this.db.export(); // Uint8Array
    const tmp = this.dbPath + '.tmp';
    fs.writeFileSync(tmp, Buffer.from(binary));
    fs.renameSync(tmp, this.dbPath);
  }

  // ---- low-level helpers -------------------------------------------------
  _run(sql, params = []) {
    const stmt = this.db.prepare(sql);
    try {
      stmt.bind(params);
      stmt.step();
      const changes = this.db.getRowsModified();
      return { changes };
    } finally {
      stmt.free();
    }
  }

  _get(sql, params = []) {
    const stmt = this.db.prepare(sql);
    try {
      stmt.bind(params);
      if (stmt.step()) return stmt.getAsObject();
      return null;
    } finally {
      stmt.free();
    }
  }

  _all(sql, params = []) {
    const stmt = this.db.prepare(sql);
    try {
      stmt.bind(params);
      const rows = [];
      while (stmt.step()) rows.push(stmt.getAsObject());
      return rows;
    } finally {
      stmt.free();
    }
  }

  _mutate(sql, params = []) {
    const info = this._run(sql, params);
    this._scheduleSave();
    return info;
  }

  // ---- meta / config -----------------------------------------------------
  getMeta(key, fallback = null) {
    const row = this._get('SELECT value FROM meta WHERE key = ?', [key]);
    return row ? row.value : fallback;
  }
  setMeta(key, value) {
    this._mutate('INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)', [key, String(value)]);
  }
  getConfig(key, fallback = null) {
    const row = this._get('SELECT value FROM config WHERE key = ?', [key]);
    return row ? row.value : fallback;
  }
  setConfig(key, value) {
    this._mutate('INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)', [key, String(value)]);
  }
  getAllConfig() {
    const out = {};
    for (const row of this._all('SELECT key, value FROM config')) out[row.key] = row.value;
    return out;
  }

  // ---- keys CRUD ---------------------------------------------------------
  listKeys() {
    return this._all('SELECT * FROM keys ORDER BY name COLLATE NOCASE ASC, createdAt ASC');
  }
  getKey(id) {
    return this._get('SELECT * FROM keys WHERE id = ?', [id]);
  }
  insertKey(k) {
    this._mutate(
      `INSERT INTO keys (id,name,type,bits,comment,fingerprint,privateKeyPem,publicKeyPem,
        publicAuthorizedKey,encrypted,passphrase,createdAt,updatedAt,tags,sshConfig)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
      [k.id, k.name, k.type, k.bits, k.comment || '', k.fingerprint, k.privateKeyPem,
       k.publicKeyPem, k.publicAuthorizedKey, k.encrypted ? 1 : 0, k.passphrase || null,
       k.createdAt, k.updatedAt, JSON.stringify(k.tags || []), JSON.stringify(k.sshConfig || [])]
    );
    this.audit('key.create', k.id);
    return k;
  }
  updateKey(id, patch) {
    const fields = [];
    const params = [];
    for (const [k, v] of Object.entries(patch)) {
      if (!UPDATABLE_KEY_FIELDS.includes(k) || k === 'updatedAt') continue;
      fields.push(k + ' = ?');
      params.push(k === 'tags' || k === 'sshConfig' ? JSON.stringify(v) : (v ?? null));
    }
    if (fields.length === 0) return this.getKey(id);
    fields.push('updatedAt = ?');
    params.push(Date.now());
    params.push(id);
    this._mutate('UPDATE keys SET ' + fields.join(', ') + ' WHERE id = ?', params);
    this.audit('key.update', id);
    return this.getKey(id);
  }
  deleteKey(id) {
    const info = this._mutate('DELETE FROM keys WHERE id = ?', [id]);
    if (info.changes > 0) this.audit('key.delete', id);
    return info.changes > 0;
  }

  // ---- audit -------------------------------------------------------------
  audit(event, detail = '') {
    try {
      this._mutate('INSERT INTO audit (ts, event, detail) VALUES (?, ?, ?)', [Date.now(), event, String(detail)]);
    } catch (e) { /* best-effort: audit must never break a primary operation */ }
  }
  listAudit(limit = 100) {
    return this._all('SELECT * FROM audit ORDER BY id DESC LIMIT ?', [Math.max(1, Number(limit) || 100)]);
  }

  close() {
    if (this._saveTimer) { clearTimeout(this._saveTimer); this._saveTimer = null; }
    if (this._ready) {
      try { this.save(); } catch (e) { /* ignore on shutdown */ }
      this.db.close();
      this._ready = false;
    }
  }
}

module.exports = { Database, SCHEMA, defaultDbPath, initSqlJs };
