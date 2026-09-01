
const assert = require('assert');
const path = require('path');
const fs = require('fs');
const os = require('os');
const { Database } = require('../src/main/services/database');

(async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sshspan-dbtest-'));
  const dbPath = path.join(tmp, 'nested', 'sshspan.db');
  const db = new Database(dbPath);
  await db.init();

  // config
  db.setConfig('theme', 'dark');
  assert.strictEqual(db.getConfig('theme'), 'dark', 'config get/set');
  assert.strictEqual(db.getConfig('missing', 'fallback'), 'fallback', 'config fallback');
  db.setConfig('theme', 'light');
  assert.strictEqual(db.getConfig('theme'), 'light', 'config replace');
  assert.deepStrictEqual(db.getAllConfig(), { theme: 'light' }, 'getAllConfig returns map');

  // meta
  assert.ok(db.getMeta('schema_version'), 'schema_version written');

  // keys CRUD
  const now = Date.now();
  const k = {
    id: 'test-id-1', name: 'work', type: 'ed25519', bits: 256, comment: 'me@host',
    fingerprint: 'SHA256:abc', privateKeyPem: 'ENC_BLOB', publicKeyPem: 'PUB',
    publicAuthorizedKey: 'ssh-ed25519 AAAA me@host', encrypted: 1, passphrase: null,
    createdAt: now, updatedAt: now, tags: ['a'], sshConfig: []
  };
  db.insertKey(k);
  const got = db.getKey('test-id-1');
  assert.strictEqual(got.name, 'work', 'getKey returns object row');
  assert.strictEqual(got.bits, 256);
  assert.strictEqual(got.encrypted, 1);
  assert.deepStrictEqual(JSON.parse(got.tags), ['a'], 'tags json');
  assert.strictEqual(got.passphrase, null, 'null passphrase');

  // type CHECK constraint
  let threw = false;
  try { db.insertKey({ ...k, id: 'bad', type: 'dsa' }); } catch { threw = true; }
  assert.ok(threw, 'invalid type rejected');

  // duplicate PK rejected
  threw = false;
  try { db.insertKey(k); } catch { threw = true; }
  assert.ok(threw, 'duplicate id rejected');

  // updateKey whitelist
  const upd = db.updateKey('test-id-1', { name: 'home', comment: 'x', evil: 'DROP TABLE keys' });
  assert.strictEqual(upd.name, 'home');
  assert.strictEqual(upd.comment, 'x');
  assert.strictEqual(db.getKey('test-id-1').evil, undefined);
  assert.ok(upd.updatedAt >= now, 'updatedAt bumped');
  // rekey support
  db.updateKey('test-id-1', { privateKeyPem: 'ENC_BLOB_2' });
  assert.strictEqual(db.getKey('test-id-1').privateKeyPem, 'ENC_BLOB_2', 'privateKeyPem rekey allowed');

  // list order by name
  db.insertKey({ ...k, id: 'test-id-2', name: 'alpha' });
  const list = db.listKeys();
  assert.deepStrictEqual(list.map(r => r.name), ['alpha', 'home'], 'listKeys name order');

  // audit
  const aud = db.listAudit(50);
  assert.ok(aud.length >= 3, 'audit rows present (' + aud.length + ')');
  assert.ok(aud.some(a => a.event === 'key.create'), 'key.create audited');
  assert.ok(aud.some(a => a.event === 'key.update'), 'key.update audited');

  // delete
  assert.strictEqual(db.deleteKey('test-id-2'), true, 'delete returns true');
  assert.strictEqual(db.deleteKey('nope'), false, 'delete missing false');
  assert.strictEqual(db.getKey('test-id-2'), null, 'deleted gone');

  // persistence: close flushes, reopen reads back
  db.close();
  assert.ok(fs.existsSync(dbPath), 'db file written');
  const db2 = new Database(dbPath);
  await db2.init();
  assert.strictEqual(db2.getKey('test-id-1').privateKeyPem, 'ENC_BLOB_2', 'reopen persists data');
  assert.strictEqual(db2.getConfig('theme'), 'light', 'reopen persists config');
  db2.close();

  fs.rmSync(tmp, { recursive: true, force: true });
  console.log('ALL DB CHECKS PASSED');
})().catch(e => { console.error('DB TEST FAIL:', e && e.message ? e.message : e); process.exitCode = 1; });
