// Bitwarden sync smoke test: crypto primitives, SSRF URL guard, and the
// two-way sync engine against a fake vault transport (no network).
// All passwords are generated at runtime — nothing sensitive is committed.
const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const SshSpan = require('../src/main/services/sshspan');
const keyService = require('../src/main/services/keyService');
const bwCrypto = require('../src/main/services/bitwardenCrypto');
const {
  resolveSafeServerUrl,
  internals: { isRestrictedAddress }
} = require('../src/main/services/bitwardenClient');

const VAULT_PW1 = 'v1-' + crypto.randomBytes(12).toString('hex'); // initial vault password
const VAULT_PW2 = 'v2-' + crypto.randomBytes(12).toString('hex'); // rotated vault password
const BW_PW = 'bw-' + crypto.randomBytes(12).toString('hex');     // fake Bitwarden master password
const KDF_PW = 'kdf-' + crypto.randomBytes(12).toString('hex');   // crypto test vector input

let pass = 0;
function ok(name, cond, extra) {
  if (!cond) throw new Error('FAILED: ' + name + (extra ? ' -> ' + extra : ''));
  pass++;
  console.log('PASS ' + name);
}

const PUB_LOOKUP = async () => [{ address: '93.184.216.34', family: 4 }];

/* ------------------------------------------------------------------------
 * Fake vault transport (same surface as BitwardenClient)
 * ---------------------------------------------------------------------- */

class FakeVault {
  constructor(cfg) {
    this.cfg = cfg;
    this.items = [];
    this.folders = [];
    this.counter = 0;
    this.connected = false;
  }

  async connect() {
    if (!this.cfg.email || !this.cfg.email.includes('@')) throw new Error('bad email');
    if (!this.cfg.masterPassword) throw new Error('bad password');
    this.connected = true;
    return { kdfType: 0, iterations: 10000 };
  }

  async sync() {
    return {
      profile: { email: this.cfg.email },
      folders: this.folders.map(f => ({ ...f })),
      ciphers: this.items.map(c => ({ ...c }))
    };
  }

  // Async on purpose: the real BitwardenClient encrypts via async WebCrypto,
  // and the fake must expose the same contract (a sync fake once masked an
  // un-awaited Promise being JSON-stringified into the request body).
  async encryptField(s) { return 'F.' + Buffer.from(String(s), 'utf8').toString('base64'); }
  async decryptField(s) {
    const i = String(s).indexOf('.');
    return Buffer.from(String(s).slice(i + 1), 'base64').toString('utf8');
  }

  async createFolder(name) {
    const f = { id: 'folder-' + (++this.counter), name, revisionDate: new Date().toISOString() };
    this.folders.push(f);
    return { ...f };
  }

  async createCipher(item) {
    const c = { id: 'c-' + (++this.counter), revisionDate: new Date().toISOString(), ...item };
    this.items.push(c);
    return { ...c };
  }

  async updateCipher(id, item) {
    const c = this.items.find(x => x.id === id);
    if (!c) throw new Error('no such cipher: ' + id);
    Object.assign(c, item, { revisionDate: new Date().toISOString() });
    return { ...c };
  }

  /** Simulate an item created by another client (e.g. the Bitwarden app). */
  async addRemoteItem(name, privateKeyPem) {
    const rec = /-----BEGIN OPENSSH PRIVATE KEY-----/.test(privateKeyPem)
      ? keyService.parseOpenSshFile(privateKeyPem)
      : keyService.parsePem(privateKeyPem);
    const c = {
      id: 'c-' + (++this.counter),
      type: 5,
      organizationId: null,
      folderId: null,
      name: await this.encryptField(name),
      notes: null,
      favorite: false,
      reprompt: 0,
      revisionDate: new Date().toISOString(),
      sshKey: {
        privateKey: await this.encryptField(privateKeyPem),
        publicKey: await this.encryptField(rec.publicAuthorizedKey),
        keyFingerprint: await this.encryptField(rec.fingerprint)
      }
    };
    this.items.push(c);
    return c;
  }

  close() {}
}

/* ------------------------------------------------------------------------
 * main
 * ---------------------------------------------------------------------- */

(async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sshspan-bw-'));

  // ---- crypto: published test vectors ------------------------------------
  const v1 = bwCrypto.pbkdf2Sha256(Buffer.from('password'), Buffer.from('salt'), 1, 32);
  ok('pbkdf2-sha256 vector c=1',
    v1.toString('hex') === '120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b');

  const v2 = bwCrypto.pbkdf2Sha256(Buffer.from('password'), Buffer.from('salt'), 4096, 32);
  ok('pbkdf2-sha256 vector c=4096',
    v2.toString('hex') === 'c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a');

  const okm = bwCrypto.hkdfExpandSha256(
    Buffer.from('077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5', 'hex'),
    Buffer.from('f0f1f2f3f4f5f6f7f8f9', 'hex'), 42);
  ok('hkdf-expand vector (RFC 5869 TC1)',
    okm.toString('hex') === '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865');

  const mk = await bwCrypto.deriveMasterKey(KDF_PW, 'User@Example.com', { kdfType: 0, iterations: 10000 });
  ok('master key is 32 bytes', mk.length === 32);
  const stretched = bwCrypto.stretchMasterKey(mk);
  ok('stretched key is 64 bytes, halves differ',
    stretched.length === 64 && !stretched.subarray(0, 32).equals(stretched.subarray(32, 64)));
  const hash1 = bwCrypto.masterPasswordHash(mk, KDF_PW);
  ok('master password hash is base64 32 bytes',
    /^[A-Za-z0-9+/]{43}=$/.test(hash1) && hash1 === bwCrypto.masterPasswordHash(mk, KDF_PW));
  const mk2 = await bwCrypto.deriveMasterKey(KDF_PW, 'user@example.com', { kdfType: 0, iterations: 10000 });
  ok('email is lowercased for KDF salt', mk.equals(mk2));

  // encString round trip + tamper detection
  const pt = '-----BEGIN OPENSSH PRIVATE KEY-----';
  const enc = await bwCrypto.encryptString(pt, stretched);
  ok('encString uses type-2 format', /^2\.[A-Za-z0-9+/=]+\|[A-Za-z0-9+/=]+\|[A-Za-z0-9+/=]+$/.test(enc));
  ok('encString round trip', (await bwCrypto.decryptString(enc, stretched)) === pt);
  const parts = enc.split('.');
  const [iv, ct, mac] = parts[1].split('|');
  await assert.rejects(() => bwCrypto.decryptString(parts[0] + '.' + iv + '|' + ct + '|' +
    Buffer.from(Buffer.from(mac, 'base64').map(b => b ^ 1)).toString('base64'), stretched),
    /HMAC verification failed/, 'tampered MAC rejected');
  const wrongStretch = bwCrypto.stretchMasterKey(crypto.randomBytes(32));
  await assert.rejects(() => bwCrypto.decryptString(enc, wrongStretch),
    /HMAC verification failed/, 'wrong key rejected');
  assert.throws(() => bwCrypto.parseEncString('0.AAA|BBB|CCC'), /only type 2/, 'legacy type 0 rejected');

  // Argon2id path (hash-wasm)
  const arg = await bwCrypto.deriveMasterKey(KDF_PW, 'user@example.com',
    { kdfType: 1, iterations: 1, memory: 32, parallelism: 1 });
  ok('argon2id master key is 32 bytes', arg.length === 32 && !arg.equals(mk));

  // ---- real client: user-key unwrap (raw bytes AND legacy base64 text) ----
  const { BitwardenClient } = require('../src/main/services/bitwardenClient');
  const rawUserKey = crypto.randomBytes(64);
  async function clientWithProfileKey(profileKey) {
    const routes = {
      'POST /identity/accounts/prelogin': { kdf: 0, kdfIterations: 10000 },
      'POST /identity/connect/token': { access_token: 't', refresh_token: 'r', expires_in: 3600 },
      'GET /api/sync': { profile: { email: 'user@example.com', key: profileKey }, folders: [], ciphers: [] }
    };
    const fetchImpl = async (url, init) => {
      const key = (init.method || 'GET') + ' ' + String(url).replace(/^https?:\/\/[^/]+/, '');
      return { ok: true, status: 200, json: async () => routes[key] };
    };
    return new BitwardenClient({
      serverUrl: 'https://vault.example.com',
      email: 'user@example.com',
      masterPassword: KDF_PW,
      deviceId: 'dev-1',
      fetchImpl,
      lookup: PUB_LOOKUP
    });
  }
  // raw-bytes plaintext (new-account format)
  {
    const profileKey = await bwCrypto.encryptBytes(rawUserKey, stretched);
    const client = await clientWithProfileKey(profileKey);
    await client.connect();
    const remote = await client.sync();
    ok('raw 64-byte user key unwrapped', client.userKey.equals(rawUserKey));
    ok('sync returns profile', remote.profile.email === 'user@example.com');
  }
  // legacy base64-text plaintext
  {
    const profileKey = await bwCrypto.encryptString(rawUserKey.toString('base64'), stretched);
    const client = await clientWithProfileKey(profileKey);
    await client.connect();
    await client.sync();
    ok('legacy base64-text user key unwrapped', client.userKey.equals(rawUserKey));
  }
  {
    const badKey = await bwCrypto.encryptString('not-a-key', stretched);
    const bad = await clientWithProfileKey(badKey);
    await bad.connect();
    let threw = false;
    try { await bad.sync(); } catch (e) { threw = /unsupported account key format/i.test(e.message); }
    ok('malformed user key rejected', threw);
  }

  // ---- SSRF URL guard ------------------------------------------------------
  ok('https public host accepted',
    (await resolveSafeServerUrl('https://vault.example.com', PUB_LOOKUP)) === 'https://vault.example.com');
  ok('path preserved',
    (await resolveSafeServerUrl('https://vault.example.com/vw/', PUB_LOOKUP)) === 'https://vault.example.com/vw');
  ok('http accepted (scheme allowed)',
    (await resolveSafeServerUrl('http://vault.example.com:8080', PUB_LOOKUP)) === 'http://vault.example.com:8080');

  const rejects = [
    'http://localhost', 'http://LOCALHOST:8080', 'https://my.vault.localhost',
    'https://nas.local', 'ftp://vault.example.com', 'https://user:pass@vault.example.com',
    'http://127.0.0.1', 'http://127.8.8.8', 'http://0.0.0.0',
    'http://10.1.2.3', 'http://172.16.0.9', 'http://172.31.255.1', 'http://192.168.1.10',
    'http://169.254.3.4', 'http://100.64.0.1', 'http://224.0.0.5', 'http://240.0.0.1',
    'http://192.0.2.9', 'http://198.51.100.7', 'http://203.0.113.9', 'http://198.18.0.3',
    'http://[::1]', 'http://[::]', 'http://[fd00::5]', 'http://[fe80::5]', 'http://[ff02::1]',
    'http://[::ffff:10.0.0.1]', 'http://[::ffff:192.168.0.1]', 'http://[2001:db8::10]'
  ];
  for (const u of rejects) {
    let threw = false;
    try { await resolveSafeServerUrl(u, PUB_LOOKUP); } catch (e) { threw = true; }
    ok('reject ' + u, threw);
  }
  ok('literal public ip accepted',
    (await resolveSafeServerUrl('https://93.184.216.34', PUB_LOOKUP)) === 'https://93.184.216.34');
  ok('isRestrictedAddress sanity',
    isRestrictedAddress('127.0.0.1') && isRestrictedAddress('192.168.0.1') &&
    isRestrictedAddress('::1') && !isRestrictedAddress('93.184.216.34'));

  // DNS that resolves into a private range must be refused
  const EVIL_LOOKUP = async () => [{ address: '10.9.9.9', family: 4 }];
  let threw = false;
  try { await resolveSafeServerUrl('https://rebind.example.com', EVIL_LOOKUP); } catch (e) { threw = true; }
  ok('hostname resolving to private IP rejected', threw);

  // ---- sync engine ---------------------------------------------------------
  const app = await new SshSpan().init(path.join(tmp, 'vault', 'sshspan.db'));
  app.createVault(VAULT_PW1);
  const local1 = app.createKey({ type: 'ed25519', comment: 'laptop', name: 'laptop' });
  const local2 = app.createKey({ type: 'rsa', bits: 3072, comment: 'server', name: 'server' });
  const pubOnly = app.importKey('ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB4xJv/imXSMFssTTg4yyLTSKWCJdICFSJ3w9R+UZKUA user@host');
  ok('public-only import used for skip test', pubOnly.publicOnly === true);

  const fake = new FakeVault();
  app.bitwardenSync.lookup = PUB_LOOKUP; // no real DNS in tests
  app.bitwardenSync.createTransport = (cfg) => { fake.cfg = cfg; fake.lastCfg = cfg; return fake; };

  // configuration (SSRF validation at save time)
  let cfgThrew = false;
  try {
    await app.syncSaveConfig({ serverUrl: 'http://localhost:8222', email: 'me@example.com' });
  } catch (e) { cfgThrew = true; }
  ok('saveConfig rejects private host', cfgThrew);
  const saved = await app.syncSaveConfig({
    serverUrl: 'https://vault.example.com',
    email: 'me@example.com',
    folderName: 'SSHSpan',
    masterPassword: BW_PW
  });
  ok('saveConfig stores sanitized config', saved.serverUrl === 'https://vault.example.com' && saved.hasStoredPassword === true);
  let setThrew = false;
  try { app.setSetting('bwSync.serverUrl', 'http://evil'); } catch (e) { setThrew = true; }
  ok('generic settings path cannot write bwSync.*', setThrew);

  // testConnection against the fake
  const test = await app.syncTest();
  ok('testConnection ok', test.ok === true && test.sshItemCount === 0 && test.account === 'me@example.com');

  // first sync: both private keys pushed, public-only skipped
  let s = await app.syncNow({ reason: 'manual' });
  ok('first sync pushes 2 keys', s.ok && s.pushed === 2, JSON.stringify(s));
  ok('public-only skipped', s.skipped.length === 1 && s.skipped[0].reason === 'public-only record');
  ok('folder created', fake.folders.length === 1 && fake.folders[0].name === 'SSHSpan');
  ok('items are type 5 with sshKey block', fake.items.length === 2 &&
    fake.items.every(c => c.type === 5 && c.sshKey && c.sshKey.privateKey && c.sshKey.publicKey && c.sshKey.keyFingerprint));
  ok('link stored on local rows', app.db.getKey(local1.id).bitwardenId === fake.items[0].id);

  // pushed private material: unencrypted OpenSSH format, 70-char wrapped
  const findByName = async (name) => {
    for (const c of fake.items) {
      if ((await fake.decryptField(c.name)) === name) return c;
    }
    return null;
  };
  const pushedItem = await findByName('laptop');
  ok('pushed item found by decrypted name', !!pushedItem);
  const pushedPriv = await fake.decryptField(pushedItem.sshKey.privateKey);
  ok('pushed key is OpenSSH armored', pushedPriv.includes('-----BEGIN OPENSSH PRIVATE KEY-----'));
  ok('pushed key lines <= 70 chars',
    pushedPriv.split('\n').slice(1, -1).every(l => l.length <= 70));
  // Node's PEM decoder does not read the OpenSSH format, so compare via our
  // parser (the same one the production pull path uses).
  const { parseOpenSSHPrivateKey } = require('../src/main/services/opensshParser');
  const pushedJwk = parseOpenSSHPrivateKey(pushedPriv).keyObject.export({ format: 'jwk' });
  const localJwk = crypto.createPrivateKey(app.getDecryptedPrivateKeyPem(local1.id)).export({ format: 'jwk' });
  ok('pushed material matches local key', pushedJwk.d === localJwk.d && pushedJwk.x === localJwk.x);
  const pushedLinked = fake.items.find(c => c.id === app.db.getKey(local1.id).bitwardenId);
  ok('pushed fingerprint matches row',
    (await fake.decryptField(pushedLinked.sshKey.keyFingerprint)) === local1.fingerprint);

  // second sync: nothing to do
  s = await app.syncNow({});
  ok('second sync is a no-op', s.ok && s.pushed === 0 && s.updatedRemote === 0 && s.pulled === 0);

  // local rename -> remote update
  app.db.updateKeyFromSync(local1.id, { bitwardenUpdatedAt: Date.now() - 60000 }); // simulate older baseline
  app.updateKey(local1.id, { name: 'laptop-renamed' });
  s = await app.syncNow({});
  ok('local change pushed as update', s.updatedRemote === 1, JSON.stringify(s));
  ok('remote item carries new name', (await findByName('laptop-renamed')) !== null);

  // remote rename -> local update
  const item2 = fake.items.find(c => c.id === app.db.getKey(local2.id).bitwardenId);
  item2.name = await fake.encryptField('server-from-bw');
  item2.revisionDate = new Date(Date.now() + 60000).toISOString();
  s = await app.syncNow({});
  ok('remote change pulled into local row', s.updatedLocal === 1, JSON.stringify(s));
  ok('local name follows remote', app.db.getKey(local2.id).name === 'server-from-bw');

  // conflict: both sides changed -> local wins, counted
  app.db.updateKeyFromSync(local1.id, { bitwardenUpdatedAt: Date.now() - 60000 });
  app.updateKey(local1.id, { name: 'laptop-conflict' });
  const item1 = fake.items.find(c => c.id === app.db.getKey(local1.id).bitwardenId);
  item1.name = await fake.encryptField('laptop-remote-edit');
  item1.revisionDate = new Date(Date.now() + 120000).toISOString();
  s = await app.syncNow({});
  ok('conflict detected and local won', s.conflicts === 1 && s.updatedRemote === 1, JSON.stringify(s));
  ok('remote now holds local name', (await fake.decryptField(item1.name)) === 'laptop-conflict');

  // pull-import of a remote item unknown locally
  const gen = keyService.generate({ type: 'ed25519', comment: 'from-bw' });
  const ossh = keyService.toOpenSSHPrivateKey(gen.privateKeyPem, { comment: 'from-bw' });
  await fake.addRemoteItem('imported-key', ossh);
  s = await app.syncNow({});
  ok('remote-only item imported', s.pulled === 1, JSON.stringify(s));
  const imported = app.listKeys().find(k => k.name === 'imported-key');
  ok('imported key decrypts + matches fingerprint', imported && imported.fingerprint === gen.fingerprint);
  ok('imported key linked', imported.bitwardenId && imported.bitwardenId.startsWith('c-'));

  // dedupe/link by fingerprint instead of duplicating
  const unlinked = keyService.generate({ type: 'ed25519', comment: 'twin' });
  app.storeSyncedKey(unlinked, { name: 'twin' });
  const twinRow = app.db.listKeys().find(k => k.name === 'twin');
  app.db.updateKeyFromSync(twinRow.id, { bitwardenId: null }); // forget the link
  await fake.addRemoteItem('twin-remote', keyService.toOpenSSHPrivateKey(unlinked.privateKeyPem, { comment: 'twin' }));
  s = await app.syncNow({});
  ok('fingerprint match links instead of duplicating', s.linked === 1 && s.pulled === 0, JSON.stringify(s));
  ok('vault has no duplicate twin', app.listKeys().filter(k => k.fingerprint === twinRow.fingerprint).length === 1);

  // remote deletion is reported, never propagated
  const delId = app.db.getKey(local2.id).bitwardenId;
  fake.items = fake.items.filter(c => c.id !== delId);
  s = await app.syncNow({});
  ok('remote deletion reported, local kept', s.remoteDeleted === 1 &&
    !!app.db.getKey(local2.id), JSON.stringify(s));

  // locked vault refuses to sync
  app.lock();
  s = await app.syncNow({});
  ok('locked vault -> sync refused', s.ok === false && /locked/i.test(s.error));
  app.unlock(VAULT_PW1);

  // changePassword re-seals the stored Bitwarden password
  app.changePassword(VAULT_PW1, VAULT_PW2);
  s = await app.syncNow({});
  ok('sync still works after vault password change', s.ok === true, s.error || '');
  ok('sync summary audited', app.listAudit(30).some(r => r.event === 'sync.run'));

  app.close();

  console.log('');
  console.log('BITWARDEN SYNC: ' + pass + ' checks passed.');
  process.exit(0);
})().catch((e) => {
  console.error(e && e.stack || e);
  process.exit(1);
});
