// App-level smoke test: vault lifecycle, key CRUD, export, rekey, deploy.
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const SshSpan = require('../src/main/services/sshspan');
const keyService = require('../src/main/services/keyService');
const { serializeOpenSSHPrivateKey } = require('../src/main/services/opensshParser');
const crypto = require('crypto');

const KEYGEN = 'C:\\Windows\\System32\\OpenSSH\\ssh-keygen.exe';
function keygenFp(file) {
  const out = execFileSync(KEYGEN, ['-l', '-f', file], { stdio: ['ignore', 'pipe', 'pipe'] }).toString();
  const m = out.match(/SHA256:[A-Za-z0-9+/]+/);
  return m ? m[0] : null;
}

let pass = 0;
function ok(name, cond, extra) {
  if (!cond) throw new Error('FAILED: ' + name + (extra ? ' -> ' + extra : ''));
  pass++;
  console.log('PASS ' + name);
}

(async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sshspan-app-'));
  const app = await new SshSpan().init(path.join(tmp, 'vault', 'sshspan.db'));

  // ---- vault lifecycle ----
  ok('no vault initially', app.hasVault() === false);
  let threw = false;
  try { app.createVault('short'); } catch { threw = true; }
  ok('weak password rejected', threw);
  app.createVault('correct-horse-9');
  ok('vault created + unlocked', app.hasVault() === true && app.session.isUnlocked());
  threw = false;
  try { app.createVault('another-pass-1'); } catch { threw = true; }
  ok('double vault creation rejected', threw);

  // ---- create key ----
  const rec = app.createKey({ type: 'ed25519', comment: 'app-test' });
  ok('createKey returns record with fingerprint', /^SHA256:/.test(rec.fingerprint));
  const listed = app.listKeys();
  ok('listKeys sanitized (no privateKeyPem)', listed.length === 1 && !('privateKeyPem' in listed[0]) && !('passphrase' in listed[0]));
  ok('listKeys exposes name/comment/fingerprint', listed[0].name.length > 0 && listed[0].comment === 'app-test');

  // ---- exports while unlocked ----
  const auth = app.exportKey(rec.id, 'authorized_keys');
  ok('authorized_keys export', auth.startsWith('ssh-ed25519 ') && auth.endsWith('app-test'));
  const pkcs8 = app.exportKey(rec.id, 'pkcs8');
  ok('pkcs8 export plaintext', pkcs8.includes('BEGIN PRIVATE KEY'));
  const ossh = app.exportKey(rec.id, 'openssh-private', { passphrase: 'filepass1', comment: 'exp' });
  ok('openssh export armor header', ossh.includes('-----BEGIN OPENSSH PRIVATE KEY-----'));
  const { parseOpenSSHPrivateKey } = require('../src/main/services/opensshParser');
  const osshParsed = parseOpenSSHPrivateKey(ossh, 'filepass1');
  ok('openssh export encrypted aes256-ctr/bcrypt', osshParsed.ciphername === 'aes256-ctr' && osshParsed.kdfname === 'bcrypt');
  ok('openssh export honors comment option', osshParsed.comment === 'exp');

  // ---- lock semantics ----
  app.lock();
  ok('locked', !app.session.isUnlocked());
  threw = false;
  try { app.exportKey(rec.id, 'pkcs8'); } catch (e) { threw = /locked/i.test(e.message); }
  ok('private export blocked when locked', threw);
  ok('public export works when locked', app.exportKey(rec.id, 'public-pem').includes('BEGIN PUBLIC KEY'));
  threw = false;
  try { app.unlock('wrong-password'); } catch (e) { threw = /incorrect/i.test(e.message); }
  ok('wrong master password rejected', threw);
  app.unlock('correct-horse-9');
  ok('unlock with right password', app.session.isUnlocked());

  // ---- import: openssh private with passphrase ----
  const genRec = keyService.generate({ type: 'rsa', bits: 3072, comment: 'import-me' });
  const keyObj = crypto.createPrivateKey(genRec.privateKeyPem);
  const encFile = serializeOpenSSHPrivateKey(keyObj, { comment: 'import-me', passphrase: 'src-pass-7' });
  threw = false;
  try { app.importKey(encFile, {}); } catch { threw = true; }
  ok('encrypted import without passphrase fails', threw);
  const imported = app.importKey(encFile, { passphrase: 'src-pass-7', name: 'imported-rsa' });
  ok('encrypted openssh import', imported.fingerprint === genRec.fingerprint && imported.name === 'imported-rsa');
  threw = false;
  try { app.importKey(encFile, { passphrase: 'src-pass-7' }); } catch (e) { threw = /already exists/i.test(e.message); }
  ok('duplicate fingerprint rejected', threw);

  // ---- import: public-only (fresh key, fingerprint not yet in vault) ----
  const strangerRec = keyService.generate({ type: 'ecdsa', curve: 'nistp256', comment: 'stranger' });
  const pubImport = app.importKey(strangerRec.publicAuthorizedKey, { name: 'pub-only' });
  ok('public-only import', pubImport.publicOnly === true);
  threw = false;
  try { app.exportKey(pubImport.id, 'pkcs8'); } catch (e) { threw = /public-only|no private/i.test(e.message); }
  ok('public-only key cannot export private', threw);

  // ---- pkcs8-encrypted requires passphrase ----
  threw = false;
  try { app.exportKey(rec.id, 'pkcs8-encrypted', {}); } catch (e) { threw = /passphrase/i.test(e.message); }
  ok('pkcs8-encrypted requires passphrase', threw);
  const pk8e = app.exportKey(rec.id, 'pkcs8-encrypted', { passphrase: 'x1' });
  ok('pkcs8-encrypted export', pk8e.includes('ENCRYPTED PRIVATE KEY'));

  // ---- change password (rekey order) ----
  const blobBefore = app.db.getKey(rec.id).privateKeyPem;
  threw = false;
  try { app.changePassword('wrong-current', 'new-pass-88'); } catch { threw = true; }
  ok('changePassword verifies current password', threw);
  app.changePassword('correct-horse-9', 'new-pass-88');
  const blobAfter = app.db.getKey(rec.id).privateKeyPem;
  ok('key blob re-encrypted on password change', blobBefore !== blobAfter);
  ok('export still works after rekey', app.exportKey(rec.id, 'pkcs8').includes('BEGIN PRIVATE KEY'));
  app.lock();
  threw = false;
  try { app.unlock('correct-horse-9'); } catch { threw = true; }
  ok('old master password no longer valid', threw);
  app.unlock('new-pass-88');
  ok('new master password valid', app.session.isUnlocked());

  // ---- deploy ----
  const keysDir = path.join(tmp, 'deployed-keys');
  const cfgPath = path.join(tmp, 'ssh-config');
  app.setSetting('sshKeysDir', keysDir);
  app.setSetting('sshConfigPath', cfgPath);
  const dep = app.deployKeys([rec.id], { host: 'myhost.example', user: 'deploy', keyPassphrase: 'dep-pass-1' });
  ok('deploy reports key file', dep.files.length === 1 && fs.existsSync(dep.files[0]));
  ok('deploy writes .pub too', fs.existsSync(dep.files[0] + '.pub'));
  const deployedPem = fs.readFileSync(dep.files[0], 'utf8');
  ok('deployed file is openssh format', deployedPem.includes('OPENSSH PRIVATE KEY'));
  // ssh-keygen accepts the deployed encrypted key and fingerprint matches
  const fp = (() => {
    try {
      const pub = execFileSync(KEYGEN, ['-y', '-P', 'dep-pass-1', '-f', dep.files[0]], { stdio: ['ignore', 'pipe', 'pipe'] }).toString().trim();
      const pf = dep.files[0] + '.derived.pub';
      fs.writeFileSync(pf, pub + '\n');
      return keygenFp(pf);
    } catch (e) { return 'ERR:' + (e.stderr ? e.stderr.toString().split('\n')[0] : e.message); }
  })();
  ok('ssh-keygen verifies deployed key', fp === rec.fingerprint, String(fp));
  const cfg = fs.readFileSync(cfgPath, 'utf8');
  ok('ssh config has managed block', cfg.includes('# >>> SSHSpan managed >>>') && cfg.includes('Host myhost.example'));
  ok('ssh config IdentityFile points at deployed key', cfg.includes('IdentityFile') && cfg.includes(rec.id));

  // ---- audit ----
  const aud = app.listAudit(200);
  const events = new Set(aud.map(a => a.event));
  ok('audit captured vault + key + deploy events',
     events.has('vault.created') && events.has('key.create') && events.has('keys.deploy'),
     JSON.stringify([...events]));

  // ---- persistence across restart ----
  app.close();
  const app2 = await new SshSpan().init(path.join(tmp, 'vault', 'sshspan.db'));
  ok('reopen: vault persists', app2.hasVault() === true);
  app2.unlock('new-pass-88');
  const list2 = app2.listKeys();
  ok('reopen: keys persist (' + list2.length + ')', list2.length === 3);
  ok('reopen: private material recoverable', app2.exportKey(rec.id, 'pkcs8').includes('BEGIN PRIVATE KEY'));
  app2.close();

  fs.rmSync(tmp, { recursive: true, force: true });
  console.log('\nALL APP CHECKS PASSED (' + pass + ')');
})().catch(e => { console.error('\nAPP TEST FAIL:', e && e.stack || e); process.exitCode = 1; });
