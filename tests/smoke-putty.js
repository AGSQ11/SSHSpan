// PuTTY (.ppk) import/export: round trips, passphrase handling, tamper
// detection, and rejection of the SHA-1-based version 2 format.
// All passphrases are generated at runtime - nothing sensitive is committed.
const crypto = require('crypto');
const { parsePPK, serializePPK, isPPK, internals } = require('../src/main/services/puttyParser');

let pass = 0;
function ok(name, cond, extra) {
  if (!cond) throw new Error('FAILED: ' + name + (extra ? ' -> ' + extra : ''));
  pass++;
  console.log('PASS ' + name);
}

// PPK v3 needs Argon2. Node 22.6+/24+ provides it via crypto.argon2Sync; on
// older runtimes this suite skips rather than failing the build.
if (typeof crypto.argon2Sync !== 'function') {
  console.log('SKIPPED: no built-in Argon2 in Node ' + process.version +
    ' (Node 22.6+ / 24+ required for PuTTY .ppk support).');
  process.exit(0);
}

const PW = 'pw-' + crypto.randomBytes(6).toString('hex');

// Low Argon2 cost keeps the suite fast; real exports use puttygen's defaults.
const FAST = { memory: 64, passes: 2 };

const TYPES = [
  ['ed25519', () => crypto.generateKeyPairSync('ed25519')],
  ['rsa-3072', () => crypto.generateKeyPairSync('rsa', { modulusLength: 3072 })],
  ['ecdsa-nistp256', () => crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' })],
  ['ecdsa-nistp384', () => crypto.generateKeyPairSync('ec', { namedCurve: 'secp384r1' })],
  ['ecdsa-nistp521', () => crypto.generateKeyPairSync('ec', { namedCurve: 'secp521r1' })]
];

(async () => {
  // ---- structure helpers --------------------------------------------------
  ok('isPPK detects a PPK header', isPPK('PuTTY-User-Key-File-3: ssh-ed25519\n'));
  ok('isPPK rejects other input', !isPPK('-----BEGIN OPENSSH PRIVATE KEY-----') && !isPPK(''));
  ok('CRLF input is normalized',
    internals.normalizeLines('a\r\nb').join('|') === 'a|b');
  ok('CR-only input is normalized',
    internals.normalizeLines('a\rb').join('|') === 'a|b');
  ok('mixed line endings are normalized',
    internals.normalizeLines('a\r\nb\rc\nd').join('|') === 'a|b|c|d');

  let threw = false;
  try { internals.parseStructure('not a key file'); } catch (e) {
    threw = /Not a PuTTY private key file/.test(e.message);
  }
  ok('non-PPK rejected', threw);

  // Each key type: plain + encrypted round trip, passphrase handling.
  for (const [label, gen] of TYPES) {
    const kp = gen();
    const orig = kp.privateKey.export({ format: 'jwk' });

    // unencrypted
    const plainPpk = await serializePPK(kp.privateKey, { comment: 'c-' + label });
    ok(label + ': header is PPK v3', /^PuTTY-User-Key-File-3: /.test(plainPpk));
    ok(label + ': unencrypted says so', /^Encryption: none$/m.test(plainPpk));
    ok(label + ': no Argon2 headers when plain', !/Argon2-/.test(plainPpk));
    let r = await parsePPK(plainPpk);
    ok(label + ': plain round trip', r.keyObject.export({ format: 'jwk' }).d === orig.d);
    ok(label + ': comment preserved', r.comment === 'c-' + label);
    ok(label + ': reports unencrypted', r.encrypted === false && r.version === 3);

    // encrypted
    const encPpk = await serializePPK(kp.privateKey,
      { comment: 'c-' + label, passphrase: PW, ...FAST });
    ok(label + ': encrypted says so', /^Encryption: aes256-cbc$/m.test(encPpk));
    ok(label + ': Argon2 headers present',
      /^Key-Derivation: Argon2id$/m.test(encPpk) && /^Argon2-Salt: [0-9a-f]+$/m.test(encPpk));
    r = await parsePPK(encPpk, PW);
    ok(label + ': encrypted round trip', r.keyObject.export({ format: 'jwk' }).d === orig.d);
    ok(label + ': reports encrypted', r.encrypted === true);

    // public half still matches after a round trip
    const pubAfter = crypto.createPublicKey(r.keyObject).export({ type: 'spki', format: 'pem' });
    const pubBefore = kp.publicKey.export({ type: 'spki', format: 'pem' });
    ok(label + ': public half unchanged', pubAfter === pubBefore);

    // wrong passphrase
    threw = false;
    try { await parsePPK(encPpk, 'definitely-wrong'); } catch (e) { threw = true; }
    ok(label + ': wrong passphrase rejected', threw);

    // missing passphrase
    threw = false;
    try { await parsePPK(encPpk); } catch (e) { threw = /enter its passphrase/.test(e.message); }
    ok(label + ': missing passphrase rejected', threw);

    // tampered MAC
    threw = false;
    try { await parsePPK(encPpk.replace(/Private-MAC: ./, 'Private-MAC: 0')); } catch (e) { threw = true; }
    ok(label + ': tampered MAC rejected', threw);

    // tampered public key (MAC covers it too)
    threw = false;
    try {
      await parsePPK(encPpk.replace(/^(Comment: .*)$/m, '$1tamper'));
    } catch (e) { threw = true; }
    ok(label + ': tampered header rejected', threw);
  }

  // ---- version and algorithm policy ---------------------------------------
  threw = false;
  try {
    await parsePPK('PuTTY-User-Key-File-2: ssh-rsa\nEncryption: none\nComment: x\n' +
      'Public-Lines: 1\nAAAA\nPrivate-Lines: 1\nAAAA\nPrivate-MAC: aaaa\n');
  } catch (e) { threw = /version 2/.test(e.message) && /PuTTYgen/.test(e.message); }
  ok('v2 rejected with conversion guidance', threw);

  threw = false;
  try { await parsePPK('PuTTY-User-Key-File-9: ssh-rsa\n'); } catch (e) {
    threw = /Unsupported PPK file version/.test(e.message);
  }
  ok('unknown version rejected', threw);

  threw = false;
  try { await parsePPK('PuTTY-User-Key-File-3: ssh-dss\n'); } catch (e) {
    threw = /Unsupported PPK key algorithm/.test(e.message);
  }
  ok('unsupported algorithm rejected', threw);

  // ---- Argon2 parameter validation ----------------------------------------
  const v = (fields) => {
    try { internals.readArgon2Params(fields); return null; } catch (e) { return e.message; }
  };
  ok('missing Key-Derivation rejected', /Key-Derivation/.test(
    v({ 'Argon2-Salt': 'aa', 'Argon2-Passes': '2', 'Argon2-Memory': '64', 'Argon2-Parallelism': '1' }) || ''));
  ok('unknown Argon2 flavour rejected', /Key-Derivation/.test(
    v({ 'Key-Derivation': 'Argon2x', 'Argon2-Salt': 'aa', 'Argon2-Passes': '2', 'Argon2-Memory': '64', 'Argon2-Parallelism': '1' }) || ''));
  ok('missing salt rejected', /Argon2-Salt/.test(
    v({ 'Key-Derivation': 'Argon2id', 'Argon2-Passes': '2', 'Argon2-Memory': '64', 'Argon2-Parallelism': '1' }) || ''));
  ok('zero passes rejected', /Argon2-Passes/.test(
    v({ 'Key-Derivation': 'Argon2id', 'Argon2-Salt': 'aa', 'Argon2-Passes': '0', 'Argon2-Memory': '64', 'Argon2-Parallelism': '1' }) || ''));
  ok('absurd memory rejected', /implausible amount/.test(
    v({ 'Key-Derivation': 'Argon2id', 'Argon2-Salt': 'aa', 'Argon2-Passes': '2', 'Argon2-Memory': '99999999999', 'Argon2-Parallelism': '1' }) || ''));

  // ---- KDF variants -------------------------------------------------------
  const kp = crypto.generateKeyPairSync('ed25519');
  const orig = kp.privateKey.export({ format: 'jwk' });
  for (const kdf of ['Argon2id', 'Argon2i', 'Argon2d']) {
    const ppk = await serializePPK(kp.privateKey, { passphrase: PW, kdf, ...FAST });
    const parsed = await parsePPK(ppk, PW);
    ok('KDF ' + kdf + ' round trips', parsed.keyObject.export({ format: 'jwk' }).d === orig.d);
  }
  threw = false;
  try {
    await serializePPK(kp.privateKey, { passphrase: PW, kdf: 'Argon2x', ...FAST });
  } catch (e) { threw = /Unsupported Argon2 variant/.test(e.message); }
  ok('unknown KDF on export rejected', threw);

  // ---- export guards ------------------------------------------------------
  threw = false;
  try { await serializePPK(kp.publicKey); } catch (e) { threw = /private key is required/.test(e.message); }
  ok('public key cannot be exported as PPK', threw);
  threw = false;
  try { await serializePPK(null); } catch (e) { threw = /KeyObject is required/.test(e.message); }
  ok('null key rejected', threw);

  // comments must not contain CR/LF (they would corrupt the file structure)
  const safe = await serializePPK(kp.privateKey, { comment: 'a\r\nb' });
  ok('comment CR/LF is sanitized', /^Comment: a b$/m.test(safe));

  // ---- end-to-end through the app service ---------------------------------
  const SshSpan = require('../src/main/services/sshspan');
  const fs = require('fs');
  const os = require('os');
  const path = require('path');
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sshspan-ppk-'));
  const app = await new SshSpan().init(path.join(tmp, 'vault', 'sshspan.db'));
  app.createVault('ppk-vault-' + crypto.randomBytes(4).toString('hex'));

  const e2e = await serializePPK(crypto.generateKeyPairSync('ed25519').privateKey,
    { comment: 'e2e', passphrase: PW, ...FAST });
  const imported = await app.importKeyAsync(e2e, { passphrase: PW, name: 'ppk-key' });
  ok('app imports a .ppk', !!imported.id && imported.name === 'ppk-key');
  ok('app stores it encrypted', imported.encrypted === 1);

  // export back to .ppk and re-import that file
  const exported = await app.exportKey(imported.id, 'ppk', { passphrase: PW });
  ok('app exports .ppk', /^PuTTY-User-Key-File-3: /.test(exported));
  const reImported = await parsePPK(exported, PW);
  const storedPem = app.getDecryptedPrivateKeyPem(imported.id);
  ok('exported .ppk matches stored key',
    reImported.keyObject.export({ format: 'jwk' }).d ===
    crypto.createPrivateKey(storedPem).export({ format: 'jwk' }).d);

  // unencrypted export round trip
  const plainExported = await app.exportKey(imported.id, 'ppk');
  ok('app exports unencrypted .ppk', /^Encryption: none$/m.test(plainExported));
  const plainBack = await parsePPK(plainExported);
  ok('unencrypted .ppk re-imports',
    plainBack.keyObject.export({ format: 'jwk' }).d ===
    crypto.createPrivateKey(storedPem).export({ format: 'jwk' }).d);

  // duplicate fingerprint is rejected, as with any import
  threw = false;
  try { await app.importKeyAsync(e2e, { passphrase: PW, name: 'dupe' }); } catch (e) {
    threw = /already exists/i.test(e.message);
  }
  ok('duplicate .ppk rejected', threw);
  app.close();

  console.log('');
  console.log('PUTTY: ' + pass + ' checks passed.');
  process.exit(0);
})().catch((e) => {
  console.error(e && e.stack || e);
  process.exit(1);
});
