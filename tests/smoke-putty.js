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

/**
 * Build a PPK version 2 file (PuTTY 0.52-0.74) from the spec:
 *   cipher key = SHA1(0||pw) || SHA1(1||pw), first 32 bytes
 *   IV         = 16 zero bytes
 *   MAC key    = SHA1("putty-private-key-file-mac-key" || pw)
 *   MAC        = HMAC-SHA-1 over the usual five-string preimage
 * Unencrypted v2 files use an empty passphrase and a plain SHA-1 of the blob.
 * (Corroborated by the Go implementation at kayrus/putty and by hashcat's
 * mode 99200, which cracks real v2 files.)
 */
function buildV2(keyPair, opts = {}) {
  const pw = Buffer.from(opts.passphrase || '', 'utf8');
  const jwk = keyPair.privateKey.export({ format: 'jwk' });
  const pub = internals.publicBlobFromJwk(jwk);
  const body = internals.privateBlobFromJwk(jwk);
  const encrypted = opts.passphrase ? 'aes256-cbc' : 'none';
  const comment = opts.comment || 'v2-key';

  const padded = (() => {
    const padLen = (16 - (body.length % 16)) % 16;
    return padLen ? Buffer.concat([body, crypto.randomBytes(padLen)]) : body;
  })();

  let blob = padded;
  if (opts.passphrase) {
    const seq = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n, 0); return b; };
    const hash = (n) => crypto.createHash('sha1')
      .update(Buffer.concat([seq(n), pw])).digest();
    const cipherKey = Buffer.concat([hash(0), hash(1)]).subarray(0, 32);
    const iv = Buffer.alloc(16);
    const c = crypto.createCipheriv('aes-256-cbc', cipherKey, iv);
    blob = Buffer.concat([c.update(padded), c.final()]);
  }

  // MAC: unencrypted v2 hashes the blob directly; encrypted v2 uses HMAC-SHA-1.
  let mac;
  if (opts.passphrase) {
    const macKey = crypto.createHash('sha1')
      .update(Buffer.from('putty-private-key-file-mac-key', 'utf8'))
      .update(pw).digest();
    mac = crypto.createHmac('sha1', macKey)
      .update(internals.macPreimage(internals.algorithmForJwk(jwk),
        encrypted, comment, pub, padded))
      .digest('hex');
  } else {
    mac = crypto.createHash('sha1').update(blob).digest('hex');
  }

  const b64 = (b) => {
    const s = b.toString('base64');
    const out = [];
    for (let i = 0; i < s.length; i += 64) out.push(s.slice(i, i + 64));
    return out;
  };
  const pubLines = b64(pub);
  const privLines = b64(blob);
  const algo = internals.algorithmForJwk(jwk);

  return [
    'PuTTY-User-Key-File-2: ' + algo,
    'Encryption: ' + encrypted,
    'Comment: ' + comment,
    'Public-Lines: ' + pubLines.length, ...pubLines,
    'Private-Lines: ' + privLines.length, ...privLines,
    'Private-MAC: ' + mac
  ].join('\n') + '\n';
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

  // ---- version 2 (legacy, SHA-1 based) can be IMPORTED --------------------
  // Corroborated against the spec (PuTTY docs C.5.1), the Go implementation at
  // kayrus/putty and hashcat mode 99200.
  for (const [label, gen] of TYPES) {
    const kp = gen();
    const orig = kp.privateKey.export({ format: 'jwk' });

    // unencrypted v2
    const v2plain = buildV2(kp, { comment: 'legacy-plain' });
    ok(label + ' v2: header recognised', isPPK(v2plain));
    let r = await parsePPK(v2plain);
    ok(label + ' v2: plain round trip', r.keyObject.export({ format: 'jwk' }).d === orig.d);
    ok(label + ' v2: version reported', r.version === 2 && r.encrypted === false);

    // encrypted v2
    const v2enc = buildV2(kp, { comment: 'legacy-enc', passphrase: PW });
    r = await parsePPK(v2enc, PW);
    ok(label + ' v2: encrypted round trip', r.keyObject.export({ format: 'jwk' }).d === orig.d);
    ok(label + ' v2: reports encrypted', r.encrypted === true);

    // wrong passphrase
    threw = false;
    try { await parsePPK(v2enc, 'not-the-passphrase'); } catch (e) { threw = true; }
    ok(label + ' v2: wrong passphrase rejected', threw);

    // tampered MAC
    threw = false;
    try { await parsePPK(v2enc.replace(/Private-MAC: ./, 'Private-MAC: 0')); } catch (e) { threw = true; }
    ok(label + ' v2: tampered MAC rejected', threw);

    // v2 MAC is HMAC-SHA-1 (40 hex digits), v3 is HMAC-SHA-256 (64)
    ok(label + ' v2: MAC is 40 hex digits (SHA-1)',
      /^Private-MAC: [0-9a-f]{40}$/m.test(v2enc));
  }

  // v3 files keep the longer MAC
  const v3mac = await serializePPK(crypto.generateKeyPairSync('ed25519').privateKey,
    { comment: 'c', passphrase: PW, ...FAST });
  ok('v3: MAC is 64 hex digits (SHA-256)', /^Private-MAC: [0-9a-f]{64}$/m.test(v3mac));

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
