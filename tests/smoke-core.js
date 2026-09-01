/**
 * smoke-core.js — quick sanity checks for the rewritten crypto core.
 * Run: node tests/smoke-core.js
 */
'use strict';
const crypto = require('crypto');
const keyService = require('../src/main/services/keyService');
const { parseOpenSSHPrivateKey, serializeOpenSSHPrivateKey } = require('../src/main/services/opensshParser');

let failures = 0;
function check(name, cond) {
  console.log((cond ? 'PASS ' : 'FAIL ') + name);
  if (!cond) failures++;
}
function expectThrow(name, fn) {
  try { fn(); check(name, false); } catch (e) { check(name + ' (' + e.message.slice(0, 60) + ')', true); }
}

// 1. Generate each type
const cases = [
  { type: 'rsa', bits: 3072 },
  { type: 'ed25519' },
  { type: 'ecdsa', curve: 'nistp256' },
  { type: 'ecdsa', curve: 'nistp384' },
  { type: 'ecdsa', curve: 'nistp521' }
];

for (const opts of cases) {
  const rec = keyService.generate({ ...opts, comment: 'smoke@test' });
  const label = opts.type + (opts.curve ? '-' + opts.curve : '') + (opts.bits ? '-' + opts.bits : '');
  check(label + ': fingerprint format', /^SHA256:[A-Za-z0-9+/]{43}$/.test(rec.fingerprint));
  const prefix = { rsa: 'ssh-rsa', ed25519: 'ssh-ed25519', ecdsa: 'ecdsa-sha2-' }[opts.type];
  check(label + ': authorized key prefix', rec.publicAuthorizedKey.startsWith(prefix));
  check(label + ': authorized key comment', rec.publicAuthorizedKey.endsWith('smoke@test'));
  // public key reconstructable
  const pub = crypto.createPublicKey(rec.publicKeyPem);
  check(label + ': publicKeyPem valid', !!pub);

  // 2. OpenSSH export (unencrypted) -> reparse -> same fingerprint
  const openssh = keyService.toOpenSSHPrivateKey(rec.privateKeyPem, {});
  const parsed = parseOpenSSHPrivateKey(openssh, '');
  const pubPem = crypto.createPublicKey(parsed.keyObject).export({ type: 'spki', format: 'pem' });
  const line = keyService.toAuthorizedKey(pubPem, '');
  check(label + ': openssh roundtrip fingerprint', line.split(' ')[1] === rec.publicAuthorizedKey.split(' ')[1]);

  // 3. OpenSSH export with passphrase -> reparse with passphrase
  const enc = keyService.toOpenSSHPrivateKey(rec.privateKeyPem, { passphrase: 'hunter2-test' });
  const parsed2 = parseOpenSSHPrivateKey(enc, 'hunter2-test');
  const pubPem2 = crypto.createPublicKey(parsed2.keyObject).export({ type: 'spki', format: 'pem' });
  const line2 = keyService.toAuthorizedKey(pubPem2, '');
  check(label + ': openssh encrypted roundtrip', line2.split(' ')[1] === rec.publicAuthorizedKey.split(' ')[1]);
  expectThrow(label + ': wrong passphrase rejected', () => parseOpenSSHPrivateKey(enc, 'wrong'));

  // 4. PKCS8 + encrypted PKCS8 roundtrip
  const pk8 = keyService.toPkcs8PrivateKey(rec.privateKeyPem, '');
  check(label + ': pkcs8 header', /BEGIN PRIVATE KEY/.test(pk8));
  const pk8enc = keyService.toPkcs8PrivateKey(rec.privateKeyPem, 'secret');
  check(label + ': pkcs8-encrypted header', /ENCRYPTED PRIVATE KEY/.test(pk8enc));
  const rt = crypto.createPrivateKey({ key: pk8enc, passphrase: 'secret' });
  const pubRt = crypto.createPublicKey(rt).export({ type: 'spki', format: 'pem' });
  check(label + ': pkcs8-encrypted roundtrip', pubRt === rec.publicKeyPem);
}

// 5. Import public-only authorized_keys line
const rec = keyService.generate({ type: 'ed25519', comment: 'pub' });
const pubOnly = keyService.parsePem(rec.publicAuthorizedKey, '');
check('import authorized_keys line: publicOnly', pubOnly.publicOnly === true);
check('import authorized_keys line: fingerprint', pubOnly.fingerprint === rec.fingerprint);

// 6. Import SPKI PEM public
const spkiImport = keyService.parsePem(rec.publicKeyPem, '');
check('import SPKI pem', spkiImport.publicOnly === true && spkiImport.fingerprint === rec.fingerprint);

// 7. Import PKCS8 private PEM
const privImport = keyService.parsePem(rec.privateKeyPem, '');
check('import PKCS8 pem', privImport.fingerprint === rec.fingerprint && !privImport.publicOnly);

// 8. SSH public blob roundtrip (parse public line back)
const rsaRec = keyService.generate({ type: 'rsa', bits: 3072, comment: 'blob' });
const rsaPub = keyService.parsePem(rsaRec.publicAuthorizedKey, '');
check('rsa public blob roundtrip', rsaPub.fingerprint === rsaRec.fingerprint);
const ecRec = keyService.generate({ type: 'ecdsa', curve: 'nistp521', comment: 'blob' });
const ecPub = keyService.parsePem(ecRec.publicAuthorizedKey, '');
check('ecdsa-521 public blob roundtrip', ecPub.fingerprint === ecRec.fingerprint);

console.log(failures === 0 ? '\nALL CORE CHECKS PASSED' : '\n' + failures + ' FAILURES');
process.exit(failures === 0 ? 0 : 1);
