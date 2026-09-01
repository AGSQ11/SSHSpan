#!/usr/bin/env node
/**
 * run-tests.js
 * ---------------------------------------------------------------------------
 * SSHSpan test runner (npm test).
 *
 * Runs every suite in its own Node process so a crash in one suite cannot
 * hide results from the others:
 *
 *   1. smoke-core.js        - crypto core: generation, parsing, formats
 *   2. smoke-db.js          - sql.js persistence layer (CRUD + durability)
 *   3. smoke-app.js         - end-to-end vault/import/export/rekey/deploy
 *   4. crosscheck-keygen.js - interop against real OpenSSH ssh-keygen
 *                             (skipped with a loud notice when no ssh-keygen
 *                              binary is available; set SSH_KEYGEN to point
 *                              at one explicitly)
 * ---------------------------------------------------------------------------
 */

'use strict';

const path = require('path');
const { spawnSync } = require('child_process');

const SUITES = [
  { name: 'core', file: 'smoke-core.js' },
  { name: 'database', file: 'smoke-db.js' },
  { name: 'app', file: 'smoke-app.js' },
  { name: 'openssh-crosscheck', file: 'crosscheck-keygen.js' }
];

let failures = 0;
const summary = [];

for (const suite of SUITES) {
  const file = path.join(__dirname, suite.file);
  console.log('');
  console.log('========================================================');
  console.log('  suite: ' + suite.name + '  (' + suite.file + ')');
  console.log('========================================================');
  const started = Date.now();
  const res = spawnSync(process.execPath, [file], { stdio: 'inherit' });
  const ms = Date.now() - started;
  const status = res.status === 0 ? 'PASS' : 'FAIL';
  if (res.status !== 0) failures++;
  summary.push({ suite: suite.name, status, ms });
}

console.log('');
console.log('========================================================');
console.log('  SUMMARY');
console.log('========================================================');
for (const s of summary) {
  console.log('  ' + s.status.padEnd(6) + s.suite.padEnd(22) + (s.ms / 1000).toFixed(1) + 's');
}
console.log('');
if (failures > 0) {
  console.log(failures + ' suite(s) FAILED.');
  process.exit(1);
}
console.log('All suites passed.');
