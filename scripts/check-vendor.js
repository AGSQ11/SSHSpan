#!/usr/bin/env node
/*
 * Verify the committed front-end libraries against the hashes recorded in
 * src/renderer/vendor/VENDOR.md.
 *
 * The files in that directory carry no version marker of their own, so without
 * this the only way to know what they are is to download upstream and diff.
 * Reading the table out of VENDOR.md rather than duplicating it here means the
 * documentation and the check cannot drift apart: editing one without the other
 * fails the build.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const VENDOR_DIR = path.join(__dirname, '..', 'src', 'renderer', 'vendor');
const MANIFEST = path.join(VENDOR_DIR, 'VENDOR.md');

if (!fs.existsSync(MANIFEST)) {
  console.error(`Missing ${path.relative(process.cwd(), MANIFEST)} - the vendored`);
  console.error('libraries have no recorded provenance. See that file for the format.');
  process.exit(1);
}

// Rows look like: | `xterm.js` | [xterm](url) | 5.5.0 | `<64 hex>` |
const rows = [];
for (const line of fs.readFileSync(MANIFEST, 'utf8').split('\n')) {
  const m = line.match(/^\|\s*`([^`]+)`\s*\|[^|]*\|\s*([^|]+?)\s*\|\s*`([0-9a-f]{64})`\s*\|/);
  if (m) rows.push({ file: m[1], version: m[2], sha256: m[3] });
}

if (rows.length === 0) {
  console.error('VENDOR.md contains no parseable rows - has the table format changed?');
  process.exit(1);
}

let failed = 0;

// Every row must match the file on disk.
for (const row of rows) {
  const p = path.join(VENDOR_DIR, row.file);
  if (!fs.existsSync(p)) {
    console.error(`  MISSING  ${row.file} is listed in VENDOR.md but not present`);
    failed++;
    continue;
  }
  const actual = crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex');
  if (actual !== row.sha256) {
    console.error(`  CHANGED  ${row.file} (${row.version})`);
    console.error(`           recorded ${row.sha256}`);
    console.error(`           on disk  ${actual}`);
    console.error('           Update the version AND the hash in VENDOR.md, or restore the file.');
    failed++;
  } else {
    console.log(`  ok       ${row.file}  ${row.version}`);
  }
}

// And every vendored file must have a row, so a new one cannot slip in unrecorded.
const listed = new Set(rows.map(r => r.file));
for (const name of fs.readdirSync(VENDOR_DIR)) {
  if (name === 'VENDOR.md' || listed.has(name)) continue;
  console.error(`  UNLISTED ${name} is vendored but has no row in VENDOR.md`);
  failed++;
}

if (failed) {
  console.error(`\n${failed} vendored file(s) do not match their recorded provenance.`);
  process.exit(1);
}
console.log(`\nAll ${rows.length} vendored files match VENDOR.md.`);
