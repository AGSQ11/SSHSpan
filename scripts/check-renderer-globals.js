#!/usr/bin/env node
/**
 * Flag calls to project functions that are never defined.
 *
 * Why this exists: `sftpWireLocalTbodyDelegation(tabId)` was called in
 * buildSftpPanel and never written — left behind by a refactor that moved the
 * remote pane to a delegated listener and was going to do the same for the
 * local pane. It is valid JavaScript, so `node --check` passes; it throws a
 * ReferenceError at runtime, and because the call sat inside buildSftpPanel
 * the ENTIRE SFTP view failed to build and rendered blank.
 *
 * The renderer's scripts are classic <script> tags sharing one global scope,
 * so a function defined in any of them is visible to all. That makes the check
 * simple: collect every definition across the files, then flag any call to an
 * identifier matching this project's own naming convention that has no
 * definition anywhere.
 *
 * Scoping to the project's prefixes is deliberate. A general no-undef needs a
 * full browser-global list and a scope-aware parser to avoid drowning in false
 * positives; this catches the mistake that actually happened, with no
 * dependencies and no config to rot.
 */
'use strict';
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const FILES = ['src/renderer/app.js', 'src/renderer/sftp.js', 'src/renderer/terminal.js', 'src/renderer/icons.js'];

// Identifiers this project owns. A call to anything else (browser or library
// globals) is out of scope.
const OWNED = /^(sftp|terminal|vault|key|category|server|queue|render|refresh|build|show|open|close|update|toast|el|call|ico|escapeHtml|fmt|format|join|state|system|bw)[A-Za-z0-9_]*$/;

const sources = new Map();
for (const rel of FILES) {
  const abs = path.join(ROOT, rel);
  if (fs.existsSync(abs)) sources.set(rel, fs.readFileSync(abs, 'utf8'));
}

/** Strip comments and string/template literals so they cannot produce hits. */
function scrub(src) {
  let out = '';
  let i = 0;
  while (i < src.length) {
    const c = src[i];
    const n = src[i + 1];
    if (c === '/' && n === '/') { while (i < src.length && src[i] !== '\n') i++; continue; }
    if (c === '/' && n === '*') { i += 2; while (i < src.length && !(src[i] === '*' && src[i + 1] === '/')) i++; i += 2; continue; }
    if (c === "'" || c === '"' || c === '`') {
      const q = c; i++;
      while (i < src.length) {
        if (src[i] === '\\') { i += 2; continue; }
        if (src[i] === q) { i++; break; }
        i++;
      }
      out += '""';
      continue;
    }
    out += c;
    i++;
  }
  return out;
}

// Every name bound at any scope: declarations, assignments, params, imports.
const defined = new Set();
const scrubbed = new Map();
for (const [rel, src] of sources) {
  const s = scrub(src);
  scrubbed.set(rel, s);
  for (const re of [
    /\bfunction\s+([A-Za-z_$][\w$]*)/g,
    /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)/g,
    /\bclass\s+([A-Za-z_$][\w$]*)/g,
    /\bwindow\.([A-Za-z_$][\w$]*)\s*=/g,
    // Destructuring and parameter lists: take every identifier, over-broad on
    // purpose — a false NEGATIVE here is better than crying wolf.
    /\b(?:const|let|var)\s*[{[]([^}\]]*)[}\]]/g,
  ]) {
    let m;
    while ((m = re.exec(s))) {
      for (const part of m[1].split(/[,:\s]+/)) {
        const name = part.replace(/[^\w$]/g, '');
        if (name) defined.add(name);
      }
    }
  }
  // Function parameters.
  let fm;
  const fnRe = /\bfunction\s*[A-Za-z_$\w]*\s*\(([^)]*)\)/g;
  while ((fm = fnRe.exec(s))) {
    for (const part of fm[1].split(',')) {
      const name = part.trim().split(/[\s=]/)[0].replace(/[^\w$]/g, '');
      if (name) defined.add(name);
    }
  }
  const arrowRe = /\(([^)]*)\)\s*=>/g;
  while ((fm = arrowRe.exec(s))) {
    for (const part of fm[1].split(',')) {
      const name = part.trim().split(/[\s=]/)[0].replace(/[^\w$]/g, '');
      if (name) defined.add(name);
    }
  }
}

const problems = [];
for (const [rel, s] of scrubbed) {
  const lines = s.split('\n');
  lines.forEach((line, idx) => {
    const re = /(^|[^.\w$])([A-Za-z_$][\w$]*)\s*\(/g;
    let m;
    while ((m = re.exec(line))) {
      const name = m[2];
      if (!OWNED.test(name)) continue;
      if (defined.has(name)) continue;
      if (['if', 'for', 'while', 'switch', 'catch', 'return', 'typeof', 'function'].includes(name)) continue;
      problems.push(`${rel}:${idx + 1}  calls '${name}(...)', which is never defined in any renderer script`);
    }
  });
}

console.log(`Checked ${scrubbed.size} renderer scripts; ${defined.size} names in scope.`);
if (problems.length) {
  console.error(`\n${problems.length} undefined call(s):\n`);
  for (const p of [...new Set(problems)]) console.error('  ' + p);
  console.error('\nThese are valid syntax, so `node --check` passes; they throw a\nReferenceError at runtime and can take a whole view down with them.\n');
  process.exit(1);
}
console.log('No calls to undefined project functions.');
