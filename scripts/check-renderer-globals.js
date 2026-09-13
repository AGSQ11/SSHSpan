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
const rawSources = new Map();
for (const rel of FILES) {
  const abs = path.join(ROOT, rel);
  if (fs.existsSync(abs)) {
    const text = fs.readFileSync(abs, 'utf8');
    sources.set(rel, text);
    rawSources.set(rel, text);
  }
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
// name -> [{file, line}] for TOP-LEVEL declarations only. Used for the
// duplicate-global check below; nested/param names are not collected here.
const topLevel = new Map();
const scrubbed = new Map();
for (const [rel, src] of sources) {
  const s = scrub(src);
  scrubbed.set(rel, s);
  // Top-level declarations: column 0 only, so nested helpers are excluded.
  for (const re of [
    /^(?:async\s+)?function\s+([A-Za-z_$][\w$]*)/gm,
    /^(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=/gm,
    /^class\s+([A-Za-z_$][\w$]*)/gm,
  ]) {
    let m;
    while ((m = re.exec(s))) {
      const line = s.slice(0, m.index).split('\n').length;
      if (!topLevel.has(m[1])) topLevel.set(m[1], []);
      topLevel.get(m[1]).push({ file: rel, line });
    }
  }
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

// ---- Duplicate top-level names across files -------------------------------
// The renderer's scripts are classic <script> tags sharing ONE global scope,
// loaded app.js -> terminal.js -> sftp.js. Two files declaring the same
// top-level name is not a shadow, it is a REPLACEMENT: the later one wins for
// every caller in every file, silently.
//
// This is not hypothetical. terminal.js had its own `copyText` and its own
// `markTerminalBell`, both of which replaced app.js's:
//   * copyText returned undefined, so sftp.js's `copyText(x).then(...)` threw
//     and app.js's `const ok = await copyText(x)` reported "Clipboard
//     unavailable." on copies that had actually succeeded;
//   * markTerminalBell called `window.markTerminalBell(...)`, which after the
//     replacement was itself — infinite recursion on every background-tab bell.
for (const [name, sites] of topLevel) {
  if (sites.length < 2) continue;
  const files = new Set(sites.map((s2) => s2.file));
  const where = sites.map((s2) => `${s2.file}:${s2.line}`).join(', ');
  if (files.size > 1) {
    problems.push(
      `'${name}' is declared at top level in more than one renderer script: ${where}\n` +
      `        They share one global scope, so the last one loaded silently replaces the others.`
    );
  } else {
    // Same file, declared twice. Function declarations hoist, so the LAST one
    // wins for every caller — including callers written against the first.
    // app.js carried two `filteredKeys`: the first applied the active category
    // filter, the second only search and type. The second won, so selecting a
    // category never filtered the key list.
    problems.push(
      `'${name}' is declared ${sites.length} times at top level in one file: ${where}\n` +
      `        The last declaration wins for every caller; the earlier ones are dead.`
    );
  }
}

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

// ---- Element ids looked up but never created ------------------------------
// `el('x')` and `getElementById('x')` return null for an id that does not
// exist, and the very next `.value` / `.textContent` / `.addEventListener`
// throws. Collect every id the page declares statically plus every id the
// renderer assigns at runtime, then flag lookups that can never match.
{
  const htmlPath = path.join(ROOT, 'src/renderer/index.html');
  if (fs.existsSync(htmlPath)) {
    const html = fs.readFileSync(htmlPath, 'utf8');
    const staticIds = new Set([...html.matchAll(/\bid="([^"]+)"/g)].map((m) => m[1]));
    const exactIds = new Set();
    const prefixes = new Set();
    for (const [, raw] of rawSources) {
      for (const m of raw.matchAll(/\.id\s*=\s*'([^']+)'\s*\+/g)) prefixes.add(m[1]);
      for (const m of raw.matchAll(/\.id\s*=\s*`([^`$]*)\$\{/g)) prefixes.add(m[1]);
      for (const m of raw.matchAll(/\bid="([^"$]*)\$\{/g)) prefixes.add(m[1]);
      for (const m of raw.matchAll(/\.id\s*=\s*'([^']+)'\s*;/g)) exactIds.add(m[1]);
      for (const m of raw.matchAll(/\.id\s*=\s*`([^`$]+)`/g)) exactIds.add(m[1]);
      for (const m of raw.matchAll(/\bid="([^"$]+)"/g)) exactIds.add(m[1]);
    }
    const known = (id) =>
      staticIds.has(id) ||
      exactIds.has(id) ||
      [...prefixes].some((p2) => id.startsWith(p2));
    const knownPrefix = (pfx) =>
      prefixes.has(pfx) ||
      [...staticIds].some((x) => x.startsWith(pfx)) ||
      [...exactIds].some((x) => x.startsWith(pfx));

    for (const [rel, raw] of rawSources) {
      raw.split('\n').forEach((line, idx) => {
        if (/^\s*(\/\/|\*)/.test(line)) return;
        for (const m of line.matchAll(/(?:\bel|getElementById)\(\s*'([^']+)'\s*\)/g)) {
          if (!known(m[1])) {
            problems.push(`${rel}:${idx + 1}  looks up element id '${m[1]}', which is never created`);
          }
        }
        for (const m of line.matchAll(/(?:\bel|getElementById)\(\s*'([^']*)'\s*\+/g)) {
          if (!knownPrefix(m[1])) {
            problems.push(`${rel}:${idx + 1}  looks up ids starting '${m[1]}', but nothing creates one`);
          }
        }
      });
    }
  }
}

console.log(`Checked ${scrubbed.size} renderer scripts; ${defined.size} names in scope.`);
if (problems.length) {
  console.error(`\n${problems.length} problem(s):\n`);
  for (const p of [...new Set(problems)]) console.error('  ' + p);
  console.error(
    '\nAll of these are valid syntax, so `node --check` passes. They fail at\n' +
    'runtime: an undefined call throws a ReferenceError, and a duplicated\n' +
    'global silently replaces the version every other file is calling.\n'
  );
  process.exit(1);
}
console.log('No undefined calls and no duplicated globals.');
