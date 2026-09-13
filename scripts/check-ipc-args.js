#!/usr/bin/env node
/**
 * Cross-check every renderer invoke()/call() argument name against the Rust
 * #[tauri::command] signature it targets.
 *
 * Why this exists: Tauri v2 converts a command's snake_case parameters to
 * camelCase by default (tauri-macros ArgumentCase::Camel). An argument the
 * renderer spells differently is not an error - the key simply is not found,
 * and an Option<T> parameter deserializes to None. It compiles, it runs, and
 * the feature quietly does nothing.
 *
 * That is exactly how bitwarden_sync came to ignore the user's "apply remote
 * changes?" approval while still reporting "Sync complete." Nothing else in
 * the toolchain catches this class, so it is checked here.
 *
 * Exits non-zero on: an unknown command, a misnamed/unexpected argument, or a
 * required (non-Option) argument the renderer never passes.
 */
'use strict';
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const RUST_DIR = path.join(ROOT, 'src-tauri/src');
const JS_FILES = ['src/renderer/app.js', 'src/renderer/sftp.js', 'src/renderer/terminal.js'];

// Parameters injected by Tauri itself - never sent from JS.
const INJECTED = /^(AppHandle|tauri::AppHandle|Window|tauri::Window|WebviewWindow|tauri::WebviewWindow|State<|tauri::State<|tauri::ipc::|Request|Channel<|tauri::Runtime)/;

function walk(dir, out = []) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p, out);
    else if (p.endsWith('.rs')) out.push(p);
  }
  return out;
}

function splitTopLevel(text, sep) {
  const parts = [];
  let depth = 0, cur = '';
  for (const ch of text) {
    if ('<([{'.includes(ch)) depth++;
    if ('>)]}'.includes(ch)) depth--;
    if (ch === sep && depth === 0) { parts.push(cur); cur = ''; }
    else cur += ch;
  }
  if (cur.trim()) parts.push(cur);
  return parts;
}

const toCamel = (s) => s.replace(/_([a-z0-9])/g, (_, c) => c.toUpperCase());

/** Parse every #[tauri::command] into { name: {args, file, line} }. */
function parseRustCommands() {
  const cmds = {};
  for (const file of walk(RUST_DIR)) {
    const src = fs.readFileSync(file, 'utf8');
    const re = /#\[tauri::command([^\]]*)\][\s\S]{0,400}?(?:pub\s+)?(?:async\s+)?fn\s+([a-z_0-9]+)\s*\(([\s\S]*?)\)\s*(?:->|\{)/g;
    let m;
    while ((m = re.exec(src))) {
      const snake = /rename_all\s*=\s*"snake_case"/.test(m[1] || '');
      const name = m[2];
      const args = [];
      for (let part of splitTopLevel(m[3], ',')) {
        // Strip comment lines; they sit between parameters.
        part = part.split('\n').filter((l) => !/^\s*(\/\/|#\[)/.test(l)).join('\n').trim();
        if (!part) continue;
        const pm = part.match(/^(?:mut\s+)?([a-z_0-9]+)\s*:\s*([\s\S]+)$/);
        if (!pm) continue;
        const [, pname, ptypeRaw] = pm;
        const ptype = ptypeRaw.trim();
        if (INJECTED.test(ptype)) continue;
        args.push({
          key: snake ? pname : toCamel(pname),
          optional: /^Option</.test(ptype),
        });
      }
      cmds[name] = { args, file: path.relative(ROOT, file), line: src.slice(0, m.index).split('\n').length };
    }
  }
  return cmds;
}

/** Find invoke()/call() sites and the literal top-level keys they pass. */
function parseJsCallSites() {
  const sites = [];
  for (const rel of JS_FILES) {
    const file = path.join(ROOT, rel);
    if (!fs.existsSync(file)) continue;
    const src = fs.readFileSync(file, 'utf8');
    const re = /(?:\bcall|\.invoke|\binvoke)\(\s*(['"`])([a-z_0-9]+)\1\s*(,|\))/g;
    let m;
    while ((m = re.exec(src))) {
      const line = src.slice(0, m.index).split('\n').length;
      const site = { cmd: m[2], file: rel, line, keys: [], dynamic: false };
      if (m[3] === ')') { sites.push(site); continue; }
      let i = re.lastIndex;
      while (i < src.length && /\s/.test(src[i])) i++;
      if (src[i] !== '{') { site.dynamic = true; sites.push(site); continue; }
      // Walk the object literal, collecting only depth-0 `key:` tokens.
      let depth = 0, str = null, tok = '', j = i, skipValue = false;
      const pushKey = (raw) => {
        const t = raw.trim();
        if (/^[A-Za-z_$][\w$]*$/.test(t)) site.keys.push(t);
      };
      for (; j < src.length; j++) {
        const c = src[j];
        if (str) { if (c === '\\') { j++; continue; } if (c === str) str = null; continue; }
        if (c === "'" || c === '"' || c === '`') { str = c; continue; }
        if ('([{'.includes(c)) { depth++; continue; }
        if (')]}'.includes(c)) {
          depth--;
          if (depth === 0) { if (!skipValue) pushKey(tok); break; }
          continue;
        }
        if (depth === 1) {
          // `key: value` and ES6 shorthand `{ key }` both name a key. A
          // shorthand entry is a bare identifier terminated by ',' or the
          // closing brace, so flush on both.
          if (c === ':') { pushKey(tok); tok = ''; skipValue = true; }
          else if (c === ',') { if (!skipValue) pushKey(tok); tok = ''; skipValue = false; }
          else tok += c;
        }
      }
      if (/\.\.\./.test(src.slice(i, j + 1))) site.dynamic = true;
      sites.push(site);
    }
  }
  return sites;
}

const cmds = parseRustCommands();
const sites = parseJsCallSites();
const problems = [];

for (const s of sites) {
  const def = cmds[s.cmd];
  if (!def) { problems.push(`${s.file}:${s.line}  unknown command '${s.cmd}'`); continue; }
  if (s.dynamic) continue; // spread or computed args - cannot check statically
  const expected = new Set(def.args.map((a) => a.key));
  for (const k of s.keys) {
    if (!expected.has(k)) {
      const hint = expected.has(toCamel(k)) ? ` (did you mean '${toCamel(k)}'? Tauri camelCases parameters)` : '';
      problems.push(
        `${s.file}:${s.line}  '${s.cmd}' got unexpected arg '${k}'${hint}\n` +
        `        Rust expects: ${[...expected].join(', ') || '<none>'}  [${def.file}:${def.line}]`
      );
    }
  }
  for (const a of def.args) {
    if (!a.optional && !s.keys.includes(a.key)) {
      problems.push(
        `${s.file}:${s.line}  '${s.cmd}' is missing required arg '${a.key}'  [${def.file}:${def.line}]`
      );
    }
  }
}

console.log(`Checked ${sites.length} call sites against ${Object.keys(cmds).length} commands.`);
if (problems.length) {
  console.error(`\n${problems.length} IPC argument problem(s):\n`);
  for (const p of problems) console.error('  ' + p);
  console.error(
    '\nTauri v2 silently drops an argument whose key does not match, and an\n' +
    'Option<T> parameter then becomes None - so these fail quietly at runtime.\n'
  );
  process.exit(1);
}
console.log('No IPC argument mismatches.');
