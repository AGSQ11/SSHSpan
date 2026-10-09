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
 * A command must also be REGISTERED: a function can keep its
 * #[tauri::command] attribute after it is taken out of the
 * `tauri::generate_handler![...]` list in src-tauri/src/lib.rs (deliberately,
 * like vault_backup_create - see the "NOT REGISTERED" doc comments), and a
 * call to it then fails at runtime as an unknown command. The attribute scan
 * alone cannot see that, so the handler list is read too.
 *
 * Exits non-zero on: an unknown or unregistered command, a misnamed/unexpected
 * argument, or a required (non-Option) argument the renderer never passes -
 * and if the handler-list parser fails its own self-check below.
 */
'use strict';
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const RUST_DIR = path.join(ROOT, 'src-tauri/src');
const LIB_RS = path.join(ROOT, 'src-tauri/src/lib.rs');
const JS_FILES = ['src/renderer/app.js', 'src/renderer/sftp.js', 'src/renderer/terminal.js', 'src/renderer/mcp.js', 'src/renderer/assistant.js'];

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

/**
 * The command names in `generate_handler![...]`: the last path segment of
 * each entry (`assistant::mcp::mcp_list_servers` registers mcp_list_servers),
 * with // and block comments skipped - the list comments out the commands it
 * deliberately leaves unregistered, and a comment may contain a `]`. Returns
 * null when the source has no complete handler list.
 */
function parseRegisteredCommands(src) {
  const at = src.search(/generate_handler!\s*\[/);
  if (at < 0) return null;
  let i = src.indexOf('[', at) + 1;
  let body = '';
  let depth = 0;
  while (i < src.length) {
    const c = src[i];
    const n = src[i + 1];
    if (c === '/' && n === '/') { while (i < src.length && src[i] !== '\n') i++; continue; }
    if (c === '/' && n === '*') {
      const end = src.indexOf('*/', i + 2);
      i = end < 0 ? src.length : end + 2;
      continue;
    }
    if (c === '[') depth++;
    if (c === ']') {
      if (depth === 0) {
        const names = new Set();
        for (const entry of body.split(',')) {
          const name = entry.trim().split('::').pop().trim();
          if (/^[a-z_][a-z0-9_]*$/.test(name)) names.add(name);
        }
        return names;
      }
      depth--;
    }
    body += c;
    i++;
  }
  return null;
}

/** Find invoke()/call() sites and the literal top-level keys they pass. */
function parseJsCallSites() {
  const sites = [];
  for (const rel of JS_FILES) {
    const file = path.join(ROOT, rel);
    if (!fs.existsSync(file)) continue;
    const src = fs.readFileSync(file, 'utf8');
    // sftpCall is sftp.js's own wrapper around invoke(); without it here most
    // of that file's IPC calls were never checked at all.
    const re = /(?:\bcall|sftpCall|mcpCall|\.invoke|\binvoke)\(\s*(['"`])([a-z_0-9]+)\1\s*(,|\))/g;
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

/** Every problem with these call sites, given the commands and the registered set. */
function findProblems(sites, cmds, registered) {
  const problems = [];
  for (const s of sites) {
    const def = cmds[s.cmd];
    if (!def) { problems.push(`${s.file}:${s.line}  unknown command '${s.cmd}'`); continue; }
    if (!registered.has(s.cmd)) {
      problems.push(
        `${s.file}:${s.line}  '${s.cmd}' is not registered in generate_handler! (src-tauri/src/lib.rs)\n` +
        `        The function exists [${def.file}:${def.line}], but the call fails at runtime as an unknown command.`
      );
      continue;
    }
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
  return problems;
}

// ─── self-check: the checker must catch what it exists to catch ─────────────
//
// A parser that silently returns too much (a commented-out command counted as
// registered) or too little would make the registration check pass or fail for
// the wrong reason, so it is run on a known input first.

function selfCheck() {
  const failed = [];
  const probe = [
    'fn other() { let url = "https://example.com/[not-the-list]"; }',
    '.invoke_handler(tauri::generate_handler![',
    '    // Vault commands [a bracket in a comment does not end the list]',
    '    vault_create,',
    '    /* vault_backup_create, kept out on purpose */',
    '    // vault_backup_restore,',
    '    assistant::mcp::mcp_list_servers,',
    '    sftp_open, sftp_close',
    '])',
  ].join('\n');
  const got = parseRegisteredCommands(probe);
  const want = ['vault_create', 'mcp_list_servers', 'sftp_open', 'sftp_close'];
  if (!got || JSON.stringify([...got]) !== JSON.stringify(want)) {
    failed.push(`handler list parsed as ${JSON.stringify(got && [...got])}, want ${JSON.stringify(want)}`);
  }
  if (parseRegisteredCommands('fn main() {}') !== null) failed.push('a source with no handler list must parse as null');
  if (parseRegisteredCommands('generate_handler![ a, b') !== null) failed.push('an unterminated handler list must parse as null');
  const def = { args: [], file: 'probe.rs', line: 1 };
  const flagged = findProblems(
    [{ cmd: 'vault_backup_create', file: 'probe.js', line: 1, keys: [], dynamic: false },
      { cmd: 'vault_create', file: 'probe.js', line: 2, keys: [], dynamic: false }],
    { vault_backup_create: def, vault_create: def },
    new Set(['vault_create']),
  );
  if (flagged.length !== 1 || !/vault_backup_create' is not registered/.test(flagged[0])) {
    failed.push(`a call to an unregistered command must be the only problem flagged, got ${JSON.stringify(flagged)}`);
  }
  return failed;
}

const selfFailures = selfCheck();
if (selfFailures.length) {
  console.error('check-ipc-args.js failed its own self-check:\n');
  for (const f of selfFailures) console.error('  ' + f);
  process.exit(1);
}

const cmds = parseRustCommands();
const registered = parseRegisteredCommands(fs.readFileSync(LIB_RS, 'utf8'));
if (!registered) {
  console.error(`Could not find a complete tauri::generate_handler![...] list in ${path.relative(ROOT, LIB_RS)}.`);
  process.exit(1);
}
const sites = parseJsCallSites();
const problems = findProblems(sites, cmds, registered);

console.log(`Checked ${sites.length} call sites against ${Object.keys(cmds).length} commands (${registered.size} registered).`);
if (problems.length) {
  console.error(`\n${problems.length} IPC problem(s):\n`);
  for (const p of problems) console.error('  ' + p);
  console.error(
    '\nTauri v2 silently drops an argument whose key does not match, and an\n' +
    'Option<T> parameter then becomes None - so these fail quietly at runtime.\n' +
    'A command missing from generate_handler! fails every call as unknown.\n'
  );
  process.exit(1);
}
console.log('No IPC argument mismatches and no calls to unregistered commands.');
