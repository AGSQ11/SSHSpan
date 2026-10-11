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
 * argument (a snake_case twin sent next to its camelCase key included), or a
 * required (non-Option) argument the renderer never passes - and if the
 * handler-list parser fails its own self-check below.
 *
 * This is the one place the renderer-to-backend ARGUMENT contract is enforced,
 * the MCP commands included (mcp.js's mcpCall sites, with the two payloads it
 * builds in a variable: mcp_save_server's `payload` and mcp_set_tool_state's
 * `args`). It used to be written out three times - here, in check-renderer-ui.js
 * and in check-mcp-contract.js - and the copies drifted (A8-17).
 * scripts/check-mcp-contract.js keeps only the checks that are not about
 * argument names, and reads mcp.js's payloads with this file's parser
 * (`require('./check-ipc-args.js')` exports it; running the file is the CLI).
 *
 * What it cannot read it does not guess at: a payload that is a spread, a
 * parameter, a computed key or a variable that is reassigned, deleted from or
 * shadowed is skipped, and the run says how many call sites that was.
 */
'use strict';
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const RUST_DIR = path.join(ROOT, 'src-tauri/src');
const LIB_RS = path.join(ROOT, 'src-tauri/src/lib.rs');
const JS_FILES = ['src/renderer/app.js', 'src/renderer/sftp.js', 'src/renderer/terminal.js', 'src/renderer/mcp.js', 'src/renderer/assistant.js'];

// Parameters Tauri injects itself - never sent from JS. These are the types whose
// `CommandArg` implementation in tauri 2.11.5 does not read the invoke payload:
// AppHandle, Window, Webview, WebviewWindow, State<T>, the ACL scopes
// CommandScope<T> and GlobalScope<T> (tauri::ipc), and the raw tauri::ipc::Request.
// Each may be written with a `tauri::` path in front (`tauri::ipc::CommandScope<T>`,
// `tauri::webview::Webview<R>`). A `Channel<T>` is NOT one of them: it deserializes
// from the payload by its parameter name, so the renderer creates it and passes it
// as an argument (terminal_connect's `onData`) and it is checked like any other.
const INJECTED = /^(?:tauri::(?:[a-z_]+::)*)?(?:(?:AppHandle|WebviewWindow|Webview|Window|Request)\b|(?:State|CommandScope|GlobalScope)\s*<)|^tauri::Runtime\b/;

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
    Object.assign(cmds, parseCommandsIn(fs.readFileSync(file, 'utf8'), path.relative(ROOT, file)));
  }
  return cmds;
}

/** The #[tauri::command]s in one Rust source text. */
function parseCommandsIn(src, rel) {
  const cmds = {};
  const re = /#\[tauri::command([^\]]*)\][\s\S]{0,400}?(?:pub\s+)?(?:async\s+)?fn\s+([a-z_0-9]+)\s*\(([\s\S]*?)\)\s*(?:->|\{)/g;
  let m;
  while ((m = re.exec(src))) {
    const snake = /rename_all\s*=\s*"snake_case"/.test(m[1] || '');
    const name = m[2];
    const args = [];
    // Comments are blanked BEFORE the list is split: a comma or a bracket in
    // a comment between two parameters used to split it there, and the
    // parameter after it was lost.
    for (let part of splitTopLevel(blankRustComments(m[3]), ',')) {
      // Drop attribute lines (#[...]) in front of a parameter.
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
    cmds[name] = { args, file: rel, line: src.slice(0, m.index).split('\n').length };
  }
  return cmds;
}

/// Rust source with every comment blanked to spaces (newlines kept) and string
/// literals left alone, so a comment cannot be mistaken for code - the doc
/// comments mention `generate_handler![...]` - and a `//` inside a string is
/// not taken for a comment.
function blankRustComments(src) {
  let out = '';
  let i = 0;
  while (i < src.length) {
    const c = src[i];
    const n = src[i + 1];
    if (c === '"') {
      let j = i + 1;
      while (j < src.length && src[j] !== '"') j += src[j] === '\\' ? 2 : 1;
      out += src.slice(i, j + 1);
      i = j + 1;
      continue;
    }
    if (c === '/' && n === '/') {
      while (i < src.length && src[i] !== '\n') { out += ' '; i++; }
      continue;
    }
    if (c === '/' && n === '*') {
      const end = src.indexOf('*/', i + 2);
      const stop = end < 0 ? src.length : end + 2;
      out += src.slice(i, stop).replace(/[^\n]/g, ' ');
      i = stop;
      continue;
    }
    out += c;
    i++;
  }
  return out;
}

/// `body` without its `#[...]` attributes (brackets balanced), so a
/// `#[cfg(...)]` in front of an entry neither hides the entry nor - with a
/// comma inside it - splits it in two.
function stripRustAttributes(body) {
  let out = '';
  let i = 0;
  while (i < body.length) {
    if (body[i] === '#' && body[i + 1] === '[') {
      let depth = 0;
      let j = i + 1;
      for (; j < body.length; j++) {
        if (body[j] === '[') depth++;
        else if (body[j] === ']' && --depth === 0) break;
      }
      i = j + 1;
      continue;
    }
    out += body[i];
    i++;
  }
  return out;
}

/**
 * The command names in `generate_handler![...]`: the last path segment of
 * each entry (`assistant::mcp::mcp_list_servers` registers mcp_list_servers).
 * Comments are skipped everywhere: the list comments out the commands it
 * deliberately leaves unregistered, a comment may contain a `]`, and a doc
 * comment ABOVE the macro may mention it. An entry behind `#[cfg(...)]` counts
 * as registered - it is, on the platforms it is built for. Returns null when
 * the source has no complete handler list.
 */
function parseRegisteredCommands(src) {
  const code = blankRustComments(src);
  const at = code.search(/generate_handler!\s*\[/);
  if (at < 0) return null;
  let i = code.indexOf('[', at) + 1;
  let body = '';
  let depth = 0;
  while (i < code.length) {
    const c = code[i];
    if (c === '[') depth++;
    if (c === ']') {
      if (depth === 0) {
        const names = new Set();
        for (const entry of stripRustAttributes(body).split(',')) {
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

/**
 * The top-level keys of the object literal whose `{` is at src[open]. `end` is
 * the index of its closing `}`; `spread` is true when the literal contains a
 * `...`, so not every key can be known statically.
 */
function readObjectKeys(src, open) {
  const keys = [];
  // Walk the object literal, collecting only depth-0 `key:` tokens.
  let depth = 0, str = null, tok = '', j = open, skipValue = false;
  const pushKey = (raw) => {
    const t = raw.trim();
    if (/^[A-Za-z_$][\w$]*$/.test(t)) keys.push(t);
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
  return { keys, end: j, spread: /\.\.\./.test(src.slice(open, j + 1)) };
}

/**
 * Why `name` cannot be assumed to still hold the object literal that declared it,
 * or null when nothing in `code` (the text between that literal and the call)
 * rebinds, rewrites or shadows it. The shapes: a reassignment (`name = ...`,
 * `name ||= ...`, a `for (name of rows)` loop variable, a destructuring assignment),
 * `delete name.key`, the name declared again (including by destructuring), and the
 * name as a parameter of an arrow function, a function, a method or a catch clause -
 * a same-named callback parameter makes the call below it send something else.
 * `name` is a plain identifier (no `$`).
 */
function rebinding(code, name) {
  const word = '(?<![\\w$.])' + name + '(?![\\w$])';
  const reassigned = '(?<![\\w$.])' + name + '\\s*(?:\\*\\*|<<|>>>?|&&|\\|\\||\\?\\?|[-+*/%&|^])?=(?![=>])';
  if (new RegExp(reassigned).test(code)) return 'it is reassigned';
  // Assigned without `=` next to the name: a loop variable (`for (name of rows)`) or a
  // destructuring assignment (`({ name } = other)`, `[name] = other`) - not an index
  // write such as `seen[name] = true`, hence the lookbehind.
  if (new RegExp('\\bfor\\s*(?:await\\s*)?\\(\\s*' + name + '\\s+(?:of|in)\\b').test(code)
    || new RegExp('(?<![\\w$\\])])[\\[{][^=;()]*' + word + '[^=;()]*[\\]}]\\s*=(?![=>])').test(code)) return 'it is reassigned';
  if (new RegExp('\\bdelete\\s+' + name + '\\s*[.\\[]').test(code)) return 'a key is deleted from it';
  if (new RegExp('\\b(?:const|let|var)\\s+' + name + '(?![\\w$])').test(code)
    || new RegExp('\\b(?:const|let|var)\\s*[\\[{][^=;]*' + word).test(code)) return 'the name is declared again';
  if (new RegExp('(?<![\\w$.])' + name + '\\s*=>').test(code)) return 'it is the parameter of an arrow function';
  const parameterLists = [
    ...code.matchAll(/\(([^()]*)\)\s*=>/g),
    ...code.matchAll(/\bfunction\b[^(){};]*\(([^()]*)\)/g),
    // A method: `run(payload) {` - but not `if (payload) {` and the other keywords that take a parenthesis.
    ...code.matchAll(/(?<![\w$.])(?!(?:if|for|while|switch|catch|with|return|typeof|await|else)\b)[A-Za-z_$][\w$]*\s*\(([^()]*)\)\s*\{/g),
  ];
  if (parameterLists.some((m) => new RegExp(word).test(m[1]))) return 'it is a parameter of a function';
  if (new RegExp('\\bcatch\\s*\\([^)]*' + word).test(code)) return 'it is a catch parameter';
  return null;
}

/**
 * The keys of a payload that is built in a variable before the call:
 * `mcpCall('mcp_save_server', payload)` and `mcpCall('mcp_set_tool_state',
 * args)` in mcp.js (A8-17: the MCP contract check this replaces, in
 * check-renderer-ui.js and check-mcp-contract.js, read the same two payloads).
 * `argStart` is the index of the identifier. The keys are those of the object
 * literal that declares it (the nearest `const|let|var name = {` above the call,
 * inside the same function) plus every `name.key = ...` assigned between that
 * literal and the call. Returns null - the call then stays "dynamic", is reported
 * as not checked and is never guessed at - for anything less simple: a spread,
 * `Object.assign`, a computed key, a declaration in another function, or anything
 * `rebinding()` finds between the literal and the call.
 */
function variablePayloadKeys(src, argStart) {
  const ident = /^([A-Za-z_$][\w$]*)\s*\)/.exec(src.slice(argStart, argStart + 80));
  if (!ident) return null;
  const name = ident[1];
  if (name.includes('$')) return null; // legal in an identifier, special in a RegExp: leave it unchecked
  const declRe = new RegExp('(?:const|let|var)\\s+' + name + '\\s*=\\s*\\{', 'g');
  const above = src.slice(0, argStart);
  let decl = null;
  for (let d = declRe.exec(above); d; d = declRe.exec(above)) decl = d;
  if (!decl) return null;
  // The renderer indents everything inside a function, so a line that starts in
  // column 0 between the declaration and the call is another function's edge.
  if (/\n\S/.test(src.slice(decl.index, argStart))) return null;
  const open = decl.index + decl[0].length - 1;
  const literal = readObjectKeys(src, open);
  if (literal.spread) return null;
  const tail = src.slice(literal.end, argStart);
  if (rebinding(tail, name)) return null;
  if (new RegExp('Object\\.assign\\(\\s*' + name + '\\b').test(tail)) return null;
  if (new RegExp('\\b' + name + '\\s*\\[').test(tail)) return null;
  const keys = [...literal.keys];
  const assigned = new RegExp('\\b' + name + '\\.([A-Za-z_$][\\w$]*)\\s*=(?!=)', 'g');
  for (let a = assigned.exec(tail); a; a = assigned.exec(tail)) keys.push(a[1]);
  return keys;
}

/** The invoke()/call() sites in one source text, with the literal top-level keys they pass. */
function parseCallSitesIn(src, rel) {
  const sites = [];
  // sftpCall is sftp.js's own wrapper around invoke(); without it here most
  // of that file's IPC calls were never checked at all. aiCall is
  // assistant.js's, and was missing the same way (A8-17).
  const re = /(?:\bcall|sftpCall|mcpCall|aiCall|\.invoke|\binvoke)\(\s*(['"`])([a-z_0-9]+)\1\s*(,|\))/g;
  let m;
  while ((m = re.exec(src))) {
    const line = src.slice(0, m.index).split('\n').length;
    const site = { cmd: m[2], file: rel, line, keys: [], dynamic: false };
    if (m[3] === ')') { sites.push(site); continue; }
    let i = re.lastIndex;
    while (i < src.length && /\s/.test(src[i])) i++;
    if (src[i] !== '{') {
      const viaVariable = variablePayloadKeys(src, i);
      if (viaVariable) site.keys = viaVariable; else site.dynamic = true;
      sites.push(site);
      continue;
    }
    const literal = readObjectKeys(src, i);
    site.keys = literal.keys;
    if (literal.spread) site.dynamic = true;
    sites.push(site);
  }
  return sites;
}

/** Find invoke()/call() sites and the literal top-level keys they pass. */
function parseJsCallSites() {
  const sites = [];
  for (const rel of JS_FILES) {
    const file = path.join(ROOT, rel);
    if (!fs.existsSync(file)) continue;
    sites.push(...parseCallSitesIn(fs.readFileSync(file, 'utf8'), rel));
  }
  return sites;
}

/** Every problem with these call sites, given the commands and the registered
 *  set. No exemptions: a snake_case twin sent next to its camelCase key (the
 *  seven assistant.js used to send, A8-17) is an unexpected argument like any
 *  other - Tauri drops it silently. */
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
  // A comment that mentions the macro (the doc comments do) is not the list.
  const mentioned = parseRegisteredCommands([
    '/// A command can be taken out of `tauri::generate_handler![...]` on purpose.',
    '// see generate_handler![old_cmd] above',
    '/* generate_handler![ commented_out ] */',
    '.invoke_handler(tauri::generate_handler![ real_cmd ])',
  ].join('\n'));
  if (!mentioned || JSON.stringify([...mentioned]) !== JSON.stringify(['real_cmd'])) {
    failed.push(`a macro mentioned in a comment must not be taken for the list, got ${JSON.stringify(mentioned && [...mentioned])}`);
  }
  // A cfg-gated entry is a registered command (on the platforms it is built
  // for); a comma inside its attribute does not split it.
  const gated = parseRegisteredCommands([
    'tauri::generate_handler![',
    '    always_cmd,',
    '    #[cfg(windows)] win_only_cmd,',
    '    #[cfg(any(target_os = "linux", target_os = "macos"))]',
    '    unix_cmd,',
    '    after_cmd',
    ']',
  ].join('\n'));
  const gatedWant = ['always_cmd', 'win_only_cmd', 'unix_cmd', 'after_cmd'];
  if (!gated || JSON.stringify([...gated]) !== JSON.stringify(gatedWant)) {
    failed.push(`cfg-gated entries must count, got ${JSON.stringify(gated && [...gated])}, want ${JSON.stringify(gatedWant)}`);
  }
  // A comment between two parameters may hold a comma (the one above
  // assistant_save_config's clear_api_key does): the parameter after it
  // must still be read, or a call that sends it is flagged as unexpected.
  const probeCmd = parseCommandsIn([
    '#[tauri::command]',
    'pub fn probe_cmd(',
    '    app: AppHandle,',
    '    api_key: Option<String>,',
    '    // A note (with parentheses), and a comma - then one more line',
    '    // of the same comment.',
    '    clear_api_key: Option<bool>,',
    '    level: String,',
    ') -> CmdResult<Value> {',
  ].join('\n'), 'probe.rs').probe_cmd;
  const probeKeys = probeCmd ? probeCmd.args.map((a) => a.key + (a.optional ? '?' : '')) : null;
  if (JSON.stringify(probeKeys) !== JSON.stringify(['apiKey?', 'clearApiKey?', 'level'])) {
    failed.push(`parameters around a comment with a comma parsed as ${JSON.stringify(probeKeys)}, want ["apiKey?","clearApiKey?","level"]`);
  }
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
  // A Channel<T> parameter is an argument the renderer supplies (terminal_connect's
  // `onData`), not one Tauri injects.
  const channelCmd = parseCommandsIn([
    '#[tauri::command]',
    'pub async fn connect_probe(app: AppHandle, server_id: String, on_data: Channel<String>) -> CmdResult<Value> {',
  ].join('\n'), 'probe.rs').connect_probe;
  const channelKeys = channelCmd ? channelCmd.args.map((a) => a.key + (a.optional ? '?' : '')) : null;
  if (JSON.stringify(channelKeys) !== JSON.stringify(['serverId', 'onData'])) {
    failed.push(`a Channel parameter parsed as ${JSON.stringify(channelKeys)}, want ["serverId","onData"]`);
  }
  // A payload built in a variable first (mcp.js's mcp_save_server `payload` and
  // mcp_set_tool_state `args`): the keys of the literal that declares it, plus
  // any `name.key = ...` added before the call, are the call's keys. Anything
  // less simple stays dynamic - unchecked, never guessed at.
  const viaVariable = parseCallSitesIn([
    'async function save() {',
    '  const payload = {',
    '    id: null,',
    '    name,',
    '    auth_type: kind,',
    '  };',
    "  await mcpCall('mcp_save_server', payload);",
    '}',
    'async function toggle() {',
    '  const args = { id, tool: t.name, enabled };',
    '  if (enabled) args.expected_hash = hash;',
    "  await mcpCall('mcp_set_tool_state', args);",
    '}',
    'function spreads() {',
    '  const merged = { a: 1, ...more };',
    "  mcpCall('spread_cmd', merged);",
    '}',
    'function declared() {',
    '  const other = { a: 1 };',
    '}',
    'function receives(other) {',
    "  return mcpCall('param_cmd', other);",
    '}',
  ].join('\n'), 'probe.js');
  const variableKeys = (cmd) => {
    const s = viaVariable.find((x) => x.cmd === cmd);
    return s ? (s.dynamic ? 'dynamic' : s.keys.join(',')) : 'no such call site';
  };
  const variableWant = {
    mcp_save_server: 'id,name,auth_type',
    mcp_set_tool_state: 'id,tool,enabled,expected_hash',
    spread_cmd: 'dynamic',
    param_cmd: 'dynamic',
  };
  for (const [cmd, want] of Object.entries(variableWant)) {
    if (variableKeys(cmd) !== want) failed.push(`${cmd}'s payload variable parsed as ${variableKeys(cmd)}, want ${want}`);
  }
  // Shapes the resolver must leave unchecked rather than guess at: the variable is
  // reassigned, a key is deleted from it, the name is declared again, or a
  // same-named parameter shadows it (arrow, bare arrow, function, method, catch).
  // The last function is the control: a callback that does NOT shadow still resolves.
  const rebound = parseCallSitesIn([
    'function reassigned() {',
    '  let payload = { a: 1 };',
    '  if (retry) payload = rebuilt();',
    "  mcpCall('reassigned_cmd', payload);",
    '}',
    'function reassignedWithAnOperator() {',
    '  let payload = { a: 1 };',
    '  payload ||= fallback;',
    "  mcpCall('operator_cmd', payload);",
    '}',
    'function loopVariable() {',
    '  let payload = { a: 1 };',
    '  for (payload of rows) { go(); }',
    "  mcpCall('loop_cmd', payload);",
    '}',
    'function destructuringAssignment() {',
    '  let payload = { a: 1 };',
    '  ({ payload } = other());',
    "  mcpCall('destructure_assign_cmd', payload);",
    '}',
    'function deletes() {',
    '  const payload = { a: 1, b: 2 };',
    '  delete payload.b;',
    "  mcpCall('delete_cmd', payload);",
    '}',
    'function arrowParameter() {',
    '  const payload = { a: 1 };',
    '  rows.forEach((row, payload) => {',
    "    mcpCall('arrow_cmd', payload);",
    '  });',
    '}',
    'function bareArrowParameter() {',
    '  const payload = { a: 1 };',
    "  rows.forEach(payload => mcpCall('bare_arrow_cmd', payload));",
    '}',
    'function functionParameter() {',
    '  const payload = { a: 1 };',
    '  rows.forEach(function (row, payload) {',
    "    mcpCall('function_cmd', payload);",
    '  });',
    '}',
    'function methodParameter() {',
    '  const payload = { a: 1 };',
    '  const handlers = {',
    '    run(payload) {',
    "      mcpCall('method_cmd', payload);",
    '    },',
    '  };',
    '}',
    'function catchParameter() {',
    '  const payload = { a: 1 };',
    '  try { go(); } catch (payload) {',
    "    mcpCall('catch_cmd', payload);",
    '  }',
    '}',
    'function declaredAgain() {',
    '  const payload = { a: 1 };',
    '  {',
    '    const payload = other();',
    "    mcpCall('redeclared_cmd', payload);",
    '  }',
    '}',
    'function destructuredAgain() {',
    '  const payload = { a: 1 };',
    '  {',
    '    const { payload } = other();',
    "    mcpCall('destructured_cmd', payload);",
    '  }',
    '}',
    'function stillReadable() {',
    '  const payload = { a: 1 };',
    '  if (payload.a) { rows.forEach((row) => { if (row.ok) payload.b = row.v; }); }',
    "  mcpCall('readable_cmd', payload);",
    '}',
    'function usedAsAnIndex() {',
    '  const payload = { a: 1 };',
    '  seen[payload] = true;',
    "  mcpCall('index_cmd', payload);",
    '}',
  ].join('\n'), 'probe.js');
  const reboundKeys = (cmd) => {
    const s = rebound.find((x) => x.cmd === cmd);
    return s ? (s.dynamic ? 'dynamic' : s.keys.join(',')) : 'no such call site';
  };
  for (const cmd of ['reassigned_cmd', 'operator_cmd', 'loop_cmd', 'destructure_assign_cmd', 'delete_cmd', 'arrow_cmd', 'bare_arrow_cmd', 'function_cmd', 'method_cmd', 'catch_cmd', 'redeclared_cmd', 'destructured_cmd']) {
    if (reboundKeys(cmd) !== 'dynamic') failed.push(`${cmd}'s payload variable is rebound, so it must stay dynamic (unchecked), got ${reboundKeys(cmd)}`);
  }
  if (reboundKeys('readable_cmd') !== 'a,b') failed.push(`a callback that does not shadow the payload must still resolve to a,b, got ${reboundKeys('readable_cmd')}`);
  if (reboundKeys('index_cmd') !== 'a') failed.push(`using the payload as an index (seen[payload] = true) rebinds nothing and must still resolve to a, got ${reboundKeys('index_cmd')}`);
  // Every type Tauri injects is skipped, with or without its path; a Channel is not injected.
  const injectedProbe = parseCommandsIn([
    '#[tauri::command]',
    'pub async fn injected_probe(',
    '    app: tauri::AppHandle,',
    '    window: Window,',
    '    webview: Webview<R>,',
    '    qualified_webview: tauri::Webview<R>,',
    '    webview_window: tauri::WebviewWindow<R>,',
    "    state: State<'_, Foo>,",
    "    qualified_state: tauri::State<'_, Foo>,",
    '    scope: CommandScope<Scope>,',
    '    qualified_scope: tauri::ipc::CommandScope<Scope>,',
    '    global: GlobalScope<Scope>,',
    '    qualified_global: tauri::ipc::GlobalScope<Scope>,',
    "    request: tauri::ipc::Request<'_>,",
    "    bare_request: Request<'_>,",
    '    on_event: Channel<String>,',
    '    qualified_on_event: tauri::ipc::Channel<String>,',
    '    name: String,',
    ') -> Result<(), String> {',
  ].join('\n'), 'probe.rs').injected_probe;
  const injectedKeys = injectedProbe ? injectedProbe.args.map((a) => a.key) : null;
  if (JSON.stringify(injectedKeys) !== JSON.stringify(['onEvent', 'qualifiedOnEvent', 'name'])) {
    failed.push(`injected parameters (AppHandle, Window, Webview, WebviewWindow, State, CommandScope, GlobalScope, Request) must be skipped and Channels kept, got ${JSON.stringify(injectedKeys)}`);
  }
  return failed;
}

function main() {
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
  // A payload the checker cannot read (a spread, a parameter, a rebound variable) is
  // counted and named here, so it cannot be mistaken for one whose names were checked.
  const unchecked = sites.filter((s) => s.dynamic && cmds[s.cmd] && registered.has(s.cmd));
  if (unchecked.length) {
    console.log(`${unchecked.length} of them pass a payload that cannot be read statically; their argument names were NOT checked:`);
    for (const s of unchecked) console.log(`  ${s.file}:${s.line}  ${s.cmd}`);
  } else {
    console.log('Every payload was read statically, so every argument name was checked.');
  }
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
}

// check-mcp-contract.js reads mcp.js's payloads with the same parser instead of
// carrying a copy of it.
module.exports = { INJECTED, parseCommandsIn, parseRegisteredCommands, parseCallSitesIn, readObjectKeys, variablePayloadKeys, rebinding, findProblems };

if (require.main === module) main();
