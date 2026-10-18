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
 * What it cannot read it does not guess at, and it never counts as checked: a
 * command named by a variable or an expression (`call(cmd, { jobId })`), a
 * payload that is a spread, a parameter, a variable that is reassigned, deleted
 * from or shadowed, or that holds a computed key (`[name]: v`) or another key
 * that is not a plain name, and every other use of a wrapper's name - an alias
 * (`const c = call`), `.call`/`.apply`, `window.call`, a bracket access
 * (`tcore['invoke']`), `(0, call)(...)`, a destructured alias, `(window.call
 * || call)(...)` - through which calls are made that cannot be read. Each such
 * call site is listed by the run with the reason, and the summary says "every
 * argument name was checked" only when there is none. A quoted key ('jobId':
 * v) is read like a plain one; a call with spaces, a line break or `?.`
 * before its "(" like any other. Comments and the text of strings are never
 * read as code.
 */
'use strict';
const fs = require('fs');
const path = require('path');
// The renderer's source as code alone (comments and the text of strings,
// templates and regular expressions blanked), from the hygiene check's reader.
const { jsMask, jsCode } = require('./check-renderer-hygiene.js');

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

/// The characters after which a `/` starts a regular expression rather than a
/// division (the walkers below skip a regular expression whole: one can hold a
/// quote, a bracket or `//`).
const REGEX_MAY_FOLLOW = /^$|[(,=:[!&|?{};+\-*%<>~^]/;

/// The index of the last character of the regular expression literal that
/// starts at src[at] (its flags included).
function endOfRegex(src, at) {
  let j = at + 1;
  let inClass = false;
  for (; j < src.length && src[j] !== '\n'; j++) {
    const c = src[j];
    if (c === '\\') { j++; continue; }
    if (c === '[') inClass = true;
    else if (c === ']') inClass = false;
    else if (c === '/' && !inClass) break;
  }
  while (j + 1 < src.length && /[a-z]/i.test(src[j + 1])) j++;
  return j;
}

/**
 * The top-level keys of the object literal whose `{` is at src[open]. `end` is
 * the index of its closing `}`; `spread` is true when the literal contains a
 * `...`, so not every key can be known statically. A quoted key is the text
 * between its quotes ('jobId' is jobId), so a misspelled one is caught like a
 * plain one. A key that cannot be read - computed ([name]), quoted with an
 * escape in it, a number, an accessor - is never dropped quietly: `unreadable`
 * says what it was, and the call site is then reported as not checked.
 * Comments and regular expressions inside the literal are skipped.
 */
function readObjectKeys(src, open) {
  const keys = [];
  let unreadable = null;
  // Walk the object literal, collecting only depth-1 `key:` tokens.
  let depth = 0, str = null, tok = '', quoted = null, j = open, skipValue = false, prev = '';
  const cannotRead = (why) => { if (!unreadable) unreadable = why; };
  const pushKey = () => {
    const t = tok.trim();
    if (quoted !== null) {
      if (t) cannotRead(`a key that is not a plain name ('${quoted}' ${t})`);
      else if (quoted.includes('\\')) cannotRead(`a quoted key with an escape ('${quoted}')`);
      else keys.push(quoted);
    } else if (/^[A-Za-z_$][\w$]*$/.test(t)) {
      keys.push(t);
    } else if (t && !t.startsWith('...')) {
      cannotRead(`a key that is not a plain name (${t.replace(/\s+/g, ' ')})`);
    }
    tok = '';
    quoted = null;
  };
  for (; j < src.length; j++) {
    const c = src[j];
    if (str) {
      if (c === '\\') { if (str.key) str.text += c + (src[j + 1] || ''); j++; continue; }
      if (c === str.q) { if (str.key) quoted = str.text; str = null; prev = c; continue; }
      if (str.key) str.text += c;
      continue;
    }
    if (c === '/' && src[j + 1] === '/') { const nl = src.indexOf('\n', j); j = nl < 0 ? src.length : nl - 1; continue; }
    if (c === '/' && src[j + 1] === '*') { const e = src.indexOf('*/', j + 2); j = e < 0 ? src.length : e + 1; continue; }
    if (c === '/' && REGEX_MAY_FOLLOW.test(prev)) { j = endOfRegex(src, j); prev = '/'; continue; }
    if (!/\s/.test(c)) prev = c;
    const atKey = depth === 1 && !skipValue && !tok.trim() && quoted === null;
    if (c === "'" || c === '"' || c === '`') {
      // A string where a key starts is the key; anywhere else it is skipped.
      str = { q: c, key: atKey && c !== '`', text: '' };
      continue;
    }
    if (atKey && c === '[') cannotRead('a computed key ([...])');
    if ('([{'.includes(c)) { depth++; continue; }
    if (')]}'.includes(c)) {
      depth--;
      if (depth === 0) { if (!skipValue) pushKey(); break; }
      continue;
    }
    if (depth === 1) {
      // `key: value` and ES6 shorthand `{ key }` both name a key. A
      // shorthand entry is a bare identifier terminated by ',' or the
      // closing brace, so flush on both.
      if (c === ':' && !skipValue) { pushKey(); skipValue = true; }
      else if (c === ',') { if (!skipValue) pushKey(); tok = ''; quoted = null; skipValue = false; }
      else if (!skipValue) tok += c;
    }
  }
  return { keys, end: j, spread: /\.\.\./.test(src.slice(open, j + 1)), unreadable };
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
  if (literal.spread || literal.unreadable) return null;
  const tail = src.slice(literal.end, argStart);
  if (rebinding(tail, name)) return null;
  if (new RegExp('Object\\.assign\\(\\s*' + name + '\\b').test(tail)) return null;
  if (new RegExp('\\b' + name + '\\s*\\[').test(tail)) return null;
  const keys = [...literal.keys];
  const assigned = new RegExp('\\b' + name + '\\.([A-Za-z_$][\\w$]*)\\s*=(?!=)', 'g');
  for (let a = assigned.exec(tail); a; a = assigned.exec(tail)) keys.push(a[1]);
  return keys;
}

// The ways the renderer calls a command: invoke() itself and the wrappers
// around it. sftpCall is sftp.js's own; without it here most of that file's
// IPC calls were never checked at all. aiCall is assistant.js's, and was
// missing the same way (A8-17). A method of that name on something else
// (`fn.call(this, ...)`) is not one. Spaces, a line break or `?.` may stand
// between the name and its "(".
const WRAPPER_NAMES = ['call', 'sftpCall', 'mcpCall', 'aiCall', 'invoke'];
const WRAPPER_ALT = WRAPPER_NAMES.join('|');
const IPC_CALL = new RegExp('(?<![\\w$.])(?:' + WRAPPER_ALT + ')\\s*(?:\\?\\.\\s*)?\\(|\\.\\s*invoke\\s*(?:\\?\\.\\s*)?\\(', 'g');
/// A wrapper's name as a word of code.
const WRAPPER_WORD = new RegExp('(?<![\\w$])(' + WRAPPER_ALT + ')(?![\\w$])', 'g');
/// A wrapper's name as a string in brackets: tcore['invoke'], window["call"].
const WRAPPER_BRACKET = new RegExp('\\[\\s*([\'"`])(' + WRAPPER_ALT + ')\\1\\s*\\]', 'g');

/**
 * The bodies of the wrappers declared in `code` (masked: comments and the text
 * of strings blanked) - `async function call(cmd, args) { return await
 * invoke(cmd, args ?? {}); }` and the arrow wrappers `const mcpCall = (cmd,
 * args) => (window.call || call)(cmd, args);`: where a wrapper hands its own
 * first parameter on to the next layer. That is the wrapper, not a call site,
 * and the names it uses there are the chain of wrappers, not references.
 */
function wrapperBodies(code) {
  const bodies = [];
  const blockEnd = (open) => {
    let depth = 0;
    let j = open;
    for (; j < code.length; j++) {
      if (code[j] === '{') depth++;
      else if (code[j] === '}' && --depth === 0) break;
    }
    return j;
  };
  const fnRe = new RegExp('\\bfunction\\s+(' + WRAPPER_ALT + ')\\s*\\(\\s*([A-Za-z_$][\\w$]*)[^)]*\\)\\s*\\{', 'g');
  for (let m = fnRe.exec(code); m; m = fnRe.exec(code)) {
    bodies.push({ from: m.index + m[0].length, to: blockEnd(m.index + m[0].length - 1), param: m[2] });
  }
  const arrowRe = new RegExp('\\b(?:const|let|var)\\s+(' + WRAPPER_ALT + ')\\s*=\\s*(?:async\\s*)?\\(\\s*([A-Za-z_$][\\w$]*)[^)]*\\)\\s*=>\\s*', 'g');
  for (let m = arrowRe.exec(code); m; m = arrowRe.exec(code)) {
    const from = m.index + m[0].length;
    let to = from;
    if (code[from] === '{') {
      to = blockEnd(from);
    } else {
      // An expression body: to the `;`, the line break or the bracket that
      // ends it at its own depth.
      let depth = 0;
      for (; to < code.length; to++) {
        const c = code[to];
        if ('([{'.includes(c)) depth++;
        else if (')]}'.includes(c)) { if (depth === 0) break; depth--; }
        else if ((c === ';' || c === '\n' || c === ',') && depth === 0) break;
      }
    }
    bodies.push({ from, to, param: m[2] });
  }
  return bodies;
}

/// The index of the `(`, `[` or `{` that holds `at` in `code` (masked), or -1.
function enclosingOpen(code, at) {
  let depth = 0;
  for (let i = at - 1; i >= 0; i--) {
    const c = code[i];
    if (')]}'.includes(c)) depth++;
    else if ('([{'.includes(c)) {
      if (depth === 0) return i;
      depth--;
    }
  }
  return -1;
}

/// The index of the bracket that closes the one at `open`, or -1.
function matchingClose(code, open) {
  const o = code[open];
  const c = { '(': ')', '[': ']', '{': '}' }[o];
  let depth = 0;
  for (let i = open; i < code.length; i++) {
    if (code[i] === o) depth++;
    else if (code[i] === c && --depth === 0) return i;
  }
  return -1;
}

/// Whether the `(` at `open` starts a parameter list - a function's, an
/// arrow's, a method's - or a catch clause's, where a pattern renames too.
function isParameterList(code, open) {
  const before = code.slice(Math.max(0, open - 60), open);
  if (/\bcatch\s*$/.test(before)) return true;
  if (/\bfunction\b[^(){};=]*$/.test(before)) return true;
  const close = matchingClose(code, open);
  const after = close >= 0 ? code.slice(close + 1, close + 20) : '';
  if (/^\s*=>/.test(after)) return true;
  // A method: `name(...) {` - not `if (...) {` and the other keywords.
  return /^\s*\{/.test(after)
    && /(?<![\w$.])(?!(?:if|for|while|switch|catch|with|return|typeof|await|else|function)\b)[A-Za-z_$][\w$]*\s*$/.test(before);
}

/// Whether the key at `at` sits in a destructuring pattern - `const {
/// invoke: inv } = ...`, `({ invoke: inv } = ...)`, a parameter's or a catch
/// clause's (`function f({ invoke: inv })`, `({ call: c }) => ...`), nested in
/// other object or array patterns too - rather than in an object literal.
function inDestructuring(code, at) {
  let open = enclosingOpen(code, at);
  for (let level = 0; open >= 0 && level < 8; level++) {
    if (code[open] === '(') return isParameterList(code, open);
    const before = code.slice(Math.max(0, open - 40), open);
    if (/\b(?:const|let|var)\s*$/.test(before)) return true;
    const close = matchingClose(code, open);
    if (close >= 0 && /^\s*=(?![=>])/.test(code.slice(close + 1, close + 20))) return true;
    // Only a pattern inside a pattern, or one in a parameter list, goes on
    // outwards: `{ a: { invoke: x } }`, `[{ invoke: x }]`, `(a, { call: c })`.
    if (!/[:,[{(]\s*$/.test(before)) return false;
    open = enclosingOpen(code, open);
  }
  return false;
}

/**
 * Every use of a wrapper's name in `code` (masked) that is neither a call
 * (the sites IPC_CALL finds) nor a definition: it hands the wrapper on - an
 * alias (`const c = call`), `.call`/`.apply` on it, `window.call`, `(0,
 * call)(...)`, a destructured alias (`{ invoke: inv }`), `(window.call ||
 * call)(...)`, a bracket access (`tcore['invoke']`, read in `commentFree`:
 * the source with comments blanked and strings kept) - and the calls made
 * through it cannot be read. As { at, text }. Not one: a definition
 * (`function call(...)`, `const mcpCall = ...`, `const { invoke } = ...`),
 * the names inside a wrapper's own body, and a method of that name on
 * another object (`handler.call(this, ev)`).
 */
function wrapperReferences(code, commentFree, bodies) {
  const found = [];
  WRAPPER_WORD.lastIndex = 0;
  for (let m = WRAPPER_WORD.exec(code); m; m = WRAPPER_WORD.exec(code)) {
    const at = m.index;
    const name = m[1];
    if (bodies.some((w) => at >= w.from && at < w.to)) continue;
    const before = code.slice(Math.max(0, at - 200), at);
    const after = code.slice(at + name.length, at + name.length + 40);
    const called = /^\s*(?:\?\.\s*)?\(/.test(after);
    const owner = /([A-Za-z_$][\w$]*)?\s*(?:\?\.|\.)\s*$/.exec(before);
    if (owner) {
      const onGlobal = /^(?:window|globalThis|self)$/.test(owner[1] || '');
      if (!onGlobal && (name === 'call' || (name === 'invoke' && called))) continue;
      found.push({ at, text: (owner[1] ? owner[1] + '.' : '.') + name });
      continue;
    }
    if (called) continue;
    if (/\bfunction\s*\*?\s*$/.test(before)) continue;
    if (/\b(?:const|let|var)\s+$/.test(before) && /^\s*=/.test(after)) continue;
    if (/[{,]\s*$/.test(before) && /^\s*[,}]/.test(after) && /\b(?:const|let|var)\s*\{[^}]*$/.test(before)) continue;
    // A key named like a wrapper (`{ call: () => 1 }`) is no reference to one
    // - unless the braces are a destructuring pattern, where `{ invoke: inv }`
    // renames the wrapper. (After "?" it is a ternary's branch: a reference.)
    if (/[{,]\s*$/.test(before) && /^\s*:/.test(after) && !inDestructuring(code, at)) continue;
    found.push({ at, text: name });
  }
  WRAPPER_BRACKET.lastIndex = 0;
  for (let m = WRAPPER_BRACKET.exec(commentFree); m; m = WRAPPER_BRACKET.exec(commentFree)) {
    if (code[m.index] === '[') found.push({ at: m.index, text: `[${m[1]}${m[2]}${m[1]}]` });
  }
  return found;
}

/**
 * The first argument of the call whose `(` ends at src[at - 1]: its text up to
 * the top-level `,` or `)` that ends it, and where that is. `literal` is the
 * command name when the argument is exactly one string literal; otherwise
 * null - a variable, a template with a substitution, a concatenation, a
 * conditional - and the command cannot be read.
 */
function firstArgument(src, at) {
  let i = at;
  while (i < src.length && /\s/.test(src[i])) i++;
  const q = src[i];
  if (q === "'" || q === '"' || q === '`') {
    let j = i + 1;
    while (j < src.length && src[j] !== q && src[j] !== '\n') j += src[j] === '\\' ? 2 : 1;
    let k = j + 1;
    while (k < src.length && /\s/.test(src[k])) k++;
    const text = src.slice(i + 1, j);
    const plain = !text.includes('\\') && !(q === '`' && text.includes('${'));
    if (plain && (src[k] === ',' || src[k] === ')')) return { literal: text, text: src.slice(i, j + 1), end: k };
  }
  let depth = 0;
  let j = i;
  for (; j < src.length; j++) {
    const c = src[j];
    if (c === "'" || c === '"' || c === '`') {
      let k = j + 1;
      while (k < src.length && src[k] !== c) k += src[k] === '\\' ? 2 : 1;
      j = k;
      continue;
    }
    if ('([{'.includes(c)) depth++;
    else if (')]}'.includes(c)) { if (depth === 0) break; depth--; }
    else if (c === ',' && depth === 0) break;
  }
  return { literal: null, text: src.slice(i, j).trim(), end: j };
}

/**
 * The invoke()/call() sites in one source text, with the top-level keys they
 * pass. A site whose command name is not a plain string literal (a variable,
 * a template with a substitution, an expression) cannot be checked at all: it
 * is kept with `cmd: null`, and the run lists it as not checked. `why` says
 * why a site is not (fully) checked.
 */
function parseCallSitesIn(src, rel) {
  const sites = [];
  // Calls are found in the code alone - a comment or a string that says "a
  // call (...)" is none - and read from the source at the same place.
  const code = jsMask(src);
  const wrappers = wrapperBodies(code);
  const lineOf = (at) => src.slice(0, at).split('\n').length;
  IPC_CALL.lastIndex = 0;
  for (let m = IPC_CALL.exec(code); m; m = IPC_CALL.exec(code)) {
    // A declaration of the wrapper is no call (`async function call(cmd, args)`).
    if (/\bfunction\s*\*?\s*$/.test(code.slice(Math.max(0, m.index - 20), m.index))) continue;
    const after = m.index + m[0].length;
    const arg = firstArgument(src, after);
    // `invoke()` with nothing in it is no call.
    if (!arg.text) continue;
    if (arg.literal === null && wrappers.some((w) => m.index >= w.from && m.index < w.to && arg.text === w.param)) continue;
    const line = lineOf(m.index);
    if (arg.literal === null) {
      const shown = arg.text.length > 48 ? arg.text.slice(0, 45) + '...' : arg.text;
      sites.push({ at: m.index, cmd: null, file: rel, line, keys: [], dynamic: true, why: `the command name is not a string literal (${shown})` });
      continue;
    }
    const site = { at: m.index, cmd: arg.literal, file: rel, line, keys: [], dynamic: false };
    sites.push(site);
    if (src[arg.end] === ')') continue;
    let i = arg.end + 1;
    while (i < src.length && /\s/.test(src[i])) i++;
    if (src[i] === ')') continue;
    if (src[i] !== '{') {
      const viaVariable = variablePayloadKeys(src, i);
      if (viaVariable) site.keys = viaVariable;
      else Object.assign(site, { dynamic: true, why: 'the payload is not an object literal or a plainly declared variable' });
      continue;
    }
    const literal = readObjectKeys(src, i);
    site.keys = literal.keys;
    if (literal.spread) Object.assign(site, { dynamic: true, why: 'the payload has a spread (...)' });
    else if (literal.unreadable) Object.assign(site, { dynamic: true, why: 'the payload has ' + literal.unreadable });
  }
  // The wrapper handed on: one site NOT checked per line that does it.
  const byLine = new Map();
  for (const r of wrapperReferences(code, jsCode(src), wrappers)) {
    const line = lineOf(r.at);
    const had = byLine.get(line);
    if (had) had.texts.push(r.text);
    else byLine.set(line, { at: r.at, texts: [r.text] });
  }
  for (const [line, r] of byLine) {
    sites.push({ at: r.at, cmd: null, file: rel, line, keys: [], dynamic: true,
      why: `the wrapper is handed on (${r.texts.join(', ')}), so the calls made through it cannot be read` });
  }
  return sites.sort((a, b) => a.at - b.at);
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
    if (s.cmd == null) continue; // its command cannot be read: listed as not checked
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

/**
 * The run's summary, which counts as checked only the call sites whose argument
 * names were compared with the Rust signature. A site whose command name or
 * payload cannot be read statically (a variable command, a spread, a computed
 * key, a parameter, a rebound variable) is named with the reason, so it cannot
 * be taken for one that was checked; only when there is none does the summary
 * say every argument name was checked.
 */
function summaryLines(sites, cmds, registered) {
  const notChecked = sites.filter((s) => s.cmd == null || (s.dynamic && cmds[s.cmd] && registered.has(s.cmd)));
  const checked = sites.length - notChecked.length;
  const lines = [`Checked ${checked} call site${checked === 1 ? '' : 's'} against ${Object.keys(cmds).length} commands (${registered.size} registered).`];
  if (notChecked.length) {
    lines.push(notChecked.length === 1
      ? '1 more call site was NOT checked - its command name or payload cannot be read statically:'
      : `${notChecked.length} more call sites were NOT checked - their command name or payload cannot be read statically:`);
    for (const s of notChecked) lines.push(`  ${s.file}:${s.line}  ${s.cmd == null ? '(command unknown)' : s.cmd} - ${s.why || 'the payload cannot be read statically'}`);
  } else {
    lines.push('Every call site was read statically, so every argument name was checked.');
  }
  return lines;
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
  // A command named by a variable or an expression cannot be checked at all, so it
  // is a site that is listed as NOT checked - sftp.js's `call(cmd, { jobId })`
  // (pause, resume, cancel, retry) used to be no site at all. A wrapper handing its
  // own parameters on (app.js `call`, sftp.js `sftpCall`) is the wrapper, not a
  // site; its declaration and a comment that mentions invoke() are none either.
  const variableCommands = parseCallSitesIn([
    '/** Every IPC call goes through invoke() which returns the result. */',
    'async function call(cmd, args) {',
    '  return await invoke(cmd, args ?? {});',
    '}',
    'async function sftpCall(cmd, args) {',
    '  return await sftpCore.invoke(cmd, args);',
    '}',
    'function jobButton(cmd, j) {',
    "  b.addEventListener('click', () => call(cmd, { jobId: j.id }));",
    '}',
    'function op(kind, dir) {',
    '  sftpCall(`sftp_${kind}`, { sessionId });',
    "  sftpCall('sftp_' + kind, { sessionId });",
    "  return call(kind === 'a' ? 'cmd_a' : 'cmd_b', { sessionId, path: dir });",
    '}',
    "call('literal_cmd', { sessionId });",
    'handler.call(this, ev); // a method of another object, not the IPC wrapper',
  ].join('\n'), 'probe.js');
  const named = variableCommands.map((s) => (s.cmd == null ? '?' : s.cmd) + '@' + s.line);
  const namedWant = ['?@9', '?@12', '?@13', '?@14', 'literal_cmd@16'];
  if (JSON.stringify(named) !== JSON.stringify(namedWant)) {
    failed.push(`call sites with a command in a variable parsed as ${JSON.stringify(named)}, want ${JSON.stringify(namedWant)} (? = not readable)`);
  }
  const probeCmds = { literal_cmd: { args: [{ key: 'sessionId', optional: false }], file: 'probe.rs', line: 1 } };
  const probeRegistered = new Set(['literal_cmd']);
  const variableProblems = findProblems(variableCommands, probeCmds, probeRegistered);
  if (variableProblems.length) failed.push(`a site whose command cannot be read is not checked, so it is no problem either, got ${JSON.stringify(variableProblems)}`);
  // Quoted keys are keys like any other (recorded without their quotes, so a
  // misspelled one is caught); a computed key, a key with an escape and anything
  // else that is not a plain name cannot be read, and its site is not checked.
  const keyed = parseCallSitesIn([
    "call('quoted_cmd', { 'jobId': 1, \"sessionId\": s, plain });",
    "call('computed_cmd', { [field]: 1, a: 2 });",
    "call('escaped_cmd', { 'job\\u0049d': 1 });",
    'function save() {',
    "  const payload = { 'name': n, url };",
    "  return mcpCall('variable_quoted_cmd', payload);",
    '}',
    'function computed() {',
    '  const payload = { [k]: v };',
    "  return mcpCall('variable_computed_cmd', payload);",
    '}',
    "call('numeric_cmd', { 1: x });",
    "call('accessor_cmd', { get value() { return 1; } });",
    "call('misnamed_cmd', { 'job_id': 1 });",
  ].join('\n'), 'probe.js');
  const keysOf = (cmd) => {
    const s = keyed.find((x) => x.cmd === cmd);
    return s ? (s.dynamic ? 'dynamic' : s.keys.join(',')) : 'no such call site';
  };
  const keyedWant = {
    quoted_cmd: 'jobId,sessionId,plain',
    computed_cmd: 'dynamic',
    escaped_cmd: 'dynamic',
    variable_quoted_cmd: 'name,url',
    variable_computed_cmd: 'dynamic',
    numeric_cmd: 'dynamic',
    accessor_cmd: 'dynamic',
    misnamed_cmd: 'job_id',
  };
  for (const [cmd, want] of Object.entries(keyedWant)) {
    if (keysOf(cmd) !== want) failed.push(`${cmd}'s payload keys parsed as ${keysOf(cmd)}, want ${want}`);
  }
  const misnamed = findProblems(keyed.filter((s) => s.cmd === 'misnamed_cmd'),
    { misnamed_cmd: { args: [{ key: 'jobId', optional: false }], file: 'probe.rs', line: 1 } }, new Set(['misnamed_cmd']));
  if (!(misnamed.length === 2 && /unexpected arg 'job_id' \(did you mean 'jobId'/.test(misnamed[0]) && /missing required arg 'jobId'/.test(misnamed[1]))) {
    failed.push(`a misspelled quoted key must be flagged like a plain one, got ${JSON.stringify(misnamed)}`);
  }
  // The summary never claims every argument name was checked while a site was not:
  // each one is named, with the reason.
  const partial = summaryLines(variableCommands, probeCmds, probeRegistered);
  const partialText = partial.join('\n');
  if (/every argument name was checked/i.test(partialText)
    || !['probe.js:9', 'probe.js:12', 'probe.js:13', 'probe.js:14'].every((at) => partialText.includes(at))
    || !/^Checked 1 call site against /.test(partial[0])) {
    failed.push(`with unreadable sites the summary must count only the checked ones and name the rest, got ${JSON.stringify(partial)}`);
  }
  const spreadSite = { cmd: 'literal_cmd', file: 'probe.js', line: 30, keys: [], dynamic: true, why: 'the payload has a spread' };
  const spreadSummary = summaryLines([spreadSite], probeCmds, probeRegistered).join('\n');
  if (/every argument name was checked/i.test(spreadSummary) || !spreadSummary.includes('probe.js:30')) {
    failed.push(`a payload that cannot be read must be named as not checked, got ${JSON.stringify(spreadSummary)}`);
  }
  const complete = summaryLines(variableCommands.filter((s) => s.cmd === 'literal_cmd'), probeCmds, probeRegistered);
  if (!/every argument name was checked/i.test(complete.join('\n'))) {
    failed.push(`with every site read the summary says so, got ${JSON.stringify(complete)}`);
  }
  // A call written with spaces, a line break or `?.` before its "(" is read
  // like any other. Every other use of a wrapper's name hands the wrapper on
  // to calls that cannot be read - an alias, .call/.apply, window.call, a
  // bracket access, (0, call)(...), a destructured alias, (window.call ||
  // call)(...) - so each is a site NOT checked (one per line). Comments,
  // strings, templates and regular expressions name them freely, and the
  // definitions - `const { invoke } = ...`, `function call(...)`, an arrow
  // wrapper handing its own parameter on - are no sites.
  const shapes = parseCallSitesIn([
    "call\n  ('spaced_cmd', { sessionId });",
    "call?.('optional_cmd', { sessionId });",
    "tcore.invoke ?.('optional_invoke_cmd', { sessionId });",
    'const c = call;',
    "call.call(null, 'x_cmd', {});",
    "invoke.apply(null, ['x_cmd', {}]);",
    "tcore['invoke']('x_cmd', {});",
    "window.call('x_cmd', {});",
    "(0, call)('x_cmd', {});",
    'const { invoke: inv } = tcore;',
    "(window.call || call)('x_cmd', {});",
    '// a call (in a comment) and invoke() mentioned',
    "const s = 'a call (in a string)' + `and ${'call'} (a template)`;",
    'handler.call(this, ev); fn.apply(this, args);',
    'const { invoke } = window.__TAURI__.core;',
    'const mcpCall = (cmd, args) => (window.call || call)(cmd, args);',
    'async function call(cmd, args) { return await invoke(cmd, args); }',
    'const re = /call\\(|invoke\\(/g;',
    // An object literal's keys named like a wrapper are no reference to one;
    // a destructuring assignment that renames one is; so is a ternary branch.
    'const api = { call: () => 1, invoke: 2, mcpCall: 3 };',
    '({ invoke: inv2 } = tcore);',
    'const handlers = { call() { return 1; } };',
    'const pick = fast ? call : sftpCall;',
    'const [{ invoke: inv3 }] = list;',
    'const nested = { a: { call: 1 }, b: [{ invoke: 2 }] }; run({ mcpCall: 3 });',
    'for (const { invoke: inv4 } of list) {}',
    // A parameter pattern renames a wrapper as well: a function's, an arrow's,
    // a method's (a later parameter too) and a catch clause's. An object
    // literal handed to a call, or tested in an if, does not.
    'function useApi({ invoke: inv5 }) { return inv5; }',
    'const run = ({ call: c1 }) => c1;',
    'try { go(); } catch ({ invoke: inv6 }) {}',
    'class Api { m({ mcpCall: m1 }) { return m1; } }',
    'go({ call: 1 }); if (ok({ invoke: 2 })) { done(); }',
    'function two(a, { sftpCall: s1 }) { return s1; }',
    'list.forEach(function ({ invoke: inv7 }) { return inv7; });',
  ].join('\n'), 'probe.js');
  const shapesGot = shapes.map((s) => (s.cmd == null ? '?' : s.cmd) + '@' + s.line);
  const shapesWant = ['spaced_cmd@1', 'optional_cmd@3', 'optional_invoke_cmd@4', '?@5', '?@6', '?@7', '?@8', '?@9', '?@10', '?@11', '?@12',
    '?@21', '?@23', '?@24', '?@26', '?@27', '?@28', '?@29', '?@30', '?@32', '?@33'];
  if (JSON.stringify(shapesGot) !== JSON.stringify(shapesWant)) {
    failed.push(`calls with a space or ?. and other uses of a wrapper's name parsed as ${JSON.stringify(shapesGot)}, want ${JSON.stringify(shapesWant)}`);
  }
  const shapeCmds = Object.fromEntries(['spaced_cmd', 'optional_cmd', 'optional_invoke_cmd']
    .map((c) => [c, { args: [{ key: 'sessionId', optional: false }], file: 'probe.rs', line: 1 }]));
  const shapeRegistered = new Set(Object.keys(shapeCmds));
  const shapeProblems = findProblems(shapes, shapeCmds, shapeRegistered);
  if (shapeProblems.length) failed.push(`the readable calls among them pass, got ${JSON.stringify(shapeProblems)}`);
  const shapeSummary = summaryLines(shapes, shapeCmds, shapeRegistered);
  if (shapeSummary[0] !== 'Checked 3 call sites against 3 commands (3 registered).'
    || !/^18 more call sites were NOT checked/.test(shapeSummary[1] || '')
    || /every argument name was checked/i.test(shapeSummary.join('\n'))) {
    failed.push(`with the wrapper passed on, the summary must count 3 checked and name 18 not checked, got ${JSON.stringify(shapeSummary)}`);
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

  for (const line of summaryLines(sites, cmds, registered)) console.log(line);
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
module.exports = { INJECTED, parseCommandsIn, parseRegisteredCommands, parseCallSitesIn, readObjectKeys, variablePayloadKeys, rebinding, findProblems, summaryLines };

if (require.main === module) main();
