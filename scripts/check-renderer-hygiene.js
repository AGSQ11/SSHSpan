#!/usr/bin/env node
/**
 * check-renderer-hygiene.js - static checks that the renderer's comments stay
 * readable for someone who never saw the remediation's working notes, and
 * that dead exports stay gone. Plain Node, no browser:
 *
 *     node scripts/check-renderer-hygiene.js
 *
 * 1. No comment cites an internal work-package or review-round name - "JU3",
 *    "RU6b", "fix round 1", "fix2 N1", "I1", "M7", "item 7" and the like.
 *    Nobody reading the code can look those up. A comment gives the audit ID
 *    (docs/audit/2026-10-09: A4-24, A6-12, ...) or the plain reason. Not
 *    labels: audit IDs, the plan's rulings R1-R12, C0/C1 (control sets).
 * 2. Exports nothing calls stay deleted (an unused window.* function is an
 *    entry point a later change could wire up without anyone reviewing it),
 *    and so do helpers the shared ones replaced.
 * 3. Comments that described code which has since changed stay corrected.
 * 4. No error is turned into text by hand in the shapes it knows
 *    (`e.message || String(e)`, `(r && r.error) || String(r)`, `e && e.message
 *    ? e.message : String(e)`, `'Failed: ' + e.message`): app.js's errText
 *    does it. Hand-made copies read `undefined.message` for a null rejection
 *    and "[object Object]" for an { error } object.
 *
 * Every renderer file is read: the scripts' comments, the comments of
 * index.html and styles.css. It checks itself first: the comment reader must
 * find every comment and no text inside a string, a template literal or a
 * regular expression, and the label rule must flag each kind of label and
 * pass audit IDs.
 *
 * Exit 0 when everything passes, 1 otherwise. check-ui-polish.js runs it
 * (test:polish), so CI does too.
 */
'use strict';

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');

/// The renderer scripts whose comments are checked.
const COMMENT_FILES = ['src/renderer/app.js', 'src/renderer/sftp.js', 'src/renderer/terminal.js', 'src/renderer/icons.js',
  'src/renderer/assistant.js', 'src/renderer/mcp.js'];
/// The page and its style sheet: their comments.
const MARKUP_FILES = ['src/renderer/index.html', 'src/renderer/styles.css'];

/// Keywords after which a `/` starts a regular expression, not a division.
const REGEX_AFTER_WORDS = new Set(['return', 'typeof', 'case', 'in', 'of', 'new', 'delete', 'void',
  'throw', 'else', 'do', 'yield', 'await', 'instanceof']);

/**
 * One pass over a JavaScript source: every comment as { line, text, start,
 * end } - `//` and block comments, never text inside a string, a template
 * literal (substitutions included, nested ones too) or a regular expression
 * literal - and, as { start, end }, the text of every string, template and
 * regular expression (their delimiters left out). A `/` is a regular
 * expression where an operand is expected - at the start, after an operator
 * or an opening bracket, after a keyword such as `return` - and a division
 * after a name, a number or a closing bracket.
 */
function jsScan(src) {
  const comments = [];
  const literals = [];
  const n = src.length;
  let i = 0;
  let line = 1;
  let last = '';     // the last significant character outside comments
  let word = '';     // the name or keyword that ended at `last`
  let depth = 0;     // { } nesting, to find where a template substitution ends
  const resume = []; // for each open `${`: the depth its closing `}` returns to
  const step = () => { if (src[i] === '\n') line++; i++; };
  // From inside a template's text: to its closing backtick (true), or into a
  // substitution (false).
  const templateText = () => {
    const from = i;
    while (i < n) {
      if (src[i] === '\\') { step(); step(); continue; }
      if (src[i] === '`') { literals.push({ start: from, end: i }); step(); return true; }
      if (src[i] === '$' && src[i + 1] === '{') { literals.push({ start: from, end: i }); step(); step(); resume.push(depth); depth++; return false; }
      step();
    }
    literals.push({ start: from, end: i });
    return true;
  };
  const regexLiteral = () => {
    step();
    const from = i;
    let inClass = false;
    let closed = false;
    while (i < n && src[i] !== '\n') {
      const ch = src[i];
      if (ch === '\\') { step(); step(); continue; }
      if (ch === '[') inClass = true;
      else if (ch === ']') inClass = false;
      else if (ch === '/' && !inClass) { literals.push({ start: from, end: i }); closed = true; step(); break; }
      step();
    }
    if (!closed) literals.push({ start: from, end: i });
    while (i < n && /[a-z]/i.test(src[i])) step();
  };
  while (i < n) {
    const c = src[i];
    const d = src[i + 1];
    if (c === '/' && d === '/') {
      let j = i + 2;
      while (j < n && src[j] !== '\n') j++;
      comments.push({ line, text: src.slice(i + 2, j), start: i, end: j });
      i = j;
      continue;
    }
    if (c === '/' && d === '*') {
      const end = src.indexOf('*/', i + 2);
      const stop = end < 0 ? n : end + 2;
      comments.push({ line, text: src.slice(i + 2, end < 0 ? n : end), start: i, end: stop });
      while (i < stop) step();
      continue;
    }
    if (c === "'" || c === '"') {
      step();
      const from = i;
      while (i < n && src[i] !== c && src[i] !== '\n') { if (src[i] === '\\') step(); step(); }
      literals.push({ start: from, end: i });
      step();
      last = c; word = '';
      continue;
    }
    if (c === '`' || (c === '}' && resume.length && resume[resume.length - 1] === depth - 1)) {
      if (c === '}') { resume.pop(); depth--; }
      step();
      const closed = templateText();
      last = closed ? '`' : '{'; word = '';
      continue;
    }
    if (c === '/' && !(/[\w$)\]]/.test(last) && !REGEX_AFTER_WORDS.has(word))) {
      regexLiteral();
      last = '/'; word = '';
      continue;
    }
    if (/\s/.test(c)) { step(); continue; }
    if (/[\w$]/.test(c)) {
      let j = i;
      while (j < n && /[\w$]/.test(src[j])) j++;
      word = src.slice(i, j);
      last = src[j - 1];
      i = j;
      continue;
    }
    if (c === '{') depth++;
    else if (c === '}') depth--;
    last = c; word = '';
    step();
  }
  return { comments, literals };
}

/// Every comment in a JavaScript source as { line, text, start, end }.
function jsComments(src) {
  return jsScan(src).comments;
}

/// `src` with every comment blanked (newlines kept): code only.
function jsCode(src) {
  let out = '';
  let at = 0;
  for (const c of jsComments(src)) {
    out += src.slice(at, c.start) + src.slice(c.start, c.end).replace(/[^\n]/g, ' ');
    at = c.end;
  }
  return out + src.slice(at);
}

/// `src` with every comment and the text of every string, template and
/// regular expression blanked - their delimiters and template substitutions
/// kept, newlines kept, every position unchanged: the code alone, for a scan
/// that must not take words in text or comments for code
/// (scripts/check-ipc-args.js reads its call sites in it).
function jsMask(src) {
  const out = src.split('');
  const { comments, literals } = jsScan(src);
  for (const { start, end } of [...comments, ...literals]) {
    for (let k = start; k < end; k++) if (out[k] !== '\n') out[k] = ' ';
  }
  return out.join('');
}

/// The comments of an HTML page (<!-- -->) or a style sheet (/* */).
function markupComments(src, kind) {
  const re = kind === 'html' ? /<!--([\s\S]*?)-->/g : /\/\*([\s\S]*?)\*\//g;
  return [...src.matchAll(re)].map((m) => ({ line: src.slice(0, m.index).split('\n').length, text: m[1] }));
}

/// What an internal label looks like. Audit IDs (A4-24), the plan's rulings
/// (R6) and the control sets C0/C1 never match.
const LABELS = [
  [/\b(?:JU|RU)\d+[a-z]?\b/, 'a work-package name'],
  [/\b(?:JW|RW)\b/, 'a work-package name'],
  [/\bfix(?:\s+round\b|\d+\b)/i, 'a fix round'],
  [/\bround \d+\b/i, 'a review round'],
  [/(?<![\w+#-])[BHILMNS]\d+(?:-[a-z])?\b/, 'a review finding (I1, M7, N1 ...)'],
  [/\bF\d+-[a-z]\b/, 'a review finding (F1-b)'],
  [/\bitem \d+\b/i, 'a brief item'],
  [/\bhand-?off \d+\b/i, 'a hand-off'],
  [/\breview [AB]\d*\b/, 'a review name'],
  // "agent-e" in any case; with a space only before a capital ("Agent E"), so
  // "forwarded to the agent a second time" is plain English.
  [/\b[Aa]gent-[A-Za-z]\b|\b[Aa]gent [A-Z]\b/, 'an agent name'],
];

function labelIn(text) {
  for (const [re, what] of LABELS) {
    const m = re.exec(text);
    if (m) return `${what} "${m[0]}"`;
  }
  return null;
}

/// Things that must not come back, per file.
const GONE = [
  ['src/renderer/terminal.js', /\bterminalSendText\b/, 'window.terminalSendText - nothing called it'],
  ['src/renderer/terminal.js', /\bsendTerminalBytes\b/, 'sendTerminalBytes - only the dead terminalSendText used it'],
  ['src/renderer/app.js', /\bappQuit\b/, 'window.appQuit - nothing called it (quitApp is the one quit)'],
  ['src/renderer/mcp.js', /text-prefix test/, 'the loopback comment\'s "text-prefix test": the backend decides loopback on the parsed address'],
  ['src/renderer/sftp.js', /resume\/\.part update lands/, 'the note that the backend overwrites instead of resuming: it resumes from the .part'],
  ['src/renderer/sftp.js', /until the two keys are added to the backend whitelist/, 'the note that the conflict defaults are not on the settings list: they are'],
  ['src/renderer/sftp.js', /A recursive run applies ONE mode to the/, 'the note that a recursive chmod gives every entry one mode: files get the plain bits'],
  ['src/renderer/sftp.js', /\bjoinLocal\b/, 'joinLocal - the one platform path join is joinPlatformPath (app.js)'],
  ['src/renderer/assistant.js', /\baiErrText\b/, 'aiErrText - errText (app.js) turns every error into text'],
  ['src/renderer/mcp.js', /\bmcpErrText\b/, 'mcpErrText - errText (app.js) turns every error into text'],
];

/// Code (comments left out) that must not appear in a renderer script, per line:
/// an error turned into text by hand. `x.message || String(x)`, `(r &&
/// r.error) || String(r)` and their forms; the ternary `e && e.message ?
/// e.message : String(e)`; and a sentence built with a bare `e.message`
/// (`'Failed: ' + e.message`, `${err.message}`) - the names a caught error
/// goes by here (e, err, error, ex, reason), so an event's own .message is
/// not one.
const CODE_RULES = [
  [/\.(?:message|error)\)*\s*\|\|\s*String\(|\.message\s*\|\|\s*[A-Za-z_$][\w$]*\.error\b|\.message\)?\s*\|\|\s*[A-Za-z_$][\w$]*\s*[)}]/,
    'an error turned into text by hand - use errText(e) (app.js)'],
  [/\.message\s*\?\s*[A-Za-z_$][\w$.]*\.message\s*:/,
    'an error turned into text by hand (e.message ? e.message : ...) - use errText(e) (app.js)'],
  [/(?:['"`]\s*\+\s*\(?\s*|\$\{\s*)\b(?:e|err|error|ex|reason)\.message\b|\b(?:e|err|error|ex|reason)\.message\s*\+\s*['"`]/,
    'an error message built into a sentence by hand - use errText(e) (app.js)'],
];

function selfCheck() {
  const failed = [];
  const probe = [
    "const a = 'JU3 in a string'; // RU6b in a comment",
    "const re = /^https?:\\/\\//; const q = /'JU4/g; // after two regular expressions",
    'const t = `fix round 1 ${x /* M7 */} text ${`nested ${y}`} end`;',
    '/* a block',
    '   with N1 */',
    'const d = total / 2; // the audit ID A4-24, the ruling R6, C0 and C1',
    'const u = "http://example.com"; return /a\\/b/.test(u) ? 1 : 2 / 3;',
    'if (ok) { /* item 7 */ }',
  ].join('\n');
  const got = jsComments(probe).map((c) => c.line + ':' + c.text.trim().replace(/\s+/g, ' '));
  const want = ['1:RU6b in a comment', '2:after two regular expressions', '3:M7', '4:a block with N1',
    '6:the audit ID A4-24, the ruling R6, C0 and C1', '8:item 7'];
  if (JSON.stringify(got) !== JSON.stringify(want)) failed.push(`comments read as ${JSON.stringify(got)}, want ${JSON.stringify(want)}`);
  const flagged = jsComments(probe).map((c) => labelIn(c.text) !== null);
  if (JSON.stringify(flagged) !== JSON.stringify([true, false, true, true, false, true])) {
    failed.push(`labels flagged as ${JSON.stringify(flagged)}, want [true, false, true, true, false, true]`);
  }
  for (const label of ['JU3', 'RU6b', 'RW', 'fix round 2', 'fix2', 'round 3', 'I1', 'M7', 'N1', 'H1', 'L8', 'S2', 'B1', 'F1-b', 'item 7', 'hand-off 10', 'review B',
    'Agent E', 'agent-e', "Agent E's comparison"]) {
    if (!labelIn('see ' + label + ' here')) failed.push(`the label ${label} must be flagged`);
  }
  for (const fine of ['A4-24', 'A2-11 / A5-20', 'R6', 'R12', 'C0 and C1', 'Shift+F10', 'F2', 'IPv4', 'x86_64', 'SHA256', 'UTF-8', 'an item', '#B1C2D3',
    'the agent loop', 'agent-loop bridge', 'the agent/tool loop', 'jump hosts or agent forwarding', 'ssh-agent',
    'forwarded to the agent a second time']) {
    if (labelIn('see ' + fine + ' here')) failed.push(`"${fine}" is not a label, got ${labelIn('see ' + fine + ' here')}`);
  }
  const code = jsCode('a(); // x JU3\nconst s = "// kept"; /* y */ b();');
  if (code !== 'a();         \nconst s = "// kept";         b();') failed.push(`code without comments read as ${JSON.stringify(code)}`);
  const html = markupComments('<p>JU1</p>\n<!-- a JU3 note -->\n<b>x</b>', 'html').map((c) => c.line + ':' + c.text.trim());
  if (JSON.stringify(html) !== JSON.stringify(['2:a JU3 note'])) failed.push(`HTML comments read as ${JSON.stringify(html)}`);
  const css = markupComments('a { color: red; } /* fix round 1 */\nb {}', 'css').map((c) => c.line + ':' + c.text.trim());
  if (JSON.stringify(css) !== JSON.stringify(['1:fix round 1'])) failed.push(`CSS comments read as ${JSON.stringify(css)}`);
  const ruleHits = (line) => CODE_RULES.some(([re]) => re.test(line));
  for (const bad of ['toast(e.message || String(e))', 'x = (e && e.message) || String(e);', 'x = (err && (err.message || err.error)) || String(err);',
    "toast('failed: ' + (e.message || e), 'err');", 'x = `${e.message || e}`;', 'x = `${(e && e.message) || e}`;',
    // The ternary, string building with a bare message, the { error } object.
    'const msg = e && e.message ? e.message : String(e);', "push('unhandled rejection: ' + (r && r.message ? r.message : String(r)));",
    'const said = e.message ? e.message : e.error;', "toast('UI init failed: ' + e.message, 'err');", 'x = `failed: ${err.message}`;',
    "x = error.message + ' - try again';", 'x = (r && r.error) || String(r);', 'x = r.error || String(r);']) {
    if (!ruleHits(bad)) failed.push(`a hand-made error text must be caught: ${bad}`);
  }
  for (const fine of ['toast(errText(e), \'err\');', 'const m = e.message;', "const msg = 'JS error: ' + (ev.message || 'unknown');",
    'for (const said of [e.message, e.error]) {', "if (typeof said === 'string' && said.trim()) return said;",
    "window.__bootErrors.push('wire() threw: ' + (e.stack || errText(e)));", 'if (r && r.error) warnings.push(errText(r.error));']) {
    if (ruleHits(fine)) failed.push(`not a hand-made error text: ${fine}`);
  }
  return failed;
}

function main() {
  const selfFailures = selfCheck();
  if (selfFailures.length) {
    console.error('check-renderer-hygiene.js failed its own self-check:\n');
    for (const f of selfFailures) console.error('  ' + f);
    process.exit(1);
  }
  const problems = [];
  let comments = 0;
  const labelled = (rel, list) => {
    for (const c of list) {
      comments++;
      const label = labelIn(c.text);
      if (label) problems.push(`${rel}:${c.line}  a comment cites ${label} - give the audit ID or the plain reason`);
    }
  };
  for (const rel of COMMENT_FILES) {
    const src = fs.readFileSync(path.join(ROOT, rel), 'utf8');
    labelled(rel, jsComments(src));
    const lines = jsCode(src).split('\n');
    for (const [re, what] of CODE_RULES) {
      lines.forEach((line, i) => { if (re.test(line)) problems.push(`${rel}:${i + 1}  ${what}`); });
    }
  }
  for (const rel of MARKUP_FILES) {
    labelled(rel, markupComments(fs.readFileSync(path.join(ROOT, rel), 'utf8'), rel.endsWith('.html') ? 'html' : 'css'));
  }
  for (const [rel, re, what] of GONE) {
    const src = fs.readFileSync(path.join(ROOT, rel), 'utf8');
    const m = re.exec(src);
    if (m) problems.push(`${rel}:${src.slice(0, m.index).split('\n').length}  is back: ${what}`);
  }
  console.log(`Read ${comments} comments in ${COMMENT_FILES.length + MARKUP_FILES.length} renderer files; ${GONE.length} removals and ${CODE_RULES.length} code rule${CODE_RULES.length === 1 ? '' : 's'} checked.`);
  if (problems.length) {
    console.error(`\n${problems.length} problem(s):\n`);
    for (const p of problems) console.error('  ' + p);
    process.exit(1);
  }
  console.log('No internal labels in comments, nothing removed has come back, and no error turned into text by hand in the shapes checked.');
}

module.exports = { jsComments, jsCode, jsMask, markupComments, labelIn };

if (require.main === module) main();
