#!/usr/bin/env node
/*
 * check-mcp-contract.js - static checks of the renderer's MCP contract that
 * check-ipc-args.js cannot make. Runs in plain Node, no browser required:
 *
 *     node scripts/check-mcp-contract.js
 *
 * Which keys mcp.js sends to which command is enforced by scripts/check-ipc-args.js
 * against the Rust signatures: a misspelled or camelCase-twin key, and a REQUIRED
 * (non-Option) argument that is not sent (auth_type; mcp_call_tool's tabId, id, tool,
 * argumentsJson and approved). This file used to check those a second time, and
 * check-renderer-ui.js a third (A8-17); the copies drifted, so only that one is kept.
 * What it cannot enforce is a key whose Rust type is Option<T>, because absent is a
 * legal call - and for mcp_save_server's three auth fields absent is a SILENT one, so
 * those presence checks stay here. The payload is read with check-ipc-args.js's own
 * parser (it exports it), not a second copy.
 *
 * Checks:
 *   1. mcp_save_server's payload can be read statically and ALWAYS carries
 *      auth_header_name, auth_secret and auth_env_var (null keeps the stored value, a
 *      value replaces it; a payload that stops carrying one leaves the old secret in use
 *      while the UI says "saved"). mcp_call_tool's call site is found and readable.
 *   2. The custom auth form value is exactly 'custom_header'.
 *   3. Tool schema validation exists and rejects missing/invalid schemas.
 *   4. mcpCallTool is exposed, and aiRunTool wraps MCP results as untrusted.
 *   5. Built-in tools come before MCP tools in the model's tool list.
 *   6. tool_view (Rust) emits the `inputSchema` key mcp.js reads - if it stopped,
 *      every MCP tool would reach the model without a parameter schema.
 *
 * Exit 0 if all checks pass, 1 otherwise.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const { parseCallSitesIn } = require('./check-ipc-args.js');

const ROOT = path.join(__dirname, '..');
const mcpPath = path.join(ROOT, 'src', 'renderer', 'mcp.js');
const htmlPath = path.join(ROOT, 'src', 'renderer', 'index.html');
const rustPath = path.join(ROOT, 'src-tauri', 'src', 'assistant', 'mcp.rs');
const code = fs.readFileSync(mcpPath, 'utf8');

let failures = 0;
function ok(name) { console.log('  ok  ' + name); }
function fail(name, got, want) {
  failures++;
  console.log('  FAIL ' + name);
  console.log('       got:  ' + got);
  console.log('       want: ' + want);
}

console.log('mcp.js contract checks (argument names and required arguments: scripts/check-ipc-args.js)');

// 1. The payloads mcp.js sends. In Rust auth_header_name, auth_secret and auth_env_var
// are Option<String>, so check-ipc-args.js treats them as optional - but "null keeps
// the stored value, a value replaces it" only works if the key is always sent.
const MUST_SEND = ['auth_header_name', 'auth_secret', 'auth_env_var'];
const sites = parseCallSitesIn(code, 'src/renderer/mcp.js');

const saveSites = sites.filter((s) => s.cmd === 'mcp_save_server');
if (saveSites.length !== 1) {
  fail('mcp_save_server payload found', saveSites.length + " mcpCall('mcp_save_server', ...) sites", 'exactly one');
} else if (saveSites[0].dynamic) {
  fail('mcp_save_server payload can be read statically', 'a spread, a parameter or a variable that is rebound before the call',
    "a plain `const payload = { ... }` literal in the same function (or update this check and check-ipc-args.js's parser together)");
} else {
  ok('mcp_save_server payload found and readable (mcp.js:' + saveSites[0].line + ')');
  for (const key of MUST_SEND) {
    if (!saveSites[0].keys.includes(key)) {
      fail(key + ' key present in the mcp_save_server payload', 'missing from {' + saveSites[0].keys.join(', ') + '}',
        key + ': - without it an edit leaves the stored value in use (null keeps it, a value replaces it)');
    } else {
      ok(key + ' key present in the mcp_save_server payload');
    }
  }
}

const callSites = sites.filter((s) => s.cmd === 'mcp_call_tool');
if (callSites.length !== 1 || callSites[0].dynamic) {
  fail('mcp_call_tool payload found and readable', callSites.length + ' sites' + (callSites.length === 1 ? ', not an object literal' : ''),
    "exactly one mcpCall('mcp_call_tool', { ... }) literal (its keys are checked by check-ipc-args.js)");
} else {
  ok('mcp_call_tool payload found and readable (mcp.js:' + callSites[0].line + ')');
}

// 2. The form option value for custom header auth is 'custom_header'.
const html = fs.readFileSync(htmlPath, 'utf8');
if (!/<option value="custom_header">Custom header<\/option>/.test(html)) {
  fail('HTML option value for custom header auth', 'not "custom_header"', '<option value="custom_header">Custom header</option>');
} else {
  ok('HTML option value for custom header auth is custom_header');
}

// 3. The renderer validates tool schemas and fails on missing/invalid input.
if (!/function mcpValidateToolSchema/.test(code)) {
  fail('mcpValidateToolSchema function exists', 'missing', 'function mcpValidateToolSchema');
} else {
  ok('mcpValidateToolSchema function exists');
}
if (!/t\.inputSchema/.test(code) || !/parameters_json/.test(code)) {
  fail('tool schema reads backend inputSchema and emits provider parameters_json', 'missing', 'inputSchema -> parameters_json');
} else {
  ok('tool schema reads backend inputSchema and emits provider parameters_json');
}
if (!/mcpValidateToolSchema\(t, sv\.name, t\.name\)/.test(code)) {
  fail('mcpGetTools validates each tool schema', 'missing', 'mcpValidateToolSchema(t, sv.name, t.name)');
} else {
  ok('mcpGetTools validates each tool schema');
}
if (!/has no inputSchema/.test(code)) {
  fail('missing schema produces visible error', 'missing', 'error message with "has no inputSchema"');
} else {
  ok('missing schema produces visible error');
}
if (!/invalid inputSchema/.test(code)) {
  fail('invalid schema produces visible error', 'missing', 'error message with "invalid inputSchema"');
} else {
  ok('invalid schema produces visible error');
}

// 4. mcpCallTool is called by assistant.js and its result is wrapped through
// aiWrapUntrusted (the runtime contract is enforced in assistant.js, but the
// helper is invoked there, not in mcp.js).
if (!/window\.mcpCallTool/.test(code)) {
  fail('mcpCallTool is exposed on window', 'missing', 'window.mcpCallTool');
} else {
  ok('mcpCallTool exposed on window');
}

// aiRunTool still wraps MCP results through aiWrapUntrusted.
const assistantCode = fs.readFileSync(path.join(ROOT, 'src', 'renderer', 'assistant.js'), 'utf8');
const mcpBranch = assistantCode.match(/if \(name\.lastIndexOf\('mcp__'[\s\S]*?return wrap\(text\);/);
if (!mcpBranch) {
  fail('MCP branch in aiRunTool found', 'not found', 'mcp__ branch wrapping result');
} else {
  ok('MCP branch in aiRunTool found');
  if (!/return wrap\(text\);/.test(mcpBranch[0])) {
    fail('MCP result is wrapped before returning', 'not wrapping', 'return wrap(text);');
  } else {
    ok('MCP result is wrapped before returning');
  }
}

// 5. Built-ins-first order is preserved in assistant.js.
if (!/window\.mcpGetTools\(\)\.slice\(0, remaining\)/.test(assistantCode)) {
  fail('built-ins-first merge in aiToolsForLevel', 'missing', 'window.mcpGetTools().slice(0, remaining)');
} else {
  ok('built-ins-first merge preserved in aiToolsForLevel');
}

// 6. Schema forwarding: the MCP wire field is `inputSchema` (camelCase), which
// renderer validation serializes to the provider-facing `parameters_json`.
// tool_view must emit the key the renderer reads.
const rust = fs.readFileSync(rustPath, 'utf8');
const view = rust.match(/fn tool_view\([\s\S]*?json!\(\{([\s\S]*?)\n    \}\)/m);
const viewKeys = view ? new Set([...view[1].matchAll(/"(\w+)":/g)].map((x) => x[1])) : null;
if (!viewKeys) {
  fail('tool_view() shape is parseable', 'unparseable', 'json!({ ... }) in fn tool_view of src-tauri/src/assistant/mcp.rs - update this check with it');
} else if (/\bt\.inputSchema\b/.test(code) && !viewKeys.has('inputSchema')) {
  fail('tool_view emits the inputSchema that mcp.js reads', '{' + [...viewKeys].join(', ') + '}', 'a "inputSchema" key');
} else {
  ok('tool_view emits the inputSchema that mcp.js reads');
}

if (failures) {
  console.log(`\n${failures} MCP contract check(s) failed.`);
  process.exit(1);
}
console.log('\nAll MCP contract checks passed.');
