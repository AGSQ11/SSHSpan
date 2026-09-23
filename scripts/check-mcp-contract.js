#!/usr/bin/env node
/*
 * check-mcp-contract.js - static + runtime-ish checks for the renderer's
 * MCP contract. Runs in plain Node, no browser required.
 *
 * Checks:
 *   1. mcp.js sends camelCase top-level keys to mcp_save_server.
 *   2. The custom auth form value is exactly 'custom_header'.
 *   3. Tool schemas validation exists and rejects missing/invalid schemas.
 *   4. mcp_call_tool payload keys are camelCase (tabId, argumentsJson, approved).
 *
 * Exit 0 if all checks pass, 1 otherwise.
 */
'use strict';

const fs = require('fs');
const path = require('path');

const mcpPath = path.join(__dirname, '..', 'src', 'renderer', 'mcp.js');
const htmlPath = path.join(__dirname, '..', 'src', 'renderer', 'index.html');
const code = fs.readFileSync(mcpPath, 'utf8');

let failures = 0;
function ok(name) { console.log('  ok  ' + name); }
function fail(name, got, want) {
  failures++;
  console.log('  FAIL ' + name);
  console.log('       got:  ' + got);
  console.log('       want: ' + want);
}

console.log('mcp.js contract checks');

// 1. mcp_save_server payload uses camelCase keys matching Rust command args.
const payloadMatch = code.match(/const payload = \{[\s\S]*?authEnvVar[\s\S]*?\};/);
if (!payloadMatch) {
  fail('mcp_save_server payload found', 'not found', 'payload object');
} else {
  const payload = payloadMatch[0];
  if (!/authType:/.test(payload)) fail('authType key present', 'missing', 'authType:');
  else ok('authType key present');
  if (!/authHeaderName:/.test(payload)) fail('authHeaderName key present', 'missing', 'authHeaderName:');
  else ok('authHeaderName key present');
  if (!/authSecret:/.test(payload)) fail('authSecret key present', 'missing', 'authSecret:');
  else ok('authSecret key present');
  if (!/authEnvVar:/.test(payload)) fail('authEnvVar key present', 'missing', 'authEnvVar:');
  else ok('authEnvVar key present');
  // Ensure no snake_case top-level keys remain in the payload block.
  if (/auth_type:/.test(payload)) fail('no snake_case auth_type in save payload', 'found', 'none');
  else ok('no snake_case auth_type in save payload');
  if (/auth_header_name:/.test(payload)) fail('no snake_case auth_header_name in save payload', 'found', 'none');
  else ok('no snake_case auth_header_name in save payload');
  if (/auth_secret:/.test(payload)) fail('no snake_case auth_secret in save payload', 'found', 'none');
  else ok('no snake_case auth_secret in save payload');
  if (/auth_env_var:/.test(payload)) fail('no snake_case auth_env_var in save payload', 'found', 'none');
  else ok('no snake_case auth_env_var in save payload');
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

// 4. mcp_call_tool payload uses camelCase keys.
const callMatch = code.match(/mcpCall\('mcp_call_tool',\s*\{\s*tabId,[\s\S]*?\}\s*\);/m);
if (!callMatch) {
  fail('mcp_call_tool payload found', 'not found', 'payload object');
} else {
  const callPayload = callMatch[0];
  if (!/argumentsJson:/.test(callPayload)) fail('argumentsJson key present', 'missing', 'argumentsJson:');
  else ok('argumentsJson key present in mcp_call_tool');
  if (!/tabId/.test(callPayload)) fail('tabId key present', 'missing', 'tabId');
  else ok('tabId key present in mcp_call_tool');
  if (!/approved:/.test(callPayload)) fail('approved key present', 'missing', 'approved:');
  else ok('approved key present in mcp_call_tool');
  if (/arguments_json:/.test(callPayload)) fail('no snake_case arguments_json in call payload', 'found', 'none');
  else ok('no snake_case arguments_json in call payload');
}

// 5. mcpCallTool is called by assistant.js and its result is wrapped through
// aiWrapUntrusted (the runtime contract is enforced in assistant.js, but the
// helper is invoked there, not in mcp.js).
if (!/window\.mcpCallTool/.test(code)) {
  fail('mcpCallTool is exposed on window', 'missing', 'window.mcpCallTool');
} else {
  ok('mcpCallTool exposed on window');
}

// 6. aiRunTool still wraps MCP results through aiWrapUntrusted.
const assistantCode = fs.readFileSync(path.join(__dirname, '..', 'src', 'renderer', 'assistant.js'), 'utf8');
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

// 7. Built-ins-first order is preserved in assistant.js.
if (!/window\.mcpGetTools\(\)\.slice\(0, remaining\)/.test(assistantCode)) {
  fail('built-ins-first merge in aiToolsForLevel', 'missing', 'window.mcpGetTools().slice(0, remaining)');
} else {
  ok('built-ins-first merge preserved in aiToolsForLevel');
}

if (failures) {
  console.log(`\n${failures} MCP contract check(s) failed.`);
  process.exit(1);
}
console.log('\nAll MCP contract checks passed.');
