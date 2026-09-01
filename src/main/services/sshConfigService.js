/**
 * sshConfigService.js
 * ---------------------------------------------------------------------------
 * Generate and maintain ~/.ssh/config Host blocks from SSHSpan keys.
 * Never writes into ~/.ssh/config without explicit user consent.
 * Uses a marker comment so entries can be safely removed later.
 * ---------------------------------------------------------------------------
 */

'use strict';

const path = require('path');
const os = require('os');
const fs = require('fs');

const MARKER = '# >>> SSHSpan managed >>>';
const MARKER_END = '# <<< SSHSpan managed <<<';

function defaultSshConfigPath() {
  return path.join(os.homedir(), '.ssh', 'config');
}

function readExisting(path) {
  try {
    return fs.readFileSync(path, 'utf8');
  } catch (e) {
    return '';
  }
}

function stripManaged(content) {
  const lines = content.split(/\r?\n/);
  const out = [];
  let skipping = false;
  for (const line of lines) {
    if (line.trim() === MARKER) { skipping = true; continue; }
    if (line.trim() === MARKER_END) { skipping = false; continue; }
    if (!skipping) out.push(line);
  }
  return out.join('\n').replace(/\n{3,}/g, '\n\n').trim() + '\n';
}

function buildBlock(key, options = {}) {
  const host = options.host || key.name || key.id;
  const identityFile = (typeof options.identityFileFor === 'function' && options.identityFileFor(key))
    || options.identityFile
    || '~/.sshspan/keys/' + key.id;
  const user = options.user ? '    User ' + options.user + '\n' : '';
  const port = options.port ? '    Port ' + options.port + '\n' : '';
  const strictHostKey = options.strictHostKey === false ? '    StrictHostKeyChecking no\n' : '';
  const lines = [
    MARKER,
    'Host ' + host,
    '    HostName ' + (options.hostName || host),
    '    IdentityFile ' + identityFile,
    user,
    port,
    '    IdentitiesOnly yes',
    strictHostKey,
    MARKER_END
  ].filter(Boolean);
  return lines.join('\n') + '\n';
}

function renderFullConfig(keys, options = {}) {
  const existing = readExisting(options.path || defaultSshConfigPath());
  const base = stripManaged(existing);
  const blocks = keys.map(k => buildBlock(k, options)).join('\n');
  const tail = base.endsWith('\n') ? base : base + '\n';
  return tail + '\n' + blocks;
}

function writeConfig(keys, opts = {}) {
  const target = opts.path || defaultSshConfigPath();
  const dir = path.dirname(target);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  const content = renderFullConfig(keys, opts);
  fs.writeFileSync(target, content, 'utf8');
  return { path: target, bytes: Buffer.byteLength(content) };
}

module.exports = {
  MARKER,
  MARKER_END,
  defaultSshConfigPath,
  readExisting,
  stripManaged,
  buildBlock,
  renderFullConfig,
  writeConfig
};
