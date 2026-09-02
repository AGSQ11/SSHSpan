/**
 * ipcHandlers.js
 * ---------------------------------------------------------------------------
 * All Electron IPC handlers. Each handler is a pure function receiving
 * (event, payload) and returning a serializable result or throwing.
 * No renderer code runs here; everything goes through the context bridge.
 * ---------------------------------------------------------------------------
 */

'use strict';

let app = null;

function bind(ss) { app = ss; }

// ---- vault ----
async function vaultStatus() {
  return { hasVault: app.hasVault(), unlocked: app.session.isUnlocked() };
}
async function vaultCreate(payload) {
  app.createVault(payload.password);
  return { ok: true };
}
async function vaultUnlock(payload) {
  app.unlock(payload.password);
  return { ok: true };
}
async function vaultLock() {
  app.lock();
  return { ok: true };
}
async function vaultChangePassword(payload) {
  // Full rekey flow: re-encrypt every stored private key with the new
  // password BEFORE the master verification hash is replaced.
  app.changePassword(app.session.getPassword(), payload.password);
  return { ok: true };
}

// ---- keys ----
async function keysList() {
  return app.listKeys();
}
async function keysGet(payload) {
  const k = app.getKey(payload.id);
  if (!k) throw new Error('Key not found');
  // app.getKey already strips private material; flag whether a private half exists.
  return { ...k, hasPrivate: !k.publicOnly };
}
async function keysCreate(payload) {
  const k = app.createKey(payload);
  return { id: k.id };
}
async function keysImport(payload) {
  const k = await app.importKeyAsync(payload.pem, payload);
  return { id: k.id };
}
async function keysUpdate(payload) {
  return app.updateKey(payload.id, payload.patch);
}
async function keysDelete(payload) {
  const ok = app.deleteKey(payload.id);
  return { ok };
}
async function keysExport(payload) {
  const data = app.exportKey(payload.id, payload.format, payload);
  return { data };
}
async function keysCopyPublic(payload) {
  const k = app.getKey(payload.id);
  if (!k) throw new Error('Key not found');
  const { clipboard } = require('electron');
  clipboard.writeText(k.publicAuthorizedKey);
  return { ok: true };
}
async function keysDeploy(payload) {
  return app.deployKeys(payload.ids, payload);
}
async function keysRenderConfig(payload) {
  return app.renderConfig(payload.ids, payload);
}

// ---- settings ----
async function settingsGet() {
  return app.getSettings();
}
async function settingsSet(payload) {
  app.setSetting(payload.key, payload.value);
  return { ok: true };
}

// ---- bitwarden sync ----
async function syncGetConfig() {
  return app.syncGetConfig();
}
async function syncSaveConfig(payload) {
  return app.syncSaveConfig(payload || {});
}
async function syncTest() {
  return app.syncTest();
}
async function syncNow(payload) {
  return app.syncNow(payload || {});
}

// ---- audit ----
async function auditList(payload) {
  return app.listAudit(payload && payload.limit);
}

// ---- file dialogs (main process reads/writes; renderer never touches fs) ----
async function dialogReadTextFile(payload = {}) {
  return app.readTextFileFromDialog(payload);
}
async function dialogSaveText(payload = {}) {
  return app.saveTextFileViaDialog(payload);
}

// ---- clipboard (public key only) ----
async function clipboardWritePublic(payload) {
  const k = app.getKey(payload.id);
  if (!k) throw new Error('Key not found');
  const { clipboard } = require('electron');
  clipboard.writeText(k.publicAuthorizedKey);
  return { ok: true };
}

const handlers = {
  'vault:status': vaultStatus,
  'vault:create': vaultCreate,
  'vault:unlock': vaultUnlock,
  'vault:lock': vaultLock,
  'vault:change-password': vaultChangePassword,
  'keys:list': keysList,
  'keys:get': keysGet,
  'keys:create': keysCreate,
  'keys:import': keysImport,
  'keys:update': keysUpdate,
  'keys:delete': keysDelete,
  'keys:export': keysExport,
  'keys:copy-public': keysCopyPublic,
  'keys:deploy': keysDeploy,
  'keys:render-config': keysRenderConfig,
  'settings:get': settingsGet,
  'settings:set': settingsSet,
  'sync:get-config': syncGetConfig,
  'sync:save-config': syncSaveConfig,
  'sync:test': syncTest,
  'sync:now': syncNow,
  'dialog:read-text-file': dialogReadTextFile,
  'dialog:save-text': dialogSaveText,
  'audit:list': auditList,
  'clipboard:write-public': clipboardWritePublic
};

function register(ipcMain, ss) {
  bind(ss);
  for (const [channel, fn] of Object.entries(handlers)) {
    ipcMain.handle(channel, async (event, payload) => {
      try {
        const result = await fn(payload);
        return { ok: true, data: result };
      } catch (e) {
        return { ok: false, error: e.message || String(e) };
      }
    });
  }
}

module.exports = { register, handlers };
