/**
 * preload.js — secure context bridge.
 * Exposes a minimal, typed API to the renderer. No Node APIs leak through.
 * All private key material stays in the main process.
 */

'use strict';

const { contextBridge, ipcRenderer } = require('electron');

const api = {
  // vault
  vaultStatus: () => ipcRenderer.invoke('vault:status'),
  vaultCreate: (password) => ipcRenderer.invoke('vault:create', { password }),
  vaultUnlock: (password) => ipcRenderer.invoke('vault:unlock', { password }),
  vaultLock: () => ipcRenderer.invoke('vault:lock'),
  vaultChangePassword: (password) => ipcRenderer.invoke('vault:change-password', { password }),

  // keys
  keysList: () => ipcRenderer.invoke('keys:list'),
  keysGet: (id) => ipcRenderer.invoke('keys:get', { id }),
  keysCreate: (payload) => ipcRenderer.invoke('keys:create', payload),
  keysImport: (pem, opts) => ipcRenderer.invoke('keys:import', { pem, ...opts }),
  keysUpdate: (id, patch) => ipcRenderer.invoke('keys:update', { id, patch }),
  keysDelete: (id) => ipcRenderer.invoke('keys:delete', { id }),
  keysExport: (id, format, opts) => ipcRenderer.invoke('keys:export', { id, format, ...opts }),
  keysCopyPublic: (id) => ipcRenderer.invoke('keys:copy-public', { id }),
  keysDeploy: (ids, opts) => ipcRenderer.invoke('keys:deploy', { ids, ...opts }),
  keysRenderConfig: (ids, opts) => ipcRenderer.invoke('keys:render-config', { ids, ...opts }),

  // settings
  settingsGet: () => ipcRenderer.invoke('settings:get'),
  settingsSet: (key, value) => ipcRenderer.invoke('settings:set', { key, value }),

  // bitwarden sync
  syncGetConfig: () => ipcRenderer.invoke('sync:get-config'),
  syncSaveConfig: (patch) => ipcRenderer.invoke('sync:save-config', patch),
  syncTest: () => ipcRenderer.invoke('sync:test'),
  syncNow: (opts) => ipcRenderer.invoke('sync:now', opts),

  // audit
  auditList: (limit) => ipcRenderer.invoke('audit:list', { limit }),

  // clipboard
  clipboardWritePublic: (id) => ipcRenderer.invoke('clipboard:write-public', { id })
};

contextBridge.exposeInMainWorld('sshspan', api);
