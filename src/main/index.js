/**
 * index.js — SSHSpan main process entry point.
 * ---------------------------------------------------------------------------
 * Electron main process. Loads the app service, registers IPC handlers, and
 * creates the browser window. Runs with nodeIntegration off and contextIsolation
 * on so the renderer can only talk to main via the exposed API.
 * ---------------------------------------------------------------------------
 */

'use strict';

const { app, BrowserWindow, ipcMain, dialog, Menu, Tray, nativeImage, clipboard, shell } = require('electron');
const path = require('path');
const SshSpan = require('./services/sshspan');
const { register } = require('./services/ipcHandlers');

let mainWindow = null;
let tray = null;
let sshspan = null;

function createWindow() {
  // src/main -> src -> project root (works unpacked and inside asar)
  const icon = nativeImage.createFromPath(path.join(__dirname, '..', '..', 'assets', 'icon.png'));
  mainWindow = new BrowserWindow({
    width: 1100,
    height: 720,
    minWidth: 880,
    minHeight: 560,
    title: 'SSHSpan',
    backgroundColor: '#0f1115',
    show: false,
    icon,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,
      webSecurity: true
    }
  });

  mainWindow.loadFile(path.join(__dirname, '..', 'renderer', 'index.html'));

  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
    if (app.isPackaged) { /* no devtools in prod */ }
  });

  mainWindow.on('close', (e) => {
    if (process.platform === 'darwin') return;
    e.preventDefault();
    mainWindow.hide();
    if (tray) tray.destroy();
    tray = createTray();
  });

  return mainWindow;
}

function createTray() {
  const icon = nativeImage.createFromPath(path.join(__dirname, '..', '..', 'assets', 'icon.png')).resize({ width: 16, height: 16 });
  tray = new Tray(icon);
  const menu = Menu.buildFromTemplate([
    { label: 'Open SSHSpan', click: () => { if (mainWindow) mainWindow.show(); } },
    { label: 'Lock Vault', click: () => { if (sshspan) sshspan.lock(); } },
    { type: 'separator' },
    { label: 'Quit', click: () => { app.quit(); } }
  ]);
  tray.setContextMenu(menu);
  tray.setToolTip('SSHSpan');
  return tray;
}

async function bootstrap() {
  sshspan = new SshSpan();
  await sshspan.init();
  register(ipcMain, sshspan);
  createWindow();
}

app.whenReady().then(() => {
  bootstrap().catch(e => {
    console.error('Bootstrap failed:', e);
    dialog.showMessageBoxSync(null, { type: 'error', title: 'SSHSpan', message: 'Failed to start: ' + e.message });
    app.quit();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

app.on('activate', () => {
  if (!mainWindow) createWindow();
  else mainWindow.show();
});

app.on('quit', () => {
  if (sshspan) sshspan.close();
});

// Keep the app running in tray on Windows/Linux.
app.on('blur', () => {
  // no-op
});

// Prevent multiple instances
const gotLock = app.requestSingleInstanceLock();
if (!gotLock) {
  app.quit();
} else {
  app.on('second-instance', () => {
    if (mainWindow) {
      if (mainWindow.isMinimized()) mainWindow.restore();
      mainWindow.show();
      mainWindow.focus();
    }
  });
}
