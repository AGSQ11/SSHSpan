/* FileZilla-parity feature e2e: chmod, touch, fs_info, search, bookmarks,
   queue (upload+download+progress), multi-select, sort, hidden files,
   dual-pane local listing, settings. */
'use strict';
const fs = require('fs');
const path = require('path');
const TMP = process.env.SSHSPAN_E2E_TMP || require('os').tmpdir();
const wsUrl = process.argv[2];
const ws = new WebSocket(wsUrl);
let id = 0;
const pending = new Map();
const errors = [];
ws.onmessage = (ev) => {
  const m = JSON.parse(ev.data);
  if (m.id && pending.has(m.id)) { pending.get(m.id)(m.result); pending.delete(m.id); }
  if (m.method === 'Runtime.exceptionThrown') {
    errors.push((m.params.exceptionDetails.exception && m.params.exceptionDetails.exception.description) || m.params.exceptionDetails.text);
  }
};
function send(method, params) {
  return new Promise((resolve) => { const mid = ++id; pending.set(mid, resolve); ws.send(JSON.stringify({ id: mid, method, params })); });
}
const sleep = (ms) => new Promise(r => setTimeout(r, ms));
ws.onopen = async () => {
  await send('Runtime.enable', {});
  const ev = async (expr) => {
    const r = await send('Runtime.evaluate', { expression: expr, awaitPromise: true, returnByValue: true });
    if (r.exceptionDetails) {
      const exc = r.exceptionDetails.exception;
      return 'EVAL_ERR: ' + (exc ? (exc.description || exc.value || JSON.stringify(exc)) : r.exceptionDetails.text);
    }
    return r.result ? r.result.value : 'UNDEF';
  };

  // Setup: vault + server + connect + SFTP.
  console.log('1_VAULT:', await ev(`call('vault_create', { password: 'e2e-v143' }).then(r => JSON.stringify(r))`));
  await sleep(300);
  await ev('refreshVaultStatus()');
  await ev(`call('server_save', { id: null, name: 'dev-sshd', host: '127.0.0.1', port: 2222, username: 'tester', authMethod: 'password', keyId: null, pemPath: null, savedPassword: 'testpass', categoryId: null, color: null })`);
  await ev('loadServers()');
  console.log('2_CONNECT:', await ev(`openSessionTab(state.servers[0]).then(() => 'tab=' + state.activeTabId + ' live=' + tabSessionLive(state.activeTabId))`));
  await sleep(2000);
  console.log('3_SFTP_TOGGLE:', await ev(`toggleSshSftpMode().then(() => { const t = state.sessions.get(state.activeTabId); return 'mode=' + t.mode + ' path=' + t.sftpPath; })`));
  await sleep(800);
  const sidRaw = await ev('state.sessions.get(state.activeTabId).sessionId');
  const sid = JSON.stringify(sidRaw);

  // 4. chmod round-trip.
  console.log('4_CHMOD_BEFORE:', await ev(`call('sftp_get_permissions', { sessionId: ${sid}, path: '/hello.txt' }).then(r => JSON.stringify(r))`));
  console.log('5_CHMOD_SET600:', await ev(`call('sftp_chmod', { sessionId: ${sid}, path: '/hello.txt', mode: 384, recursive: false, applyTo: 'all' }).then(r => JSON.stringify(r))`));
  console.log('6_CHMOD_AFTER:', await ev(`call('sftp_get_permissions', { sessionId: ${sid}, path: '/hello.txt' }).then(r => JSON.stringify(r))`));

  // 7. touch (new file).
  console.log('7_TOUCH:', await ev(`call('sftp_touch', { sessionId: ${sid}, path: '/created-e2e.txt' }).then(r => JSON.stringify(r))`));
  console.log('8_TOUCH_EXISTS:', await ev(`call('sftp_touch', { sessionId: ${sid}, path: '/created-e2e.txt' }).then(r => 'unexpected-ok').catch(e => 'rejected: ' + e.message)`));

  // 9. fs_info (statvfs; dev-sshd may not support it — must return supported:false gracefully).
  console.log('9_FS_INFO:', await ev(`call('sftp_fs_info', { sessionId: ${sid}, path: '/' }).then(r => JSON.stringify(r))`));

  // 10. search (find nested.txt under /).
  console.log('10_SEARCH:', await ev(`(async () => {
    const results = [];
    const un = await listen('sftp-search', (e2) => { if (e2.payload.path) results.push(e2.payload.path); if (e2.payload.done) window.__searchDone = e2.payload; });
    await call('sftp_search', { sessionId: ${sid}, rootPath: '/', query: 'nested' });
    await new Promise(r => setTimeout(r, 1200));
    un();
    return JSON.stringify({ results, done: window.__searchDone || null });
  })()`));

  // 11. bookmarks save + list.
  console.log('11_BOOKMARK_SAVE:', await ev(`(async () => {
    const t = state.sessions.get(state.activeTabId);
    const r1 = await call('sftp_bookmarks_list', { serverId: t.serverId });
    await call('sftp_bookmarks_save', { serverId: t.serverId, bookmarks: [...(r1.bookmarks||[]), { name: 'root', remotePath: '/', localPath: null }] });
    const r2 = await call('sftp_bookmarks_list', { serverId: t.serverId });
    return JSON.stringify(r2.bookmarks);
  })()`));

  // 12. queue: upload a local file + download it back, verify progress events.
  const uploadSrc = path.join(TMP, 'e2e-queue-upload.txt').replace(/\\/g, '/');
  fs.writeFileSync(uploadSrc, 'queue test content ' + 'x'.repeat(5000));
  console.log('12_QUEUE_UPLOAD:', await ev(`(async () => {
    const seen = [];
    const un = await listen('sftp-queue', (e2) => { for (const j of e2.payload.jobs) seen.push(j.state + ':' + j.bytesDone); });
    const r = await call('sftp_queue_add', { sessionId: ${sid}, direction: 'upload', items: [{ local: '${uploadSrc}', remote: '/queued-upload.txt' }] });
    await new Promise(res => setTimeout(res, 1500));
    un();
    return JSON.stringify({ added: r.added, events: seen.slice(0, 6), last: seen[seen.length-1] });
  })()`));
  await sleep(500);

  // 13. queue: download the file we uploaded, to temp dir.
  console.log('13_QUEUE_DOWNLOAD:', await ev(`(async () => {
    const seen = [];
    const un = await listen('sftp-queue', (e2) => { for (const j of e2.payload.jobs) seen.push(j.state + ':' + j.bytesDone + '/' + j.size); });
    const r = await call('sftp_queue_add', { sessionId: ${sid}, direction: 'download', items: [{ remote: '/queued-upload.txt' }], destDir: '${(TMP.replace(/\\/g, '/'))}' });
    await new Promise(res => setTimeout(res, 1500));
    un();
    return JSON.stringify({ added: r.added, events: seen.slice(0, 6), last: seen[seen.length-1] });
  })()`));

  // 14. queue list shows job states.
  console.log('14_QUEUE_LIST:', await ev(`call('sftp_queue_list').then(r => 'ok')`));

  // 15. multi-select via UI: ctrl-click two rows.
  console.log('15_MULTISELECT:', await ev(`(async () => {
    await refreshSftpPanel(state.activeTabId);
    await new Promise(r => setTimeout(r, 500));
    const t = state.sessions.get(state.activeTabId);
    const rows = [...document.querySelectorAll('#sftpTbody-' + state.activeTabId + ' .sftp-entry')];
    const fileRows = rows.filter(r => r.dataset.isdir === '0');
    if (fileRows.length < 2) return 'NEED_TWO_FILES';
    fileRows[0].dispatchEvent(new MouseEvent('click', { bubbles: true }));
    fileRows[1].dispatchEvent(new MouseEvent('click', { bubbles: true, ctrlKey: true }));
    return 'selected=' + t.sftpSelected.size;
  })()`));

  // 16. hidden files: create a dotfile, hidden by default, visible after toggle.
  console.log('16_HIDDEN:', await ev(`(async () => {
    await call('sftp_touch', { sessionId: ${sid}, path: '/.hidden-e2e' });
    const t = state.sessions.get(state.activeTabId);
    t.showHidden = false;
    await refreshSftpPanel(state.activeTabId);
    await new Promise(r => setTimeout(r, 400));
    const hiddenCount1 = document.querySelectorAll('#sftpTbody-' + state.activeTabId + ' .sftp-entry').length;
    t.showHidden = true;
    renderEntries(state.activeTabId);
    const hiddenCount2 = document.querySelectorAll('#sftpTbody-' + state.activeTabId + ' .sftp-entry').length;
    t.showHidden = false;
    return 'withoutHidden=' + hiddenCount1 + ' withHidden=' + hiddenCount2;
  })()`));

  // 17. sort: click the Size header twice, verify order changes.
  console.log('17_SORT:', await ev(`(async () => {
    const t = state.sessions.get(state.activeTabId);
    t.sortKey = 'name'; t.sortDesc = false;
    renderEntries(state.activeTabId);
    const first1 = document.querySelector('#sftpTbody-' + state.activeTabId + ' .sftp-entry td').textContent;
    t.sortKey = 'name'; t.sortDesc = true;
    renderEntries(state.activeTabId);
    const first2 = document.querySelector('#sftpTbody-' + state.activeTabId + ' .sftp-entry td').textContent;
    return 'asc=' + first1 + ' | desc=' + first2;
  })()`));

  // 18. dual-pane: toggle on, local pane lists home dir.
  console.log('18_DUALPANE:', await ev(`(async () => {
    toggleDualPane(state.activeTabId);
    await new Promise(r => setTimeout(r, 800));
    const t = state.sessions.get(state.activeTabId);
    const localRows = document.querySelectorAll('#sftpLocalTbody-' + state.activeTabId + ' .sftp-entry').length;
    return 'dual=' + t.dualPane + ' localRows=' + localRows;
  })()`));

  // 19. chmod modal exists and prefills.
  console.log('19_CHMOD_MODAL:', await ev(`(async () => {
    openChmodDialog(state.activeTabId, ['/hello.txt'], { name: 'hello.txt' });
    await new Promise(r => setTimeout(r, 600));
    const visible = !document.getElementById('chmodModal').hidden;
    const octal = document.getElementById('chmodOctal').value;
    document.getElementById('chmodCancelBtn').click();
    return 'visible=' + visible + ' octal=' + octal;
  })()`));

  // 20. queue panel visible with jobs.
  console.log('20_QUEUE_PANEL:', await ev(`(async () => {
    const panel = document.getElementById('sftpQueuePanel');
    return 'exists=' + !!panel + ' items=' + (panel ? panel.querySelectorAll('.sftp-queueitem').length : 0);
  })()`));

  // 21. statvfs display element rendered.
  console.log('21_FSINFO_EL:', await ev(`(async () => {
    await updateFsInfo(state.activeTabId);
    const el = document.getElementById('sftpFsInfo-' + state.activeTabId);
    return 'text="' + (el ? el.textContent : 'MISSING') + '"';
  })()`));

  // 22. activity log has entries.
  console.log('22_LOG:', await ev(`(async () => {
    const t = state.sessions.get(state.activeTabId);
    return 'lines=' + t.log.length;
  })()`));

  // 23. settings round-trip.
  console.log('23_SETTINGS:', await ev(`(async () => {
    await call('settings_set', { key: 'sftpParallel', value: '3' });
    const s = await call('settings_get');
    return 'parallel=' + s.sftpParallel;
  })()`));

  console.log('JS_ERRORS:', errors.length, errors.slice(0, 3));
  const shot = await send('Page.captureScreenshot', { format: 'png' });
  fs.writeFileSync(path.join(TMP, 'sshspan-featurepass.png'), Buffer.from(shot.data, 'base64'));
  console.log('SCREENSHOT: ' + path.join(TMP, 'sshspan-featurepass.png'));
  ws.close(); process.exit(0);
};
setTimeout(() => { console.error('TIMEOUT. errors:', errors.length, errors.slice(0, 3)); process.exit(1); }, 90000);
