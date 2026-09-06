/* File ops round-trip: upload, download, rename, delete. */
'use strict';
const wsUrl = process.argv[2];
const ws = new WebSocket(wsUrl);
let id = 0; const pending = new Map();
ws.onmessage = (ev) => { const m = JSON.parse(ev.data); if (m.id && pending.has(m.id)) { pending.get(m.id)(m.result); pending.delete(m.id); } };
ws.onopen = async () => {
  const send = (method, params) => new Promise(res => { const mid = ++id; pending.set(mid, res); ws.send(JSON.stringify({ id: mid, method, params })); });
  const ev = async (expr) => {
    const r = await send('Runtime.evaluate', { expression: expr, awaitPromise: true, returnByValue: true });
    if (r.exceptionDetails) {
      const exc = r.exceptionDetails.exception;
      const msg = exc ? (exc.description || exc.value || JSON.stringify(exc)) : r.exceptionDetails.text;
      return 'EVAL_ERR: ' + msg;
    }
    return r.result ? r.result.value : 'UNDEF';
  };
  const tab = JSON.parse(await ev('JSON.stringify(state.sessions.get(state.activeTabId))'));
  const sid = JSON.stringify(tab.sessionId);

  console.log('UPLOAD:', await ev(`(async () => {
    await call('system_write_text_file', { path: 'C:/Users/Andrei/AppData/Local/Temp/e2e-upload.txt', contents: 'uploaded content ' + Date.now() });
    await call('sftp_upload', { sessionId: ${sid}, local: 'C:/Users/Andrei/AppData/Local/Temp/e2e-upload.txt', remote: '/e2e-upload.txt' });
    const r = await call('sftp_list_dir', { sessionId: ${sid}, path: '/' });
    return r.entries.map(e => e.name).join(',');
  })()`));

  console.log('DOWNLOAD:', await ev(`(async () => {
    const r = await call('sftp_download', { sessionId: ${sid}, remote: '/e2e-upload.txt', local: 'C:/Users/Andrei/AppData/Local/Temp/e2e-dl.txt' });
    return JSON.stringify(r);
  })()`));

  console.log('RENAME:', await ev(`(async () => {
    const r = await call('sftp_rename', { sessionId: ${sid}, from: '/e2e-upload.txt', to: '/e2e-renamed.txt' });
    return JSON.stringify(r);
  })()`));

  console.log('LIST_AFTER:', await ev(`(async () => {
    const r = await call('sftp_list_dir', { sessionId: ${sid}, path: '/' });
    return r.entries.map(e => e.name).join(',');
  })()`));

  console.log('DELETE:', await ev(`(async () => {
    const r = await call('sftp_remove', { sessionId: ${sid}, path: '/e2e-renamed.txt', isDir: false });
    return JSON.stringify(r);
  })()`));

  ws.close(); process.exit(0);
};
setTimeout(() => process.exit(1), 30000);
