/* Focused: connect + watch terminal + then SFTP toggle, generous timeouts. */
'use strict';
const fs = require('fs');
const path = require('path');
const TMP = process.env.SSHSPAN_E2E_TMP || require('os').tmpdir();
const wsUrl = process.argv[2];
const ws = new WebSocket(wsUrl);
let id = 0;
const pending = new Map();
ws.onmessage = (ev) => {
  const m = JSON.parse(ev.data);
  if (m.id && pending.has(m.id)) { pending.get(m.id)(m.result); pending.delete(m.id); }
};
const sleep = (ms) => new Promise(r => setTimeout(r, ms));
function send(method, params) {
  return new Promise((resolve) => { const mid = ++id; pending.set(mid, resolve); ws.send(JSON.stringify({ id: mid, method, params })); });
}
ws.onopen = async () => {
  await send('Runtime.enable', {});
  const ev = async (expr) => {
    const r = await send('Runtime.evaluate', { expression: expr, awaitPromise: true, returnByValue: true });
    if (r.exceptionDetails) return 'EVAL_ERR: ' + (r.exceptionDetails.exception && r.exceptionDetails.exception.description || '');
    return r.result ? (r.result.value !== undefined ? r.result.value : JSON.stringify(r.result)) : 'UNDEF';
  };

  // Close any leftover tab for this server, then open a fresh one.
  await ev(`(async () => { for (const [tid, t] of [...state.sessions]) { if (window.tabSessionLive(tid)) await call('terminal_disconnect', { sessionId: t.sessionId }).catch(()=>{}); window.destroyTabTerminal(tid); state.sessions.delete(tid); } state.activeTabId = null; return 'cleared'; })()`);
  await sleep(500);
  await ev(`(async () => { if (!state.unlocked) { await call('vault_unlock', { password: 'e2e-test-pw-1' }); await refreshVaultStatus(); } await loadServers(); return 'unlocked=' + state.unlocked + ', servers=' + state.servers.length; })()`);
  await sleep(300);

  const connectResult = await Promise.race([
    ev(`(async () => {
      const srv = state.servers[0];
      await openSessionTab(srv);
      const t = state.sessions.get(state.activeTabId);
      return JSON.stringify({ tabId: t.tabId, ended: t.ended, live: tabSessionLive(t.tabId) });
    })()`),
    sleep(20000).then(() => 'CONNECT_TIMEOUT_20S'),
  ]);
  console.log('CONNECT:', connectResult);

  await sleep(3000);
  console.log('TERM_BUFFER:', await ev(`(() => {
    const rec = tabRecord(state.activeTabId);
    if (!rec) return 'NO_REC';
    const lines = [];
    for (let i = 0; i < rec.term.buffer.active.length; i++) {
      const l = rec.term.buffer.active.getLine(i);
      if (l && l.translateToString(true)) lines.push(l.translateToString(true));
    }
    return lines.join(' | ').slice(-400) || 'EMPTY';
  })()`));
  console.log('LIVE_AFTER_3S:', await ev(`tabSessionLive(state.activeTabId)`));
  console.log('SESSION_LIST:', await ev(`call('terminal_list').then(r => JSON.stringify(r.active))`));

  // SFTP toggle with generous wait.
  console.log('SFTP_TOGGLE:', await Promise.race([
    ev(`(async () => { await toggleSshSftpMode(); const t = state.sessions.get(state.activeTabId); return JSON.stringify({ mode: t.mode, ready: t.sftpReady, path: t.sftpPath }); })()`),
    sleep(15000).then(() => 'SFTP_TIMEOUT_15S'),
  ]));
  await sleep(1500);
  console.log('SFTP_ROWS:', await ev(`(() => {
    const p = document.getElementById('sftpPanel-' + state.activeTabId);
    if (!p) return 'NO_PANEL';
    const tb = p.querySelector('tbody');
    return tb ? [...tb.rows].map(r => r.cells[0].textContent).join(',') : 'NO_TBODY';
  })()`));

  const fs = require('fs');
  const shot = await send('Page.captureScreenshot', { format: 'png' });
  fs.writeFileSync(path.join(TMP, 'sshspan-e2e2.png'), Buffer.from(shot.data, 'base64'));
  console.log('SCREENSHOT saved');
  ws.close(); process.exit(0);
};
setTimeout(() => process.exit(1), 60000);