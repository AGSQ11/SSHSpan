#!/usr/bin/env node
/* JU3: real-page assistant/MCP regression evals. No provider, SSH host or secrets.
 * Each scenario gets a fresh app from the shared renderer harness. The stub
 * records actual IPC; these checks never reimplement renderer algorithms.
 * SSHSPAN_RENDERER_DIR can point at the captured baseline for RED evidence.
 */
'use strict';
const {
  failures, check, yes, part, loadChromium, serve, rendererDir, openApp,
  openLiveTab, waitVisible, answerConfirm, hold, letGo, toasts, SERVER,
} = require('./lib/renderer-harness');

const CONFIG = { provider: 'openai', base_url: 'https://api.openai.com/v1', model: 'fixture-model', has_api_key: true };
const TOOL = (more = {}) => ({
  name: 'echo', display_name: 'Echo', description: 'Return the supplied text.',
  enabled: true, auto_approve: false, pinned: true, definition_changed: false,
  definition_hash: 'hash-one', exposed_name: 'mcp__svc__echo',
  inputSchema: { type: 'object', properties: { text: { type: 'string' }, password: { type: 'string', writeOnly: true } } },
  annotations: { readOnlyHint: true }, ...more,
});
const MCP = (more = {}) => ({
  id: 'm1', name: 'svc', url: 'https://mcp.example.test/mcp', auth_type: 'none',
  auth_header_name: null, auth_env_var: null, has_secret: false,
  protocol_version: '2025-03-26', confirmed: true, loopback_insecure: false,
  status: 'connected', tool_count: 1, tools: [TOOL()], ...more,
});
const TC = (id, name = 'get_session_info', args = {}) => ({ id, name, arguments_json: JSON.stringify(args) });
// Argument names a server may choose for anything - credential-looking ones
// included - with the values the user must see on the approval card.
const FULL_ARGS = {
  text: 'hello', password: 'fixture-sensitive-value', page_token: 'fixture-page-token-value',
  tokens: 'fixture-tokens-value', max_tokens: 'fixture-max-tokens-value', credentials_file: 'fixture-credentials-file-value',
};
const FULL_ARG_VALUES = Object.values(FULL_ARGS);
let passed = 0;
const ok = (name, got, want) => { const n = failures.length; check(name, got, want); if (failures.length === n) passed++; };
const expect = (name, cond) => ok(name, !!cond, true);

async function fixture(browser, server, title, fn, opts = {}) {
  await part(title, async () => {
    const app = await openApp(browser, server, { ...opts, replies: {
      assistant_get_config: CONFIG, mcp_list_servers: [MCP()], ...opts.replies,
    } });
    try {
      await app.page.evaluate((fullArgs) => {
        window.__fullArgs = fullArgs;
        window.__levels = {};
        window.__replies.assistant_get_level = (a) => ({ level: window.__levels[a.tabId] || 'read' });
        window.__replies.assistant_set_level = (a) => { window.__levels[a.tabId] = a.level; return { ok: true }; };
        window.__replies.assistant_chat = { text: 'Finished.', tool_calls: [] };
        window.__replies.mcp_call_tool = { ok: true, content: 'tool output', is_error: false, warning: null };
      }, FULL_ARGS);
      // A scenario that hangs (an awaited promise that never settles) fails
      // on its own instead of stalling the whole suite.
      let timer;
      await Promise.race([fn(app), new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('scenario timed out after 90 s')), 90000); })])
        .finally(() => clearTimeout(timer));
      ok(title + ': no page errors', app.errors, []);
    } finally { await app.close(); }
  });
}
async function panel(app) {
  const id = await openLiveTab(app);
  await app.page.evaluate(() => { if (!assistantIsOpen()) assistantToggle(); });
  await app.page.waitForTimeout(180); // terminal's deferred connect focus settles
  return id;
}
async function level(page, id, value) {
  if (value === 'yolo') {
    await page.evaluate((t) => { aiSetLevel(t, 'yolo'); }, id);
    await page.click('#yoloEnableBtn');
  } else await page.evaluate(({ t, v }) => aiSetLevel(t, v), { t: id, v: value });
  await page.waitForFunction(({ t, v }) => window.__levels[t] === v, { t: id, v: value });
}
async function send(page, text = 'Help with this session') {
  await page.fill('#assistantInput', text);
  // Like a click: start the turn, do not wait for it (it may wait on a card).
  await page.evaluate(() => { aiSend(); });
}
async function idle(page) {
  await page.waitForFunction(() => document.getElementById('assistantThinking').hidden, null, { timeout: 7000 });
}
const transcript = (page) => page.locator('#assistantMessages').innerText();
const wire = async (app) => (await app.calls('assistant_chat')).at(-1).args.messages;
function complete(messages) {
  const pending = new Set();
  for (const m of messages) {
    if (m.role === 'assistant') {
      if (pending.size) return false;
      for (const c of m.tool_calls || []) pending.add(c.id);
    } else if (m.role === 'tool') {
      if (!pending.delete(m.tool_call_id)) return false;
    } else if (pending.size) return false;
  }
  return pending.size === 0;
}
async function settings(page) {
  await page.evaluate(async () => { await switchView('settings'); showSettingsSection('assistant'); await aiLoadConfig(); await mcpLoadSettings(); });
}

async function approvalChecks(browser, server) {
  for (const v of ['read', 'draft', 'execute']) {
    await fixture(browser, server, 'MCP explicit approval at ' + v, async (app) => {
      const { page } = app;
      const id = await panel(app);
      if (v !== 'read') await level(page, id, v);
      await page.evaluate(() => {
        window.__replies.mcp_list_servers = [Object.assign({}, window.__replies.mcp_list_servers[0], {
          tools: [Object.assign({}, window.__replies.mcp_list_servers[0].tools[0], { auto_approve: true })],
        })];
      });
      await page.evaluate(() => mcpRefresh());
      // execute: turn auto off so its explicit-card path is exercised too.
      if (v === 'execute') await page.evaluate(() => { window.__replies.mcp_list_servers[0].tools[0].auto_approve = false; return mcpRefresh(); });
      await page.evaluate(() => {
        let n = 0;
        window.__replies.assistant_chat = () => ++n === 1
          ? { text: 'Checking the service now.', tool_calls: [{ id: 'mcall', name: 'mcp__svc__echo', arguments_json: JSON.stringify(window.__fullArgs) }] }
          : { text: 'Done.', tool_calls: [] };
      });
      await send(page);
      const card = await waitVisible(page, '.ai-card.confirm', 900);
      expect(v + ': card is required (even when Auto-approve at read/draft)', card);
      if (card) {
        ok('no MCP request before approval', await app.count('mcp_call_tool'), 0);
        // The card, not its danger button, takes the focus: a key-repeat Enter
        // from the user's own Send must not approve (fix round 1, item 2).
        ok('the pending card itself has the focus', await page.evaluate(() => {
          const a = document.activeElement; return !!a && a.classList.contains('ai-card') && a.classList.contains('confirm');
        }), true);
        expect('the focused card has an accessible name', await page.evaluate(() => /approv/i.test(document.activeElement.getAttribute('aria-label') || '')));
        await page.keyboard.press('Enter'); await page.waitForTimeout(40);
        ok('Enter on the focused card approves nothing', await app.count('mcp_call_tool'), 0);
        await page.keyboard.press('Tab');
        ok('Tab reaches Approve from the card', await page.evaluate(() => document.activeElement.textContent), 'Approve');
        // The card is the control between an injected model and an
        // exfiltration: every argument value is shown, whatever its name -
        // server-chosen names must not hide anything (fix round 1, item 1).
        const cardText = await page.locator('.ai-card.confirm').last().innerText();
        expect('card shows every argument value in full (no name-based masking)',
          FULL_ARG_VALUES.every((x) => cardText.includes(x)) && !/redacted/i.test(cardText));
        await page.locator('.ai-card.confirm button').filter({ hasText: /^Approve$/ }).click();
      }
      await idle(page);
      const c = (await app.calls('mcp_call_tool')).at(-1);
      ok(v + ': IPC is explicitly approved', c && c.args.approved, true);
      ok('actual real tool name is sent', c && c.args.tool, 'echo');
      ok('actual arguments are not redacted on IPC', c && JSON.parse(c.args.argumentsJson).password, 'fixture-sensitive-value');
      const text = await transcript(page);
      expect('tool-call commentary is visible', text.includes('Checking the service now.'));
      expect('non-interactive event names server, real tool and explicit source', /svc/.test(text) && /echo/.test(text) && /explicit/i.test(text));
      expect('result is visible', text.includes('tool output'));
      ok('one event for the call', await page.locator('.ai-tool-event').count(), 1);
      const eventText = await page.locator('.ai-tool-event').last().innerText();
      expect('the event row shows every argument value in full',
        FULL_ARG_VALUES.every((x) => eventText.includes(x)) && !/redacted/i.test(eventText));
      ok('the event has no action controls', await page.locator('.ai-tool-event button, .ai-tool-event input').count(), 0);
    });
  }
  for (const v of ['execute', 'yolo']) {
    await fixture(browser, server, 'MCP automatic call at ' + v, async (app) => {
      const { page } = app; const id = await panel(app); await level(page, id, v);
      await page.evaluate(() => {
        window.__replies.mcp_list_servers[0].tools[0].auto_approve = true;
        window.__replies.mcp_call_tool = { ok: true, content: '<img src=x onerror="window.__injected=1"> output', is_error: false,
          warning: '<script>window.__injected=2</script> refresh failed' };
        let n = 0;
        window.__replies.assistant_chat = () => ++n === 1
          ? { text: 'Using the tool.', tool_calls: [{ id: 'mc', name: 'mcp__svc__echo', arguments_json: '{"token":"fixture-token","page_token":"fixture-page-token","tokens":"fixture-tokens","items":[1,2]}' }] }
          : { text: 'Finished.', tool_calls: [] };
        return mcpRefresh();
      });
      await send(page); await idle(page);
      ok(v + ': no approval card', await page.locator('.ai-card.confirm').count(), 0);
      ok(v + ': bypass is NOT falsely attested as explicit', (await app.calls('mcp_call_tool')).at(-1).args.approved, false);
      const text = await transcript(page);
      expect('approval source visible', v === 'yolo' ? /YOLO/.test(text) : /auto/i.test(text));
      expect('warning is visible', text.includes('refresh failed'));
      expect('unattended calls show every argument value in full (no name-based masking)',
        ['fixture-token', 'fixture-page-token', 'fixture-tokens'].every((x) => text.includes(x)) && !/redacted/i.test(text));
      ok('no server HTML injection', await page.locator('#assistantMessages img, #assistantMessages script').count(), 0);
      ok('no injected code ran', await page.evaluate(() => window.__injected || 0), 0);
      const result = (await wire(app)).find((m) => m.role === 'tool');
      expect('warning is part of the untrusted model result', result && /trust="untrusted"/.test(result.content) && result.content.includes('refresh failed'));
    });
  }
  await fixture(browser, server, 'Long MCP arguments: every key visible, the full text one click away', async (app) => {
    const { page } = app; const id = await panel(app);
    const long = 'L'.repeat(5000) + 'END-OF-LONG-VALUE';
    await page.evaluate(({ t, long }) => {
      window.__card = aiConfirmMcpCard(t, 'svc', 'echo', { notes: long, page_token: 'short-token-value', nested: { cookie: 'nested-cookie-value' } }, null);
    }, { t: id, long });
    const card = page.locator('.ai-card.confirm').last();
    const visible = await card.innerText();
    expect('collapsed card still names every argument', ['notes', 'page_token', 'nested', 'cookie'].every((k) => visible.includes(k)));
    expect('short values are shown in full next to a long one', visible.includes('short-token-value') && visible.includes('nested-cookie-value'));
    expect('a shortened value says how much is not shown yet', /more characters/i.test(visible) && !visible.includes('END-OF-LONG-VALUE'));
    const toggle = card.locator('summary, button').filter({ hasText: /show all/i });
    ok('a user-controlled "Show all" exists', await toggle.count(), 1);
    if (await toggle.count()) {
      await toggle.click();
      expect('"Show all" reveals the complete value', (await card.innerText()).includes('END-OF-LONG-VALUE'));
    }
    await card.locator('button').filter({ hasText: /^Deny$/ }).click();
    ok('the card answers', await page.evaluate(() => window.__card), false);
  });
  await fixture(browser, server, 'MCP denial and failure visibility', async (app) => {
    const { page } = app; const id = await panel(app);
    await page.evaluate((t) => { window.__toolTask = aiRunTool(t, { id: 'denied', name: 'mcp__svc__echo', arguments_json: '{}' }); }, id);
    await page.locator('.ai-card.confirm button').filter({ hasText: /^Deny$/ }).click();
    expect('denial is a tool result', /denied/i.test(await page.evaluate(() => window.__toolTask)));
    ok('denied call sends nothing', await app.count('mcp_call_tool'), 0);
    await level(page, id, 'execute');
    await page.evaluate(() => { window.__replies.mcp_list_servers[0].tools[0].auto_approve = true; window.__replies.mcp_call_tool = { ok: true, content: 'service refused', is_error: true, warning: 'retry later' }; return mcpRefresh(); });
    const r = await page.evaluate((t) => aiRunTool(t, { id: 'err', name: 'mcp__svc__echo', arguments_json: '{}' }), id);
    expect('is_error becomes an error result', /error.*service refused/s.test(r));
    expect('tool failure and warning both visible', /service refused/.test(await transcript(page)) && /retry later/.test(await transcript(page)));
  });
}

async function typingChecks(browser, server) {
  await fixture(browser, server, 'AI typing and suggestion actions', async (app) => {
    const { page } = app; const id = await panel(app); await level(page, id, 'draft');
    await hold(page, 'assistant_type_text');
    await page.evaluate((t) => {
      window.__typedDone = false;
      window.__typeTask = aiRunTool(t, { id: 'typed', name: 'type_command', arguments_json: '{"command":"echo café"}' }).then((r) => { window.__typedDone = true; return r; });
    }, id);
    await page.waitForTimeout(60);
    ok('typing awaits backend acknowledgement', await page.evaluate(() => window.__typedDone), false);
    await letGo(page, 'assistant_type_text');
    expect('success is returned after acknowledgement', /^typed:/.test(await page.evaluate(() => window.__typeTask)));
    const typed = (await app.calls('assistant_type_text')).at(-1);
    ok('model text uses ONLY typed-text IPC keys', typed && Object.keys(typed.args).sort(), ['sessionId', 'tabId', 'text']);
    ok('model text and target round-trip', typed && [typed.args.tabId, typed.args.text], [id, 'echo café']);
    ok('model text never uses terminal_send', await app.count('terminal_send'), 0);
    const before = await app.count('assistant_type_text');
    const multi = await page.evaluate((t) => aiRunTool(t, { id: 'multi', name: 'type_command', arguments_json: '{"command":"echo one\\nid"}' }), id);
    expect('multi-line model text is explicitly denied', /^denied:.*single line/s.test(multi));
    ok('multi-line text never crosses IPC', await app.count('assistant_type_text'), before);
    await page.evaluate(() => { window.__replies.assistant_type_text = { $reject: "AI access level is 'read' - raise it to Draft or higher in the assistant panel to let the assistant type into the terminal." }; });
    const refused = await page.evaluate((t) => aiRunTool(t, { id: 'gate', name: 'type_command', arguments_json: '{"command":"id"}' }), id);
    expect('backend level denial survives exactly', refused.includes("AI access level is 'read' - raise it to Draft or higher"));
    for (const raw of ['null', '[]', '42', '"bad"', '{bad']) {
      const r = await page.evaluate(({ t, raw }) => aiRunTool(t, { id: 'invalid', name: 'type_command', arguments_json: raw }), { t: id, raw });
      expect('invalid tool args yield a result, not an exception: ' + raw, /^(error|denied):/.test(r));
    }
    await page.evaluate(() => { window.__replies.assistant_type_text = { ok: true }; });
    await page.evaluate((t) => aiSuggestCard(t, 'echo insert', 'review it'), id);
    await page.locator('.ai-card.suggest button').filter({ hasText: /^Insert$/ }).last().click();
    await page.waitForTimeout(40);
    ok('Insert also uses assistant_type_text', (await app.calls('assistant_type_text')).at(-1).args.text, 'echo insert');
    await level(page, id, 'read');
    const prior = await app.count('assistant_type_text');
    await page.locator('.ai-card.suggest button').filter({ hasText: /^Insert$/ }).last().click();
    ok('an old Insert cannot type after downgrade', await app.count('assistant_type_text'), prior);
    await level(page, id, 'execute');
    await page.evaluate(() => { window.__replies.assistant_exec = { $reject: 'Session is closing.' }; });
    await page.evaluate((t) => aiSuggestCard(t, 'echo run', 'review run'), id);
    const run = page.locator('.ai-card.suggest button').filter({ hasText: /^Run$/ }).last();
    await run.click(); await page.waitForTimeout(40);
    ok('failed Run is re-enabled', await run.isDisabled(), false);
    const execs = await app.count('assistant_exec');
    await page.evaluate((t) => aiSuggestCard(t, '   ', ''), id);
    await page.locator('.ai-card.suggest button').filter({ hasText: /^Run$/ }).last().click({ force: true });
    ok('empty proposal never sends a bare Enter', await app.count('assistant_exec'), execs);
    ok('still no raw terminal sends from model actions', await app.count('terminal_send'), 0);
  });
}

async function historyChecks(browser, server) {
  await fixture(browser, server, 'Stop while a provider reply is in flight', async (app) => {
    const { page } = app; await panel(app);
    await page.evaluate(() => { window.__replies.assistant_chat = { text: 'Tool commentary.', tool_calls: ['a', 'b', 'c'].map((id) => ({ id, name: 'get_session_info', arguments_json: '{}' })) }; });
    await hold(page, 'assistant_chat'); await send(page); await page.click('#assistantStopBtn'); await letGo(page, 'assistant_chat'); await idle(page);
    await page.evaluate(() => { window.__replies.assistant_chat = { text: 'Next.', tool_calls: [] }; });
    await send(page, 'Next question'); await idle(page);
    const m = await wire(app);
    expect('next request has complete stopped tool group', complete(m));
    ok('each in-flight call received a cancellation result', m.filter((x) => x.role === 'tool').map((x) => x.tool_call_id), ['a', 'b', 'c']);
    expect('all stopped results are explicit', m.filter((x) => x.role === 'tool').every((x) => /cancelled/i.test(x.content)));
    ok('every cancelled call has a visible event', await page.locator('.ai-tool-event').count(), 3);
  });
  await fixture(browser, server, 'Stop denies a pending card and answers remaining calls', async (app) => {
    const { page } = app; const id = await panel(app); await level(page, id, 'execute');
    await page.evaluate(() => { window.__replies.assistant_chat = { text: '', tool_calls: [
      { id: 'one', name: 'run_command', arguments_json: '{"command":"id"}' },
      { id: 'two', name: 'get_session_info', arguments_json: '{}' },
    ] }; });
    await send(page); await waitVisible(page, '.ai-card.confirm'); await page.click('#assistantStopBtn'); await idle(page);
    await page.evaluate(() => { window.__replies.assistant_chat = { text: 'Next.', tool_calls: [] }; });
    await send(page); await idle(page);
    const m = await wire(app);
    expect('pending-card stop leaves no orphan', complete(m));
    ok('no command was run', await app.count('assistant_exec'), 0);
    ok('both calls get results', m.filter((x) => x.role === 'tool').length, 2);
  });
  await fixture(browser, server, 'Tool cap, invalid args, tool exceptions and empty replies', async (app) => {
    const { page } = app; await panel(app);
    await page.evaluate(() => { window.__replies.assistant_chat = { text: 'Many calls.', tool_calls: Array.from({ length: 30 }, (_, n) => ({ id: 'cap' + n, name: 'get_session_info', arguments_json: '{}' })) }; });
    await send(page); await idle(page);
    expect('tool cap is visible', /25 tool calls/.test(await transcript(page)));
    ok('all 30 calls (including cap cancellations) have events', await page.locator('.ai-tool-event').count(), 30);
    await page.evaluate(() => { window.__replies.assistant_chat = { text: '', tool_calls: [] }; });
    await send(page); await idle(page);
    expect('empty model reply is visible, not a blank assistant row', /returned no (text|content)|empty reply/i.test(await transcript(page)));
    await page.evaluate(() => {
      let n = 0; const old = window.mcpCallTool;
      window.mcpCallTool = async () => { throw new Error('fixture tool exception'); };
      window.__oldMcpCall = old;
      window.__replies.mcp_list_servers[0].tools[0].auto_approve = true;
      window.__replies.assistant_chat = () => ++n === 1 ? { text: '', tool_calls: [
        { id: 'null', name: 'propose_command', arguments_json: 'null' },
        { id: 'throws', name: 'mcp__svc__echo', arguments_json: '{}' },
        { id: 'after', name: 'get_session_info', arguments_json: '{}' },
      ] } : { text: 'Recovered.', tool_calls: [] };
      return mcpRefresh();
    });
    const id = await page.evaluate(() => state.activeTabId); await level(page, id, 'execute');
    await send(page); await idle(page);
    const m = await wire(app);
    expect('error paths still send complete groups', complete(m));
    expect('a tool exception is sent as a tool error', m.some((x) => x.role === 'tool' && /fixture tool exception/.test(x.content)));
    expect('no empty assistant message is replayed', m.every((x) => x.role !== 'assistant' || !!(x.content && x.content.trim()) || !!(x.tool_calls && x.tool_calls.length)));
  });
  await fixture(browser, server, 'Bounded UTF-8 results and complete history groups', async (app) => {
    const { page } = app; const id = await panel(app); await level(page, id, 'execute');
    await page.evaluate(() => {
      window.__replies.mcp_list_servers[0].tools[0].auto_approve = true;
      window.__replies.mcp_call_tool = { ok: true, content: '界'.repeat(500000), warning: 'large fixture result', is_error: false };
      let n = 0;
      window.__replies.assistant_chat = () => ++n === 1 ? { text: 'Large result.', tool_calls: [{ id: 'big', name: 'mcp__svc__echo', arguments_json: '{"items":[]}' }] } : { text: 'Small reply.', tool_calls: [] };
      return mcpRefresh();
    });
    await send(page); await idle(page);
    const result = (await wire(app)).find((x) => x.role === 'tool');
    expect('result capped at 64 KiB INCLUDING untrusted boundary', result && Buffer.byteLength(result.content, 'utf8') <= 65536);
    expect('truncation is explicit', result && /truncated/i.test(result.content));
    expect('UTF-8 is not split', result && !result.content.includes('�'));
    expect('untrusted block is still closed', result && /<\/terminal_output_[0-9]+>$/.test(result.content));
    expect('visible result is bounded', (await transcript(page)).length < 12000);
    for (let n = 0; n < 25; n++) { await send(page, 'history ' + n); await idle(page); }
    const m = await wire(app);
    expect('wire history is bounded to ~40 messages', m.length <= 42);
    expect('trimming never leaves orphan tool results', complete(m));
    const newChat = await page.locator('#assistantNewChatBtn').count();
    ok('New chat exists', newChat, 1);
    if (newChat) {
      await page.click('#assistantNewChatBtn'); await send(page, 'Fresh'); await idle(page);
      const fresh = await wire(app);
      ok('New chat resets context, retaining only system and fresh user', fresh.map((x) => x.role), ['system', 'user']);
      ok('New chat retains the chosen level', await page.evaluate((t) => window.__levels[t], id), 'execute');
    }
  });
}

async function lifecycleChecks(browser, server) {
  await fixture(browser, server, 'Per-tab busy state, close cleanup and late replies', async (app) => {
    const { page } = app; const a = await panel(app);
    await hold(page, 'assistant_chat'); await send(page, 'Question in A');
    await page.evaluate((s) => { window.__tabB = openSessionTab(s); }, SERVER('s2', 'web-2'));
    await page.waitForFunction(() => state.sessions.size === 2);
    const b = await page.evaluate(() => state.activeTabId);
    ok('B input is usable while A thinks', await page.locator('#assistantInput').isDisabled(), false);
    ok('B does not show A thinking', await page.locator('#assistantThinking').isVisible(), false);
    await page.evaluate((t) => activateSessionSurface(t), a);
    ok('return to A restores busy', await page.locator('#assistantInput').isDisabled(), true);
    await page.evaluate((t) => closeSessionTab(t, { skipConfirm: true }), a);
    await page.evaluate(() => { window.__replies.assistant_chat = { text: 'late reply for closed A', tool_calls: [] }; });
    await letGo(page, 'assistant_chat'); await page.waitForTimeout(80);
    ok('B remains active', await page.evaluate(() => state.activeTabId), b);
    expect('late A text is dropped', !(await transcript(page)).includes('late reply for closed A'));
    ok('only B transcript subtree remains', await page.locator('.ai-tab-list').count(), 1);
    ok('no global thinking wedge', await page.locator('#assistantInput').isDisabled(), false);
    expect('closing A resets its backend level to read', (await app.calls('assistant_set_level')).some((x) => x.args.tabId === a && x.args.level === 'read'));
  });
  await fixture(browser, server, 'Lock denies approvals, wipes transcripts and resets YOLO', async (app) => {
    const { page } = app; const id = await panel(app); await level(page, id, 'execute');
    await page.evaluate(() => { window.__replies.assistant_chat = { text: '', tool_calls: [{ id: 'r', name: 'run_command', arguments_json: '{"command":"id"}' }] }; });
    await send(page, 'private fixture conversation'); await waitVisible(page, '.ai-card.confirm');
    await page.evaluate(() => { window.__backend.unlocked = false; return refreshVaultStatus(); });
    await page.waitForTimeout(70);
    ok('lock removes all transcript lists', await page.locator('.ai-tab-list').count(), 0);
    ok('lock sends no pending command', await app.count('assistant_exec'), 0);
    ok('locked input is disabled', await page.locator('#assistantInput').isDisabled(), true);
    expect('lock resets backend level', (await app.calls('assistant_set_level')).some((x) => x.args.tabId === id && x.args.level === 'read'));
    await page.evaluate(() => { window.__backend.unlocked = true; return refreshVaultStatus(); });
    const t = await panel(app); await level(page, t, 'yolo');
    await page.evaluate((x) => window.onSessionClosed(x), t);
    await page.waitForTimeout(70);
    ok('session drop resets YOLO to read', await page.evaluate((x) => window.__levels[x], t), 'read');
    await page.evaluate((x) => { assistantClearTab(x); assistantClearTab(x); assistantClearTab('unknown-tab'); }, t);
    expect('idempotent clear never arms YOLO', (await app.calls('assistant_set_level')).filter((x) => x.args.tabId === t).at(-1).args.level === 'read');
  });
  await fixture(browser, server, 'A dropped session keeps the transcript, ends the turn, resets the level', async (app) => {
    const { page } = app; const id = await panel(app); await level(page, id, 'execute');
    await page.evaluate(() => { window.__replies.assistant_chat = { text: 'Kept commentary.', tool_calls: [{ id: 'r', name: 'run_command', arguments_json: '{"command":"id"}' }] }; });
    await send(page, 'question before the drop'); await waitVisible(page, '.ai-card.confirm');
    await page.evaluate((t) => window.onSessionClosed(t), id);
    await page.waitForTimeout(80);
    const text = await transcript(page);
    expect('the transcript survives a dropped session', text.includes('question before the drop') && text.includes('Kept commentary.'));
    ok('the pending command card was denied - nothing ran', await app.count('assistant_exec'), 0);
    ok('the card stays, marked denied', await page.locator('.ai-card.confirm.denied').count(), 1);
    ok('the access level is back to read', await page.evaluate((t) => window.__levels[t], id), 'read');
    ok('no thinking row left', await page.locator('#assistantThinking').isVisible(), false);
    ok('the input works again', await page.locator('#assistantInput').isDisabled(), false);
    await page.evaluate(() => { window.__replies.assistant_chat = { text: 'After the drop.', tool_calls: [] }; });
    await send(page, 'after the drop'); await idle(page);
    expect('the kept history is complete', complete(await wire(app)));
    await page.click('#assistantNewChatBtn');
    expect('New chat still clears it', !(await transcript(page)).includes('question before the drop'));
  });
  await fixture(browser, server, 'A YOLO dialog left open never arms a closed tab', async (app) => {
    const { page } = app; const id = await panel(app);
    await page.evaluate((t) => { aiSetLevel(t, 'yolo'); }, id);
    await waitVisible(page, '#yoloModal');
    await page.evaluate((t) => closeSessionTab(t, { skipConfirm: true }), id);
    await page.waitForTimeout(60);
    const stillOpen = await app.open('yoloModal');
    ok('the dialog closes with its tab', stillOpen, false);
    if (stillOpen) await page.click('#yoloEnableBtn');
    await page.waitForTimeout(60);
    ok('no YOLO for the closed tab', (await app.calls('assistant_set_level')).filter((x) => x.args.level === 'yolo').length, 0);
  });
  await fixture(browser, server, 'New chat during approval cancels the old turn', async (app) => {
    const { page } = app; const id = await panel(app); await level(page, id, 'execute');
    await page.evaluate(() => { window.__replies.assistant_chat = { text: '', tool_calls: [{ id: 'r', name: 'run_command', arguments_json: '{"command":"id"}' }] }; });
    await send(page); await waitVisible(page, '.ai-card.confirm');
    if (await page.locator('#assistantNewChatBtn').count()) {
      await page.click('#assistantNewChatBtn'); await page.waitForTimeout(40);
      ok('New chat denies a pending approval', await app.count('assistant_exec'), 0);
      ok('New chat re-enables its input', await page.locator('#assistantInput').isDisabled(), false);
      ok('New chat removes the pending card', await page.locator('.ai-card.confirm').count(), 0);
    } else ok('New chat available during a pending approval', false, true);
  });
}

async function mcpSettingsChecks(browser, server) {
  await fixture(browser, server, 'MCP round-trip, counts, protocol and credential binding', async (app) => {
    const { page } = app;
    await page.evaluate(() => { window.__replies.mcp_list_servers = [
      { id: 'm1', name: 'env-service', url: 'https://mcp.example.test/mcp', auth_type: 'custom_header', auth_header_name: 'X-Fixed', auth_env_var: 'FIXTURE_ENV_NAME', has_secret: false, confirmed: false, status: 'unknown', protocol_version: '2025-03-26', tool_count: 0, tools: [
        { name: 'echo', display_name: 'Echo', description: 'Review fixture description', enabled: false, auto_approve: false, pinned: false, definition_changed: false, definition_hash: 'hash-one', exposed_name: 'mcp__svc__echo', inputSchema: { type: 'object' }, annotations: null },
      ] },
    ]; });
    await settings(page);
    expect('count is enabled/total', /0\s*\/\s*1/.test(await page.locator('.mcp-server-count').innerText()));
    expect('unconfirmed entry is visibly inert', /unconfirmed.*review.*re-save/i.test(await page.locator('.mcp-server-row').innerText()));
    expect('negotiated protocol visible', /2025-03-26/.test(await page.locator('.mcp-server-row').innerText()));
    expect('status dot has a textual accessible name', !!(await page.locator('.mcp-dot').getAttribute('aria-label')));
    const review = page.locator('.mcp-server-row button').filter({ hasText: /^Review tools$/ });
    ok('Review tools action exists without reconnecting', await review.count(), 1);
    if (await review.count()) await review.click(); else await page.evaluate(() => mcpShowToolsFor('m1'));
    ok('Review tools sends no connection request', await app.count('mcp_test_connection'), 0);
    await page.locator('.mcp-server-row button').filter({ hasText: /^Edit$/ }).click();
    ok('stored custom header is prefilled', await page.inputValue('#mcpHeaderName'), 'X-Fixed');
    ok('stored env-var NAME is prefilled', await page.inputValue('#mcpAuthEnvVar'), 'FIXTURE_ENV_NAME');
    ok('environment variable source is selected', await page.inputValue('#mcpSecretSource'), 'env');
    ok('no false stored-secret hint', (await page.locator('#mcpSecretHint').textContent()).trim(), '');
    await page.fill('#mcpName', 'renamed'); await page.click('#mcpSaveBtn'); await page.waitForTimeout(40);
    const p = (await app.calls('mcp_save_server')).at(-1).args;
    ok('round-trip keeps header + env-var', [p.auth_header_name, p.auth_env_var, p.auth_secret], ['X-Fixed', 'FIXTURE_ENV_NAME', null]);
    // Env var -> "stored secret" with nothing typed: the backend keeps the
    // binding, and the form says so instead of refusing (fix round 1, item 7).
    await page.locator('.mcp-server-row button').filter({ hasText: /^Edit$/ }).click();
    await page.selectOption('#mcpSecretSource', 'stored');
    expect('the form says the env-var binding stays in effect', /FIXTURE_ENV_NAME[^.]*stays in effect/i.test(await page.locator('#mcpFormHost').innerText()));
    const saves = await app.count('mcp_save_server');
    await page.click('#mcpSaveBtn'); await page.waitForTimeout(60);
    ok('the save goes through, keeping the binding', await app.count('mcp_save_server'), saves + 1);
    const kept = (await app.calls('mcp_save_server')).at(-1).args;
    ok('it neither invents a secret nor clears the variable', [kept.auth_secret, kept.auth_env_var], [null, null]);
    await page.evaluate(() => { window.__replies.mcp_list_servers[0].has_secret = true; window.__replies.mcp_list_servers[0].auth_env_var = null; return mcpLoadSettings(); });
    await page.locator('.mcp-server-row button').filter({ hasText: /^Edit$/ }).click();
    expect('actual stored-secret hint says blank keeps it', /stored.*blank.*keep/i.test(await page.locator('#mcpSecretHint').textContent()));
    await page.fill('#mcpUrl', 'https://new.example.test/mcp');
    expect('URL change warns about discarded credential BEFORE save', /discard|re-enter/i.test(await page.locator('#mcpFormHost').innerText()));
    const prior = await app.count('mcp_save_server'); await page.click('#mcpSaveBtn'); await page.waitForTimeout(40);
    ok('origin change with no re-entered source fails closed', await app.count('mcp_save_server'), prior);
  });
  await fixture(browser, server, 'MCP definition compare-and-swap and refreshed pins', async (app) => {
    const { page } = app;
    await page.evaluate(() => {
      window.__registry = structuredClone(window.__replies.mcp_list_servers);
      window.__registry[0].tools[0] = Object.assign({}, window.__registry[0].tools[0], { enabled: false, auto_approve: true, pinned: true, definition_changed: true });
      window.__replies.mcp_list_servers = () => structuredClone(window.__registry);
      window.__replies.mcp_set_tool_state = (a) => {
        const t = window.__registry[0].tools[0];
        if (window.__stale) { window.__stale = false; t.definition_hash = 'hash-two'; t.description = 'NEW definition to review'; t.enabled = false; t.definition_changed = true; t.auto_approve = false; throw "This tool's definition changed - review it and approve again."; }
        Object.assign(t, { enabled: a.enabled, auto_approve: a.auto_approve, pinned: a.enabled, definition_changed: false });
        return { ok: true };
      };
    });
    await settings(page); await page.evaluate(() => mcpShowToolsFor('m1'));
    expect('changed definition is visibly marked', /definition changed.*re-approve/i.test(await page.locator('.mcp-tool-row').innerText()));
    expect('schema is displayed for the reviewed definition', await page.locator('.mcp-tool-schema').count() === 1);
    await page.locator('.mcp-tool-row label').filter({ hasText: /^Enable$/ }).click(); await page.waitForTimeout(60);
    let c = (await app.calls('mcp_set_tool_state')).at(-1).args;
    ok('enable pins the DISPLAYED definition hash', c.expected_hash, 'hash-one');
    ok('changed tool never inherits Auto-approve', c.auto_approve, false);
    expect('fresh pins immediately expose the tool', await page.evaluate(() => mcpGetTools().some((t) => t.name === 'mcp__svc__echo')));
    ok('auto-approve toggle becomes usable after refresh', await page.locator('.mcp-tool-row input').nth(1).isDisabled(), false);
    await page.locator('.mcp-tool-row label').filter({ hasText: /^Auto-approve$/ }).click(); await page.waitForTimeout(60);
    c = (await app.calls('mcp_set_tool_state')).at(-1).args;
    ok('Auto-approve also binds the DISPLAYED hash', c.expected_hash, 'hash-one');
    await page.evaluate(() => { window.__stale = true; });
    const before = await app.count('mcp_set_tool_state');
    await page.locator('.mcp-tool-row label').filter({ hasText: /^Auto-approve$/ }).click(); await page.waitForTimeout(80);
    ok('stale approval is not silently retried', await app.count('mcp_set_tool_state'), before + 1);
    expect('stale approval reloads and shows new definition', /NEW definition to review/.test(await page.locator('.mcp-tool-row').innerText()));
    expect('stale approval requests re-review visibly', /review.*approve|re-approve/i.test(await page.locator('#mcpStatus').innerText()));
    await page.locator('.mcp-tool-row label').filter({ hasText: /^Enable$/ }).click(); await page.waitForTimeout(60);
    c = (await app.calls('mcp_set_tool_state')).at(-1).args;
    ok('fresh re-approval binds the new hash', c.expected_hash, 'hash-two');
    ok('fresh re-approval still turns Auto-approve OFF', c.auto_approve, false);
    await page.locator('.mcp-tool-row label').filter({ hasText: /^Enable$/ }).click(); await page.waitForTimeout(60);
    ok('disabling withdraws model exposure immediately', await page.evaluate(() => mcpGetTools().length), 0);
    ok('disabling clears and disables Auto-approve in UI', await page.locator('.mcp-tool-row input').nth(1).isDisabled(), true);
  });
  await fixture(browser, server, 'MCP exposed names, strict URL classifier and unknown-command detection', async (app) => {
    const { page } = app;
    await page.evaluate(() => { window.__replies.mcp_list_servers[0].tools[0].name = 'long_tool_name_'.repeat(8); window.__replies.mcp_list_servers[0].tools[0].exposed_name = 'mcp__svc__long_tool_name_12345678'; return mcpRefresh(); });
    const name = 'mcp__svc__long_tool_name_12345678';
    ok('model sees canonical exposed_name', await page.evaluate(() => mcpGetTools().map((t) => t.name)), [name]);
    ok('canonical exposed_name resolves to the real tool', await page.evaluate((n) => mcpToolInfo(n).toolName, name), 'long_tool_name_'.repeat(8));
    await settings(page); await page.click('#mcpAddBtn');
    for (const [url, allowed] of [
      ['http://localhost:9999/mcp', true], ['http://127.0.0.2/mcp', true], ['http://127.255.255.254/mcp', true], ['http://[::1]/mcp', true],
      ['http://sub.localhost/mcp', false], ['http://10.0.0.1/mcp', false], ['http://192.168.1.1/mcp', false], ['http://[fc00::1]/mcp', false],
      ['http://example.test/mcp', false], ['https://example.test/mcp', true], ['ftp://example.test/mcp', false], ['not a URL', false],
      ['https://example.test/mcp?route=one', false], ['https://example.test/mcp#part', false], ['https://u:fixture@x.test/mcp', false],
    ]) {
      await page.fill('#mcpUrl', url);
      ok('MCP URL classification ' + url, !(await page.locator('#mcpUrlError').isVisible()), allowed);
      ok('MCP URL invalid state tracks validity ' + url, await page.locator('#mcpUrl').getAttribute('aria-invalid'), allowed ? 'false' : 'true');
    }
    await page.fill('#mcpUrl', 'https://example.test/mcp?q=fixture');
    expect('unsupported query is explicitly explained', /query|fragment/i.test(await page.locator('#mcpUrlError').innerText()));
    await page.evaluate(() => { window.__replies.mcp_list_servers = { $reject: 'missing field auth_type' }; return mcpLoadSettings(); });
    expect('missing-field error does NOT claim missing MCP backend', !/no MCP support/i.test(await page.locator('#mcpStatus').innerText()));
    await page.evaluate(() => { window.__replies.mcp_list_servers = { $reject: 'no such table: mcp_servers' }; return mcpLoadSettings(); });
    expect('DB error does NOT disable MCP support', !/no MCP support/i.test(await page.locator('#mcpStatus').innerText()));
    await page.evaluate(() => { window.__replies.mcp_list_servers = []; return mcpLoadSettings(); });
    expect('refresh can recover from a data/DB error', /No MCP servers/.test(await page.locator('#mcpServerList').innerText()));
    await page.evaluate(() => { window.__replies.mcp_list_servers = { $reject: 'Command mcp_list_servers not found' }; return mcpLoadSettings(); });
    expect('ONLY the Tauri unknown-command rejection means no MCP support', /no MCP support/i.test(await page.locator('#mcpStatus').innerText()));
  });
  await fixture(browser, server, 'MCP busy controls and failure/removal warnings', async (app) => {
    const { page } = app; await settings(page); await page.click('#mcpAddBtn');
    await page.fill('#mcpName', 'new-service'); await page.fill('#mcpUrl', 'https://new.example.test/mcp');
    await hold(page, 'mcp_save_server');
    await page.evaluate(() => { mcpSaveServer(); mcpSaveServer(); }); await page.waitForTimeout(40);
    ok('double Save sends one request', await app.count('mcp_save_server'), 1);
    ok('Save is busy and disabled', await page.locator('#mcpSaveBtn').isDisabled(), true);
    ok('Save announces busy', await page.locator('#mcpSaveBtn').getAttribute('aria-busy'), 'true');
    await page.evaluate(() => mcpUrlCheck());
    ok('URL validation does not re-enable busy Save', await page.locator('#mcpSaveBtn').isDisabled(), true);
    await letGo(page, 'mcp_save_server'); await page.waitForTimeout(60);
    await hold(page, 'mcp_test_connection');
    await page.evaluate(() => { mcpTestConnection('m1'); mcpTestConnection('m1'); }); await page.waitForTimeout(40);
    ok('double Test sends once', await app.count('mcp_test_connection'), 1);
    expect('row Test/Remove are disabled while testing', await page.locator('.mcp-server-row button').filter({ hasText: /Test|Remove/ }).evaluateAll((bs) => bs.every((b) => b.disabled)));
    await page.evaluate(() => { window.__replies.mcp_test_connection = { $reject: '<img> fixture connection failed' }; });
    await letGo(page, 'mcp_test_connection'); await page.waitForTimeout(80);
    expect('test failure is visible beside its row', /fixture connection failed/.test(await page.locator('.mcp-server-row').innerText()));
    ok('error text creates no HTML', await page.locator('.mcp-server-row img').count(), 0);
    await page.evaluate(() => { window.__replies.mcp_remove_server = { ok: true, warning: '<b> fixture teardown failed' }; });
    await page.locator('.mcp-server-row button').filter({ hasText: /^Remove$/ }).click(); await answerConfirm(page, 'ok'); await page.waitForTimeout(60);
    expect('successful removal still shows teardown warning', /fixture teardown failed/.test(await page.locator('#mcpStatus').innerText()));
    ok('warning creates no HTML', await page.locator('#mcpStatus b').count(), 0);
  });
}

async function providerChecks(browser, server) {
  await fixture(browser, server, 'Provider presets, saved-key removal, reuse confirmation and dirty reload', async (app) => {
    const { page } = app; await settings(page);
    await page.selectOption('#aiProvider', 'anthropic'); await page.selectOption('#aiBaseUrlPreset', 'http://localhost:11434/v1');
    ok('Ollama preset sets provider', await page.inputValue('#aiProvider'), 'openai');
    ok('Ollama preset sets URL', await page.inputValue('#aiBaseUrl'), 'http://localhost:11434/v1');
    await page.selectOption('#aiBaseUrlPreset', 'https://api.anthropic.com');
    ok('Anthropic preset sets provider', await page.inputValue('#aiProvider'), 'anthropic');
    ok('Anthropic preset sets URL placeholder', await page.locator('#aiBaseUrl').getAttribute('placeholder'), 'https://api.anthropic.com');
    await page.fill('#aiModel', 'unsaved fixture model');
    await page.evaluate(() => { window.__load = aiLoadConfig(); });
    const asked = await answerConfirm(page, 'cancel');
    expect('dirty reload asks before discarding', asked);
    await page.evaluate(() => window.__load);
    ok('Cancel preserves dirty model', await page.inputValue('#aiModel'), 'unsaved fixture model');
    await page.evaluate(() => { window.__load = aiLoadConfig(); });
    if (await waitVisible(page, '#confirmModal', 500)) await answerConfirm(page, 'ok');
    await page.evaluate(() => window.__load);
    await page.fill('#aiBaseUrl', 'https://new-provider.example.test/v1');
    await page.evaluate(() => { window.__replies.assistant_save_config = (a) => {
      if (!a.reuseKeyAtNewOrigin) throw 'The provider or base URL changed but no new API key was entered - enter the key for the new endpoint, or confirm reusing the stored key there.';
      return { ok: true };
    }; });
    await page.click('#aiSaveBtn'); const confirm = await answerConfirm(page, 'cancel'); expect('reuse is opt-in, not silent', confirm); await page.waitForTimeout(40);
    ok('Cancel sends no confirmed reuse', (await app.calls('assistant_save_config')).filter((x) => x.args.reuseKeyAtNewOrigin).length, 0);
    await page.click('#aiSaveBtn'); if (await waitVisible(page, '#confirmModal', 500)) await answerConfirm(page, 'ok'); await page.waitForTimeout(60);
    ok('confirmed retry explicitly attests reuse', (await app.calls('assistant_save_config')).at(-1).args.reuseKeyAtNewOrigin, true);
    const remove = page.locator('#aiRemoveKeyBtn'); ok('Remove stored key exists', await remove.count(), 1);
    if (await remove.count()) {
      await page.evaluate(() => { window.__replies.assistant_save_config = { ok: true }; });
      await remove.click(); if (await waitVisible(page, '#confirmModal', 500)) await answerConfirm(page, 'ok'); await page.waitForTimeout(50);
      ok('Remove stored key sends clearApiKey=true', (await app.calls('assistant_save_config')).at(-1).args.clearApiKey, true);
    }
    expect('provider strings are complete (no [OI] placeholder)', !/\[OI\]/.test(await page.locator('.settings-section[data-section="assistant"]').innerText()));
    expect('complete model placeholder', !/\/\s*$/.test(await page.locator('#aiModel').getAttribute('placeholder')));
  });
  await fixture(browser, server, 'Save & test uses visible values; errors once, input restored, setup link', async (app) => {
    const { page } = app; await settings(page); await page.fill('#aiModel', 'visible-model');
    await page.fill('#aiApiKey', 'fixture-only-entered-value');
    await hold(page, 'assistant_test_connection'); await page.click('#aiTestBtn'); await page.waitForTimeout(50);
    const save = (await app.calls('assistant_save_config')).at(-1);
    ok('test saves visible form FIRST', save && save.args.model, 'visible-model');
    ok('API key travels only in its IPC field', save && save.args.apiKey, 'fixture-only-entered-value');
    ok('successful save clears secret input', await page.inputValue('#aiApiKey'), '');
    ok('test button is disabled while testing', await page.locator('#aiTestBtn').isDisabled(), true);
    expect('progress is visible in aiStatus', /test|connect/i.test(await page.locator('#aiStatus').innerText()));
    await page.evaluate(() => { window.__replies.assistant_test_connection = { detail: 'Connected to visible-model.' }; });
    await letGo(page, 'assistant_test_connection'); await page.waitForTimeout(60);
    expect('connection result is persistent in aiStatus', /Connected to visible-model/.test(await page.locator('#aiStatus').innerText()));
    expect('API key is never rendered in status/toasts', !(await page.locator('#aiStatus').innerText()).includes('fixture-only-entered-value') && !(await toasts(page)).join(' ').includes('fixture-only-entered-value'));
    const id = await panel(app);
    await page.evaluate(() => { window.__replies.assistant_chat = { $reject: 'Provider error (400). {"error":{"message":"fixture bad model","secret":"not-for-display"}}' }; });
    await send(page, 'retry this text'); await idle(page);
    expect('provider error JSON is reduced to its message', /fixture bad model/.test(await transcript(page)) && !(await transcript(page)).includes('not-for-display'));
    ok('failed send restores input', await page.inputValue('#assistantInput'), 'retry this text');
    ok('provider error is NOT duplicated as a toast', (await toasts(page)).filter((x) => x.includes('fixture bad model')).length, 0);
    await page.evaluate(() => { window.__replies.assistant_chat = { $reject: 'AI assistant is not configured - open Settings > AI assistant.' }; });
    await send(page); await idle(page);
    const setup = page.locator('#assistantMessages button').filter({ hasText: /Set up the assistant|Open assistant settings/ });
    expect('not-configured error includes a working setup action', await setup.count() > 0);
    if (await setup.count()) { await setup.last().click(); await page.waitForTimeout(50); expect('setup action opens assistant settings', await page.locator('.settings-section[data-section="assistant"]').isVisible()); }
  });
}

async function lockedSettingsChecks(browser, server) {
  await fixture(browser, server, 'Locked vault disables assistant and MCP write actions', async (app) => {
    const { page } = app;
    const read = () => page.evaluate(() => {
      const rowButtons = [...document.querySelectorAll('.mcp-server-row button')].filter((b) => /^(Test connection|Remove)$/.test(b.textContent));
      return {
        save: document.getElementById('aiSaveBtn').disabled,
        test: document.getElementById('aiTestBtn').disabled,
        add: document.getElementById('mcpAddBtn').disabled,
        rowActions: rowButtons.length > 0 && rowButtons.every((b) => b.disabled),
        toggles: [...document.querySelectorAll('.mcp-tool-row input')].every((i) => i.disabled),
      };
    });
    await page.evaluate(() => { window.__backend.unlocked = false; return refreshVaultStatus(); });
    await page.waitForTimeout(60);
    await settings(page); await page.evaluate(() => mcpShowToolsFor('m1'));
    ok('locked: write actions are disabled (fail closed)', await read(), { save: true, test: true, add: true, rowActions: true, toggles: true });
    await page.evaluate(() => { window.__backend.unlocked = true; return refreshVaultStatus(); });
    await page.waitForTimeout(80);
    ok('unlocked: the same actions work again', await read(), { save: false, test: false, add: false, rowActions: false, toggles: false });
  });
}

async function setupChecks(browser, server) {
  await fixture(browser, server, 'First open without a provider shows the setup card', async (app) => {
    const { page } = app; await panel(app);
    await page.waitForTimeout(80);
    ok('setup card is shown', await page.locator('#assistantSetup').isVisible(), true);
    await page.click('#assistantSetupBtn'); await page.waitForTimeout(120);
    ok('its button opens the assistant settings', await page.locator('.settings-section[data-section="assistant"]').isVisible(), true);
    expect('showing the section loads the form', (await app.count('assistant_get_config')) >= 2);
    expect('showing the section loads the MCP list', (await app.count('mcp_list_servers')) >= 2);
  }, { replies: { assistant_get_config: { provider: null, base_url: null, model: null, has_api_key: false } } });
  await fixture(browser, server, 'Any path to the section loads it; configured panel has no setup card', async (app) => {
    const { page } = app; await panel(app); await page.waitForTimeout(80);
    ok('configured: no setup card', await page.locator('#assistantSetup').isVisible(), false);
    const cfg = await app.count('assistant_get_config'); const list = await app.count('mcp_list_servers');
    await page.evaluate(async () => { await switchView('settings'); showSettingsSection('general'); showSettingsSection('assistant'); });
    await page.waitForTimeout(80);
    expect('palette-style showSettingsSection loads the form', (await app.count('assistant_get_config')) > cfg);
    expect('and the MCP list', (await app.count('mcp_list_servers')) > list);
  });
}

async function panelChecks(browser, server) {
  await fixture(browser, server, 'Panel accessibility, markdown and maximize overlap', async (app) => {
    const { page } = app; const id = await panel(app);
    ok('transcript role', await page.locator('#assistantMessages').getAttribute('role'), 'log');
    ok('transcript is announced politely', await page.locator('#assistantMessages').getAttribute('aria-live'), 'polite');
    ok('thinking is status', await page.locator('#assistantThinking').getAttribute('role'), 'status');
    expect('textarea has a real accessible label', !!(await page.locator('#assistantInput').getAttribute('aria-label')));
    ok('panel toggle reflects open state', await page.locator('#assistantToggleBtn').getAttribute('aria-pressed'), 'true');
    ok('access levels are a radiogroup', await page.locator('#assistantLevelSeg').getAttribute('role'), 'radiogroup');
    ok('each level is a radio, not a tab', await page.locator('#assistantLevelSeg button').evaluateAll((bs) => bs.map((b) => b.getAttribute('role'))), ['radio', 'radio', 'radio', 'radio']);
    ok('radio state and tab stops are consistent', await page.locator('#assistantLevelSeg button').evaluateAll((bs) => bs.map((b) => [b.getAttribute('aria-checked'), b.tabIndex])), [['true', 0], ['false', -1], ['false', -1], ['false', -1]]);
    await page.focus('#assistantLevelSeg [data-level="read"]'); await page.keyboard.press('ArrowRight');
    ok('arrow moves radio focus without selecting YOLO/level', await page.evaluate(() => document.activeElement.dataset.level), 'draft');
    await page.keyboard.press('Enter'); await page.waitForTimeout(40);
    ok('manual activation commits Draft', await page.locator('#assistantLevelSeg [data-level="draft"]').getAttribute('aria-checked'), 'true');
    await page.evaluate((t) => aiSetLevel(t, 'yolo'), id);
    expect('YOLO dialog names server and host', /web-1/.test(await page.locator('#yoloModal').innerText()) && /10\.0\.0\.1/.test(await page.locator('#yoloModal').innerText()));
    expect('YOLO alertdialog has a description', !!(await page.locator('#yoloModal [role="alertdialog"]').getAttribute('aria-describedby')));
    await page.keyboard.press('Escape'); ok('Escape still fails closed', await app.open('yoloModal'), false);
    for (const [w, h] of [[880, 560], [1100, 720], [1600, 1000]]) {
      await page.setViewportSize({ width: w, height: h }); await page.waitForTimeout(60);
      ok('Send is not intercepted at ' + w + 'x' + h, await page.evaluate(() => { const b = document.getElementById('assistantSendBtn'); const r = b.getBoundingClientRect(); const hit = document.elementFromPoint(r.x + r.width / 2, r.y + r.height / 2); return !!hit && (hit === b || b.contains(hit)); }), true);
    }
    await page.setViewportSize({ width: 1600, height: 1000 });
    await page.waitForTimeout(300);
    expect('A1-03 docked beside a >=60-column terminal on a wide window', await page.evaluate((t) =>
      getComputedStyle(document.getElementById('assistantPanel')).position === 'static' && window.tabRecord(t).term.cols >= 60, id));
    await page.setViewportSize({ width: 1100, height: 720 });
    await page.waitForTimeout(200);
    expect('A1-03 terminal retains >=60 columns OR assistant overlays at default width', await page.evaluate((t) =>
      window.tabRecord(t).term.cols >= 60 || getComputedStyle(document.getElementById('assistantPanel')).position === 'absolute', id));
    await page.evaluate(() => { document.getElementById('sessionSurface').classList.add('split'); document.getElementById('sftpBody').classList.add('visible'); });
    for (const width of [1100, 1600]) {
      await page.setViewportSize({ width, height: 720 }); await page.waitForTimeout(60);
      expect('A1-03 Split assistant controls fit viewport at ' + width, await page.evaluate(() =>
        [...document.querySelectorAll('#assistantLevelSeg button, #assistantSendBtn')].every((b) => {
          const r = b.getBoundingClientRect(); return r.width >= 24 && r.x >= 0 && r.right <= innerWidth && r.y >= 0 && r.bottom <= innerHeight;
        })));
    }
    await page.evaluate(() => { document.getElementById('sessionSurface').classList.remove('split'); document.getElementById('sftpBody').classList.remove('visible'); });
    await page.evaluate((t) => aiAppendMsg(t, 'assistant', '1. first\n2. second\n```bash\nls -la /tmp/*.log\n```\nuse *.log and *.txt; *real italic* and **bold** <img>'), id);
    ok('numbered steps render an ordered list', await page.locator('.ai-msg.assistant ol li').count(), 2);
    ok('fenced code drops only language header', await page.locator('.ai-msg.assistant pre code').last().textContent(), 'ls -la /tmp/*.log\n');
    await page.evaluate((t) => aiAppendMsg(t, 'assistant', 'Run this:\n```pwd\n```'), id);
    expect('a one-line block keeps its only line (not taken for a language tag)',
      /pwd/.test(await page.locator('.ai-msg.assistant pre code').last().textContent()));
    expect('glob stars survive inline markdown', /use \*\.log and \*\.txt/.test(await transcript(page)));
    ok('real emphasis still renders', await page.locator('.ai-msg.assistant em').last().textContent(), 'real italic');
    ok('markdown never inserts HTML', await page.locator('#assistantMessages img').count(), 0);
    await settings(page);
    ok('API key stored hint is described', await page.locator('#aiApiKey').getAttribute('aria-describedby'), 'aiKeyHint');
    await page.click('#mcpAddBtn'); await page.selectOption('#mcpAuthType', 'bearer');
    ok('MCP stored-secret hint is described', await page.locator('#mcpAuthSecret').getAttribute('aria-describedby'), 'mcpSecretHint');
    ok('URL error announces alert', await page.locator('#mcpUrlError').getAttribute('role'), 'alert');
    expect('preset has a separate label', !(await page.locator('#aiBaseUrl').evaluate((n) => n.closest('label')?.contains(document.getElementById('aiBaseUrlPreset')))));
    ok('MCP URL placeholder is Streamable HTTP', await page.locator('#mcpUrl').getAttribute('placeholder'), 'https://mcp.example.com/mcp');
  });
}

(async () => {
  const chromium = loadChromium();
  if (!chromium) { console.error('Playwright is required for test:assistant; no silent skip.'); process.exit(1); }
  const server = await serve(rendererDir()); const browser = await chromium.launch({ headless: true });
  try {
    for (const fn of [approvalChecks, typingChecks, historyChecks, lifecycleChecks, mcpSettingsChecks, providerChecks, lockedSettingsChecks, setupChecks, panelChecks]) {
      // ASSISTANT_ONLY=<group> runs one group while iterating; CI runs all.
      if (process.env.ASSISTANT_ONLY && fn.name !== process.env.ASSISTANT_ONLY) continue;
      console.log('\n' + fn.name); await fn(browser, server);
    }
  } finally { await browser.close(); await new Promise((r) => server.close(r)); }
  console.log(`\nAssistant UI: ${passed} ok, ${failures.length} FAIL.`);
  if (failures.length) process.exitCode = 1;
})().catch((e) => { console.error(e); process.exitCode = 1; });
