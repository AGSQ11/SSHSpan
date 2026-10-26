#!/usr/bin/env node
/* Real-page assistant/MCP regression evals. No provider, SSH host or secrets.
 * Each scenario gets a fresh app from the shared renderer harness. The stub
 * records actual IPC; these checks never reimplement renderer algorithms.
 * SSHSPAN_RENDERER_DIR can point at the captured baseline for RED evidence.
 *
 * The stub answers like the backend: an MCP save comes back with `confirmed`
 * (a credential bound to a new place is asked about in a NATIVE dialog the
 * page cannot answer - declined, the server stays switched off and `warning`
 * says why), and a move of the stored API key to another address is asked
 * about the same way (declined, the save is refused with the backend's text).
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
// Names an MCP server chooses, holding a text-direction override and a
// zero-width space, and how the renderer must show them. The characters are
// built from their code points, so this file holds none of them itself.
const RLO = String.fromCodePoint(0x202E);
const ZWSP = String.fromCodePoint(0x200B);
const FSI = String.fromCodePoint(0x2068);
const PDI = String.fromCodePoint(0x2069);
const RLO_TOOL = 'echo' + RLO + 'txt.exe';
const RLO_SHOWN = 'echo<U+202E>txt.exe';
const ZWSP_DISPLAY = 'Ec' + ZWSP + 'ho';
const ZWSP_SHOWN = 'Ec<U+200B>ho';
// A server's own name is checked when it is saved, not when a backup restores it.
const RESTORED_SERVER = 'svc' + RLO + 'x';
const RESTORED_SHOWN = 'svc<U+202E>x';
// One a save accepts - a token once trimmed - whose tool names would be the
// first one's (both sanitize to svc_x).
const PADDED_SERVER = 'svc-x' + String.fromCodePoint(0xA0);
const PADDED_SHOWN = 'svc-x<U+00A0>';
// Nor are the URL, the custom header's name and the name of the environment
// variable a token comes from: a save normalizes the URL and checks the rest.
const RESTORED_URL = 'https://mcp.example.test/m' + RLO + 'cp';
const RESTORED_URL_SHOWN = 'https://mcp.example.test/m<U+202E>cp';
const RESTORED_HEADER = 'X-Fixture' + RLO + 'Key';
const RESTORED_ENV = 'FIXTURE' + RLO + '_TOKEN';
const RESTORED_ENV_SHOWN = 'FIXTURE<U+202E>_TOKEN';
const hidesAny = (text) => text.includes(RLO) || text.includes(ZWSP);
const SPELLED_MCP = (name = 'svc') => MCP({ name, tools: [TOOL({ name: RLO_TOOL, display_name: ZWSP_DISPLAY, exposed_name: 'mcp__svc__echo_txt_exe' })] });
// Argument names a server may choose for anything - credential-looking ones
// included - with the values the user must see on the approval card.
const FULL_ARGS = {
  text: 'hello', password: 'fixture-sensitive-value', page_token: 'fixture-page-token-value',
  tokens: 'fixture-tokens-value', max_tokens: 'fixture-max-tokens-value', credentials_file: 'fixture-credentials-file-value',
};
const FULL_ARG_VALUES = Object.values(FULL_ARGS);
// The backend's own words (src-tauri/src/assistant/mcp.rs settle_binding,
// assistant/mod.rs save_config_confirmed, commands CREDENTIAL_QUESTION_OPEN).
const DECLINED = (host) => 'The server was saved but stays switched off, because sending its credential to '
  + host + ' was not allowed. Save it again to be asked again.';
const KEY_MOVE_DECLINED = 'Enter the API key for the new address.';
const KEY_MOVE_CHANGED = 'The assistant settings changed while you were deciding - save them again.';
const KEY_MOVE_TOO_QUICK = 'The question about sending the stored API key was answered within a second of opening - too fast to be a decision. Save again to be asked again.';
const QUESTION_OPEN = 'Another question about sending a credential is still open - answer it, then save again.';
// mcp_save_server's refusals (src-tauri/src/assistant/mcp.rs check_save_fields, save_server,
// check_env_var_name).
const NAME_RULE = "Server name must be non-empty and use only letters, digits and ! # $ % & ' * + - . ^ _ ` | ~ (no spaces).";
const NAME_TAKEN = (other, name) => "An MCP server named '" + other + "' already exists and '" + name
  + "' would share its model-facing tool names - choose a different name.";
const ENV_RULE = "The environment variable name must be 1 to 128 visible ASCII characters, without spaces or '='.";
// What a connect says when the variable a bearer token comes from is not set (resolve_secret_value).
const ENV_UNSET = (name) => "Environment variable '" + name + "' (MCP auth for header 'Authorization') is not set.";
// What a server row says while its credential is not allowed yet.
const NOT_CONFIRMED = 'Not confirmed - SSHSpan will not send this credential until you allow it';
const MCP_SAVED_NOT_CONFIRMED_TEXT = 'Saved, but not confirmed - SSHSpan will not send its credential until you allow it.';
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
        // Plain saves, shaped like the backend's answers (a scenario that
        // needs the native question installs emulateCredentialQuestion).
        if (!('mcp_save_server' in window.__replies)) {
          window.__replies.mcp_save_server = (a) => ({ ok: true, id: a.id || 'm-new', warning: null, confirmed: true });
        }
        if (!('assistant_save_config' in window.__replies)) window.__replies.assistant_save_config = { ok: true, warning: null };
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
/// A stand-in for the backend's mcp_save_server and the native question it
/// asks (binding_needs_confirmation / settle_binding): a save that binds a
/// credential to a place it was not confirmed for is asked about, and the
/// user's answer is window.__answer ('allow' or anything else for "Don't
/// allow"). The questions asked are counted in window.__asked; the records
/// live in window.__registry, which mcp_list_servers serves.
async function emulateCredentialQuestion(page, registry) {
  await page.evaluate((reg) => {
    window.__registry = reg;
    window.__asked = [];
    window.__answer = 'deny';
    window.__replies.mcp_list_servers = () => structuredClone(window.__registry);
    window.__replies.mcp_save_server = (a) => {
      const at = window.__registry.findIndex((s) => s.id === a.id);
      const prev = at >= 0 ? window.__registry[at] : null;
      const rec = Object.assign({
        id: 'm-new', status: 'unknown', has_secret: false, auth_env_var: null, auth_header_name: null,
        protocol_version: null, loopback_insecure: false, tool_count: 0, tools: [],
      }, structuredClone(prev || {}), { name: a.name, url: a.url, auth_type: a.auth_type });
      if (a.auth_header_name != null) rec.auth_header_name = a.auth_header_name;
      if (a.auth_secret) { rec.has_secret = true; rec.auth_env_var = null; }
      if (a.auth_env_var) { rec.auth_env_var = a.auth_env_var; rec.has_secret = false; }
      const sends = rec.auth_type !== 'none' && (rec.has_secret || !!rec.auth_env_var);
      const sameAsConfirmed = !!prev && prev.confirmed && prev.url === rec.url
        && (!a.auth_env_var || a.auth_env_var === prev.auth_env_var);
      const asks = sends && !sameAsConfirmed;
      let warning = null;
      rec.confirmed = !asks;
      if (asks) {
        window.__asked.push(rec.url);
        if (window.__answer === 'allow') rec.confirmed = true;
        else warning = 'The server was saved but stays switched off, because sending its credential to '
          + new URL(rec.url).hostname + ' was not allowed. Save it again to be asked again.';
      }
      if (at >= 0) window.__registry[at] = rec; else window.__registry.push(rec);
      return { ok: true, id: rec.id, warning, confirmed: rec.confirmed };
    };
  }, registry);
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
        // from the user's own Send must not approve (A4-24).
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
        // server-chosen names must not hide anything (R6).
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
    expect('unconfirmed entry is visibly inert', (await page.locator('.mcp-server-row').innerText()).includes(NOT_CONFIRMED));
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
    // binding, and the form says so instead of refusing (A4-07).
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
  await fixture(browser, server, 'Provider presets, saved-key removal, the native key-move question and dirty reload', async (app) => {
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
    // A new address and no new key: the backend asks in a NATIVE dialog
    // whether the stored key may go there - the page can neither show that
    // question nor answer it. Declined, the save is refused with its text.
    await page.fill('#aiBaseUrl', 'https://new-provider.example.test/v1');
    await page.evaluate((m) => { window.__replies.assistant_save_config = () => { throw m; }; }, KEY_MOVE_DECLINED);
    const saves = await app.count('assistant_save_config');
    await page.click('#aiSaveBtn'); await page.waitForTimeout(80);
    ok('the renderer asks no key question of its own', [await app.open('confirmModal'), await page.evaluate(() => window.__nativeDialogCalls)], [false, 0]);
    ok('one save request, never resent with a flag', await app.count('assistant_save_config'), saves + 1);
    const sent = (await app.calls('assistant_save_config')).at(-1).args;
    ok('no renderer flag claims the key may move', Object.prototype.hasOwnProperty.call(sent, 'reuseKeyAtNewOrigin'), false);
    ok('the refusal is shown as the backend says it', (await page.textContent('#aiStatus')).trim(), KEY_MOVE_DECLINED);
    for (const refusal of [KEY_MOVE_TOO_QUICK, KEY_MOVE_CHANGED, QUESTION_OPEN]) {
      await page.evaluate((m) => { window.__replies.assistant_save_config = () => { throw m; }; }, refusal);
      await page.click('#aiSaveBtn'); await page.waitForTimeout(60);
      ok('shown as it is: ' + refusal.slice(0, 40), (await page.textContent('#aiStatus')).trim(), refusal);
    }
    ok('none of them opened a question in the page', await app.open('confirmModal'), false);
    // Allowed in the native dialog: the save goes through like any other.
    await page.evaluate(() => { window.__replies.assistant_save_config = { ok: true, warning: null }; });
    await page.click('#aiSaveBtn'); await page.waitForTimeout(80);
    ok('allowed there, it is saved', (await page.textContent('#aiStatus')).trim(), 'Saved.');
    ok('still without a flag', (await app.calls('assistant_save_config')).some((x) => Object.prototype.hasOwnProperty.call(x.args, 'reuseKeyAtNewOrigin')), false);
    // The backend stores the address as it parsed it (lowercase host, no
    // default port, no trailing slash); the form shows what was stored.
    await page.evaluate(() => {
      window.__replies.assistant_save_config = () => { window.__storedUrl = 'https://new-provider.example.test/v1'; return { ok: true, warning: null }; };
      window.__replies.assistant_get_config = () => ({ provider: 'openai', base_url: window.__storedUrl || 'https://api.openai.com/v1', model: 'fixture-model', has_api_key: true });
    });
    await page.fill('#aiBaseUrl', 'HTTPS://New-Provider.Example.TEST:443/v1/');
    await page.click('#aiSaveBtn'); await page.waitForTimeout(100);
    ok('after a save the form shows the address as stored', await page.inputValue('#aiBaseUrl'), 'https://new-provider.example.test/v1');
    const remove = page.locator('#aiRemoveKeyBtn'); ok('Remove stored key exists', await remove.count(), 1);
    if (await remove.count()) {
      await page.evaluate(() => { window.__replies.assistant_save_config = { ok: true, warning: null }; });
      await remove.click(); if (await waitVisible(page, '#confirmModal', 500)) await answerConfirm(page, 'ok'); await page.waitForTimeout(50);
      const removal = (await app.calls('assistant_save_config')).at(-1).args;
      ok('Remove stored key sends clearApiKey=true and no reuse flag', [removal.clearApiKey, Object.prototype.hasOwnProperty.call(removal, 'reuseKeyAtNewOrigin')], [true, false]);
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
      const allow = [...document.querySelectorAll('.mcp-server-row button')].filter((b) => /^Allow sending/.test(b.textContent));
      return {
        save: document.getElementById('aiSaveBtn').disabled,
        test: document.getElementById('aiTestBtn').disabled,
        add: document.getElementById('mcpAddBtn').disabled,
        rowActions: rowButtons.length > 0 && rowButtons.every((b) => b.disabled),
        allow: allow.length > 0 && allow.every((b) => b.disabled),
        toggles: [...document.querySelectorAll('.mcp-tool-row input')].every((i) => i.disabled),
      };
    });
    await page.evaluate(() => { window.__backend.unlocked = false; return refreshVaultStatus(); });
    await page.waitForTimeout(60);
    await settings(page); await page.evaluate(() => mcpShowToolsFor('m1'));
    ok('locked: write actions are disabled (fail closed)', await read(), { save: true, test: true, add: true, rowActions: true, allow: true, toggles: true });
    await page.evaluate(() => { window.__backend.unlocked = true; return refreshVaultStatus(); });
    await page.waitForTimeout(80);
    ok('unlocked: the same actions work again', await read(), { save: false, test: false, add: false, rowActions: false, allow: false, toggles: false });
  }, { replies: { mcp_list_servers: [MCP(), MCP({ id: 'm2', name: 'svc2', auth_type: 'bearer', has_secret: true, confirmed: false })] } });
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

async function mcpConfirmChecks(browser, server) {
  // A server record without `confirmed: true` is not confirmed, on the rows
  // as in a save's answer: one rule everywhere (fail closed).
  await fixture(browser, server, 'A server row without `confirmed` reads not confirmed', async (app) => {
    const { page } = app;
    await page.evaluate(() => {
      const record = Object.assign({}, window.__replies.mcp_list_servers[0], { auth_type: 'bearer', has_secret: true });
      delete record.confirmed;
      window.__replies.mcp_list_servers = [record];
    });
    await settings(page);
    const row = await page.locator('.mcp-server-row').first().innerText();
    expect('10 a row whose record says nothing of `confirmed` reads not confirmed', row.includes(NOT_CONFIRMED));
    ok('10 and offers to allow sending', await page.locator('.mcp-server-row button').filter({ hasText: /^Allow sending/ }).count(), 1);
    ok('no page errors so far', app.errors, []);
  });
  await fixture(browser, server, 'An MCP save the native question did not allow: the row says so and asks again', async (app) => {
    const { page } = app;
    await emulateCredentialQuestion(page, [MCP({ auth_type: 'bearer', has_secret: true })]);
    await settings(page);
    await page.locator('.mcp-server-row button').filter({ hasText: /^Edit$/ }).click();
    await page.fill('#mcpUrl', 'https://other.example.test/mcp');
    await page.fill('#mcpAuthSecret', 'fixture-new-secret');
    await page.click('#mcpSaveBtn'); await page.waitForTimeout(100);
    ok('the page asks no credential question of its own', [await app.open('confirmModal'), await page.evaluate(() => window.__nativeDialogCalls)], [false, 0]);
    ok('one save, one native question', [await app.count('mcp_save_server'), await page.evaluate(() => window.__asked.length)], [1, 1]);
    const declined = DECLINED('other.example.test');
    ok('why it stays off is shown as the backend says it', (await page.textContent('#mcpStatus')).trim(), declined);
    const shown = await toasts(page);
    expect('as a warning, never as "saved"', shown.includes(declined) && !shown.some((x) => /^MCP server saved/.test(x)));
    const row = page.locator('.mcp-server-row').first();
    expect('the row says the credential is not sent until it is allowed', (await row.innerText()).includes(NOT_CONFIRMED));
    expect('without the old backup-only explanation', !/Restored from a backup/i.test(await row.evaluate((r) => r.outerHTML)));
    const allow = () => page.locator('.mcp-server-row button').filter({ hasText: /^Allow sending/ });
    ok('the row offers a way to be asked again', await allow().count(), 1);
    // Asked again: the stored settings unchanged, nothing typed - the backend
    // keeps the stored credential and asks its question again.
    await hold(page, 'mcp_save_server');
    await allow().click();
    await page.waitForTimeout(60);
    expect('while the question is open the row is busy', await page.locator('.mcp-server-row').first().evaluate((r) =>
      r.getAttribute('aria-busy') === 'true' && [...r.querySelectorAll('.mcp-server-actions button')].every((b) => b.disabled)));
    expect('and the status line says what it waits for', /answer/i.test(await page.textContent('#mcpStatus')));
    await page.evaluate(() => { const b = [...document.querySelectorAll('.mcp-server-row button')].find((x) => /^Allow sending/.test(x.textContent)); if (b) b.click(); });
    await letGo(page, 'mcp_save_server'); await page.waitForTimeout(100);
    const calls = await app.calls('mcp_save_server');
    ok('a second click meanwhile asks nothing more', calls.length, 2);
    ok('asking again re-saves the stored settings and keeps the credential', calls.at(-1).args, {
      id: 'm1', name: 'svc', url: 'https://other.example.test/mcp', auth_type: 'bearer',
      auth_header_name: null, auth_secret: null, auth_env_var: null,
    });
    ok('declined again: said as it is', (await page.textContent('#mcpStatus')).trim(), declined);
    ok('and the row still offers it', await allow().count(), 1);
    await page.evaluate(() => { window.__answer = 'allow'; });
    await allow().click(); await page.waitForTimeout(100);
    const after = await page.locator('.mcp-server-row').first().innerText();
    expect('allowed: the row no longer says it is not confirmed', !/not confirmed/i.test(after));
    ok('and offers nothing to allow', await allow().count(), 0);
    expect('the confirmation is said', (await toasts(page)).some((x) => /is confirmed/i.test(x)));
    ok('no page dialog at any point', await page.evaluate(() => window.__nativeDialogCalls), 0);
  });
  await fixture(browser, server, 'Not-confirmed MCP servers: with and without a credential, and every answer shape', async (app) => {
    const { page } = app;
    await emulateCredentialQuestion(page, [
      MCP({ confirmed: false }),
      MCP({ id: 'm2', name: 'env-svc', auth_type: 'bearer', auth_env_var: 'FIXTURE_TOKEN', confirmed: false }),
    ]);
    await settings(page);
    const plain = page.locator('.mcp-server-row').nth(0);
    const plainText = await plain.innerText();
    expect('a server without a credential says it is not confirmed', /not confirmed/i.test(plainText));
    expect('and that Edit and Save switch it on', /Edit/.test(plainText) && /save/i.test(plainText));
    expect('without credential wording', !plainText.includes(NOT_CONFIRMED));
    ok('Edit is its way: no ask-again button', await plain.locator('button').filter({ hasText: /^Allow sending/ }).count(), 0);
    const env = page.locator('.mcp-server-row').nth(1);
    expect('a server sending an environment variable says the credential is held back', (await env.innerText()).includes(NOT_CONFIRMED));
    ok('and can be asked again', await env.locator('button').filter({ hasText: /^Allow sending/ }).count(), 1);
    // An answer that says "not confirmed" without a reason still says so.
    await page.evaluate(() => { window.__replies.mcp_save_server = (a) => ({ ok: true, id: a.id, warning: null, confirmed: false }); });
    await env.locator('button').filter({ hasText: /^Allow sending/ }).click(); await page.waitForTimeout(100);
    expect('a bare "confirmed: false" is a warning, not a success', /not confirmed/i.test(await page.textContent('#mcpStatus'))
      && !(await toasts(page)).some((x) => /is confirmed/i.test(x)));
    // An answer without `confirmed: true` is not confirmed (fail closed): it
    // used to read as a plain save, and "Allow sending..." as confirmed.
    await page.evaluate(() => { window.__replies.mcp_save_server = (a) => ({ ok: true, id: a.id || 'm-new', warning: null }); });
    await env.locator('button').filter({ hasText: /^Allow sending/ }).click(); await page.waitForTimeout(100);
    expect('I2 "Allow sending..." answered without `confirmed` is not said to be confirmed',
      /not confirmed/i.test(await page.textContent('#mcpStatus')) && !(await toasts(page)).some((x) => /is confirmed/i.test(x)));
    await page.locator('.mcp-server-row button').filter({ hasText: /^Edit$/ }).first().click();
    await page.fill('#mcpName', 'renamed-svc'); await page.click('#mcpSaveBtn'); await page.waitForTimeout(100);
    expect('I2 a save answered without `confirmed` says it is not confirmed, not "MCP server saved."',
      (await toasts(page)).includes(MCP_SAVED_NOT_CONFIRMED_TEXT) && !(await toasts(page)).includes('MCP server saved.'));
    ok('no page errors so far', app.errors, []);
  });
}

// An MCP server chooses its tools' names and display names, and the results:
// shown spelled out on the approval card, in the tools list, in the tool log
// and in the notices that name a tool, so a tool cannot read as another -
// while the backend, the model and the stored record get them as they are.
// A server's own name that a backup restored unchecked is shown the same way,
// there and in the MCP settings, and so are the URL and the environment
// variable's name restored with it.
async function spelledNameChecks(browser, server) {
  await fixture(browser, server, 'MCP tool names in the tools list and its notices are spelled out', async (app) => {
    const { page } = app;
    await settings(page); await page.evaluate(() => mcpShowToolsFor('m1'));
    const name = page.locator('.mcp-tool-name');
    ok('the display name and the name, spelled out', await name.textContent(), ZWSP_SHOWN + ' (' + RLO_SHOWN + ')');
    ok('each in a text-direction isolate of its own', await name.locator('bdi').allTextContents(), [ZWSP_SHOWN, RLO_SHOWN]);
    ok('the model is told both names as they are', await page.evaluate(() => mcpGetTools().map((t) => t.description)),
      [ZWSP_DISPLAY + ' (MCP server "svc", tool "' + RLO_TOOL + '")']);
    await page.evaluate((refusal) => {
      Object.assign(window.__replies.mcp_list_servers[0].tools[0], { display_name: null, enabled: false });
      window.__replies.mcp_set_tool_state = { $reject: refusal };
      return mcpLoadSettings();
    }, "This tool's definition changed - review it and approve again.");
    ok('a name shown alone is spelled out too', await name.textContent(), RLO_SHOWN);
    await page.locator('.mcp-tool-row label').filter({ hasText: /^Enable$/ }).click();
    await page.waitForFunction(() => /was not approved/.test(document.getElementById('mcpStatus').textContent));
    ok('the backend is asked about the tool by its name as it is', (await app.calls('mcp_set_tool_state')).at(-1).args.tool, RLO_TOOL);
    const refused = await page.locator('#mcpStatus').textContent();
    expect('a refused approval names the tool spelled out, kept to itself',
      refused.includes('Tool "' + FSI + RLO_SHOWN + PDI + '" was not approved') && !hidesAny(refused));
    // The backend's refusals can quote the tool ("Tool '...' not found").
    await page.evaluate((refusal) => { window.__replies.mcp_set_tool_state = { $reject: refusal }; },
      "Tool '" + RLO_TOOL + "' not found on this MCP server.");
    await page.locator('.mcp-tool-row label').filter({ hasText: /^Enable$/ }).click();
    await page.waitForFunction(() => [...document.querySelectorAll('#toast .toast-text')].some((n) => /not found on this MCP server/.test(n.textContent)));
    expect('a refusal that quotes the tool is spelled out',
      (await toasts(page)).includes("Tool '" + RLO_SHOWN + "' not found on this MCP server."));
    await page.evaluate((tool) => {
      window.__replies.mcp_test_connection = { tools: [], changed: [tool] };
      return mcpTestConnection('m1');
    }, RLO_TOOL);
    const changed = await page.locator('#mcpStatus').textContent();
    expect('a tool that changed on the server is named spelled out, kept to itself',
      changed.includes(FSI + RLO_SHOWN + PDI) && !hidesAny(changed));
  }, { replies: { mcp_list_servers: [SPELLED_MCP()] } });
  await fixture(browser, server, 'MCP names on the approval card and in the tool log are spelled out', async (app) => {
    const { page } = app; const id = await panel(app);
    const card = () => page.locator('.ai-card.confirm').last();
    const call = (callId) => page.evaluate(({ t, c }) => {
      window.__toolTask = aiRunTool(t, { id: c, name: 'mcp__svc__echo_txt_exe', arguments_json: '{"text":"hi"}' });
    }, { t: id, c: callId });
    const result = 'first' + RLO + 'tsal\nzero' + ZWSP + 'width';
    const warning = 'The tool ran, but refreshing its tool list failed: tool "x' + RLO + 'y" is invalid';
    await page.evaluate(({ content, warn }) => {
      window.__replies.mcp_call_tool = { ok: true, content, is_error: false, warning: warn };
    }, { content: result, warn: warning });
    await call('denied');
    await card().waitFor();
    ok('the card\'s accessible name spells the tool and the server out', await card().getAttribute('aria-label'),
      'Approval needed: call tool ' + RLO_SHOWN + ' on MCP server ' + RESTORED_SHOWN);
    const target = card().locator('.ai-card-why').nth(1);
    ok('the card names the server and the tool, spelled out', await target.textContent(),
      'Server "' + RESTORED_SHOWN + '" - tool ' + RLO_SHOWN + ' (server claims: read-only)');
    ok('each in a text-direction isolate of its own', await target.locator('bdi').allTextContents(), [RESTORED_SHOWN, RLO_SHOWN]);
    expect('nothing on the card is an override or a zero-width space left unshown', !hidesAny(await card().textContent()));
    await card().locator('button').filter({ hasText: /^Deny$/ }).click();
    ok('the denied call is answered', await page.evaluate(() => window.__toolTask), 'denied by user');
    ok('and its row names the server and the tool, spelled out',
      await page.locator('.ai-tool-event-name').last().textContent(), 'MCP ' + RESTORED_SHOWN + ' - ' + RLO_SHOWN);
    await call('approved');
    await page.waitForFunction(() => document.querySelectorAll('.ai-card.confirm').length === 2);
    await card().locator('button').filter({ hasText: /^Approve$/ }).click();
    const sent = await page.evaluate(() => window.__toolTask);
    ok('the backend is asked for the tool by its name as it is', (await app.calls('mcp_call_tool')).at(-1).args.tool, RLO_TOOL);
    expect('the model gets the result and the warning as they are', sent.includes(result) && sent.includes(warning));
    const row = page.locator('.ai-tool-event').last();
    const head = row.locator('.ai-tool-event-name');
    ok('the row names the server and the tool, spelled out', await head.textContent(), 'MCP ' + RESTORED_SHOWN + ' - ' + RLO_SHOWN);
    ok('each in a text-direction isolate of its own', await head.locator('bdi').allTextContents(), [RESTORED_SHOWN, RLO_SHOWN]);
    const shown = row.locator('pre').last();
    ok('the result shows each such character as its code point, its lines kept', await shown.textContent(),
      'Result: first<U+202E>tsal\nzero<U+200B>width');
    ok('each one marked, so it cannot pass for text', await shown.locator('.ai-hidden-char').allTextContents(), ['<U+202E>', '<U+200B>']);
    expect('the warning is spelled out too', (await row.locator('.ai-tool-event-warn').textContent()).includes('tool "x<U+202E>y" is invalid'));
    expect('nothing in the row is an override or a zero-width space left unshown', !hidesAny(await row.textContent()));
    // A tool name the model made up: answered as it was called, shown spelled out.
    const madeUp = 'get_session_info' + RLO;
    ok('the model is answered with the name as it called it',
      await page.evaluate(({ t, n }) => aiRunTool(t, { id: 'odd', name: n, arguments_json: '{}' }), { t: id, n: madeUp }), 'unknown tool: ' + madeUp);
    ok('its row spells it out', await page.locator('.ai-tool-event-name').last().textContent(), 'get_session_info<U+202E>');
    // A call the turn never reached (Stop) is logged by the name the model gave it.
    await page.evaluate((n) => {
      let k = 0;
      window.__replies.assistant_chat = () => ++k === 1 ? { text: '', tool_calls: [
        { id: 'first', name: 'mcp__svc__echo_txt_exe', arguments_json: '{}' },
        { id: 'second', name: n, arguments_json: '{}' },
      ] } : { text: 'Done.', tool_calls: [] };
    }, madeUp);
    await send(page);
    await page.waitForFunction(() => document.querySelectorAll('.ai-card.confirm:not(.approved):not(.denied)').length === 1);
    await page.click('#assistantStopBtn'); await idle(page);
    ok('a call the turn never reached is logged by its name, spelled out',
      await page.locator('.ai-tool-event.cancelled .ai-tool-event-name').last().textContent(), 'get_session_info<U+202E>');
  }, { replies: { mcp_list_servers: [SPELLED_MCP(RESTORED_SERVER)] } });
  await fixture(browser, server, 'A tool schema error names the tool spelled out', async (app) => {
    const { page } = app;
    // The JSON parser's error quotes the schema, so one holds an override
    // where a value should be (quoted twice: as the token and in the text).
    const errors = await page.evaluate(({ server, tool, rlo }) => [undefined, '{"a":' + rlo + '}', 42, '[]'].map((schema) => {
      try { mcpValidateToolSchema({ inputSchema: schema }, server, tool); return 'accepted'; } catch (e) { return e.message; }
    }), { server: RESTORED_SERVER, tool: RLO_TOOL, rlo: RLO });
    const named = 'MCP tool "' + FSI + RLO_SHOWN + PDI + '" from server "' + FSI + RESTORED_SHOWN + PDI + '"';
    expect('each one spells the tool and the server out, each kept to itself', errors.length === 4
      && errors.every((m) => m.startsWith(named) && !hidesAny(m)));
    expect('and the quoted schema is spelled out too', /<U\+202E>/.test(errors[1].slice(errors[1].indexOf('inputSchema:'))));
    await panel(app);
    await page.evaluate(() => { delete window.__replies.mcp_list_servers[0].tools[0].inputSchema; return mcpRefresh(); });
    await send(page); await idle(page);
    // Shown as it is worded (aiError): the names are spelled out once, so the
    // isolates around them stay isolates and never read <U+2068> ... <U+2069>.
    ok('the turn it stops says so, each name spelled out once and kept to itself',
      await page.locator('.ai-msg.error').last().textContent(), named + ' has no inputSchema.');
  }, { replies: { mcp_list_servers: [SPELLED_MCP(RESTORED_SERVER)] } });
  await fixture(browser, server, 'A restored MCP server\'s name is spelled out in the MCP settings', async (app) => {
    const { page } = app;
    // As a restore stores them: switched off, their tools off, their secrets kept.
    const restored = (more) => MCP({ auth_type: 'bearer', has_secret: true, confirmed: false, status: 'unknown', protocol_version: null, ...more });
    await emulateCredentialQuestion(page, [
      restored({ name: RESTORED_SERVER, tools: [TOOL({ enabled: false, pinned: false })] }),
      restored({ id: 'm2', name: PADDED_SERVER, tools: [] }),
    ]);
    await settings(page);
    const row = (i) => page.locator('.mcp-server-row').nth(i);
    const allow = (i) => row(i).locator('button').filter({ hasText: /^Allow sending/ });
    // The text of the toast matching `re`, read as soon as it is shown.
    const toastText = (re) => page.waitForFunction((src) => [...document.querySelectorAll('#toast .toast-text')]
      .map((n) => n.textContent).find((t) => new RegExp(src).test(t)), re.source).then((h) => h.jsonValue());
    const refuseSaves = (refusal) => page.evaluate((r) => { window.__replies.mcp_save_server = { $reject: r }; }, refusal);
    ok('its row names it spelled out', await row(0).locator('.mcp-server-name').textContent(), RESTORED_SHOWN);
    expect('nothing in the row is an override left unshown', !hidesAny(await row(0).textContent()));
    await row(0).locator('button').filter({ hasText: /^Review tools$/ }).click();
    const title = page.locator('.mcp-tools-title');
    ok('the heading of its tools names it spelled out', await title.textContent(),
      'Tools from "' + RESTORED_SHOWN + '" (0/1 enabled) - review each before enabling:');
    ok('kept to itself', await title.locator('bdi').allTextContents(), [RESTORED_SHOWN]);
    await page.evaluate(() => { Object.assign(window.__registry[0].tools[0], { enabled: true, pinned: true }); return mcpRefresh(); });
    ok('the model is told its name as it is', await page.evaluate(() => mcpGetTools().map((t) => t.description)),
      ['Echo (MCP server "' + RESTORED_SERVER + '", tool "echo")']);
    // "Allow sending...": the status line names it while the save waits for
    // the backend, which then refuses the name, as every save does.
    await page.evaluate(() => { window.__emulatedSave = window.__replies.mcp_save_server; });
    await hold(page, 'mcp_save_server');
    await allow(0).click();
    await page.waitForFunction(() => /Waiting for your answer/.test(document.getElementById('mcpStatus').textContent));
    ok('the status line waiting for the answer names it spelled out, kept to itself', await page.textContent('#mcpStatus'),
      'Waiting for your answer: SSHSpan asks in its own dialog whether it may send the credential of "' + FSI + RESTORED_SHOWN + PDI + '".');
    await refuseSaves(NAME_RULE);
    await letGo(page, 'mcp_save_server');
    await toastText(/^Server name must be/);
    ok('the backend is sent its name as it is', (await app.calls('mcp_save_server')).at(-1).args, {
      id: 'm1', name: RESTORED_SERVER, url: 'https://mcp.example.test/mcp', auth_type: 'bearer',
      auth_header_name: null, auth_secret: null, auth_env_var: null,
    });
    // A server whose tool names it would share is refused with its name
    // quoted - asked again from its row, or saved from the form.
    await refuseSaves(NAME_TAKEN(RESTORED_SERVER, 'svc-x'));
    await allow(1).click();
    const taken = NAME_TAKEN(RESTORED_SHOWN, 'svc-x');
    ok('a refusal that quotes it is spelled out', await toastText(/'svc-x' would share/), taken);
    ok('on the status line as well', await page.textContent('#mcpStatus'), taken);
    await refuseSaves(NAME_TAKEN(RESTORED_SERVER, 'svc.x'));
    await page.click('#mcpAddBtn');
    await page.fill('#mcpName', 'svc.x'); await page.fill('#mcpUrl', 'https://other.example.test/mcp');
    await page.click('#mcpSaveBtn');
    ok('so is the form\'s', await toastText(/'svc\.x' would share/), NAME_TAKEN(RESTORED_SHOWN, 'svc.x'));
    // Removal: the question, and the backend's warning, which can quote it.
    await page.evaluate((name) => {
      window.__replies.mcp_remove_server = (a) => {
        window.__registry = window.__registry.filter((s) => s.id !== a.id);
        return { ok: true, warning: "MCP session teardown for '" + name + "' timed out after 2 s." };
      };
    }, RESTORED_SERVER);
    await row(0).locator('button').filter({ hasText: /^Remove$/ }).click();
    expect('removing it asks first', await waitVisible(page, '#confirmModal', 1200));
    ok('the removal question names it spelled out, kept to itself', await page.textContent('#confirmMessage'),
      'Remove MCP server "' + FSI + RESTORED_SHOWN + PDI + '"?');
    await answerConfirm(page, 'ok');
    const removed = "MCP server removed. MCP session teardown for '" + RESTORED_SHOWN + "' timed out after 2 s.";
    ok('a removal warning that quotes it is spelled out', await toastText(/^MCP server removed/), removed);
    ok('on the status line too', await page.textContent('#mcpStatus'), removed);
    ok('the backend is asked to remove it by its id', (await app.calls('mcp_remove_server')).at(-1).args, { id: 'm1' });
    // With that one gone the other one's save goes through, and its
    // confirmation names it spelled out.
    await page.evaluate(() => { window.__replies.mcp_save_server = window.__emulatedSave; window.__answer = 'allow'; });
    await allow(0).click();
    ok('the confirmation names it spelled out, kept to itself', await toastText(/is confirmed/),
      'MCP server "' + FSI + PADDED_SHOWN + PDI + '" is confirmed - SSHSpan may send its credential now.');
    ok('the backend is sent that name as it is', (await app.calls('mcp_save_server')).at(-1).args.name, PADDED_SERVER);
  });
  await fixture(browser, server, 'A restored MCP server\'s URL and environment variable are spelled out in the MCP settings', async (app) => {
    const { page } = app;
    // As a restore stores them: switched off, the token's source kept, the
    // URL and the names as the backup had them.
    const restored = (more) => MCP({ auth_type: 'bearer', auth_env_var: RESTORED_ENV, confirmed: false, status: 'unknown', protocol_version: null, tools: [], ...more });
    await emulateCredentialQuestion(page, [
      restored({ url: RESTORED_URL, auth_type: 'custom_header', auth_header_name: RESTORED_HEADER }),
      restored({ id: 'm2', name: 'env-svc' }),
      // Restored and saved before a save checked variable names (v1.10.0):
      // confirmed, the name unchecked.
      MCP({ id: 'm3', name: 'old-svc', auth_type: 'bearer', auth_env_var: RESTORED_ENV, tools: [] }),
    ]);
    await settings(page);
    const row = page.locator('.mcp-server-row').first();
    const url = row.locator('.mcp-server-url');
    ok('its row shows the URL spelled out', await url.textContent(), RESTORED_URL_SHOWN);
    ok('so does the URL\'s tooltip', await url.getAttribute('title'), RESTORED_URL_SHOWN);
    expect('nothing in the row is an override left unshown', !hidesAny(await row.textContent()));
    // The form holds what a save sends: the values as stored.
    await row.locator('button').filter({ hasText: /^Edit$/ }).click();
    ok('the form holds the URL and the names as stored',
      [await page.inputValue('#mcpUrl'), await page.inputValue('#mcpHeaderName'), await page.inputValue('#mcpAuthEnvVar')],
      [RESTORED_URL, RESTORED_HEADER, RESTORED_ENV]);
    // A save stores the URL normalized (its path percent-encoded), so the form
    // counts it as a new URL and says where the variable's token goes.
    const notice = page.locator('#mcpRebindWarn');
    ok('the notice that the token goes to the new settings names the variable spelled out, kept to itself',
      await notice.textContent(), 'Changing the URL or the auth settings sends the token from environment variable '
        + FSI + RESTORED_ENV_SHOWN + PDI + ' to the new settings - change the variable name if that is not intended.');
    // The backend refuses such a variable's name, typed or kept.
    await page.evaluate((refusal) => {
      window.__emulatedSave = window.__replies.mcp_save_server;
      window.__replies.mcp_save_server = { $reject: refusal };
      return mcpSaveServer();
    }, ENV_RULE);
    ok('the backend is sent the URL and the names as they are', (await app.calls('mcp_save_server')).at(-1).args, {
      id: 'm1', name: 'svc', url: RESTORED_URL, auth_type: 'custom_header',
      auth_header_name: RESTORED_HEADER, auth_secret: null, auth_env_var: RESTORED_ENV,
    });
    // A Test of the record an older version confirmed quotes the variable
    // when it is not set.
    await page.evaluate((refusal) => {
      window.__replies.mcp_test_connection = { $reject: refusal };
      return mcpTestConnection('m3');
    }, ENV_UNSET(RESTORED_ENV));
    ok('a failed Test that quotes it is spelled out beside the row',
      await page.locator('.mcp-server-row').nth(2).locator('.mcp-server-error').textContent(), 'Last test failed: ' + ENV_UNSET(RESTORED_ENV_SHOWN));
    ok('and in its toast', (await toasts(page)).filter((t) => /is not set/.test(t)), [ENV_UNSET(RESTORED_ENV_SHOWN)]);
    // A record whose URL a save keeps: with no secret typed, its variable
    // stays in effect, which the form says.
    await page.click('#mcpCancelBtn');
    await page.locator('.mcp-server-row').nth(1).locator('button').filter({ hasText: /^Edit$/ }).click();
    await page.selectOption('#mcpSecretSource', 'stored');
    const kept = FSI + RESTORED_ENV_SHOWN + PDI;
    ok('the notice that the variable stays in effect names it spelled out, kept to itself', await notice.textContent(),
      'No secret entered: the environment variable ' + kept + ' stays in effect. Type a secret to replace it with a stored one.');
    // The backend refuses to keep it too: save_server checks a kept
    // variable's name as well.
    await page.evaluate(() => mcpSaveServer());
    ok('a save that keeps it sends no variable', (await app.calls('mcp_save_server')).at(-1).args, {
      id: 'm2', name: 'env-svc', url: 'https://mcp.example.test/mcp', auth_type: 'bearer',
      auth_header_name: null, auth_secret: null, auth_env_var: null,
    });
    // The stub then answers the same save as if it had kept the variable, to
    // show the renderer does not count on that refusal: what it says next
    // names the variable spelled out too.
    await page.evaluate(() => {
      window.__replies.mcp_save_server = window.__emulatedSave;
      window.__answer = 'allow';
      return mcpSaveServer();
    });
    ok('the toast that says it stays in effect names it spelled out, kept to itself',
      (await toasts(page)).filter((t) => /stays in effect/.test(t)), ['MCP server saved - the environment variable ' + kept + ' stays in effect.']);
    ok('so does the status line', await page.textContent('#mcpStatus'),
      'Saved. No secret was entered, so the environment variable ' + kept + ' stays in effect.');
  });
}

async function focusChecks(browser, server) {
  await fixture(browser, server, 'A new approval card takes the focus only from the panel or the page', async (app) => {
    const { page } = app; const id = await panel(app);
    const focus = () => page.evaluate(() => {
      const a = document.activeElement;
      if (!a || a === document.body) return 'body';
      if (a.classList.contains('ai-card')) return 'card';
      if (a.closest('#terminalBody')) return 'terminal';
      return a.id || a.className;
    });
    let n = 0;
    const card = async () => {
      n += 1;
      await page.evaluate(({ t, k }) => { window['__card' + k] = aiConfirmCard(t, 'echo ' + k); }, { t: id, k: n });
      await page.waitForFunction((k) => document.querySelectorAll('.ai-card.confirm').length >= k, n);
    };
    // Answered without a click, so the answer moves no focus.
    const deny = () => page.evaluate(() => {
      for (const c of document.querySelectorAll('.ai-card.confirm:not(.approved):not(.denied)')) {
        [...c.querySelectorAll('button')].find((b) => b.textContent === 'Deny').click();
      }
    });
    await page.evaluate((t) => window.tabRecord(t).term.focus(), id);
    ok('the user is typing in the terminal', await focus(), 'terminal');
    await card();
    ok('a new card leaves the keyboard in the terminal', await focus(), 'terminal');
    expect('the card is still announced (the transcript is a live log)', (await page.getAttribute('#assistantMessages', 'aria-live')) === 'polite');
    await deny();
    await page.focus('#assistantToggleBtn');
    await card();
    ok('nor does it take the keyboard from a control outside the panel', await focus(), 'assistantToggleBtn');
    await deny();
    await page.evaluate(() => { if (document.activeElement) document.activeElement.blur(); });
    ok('nothing has the focus', await focus(), 'body');
    await card();
    ok('from <body> the card takes the focus', await focus(), 'card');
    await deny();
    await page.focus('#assistantInput');
    await card();
    ok('from inside the panel the card takes the focus', await focus(), 'card');
    await deny();
  });
  await fixture(browser, server, 'Closing the panel returns the keyboard to its toggle', async (app) => {
    const { page } = app; await panel(app);
    const where = () => page.evaluate(() => [assistantIsOpen(), document.activeElement === document.body ? 'body' : document.activeElement.id]);
    await page.click('#assistantCloseBtn');
    ok('the X closes the panel and the toggle has the focus, not <body>', await where(), [false, 'assistantToggleBtn']);
    ok('the toggle says the panel is closed', await page.getAttribute('#assistantToggleBtn', 'aria-pressed'), 'false');
    await page.keyboard.press('Enter');
    await page.waitForFunction(() => assistantIsOpen());
    await page.waitForTimeout(150); // the panel's input takes the focus
    await page.focus('#assistantCloseBtn'); await page.keyboard.press('Enter');
    ok('the X from the keyboard does the same', await where(), [false, 'assistantToggleBtn']);
    // WebKit (macOS) does not focus a button it clicks: the X closes the panel
    // while the focus is on <body>, and must still hand it to the toggle.
    await page.keyboard.press('Enter');
    await page.waitForFunction(() => assistantIsOpen());
    await page.waitForTimeout(150);
    await page.evaluate(() => { document.activeElement.blur(); document.getElementById('assistantCloseBtn').click(); });
    ok('a click that does not focus the X still returns the focus to the toggle', await where(), [false, 'assistantToggleBtn']);
    await page.keyboard.press('Enter');
    await page.waitForFunction(() => assistantIsOpen());
    await page.waitForTimeout(150);
    await page.focus('#assistantInput');
    await page.keyboard.press('Control+Shift+A');
    ok('closed with Ctrl+Shift+A from inside it, the focus goes to the toggle too', await where(), [false, 'assistantToggleBtn']);
  });
}

(async () => {
  const chromium = loadChromium();
  if (!chromium) { console.error('Playwright is required for test:assistant; no silent skip.'); process.exit(1); }
  const server = await serve(rendererDir()); const browser = await chromium.launch({ headless: true });
  try {
    for (const fn of [approvalChecks, typingChecks, historyChecks, lifecycleChecks, mcpSettingsChecks, mcpConfirmChecks, spelledNameChecks, providerChecks, lockedSettingsChecks, setupChecks, panelChecks, focusChecks]) {
      // ASSISTANT_ONLY=<group> runs one group while iterating; CI runs all.
      if (process.env.ASSISTANT_ONLY && fn.name !== process.env.ASSISTANT_ONLY) continue;
      console.log('\n' + fn.name); await fn(browser, server);
    }
  } finally { await browser.close(); await new Promise((r) => server.close(r)); }
  console.log(`\nAssistant UI: ${passed} ok, ${failures.length} FAIL.`);
  if (failures.length) process.exitCode = 1;
})().catch((e) => { console.error(e); process.exitCode = 1; });
