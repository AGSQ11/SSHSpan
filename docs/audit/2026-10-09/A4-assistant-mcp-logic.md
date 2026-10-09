# A4 - Assistant + MCP renderer logic audit

- **Counts:** 27 findings - High 5, Medium 13, Low 9 (Critical 0). 20 reproduced in headless Chromium against the real renderer with a stubbed Tauri bridge (drivers: `.superpowers/audit/scratch/A4/*.js`); the rest proven by code reading and marked as such.
- **Covered:** all of `src/renderer/assistant.js` (869) and `mcp.js` (603); `index.html` assistant settings section (353-477), `#yoloModal` (504-541), assistant panel markup (230-254); every Rust contract they call in `src-tauri/src/assistant/mod.rs` and `mcp.rs` (commands, `tool_view`, `merge_tools`, `mcp_call_tool` gates, `build_name_map`, `classify_url`); `docs/MCP-SMOKE-TEST.md`, SECURITY.md "MCP servers", README/CHANGELOG assistant claims; the wiring in `app.js` (`closeSessionTab`, `clearConnectView`, `onSessionClosed`, Escape chain) and `terminal.js`.
- **Not covered / not verifiable:** nothing executed in Rust (no cargo; Rust claims are by reading, marked `likely` where the effect depends on runtime); no real provider or MCP server (the 64-char tool-name limit and the `max_tokens` rejection come from documented provider behaviour); WebView2/WebKitGTK not tried (Chromium stand-in); prompt-injection depth left to the security reviewer (not examined: bidi/zero-width/control characters inside the Approve-card command text).
- **Checked and clean:** no `innerHTML`/`insertAdjacentHTML` in either file (all model/server text goes through `textContent`); every element id used by the two files exists in `index.html`, no duplicate ids; every `call()`/`mcpCall()` site has try/catch and errors are plain strings (no `[object Object]` path); `mcp_save_server`/`mcp_set_tool_state` snake_case and `assistant_*`/`mcp_call_tool` camelCase argument names match the Rust signatures; no send double-submit (`s.running` guard plus synchronous input disable); listeners are attached once (`aiWire`/`mcpWire` run once; per-row listeners die with their DOM); the turn timer is cleared in `finally`; YOLO is never persisted by the backend (in-memory map, cleared on lock).
- **Fix-priority hint:** A4-01..A4-04 are small, independent and user-visible. A4-06, A4-09, A4-10 and A4-19 share one root cause (per-tab assistant state is neither torn down with the tab nor kept separate from global DOM state). A4-03 and A4-16 share another (conversation history is never repaired or bounded); A4-01, A4-05 and A4-17 are the MCP approval/visibility cluster and are best fixed together.

---

## A4-01: MCP tool calls the user APPROVES on the card are always denied by the backend (`approved` is never sent as true)
- **Severity:** High
- **Category:** js-logic
- **Location:** `src/renderer/assistant.js:589-595` (call site), `src/renderer/mcp.js:138-150` (`mcpCallTool(tabId, name, args, approved)` -> `approved: approved === true`), `src-tauri/src/assistant/mcp.rs:1857-1871` (gates)
- **Evidence:** `aiRunTool` shows the Approve/Deny card, then calls `text = await window.mcpCallTool(tabId, name, args);` - the 4th argument is omitted, so the payload is always `approved:false`. Reproduced: level `execute`, enabled+pinned tool, clicked Approve on the card -> IPC `mcp_call_tool {"tabId":"tab-...","id":"s1","tool":"echo","argumentsJson":"{\"x\":1}","approved":false}`. Rust then denies: `if matches!(level, "read"|"draft") && !approved` -> "AI access level is 'read' - tool calls need your approval."; `if !entry.auto_approve && !approved && level != "yolo"` -> "Tool 'x' requires approval before it can run." The model receives `error: ...`; the user sees nothing. The comment at mcp.js:138-140 says `approved: true means the user approved the card (or the level is yolo / the tool is auto_approve)` - false in code. `scripts/check-mcp-contract.js:105` only greps for the text `approved:`, so it passes.
- **Why it is a flaw:** the documented flow (SECURITY.md "the click that says 'this user approved this call' comes from the renderer"; CHANGELOG 1.9.1; MCP-SMOKE-TEST step 11 "the call runs only after you click Approve") cannot work. MCP tools only run at YOLO or when Auto-approve is on at `execute`; at read/draft they never run, and an auto-approve tool skips its card there and is then denied too (renderer skips the card when `meta.autoApprove`, backend still demands `approved` at read/draft). The Approve button is cosmetic.
- **Proposed fix:** in the MCP branch keep `let approved = false;`, set it `true` after `aiConfirmMcpCard` resolves true (and for the yolo / auto-approve paths the comment describes), and call `window.mcpCallTool(tabId, name, args, approved)`. Decide the read/draft + auto-approve case explicitly (always show the card at read/draft, or relax the Rust gate and fix the docs). Make `check-mcp-contract.js` assert the 4th argument at the assistant.js call site.
- **Confidence:** confirmed (reproduced)
- **Effort:** S

## A4-02: Draft-level `type_command` forwards model text raw to the PTY - an embedded newline or control byte executes a command with no approval and no audit
- **Severity:** High
- **Category:** security
- **Location:** `src/renderer/assistant.js:566-570` (`type_command`), `:329-335` (Insert button), `src/renderer/terminal.js:146-153,629` (`sendTerminalBytes` / `terminalSendText`), `src-tauri/src/commands/terminal.rs:241-255` (`terminal_send`)
- **Evidence:** `window.terminalSendText(tabId, args.command || '')` with no filtering; `sendTerminalBytes` encodes the whole string; `terminal_send` writes the bytes verbatim. Reproduced: at level `draft`, `aiRunTool(tab,{name:'type_command',arguments_json:'{"command":"echo hi\\nid\\r"}'})` -> result `typed: echo hi\nid`, IPC `terminal_send` bytes `[101,99,104,111,32,104,105,10,105,100,13]` (LF and CR on the wire). No bracketed-paste wrapping, no `assistant_exec`, no `assistant.exec` audit row.
- **Why it is a flaw:** README ("Draft - may also type into your prompt line, but never presses Enter"), the level caption (assistant.js:28), the system prompt and the tool description all promise the model cannot press Enter at Draft. A trailing `\n` is a common thing for a model to put in a "command" argument, and `\r`/`\n`/Ctrl-C/Ctrl-D bytes from an injected instruction do the same: the command runs, bypassing the `assistant_exec` level gate, the Approve card and the audit log. The Insert button on `propose_command` cards has the same raw path (a multi-line "proposal" executes on Insert).
- **Proposed fix:** in the `type_command` branch reject any command matching `/[\x00-\x08\x0a-\x1f\x7f]/` (TAB allowed) with `denied: type_command must be one line without control characters`; in the Insert handler refuse or confirm the same set. Longer term route typing through a Rust command that enforces it and audits.
- **Confidence:** confirmed (reproduced)
- **Effort:** S

## A4-03: A stopped, capped, errored or empty turn leaves an unanswered `tool_calls` message in history - every later send in that tab can fail with a provider 400
- **Severity:** High
- **Category:** js-logic
- **Location:** `src/renderer/assistant.js:692` (assistant message pushed before its results), `:696` (`if (s.stopRequested) break;`), `:698-701` (25-call cap `return`), `:556`+`:563` (`args` null -> TypeError), `:689-709` (empty reply)
- **Evidence:** the assistant message (with all `tool_calls`) is pushed first; tool results are pushed one by one afterwards. Reproduced three ways, each followed by a second send: (1) Stop pressed while the first reply (which contains a tool call) is in flight -> next request roles `["system","user","assistant(tool_calls:c1)","user"]`, no `tool` result for `c1`; (2) the 26th tool call hits the cap -> request tail `assistant(tc:c26), user`; (3) model returns `{text:null,tool_calls:[]}` -> history gets `{"role":"assistant","content":null,"tool_calls":null}` replayed verbatim, and the UI shows nothing for the empty reply. A throw inside `aiRunTool` (for example `arguments_json` = `"null"` makes `args.command` read a property of null) takes the same path through the outer `catch`. A Stop that denies a pending card also breaks out of the `for` with the remaining calls unanswered (line 696).
- **Why it is a flaw:** OpenAI-style APIs reject an assistant `tool_calls` message not followed by a `tool` message per id; Anthropic rejects `tool_use` without `tool_result`, and Rust `anthropic_body` emits `content: []` for the null/null message, also rejected. Stop during the first "thinking" phase is the most natural click, so the tab is bricked: `s.messages` is never repaired or trimmed, there is no New chat control (A4-16), and the only reset is closing the tab or a session drop.
- **Proposed fix:** guarantee a result for every call: after pushing the assistant message, run the loop inside `try/finally` that pushes `{role:'tool', tool_call_id, name, content:'cancelled'}` for each `tc` without a result (covers Stop, cap, errors); do not push an assistant message with neither text nor calls (or push `content:''` and show a "model returned nothing" notice); guard with `if (!args || typeof args !== 'object') args = {}`.
- **Confidence:** confirmed (history shape reproduced; provider rejection per the documented message-pairing rules, not exercised live)
- **Effort:** M

## A4-04: The terminal-maximize button sits on top of the assistant Send button - clicking Send maximizes the terminal and hides the panel
- **Severity:** High
- **Category:** ui
- **Location:** `src/renderer/styles.css:1268-1285` (`.term-max-btn { position:absolute; right:8px; bottom:34px; z-index:30; 26x26 }`), `:2453-2456` (`.ai-foot`), `:2497` (`#app.term-max .assistant-panel { display:none }`), `src/renderer/index.html:252,256`
- **Evidence:** measured at 880x560, 1100x720 and 1600x1000 with a live tab and the panel open: Send = 42x33 at the panel's lower-right corner, `#termMaxBtn` = 26x26 covering its lower-right 24x20 px (about 35% of the button, including its centre). `document.elementFromPoint` at the Send centre returns `termMaxBtn`; Playwright refuses the click ("termMaxBtn intercepts pointer events"). A real mouse click at the Send centre -> `#app.term-max` set, `.assistant-panel` computed `display:none`, typed text still in the input, 0 user rows (nothing sent). Screenshot: `.superpowers/audit/scratch/A4/overlap-1100x720.png` (the expand icon is drawn on the Send button).
- **Why it is a flaw:** the panel's primary action misfires with the mouse where users naturally click, and the visible result is the whole assistant disappearing. Enter still sends, which hides the bug from keyboard-driven testing.
- **Proposed fix:** move the maximize button clear of the panel while it is open: `.session-surface.assistant-open ~ .term-max-btn { right: 396px; }` (380px panel + margins; adjust the selector to the real DOM order since `#termMaxBtn` is a sibling of `.session-surface`), or give `.ai-foot` enough bottom padding that Send clears the 34-60px band.
- **Confidence:** confirmed (reproduced at 3 window sizes)
- **Effort:** S

## A4-05: The rug-pull guard is invisible in the UI, and re-enabling a changed tool silently restores its old Auto-approve
- **Severity:** High
- **Category:** security
- **Location:** `src/renderer/mcp.js:445-446,469-474,511-522` (`needsReapprove = t.enabled && !t.pinned`), `src-tauri/src/assistant/mcp.rs:1476` (`"pinned": tool.pin_hash.is_some()`), `:1217-1225` (`merge_tools`: changed definition -> `(false, p.auto_approve, p.pin_hash.clone())`), `:1749-1764` (`mcp_set_tool_state` re-pins and stores `auto_approve && enabled`)
- **Evidence:** `merge_tools` disables a changed tool but keeps its old `pin_hash` and `auto_approve`; `tool_view` then reports `pinned:true`. The renderer's "Definition changed - re-approve" warning, the `.changed` class and the unchecked-Enable logic all require `enabled && !pinned`, a state the backend can never produce (enabling always sets `pin_hash`). Reproduced with the backend's exact view shape (`enabled:false, auto_approve:true, pinned:true`): 0 `.mcp-tool-changed` nodes, 0 `.changed` rows, Enable unchecked, Auto-approve unchecked and disabled; clicking Enable sends `mcp_set_tool_state {"enabled":true,"auto_approve":true}` (`setToolState(on, on ? t.auto_approve : false)` re-sends the stale flag), and the backend stores `auto_approve = true && enabled`.
- **Why it is a flaw:** SECURITY.md, CHANGELOG and smoke-test step 13 promise that a changed tool is disabled and shows a "definition changed, re-approve" notice. In practice the tool simply turns off with no explanation (the only trace is an audit row), and the user's re-enable pins the NEW definition AND re-grants the old auto-approve while the UI shows the box unchecked - so the changed, possibly hostile, tool runs with no card.
- **Proposed fix:** Rust: add `"definition_changed": pin_hash.is_some() && pin_hash != current_hash` to `tool_view` (or make `pinned` mean pin == current) and clear `auto_approve` in the mismatch arm of `merge_tools`. Renderer: base the warning and `.changed` class on that flag and send `auto_approve:false` when (re-)enabling a changed tool; show what changed if feasible.
- **Confidence:** confirmed (renderer side reproduced with the exact backend view shape; Rust by reading)
- **Effort:** M


## A4-06: Closing a tab or locking the vault with an Approve card pending wedges the assistant globally; transcripts survive the lock
- **Severity:** Medium
- **Category:** js-logic
- **Location:** `src/renderer/assistant.js:749-755,839-843` (`assistantClearTab` is reached only via the `onSessionClosed` chain), `:294-303` (`aiSetThinking`), `:716-724` (`finally`); `src/renderer/app.js:4295-4325` (`closeSessionTab`), `:1179-1215` (`clearConnectView`, called on lock), `src/renderer/terminal.js:405-418,556-565` (`destroyTabTerminal` clears the poll that would call `teardown` -> `onSessionClosed`)
- **Evidence:** `onSessionClosed` fires only from the poll in `terminal.js` when a session ENDS; `closeSessionTab` and `clearConnectView` call `destroyTabTerminal` (which clears that poll) and never call `assistantClearTab`. Reproduced: (a) level `execute`, model returns `run_command`, Approve card shown, close the tab and open a new tab -> `#assistantInput.disabled === true`, `#assistantThinking` visible, `aiTabs` still holds the closed tab with `running:true`; (b) same pending card, lock + unlock via `refreshVaultStatus` -> input still disabled, thinking visible, `aiTabs` retained, old user message still in the DOM. The awaited card promise can never resolve, so `finally` (the only code that re-enables the input) never runs; `aiStopTurn` only acts on the active tab. Even after a completed turn, closing the only tab leaves its transcript visible while Send only toasts "Open a connection first."
- **Why it is a flaw:** an Approve card left waiting past auto-lock, or a tab closed instead of Deny, permanently disables the assistant for every tab until app restart ("spinner forever"). Locking the vault also does not drop assistant conversations (terminal-derived output, commands and service results) from JS memory/DOM, unlike sessions, SFTP panels and terminals that `clearConnectView` tears down.
- **Proposed fix:** call `assistantClearTab(tabId)` from `closeSessionTab` and for every tab in `clearConnectView`; make `assistantClearTab` deny any pending card, remove `s.listEl`, and reset the visible busy state if needed. Make busy state per-tab (A4-09) so one abandoned turn cannot disable other tabs.
- **Confidence:** confirmed (reproduced)
- **Effort:** M

## A4-07: The MCP edit form cannot round-trip auth config - editing an env-var server silently deletes its binding
- **Severity:** Medium
- **Category:** js-logic
- **Location:** `src/renderer/mcp.js:343-369,355-360` (`sv.auth_env_var`), `:388-398` (payload); `src-tauri/src/assistant/mcp.rs:1499-1515` (`mcp_list_servers` fields), `:1627-1657`
- **Evidence:** `mcp_list_servers` returns `id,name,url,auth_type,confirmed,loopback_insecure,status,tool_count,tools` only - no `auth_env_var`, `auth_header_name`, or `has_secret`. `mcpOpenForm` nevertheless reads `sv.auth_env_var` (always undefined), always blanks `mcpHeaderName`, and defaults the source to "Stored secret". Reproduced with the real list shape: opening a bearer server and changing only its name sends `mcp_save_server {"auth_type":"bearer","auth_header_name":null,"auth_secret":null,"auth_env_var":null}`; Rust's else branch assigns `record.auth_env_var = auth_env_var` (None), erasing the binding. Custom-header servers fail with "Custom header auth requires a header name." until the unseen header is retyped.
- **Why it is a flaw:** a routine edit breaks authentication without warning, and the user cannot see what was stored. The hint "Stored secret: leave blank to keep the current one" is also false whenever URL/auth/header changes (origin binding drops the secret at mcp.rs:1627-1632). A NEW bearer/custom server saved with no secret and no env var is accepted and only fails later at Test ("No auth source configured").
- **Proposed fix:** return `auth_header_name`, `auth_env_var`, `has_secret` from `mcp_list_servers`; prefill from them; show the hint only when `has_secret`; warn inline when a URL/auth/header change will discard the secret; refuse Save for bearer/custom_header when neither a new source nor an existing source is present.
- **Confidence:** confirmed (renderer payload reproduced; Rust assignment by reading)
- **Effort:** M

## A4-08: Enabling or disabling an MCP tool leaves the local registry and Auto-approve controls desynchronized
- **Severity:** Medium
- **Category:** js-logic
- **Location:** `src/renderer/mcp.js:91,122` (`!t.enabled || !t.pinned` filters), `:499-522` (`setToolState` + toggle wiring), `src/renderer/styles.css:540-570` (no disabled styling for `.toggle-chip`)
- **Evidence:** on success `setToolState` changes only `t.enabled` and `t.auto_approve`; the backend also sets/clears `pin_hash`, but local `t.pinned` is never changed. Reproduced: new tool `{enabled:false,pinned:false}`, click Enable -> IPC succeeds, local flags `{enabled:true,pinned:false}`, `mcpGetTools()` returns `[]` and `mcpResolveTool` rejects it until a later `mcpRefresh` (panel reopen / settings nav). The Auto-approve input is rendered disabled for a disabled tool and never re-enabled after Enable (`autoInput.disabled` is calculated once), with no visual disabled style. Conversely, disabling a tool whose Auto-approve box was checked leaves that box checked and enabled although the backend cleared the flag.
- **Why it is a flaw:** enabling a tool while the panel is already open leaves the model unable to use it until refresh; Auto-approve cannot be set without a re-render, and the displayed approval state can disagree with what the backend enforces.
- **Proposed fix:** after success run `await mcpLoadSettings(); mcpRenderTools();` (refreshes `pinned` and re-renders both boxes), or update `t.pinned`, `autoInput.disabled` and `autoInput.checked` in place. Add `.toggle-chip:has(input:disabled){opacity:.5;cursor:not-allowed}`.
- **Confidence:** confirmed (reproduced)
- **Effort:** S

## A4-09: One running turn disables the input and shows "thinking..." in every tab; Stop only acts on the active tab
- **Severity:** Medium
- **Category:** js-logic
- **Location:** `src/renderer/assistant.js:294-303` (`aiSetThinking`; the active-tab guard on line 302 comes after all global DOM writes), `:94-107` (`assistantOnTabSwitch` does not restore per-tab busy state), `:727-733` (`aiStopTurn` uses active tab)
- **Evidence:** reproduced with two tabs: turn running in A, switch to B -> `#assistantInput.disabled === true`, `#assistantThinking` visible; click the displayed Stop button while viewing B -> A remains `running:true, stopRequested:false`.
- **Why it is a flaw:** B cannot be used while A waits (up to two minutes per provider call, indefinitely at an approval card); B shows a spinner for work it is not doing, and that spinner's Stop button does nothing to the actual turn. This is why A4-06 becomes global rather than local.
- **Proposed fix:** make `aiSetThinking` touch DOM only when `tabId === state.activeTabId`; have `assistantOnTabSwitch` apply thinking/input/send state from `aiTabState(tabId).running`.
- **Confidence:** confirmed (reproduced)
- **Effort:** S

## A4-10: YOLO survives a session drop and Reconnect; the code comment claims the level is cleared
- **Severity:** Medium
- **Category:** security
- **Location:** `src/renderer/assistant.js:837-843` (comment: "Clear a tab's conversation and level when its session closes"), `:749-755` (`assistantClearTab`), `:109-118` (`aiRefreshLevel`), `src-tauri/src/assistant/mod.rs:62-72` (levels are removed only by `clear()` on vault lock)
- **Evidence:** `assistantClearTab` deletes only the renderer state; it never calls `assistant_set_level`, and no backend path removes a tab's level when its session ends. Reproduced: tab at YOLO, session dropped through the close-detection path -> 0 `assistant_set_level` calls; the re-created panel state calls `assistant_get_level`, receives `yolo`, and the red YOLO badge and Danger caption are shown for the dead session. `Reconnect` reuses the same `tabId`, so the new SSH session starts at YOLO without the one-time confirmation dialog.
- **Why it is a flaw:** assistant.js's header says the level is per tab, in memory, and cannot survive; the cleanup comment says it is cleared on session close. In code, a disconnected tab that is later reconnected silently re-arms full autonomy for the new session (a changed remote host account, a new server key, or simply a long-forgotten tab).
- **Proposed fix:** in `assistantClearTab` (and on tab close) call `assistant_set_level {tabId, level:'read'}`; optionally have the Rust side drop a tab's level when its session ends.
- **Confidence:** confirmed (renderer side reproduced; backend persistence by reading)
- **Effort:** S

## A4-11: The renderer ignores the backend's 64-character MCP tool name (`exposed_name`) - one long tool can break every chat request
- **Severity:** Medium
- **Category:** ipc
- **Location:** `src/renderer/mcp.js:92,123` (names rebuilt from `mcpSanitizeName` with no cap), `src-tauri/src/assistant/mcp.rs:284-332` (`exposed_tool_name` truncates + hashes to 64), `:1481-1483` (`tool_view` sends `exposed_name`)
- **Evidence:** `tool_view` emits `exposed_name` with the comment "the renderer derives it identically"; the renderer never reads it. Reproduced: server `my-company-internal-tools` + tool `list_pull_request_review_comments_for_repository` -> `mcpGetTools()` offers an 80-character name while the backend view carries its capped, hashed name. The backend's collision map is built on the capped spelling, while renderer resolution uses the uncapped spelling.
- **Why it is a flaw:** OpenAI-compatible and Anthropic tool names are limited to 64 characters, so enabling one such tool makes the provider reject the whole tool list on every chat request, not only requests that use that tool; collision decisions also differ across the IPC boundary.
- **Proposed fix:** use `t.exposed_name` in `mcpGetTools` and compare against it in `mcpResolveTool`; for old backends, implement the exact same 64-character + SHA-256 suffix algorithm as Rust.
- **Confidence:** likely (renderer/backend mismatch reproduced; provider rejection from documented API limits, not exercised live)
- **Effort:** S


## A4-12: Save/Test have no busy state: double-click Save creates duplicate MCP servers, and equal-name servers bypass collision detection
- **Severity:** Medium
- **Category:** js-logic
- **Location:** `src/renderer/mcp.js:377-408` (`mcpSaveServer`), `:412-425` (`mcpTestConnection`), `:233-243` (row buttons); `src/renderer/assistant.js:773-800` (assistant Save/Test); `src-tauri/src/assistant/mcp.rs:345-397` (`build_name_map`), `src-tauri/src/db/mod.rs:449-455` (id-only primary key)
- **Evidence:** reproduced: slow `mcp_save_server`, double-click Save -> 2 invocations, both `id:null`, so Rust allocates two UUIDs and saves two records with the same name. No save/test/remove button is disabled while awaiting (`#aiTestBtn.disabled === false` during a delayed call; MCP Test can wait through multiple 60-second requests). The backend permits duplicate names. `build_name_map` records `server_seen` by NAME and treats two equal strings as the same server; its final map stores `(server_name, tool_name)`, so equal-name/equal-tool pairs also look identical. The renderer's resolver simply takes the first registry match.
- **Why it is a flaw:** a normal double-click creates duplicate rows; model-facing names and Approve cards cannot distinguish them; toggles can modify one server while calls resolve to another. Test/Save also look idle during long operations and can be launched repeatedly.
- **Proposed fix:** add an in-flight guard plus `disabled`/`aria-busy` for every Save/Test/Remove action; reject duplicate sanitized server names in `mcp_save_server`; build the collision map with server id as identity while retaining the name only for the exposed prefix and messages.
- **Confidence:** confirmed (double-save reproduced; collision logic proven by reading)
- **Effort:** M

## A4-13: The stored API key cannot be removed in the UI, and changing provider/Base URL reuses that key at the new origin
- **Severity:** Medium
- **Category:** security
- **Location:** `src/renderer/assistant.js:773-791` (`aiSaveConfig` never sends `clearApiKey`), `src/renderer/index.html:391-394`; `src-tauri/src/assistant/mod.rs:104-163` (`clear_api_key` and key retention), `:195-210,557-575` (the retained key is sent to resolved Base URL)
- **Evidence:** Rust explicitly added `clear_api_key: Option<bool>` because blank `api_key` means "keep the stored key" and otherwise made removal impossible; no renderer code references that argument and no Remove control exists. Reproduced save payload with a blank key: `{"provider":...,"base_url":...,"model":...,"api_key":null,"apiKey":null}`. The same retained sealed key survives a provider or Base URL change and `load_provider` sends it as bearer/x-api-key to the new host. Unlike MCP's `mcp_save_server` origin-binding, assistant config has no origin-change check. Rust also accepts plain `http://` for any provider host although its error says "for local servers"; the UI gives no warning.
- **Why it is a flaw:** users cannot revoke a provider credential without replacing it or wiping the vault. More importantly, choosing OpenRouter/Groq/a LAN endpoint with the key field blank silently sends the previously stored provider's credential to a different origin.
- **Proposed fix:** add "Remove stored key" -> `clearApiKey:true`; when host/provider changes, require a new key or an explicit "reuse this key at the new endpoint" confirmation; warn or refuse plain HTTP unless loopback.
- **Confidence:** confirmed (removal gap and payload reproduced; key follows changed origin proven by Rust path)
- **Effort:** M

## A4-14: Provider presets do not set the provider, Test ignores unsaved fields, and re-opening the section discards edits
- **Severity:** Medium
- **Category:** ux
- **Location:** `src/renderer/assistant.js:759-800` (load/save/test), `:824-835` (preset and nav handlers), `src/renderer/index.html:368-400` (form / static `#aiStatus`)
- **Evidence:** reproduced: saved provider `anthropic`, choose preset "Ollama" -> Base URL becomes `http://localhost:11434/v1`, provider remains Anthropic, so Rust calls `.../v1/v1/messages`; choosing the Anthropic preset while provider remains OpenAI leads to `https://api.anthropic.com/chat/completions`. The Base URL placeholder stays OpenAI's even when Anthropic is selected. After typing a new model and clicking Test, IPC is `assistant_test_connection {}`: it tests the previously saved config, not the visible form, and can toast success naming the old model/URL. `#aiStatus` is never written. Clicking the already-active AI settings item runs `aiLoadConfig` again and silently overwrites unsaved provider/Base URL/model edits (the API-key field remains, making the form internally mixed).
- **Why it is a flaw:** the quickest setup path creates a confusing 404; Test can say "Connected" for values different from what is on screen; ordinary navigation loses edits without warning.
- **Proposed fix:** give presets a provider and set provider + URL + placeholder together; either pass form values to a test command or Save before Test / label it "Test saved settings"; write persistent progress/result to `#aiStatus`; track dirtiness and prompt before reload.
- **Confidence:** confirmed (reproduced)
- **Effort:** M

## A4-15: MCP list/status/tool views go stale and the "N tools" label actually counts only enabled tools
- **Severity:** Medium
- **Category:** ux
- **Location:** `src/renderer/mcp.js:193-221` (dot/count), `:412-425` (no refresh on test failure), `:549-577` (`mcpLoadSettings` replaces registry but does not re-render tool host); `src-tauri/src/assistant/mcp.rs:1503-1513` (`tool_count` = enabled count)
- **Evidence:** reproduced: a server with one known but disabled tool renders `0 tools`; a failed `mcp_test_connection` updates the backend state to `status:"error"` but the row remains `title="unknown"` with a neutral dot because the catch only toasts and never reloads. `mcpLoadSettings` later replaces the `mcpServers` array but does not call `mcpRenderTools`, so existing tool-row event closures continue mutating objects from the old snapshot. There is no row action to show already-discovered tools; Test is the only action that calls `mcpShowToolsFor`. `mcp_list_servers` also returns `confirmed` (mcp.rs:1509) but `mcp.js` never reads it, so a backup-restored (inert) server looks like any other row and only fails at Test with a toast (SECURITY.md:260-268 promises re-confirmation by re-saving).
- **Why it is a flaw:** after discovery a server can appear to have zero tools; a dead connection never visibly turns red; toggles can operate on stale UI state; reviewing a server's existing tool permissions unnecessarily reconnects it.
- **Proposed fix:** badge unconfirmed rows ("review and re-save before connecting"); render `enabled / total` from `sv.tools`; refresh/list-render in `finally` of Test and show the stored error beside the row; call `mcpRenderTools()` after every registry reload; add a "Review tools" row action independent of Test.
- **Confidence:** confirmed (reproduced and traced)
- **Effort:** M

## A4-16: Conversation and tool-result history is unbounded; a single MCP call can add about 2 MB that is resent on every model loop
- **Severity:** Medium
- **Category:** perf
- **Location:** `src/renderer/assistant.js:665-688,692,703` (`s.messages` grows and the full list is sent), `:615-624` (wrapper adds but does not cap), `src/renderer/mcp.js:141-153` (full content returned), `src-tauri/src/assistant/mcp.rs:58-60` (`MAX_BODY_BYTES = 2 MB`), `src/renderer/index.html:231-235` (no Clear/New chat control)
- **Evidence:** there is no splice/trim/reset of `s.messages`; each loop uses `s.messages.slice()` and each user turn keeps every assistant/tool result forever. Reproduced with one MCP result of 1,500,000 characters: history stored a tool message of 1,500,097 chars and the immediately following `assistant_chat` payload was 1,501,626 chars; no result text was visible in the transcript. The backend permits a response body up to 2 MB and one turn permits 25 calls, so tens of MB can be retained/reserialized before the next user message. Built-in terminal results are also retained (up to about 8 KB each).
- **Why it is a flaw:** latency, provider cost, serialization work and renderer memory grow monotonically; a few large tools can hit the model context limit or freeze the UI. There is no user-facing recovery except closing the session tab, and A4-03 can leave a broken history that needs exactly such a reset.
- **Proposed fix:** add a New chat/Clear button that resets history and DOM while retaining the access level; cap each tool result before storing/sending (with an explicit truncation marker); retain only the latest N complete assistant/tool groups under a token/byte budget.
- **Confidence:** confirmed (reproduced)
- **Effort:** M

## A4-17: YOLO and Auto-approved MCP calls leave no visible record of which service/tool/arguments ran; tool-call commentary and results are suppressed
- **Severity:** Medium
- **Category:** ux
- **Location:** `src/renderer/assistant.js:585-600` (no card on YOLO/auto-approve), `:689-709` (assistant text displayed only when there are no tool calls), `src/renderer/mcp.js:141-153` (tool identity/result returned only to history), `src-tauri/src/assistant/mcp.rs:1941-1950` (only the separate audit log records server/tool)
- **Evidence:** reproduced at YOLO with an auto-approved `mcp__srv__delete_issue` call and arguments `{"issue":42}`: 0 cards; visible transcript was only user "clean up the tracker" then assistant "Done." The model's first reply text "Deleting the issue now." was pushed to hidden history but never rendered, and the tool result was not rendered either. The transcript contained no server name, tool name, arguments, success/error, or result; only Settings -> Audit can reveal a hashed-argument entry.
- **Why it is a flaw:** in the exact modes where confirmation is intentionally skipped, the user cannot tell what side effect occurred or which connected account was touched. A provider could call several SaaS tools and finish with "Done"; the chat provides no accountability or usable troubleshooting trail.
- **Proposed fix:** always append a non-interactive tool-event row for every call (server, real tool name, pretty args, approval source: explicit/auto/YOLO, success/error, truncated result); render any assistant text accompanying tool calls before starting them.
- **Confidence:** confirmed (reproduced)
- **Effort:** M
## A4-18: OpenAI-style chat requests always send `max_tokens`, which current OpenAI reasoning/GPT-5-class models reject
- **Severity:** Medium
- **Category:** rust-logic
- **Location:** `src-tauri/src/assistant/mod.rs:331-335` (`openai_body`: `"max_tokens": max_tokens`), `src/renderer/assistant.js:683-688` (always sends `max_tokens`/`maxTokens`), `src/renderer/index.html:370,389` (default provider and `gpt-4o-mini` placeholder)
- **Evidence:** the request body is built with `max_tokens` unconditionally; there is no provider/model switch and no retry with `max_completion_tokens`. OpenAI documents `max_tokens` as deprecated in Chat Completions and incompatible with its o-series reasoning models; its newer GPT-5-class models answer such requests with an "Unsupported parameter: 'max_tokens' ... Use 'max_completion_tokens' instead" 400. Not exercised against a live provider here.
- **Why it is a flaw:** if the flagship models behave as documented, the default "OpenAI-compatible" provider would pass Settings -> Test (a GET /models call) and then fail every chat turn with a provider error, while local servers (Ollama/LM Studio/Groq) still need `max_tokens`. The failure appears only after setup is "successful".
- **Proposed fix:** send `max_completion_tokens` when the base URL is api.openai.com (or on a 400 mentioning `max_tokens`, retry once with it), and make Test exercise a one-token chat request so setup validates the real path.
- **Confidence:** suspected (documented provider behaviour; not verified live)
- **Effort:** S

## A4-19: A late reply for a tab whose session dropped replaces the active tab's visible conversation
- **Severity:** Low
- **Category:** js-logic
- **Location:** `src/renderer/assistant.js:188-197` (`aiAppendMsg` -> `assistantOnTabSwitch` when `listEl` is null), `:94-107` (hides every other list), `:749-755` (`assistantClearTab` deletes state but not its DOM list), `:650-725`
- **Evidence:** reproduced: turn pending in background tab A, user viewing tab B (B's list visible), A's SSH session drops (close detection -> `assistantClearTab(A)`), then A's provider reply arrives. `aiAppendMsg(A,...)` creates a new ghost state/list and calls `assistantOnTabSwitch(A)`; B's list becomes hidden and `["late reply for A"]` is visible while `state.activeTabId` is still B. `aiTabs` gains a ghost A entry, and the cleared A list remains as another hidden subtree (each cleared session leaves its `.ai-tab-list` in the DOM forever). On the ACTIVE tab the same sequence self-heals, which is why the trigger (background tab whose session ends mid-turn) is rare.
- **Why it is a flaw:** the user sees another tab's reply in place of the current conversation until they switch tabs; every occurrence leaks a DOM subtree and per-tab state.
- **Proposed fix:** in `aiRunTurn` abandon UI/history work when `aiTabs.get(tabId) !== s`; `aiAppendMsg` must create a non-active tab's list without changing visibility; `assistantClearTab` should `s.listEl.remove()`.
- **Confidence:** confirmed (reproduced)
- **Effort:** S

## A4-20: Markdown renderer defects: fenced code shows its language tag as code, numbered lists become bullets, a lone `*` pair eats glob characters
- **Severity:** Low
- **Category:** ui
- **Location:** `src/renderer/assistant.js:204-217` (`aiRenderText`), `:238-247` (list regex always builds a `<ul>`), `:261-284` (`aiRenderInline`)
- **Evidence:** reproduced: input `1. first\n2. second\n```bash\nls -la /tmp/*.log\n```\nuse *.log and *.txt` renders `<ul><li>first</li><li>second</li></ul>`, `<pre><code>bash\nls -la /tmp/*.log\n</code></pre>` and `use <em>.log and </em>.txt`.
- **Why it is a flaw:** every fenced reply starts with a stray "bash" line inside the code block (a visible and copy-pasted artifact when the user selects the block); numbered steps lose their numbers; glob patterns in prose are mangled into italics.
- **Proposed fix:** drop the first line of an odd-index fence part when it matches `/^[\w+#.-]*$/`; render `^\s*\d+\.` items as `<ol>`; require non-space characters adjacent to the `*` delimiters and no preceding word character for `*italic*`.
- **Confidence:** confirmed (reproduced)
- **Effort:** S

## A4-21: YOLO dialog: Escape does nothing, a missing modal arms YOLO with no confirmation, and the dialog does not name its target
- **Severity:** Low
- **Category:** a11y
- **Location:** `src/renderer/assistant.js:167-181` (`:169` `if (!modal) { aiCommitLevel(tabId, 'yolo', prev); return; }`), `src/renderer/app.js:3401-3418` (global Escape chain omits `#yoloModal`), `src/renderer/index.html:505-541`
- **Evidence:** reproduced: opening the dialog correctly focuses Cancel, but pressing Escape leaves `#yoloModal` visible (the global handler lists palette, picker, deploy, key, server and vault modals only). The `!modal` branch fails open on the one security opt-in. The text never says which session/server it arms, and `role="alertdialog"` has no `aria-describedby`.
- **Why it is a flaw:** an alertdialog that ignores Escape traps keyboard users until they Tab to Cancel; fail-open code on the most dangerous switch is a latent regression trap; with several tabs open the user cannot confirm which host is being armed.
- **Proposed fix:** add `#yoloModal` to the Escape chain (call the same `close(false)`); fail closed (toast + return) when the modal is missing; include the server name/host in the dialog and add `aria-describedby`.
- **Confidence:** confirmed (Escape reproduced; the rest by reading)
- **Effort:** S

## A4-22: Provider labels and placeholders look unfinished, and docs promise an "unsupported transport" error that does not exist
- **Severity:** Low
- **Category:** html
- **Location:** `src/renderer/index.html:370,379,400` (`[OI]-compatible`, preset `[OI]`, status text), `:389` (`placeholder="gpt-4o-mini / "`), `:432` (`placeholder="https://mcp.example.com/sse"`); `CHANGELOG.md:17-20` (1.9.1), `docs/SECURITY.md:215-216`
- **Evidence:** the provider dropdown shows "[OI]-compatible (chat/completions)", the preset list contains an entry named "[OI]", and the status line says "Works with [OI], OpenRouter, Groq, ..." (the same token appears in README/CHANGELOG and Rust comments; it looks like an unreplaced placeholder for the vendor name - disregard if it is an intentional redaction in this checkout). The model placeholder ends in a dangling " / ". The MCP URL placeholder points to an `/sse` endpoint although only Streamable HTTP is supported. CHANGELOG says stdio and legacy HTTP+SSE "are refused with a clear 'unsupported transport' error", but no such message exists in `mcp.rs` (a legacy server just yields "MCP server returned HTTP 405.").
- **Why it is a flaw:** a primary settings surface shows what reads as a template token and a truncated hint; the URL placeholder nudges users toward an unsupported transport; the documented error does not exist.
- **Proposed fix:** replace the token with the intended provider name; complete the model placeholder (for example `gpt-4o-mini or claude-sonnet-4-5`); use `https://mcp.example.com/mcp`; either implement an unsupported-transport message (map 405 / SSE-only replies) or soften the docs.
- **Confidence:** confirmed (strings present in the files); likely a flaw (the `[OI]` token may be an artifact)
- **Effort:** S

## A4-23: The form and the backend disagree on which http URLs are loopback, and the backend silently drops the URL query
- **Severity:** Low
- **Category:** ux
- **Location:** `src/renderer/mcp.js:304-310` (`mcpIsLoopbackUrl`), `src-tauri/src/assistant/mcp.rs:96-136` (`classify_url`: accepts `127.*`, rejects `*.localhost`, rebuilds the base from `url.path()` only)
- **Evidence:** the JS accepts `foo.localhost` and rejects `127.0.0.2`; Rust accepts `127.*` and rejects `*.localhost`. `classify_url` rebuilds `scheme://host[:port]path`, so `?query` and `#fragment` are discarded: `https://x/mcp?key=...` is saved without the query and without any message.
- **Why it is a flaw:** the form passes `*.localhost` and then fails with a backend toast; `127.0.0.2` is blocked in the form though the backend allows it; a query-string credential or routing parameter vanishes silently and the server then fails to authenticate.
- **Proposed fix:** make the JS check mirror Rust (`h === 'localhost' || h === '::1' || /^127\./.test(h)`); either preserve the query or reject a URL that contains one with an explicit message.
- **Confidence:** confirmed (by reading)
- **Effort:** S

## A4-24: Accessibility gaps in the assistant panel and the MCP settings
- **Severity:** Low
- **Category:** a11y
- **Location:** `src/renderer/index.html:245-253` (`#assistantMessages`, `#assistantThinking`, `#assistantInput`), `:374-387` (Base URL label), `:434-437` (`#mcpUrlWarn`/`#mcpUrlError`), `src/renderer/assistant.js:355-388,396-440` (cards), `src/renderer/mcp.js:193-198` (status dot)
- **Evidence:** the transcript and the thinking row have no `aria-live`/`role`, so replies and Approve/Deny cards are never announced and focus never moves to a pending card (the input is disabled while a card waits); the textarea has only a placeholder; the Base URL `<label>` wraps both the input and the preset select, so the input's accessible name picks up the select's text; the URL error `<p>` has no `role="alert"`, `aria-describedby` or `aria-invalid`; the MCP status is a coloured dot with only a `title`; the toggle button has no `aria-pressed`.
- **Why it is a flaw:** screen-reader and keyboard-only users cannot tell that the assistant answered, that a command awaits approval, or whether a server is connected.
- **Proposed fix:** `role="log" aria-live="polite"` on the transcript, `role="status"` on the thinking row, focus the Approve button when a card appears, `aria-label` on the textarea, separate label for the preset select, `role="alert"` on the URL error, and a text label (visually hidden) on the status dot.
- **Confidence:** confirmed (by reading)
- **Effort:** S

## A4-25: Dead code and comments that no longer match the code
- **Severity:** Low
- **Category:** js-logic
- **Location:** `src/renderer/assistant.js:862-865` (`assistantOpenSettings`), `:302` (dead guard in `aiSetThinking`), `src/renderer/mcp.js:74-78,98-102` (description comment), `:59` (broad error regex)
- **Evidence:** `assistantOpenSettings` has no caller anywhere in `src/renderer`, and `showSettingsSection` does not load the config form or MCP list, so the helper that should take a user from the "AI assistant is not configured" error to Settings would not work. The comment at mcp.js:74-78 says the description is "truncated hard" before it reaches the model, but the code never forwards `t.description` at all (the model gets only `MCP server "x", tool "y"` plus the schema). `mcpRefresh` treats any error matching `/not a valid|unknown|no such|not found|missing/i` as "backend has no MCP support": a corrupt stored record (serde "missing field ...") or a database error ("no such table") sets `mcpAvailable=false` for the whole session and shows "This build of the backend has no MCP support".
- **Why it is a flaw:** the unconfigured-provider error has no path to Settings; the comment misdescribes a security decision (omit vs truncate); one transient or data error disables MCP with a wrong explanation until restart.
- **Proposed fix:** wire `assistantOpenSettings` to the not-configured error and have it call `aiLoadConfig`; delete the dead guard; fix the comment (or forward a truncated description deliberately); match only Tauri's "Command ... not found" message.
- **Confidence:** confirmed (by reading)
- **Effort:** S

## A4-26: Suggestion-card and error-path rough edges
- **Severity:** Low
- **Category:** ux
- **Location:** `src/renderer/assistant.js:341-346` (Run), `:566-570` (`type_command` result), `:712-715` (error shown twice), `:743-745` (input cleared before the turn), `src-tauri/src/assistant/mod.rs:223-235` (`provider_error`)
- **Evidence:** a failed Run leaves the button permanently disabled (`run.disabled = true` is never reset); Run on a `propose_command` card with an empty `command` calls `assistant_exec` with `""` and sends a bare Enter (the `run_command` path rejects empty commands, the card path does not); `type_command` returns `typed: ...` even when `sendTerminalBytes` resolved false (not awaited) so the model is told it worked; provider 400/429/5xx messages embed up to 300 characters of unparsed JSON; the user's message is cleared from the input on any failure (it stays in history); each error is shown both as a chat row and as a toast.
- **Why it is a flaw:** small but frequent annoyances, plus a bare Enter sent to a live shell and a tool result that misreports success.
- **Proposed fix:** re-enable Run on error and ignore empty commands; await the typed bytes and report failure; extract `error.message` from the provider JSON; restore the input text on failure; show each error once.
- **Confidence:** confirmed (by reading)
- **Effort:** S

## A4-27: `mcp_remove_server` fails the first time when the server is unreachable, but has already dropped the session
- **Severity:** Low
- **Category:** rust-logic
- **Location:** `src-tauri/src/assistant/mcp.rs:1687-1705`
- **Evidence:** `remove_session(&id)` runs first; if `delete_session(...)` then fails (offline, 401) the command returns `Err` before `db.delete_mcp_server`, so the server stays listed and the user gets an error toast. A second Remove finds no session and succeeds without any teardown, which defeats the stated intent ("a refused teardown fails the removal instead of silently leaking the session").
- **Why it is a flaw:** an unreachable or retired server cannot be removed on the first attempt, and the retry behaviour is accidental rather than designed.
- **Proposed fix:** attempt the teardown best-effort and audit its failure (as `teardown_all` does) but always delete the record, or keep the session in the map until the DELETE succeeds.
- **Confidence:** confirmed (by reading)
- **Effort:** S
