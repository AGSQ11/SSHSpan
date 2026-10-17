# MCP smoke-test checklist

**Last updated:** 2026-10-17  
**Status:** describes the remediation branch; checked against committed source at `38e586e`, which
changed the smoke mock (steps 5, 19 and 26); nothing MCP-related has changed since

A manual QA pass for the MCP feature. Run the real app against the mock server in
`scripts/mcp-smoke-server.py`. Each step names the Rust unit/integration test that already proves
the underlying backend property when one exists, so manual and automated evidence can be reconciled.
The renderer half (approval cards, the enable flow, the form rules) is covered by
`npm run test:assistant` against stubbed IPC; this checklist is the end-to-end pass with a real
backend and a real webview.

## Prerequisites

1. Start the mock server:

   ```bash
   python scripts/mcp-smoke-server.py 8777
   ```

   Expected: the console prints the URL and test banner, and the process stays running.

2. Unlock the vault. A model provider is needed only for steps that ask the assistant to choose a
   tool. A local Ollama/LM Studio provider is sufficient for those steps.

## Network destinations (what should appear in a packet capture)

- The only address the app contacts for MCP during this checklist is `127.0.0.1:8777`, configured by
  you. The mock binds loopback only and makes no outbound connection itself.
- MCP traffic is POST from the **Rust backend** to the configured server URL, plus a best-effort
  `DELETE` that ends each session when the vault locks, the app quits, the server is removed, or its
  URL or credential is edited. The renderer never fetches an MCP URL, so no MCP request should
  originate from the webview process.
- Model traffic goes to the provider base URL in Settings > AI assistant and is separate from MCP.
  Terminal text and tool results can be sent to that provider; use a local provider for this
  checklist.
- Nothing should connect to a URL returned in a `Location` header (step 16). The redirect target
  must show zero inbound requests.

## Settings / add server

3. Open **Settings > AI assistant > MCP servers** and add a server with URL
   `http://127.0.0.1:8777/mcp`.

   Expected: the form accepts `127.0.0.1`; after saving, the row shows "Plain HTTP on a loopback
   address - traffic to this server is not encrypted or authenticated." The form refuses a
   non-loopback plain `http://` URL ("Plain http:// is only allowed for localhost, 127.x or ::1 -
   use https:// for anything else.").

   Notes: loopback means `localhost`, `::1`, or an IPv4 address in `127.0.0.0/8`, parsed - a host
   name that merely starts with "127." (such as `127.example.com`) is refused by the form and by the
   backend. IPv6 URLs keep their brackets.

   Automated: `http_is_allowed_only_for_loopback`, `https_urls_are_accepted_everywhere`.

4. Try the URL `http://127.0.0.1:8777/mcp?token=x` (and one ending in `#frag`).

   Expected: the form refuses it - "MCP server URLs cannot carry a ?query or #fragment - SSHSpan would
   connect without it. Remove everything from the ? or # on; put a token in the auth settings below."
   The backend refuses the same URL ("MCP server URLs cannot contain ?query or #fragment parts."),
   so an older entry cannot smuggle one in. A token belongs in the auth settings.

   Automated: `mcp_urls_with_a_query_or_fragment_are_refused`.

## Connection / discovery

5. Click **Test connection** for the new server.

   Expected: a success toast ("MCP: 5 tools returned.") and a status dot; the row shows "MCP
   protocol 2025-11-25"; the mock prints nothing for these requests (its request log is silenced:
   after its banner it prints only a line for a `DELETE`, for the one-shot 404 and for a list
   change it announces), but in a capture the `initialize` answer carries
   `Mcp-Session-Id: 00000000-0000-0000-0000-000000000001` and `notifications/initialized` sends it
   back. A failure shows its error inline in the server's row.

   Automated: `initialize_negotiates_version_and_stores_session`,
   `every_post_carries_the_streamable_http_headers`.

6. Save the server and open its tool list.

   Expected: "MCP server saved." (a follow-up that failed after the save, such as an audit row, is
   shown as a warning instead of an error). The list is headed `Tools from "<name>" (0/5 enabled) -
   review each before enabling:` and shows five tools across three pages of up to two (`echo`,
   `get_time`; `read_file`, `make_error`; `image_cat`), each with its description and input schema.
   All five arrive disabled.

   Automated: `paginated_tools_list_returns_every_page`.

## Approval / enabling

7. Leave all tools disabled. Ask the assistant to use the MCP `echo` tool.

   Expected: nothing executes; disabled tools are not offered to the model.

   Automated: `merge_preserves_pins_and_disables_changed_tools`.

8. Turn **Enable** on for `echo` only. Enabling is the approval of the **definition you were shown**:
   the renderer sends that row's `definition_hash` as `expected_hash`, and the backend refuses an
   enable that carries none or a stale one.

   Expected: `echo` enables, the audit log records `mcp.tool_approved`, and asking for `read_file`
   does not offer or run it because it remains disabled.

   For reference, a refused enable reads "This approval does not say which tool definition you
   reviewed - reload the MCP server's tools, review the tool and approve it again." (no hash) or a
   "definition changed - review it and approve again" message (stale hash); the row then reloads and
   shows the current definition (`Tool "echo" was not approved: ... Its current definition is shown
   below - review it, then enable it again.`).

   Automated: `enabling_without_a_definition_hash_is_refused`,
   `enabling_with_a_stale_definition_hash_is_refused`.

9. Turn **Auto-approve** on for `echo` only.

   Expected: Auto-approve is disabled until Enable is on (its tooltip says "Enable the tool first").
   With it on, calls to `echo` can run at Execute without a card; other enabled tools still use the
   card. At Read and Draft a card is still shown and the call must carry renderer approval -
   Auto-approve applies from Execute up.

   Automated: `the_call_gate_needs_approval_below_execute_and_names_who_approved` covers the Rust gate.

## Access-level boundary

10. Set the assistant to **read**. Ask it to run `echo`.

    Expected: an approval card shows the server, the tool and every argument in full. Approve runs
    the call once (the audit row says it was approved); Deny does not call the backend. Without the
    approval the backend answers "AI access level is 'read' - tool calls need your approval."

11. Set to **draft**. Ask it to run `echo`, then ask it to type a command into the terminal.

    Expected: the tool call behaves as at Read. Typing goes through the backend's typing gate: text
    with a line break, a control character or a character that can disguise it is refused with the
    backend's message and nothing is typed; accepted text appears at the prompt and Enter is never
    pressed.

12. Set to **execute**. Ask it to run `echo hello`.

    Expected: an approval card shows server, tool, and arguments (invisible and text-direction
    characters spelled out); Approve sends `approved: true`; Deny does not call the backend. With
    Auto-approve on `echo` (step 9) the call runs without a card.

13. Set to **yolo** and ask for `echo hello`.

    Expected: the call runs without a card, but only for a tool that was enabled and approved; a
    disabled tool or a changed definition is still refused.

    Steps 10-13: the gate's rules for each level are in the pure `call_gate`, which
    `the_call_gate_needs_approval_below_execute_and_names_who_approved` covers (step 9). The
    `mcp_call_tool` command around it, which reads the stored level and runs the gate, needs a
    Tauri `AppHandle`, and no automated test invokes it; these steps check that wiring. The human
    click is renderer-attested: Rust checks the level and the definition, and cannot tell a real
    click from a claimed one.

## Rug-pull guard

14. With `echo` approved, edit the `description` of the `echo` tool in `scripts/mcp-smoke-server.py`.
    Restart the mock and press **Test connection** on the server.

    Expected: `echo` is disabled and its auto-approve cleared, the row is marked changed and says
    "Definition changed - re-approve: review the new definition above, then turn Enable on to
    approve it.", the Enable toggle's tooltip says "Approve the changed definition shown above", and
    the audit log records `mcp.tool_definition_changed`.

    Automated: `a_changed_definition_is_disabled_loses_auto_approve_and_is_flagged`,
    `list_changed_flag_drives_refetch`, `list_changed_refresh_persists_to_database`.

15. Re-approve `echo` and run it.

    Expected: turning Enable on names the newly shown definition hash and the tool works.

    Two checks sit behind this that a manual pass cannot reliably provoke:

    - The stale-row refusal (an enable that carries a hash older than the stored one): the backend
      compares the hash the page sends with the hash stored by the last fetch of the list, which
      changes only when SSHSpan fetches the list again.
    - The gate re-check: right before every `tools/call` the backend runs the gate again on the
      record as stored at that moment. A tool whose approval was revoked since the first check,
      and one that a refresh found changed meanwhile (the refresh disables it and clears its
      Auto-approve, as in step 14), are refused with "Tool 'echo' is not enabled - enable it in
      the MCP server settings.", the message step 26 shows. The gate's other refusal, "Tool 'echo'
      changed on the server since it was approved - re-approve it in the MCP settings.", is for a
      tool that is still enabled although its stored definition no longer matches the approved
      one. SSHSpan never stores such a record itself (an enable pins the current definition, and a
      refresh disables a changed tool), so only Rust tests that set one up directly get that
      message. The re-check reads only what SSHSpan has stored, so a definition changed only on
      the server is seen once SSHSpan fetches the list again: on Test connection (step 14), or
      after a `notifications/tools/list_changed` that comes with a call or with the answer to a
      session's `initialize`, which includes a renewed session (step 26).

    Automated: `enabling_with_a_stale_definition_hash_is_refused` (the stale enable),
    `a_tool_revoked_while_the_session_is_set_up_is_never_called` (the re-check refuses a tool
    revoked while the session is set up, with "not enabled") and
    `a_tool_changed_while_an_expired_session_is_renewed_is_not_called_again` (the test writes a
    changed definition for the still-enabled tool while a lost session is renewed, and the
    re-check refuses it with "changed on the server").

## Error / edge paths

16. Configure a second server with URL `http://127.0.0.1:8777/mcp-redirect` and test it.

    Expected: hard error; the client does not follow the redirect and the mock's redirect target
    receives no request.

    Automated: `redirect_is_a_hard_error`, `auth_header_never_leaves_the_configured_origin`.

17. The mock's one-shot 404 fires only for fixed session id `00000000-0000-0000-0000-000000000404`,
    which the real client never holds. Drive the mock directly:

    ```bash
    curl -X POST http://127.0.0.1:8777/mcp \
      -H "Content-Type: application/json" \
      -H "Mcp-Session-Id: 00000000-0000-0000-0000-000000000404" \
      -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
    ```

    Expected: HTTP 404 on the first call and a normal result on the repeated call.

    The client behavior - a real 404 mid-session performs exactly one re-initialize and retry - is
    covered by `session_404_reinitializes_once`.

18. Enable `make_error` (all five tools arrive disabled; review it and turn Enable on), then call
    it.

    Expected: `isError: true` is surfaced as an error, not a normal result.

    Automated: `tool_result_surfaces_is_error`.

19. Enable `image_cat` the same way, then call it.

    Expected: the mock answers with a real image content block,
    `{"type":"image","mimeType":"image/png","data":"<base64 of a 1x1 PNG>"}`, as the only block of
    the result. SSHSpan shows and forwards no image: the backend turns the block into the text
    `[image omitted]`. The assistant transcript gets a tool-event row headed
    `MCP <server> - image_cat` with the outcome "done" (not "failed"); after the arguments its
    body reads `Result: [image omitted]`, and no picture and no base64 appears anywhere. The model
    receives the same text, wrapped as untrusted output, and the audit log has an `mcp.tool_call`
    row with `result=ok`.

    Automated: `tool_result_shaping_covers_all_content_kinds` (an image block becomes
    `[image omitted]`).

## Authentication

20. Set `MCP_TEST_TOKEN=secret123` in the environment SSHSpan is launched from (SSHSpan reads the
    variable from its own process environment, so set it before starting the app), add a server
    using environment-variable auth with variable name `MCP_TEST_TOKEN`, and test it.

    Expected: the connection succeeds. The mock does not validate the header value; inspect the
    request trace or temporarily make the mock reject it if you need proof that the header was sent.
    Saving the server keeps the variable's name only, never its value (a new server gets "MCP
    server saved."; the toast "MCP server saved - the environment variable MCP_TEST_TOKEN stays in
    effect." appears when you edit an environment-variable server and save it without typing a
    secret).

    Saving a server that binds a secret or an environment variable to an address it was not bound
    to before also shows a native question ("SSHSpan - Send a credential?") that names the host and
    the variable. Its buttons are "Don't allow", "Allow" and "Cancel" ("Don't allow" is the default
    button on Windows; the GTK dialog on Linux sets none); only "Allow" allows, and Esc or
    closing the dialog counts as no. Allow: the server is confirmed and the test above works. Don't
    allow: the server is saved but stays off ("The server was saved but stays switched off, because
    sending its credential to `<host>` was not allowed. Save it again to be asked again."), its row
    says "Not confirmed - SSHSpan will not send this credential until you allow it." and offers
    "Allow sending..." (it saves the same settings again and asks the question again, but not
    within 30 seconds of a "Don't allow" or "Cancel": a save in that window asks nothing, whatever
    server it is for, and says "The server was saved but stays switched off, because sending a
    credential to `<host>` was declined a moment ago. Wait 30 seconds, then save it again.", where
    `<host>` is the server that was declined), and a connect or call is refused until it is
    allowed. Press "Allow" the moment
    the dialog appears: it is not taken ("... the question about sending its credential to
    `<host>` was answered within a second of opening - too fast to be a decision. Save it again to
    be asked again."). A second question cannot be started by hand while one is open (the dialog
    is modal over the main window); a save that would ask meanwhile is stored switched off and says
    "... because another question about sending a credential was still open. Answer it, then save
    this server again.", which only the Rust tests exercise. Lock the vault while the dialog is
    open and answer Allow afterwards: nothing is confirmed ("... because the vault was locked while
    you were deciding. Unlock it and save the server again."). The page cannot answer the question
    for you. The variable name must be 1 to 128 visible ASCII characters without spaces or `=`.

    Automated: `env_var_resolves_at_request_time_and_errors_when_unset`.

21. Unset `MCP_TEST_TOKEN` (restart SSHSpan from an environment without it: the app reads the
    variable from its own environment) and try to use a tool on that server.

    Expected: an error that names the variable and says it is not set. The assistant transcript
    shows the call as a failed tool-event row; there is no dedicated "re-configure auth"
    affordance.

    Automated: same unit test as step 20; resolution is per request and not cached.

## Vault lock / teardown

22. With an active MCP session, lock the vault.

    Expected: the mock prints `[DELETE] session=<id>` with the `Mcp-Session-Id` (the mock returns
    200; a 405 would be ignored). The in-memory session and status state are dropped. The lock
    itself does not wait for the network: each session is ended by its own background task.

    Automated: `the_lock_ends_each_session_where_it_was_set_up` proves that each session is ended
    with a DELETE at its own endpoint; the bare integration suite cannot reach the AppHandle path,
    so only the wiring of `lock_vault_internal` to it remains a manual check.

23. Unlock and run `echo` again.

    Expected: the next call re-initializes a fresh session lazily; a server you configured yourself
    stays confirmed. Entries that arrive from backup restore are different: they stay off until
    they are confirmed (the row says "Not confirmed", with "Allow sending..." when the server
    sends a credential), and tools stay disabled. A vault lock never un-confirms a configured
    server.

    Automated for restore: `backup_restored_entries_come_back_inert`.

24. With an active session, **quit SSHSpan** (the vault menu, `Ctrl+Q` or the tray's Quit).

    Expected: the mock prints `[DELETE] session=<id>` within about two seconds of the quit; an exit
    waits at most two seconds for these requests, so a hung server cannot hold it open. This is a
    manual check on Windows and Linux: the exit-time wait is covered by unit tests of its parts
    only, because the run-loop hook needs a Tauri runtime.

25. With an active session, change the server's URL (or its auth) and save, then remove the server.

    Expected: the first `DELETE` goes to the OLD endpoint with the OLD credential - a session is
    ended where it was set up, never at the new URL - and a later call uses a fresh session bound to
    the new settings. Removing the server deletes its local record even when the server is
    unreachable (the teardown is best effort, five seconds at most), and the toast adds a warning
    when the DELETE failed.

    Automated: `saving_a_new_url_or_auth_ends_the_old_session_at_the_old_endpoint`,
    `a_rename_keeps_the_live_session`, `removing_an_unreachable_server_still_deletes_it`.

## Content-type coverage

26. SSE vs JSON responses:

    - The client always sends `Accept: application/json, text/event-stream` and handles either reply;
      it never requests a streamed `tools/call` body, so the mock's `_meta.stream` branch is
      unreachable from the app.
    - The mock's `/mcp-listchanged` endpoint is `/mcp` with one difference: it answers a
      `tools/call` as a `text/event-stream` with two events, first a
      `notifications/tools/list_changed` notification and then the JSON-RPC response to the call
      (same `id`, the usual `content` and `isError`); initialize, `notifications/initialized` and
      tools/list are answered as on `/mcp`. Each such call makes the mock print a `[list-changed]`
      line. To see what the app does with it, add a server with the URL
      `http://127.0.0.1:8777/mcp-listchanged`, test it, review `echo` and turn Enable on, then stop
      the mock, edit the `description` of `echo` in `scripts/mcp-smoke-server.py`, start the mock
      again and ask the assistant to run `echo`.

      Expected: the call is answered and its tool-event row shows the usual
      `Result: {"echoed": "...", "ok": true}` as "done"; the call is not refused, because it was
      checked against the definition you approved. The stream announced a change, so SSHSpan then
      fetches the tool list again (in a capture, three `tools/list` requests to
      `/mcp-listchanged` follow the call). That refresh finds the new description: `echo` is
      disabled and its Auto-approve cleared, and the audit log records
      `mcp.tool_definition_changed`. Once the page reloads its list (opening the MCP settings or
      the assistant panel does), the row is marked changed as in step 14 and the assistant no
      longer offers `echo`; until then the page may still offer it, and the backend refuses the
      call ("Tool 'echo' is not enabled - enable it in the MCP server settings."). Without the
      edit the refresh finds the same definitions: `echo` stays enabled and no
      `mcp.tool_definition_changed` row is written.

      A change announced with the answer to an `initialize` (also on a session renewed after a
      404) counts the same way; the mock never does that, so only the automated tests cover it.
    - The backend decodes SSE incrementally and returns when the answer with the wanted id arrives; an
      open stream no longer forces the call to wait for timeout.

    Automated: `sse_and_json_responses_are_both_handled`,
    `an_sse_answer_is_returned_while_the_stream_stays_open`, `list_changed_flag_drives_refetch`
    (the notification in a call's stream, and the re-pin that disables a changed tool),
    `list_changed_refresh_persists_to_database` and
    `a_list_change_announced_with_the_initialize_answer_brings_the_refresh`.

## Additional backend behavior covered by tests

- Provider requests do not follow redirects and plain provider HTTP is limited to local/private
  addresses.
- A 405 or a legacy SSE `endpoint` event gives a "Streamable HTTP only" error.
- Vault locked: server removal and enable/disable are refused.
- A server may make at most eight requests of its own inside one response, each checked against the
  vault.

Automated: `initialize_405_names_the_unsupported_transport`,
`a_legacy_sse_endpoint_event_is_reported_as_an_unsupported_transport`.
