# MCP Phase 1 smoke-test checklist

A manual QA pass for the MCP Phase 1 feature. Run the real app against this mock server after the backend and renderer changes have landed.

Each step states the expected result and how it is otherwise covered automatically, so a manual pass and the test suite can be reconciled: the "automated" line names the test in `src-tauri/tests/mcp_integration.rs` or `src-tauri/src/assistant/mcp.rs` that already proves the same property on the code path, when one exists.

## Prerequisites

1. Start the mock server:

   ```bash
   python scripts/mcp-smoke-server.py 8777
   ```

   Expected: the console prints the URL and a short test banner, and the process stays running.

## Network destinations (what should appear in a packet capture)

- The only address the app contacts during this checklist is `127.0.0.1:8777` — the mock, configured by you. The mock binds loopback only and makes no outbound connections itself.
- MCP traffic is one-directional POST (plus a DELETE on vault lock) from the **Rust backend** to the configured server URL. The renderer never fetches an MCP URL, so no MCP request should ever appear from the webview process.
- Model traffic (the assistant's chat) goes to the provider base URL configured under Settings → AI assistant and is unrelated to MCP. With this checklist you can leave the provider pointing at a local Ollama/LM Studio; no external destination is required for any step below.
- Nothing should ever connect to a URL the mock returns in a `Location` header (step 15): a 3xx is a hard error, and the redirect target must show zero inbound requests.

## Settings / add server

2. Open **Settings → AI assistant → MCP servers**.
3. Add a server with URL `http://127.0.0.1:8777/mcp`.

   Expected: the UI allows `127.0.0.1` with a warning that plain loopback HTTP is unencrypted; it refuses non-loopback plain `http://`.

   Automated: `http_is_allowed_only_for_loopback`, `https_urls_are_accepted_everywhere` (unit tests).

## Connection / discovery

4. Click **Test connection** for the new server.

   Expected: status shows connected, protocol version `2025-11-25`, and the mock logs the `initialize` + `notifications/initialized` pair with session id `00000000-0000-0000-0000-000000000001` (the mock's fixed test session).

   Automated: `initialize_negotiates_version_and_stores_session`, `every_post_carries_the_streamable_http_headers`.

5. Save the server and open the tool list for it.

   Expected: five tools are discovered across three pages of up to two (`echo`, `get_time`; `read_file`, `make_error`; `image_cat`). Pagination works. All five arrive disabled (default-deny).

   Automated: `paginated_tools_list_returns_every_page`.

## Approval / enabling

6. Leave all tools disabled. Ask the assistant something that would use the MCP `echo` tool (e.g. "echo hello through the MCP server").

   Expected: nothing executes; the disabled tool is not offered to the model at all.

   Automated: `merge_preserves_pins_and_disables_changed_tools` (new tools arrive disabled).

7. Enable `echo` only (the Enable toggle IS the approval: it pins the tool's current definition). Ask for `read_file`.

   Expected: `read_file` is not offered; if a call is somehow attempted, the backend denies it ("not enabled") and the audit log records the denial.

   Automated: the gate itself lives in `mcp_call_tool` behind the Tauri `AppHandle` (level + vault checks); no bare integration test reaches it. The wire side (`session_404_reinitializes_once`) proves the request layer this gate sits on.

8. Enable auto-approve on `echo` only.

   Expected: calls to `echo` run without an approval card; calls to other enabled tools still show the card.

   Automated: gate logic is unit-tested only where pure; manual pass required for the card itself.

## Access-level boundary

9. Set the assistant to **read**. Ask the assistant to run `echo`.

   Expected: the model reads/proposes; no tool runs.

10. Set to **draft**. Ask the assistant to run `echo`.

    Expected: the model may type a command, but nothing executes.

11. Set to **execute**. Ask the assistant to run `echo hello`.

    Expected: an approval card appears showing the server name, tool name, and arguments; the call runs only after you click **Approve**.

12. Set to **yolo**. Ask the assistant to run `echo hello`.

    Expected: the call runs without showing a card.

    Steps 9–12: the level gate is enforced in `mcp_call_tool` (Rust), which the bare integration suite cannot invoke (needs `AppHandle`); this is the main thing the manual pass adds over the automated coverage.

## Rug-pull guard

13. With `echo` approved, edit `scripts/mcp-smoke-server.py` and change the `description` of the `echo` tool. Restart the mock server.

    Expected: the client detects the pin mismatch; `echo` is disabled and shows a "definition changed, re-approve" notice. The audit log records the rug-pull event.

    Automated: `merge_preserves_pins_and_disables_changed_tools`, `list_changed_flag_drives_refetch`, and `list_changed_refresh_persists_to_database` (the disabled state is proven to persist through the production `save_mcp_server`/`get_mcp_server` round-trip).

14. Re-approve `echo` and run it again.

    Expected: the tool works after re-approval.

## Error / edge paths

15. Configure a second server with URL `http://127.0.0.1:8777/mcp-redirect` and test connection.

    Expected: hard error; the client treats the 3xx as a failure and does not follow it. The mock's redirect target receives no request.

    Automated: `redirect_is_a_hard_error`, `auth_header_never_leaves_the_configured_origin` (proves the auth header is not carried onward).

16. The mock's one-shot 404 only fires for the fixed session id `00000000-0000-0000-0000-000000000404`, which the real client never holds. Drive it with curl to prove the *mock* behaves as scripted:

    ```bash
    curl -X POST http://127.0.0.1:8777/mcp \
      -H "Content-Type: application/json" \
      -H "Mcp-Session-Id: 00000000-0000-0000-0000-000000000404" \
      -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
    ```

    Expected: HTTP 404 on the first call, normal result on the same call repeated (one-shot).

    The *client* side — a real 404 mid-session triggers exactly one re-initialize and a retry with the new session — is covered by the integration test `session_404_reinitializes_once`, which drives the production request layer and asserts the session registration. To observe it in the app, temporarily edit the mock so the client's session id 404s once; do not ship that edit.

17. Call the `make_error` tool.

    Expected: the result returns `isError: true` and the client surfaces an error, not a normal result.

    Automated: `tool_result_surfaces_is_error` (unit test).

18. Call the `image_cat` tool.

    Expected: the UI shows `[image omitted]` (or a similar non-text placeholder) for the binary image resource.

    Automated: `tool_result_shaping_covers_all_content_kinds` (unit test).

## Authentication

19. Set environment variable `MCP_TEST_TOKEN=secret123`. Add a server that uses env-var auth with variable name `MCP_TEST_TOKEN`. Test connection.

    Expected: connection succeeds; the mock echoes the session. (The mock does not check the header's value — it only has to be present, which you can confirm in the app's audit log / packet view, or by temporarily making the mock reject it.)

    Automated: `env_var_resolves_at_request_time_and_errors_when_unset` (unit test).

20. Unset `MCP_TEST_TOKEN`. Try to use a tool on that server.

    Expected: a clear auth error naming the variable and that it is not set; the UI offers to re-configure the auth source.

    Automated: same unit test as 19 (resolution is per-request, never cached).

## Vault lock / teardown

21. With an active MCP session, lock the vault.

    Expected: the server log shows a `DELETE /mcp` request carrying the `Mcp-Session-Id` (the mock answers 200; a 405 would be ignored per spec); the client drops the in-memory session and status state.

    Automated: `teardown_all` is wired into `lock_vault_internal` (backend, verified by review); the bare integration suite cannot reach the AppHandle path, so the DELETE side effect is verified here by hand.

22. Unlock the vault and run `echo` again.

    Expected: the next assistant call re-initializes a fresh session lazily — no re-confirmation needed, because a server you configured yourself stays confirmed. The assistant should work again without touching Settings.

    Note the distinction the docs make precise: *inert until re-confirmed* applies only to entries that arrived from a backup, import, or sync (their `confirmed` flag is cleared on restore, and every connect/call is refused until you re-save them). A vault lock never un-confirms an entry; it only drops live sessions. If your QA plan needs the inert-restore path, restore a backup containing an MCP entry and confirm Test connection fails with a "re-confirmed" error until you re-save — covered automatically by `backup_restored_entries_come_back_inert`.

## Content-type coverage

23. SSE vs JSON responses:

    - The production client always requests both via `Accept: application/json, text/event-stream` and handles either reply; it never asks for a streamed `tools/call` body, so the mock's `_meta.stream` branch is unreachable from the app.
    - The `text/event-stream` reply path *is* exercised in the app by the `/mcp-listchanged` endpoint: point a server's URL at it and the response arrives as SSE with a `notifications/tools/list_changed` event ahead of the result.

    Automated: `sse_and_json_responses_are_both_handled`, `list_changed_flag_drives_refetch`, `list_changed_refresh_persists_to_database` cover both content types and the stream-changed flow; step 23 with the app is a spot-check that the wiring matches the test surface.
