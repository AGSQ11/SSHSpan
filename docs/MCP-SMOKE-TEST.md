# MCP Phase 1 smoke-test checklist

A manual QA pass for the MCP Phase 1 feature. Run the real app against this mock server after the backend and renderer changes have landed.

## Prerequisites

1. Start the mock server:

   ```bash
   python scripts/mcp-smoke-server.py 8777
   ```

   Expected: the console prints the URL and a short test banner, and the process stays running.

## Settings / add server

2. Open **Settings → AI assistant → MCP servers**.
3. Add a server with URL `http://127.0.0.1:8777/mcp`.

   Expected: the UI allows `127.0.0.1` with a warning that loopback http is only for testing; it refuses non-loopback plain `http://`.

## Connection / discovery

4. Click **Test connection** for the new server.

   Expected: status shows connected, protocol version `2025-11-25`, and a session id is created.

5. Save the server and open the tool list for it.

   Expected: five tools are discovered across two pages (`echo`, `get_time`, `read_file` on page 1; `make_error`, `image_cat` on page 2). Pagination works.

## Approval / enabling

6. Leave all tools disabled. Ask the assistant something that would use the MCP `echo` tool (e.g. "echo hello through the MCP server").

   Expected: nothing executes; the disabled tool is not offered.

7. Enable `echo` and `read_file`. Approve only `echo`. Try to run `read_file`.

   Expected: `read_file` still fails because it was not approved; the UI shows a missing-approval message.

8. Enable auto-approve on `echo` only.

   Expected: calls to `echo` run without a card; calls to other tools still require approval.

## Access-level boundary

9. Set the assistant to **read**. Ask the assistant to run `echo`.

   Expected: the model reads/proposes; no tool runs.

10. Set to **draft**. Ask the assistant to run `echo`.

    Expected: the model may type a command, but nothing executes.

11. Set to **execute**. Ask the assistant to run `echo hello`.

    Expected: an approval card appears showing the server name, tool name, and arguments; the call runs only after you click **Approve**.

12. Set to **yolo**. Ask the assistant to run `echo hello`.

    Expected: the call runs without showing a card.

## Rug-pull guard

13. With `echo` approved, edit `scripts/mcp-smoke-server.py` and change the `description` of the `echo` tool. Restart the mock server.

    Expected: the client detects the pin mismatch; `echo` is disabled and shows a "definition changed, re-approve" notice. The audit log records the rug-pull event.

14. Re-approve `echo` and run it again.

    Expected: the tool works after re-approval.

## Error / edge paths

15. Configure a second server with URL `http://127.0.0.1:8777/mcp-redirect` and test connection.

    Expected: hard error; the client treats the 302 as a failure and does not follow it.

16. In a shell, run:

    ```bash
    curl -X POST http://127.0.0.1:8777/mcp \
      -H "Content-Type: application/json" \
      -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
    ```

    Then run the same request with header `Mcp-Session-Id: 00000000-0000-0000-0000-000000000404`.

    Expected: the first call returns tools; the second returns a 404 once. The client must re-initialize once and then succeed.

17. Call the `make_error` tool.

    Expected: the result returns `isError: true` and the client surfaces an error, not a normal result.

18. Call the `image_cat` tool.

    Expected: the UI shows `[image omitted]` (or a similar non-text placeholder) for the binary image resource.

## Authentication

19. Set environment variable `MCP_TEST_TOKEN=secret123`. Add a server that uses env-var auth with variable name `MCP_TEST_TOKEN`. Test connection.

    Expected: connection succeeds.

20. Unset `MCP_TEST_TOKEN`. Try to use a tool on that server.

    Expected: a clear auth error; the UI offers to re-configure the auth source.

## Vault lock / teardown

21. With an active MCP session, lock the vault.

    Expected: the server log shows a `DELETE /mcp` request carrying the `Mcp-Session-Id`; the client drops the in-memory session and decrypted auth secrets.

22. Unlock the vault.

    Expected: the server entry is inert; it is not re-connected until you open Settings and re-confirm the server URL and auth source.

## Binary / SSE content-type coverage

23. Call `echo` with the stream flag (if exposed in the UI) or verify in the backend tests that the mock returns both:

    - `application/json` for non-streaming `tools/call`.
    - `text/event-stream` when streaming is requested.

    Expected: both content types are exercised without error.
