# Phase 1 MCP support for the AI assistant

## Summary

Adds remote MCP (Model Context Protocol) server support to the AI assistant over the **Streamable HTTP** transport (MCP protocol version `2025-11-25`). Stdio and the legacy HTTP+SSE (2024-11-05) transport are refused with a clear error. Phase 1 covers transport, tool discovery, per-tool approval/pinning, static auth (bearer / custom header / env var), and vault-lock teardown. OAuth arrives in Phase 2.

## What the user gets

- Add one or more MCP servers under **Settings → AI assistant → MCP servers**.
- Loopback `http://127.0.0.1` is allowed for local testing with a warning; any other plain-HTTP URL is rejected.
- Discovered tools are listed, start disabled, and must be individually approved.
- Each approved tool is pinned to a SHA-256 hash of its canonical definition. If the server changes the tool ("rug pull"), the tool disables itself and demands re-approval.
- Tool calls respect the existing access levels (read/draft/execute/yolo) and are audit-logged with an hash of the arguments.
- Static credentials can be sealed with the vault master password or resolved from an environment variable by name.
- Locking the vault tears down live MCP sessions via `DELETE` with the `Mcp-Session-Id`.

## Implementation

### Library decision: hand-rolled client

We did **not** use the `rmcp` SDK. The rmcp README documents no `reqwest::Client` injection point, and the Phase 1 hard requirements need full control of the HTTP client:

- guarded DNS resolver (SSRF guard from `bitwarden::ssrf`) for discovered URLs
- `redirect = none` - 3xx is a hard error
- 2 MB response cap
- `rustls-only` TLS
- sealed secrets, no credential leakage across origins

The wire surface is small enough to hand-roll: `initialize` → `notifications/initialized` → `tools/list` → `tools/call`.

### Backend

- New `mcp` module with a hand-rolled Streamable-HTTP client.
- Two reqwest clients: unguarded for the configured origin, guarded-discovered for any URL returned by the server.
- Protocol negotiation supports `{2025-11-25, 2025-06-18, 2025-03-26}`.
- Empty client capabilities; server-to-client requests return JSON-RPC `-32601`.
- Canonical-JSON pin hash over `{name, title, description, inputSchema, annotations}` (sorted keys, full description).
- 3xx responses are treated as hard errors.
- Tool results are wrapped as untrusted data before entering the assistant conversation.
- `mcp_call_tool` enforces level, enabled state, pin match, and auto-approve flag server-side.
- `DELETE` with `Mcp-Session-Id` on vault lock; 405 is ignored.

### Renderer

- Settings panel for adding/editing MCP servers, selecting auth source, and approving/enabling tools.
- Approval cards show server, tool, and arguments; the click is renderer-attested (backend enforces the rest).
- Type-specific placeholders for non-text resources (`[image omitted]`, `[audio omitted]`, `[binary resource omitted]`); text resources are passed through wrapped.

## Verification

<!-- VERIFICATION -->

## Design decisions honored (12 approved amendments)

1. Protocol negotiation with supported set `{2025-11-25, 2025-06-18, 2025-03-26}`.
2. Dual clients: unguarded-configured vs guarded-discovered.
3. Canonical-JSON pin hash over `{name, title, description, inputSchema, annotations}` (sorted keys, full description).
4. Empty client capabilities; server-to-client requests get JSON-RPC `-32601`.
5. 3xx is a hard error.
6. Backup/import/sync entries are inert until re-confirmed.
7. Built-in assistant tools are never displaced by MCP tools.
8. Renderer-attested approval boundary: backend enforces level/enabled/pin/auto-approve; the click is renderer-attested.
9. Env-var-unset test plus desktop-menu env hint.
10. Type-specific placeholders: `[image omitted]`, `[audio omitted]`, `[binary resource omitted]`; text resources passed through wrapped.
11. 405-ignored session `DELETE` on vault lock.
12. Loopback `http://127.0.0.1` allowed with warning; other plain HTTP refused.

## Notes for review

- Do not merge until backend and renderer are both present; this PR is the integration point.
- The smoke-test rig (`scripts/mcp-smoke-server.py`) and the manual QA checklist (`docs/MCP-SMOKE-TEST.md`) are included for end-to-end verification.
- Phase 2 will add OAuth and any additional resource/content-type handling.
