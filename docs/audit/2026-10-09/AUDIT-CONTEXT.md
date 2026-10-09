# SSHSpan flaw audit — shared context for every audit agent

Read this whole file before touching the repo. It is the ground truth for your
audit; your own prompt adds the scope.

## Where you are working

- Repository worktree (ALL paths below are relative to it):
  `Y:\Development\SSHSpan\SSHSpan\.claude\worktrees\app-flaws-audit-subagents-c36b18`
  (Git Bash spelling: `/y/Development/SSHSpan/SSHSpan/.claude/worktrees/app-flaws-audit-subagents-c36b18`)
- Run every command from that directory. Do NOT `cd` to the parent repository
  (`Y:\Development\SSHSpan\SSHSpan`) — it is a different checkout.
- Branch: `gsq/app-flaws-audit-subagents-c36b18` (based on `main` @ 1ca864f).

## Hard rules

1. **Read-only.** You are auditing, not fixing. Do not edit, create, or delete
   any tracked file. Do not `git add`, `git commit`, `git stash`, or `git checkout`.
2. The ONLY file you write is your findings file (path given in your prompt),
   plus scratch files under `.superpowers/audit/scratch/<your-area>/` if you
   need to script something (e.g. a Playwright driver). Both are git-ignored.
3. **Do not run `cargo`** (build/test/check/clippy). The Windows build trips
   the machine's antivirus. Rust is reviewed by reading; a controller runs the
   suite in WSL separately. `node` and `npm run <script>` are fine.
4. Do not dispatch subagents. Do the work yourself.
5. Do not install packages. `node_modules/playwright` (1.56.1, Chromium
   available) is already present in the worktree.
6. Return to the controller ONLY a ≤15-line summary: counts by severity, the
   3-5 most important findings (one line each), and anything you could not
   verify. The full report goes in your findings file.

## What the app is

SSHSpan v1.9.1 — cross-platform (Windows/Linux) SSH key manager + SSH client.
Tauri 2 desktop app: Rust core, vanilla-JS renderer (no framework, no bundler,
no build step, no TypeScript). Features: encrypted local vault (SQLite),
key generation/import/export (RSA/Ed25519/ECDSA, OpenSSH/PKCS#8/PuTTY),
categories, Bitwarden sync, deploy keys to hosts (writes private keys + SSH
config Host blocks), embedded terminal (xterm.js 5.5.0 via russh), SFTP file
browser with transfer queue, AI assistant (LLM provider + MCP servers,
Streamable HTTP), auto-updater (minisign-verified), settings with audit log,
known-hosts management, backup/restore.

## File inventory

Renderer — `src/renderer/` (classic `<script>` globals, one shared scope):
| file | lines | role |
|---|---|---|
| index.html | 974 | all static markup: nav (Keys / Servers / Settings), key list + detail pane, connect view (server list, terminal column, SFTP), settings sections (general, vault, hosts, backup, sync, assistant, audit), and ~12 modals (`#modalBackdrop` key editor, `#vaultModal`, `#connectPwModal`, `#deployModal`, `#paletteModal` command palette, `#pickerModal`, `#serverModal`, `#promptModal`, `#yoloModal`, …) |
| styles.css | 2578 | all styling, CSS custom properties, themes |
| app.js | 4551 | controller: IPC shim `call(cmd,args)` → `window.__TAURI__.core.invoke`, `el(id)`, `toast()`, `settingOn()`, routing, key list, modals, settings, palette, deploy, vault lock/unlock, updater; dynamically injects the other scripts |
| sftp.js | 3993 | SFTP panel: listing, breadcrumb path, transfers, queue, drag/drop, local/remote panes |
| terminal.js | 688 | xterm.js sessions, tabs, resize, split surface |
| assistant.js | 869 | AI assistant panel, YOLO (auto-approve) dialog, tool calls |
| mcp.js | 603 | MCP server list/settings (`mcpCall(cmd, payload)`) |
| icons.js | 3 | inline SVG icon table (`data-ico` / `data-nav-ico` spans filled at boot) |
| vendor/ | — | xterm.js 5.5.0, addon-fit 0.10.0, addon-web-links 0.11.0 (pinned via VENDOR.md; don't audit vendor code) |

Rust — `src-tauri/src/`:
| file | lines | role |
|---|---|---|
| lib.rs / main.rs | 325 / 11 | Tauri builder, state, tray, menu, command registration |
| commands/mod.rs | 2963 | most `#[tauri::command]` handlers (keys, categories, vault, settings, deploy, backup, audit log, …) |
| commands/sftp.rs | 2901 | SFTP commands + transfer queue bridge |
| commands/terminal.rs | 451 | PTY/SSH session commands + events |
| commands/server.rs | 196 | saved-server CRUD |
| commands/updater.rs | 1389 | update check/download/minisign verify/apply |
| db/mod.rs | 3013 | SQLite schema, migrations, queries |
| crypto/{vault,keys,pkcs8,putty,bitwarden,utils}.rs | ~3000 | vault encryption, key parsing/conversion |
| ssh/mod.rs, ssh_client/mod.rs | 433 / 833 | known hosts, russh client |
| sftp/{mod,queue}.rs | 931 / 2584 | SFTP engine + queue |
| bitwarden/{mod,ssrf,sync}.rs | ~2600 | Bitwarden API client, SSRF guard, sync algorithm |
| assistant/{mod,mcp}.rs | 968 / 2658 | LLM provider calls, MCP Streamable HTTP client |
| config/mod.rs | 359 | settings store |
| tests/integration.rs, tests/mcp_integration.rs | 809 / 1097 | integration suites |

Config: `src-tauri/tauri.conf.json` (CSP, window 1100×720 min 880×560,
`withGlobalTauri: true`), `src-tauri/capabilities/default.json` (ACL).
Docs: `README.md`, `CHANGELOG.md`, `docs/ARCHITECTURE.md`, `docs/SECURITY.md`,
`docs/PRIVACY.md`, `docs/MCP-SMOKE-TEST.md`, `docs/REWRITE-ROADMAP.md`.

## IPC conventions (important for logic audits)

- Renderer calls `call('command_name', { argName: … })`. Tauri v2 converts a
  Rust command's `snake_case` parameter to `camelCase` and looks up EXACTLY
  that key; a misspelled key on an `Option<T>` param is silently `None`.
  `scripts/check-ipc-args.js` cross-checks 118 call sites against 111
  commands and currently passes — so do not re-report simple name mismatches
  it already covers; DO look for semantic mismatches (wrong type, wrong
  shape, field names the renderer reads from a response that Rust never
  emits, snake_case vs camelCase on *response* structs, etc.).
- Rust commands return `Result<T, String>`; `invoke` rejects with the String.
- Settings values from `collect_settings` arrive as JSON strings (`"false"`),
  hence `settingOn()`.
- Events: `listen('event-name', handler)` from `window.__TAURI__.event`.

## Driving the real page in headless Chromium (for UI/UX/visual audits)

`scripts/check-renderer-ui.js` already does this; copy its pattern. Serve
`src/renderer` over HTTP (file:// blocks the loads), stub `window.__TAURI__`
before any script runs, and open `index.html`:

```js
const { chromium } = require('playwright');           // from worktree node_modules
const http = require('http'), fs = require('fs'), path = require('path');
const ROOT = path.resolve('src/renderer');
const TYPES = { '.html':'text/html', '.js':'text/javascript', '.css':'text/css', '.png':'image/png', '.svg':'image/svg+xml' };
const server = http.createServer((req, res) => {
  const rel = decodeURIComponent(req.url.split('?')[0]).replace(/^\/+/, '') || 'index.html';
  const file = path.join(ROOT, rel);
  if (!file.startsWith(ROOT) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) { res.writeHead(404); return res.end(); }
  res.writeHead(200, { 'Content-Type': TYPES[path.extname(file)] || 'application/octet-stream' });
  res.end(fs.readFileSync(file));
});
await new Promise(r => server.listen(0, '127.0.0.1', r));
const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1100, height: 720 } });
await page.addInitScript(({ r }) => {
  window.__TAURI__ = {
    core: { invoke: async (cmd, args) => (typeof r[cmd] === 'function' ? r[cmd](args) : (r[cmd] ?? {})) },
    event: { listen: async () => () => {} },
  };
}, { r: REPLIES });   // REPLIES: { command_name: value-or-fn } — read app.js boot to see which commands it calls and what shapes it expects
page.on('pageerror', e => console.log('PAGEERROR', e.message));
page.on('console', m => { if (m.type() === 'error') console.log('CONSOLE', m.text()); });
await page.goto(`http://127.0.0.1:${server.address().port}/index.html`);
```

Look at `scripts/check-renderer-ui.js` for the reply shapes it uses (`KEY`,
`SRV` helpers, `list_keys`, `list_servers`, `get_categories`, settings…) and
extend them. Screenshots go to `.superpowers/audit/scratch/<area>/`.
Use the app's real min window size (880×560) and default (1100×720) and a
large one (1600×1000). Note the app runs inside a WebView (WebView2 on
Windows, WebKitGTK on Linux) — Chromium is a stand-in.

## Existing checks (so you know what is already caught)

`node --check src/renderer/*.js`; `node scripts/check-renderer-globals.js`
(undefined project functions / duplicate globals); `node scripts/check-vendor.js`;
`node scripts/check-ipc-args.js`; `npm run test:ui` (Playwright behaviour
checks: key list grouping, host picker, palette, settings rail, SFTP breadcrumb,
split surface — all pass at baseline); CI runs `cargo fmt --check`,
`cargo clippy -D clippy::correctness`, `cargo test` (passes at baseline),
`cargo audit`.

## Findings file format (strict)

Write Markdown to the path given in your prompt. Start with a 5-line summary
(counts per severity, areas covered, areas NOT covered and why). Then one
block per finding, ordered by severity:

```
## <AREA>-<NN>: <one-line title>
- **Severity:** Critical | High | Medium | Low
- **Category:** ui | visual | html | css | a11y | ux | js-logic | rust-logic | ipc | security | docs | perf
- **Location:** `path/file.ext:line` (exact lines; several if needed)
- **Evidence:** quoted code or observed behaviour (what you actually saw)
- **Why it is a flaw:** user-visible consequence or correctness argument
- **Proposed fix:** concrete minimal change (what to change, where)
- **Confidence:** confirmed (reproduced / proven by code reading) | likely | suspected
- **Effort:** S (<30 lines) | M | L
```

Severity guide: Critical = data loss, security breach, crash, feature
unusable; High = wrong behaviour the user will hit in normal use; Medium =
degraded/confusing behaviour, a11y blocker, visual defect in a primary
surface; Low = polish, inconsistency, minor a11y, dead code.

## Quality bar

- Every finding must cite exact `file:line` evidence you read or reproduced.
  No "probably", no findings about code you did not open.
- Prefer 15 real findings over 60 weak ones. Do not report style
  preferences as flaws. Do not report things the existing checks already
  enforce. Do not report vendor code.
- The codebase has many deliberate, commented decisions (`// SECURITY:`,
  `/// … because …`). Read the comment before reporting; if the comment
  explains the behaviour and it is sound, it is not a flaw. If the comment's
  claim is false in the code, that IS a flaw — say so.
- When unsure whether two findings are the same root cause, merge them.
- Finish within your budget: write the file incrementally so a timeout does
  not lose your work.
