# Contributing to SSHSpan

Thank you for improving SSHSpan. SSHSpan is a Windows/Linux Rust + Tauri v2 desktop application with
a vanilla HTML/CSS/JavaScript renderer (no bundler, no TypeScript, no Node runtime in the shipped
app).

## Development setup

Install:

- Node.js 18 or newer for the Tauri CLI and renderer checks (CI uses 20; release builds use 24);
- Rust (CI pins `1.98.0`) with `rustfmt` and `clippy`;
- the Tauri v2 system prerequisites for your platform.

From the repository root:

```sh
npm ci
npm run dev
```

The Rust backend is in `src-tauri/src/`; the renderer is in `src/renderer/`. Use a disposable
profile when working on vault, deploy, backup, or SFTP behavior. Debug builds honor `SSHSPAN_DB` to
isolate a development database; release builds intentionally ignore it. Never point tests or manual
experiments at real hosts, real vaults, or user key material.

## Rust checks

Use the same gates as CI:

```sh
cargo fmt --manifest-path src-tauri/Cargo.toml -- --check
cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets -- -D clippy::correctness
cargo test --manifest-path src-tauri/Cargo.toml
```

CI denies Clippy's **correctness** group, not every warning, because the tree carries many
pre-existing style lints. Do not add new warnings in files you touch. `npm test` is the Rust test
command; it is not the renderer suite.

### Windows developers: Cargo in WSL2

On the maintainer's Windows machine Avast blocks freshly built Cargo build scripts. Do not run
native Windows Cargo there. Run Rust checks inside WSL2 and keep the target directory on the Linux
filesystem, in **one shared directory for every checkout and worktree** (a Tauri target directory
is large - about 11 GB for the Linux build and 6 GB for the Windows type-check below - and a WSL2
virtual disk grows with it but does not shrink on its own, so a target directory per checkout
fills the disk). Adapt the distro name and checkout path:

```sh
set -o pipefail; wsl.exe -d Ubuntu-25.10 -e bash -lc 'export PATH=$HOME/.cargo/bin:$PATH; \
  cd /mnt/<drive>/<path-to-checkout>; export CARGO_TARGET_DIR=$HOME/sshspan-target; \
  cargo fmt --manifest-path src-tauri/Cargo.toml -- --check && \
  cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets -- -D clippy::correctness && \
  cargo test --manifest-path src-tauri/Cargo.toml' 2>&1 | tr -d '\0'
```

`set -o pipefail` goes before `wsl.exe`, where the pipe is, so that a failing Cargo run is not
hidden by the exit code of `tr`.

`cargo check --manifest-path src-tauri/Cargo.toml --target x86_64-pc-windows-gnu --all-targets`
(with its own shared target directory, for example `$HOME/sshspan-target-win`) type-checks
`#[cfg(windows)]` code from Linux. It does **not** execute Windows behavior. Windows behavior runs
natively in CI: the `windows` job runs `cargo test` and the static renderer checks on
`windows-latest`. It passed on a runner for the first time on 2026-10-17, at `38e586e` (743
library, 47 integration and 20 MCP integration tests); its first run, on pull request #85, had
failed five library tests that assumed Unix paths or a single ACL entry, since fixed. It is still
`continue-on-error`; that flag can now be removed. The release workflow also runs
`cargo test` on `windows-latest` at every tag, never on a pull request. The library and
integration tests have also been run by hand on Windows 11, from test executables cross-built in
WSL (the next paragraph says what they need beside them); treat any other Windows-only claim
accordingly.

A Windows test executable stops at load time (`0xC0000139`, `STATUS_ENTRYPOINT_NOT_FOUND` for
`comctl32` `TaskDialogIndirect`) unless it declares Common-Controls 6. `tauri-build` embeds that
manifest in the app binary only, so the `windows` job and the release workflow's Windows test
step write the external manifest file beside each test executable (see
`.github/workflows/ci.yml` and `.github/workflows/release.yml`); a test executable cross-built
with the MinGW target also needs `WebView2Loader.dll` beside it, while the MSVC build links the
loader statically.

The SFTP end-to-end fixtures remain opt-in examples:

```sh
cargo run --manifest-path src-tauri/Cargo.toml --example dev-sshd
cargo run --manifest-path src-tauri/Cargo.toml --example sftp-smoke
```

## Renderer checks

The renderer has no build step. The static checks need only Node (`npm run check:vendor` and
`npm run check:hygiene` run two of them). The seven suites drive the real renderer files in
headless Chromium against a stubbed Tauri bridge; CI installs Playwright 1.56.1 for them only:

```sh
npm install --no-save --no-audit --no-fund playwright@1.56.1
npx playwright install chromium

for f in src/renderer/*.js; do node --check "$f"; done
node scripts/check-renderer-globals.js
node scripts/check-ipc-args.js
node scripts/check-vendor.js
node scripts/check-mcp-contract.js
node scripts/check-renderer-hygiene.js
npm run test:ui
npm run test:safety
npm run test:sftp
npm run test:polish
npm run test:assistant
npm run test:keys
npm run test:servers
```

Static checks (no browser):

- `check-renderer-globals.js`: all renderer scripts for undefined project calls and duplicate
  globals in the shared script scope;
- `check-ipc-args.js`: every `call`/`sftpCall`/`aiCall`/`mcpCall` argument key against the Rust
  command signatures (payloads built in a variable are read too, and Tauri-injected parameters are
  ignored while a `Channel<T>` counts as a renderer argument), and calls to commands absent from
  `generate_handler!`. What it cannot read statically it lists as unchecked, never guessed at: a
  payload it cannot read, a command named by a variable, a computed key, and every other use of a
  wrapper's name (an alias, `.call`/`.apply`, `window.call`, a bracket access, `(0, call)(...)`, a
  destructured alias - one in a function's, arrow's or method's parameter list (a later parameter
  too) or in a `catch (...)` clause included). Quoted keys are read, so are calls with spaces, line
  breaks or `?.` before
  the `(`, comments and the text of strings are never taken for code, and its summary says "every
  argument name was checked" only when no site is listed (none is, today: 147 call sites are
  read against 110 commands).
- `check-vendor.js`: vendored xterm/addon versions and hashes against
  `src/renderer/vendor/VENDOR.md`;
- `check-mcp-contract.js`: what an argument-name check cannot see in the renderer's MCP calls:
  `mcp_save_server` must always send `auth_header_name`, `auth_secret` and `auth_env_var` (the
  backend reads an absent one as "keep the stored value", so a payload that stopped sending a
  rotated token would say "saved" while the old one stayed in use), the `mcp_call_tool` call
  site, tool-schema validation, untrusted-result wrapping, and the `inputSchema` field the backend
  forwards.
- `check-renderer-hygiene.js` (`test:polish` runs it too): a comment in the renderer fails the
  check when it cites an internal label of a shape the check knows - a work-package name (`JU3`,
  `RU6b`, `RW`), a fix or review round ("fix round 1", "round 3"), a review finding (`I1`, `M7`),
  a brief or hand-off number ("item 7", "hand-off 10") or an agent name ("Agent E") - so give the
  audit ID or a plain reason; a label of another shape, such as "Task 6", passes and has to be
  caught in review. The same check also fails when an unused export or a stale comment it lists
  as removed comes back, when a comment that described code which has since changed is not
  corrected, and on an error turned into text by hand in the shapes it knows (`e.message ||
  String(e)` and its forms, `e && e.message ? e.message : ...`, a sentence built with a bare
  `e.message`): `errText` in `app.js` is the shared way, and the check cannot prove that no other
  shape exists. Run it as `node scripts/check-renderer-hygiene.js` or `npm run check:hygiene`.

Suites. Each prints one `ok` or `FAIL` line per check and exits non-zero on any failure. They
share `scripts/lib/renderer-harness.js`, which serves the renderer over HTTP.
`SSHSPAN_RENDERER_DIR` points a run at another copy of the renderer (for example a pristine
`git archive` of an older commit, to watch a new check fail where it should) for every suite
except `test:ui`, which always serves `src/renderer`; `--only <text>`
runs the scenarios whose title contains the text (every suite except `test:ui` and
`test:assistant`, which takes `ASSISTANT_ONLY=<group>`). Without Playwright `test:ui`,
`test:safety`, `test:sftp`, `test:polish`, `test:keys` and `test:servers` skip their browser checks
and say so; `test:assistant` refuses to run.

- `npm run test:ui` (`check-renderer-ui.js`): the key list's grouped view, the connect host
  picker, the SFTP local pane and queue grouping, the UX refactor and the session surface;
- `npm run test:safety` (`check-audit-safety.js`): confirmations (a static scan fails on a native
  `confirm(`, and the second click of a double-click is no yes), the idle auto-lock on a fake
  clock, vault dialogs and secret hygiene, native paste review, backups through Rust, settings
  and lock gates, the audit export's busy state;
- `npm run test:sftp` (`check-sftp-ui.js`): the file browser - navigation, selection, the transfer
  queue, conflicts, chmod, shortcuts, drops, edit conflicts (one question per file, vault locks
  and closed tabs), the layout at 880x560, 1100x720 and 1600x1000 (the More menu, the transfer
  panel's height, the splitters, table cells), spelled-out names, pointer-based drag and drop with
  its menu alternatives, one `sftp_open` per tab, settings that revert, listings refreshed after
  a change, "Stop editing" and the backend's guard (an Edit of a file whose stop is deciding is
  refused), the backend's texts in the edit flow shown spelled out, the SFTP menus from the
  keyboard, search caps and "Send to";
- `npm run test:polish` (`check-ui-polish.js`): keyboard behavior, ARIA roles and names, menus, the
  palette, the audit log and settings, plus static checks for dead CSS and JavaScript, for
  `errText` and the shared path join, and that no IPC call site is left unchecked
  (`--only static` runs the static part alone; it also runs `check-renderer-hygiene.js`);
- `npm run test:assistant` (`check-assistant-ui.js`): the assistant panel and MCP settings -
  approval attestation, backend-gated typing, per-tab lifecycle, bounded history, the
  provider/MCP settings round trip, servers that are not confirmed and the native key-move
  question;
- `npm run test:keys` (`check-keys-ui.js`): key creation, export and import, the key list,
  category drag and drop (pointer drags, Move up and Move down, the order next to restored loops
  through `category_set_order`), the backend-planned deploy sheet with its warnings and Host
  lines, the key-file warnings of the servers a deploy saves, removing a deployed copy, and the
  empty Keys view of a locked vault;
- `npm run test:servers` (`check-servers-ui.js`): saved passwords (including the password a changed
  server needs again), a new server in a filtered list, the key-file warning after a save, the
  connect lifecycle and status line, key compatibility, paste, chords and focus in a real xterm,
  Quit, the lock questions and gates, the updater dialog, Bitwarden results (the last result, the
  approval token, a changed list, a list too long to review), the Bitwarden destination question
  ("Not confirmed", "Allow syncing...", where the focus goes) and the backend's Bitwarden texts
  shown spelled out, the Upload picker, and a scan that checks shown text uses " - ", never an em
  dash.

These are not WebView2 or WebKitGTK tests, do not exercise native dialogs, the tray or a screen
reader, and use fake files and SSH/SFTP responses. State that distinction in reports. Test
coverage at `6c19b1b`, from V8 coverage of the renderer suites and `cargo llvm-cov` over every Rust
test with test code left out: renderer 92.9% of lines (95.7% of the lines added since 1.9.1), Rust
production code 72.0% (77.3%); see [REPORT.md, section 8.9](docs/audit/2026-10-09/REPORT.md#89-coverage).
Do not quote an 80% figure or any other number unless a coverage tool produced it.

### What CI runs

`.github/workflows/ci.yml` runs on every pull request and every push to `main`; every job has a
timeout.

- `rust`: `cargo fmt --check`, Clippy (correctness group) and `cargo test` on Linux;
- `renderer`: the syntax, globals, vendor, MCP-contract and comment-hygiene checks and the seven
  suites;
- `ipc-arg-names`: `check-ipc-args.js`;
- `cargo-audit`: dependency advisories (one advisory is ignored deliberately, with the reasoning in
  the workflow);
- `windows`: the static renderer checks (the same list as `renderer`, plus `check-ipc-args.js`),
  then `cargo test` on `windows-latest` (the suites run on Linux only: they drive the same files
  in the same browser). The job is `continue-on-error` - its failure does not fail the workflow -
  until it has passed once on a runner (audit row A7-56); delete that flag then. It has now passed
  once, on 2026-10-17 at `38e586e` (its first run had failed five library tests, since fixed);
  the flag is still set and can now be deleted.

### Scripts

- `scripts/gen_minisign_test_vector.py` (needs PyNaCl) prints the minisign vectors the updater
  tests use, including the `SSHSpan release v1.8.0` release-comment vector
  (`--release-tag` picks another tag); `--check` compares them with the constants in
  `src-tauri/src/commands/updater.rs`.
- `scripts/refactor_tabs.py` and the `scripts/cdp-*.js` drivers were removed (A8-21): they were
  unreferenced, could not run in CI, and the drivers acted on whatever app instance they attached
  to. Git history keeps them.

## Test-first workflow

For fixes, write the failing Rust test or renderer assertion first, watch it fail for the reason
being fixed, then make the smallest focused change. Add regression coverage for crypto, database
migrations, IPC contracts, SSH/SFTP behavior, and every renderer behavior you repair. A test that
passes without the fix is not evidence.

## Conventions

### Language and UI copy

- Use **vault** for the master-password-protected store, **key** for an SSH key record, and
  **Servers** for saved SSH servers.
- Use sentence case for buttons and dialog titles (`New key`, `New server`).
- Use the in-app `confirmModal`/`promptModal` dialogs, never native `confirm()`/`prompt()`. The
  dialog plugin replaces `window.confirm` with an async shim whose result is always truthy, so a
  guard written with it never blocked anything (A5-01); `check-audit-safety.js` fails on a
  reintroduced `confirm(`.
- Comments and visible text must remain true after the change; fix lying comments with the code.

### IPC

- The default Tauri JavaScript argument spelling is camelCase for snake_case Rust parameters.
- `mcp_save_server` and `mcp_set_tool_state` explicitly use snake_case on the wire.
- `scripts/check-ipc-args.js` is the arbiter. Do not send duplicate snake/camel spellings as a
  hedge.
- Register a command only if the renderer actually calls it. Dead IPC surface increases what a
  compromised renderer can reach.
- Return user-facing errors as strings; keep error text actionable and free of secrets.

### Secrets and trust boundaries

- Never log or toast master passwords, private keys, saved passwords, API keys, MCP secrets, or
  sealed blobs.
- Private key material stays in Rust except for the explicit private-key import paste/pick path.
  Exports and backups are written by Rust to native-dialog paths.
- Commands that seal with the master password or rewrite whole key/server/MCP rows must take the
  shared `VaultRotationLock` guard before their first vault read and hold it through the write.
- Re-check `VaultGeneration` after awaits that can span a lock.
- A read-then-write SQLite transaction starts with `BEGIN IMMEDIATE`, so it takes the write lock
  before it reads; a deferred transaction that upgrades fails at once under any concurrent writer.
- Argon2id and other heavy key derivation, and blocking file or database work, run on the
  blocking pool (through `run_blocking`, or `seal_off_thread` and `unseal_off_thread` for one seal
  or unseal in async code) - never on the main thread or an async worker (vault create, unlock,
  import and password change, category walks and the key unseal of Connect, Test and the
  assistant use `run_blocking`; the Bitwarden sync uses the off-thread helpers and runs its
  sign-in's master-key derivation (Argon2id or PBKDF2) on the blocking pool through
  `master_key_off_thread`, at most two at once, and the MCP connect and call unseal and the lock's
  MCP teardown unseal on the pool; a scan test fails on a direct `crypto::vault` call in the sync
  or MCP code).
- A committed write whose audit row then fails is reported as a success with a warning
  (`audit_or_warn`), never as an error: the change happened, and a retry would fail on it.
- A decision that binds a secret to a destination - an MCP credential or environment variable sent
  to an address, a stored API key moved to another provider, the Bitwarden sync pointed at a server
  and account - is asked by Rust in a native dialog (`ask_native_confirmation`: Esc means no, an
  "Allow" in under a second or after a lock is not taken, one question is open at a time, a "no"
  holds back every further question of its kind (`QuestionKind`) for 30 seconds, whatever host,
  address or account it names (`CredentialQuestions`), and "Don't allow" is the default button on
  Windows and macOS only - the GTK dialog sets none). A
  "yes" flag from the renderer is never trusted, and the renderer asks no question of its own for
  it. The Bitwarden sync reads its settings only through `settings_for_sync`; a new place that
  uploads with them goes through it too.
- Every request to an MCP server - an initialize, and again once it is answered, each `tools/list`
  page, a page asked again on a renewed session, the refreshes after a call - is checked against
  the stored record right before it goes out (`not_contactable`); a session whose server changed
  is ended where it was set up and never registered, and a `tools/call` goes through the full call
  gate (`regate_call`). Two kinds of request are not checked against the record: the `-32601`
  answers to a server's own requests inside an open response (at most eight, to the same endpoint,
  checked against the vault generation) and the session DELETEs, which only end sessions. A new
  path that sends any other request must do the same.
- Destructive or policy-changing commands refuse while the vault is locked. Do not gate harmless
  display preferences.
- Use `textContent`, `createElement`, or the project's escaping helper for dynamic renderer data.
- A local path supplied by the renderer is not trusted unless bound to a native dialog grant; if
  a deny-list is the only control, document that limit honestly. A path a human picked in a native
  save dialog still goes through the write deny-list (`SensitiveLocations::write_hit`), because the
  renderer or a server suggested its name; the private-key export and the vault backup go through
  it too (with `~/.ssh` allowed), and so must any new write to a path the renderer can influence.
  A name suggested to a save dialog is reduced to a bare file name first (`save_dialog_file_name`;
  a key's name goes through it as well), so it cannot open the dialog in a folder of its own
  choosing.
- Do not add model-visible tools or MCP behavior without a Rust-side policy and documentation of
  the data sent to the provider/MCP server.

### File and code organization

- Keep source files cohesive and prefer small modules. The soft maintainability ceiling is 800
  lines. Many current files exceed it (the largest are `commands/sftp.rs`, `assistant/mcp.rs`,
  `app.js`, `commands/mod.rs`, `db/mod.rs`, `sftp.js` and `bitwarden/sync.rs`); the split is
  deferred, and the files with their line counts and the seams are in
  [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). Do not mix module splitting into unrelated fixes.
- Comments cite an audit ID (`A6-02`) or give the plain reason, never an internal work-package or
  review-round name that nobody reading the code can look up.
- Match surrounding Rust formatting and the existing vanilla JavaScript style.
- Prefer immutable updates and early returns; avoid hidden global state in new code.

### Documentation

Docs are part of the change. Update `README.md`, `docs/SECURITY.md`, `docs/PRIVACY.md`,
`docs/ARCHITECTURE.md`, `docs/MCP-SMOKE-TEST.md`, and `CHANGELOG.md` when behavior or boundaries
change. Verify every claim against committed source, state backend-only/UI-pending partial fixes
precisely, and keep audit severities described as baseline estimates unless exploitability was
proved. Every file path, relative link and `npm run` script a document names must exist; the
audit files `docs/audit/2026-10-09/A1-*.md` to `A8-*.md` are the baseline record and are not
edited (status lives in `docs/audit/2026-10-09/README.md`).

## Pull requests

1. Branch from `main`.
2. Keep commits focused. Conventional subjects such as `fix(core): ...` are preferred; list audit
   finding IDs in the body when fixing an audit finding.
3. Run the Rust gates for backend changes and the relevant renderer suites for UI changes.
4. For Windows-only, native-dialog, WebView-specific, or packaged-app behavior, report exactly what
   was and was not run natively.
5. Do not tag, release, bump versions, or open release pull requests unless you are the maintainer.

## Reporting security issues

Do not open a public issue for a vulnerability. Contact the maintainers privately with the affected
component, severity, reproduction steps, and suggested mitigation.

## Licensing

By contributing, you agree that your contributions are licensed under the project license (see
`LICENSE`).
