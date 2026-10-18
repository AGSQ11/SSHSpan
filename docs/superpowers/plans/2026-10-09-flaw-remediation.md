# SSHSpan Flaw Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the confirmed flaws found by the 2026-10-09 eight-area audit of SSHSpan v1.9.1 (UI, visual, HTML/CSS, JS logic, Rust logic, security, UX, docs) and document every finding's disposition.

**Execution rules (binding; they override any task boilerplate below):**

- All work happens sequentially in the controller's worktree on branch `gsq/app-flaws-audit-subagents-c36b18`. The "streams" below are ownership groupings only — there are no stream branches or parallel implementers. Implementers do **not** commit; after each task's review passes, the controller commits that task's changes locally (nothing is pushed, no PR is opened and no release is cut without the user's say-so). Changelog entries go under `[Unreleased]`; do not bump the version.
- Roles: the controller plans, rules, validates and merges; Sonnet/Opus agents implement and perform task reviews; Fable agents only review, critique, advise or perform the defensive security re-review. Implementers never dispatch subagents.
- Treat the audit reports as candidate findings, not gospel: re-read the cited code before changing it; if a finding is wrong or already fixed, say so in the report with evidence instead of "fixing" it. Prefer focused repairs over broad refactors; do not add product features beyond what the finding needs; do not add security deny-lists that break legitimate SSH/SFTP workflows.
- Order of work inside a task: confirmed security, data-loss and broken-feature defects first; UI/a11y/polish second.
- Never run native Windows cargo. In WSL use `set -o pipefail` whenever piping test output, preserve the real exit code, and keep enough output to prove the result (test counts, failures). Distinguish Linux execution from the Windows cross-check (`cargo check --target x86_64-pc-windows-gnu` type-checks only).
- The existing integration test `key_deploy_creates_files` writes into the running user's real `~/.ssh` and app config dir; inside WSL that is root's home in the Ubuntu-25.10 VM (no user data), which is tolerable until Task 4 fixes the test. Never point tests at real hosts, credentials, vaults or user data.
- Per-task briefs, reports and review packages live under `.superpowers/sdd/2026-10-09-flaw-remediation/` in the controller's worktree (git-ignored); implementers read them by absolute path.

**Architecture:** Sequential task groups on one branch, each implemented by a fresh subagent and gated by an independent review before the controller commits it; a docs/CI task runs last. Every task fixes a cluster of related findings and adds regression tests in the project's existing harnesses (Playwright assertions in `scripts/check-renderer-ui.js`, Rust unit/integration tests).

**Tech Stack:** Tauri 2 (Rust 1.98.0), vanilla JS renderer (no build step), xterm.js 5.5.0, SQLite via sqlx, Playwright 1.56.1 (headless Chromium) for renderer behaviour checks.

**Spec:** the audit findings in `docs/audit/2026-10-09/` (files `A1`…`A8`; `A3` arrives when its auditor finishes) plus the **Rulings** section below, which resolves every place the findings disagree or leave a product decision open. Finding IDs (`A2-01`, `A7-09`, …) are the spec references used throughout; read the finding block before fixing it — it contains the exact lines, the reproduction and the proposed fix.

## Global Constraints

- **Never run `cargo` on Windows.** Avast blocks freshly built cargo build scripts. All Rust verification runs in WSL2:
  ```bash
  wsl.exe -d Ubuntu-25.10 -e bash -lc 'export PATH=$HOME/.cargo/bin:$PATH; cd /mnt/y/Development/SSHSpan/SSHSpan/.claude/worktrees/<WORKTREE>; export CARGO_TARGET_DIR=$HOME/sshspan-target-<STREAM>; export CARGO_BUILD_JOBS=6; cargo fmt --manifest-path src-tauri/Cargo.toml -- --check && cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets -- -D clippy::correctness && cargo test --manifest-path src-tauri/Cargo.toml' 2>&1 | tr -d '\0' | grep -vE "^\s+(Compiling|Checking|Downloaded|Downloading)"
  ```
  (`<WORKTREE>` = your worktree directory name, `<STREAM>` = A/B/C/E as given in your dispatch; pipe through `tr -d '\0'` because WSL output is UTF-16.) `cargo fmt` (without `--check`) is how you format. For `#[cfg(windows)]` code additionally run `cargo check --manifest-path src-tauri/Cargo.toml --target x86_64-pc-windows-gnu` the same way (mingw is installed; it type-checks Windows-only code).
- **Renderer verification** (run from your worktree, Windows side): `for f in src/renderer/*.js; do node --check "$f"; done && node scripts/check-renderer-globals.js && node scripts/check-ipc-args.js && node scripts/check-vendor.js && npm run test:ui`. First run `npm install --no-save --no-audit --no-fund playwright@1.56.1` once in the worktree (Chromium is already cached). `npm run test:ui` must stay green; **add an assertion to `scripts/check-renderer-ui.js` for every renderer behaviour you fix** (that file is the project's regression suite — follow its existing structure: a `check…` function per area, `ok(name, got, want)` assertions, stubbed `invoke` replies).
- **TDD:** for every fix, write the failing test/assertion first (Rust `#[test]`/integration test, or a Playwright assertion), watch it fail, then fix. Where a behaviour cannot be exercised headlessly (native dialogs, real SSH), say so in your report and add the closest contract test (e.g. feed the renderer's literal values through the Rust parser).
- **File ownership (merge safety):** touch only the files/functions your stream owns (listed per task). If a fix needs a change outside your ownership, implement the contract exactly as written in the task's *Interfaces* block and nothing more; note it in your report. Never reformat whole files, never reorder functions, never rename existing globals.
- **Style:** match the surrounding code — `'use strict'` classic scripts, 2-space indent, `///` doc comments that explain *why* (the codebase documents decisions; keep that habit, briefly). Comments and user-visible copy must be true after your change (several findings are comments that lie — fix the comment when you fix the code).
- **Security invariants (SECURITY.md):** private key material never crosses IPC into the webview except the documented import path; every HTML interpolation of dynamic data goes through `escapeHtml()` or `textContent`; no new `innerHTML` with raw data; no secrets in logs/toasts/audit rows; destructive/privileged commands refuse while the vault is locked.
- **Commits:** one commit per task (or per coherent sub-cluster), conventional subject (`fix(ui): …`, `fix(sftp): …`, `fix(core): …`, `docs: …`), body listing the finding IDs fixed, ending with `Co-Authored-By: Claude Code <noreply@anthropic.com>`. Never `git stash`; never touch other branches; never push.
- **Toasts/copy:** terminology is **Servers** (not Hosts/Connect) for saved SSH servers, **Keys** for vault keys, sentence case for button labels ("New key", "New server"), " - " for dashes in generated strings.

## Rulings (product decisions that bind every task)

- **R1 Native `confirm()`:** every `window.confirm(...)` in the renderer is replaced with `await confirmModal(title, message, okLabel)` (app.js; returns `Promise<boolean>`, Cancel gets initial focus). Callers become `async`. No native dialogs from JS anywhere.
- **R2 Auto-lock default:** absent/blank/non-numeric `autoLockMinutes` means **15**; explicit `"0"` means off. Rust `collect_settings` emits the defaults (`autoLockMinutes:"15"`, `sftpParallel:"4"`) so the UI never guesses; `settings_set` validates value shapes. Activity = capture-phase keydown/mousedown/wheel/touchstart **plus** terminal input (`window.noteUserActivity()`); the backend heartbeat is sent only when there was activity in the last 60 s.
- **R3 Deploy contract:** `key_deploy` gains `hostAlias`, `hostname`, `user`, `port`; a new `key_deploy_preview` returns the exact stanza text and file paths the backend would write, and the sheet renders *that* (no fake markers). Deploy keeps writing to SSHSpan's managed config file; the sheet states the real path and offers a one-click copy of the `Include <path>` line for `~/.ssh/config`. Deploy filenames stay `sshspan_<sanitized>`; a collision with another key's `deploy_path` (or an existing foreign file) is refused with a message, never overwritten.
- **R4 `~/.ssh/config` import:** `ssh_config_list_hosts` gains `source: "user" | "managed"`; the Servers "Config" button imports from the user's real `~/.ssh/config` (read-only; `Include` followed one level; wildcard/negated patterns and `Match` blocks skipped).
- **R5 Backups never transit the webview:** `vault_backup_export_to_file` and `vault_backup_restore_from_file` open the native dialogs in Rust; the old `vault_backup_create`/`vault_backup_restore` are removed from `generate_handler!` (keep the functions, documented like `ssh_config_write`). `system_select_file` keeps serving key import (4 MiB cap); `.pem` browsing uses the new path-only `system_pick_file_path`.
- **R6 MCP approval:** the renderer passes `approved=true` to `mcpCallTool` after the card resolves true; at read/draft the card is always shown (auto-approve applies only at execute); `tool_view` exposes `definition_changed`; a changed definition clears `auto_approve` and the UI shows the re-approve notice.
- **R7 AI typing:** `type_command` and the Insert button route through a new Rust command `assistant_type_text` (level ≥ draft, rejects control characters other than TAB, audits `assistant.type`); the renderer additionally refuses multi-line text with a clear tool result.
- **R8 Provider name:** the `[OI]` token is the provider **OpenAI** — restore the name in UI and docs.
- **R9 Key import formats:** PKCS#8/PKCS#1/SPKI/authorized_keys import is **deferred** (documented as a known limitation); the Import dialog and README state the two supported formats (OpenSSH private, PuTTY .ppk) and the renderer detects other PEM headers and explains.
- **R10 Deferred (documented, not fixed in this cycle):** A7-54/A7-55 full queue/sync test suites (targeted tests are added per fix instead), A7-58 legacy Electron vault importer (docs corrected), A7-03 importers (R9), A1-29 wholesale CSS token refactor beyond the listed dead/duplicate rules, download progress events for the updater (A5-22 gets an in-app dialog + busy state only).
- **R11 Quit/close:** add `app_quit` (tray-equivalent, runs the lock teardown); window close keeps hiding to the tray but shows a one-time toast "SSHSpan keeps running in the tray - Quit from the tray or Ctrl+Q"; `Ctrl+Q` and a palette/vault-menu "Quit" entry call `app_quit`.
- **R12 Version marker:** new `app_info` command returns `{version, platform}` from `CARGO_PKG_VERSION`; the `v14-tabs` marker is removed everywhere.

## Review Focus

1. Converting sync `confirm()` guards into `await confirmModal()` turns several functions async — a caller that previously relied on a synchronous return (tab close from `clearConnectView`, keyboard shortcuts, Bitwarden apply) must await or deliberately fire-and-forget; a missed `await` makes the guard a no-op again. Test: Playwright assertion that Cancel on the key-delete dialog leaves `key_delete` uncalled and OK calls it (Task 1).
2. Capture-phase listeners (activity + app chords) must only *observe* keystrokes bound for xterm and inputs; a `preventDefault` there eats terminal input. Test: assertion that typing into a focused xterm still reaches `terminal_send` and resets the idle deadline (Tasks 2/8).
3. `collect_settings` now emits defaults — the UI test stub seeds `autoLockMinutes:15`; remove the seed so the fresh-install state is what is tested; explicit `""` stored by older builds must read as 15 (Task 2).
4. Backup export/restore moved into Rust: the renderer must not read `pick.text` anymore and `check-ipc-args.js` must see the new command names; the restore password prompt path (`needsPassword`) must round-trip (Task 5).
5. The SFTP queue panel moves from rebuild-per-event to patch-in-place — the state transitions pending→active→paused/failed/done/cancelled and "Clear finished" must still render, and Pause/Cancel clicks must survive progress events (Task 11).

---

# Stream A - Vault, Keys, Deploy, Settings, global renderer

Worktree `fix-A`, branch `fix/stream-a`. Owns: `src/renderer/app.js` (all functions except those listed under Stream B), `src/renderer/index.html` (except lines 230-254 assistant panel, 353-477 assistant settings, 505-541 YOLO modal), `src/renderer/styles.css` (except `.sftp-*`, `.q-*`, `.term*`, `.terminal*`, `.session-surface*`, `.ai-*`, `.assistant*`, `.mcp-*`, `.yolo*` selectors), `src/renderer/icons.js`, `scripts/check-*.js`, `src-tauri/src/commands/mod.rs` (except `bitwarden_*`, `update_*`, `ssh_config_list_hosts`), `src-tauri/src/ssh/mod.rs`, `src-tauri/src/config/mod.rs` (except the new user-config parser Stream B adds), `src-tauri/src/crypto/*.rs`, `src-tauri/src/db/mod.rs`, `src-tauri/tests/integration.rs`, `src-tauri/src/lib.rs` **only** the `generate_handler!` list entries it adds/removes.

### Task 1: Native confirm, vault dialog and secret-hygiene fixes

**Files:**
- Modify: `src/renderer/app.js` (`confirmModal`, `promptModal`/`closePrompt`, `refreshVaultStatus`, `showVaultModal`, `hideVaultModal`, `lockNow`, `closeKeyModal`, the vault Cancel handler, the global keydown handler ~3400-3448, `modalDidOpen`, all `window.confirm` sites at ~588, 1696, 1725, 2179, 2884, 2957)
- Modify: `src/renderer/index.html` (`#promptInput`, `#confirmModal`, vault modal placeholders)
- Modify: `src/renderer/styles.css` (`.modal-backdrop` stacking)
- Test: `scripts/check-renderer-ui.js`

**Interfaces:**
- Produces: `confirmModal(title, message, okLabel) → Promise<boolean>` (unchanged signature; Cancel focused first; Escape = false); `promptModal(title, message, initial, onOk, { secret })` — `secret: true` sets `type="password"`, skips `trim()`, clears the value on close; `window.closeTopModal()` used by the global Escape chain; `state.vaultPromptDismissed`.
- Consumes: nothing from other streams. Stream B/C/E replace the `confirm()` sites in their own files the same way.

**Findings fixed:** A5-01 (app.js sites; `confirm` → `confirmModal`, make callers async), A1-30 (focus Cancel), A2-06 (change-password dialog closed by the poll), A2-10 / A5-08 / A1-23 (dismissed unlock dialog reopens every 10 s; remember dismissal, reopen only on lock transition or explicit open), A2-09 / A5-19 (secrets stay in DOM on lock/cancel: clear `#importPem`, `#importPass`, `#srvPassword`, `#connectPwInput`, `#keyPassphraseInput`, `#detailExportPass`, `#bw_master_password`, `#configPreview`; close every modal on lock), A2-13 / A5-18 (restore password prompt is plain text), A2-49 (change-password field order/labels: Current first, "New master password", "Confirm new password"), A2-22 (global shortcuts ignore open modals; `Ctrl+N` on no-vault keeps `create`), A2-40 / A1-27 (Escape: central handler closes the topmost dialog incl. prompt/connect-password/YOLO/vault; input handlers `stopPropagation`), A1-09 (dialogs share z-index 50: assign `zIndex = 50 + modalStack.length` on open, reset on close; palette/Ctrl+K suppressed while a non-palette modal is open), A2-20 (unhandled rejections: `addCategoryPrompt` try/catch; `unhandledrejection` handler toasts).

- [ ] **Step 1:** Add Playwright assertions (RED) in a new `checkConfirmAndVaultDialogs` section: (a) key delete → Cancel leaves `key_delete` uncalled, OK calls it; (b) `showVaultModal('change')` survives a `vault_status` poll with the fields intact; (c) Cancel on the unlock dialog → after 11 s (fake clock or short poll) the dialog stays hidden; (d) after `lockNow()` the import textarea is empty and no modal except the vault modal is open; (e) `promptModal(..., {secret:true})` renders `type=password`. Run `npm run test:ui` → see them fail.
- [ ] **Step 2:** Implement the fixes listed above, smallest change per finding; keep `confirmModal`'s existing markup.
- [ ] **Step 3:** Run the full renderer verification; all green, no console errors.
- [ ] **Step 4:** Commit `fix(ui): in-app confirmations, vault dialog lifecycle, secret hygiene (A5-01 A1-30 A2-06 A2-10 A2-09 A2-13 A2-49 A2-22 A2-40 A1-09 A2-20)`.

### Task 2: Auto-lock that actually locks, settings defaults and value validation

**Files:**
- Modify: `src/renderer/app.js` (`refreshVaultStatus`, `resetAutoLockTimer`, `renderVaultCountdown`, the activity listeners ~4536-4540, the heartbeat `setInterval` ~3603-3607, `lockNow`, settings rows for auto-lock and parallel transfers ~2506-2602, `main()` boot)
- Modify: `src-tauri/src/commands/mod.rs` (`collect_settings`, `settings_set`, the watchdog comment ~430-465, `heartbeat`, add `require_unlocked` gating to `key_delete`, `key_rename`, `category_create/rename/delete/move`, `audit_clear`, `settings_set`)
- Test: `scripts/check-renderer-ui.js`, `src-tauri/tests/integration.rs`

**Interfaces:**
- Produces: `window.noteUserActivity()` (throttled ≤1/s; resets the idle deadline and stamps `lastActivityAt`); `listen('vault-locked-by-watchdog', …)`; `collect_settings` returns `autoLockMinutes` (default `"15"`) and `sftpParallel` (default `"4"`) when unset; `settings_set` rejects `autoLockMinutes` outside integer 0..=1440, `sftpParallel` outside 1..=4, booleans other than `"true"/"false"`.
- Consumes: Stream B calls `window.noteUserActivity?.()` from terminal `onData` (Task 8).

**Findings fixed:** A2-01 (poll re-arms timer: reset only on the locked→unlocked transition), A2-14 / A8-00 / A5-06 / A7-11 (defaults, `NaN`→15, validation, Rust comment, watchdog event listener), A2-53 / A3-08 (capture-phase activity listeners; `noteUserActivity`), A5-09 (manual lock with live sessions: `confirmModal("Lock the vault?", "Locking closes N live session(s) and pauses M transfer(s).")`; 60 s before an idle lock show a warning toast "Locking in 60 s - move the mouse or press a key to stay unlocked" that any activity cancels), A6-08 (lock gates on destructive/policy commands), A5-32 (settings controls revert on failed save; auto-lock input validated/clamped before save), heartbeat only when `Date.now()-lastActivityAt < 60000`.

- [ ] **Step 1:** RED — Playwright: with `settings_get` returning `{}` and `vault_status` unlocked, after N polls of a fake clock the countdown decreases and `vault_lock` is invoked at the deadline; chip reads "locks in 15:00" on a fresh install; typing into xterm resets the deadline. Rust `#[test]`: `settings_set("autoLockMinutes","-5")` → Err; `collect_settings` on an empty DB contains `autoLockMinutes == "15"`; `key_delete` while locked → Err("Vault is locked."). Watch them fail.
- [ ] **Step 2:** Implement; remove the `autoLockMinutes: 15` seed from the UI test's default replies so the fresh state is exercised; fix the `scripts/check-renderer-ui.js` stub shape if needed.
- [ ] **Step 3:** Renderer + Rust verification green.
- [ ] **Step 4:** Commit `fix(core): idle auto-lock fires, shared setting defaults, locked-vault gates (A2-01 A2-14 A2-53 A5-09 A6-08 A5-32)`.

### Task 3: Keys - generation, export, categories, list behaviour

**Files:**
- Modify: `src/renderer/app.js` (key modal `submitKeyModal`/`openKeyModal`/`closeKeyModal`, `exportSelected`, `renderKeyList`/`keyRowEl`/`keyAvatar`/group collapse, category tree/DnD/picker (`catNodeEl`, drop handler ~705-729, `openCategoryPicker`/`closeCategoryPicker`, picker keyboard), `selectKey`, `loadKnownHosts`/`loadAudit` loaders, `deleteCategory`, selection bar, key detail pane incl. "Remove deployed copy", `catPath` walks), `src/renderer/index.html` (`#genCurve` option values, selection bar, key detail), `src/renderer/styles.css` (`.key-row-name`, `.key-group.collapsed`, `.detail-pane` sticky, `.selection-bar` wrap, `.badge.warn`, category menu icons)
- Modify: `src-tauri/src/crypto/keys.rs` (`KeyType::from_db_tag` accepts `ecdsa-nistp256/384/521`; comment sanitisation on import/export), `src-tauri/src/commands/mod.rs` (`key_export_to_file` rejects `pkcs8-encrypted` without passphrase; `key_create_with_categories`/`key_generate` async via `spawn_blocking`; `key_remove_deployed` removes the stanza via `SshService::remove_key`, reports fs errors, audits; master-password length counts chars), `src-tauri/src/db/mod.rs` (`delete_key` deletes `key_categories` rows; `delete_category` nulls `servers.category_id` and returns the real re-parented child ids; startup migration cleans existing dangling rows)
- Test: `scripts/check-renderer-ui.js`, `src-tauri/tests/integration.rs`, `#[cfg(test)]` in keys.rs

**Interfaces:**
- Produces: `key_remove_deployed` result `{ok, removed: [paths], warnings: [..]}`; `withBusy(buttonEl, busyLabel, asyncFn)` helper in app.js (disables + relabels + ignores re-entry; used by every primary action in this stream and available to Streams B/E).
- Consumes: none.

**Findings fixed:** A2-02 / A7-02 / A5-37 (ECDSA: option values `p256/p384/p521` AND Rust accepts `nistp*`), A2-03 / A7-05 / A5-38 (encrypted PKCS#8 needs a passphrase on both sides; toast names the real format), A2-18 / A5-12 (`withBusy` on key create/import, vault submit, deploy, backup, test buttons; double-click creates one key), A2-37 (modal state reset, open on Generate tab), A2-26 / A5-27 (no-match state with "Clear filter"; detail pane cleared when the selected key is filtered out), A2-23 (recursive, de-duplicated counts), A2-27 / A1-28 (menu icons via `ico()`; add `clipboard`, `eraser`, `rotate-ccw` to ICONS; `#conflictCloseBtn` gets `data-ico-x aria-label`; `.ctx-sep` `border:0` + delete duplicate rule), A2-28 (avatar colour for `ecdsa-*`), A1-12 (collapse hides rows), A2-07 (category drop zones read before class removal; renumber siblings), A2-15 (picker saves/restores `state.categoryScope`), A2-36 (picker ArrowUp from -1), A5-42 (new key/server hidden by filter: preselect active category; toast "hidden by the current filter" with Show all), A2-45 (cycle guards in `catPath`/distinct-top walk; rootless components shown under Uncategorized), A1-07 (name ellipsis; `.row-btn` out of flow), A1-24 (sticky detail pane; scroll into view in stacked layout), A5-34 (select-all-visible checkbox; prune hidden from selection on filter change; no auto-select after delete), A7-22 / A5-43 / A8-16 (Remove deployed copy button; `key_delete` confirm offers "also delete the deployed file"), A7-28 / A2-54 / A2-31 / A7-40 (dangling rows; correct reassigned count; reload servers after host-category delete), A7-52 (chars not bytes), A7-45 (comment control chars rejected/replaced on import; exports re-check), A7-12 (keygen off the main thread; bits clamped to 2048..=8192; hint "RSA 4096+ can take a minute"), A2-29 (loaders build into a fragment and `replaceChildren`; stale-response guard in `selectKey`; `known_hosts_list` failure toasts; duplicate `loadKnownHosts()` call removed), A1-40 (`.badge.warn`), A7-03 / A5-39 / R9 (Import dialog label and README-facing copy name the two supported formats; the renderer detects `BEGIN RSA|EC|PRIVATE KEY`, `BEGIN ENCRYPTED PRIVATE KEY`, `BEGIN PUBLIC KEY` and `ssh-… AAAA` lines before calling the backend and explains "convert with `ssh-keygen -p -m RFC4716`/`puttygen` or paste an OpenSSH key"; `key_import`'s error names the detected format), A8-12 (OpenSSH and PPK exports accept an *optional* passphrase: show the field for those formats, relabel "Unprotected unless you set a passphrase"), A2-42 (public-key/authorized_keys exports go through `system_pick_save_path` + `system_write_text_file` like the private formats; `EXPORT_EXT['public-pem']` becomes `.pem`), A7-53 (add a PPK export → import round-trip test and a PKCS#8 export parse-back test per key type), A8-16 (de-register `key_generate`, `key_fingerprint`, `ssh_config_read` from `generate_handler!` with a doc comment, matching the `ssh_config_write` precedent).

- [ ] **Step 1:** RED tests: Rust — `from_db_tag("ecdsa-nistp256")` ok; `key_export_to_file` contract test for the empty passphrase (unit-level helper); `delete_key` leaves no `key_categories` rows; `delete_category` nulls server category ids and returns only re-parented children; master password `"ééé"` (6 bytes? no: 3 chars) rejected. Playwright — each `#genCurve` option yields `keyType` `ecdsa-p256/p384/p521`; export with blank passphrase for `pkcs8-encrypted` does not call `key_export_to_file`; double-click Create issues one call; collapse hides rows; drop-before/into posts the right `newParentId/sortIndex`; no-match row appears for `zzzz`.
- [ ] **Step 2:** Implement in small commits if you prefer (keys core; categories; polish), each green.
- [ ] **Step 3:** Full renderer + Rust verification green.
- [ ] **Step 4:** Commit(s) `fix(keys): …` listing the IDs.

### Task 4: Deploy sheet tells the truth and cannot overwrite the wrong key

**Files:**
- Modify: `src-tauri/src/ssh/mod.rs` (`deploy_key` split into `plan_deploy(…) -> DeployPlan` + `apply`; collision refusal; `remove_key` used by `key_remove_deployed`; Windows ACL fix lives here too — see Task 5), `src-tauri/src/commands/mod.rs` (`key_deploy` new args; new `key_deploy_preview`), `src-tauri/src/config/mod.rs` (`to_config_string` for a subset of hosts), `src-tauri/src/lib.rs` (`generate_handler!` += `key_deploy_preview`), `src-tauri/tests/integration.rs` (deploy test uses temp dirs via `deploy_key_in(ssh_dir, config_path, …)` and asserts files + stanza; remove the `let _ = result;` no-op)
- Modify: `src/renderer/app.js` (`previewConfig`, `deployConfig`, `copyConfig`, `openDeploySheet`/`closeDeploySheet`), `src/renderer/index.html` (deploy modal copy at 666, 675-677, 704-716: real path, `Include` line + Copy button, no markers), `scripts/check-renderer-ui.js`

**Interfaces:**
- Produces: `key_deploy(ids, passphrase?, strictHostKey?, hostAlias?, hostname?, user?, port?)`; `key_deploy_preview(ids, hostAlias?, hostname?, user?, port?, strictHostKey?) → { configPath, sshDir, includeLine, keys: [{id, name, alias, file, pubFile, overwritesFile, ownedByOtherKey}], configText }` where `configText` is exactly what `apply` would write for those stanzas. Alias rule: one key → `hostAlias` (validated as a single Host token, else sanitized); several keys → `<hostAlias>-<sanitized key name>`; no alias → key name.
- Consumes: `withBusy` from Task 3.

**Findings fixed:** A2-05 / A7-04 / A8-01 / A5-04 (preview = backend plan; fields are honoured), A5-05 (Include hint; subtitle names the managed file), A2-33 (validate alias/user before writing; register servers before closing), A2-46 / A7-59 / A5-25 (collision refusal + duplicate-name rejection on create/import/rename, case-insensitive), A7-32 / A5-26 (disable "Also save as servers" when a deploy passphrase is set; explain), A7-56 (deploy test no longer writes to the real `~/.ssh`), A2-34 ("preview first" copy), A8-26 (deploy path joined with the platform separator from `system_paths`), A8-24 (Rust dead code: delete `SshService::list_deployed_keys`, `get_config_hosts`, `DeployedKeyInfo`, `SshConfigService::add_host`, `get_deployable_keys`, `VaultKey::new`, `derive_auth_key`; make `key_remove_deployed` use `SshService::remove_key`).

- [ ] **Step 1:** RED — Rust test: `plan_deploy` for two keys named `a.b` and `a_b` reports a collision and `apply` refuses; temp-dir deploy writes `sshspan_<name>` 0600 (unix) and a stanza containing `HostName`/`User`/`Port` when given. Playwright: the preview textarea equals the `configText` returned by the stubbed `key_deploy_preview`; `key_deploy` payload carries `hostAlias/hostname/user/port`; the register toggle is disabled when the passphrase toggle is on.
- [ ] **Step 2:** Implement.
- [ ] **Step 3:** Verification green (incl. `check-ipc-args`).
- [ ] **Step 4:** Commit `fix(deploy): honest preview, pass-through host fields, collision refusal (A2-05 A7-04 A5-05 A2-33 A2-46 A7-32 A7-56)`.

### Task 5: Secret files on Windows, backups in Rust, path-only pickers, bulk crypto off the main thread

**Files:**
- Modify: `src-tauri/src/ssh/mod.rs` (`restrict_windows_file`: `*SID`, absolute `%SystemRoot%\System32\whoami.exe`/`icacls.exe`, one `icacls` invocation `/inheritance:r /grant:r *SID:F`, `CREATE_NO_WINDOW`; `#[cfg(windows)]` test asserting a single ACE), `src-tauri/src/commands/mod.rs` (`vault_backup_export_to_file`, `vault_backup_restore_from_file`, `system_pick_file_path`, `system_select_file` 4 MiB cap, `vault_change_password`/restore loops under `spawn_blocking`, `VaultPasswordStore::get` → `Zeroizing`, `is_set()`), `src-tauri/src/crypto/vault.rs` (`Zeroizing<[u8;32]>`, fix the scrypt comment), `src-tauri/src/db/mod.rs` (restore: audit rows after commit; numeric `bitwarden_*` fields; backup includes `sftp.bookmarks.*`), `src-tauri/src/lib.rs` (handler list), `src/renderer/app.js` (`backupCreate`, `backupRestore`, `finishRestore` reloads settings/applies scale/resets timer, CSV `csvField` formula escaping, "Create your vault" copy says Argon2id), `scripts/check-renderer-ui.js`
- Test: `src-tauri/tests/integration.rs` (backup→restore round trip for keys incl. `bitwarden_revision_ts` and bookmarks), `#[cfg(windows)]` ACL test

**Interfaces:**
- Produces: `vault_backup_export_to_file() → {path, counts}`; `vault_backup_restore_from_file(path?: String, backupPassword?: String) → restore result | {needsPassword: true, path}` (path registered in `DialogPathStore` with TTL, consumed on the second call); `system_pick_file_path(title?) → {canceled, path, name}`.
- Consumes: Stream B switches the `.pem` browse button to `system_pick_file_path` (Task 7).

**Findings fixed:** A7-01 (Critical) + A7-43 + A6-13, A6-03 / A2-48 (backup never transits the webview), A6-04 / A2-19 (path-only picker; size cap), A2-30 (restore reloads settings), A7-41 (bookmarks in backup; card text lists what is covered), A7-27 (numeric metadata), A7-25 (audit after commit), A7-13 (bulk Argon2id off the main thread), A6-11 (zeroization gaps), A2-32 (CSV injection), A8-11 (Argon2id copy), A8-23(d) (vault.rs comment), A8-23(a) (app.js header comment states the real boundary: private material enters the webview only on the explicit import paste/pick path; exports and backups are written by Rust).

- [ ] **Step 1:** RED — Rust: restore of a payload whose key carries numeric `bitwarden_revision_ts` keeps it; restore with an invalid key name completes without a 5 s stall and writes the audit row after commit (assert row exists); backup JSON contains `sftp.bookmarks.*`; Windows ACL test (`cargo check --target x86_64-pc-windows-gnu` must pass; the test itself runs only on Windows CI). Playwright: `backupCreate` calls `vault_backup_export_to_file` and never `system_write_text_file` with vault JSON; restore with `{needsPassword:true}` opens the secret prompt and retries with `backupPassword`.
- [ ] **Step 2:** Implement.
- [ ] **Step 3:** Verification green (both targets).
- [ ] **Step 4:** Commit `fix(core): Windows ACL grant, backups stay in Rust, path-only picker, bulk KDF off main thread (A7-01 A6-03 A6-04 A2-30 A7-41 A7-27 A7-25 A7-13 A6-11 A2-32)`.

### Task 6: Settings, palette, menus, accessibility and global polish

**Files:**
- Modify: `src/renderer/app.js` (`mkRow` and settings handlers ~2475-2853, `loadAudit` + filter/paging UI, `renderPalette`/`paletteCandidates`/palette actions, a shared `openMenu(anchorOrPoint, items)` helper replacing the ad-hoc menu builders `openVaultMenu`/`openCatMenu`/`openKeyConnectMenu`/`openServerContextMenu`(call-site only)/`openTerminalContextMenu`(call-site only), `switchView` (breadcrumb), `injectIcons`, boot: `app_info` version display, `window.__SSHPAN_BUILD__` removal, global keydown (`ev.code` digits), error-state cards for `loadKeys`/`loadServers`/`loadSettings`, toast de-duplication), `src/renderer/index.html` (settings rows, audit filter controls, `#newKeyBtn` label, labels that bind nothing → spans/`for`, `autocomplete`/`spellcheck`, `color-scheme`), `src/renderer/styles.css` (focus-visible ring, `--text-faint` contrast, `.seg-btn.active` dark text, compact-layout vault text, categories drawer ≤900px, modal flex layout with sticky footer, `.settings-view` max-width, dead/duplicate rules listed in A1-29, `prefers-reduced-motion`, 24px hit areas, `.key-row`/`.cat-node`/`.term-tab` focusable styles), `src/renderer/icons.js`, `scripts/check-ipc-args.js` (`aiCall(` sites), `scripts/check-renderer-globals.js` (FILES += assistant.js, mcp.js; OWNED += `ai|mcp|assistant`), `src-tauri/src/commands/mod.rs` + `lib.rs` (`app_info`)
- Test: `scripts/check-renderer-ui.js`

**Interfaces:**
- Produces: `openMenu({x, y} | anchorEl, items: [{label, icon, danger, onSelect} | 'sep'], {onClose}) → closes on Escape/outside click, focuses first item, Arrow/Home/End, returns focus to anchor, resets `aria-expanded`` — Streams B/C may adopt it later but are not required to; `app_info() → {version, platform}`.
- Consumes: none.

**Findings fixed:** A2-16 / A1-05 (label nesting: `mkRow` → `div.settings-row` + explicit `<label for>`; bandwidth pill single toggle; auth-method label → `fieldset`), A5-16 (audit log: event-type select + text filter + "Load older" via `audit_list` `offset/limit`), A1-08 (settings width), A8-14 (parallel default display — with Task 2's Rust default), A2-17 (breadcrumb on view switch), A2-24 / A8-26 (version from `app_info`; drop `v14-tabs`, restore "Key manager" subtitle), A5-17 (tokenised palette search, ranking, more actions: every Settings section, Change master password, Check for updates, Quit (calls `app_quit` if defined), Lock), A2-50 / A1-26 (menu helper, keyboard, `aria-expanded`), A1-10 (focus rings), A1-11 (keyboard-operable key rows/category rows/chevrons/tab-add via role+tabindex+Enter/Space), A1-13 / A1-14 (contrast tokens), A1-19 (compact vault chip), A1-06 / A5-13 (categories reachable ≤900px: toolbar "Categories" button opens the tree as a drawer; dead `.cat-filter-btn` rules removed; false comment removed), A1-22 / A5-15 (modal flex + sticky footer; Enter submits the key dialog from single-line fields), A1-18 (selection bar wraps), A1-29 (dead selectors, duplicate declarations, `var(--mono)`, redundant `[hidden]` rules, `.badge.ghost`), A1-32, A1-33, A1-34, A1-35 (titles on ellipsised text; fingerprint wraps), A1-36 (tab/combobox ARIA, unbound labels, reduced motion, hit areas), A1-37 (`color-scheme: dark`), A5-21 (error cards with Retry instead of empty states; identical toasts collapsed), A5-35 (an eye/reveal toggle on every `type=password` input, including the JS-built Bitwarden field; the toggle never persists), A5-31 (terminology: breadcrumb root "Servers", "Server categories", "Keyboard-interactive", locked nav tooltip), A8-18 (`ev.code` for Ctrl+Shift+1/2/3), A3-35 (palette "Switch to session" picks a LIVE tab of that server, else connects), A8-17 (CI scripts cover assistant.js/mcp.js), A8-24 / A2-34 (dead code removed: `categoryIdsForScope`, `totalKeyCountFor`, `keysInCategory`, `loadBitwardenSync`, duplicate "Duplicate session" entry handled by Stream B, garbled comment at ~4438, `initTerminal` no-op call), A5-33 is Stream B's.

- [ ] **Step 1:** RED assertions: bandwidth pill one click → exactly one `settings_set`; audit filter narrows rows; palette "prod web" finds `prod-web`; Tab reaches a key row and Enter selects it; focused `#detailRenameBtn` has a non-`none` outline; `#catPanel` reachable at 880px via the toolbar button; `app_info` version text visible in the sidebar; `check-ipc-args.js` reports the assistant sites (run it: it should now count >118 sites).
- [ ] **Step 2:** Implement (several commits are fine).
- [ ] **Step 3:** Verification green; also run the contrast script idea: assert computed `--text-faint` ≥ 4.5:1 on `--bg` in a Playwright check.
- [ ] **Step 4:** Commit(s) `fix(ui): …`.

---

# Stream B - Servers, terminal, SSH client, lifecycle, updater, Bitwarden

Worktree `fix-B`, branch `fix/stream-b`. Owns: in `src/renderer/app.js` only these functions: `loadServers`, `renderServerList`, `serverRowEl`, `selectServer`, `openServerModal`, `closeServerModal`, `submitServerModal`, `setConnectAuthMethod`, `srvBrowsePemBtn` handler, `openServerContextMenu`, `deleteSelectedServer`, `importFromSshConfig`, `openSessionTab`, `closeSessionTab`, `reconnectActiveTab`, `testSelectedServer`, `askConnectPassword`, `closeConnectPwModal`, `updateTerminalHead`, `toggleTermMax`, `openTerminalContextMenu`, `activateSessionSurface`, `hostPickerTree`/`buildHostPickerLevel`/`openKeyConnectMenu` picker filtering, `bwTest`, `bwSyncNow`, `renderBitwardenForm`/`saveBitwardenConfig`, `manualUpdateCheck`; `src/renderer/terminal.js`; `src-tauri/src/commands/server.rs`, `src-tauri/src/commands/terminal.rs`, `src-tauri/src/ssh_client/mod.rs`, `src-tauri/src/commands/updater.rs`, `src-tauri/src/bitwarden/*.rs`, `src-tauri/src/lib.rs` (window/tray/exit handling + its `generate_handler!` entries), in `src-tauri/src/commands/mod.rs` only `bitwarden_*` functions and `ssh_config_list_hosts`, in `src-tauri/src/config/mod.rs` only a new `read_user_ssh_config()` parser; CSS selectors `.term*`, `.terminal*`, `.session-surface*`, `.server-*`, `#srvKeyRow`/`.server-key-row`, `.pem-row`; `src-tauri/tests/mcp_integration.rs` untouched.

### Task 7: Servers - saved passwords, test/connect flows, menus, import from the real ssh config

**Files:**
- Modify: `src-tauri/src/commands/server.rs` (`server_save`: keep `saved_password` when `None`; `clear_saved_password: Option<bool>`; `server_test` unchanged signature), `src-tauri/src/commands/terminal.rs` (`known_hosts_forget` lock gate), `src-tauri/src/config/mod.rs` (`read_user_ssh_config(path) -> Vec<SshHostConfig>` following one `Include` level, skipping `Match`, wildcard `*`/`?`/`!` patterns), `src-tauri/src/commands/mod.rs` (`ssh_config_list_hosts(source: Option<String>)`), `src/renderer/app.js` (functions listed above), `src/renderer/index.html` (server modal: saved-password hint + "Remove saved password" button, `.pem` row class rename, `#srvPort` validation message, row "…" actions button, Config button tooltip), `src/renderer/styles.css` (server selectors), `scripts/check-renderer-ui.js`

**Interfaces:**
- Produces: `server_save(…, savedPassword?, clearSavedPassword?)` — `savedPassword: null` on an existing server keeps the stored value; `clearSavedPassword: true` removes it; switching `authMethod` to `publickey` clears it; `ssh_config_list_hosts({ source: "user" | "managed" })` (default `"user"`) → `{hosts, path}`; `server_list` rows gain `hasSavedPassword` (already) — no change.
- Consumes: `confirmModal` (Task 1 — already exists on main); `system_pick_file_path` (Task 5; if not merged yet, implement the renderer call and note it); `withBusy` optional.

**Findings fixed:** A2-04 / A7-07 / A5-03 (saved password survives edits; dialog says "A password is saved - leave blank to keep it"), A2-11 / A7-38 / A5-20 (Test prompts for the password), A2-12 / A5-10 (closing a tab mid-connect disconnects the late session; "Connecting…" state with Cancel; status strip not overwritten by `switchView`), A2-44 (Reconnect reconnects the active tab; keeps `overrideKeyId`), A2-21 / A1-04 (server + terminal context menus clamped via `positionCtxMenuAt`), A2-39 / A5-30 (port 1-65535 validated inline), A2-35 / A5-41 (host picker lists only publickey servers for "Use this key"), A5-02 (connect password prompt gets focus; Escape cancels — coordinate with Task 1's Escape chain by exposing `window.closeConnectPwModal`), A2-25 (status strip: idle text only when no active tab; test result as toast), A5-28 (row "…" button opens the same menu; Edit in terminal header), A1-20 / A1-21 (server row layout; `.server-key-row`), A5-33 (drop duplicate "Duplicate session"; confirm "Restart session" when live), A2-43 / A7-26 / A8-02 / A5-05 (import from the user's `~/.ssh/config`; wildcard patterns filtered; tooltip true), A5-01 sites app.js:3810 (server delete), 4299 (close tab), 2410 (Bitwarden apply - Task 9), 3615 (update - Task 9), A6-08 (`known_hosts_forget` gate), A8-23(c) (remove the stale keepalive comments in terminal.js/terminal.rs).

- [ ] **Step 1:** RED — Rust: `server_save` update with `saved_password: None` keeps the sealed value; with `clear_saved_password: Some(true)` clears it; `read_user_ssh_config` parses a fixture with `Host a`, `Host *`, `Match`, `Include` and returns only `a` + included hosts. Playwright: editing a `hasSavedPassword` server posts `savedPassword:null, clearSavedPassword:false`; Test on a password server opens the prompt and sends `promptPassword`; closing a tab while `terminal_connect` is pending leads to one `terminal_disconnect`; right-click near the bottom-right keeps the menu inside the viewport; port 70000 is rejected inline; the prompt input has focus 200 ms after opening.
- [ ] **Step 2:** Implement.
- [ ] **Step 3:** Verification green.
- [ ] **Step 4:** Commit `fix(servers): keep saved passwords, test prompt, connect lifecycle, real ssh config import (…)`.

### Task 8: Terminal and SSH client correctness

**Files:**
- Modify: `src/renderer/terminal.js` (`buildKeyCompatibilityHandler` → `term.input()`/`sendTerminalBytes`; capture-phase `paste` listener routing every paste through `terminalPaste`; `attachCustomKeyEventHandler` that lets `Ctrl+Shift+Digit1-3` and the term-max restore chord (`Ctrl+Shift+M`) bubble to app.js and otherwise returns true; developer `trace()` lines only when `terminalSetting('debugTrace')` is on (default off) — keep failure lines; OSC-8 `linkHandler` → `system_open_url`; `onData` calls `window.noteUserActivity?.()`; `fit()` on visibility/resize; `dispose()` on tab destroy; `confirm` at ~667 → `confirmModal`), `src/renderer/app.js` (`toggleTermMax` hint text/shortcut; `openTerminalContextMenu` items), `src/renderer/styles.css` (`.terminal-host` padding → inner wrapper; `.term-max-btn` placement/opacity), `src-tauri/src/ssh_client/mod.rs` (UTF-8 carry buffer; `HostKeyOutcome` shared with the connect call; connect/auth `tokio::time::timeout`; unpadded `SHA256:` fingerprints everywhere + one-time migration of stored rows), `src-tauri/src/commands/terminal.rs` (distinct messages for mismatch vs declined in `terminal_connect` and `server_test`; `known_hosts_list` returns the labelled fingerprint), `scripts/check-renderer-ui.js`

**Interfaces:**
- Produces: error strings `"Host key mismatch for <host>:<port> - possible man-in-the-middle. If the server's key really changed, forget it under Settings > Known hosts and reconnect."` and `"Connection cancelled: host key not trusted."`; connect timeout 20 s, auth 30 s → `"Timed out connecting to <host>:<port>."`.
- Consumes: `window.noteUserActivity` (Task 2, optional-chained), `confirmModal`.

**Findings fixed:** A8-03 (dead keys), A5-45 (Ctrl+V/middle-click paste guard), A5-44 / A2-53-part (term-max restore chord that works while xterm has focus; Ctrl+Shift+1/2/3 pass through), A5-11 (traces), A6-12 (OSC-8), A1-38 (host padding; max button), A3-08 (activity from terminal input), A7-08 / A3-32 (UTF-8 split packets), A7-14 (mismatch vs declined), A7-15 (timeouts), A7-46 (fingerprint format), A2-12-part (poll cleared on destroy), A8-23(c), A3-11 (every paste path uses `term.paste()` so bracketed paste and CR translation apply), A3-13 / A3-14 (restart on a live or connecting tab: in-flight guard, SFTP state reset, old channel's "[connection closed]" suppressed), A3-26 (`terminalBackspace` maps to the real xterm option or is removed from Settings with an honest note; visual bell implemented via `onBell` tab flash, not `bellStyle`), A3-27 (returning to the Servers view focuses the active terminal; strip text follows the active tab), A3-31 (menu label matches the real mode cycle), A3-36 (restart keeps scrollback: no `reset()` on reconnect of an existing tab).

- [ ] **Step 1:** RED — Rust unit test splitting "é€😀" at every byte offset through the carry buffer; `fingerprint_of_blob` equals `ssh_fingerprint_sha256` form. Playwright (real xterm): with `terminalHomeEnd='rxvt'` a Home keydown yields `terminal_send` of `[27,91,55,126]` and no local buffer change; a native `paste` event with two lines opens the confirm (stub) instead of sending; Ctrl+Shift+M restores from term-max while xterm is focused; a connect's first lines contain no `[sshspan]` trace when the debug setting is off.
- [ ] **Step 2:** Implement.
- [ ] **Step 3:** Verification green.
- [ ] **Step 4:** Commit `fix(terminal): key compatibility sends to the session, paste guard, host-key messages, UTF-8 (…)`.

### Task 9: Lifecycle, updater and Bitwarden sync honesty

**Files:**
- Modify: `src-tauri/src/lib.rs` (`app_quit` command; `ExitRequested` → `lock_vault_internal`; setup error → native message dialog with the DB path then exit; first-close toast event `window-hidden-to-tray`), `src-tauri/src/commands/updater.rs` (trusted-comment check `SSHSpan release v<version>`; launch via `opener::open`/ShellExecute; delete partial installers on every error; prune `sshspan-*-update-*` older than 1 day at startup; `update_check` returns `newerVersion` when newer but no asset), `src-tauri/src/bitwarden/sync.rs` (update-push writes back `revisionDate`/meta; stale `bitwarden_id` cleared when no remote counterpart; `None` folder id skips the pass and records an error; server passes honour `allow_remote_overwrite` with `skippedServerOverwrites/skippedServerNew` counters), `src-tauri/src/commands/mod.rs` (`bitwarden_sync` writes `sync.run`/`sync.error` audit rows; `bitwarden_get_config` returns `hasMasterPassword`; `bitwarden_test_connection(serverUrl?, email?, masterPassword?)` optional overrides), `src/renderer/app.js` (`bwSyncNow` shows errors/counters/remoteDeleted; confirm covers servers; `bwTest` saves first or passes overrides and names what was tested; `manualUpdateCheck` → in-app dialog "Update to vX - SSHSpan will close to install; N live session(s)" + busy + "closing…" notice; `confirm` sites 2410/3615), `src/renderer/index.html`/`styles.css` (Quit in vault menu is Task 6's helper — add the item via a `window.appQuit` hook: define `window.appQuit = () => call('app_quit')` here), `scripts/check-renderer-ui.js`, Rust tests in updater.rs/sync.rs

**Interfaces:**
- Produces: `app_quit()`; `window.appQuit()`; `update_check → {available, newerVersion?, …}`; `bitwarden_get_config → {…, hasMasterPassword}`; `bitwarden_sync` result gains `skippedServerOverwrites`, `skippedServerNew`.
- Consumes: `confirmModal`, `withBusy` (optional).

**Findings fixed:** A7-37 / A5-24 / R11, A6-09 / A7-47 / A8-23(b), A7-31, A6-05, A7-10, A7-42, A2-41, A5-22 (dialog + busy + notice; no progress bar), A7-23, A7-39, A2-51, A2-47, A2-08 / A7-24, A2-52, A5-35 (Bitwarden stored-password hint; reveal toggles on password inputs are Task 6's), A8-04 (audit rows now exist - docs stream updates text), A7-48 (`bitwarden_save_config` async with the DNS lookup in `spawn_blocking`), A8-16 (de-register `terminal_keepalive` with a doc comment), A6-10 is Stream E's.

- [ ] **Step 1:** RED — Rust: minisign verification rejects a signature whose trusted comment names another version (build a test vector with the repo's existing minisign test helper); `is_newer` + missing asset → `newerVersion` set; sync unit test for the folder-`None` skip and for meta write-back (mock client already used by existing tests? if none, test the pure decision helper you extract). Playwright: update available → dialog shown, `update_download_and_run` called only after OK; Bitwarden sync result with `errors:[…]` toasts a warning and shows the messages.
- [ ] **Step 2:** Implement.
- [ ] **Step 3:** Verification green.
- [ ] **Step 4:** Commit `fix(core): quit/exit teardown, updater binding and cleanup, Bitwarden sync reporting (…)`.

---

# Stream C - SFTP

Worktree `fix-C`, branch `fix/stream-c`. Owns: `src/renderer/sftp.js`, `src-tauri/src/commands/sftp.rs`, `src-tauri/src/sftp/*.rs`, CSS selectors `.sftp-*`, `.q-*`, `#sftpBody`, `.surface-splitter`; `src/renderer/index.html` only the SFTP dialogs (`#deleteModal`, `#chmodModal`, `#conflictModal`, lines ~870-960).

### Task 10: SFTP backend - transfers that finish correctly, safe walks, honest edit sync

**Files:**
- Modify: `src-tauri/src/sftp/queue.rs` (Upload leg: `ensure_remote_dir` before open; short-copy detection against expected size; resume via `AsyncSeekExt::seek`; `preserve_ts` applied after rename with `File::set_modified`; `restore_pending` keeps `server_id`; `cancel_for_session` wired or removed; collision guard per batch (case-folded local targets → rename `name (1)`)), `src-tauri/src/commands/sftp.rs` (`sftp_download` writes `.part` then renames; `expand_download` classifies from listing attrs, skips symlinks, depth cap 64, entry cap 10 000, per-child errors collected as warnings; `chmod_tree` skips symlinks, collects errors; `sftp_search(searchId)` + `sftp_search_cancel`, events carry `searchId`; edit watcher: generation counter coalescing, upload to `<remote>.sshspan-tmp` + rename, `shutdown().await`, success/failure event `sftp-edit-sync`, parent-dir watch accepting Create/Rename; local path deny-list += managed config dir, `~/.ssh`, Startup folder, shell rc files; `sftp_download` consumes `DialogPathStore`; `sftp_local_list`/`sftp_local_remove` async + `spawn_blocking`), `src-tauri/src/sftp/mod.rs` (staged names always end with an inert extension; drop `pub` from the inert list), `src-tauri/src/lib.rs` (handler list for `sftp_search_cancel`)
- Test: `#[cfg(test)]` modules + `src-tauri/tests/integration.rs` (the existing dev-sshd example may be used only if it runs headless in WSL; otherwise unit-test the pure helpers)

**Interfaces:**
- Produces: `sftp_search(sessionId, path, query, searchId)`; events `sftp-search` `{sessionId, searchId, …}`; `sftp_search_cancel(sessionId, searchId)`; queue jobs carry `serverId`; event `sftp-edit-sync {sessionId, remote, ok, error?}`; `sftp_queue_add` honours `preserveTs` for downloads.
- Consumes: nothing.

**Findings fixed:** A7-09, A7-18, A7-34, A7-35, A7-36, A7-06, A7-16 / A6-06, A7-20, A7-21, A7-19, A7-17, A7-57, A6-02 (partial: deny-list + dialog-bound `sftp_download`; document the remaining boundary), A6-14, A7-48 (SFTP commands), A8-16 (registered-but-uncalled SFTP commands: wire `sftp_queue_resume_all` to a "Resume all" queue action and `sftp_close_edit` to a "Stop editing" row action in Task 11; de-register `sftp_upload`, `sftp_stage_path`, `sftp_file_sha256`, `sftp_set_mtime` with a doc comment unless Task 11 gives them a caller), A7-49 is Stream E/B's.

- [ ] **Step 1:** RED — unit tests: `copy_with_progress` with an early-EOF reader returns `Err("incomplete transfer …")`; `staged_file_name("Makefile")` satisfies `path_has_inert_extension`; `sanitize_remote_name` collision set detection; a walk over a fake listing with a symlinked dir skips it and caps depth; `validate_sftp_local_path` rejects `~/.ssh/config` and the managed config dir.
- [ ] **Step 2:** Implement.
- [ ] **Step 3:** Rust verification green (incl. clippy correctness).
- [ ] **Step 4:** Commit `fix(sftp): remote mkdir on upload, short-copy detection, safe walks, search ids, edit sync (…)`.

### Task 11: SFTP renderer - queue, selection, navigation, layout

**Files:**
- Modify: `src/renderer/sftp.js` (all A3 findings; queue panel patch-in-place with `Map<jobId,rowEl>`; `sftpNavigate` transactional; selection cleared on path change and intersected with visible rows; `extraTaken` for Rename conflicts; focus restore only when focus was in the table; DnD/preserve-ts wiring after append; Ctrl+A/Ctrl+Y scoped to the file table; Upload… toolbar button (multi-file native picker: add `sftp_pick_local_files` if no picker exists, or reuse `system_pick_file_path` repeatedly) + empty-area context menu; conflict dialog defaults Skip + Cancel focused; context menus clamped with `positionCtxMenuAt`; `confirm` at ~3580 → `confirmModal`; search uses `searchId`; `sftp-edit-sync` toast; resumable check by `serverId`), `src/renderer/styles.css` (SFTP selectors: queue panel collapses to its header when empty, responsive queue grid with sticky `.q-act`, `flex-wrap` head, `.sftp-tdname` as table-cell with nested flex wrapper + nowrap, spinner/symlink/quick-find styles, single-percentage dual splitter + wired `.surface-splitter` drag, local pane without Permissions/Owner columns, `.sftp-pane` min-height, toolbar overflow menu below ~1000px), `src/renderer/index.html` (SFTP dialogs: `.toggle-chip` for "Don't prompt"), `scripts/check-renderer-ui.js`

**Interfaces:**
- Consumes: Task 10's `searchId`, `serverId`, `sftp-edit-sync`; `confirmModal`; `positionCtxMenuAt` (app.js, exists).

**Findings fixed:** A3-01, A3-02, A3-03, A3-04, A3-05, A3-06, A3-07, A3-09 (listing sequence counter), A3-12 (Queued tab never drops running jobs), A3-15, A3-16 (normalise `.`/`..`; Rust returns the canonical path if cheap), A3-17 (Windows local paths: drive roots, `Up` from `C:\x`), A3-18 (local listing errors keep the folder and toast), A3-19 (case-insensitive overwrite pre-check on Windows), A3-20 (chmod dialog state/special bits/prefill), A3-21 (renderer half: resumable by `serverId`), A3-22 (drops only when the Connect view is visible and no modal is open), A3-29 (separate suppression flags for remote vs local delete; label says which), A3-33 (Cancelled bucket), A3-34, A3-37 (background tabs refresh on activation), A5-46, A5-40, A5-47, A1-01, A1-02, A1-15, A1-16, A1-17, A1-25, A1-31, A1-33, A5-07, A1-04 (SFTP menus), A5-01 (sftp.js site). A3-23 (HTML5 DnD dead on Windows) is Task 16's; keep the existing HTML5 handlers working for Linux here.

- [ ] **Step 1:** RED — Playwright (stubbed queue events): with an empty queue, the "Done" tab click produces ≤1 `sftp_queue_list` call; a Cancel click delivered during 200 ms progress events reaches the handler (dispatch events while holding mousedown); a failed `sftp_list_dir` keeps `tab.sftpPath` on the old folder; hiding dotfiles prunes them from the selection; Ctrl+A in the rename prompt selects the text, not rows; Files mode at 1100x720 shows ≥5 visible rows with an empty queue; the queue grid at 1100px keeps `.q-act` inside the viewport.
- [ ] **Step 2:** Implement.
- [ ] **Step 3:** Renderer verification green.
- [ ] **Step 4:** Commit `fix(sftp): queue rendering, selection and navigation integrity, usable layout (…)`.

---

# Stream E - AI assistant and MCP

Worktree `fix-E`, branch `fix/stream-e`. Owns: `src/renderer/assistant.js`, `src/renderer/mcp.js`, `src-tauri/src/assistant/*.rs`, `src-tauri/tests/mcp_integration.rs`, `src/renderer/index.html` lines 230-254 (assistant panel), 353-477 (assistant settings), 505-541 (YOLO modal), CSS selectors `.ai-*`, `.assistant*`, `.mcp-*`, `.yolo*`, plus one additive rule for the term-max button while the panel is open; `src-tauri/src/lib.rs` only its `generate_handler!` entries.

### Task 12: Approval, typing and rug-pull guarantees

**Files:**
- Modify: `src/renderer/assistant.js` (`aiRunTool` MCP branch passes `approved`; card always at read/draft; `type_command`/Insert → `assistant_type_text` and refuse control chars; YOLO: Escape closes, missing modal fails closed, dialog names the server, `aria-describedby`; tool-event rows for every call incl. YOLO/auto-approve; `assistantClearTab` resets the level via `assistant_set_level('read')` and denies pending cards), `src/renderer/mcp.js` (`needsReapprove` from `t.definition_changed`; re-enable sends `auto_approve:false`; `confirm` at ~246 → `confirmModal`), `src-tauri/src/assistant/mod.rs` (`assistant_type_text(session_id, tab_id, text)`; provider client `redirect::Policy::none()` + plain `http://` only for loopback/RFC1918), `src-tauri/src/assistant/mcp.rs` (`merge_tools` clears `auto_approve` and sets `definition_changed`; `tool_view` emits it; `mcp_test_connection` returns `changed`; lock gates on `mcp_remove_server`/`mcp_set_tool_state`), `src-tauri/src/lib.rs` (handler), `scripts/check-mcp-contract.js` (assert the 4th argument at the call site), `src/renderer/index.html` (YOLO modal copy/aria)
- Test: `src-tauri/tests/mcp_integration.rs`, Playwright

**Interfaces:**
- Produces: `assistant_type_text(sessionId, tabId, text) → {ok}` (level ≥ draft; rejects `[\x00-\x08\x0a-\x1f\x7f]`; audits `assistant.type` with the first 200 chars); `tool_view.definition_changed: bool`; `mcp_test_connection → {…, changed: [names]}`.
- Consumes: `confirmModal`.

**Findings fixed:** A4-01 / A6-15, A4-02 / A6-01 / R7, A4-05 / A7-29 / A8-15 / R6, A4-10, A4-21, A4-17, A6-10, A6-08 (MCP commands), A4-04 (additive CSS rule keeps `#termMaxBtn` clear of Send while `.assistant-open`).

- [ ] **Step 1:** RED — Rust: `merge_tools` on a changed definition yields `enabled=false, auto_approve=false, definition_changed=true`; `assistant_type_text` with `"ls\n"` → Err; integration test that `mcp_call_tool` with `approved:true` at level read succeeds against the mock server. Playwright: Approve on the card → `mcp_call_tool` payload `approved:true`; `type_command` with `"echo hi\nid"` → result starts with `denied:`; YOLO modal closes on Escape; `elementFromPoint` at the Send button centre is the Send button with the panel open at 1100x720.
- [ ] **Step 2:** Implement.
- [ ] **Step 3:** Verification green.
- [ ] **Step 4:** Commit `fix(assistant): approval reaches the backend, typed text cannot press Enter, rug-pull visible (…)`.

### Task 13: Conversation state and per-tab lifecycle

**Files:**
- Modify: `src/renderer/assistant.js` (history repair: a `tool` result for every `tool_calls` id on stop/cap/error; no assistant message with neither text nor calls; `args` guard; per-tab busy state (`aiSetThinking` only touches DOM for the active tab; `assistantOnTabSwitch` restores); `assistantClearTab` removes `listEl`, denies cards, resets busy; late replies for a cleared tab are dropped; history cap: per-result 64 KiB with a truncation marker + keep the last 40 messages; "New chat" button; markdown fixes (fence language line, `<ol>`, `*` delimiters); `assistantOpenSettings` wired from the not-configured error and a setup card on first open; Run button re-enabled on error; empty-command Run ignored; `type_command` awaits the send; provider error JSON → message; input restored on failure; errors shown once; `max_completion_tokens` for api.openai.com), `src-tauri/src/assistant/mod.rs` (`openai_body`/`anthropic_body` drop empty assistant messages; `max_completion_tokens` when the base URL host is `api.openai.com`; `connect_server` re-reads the record before merging (A7-49 is in mcp.rs - do it there)), `src/renderer/index.html` (panel: New chat button, `role="log" aria-live`, textarea `aria-label`, `role="status"` on thinking)
- Test: Playwright, Rust unit tests for body shaping

**Interfaces:**
- Produces: `window.assistantClearTab(tabId)` (idempotent; safe to call for unknown tabs) — Stream A calls it from `clearConnectView`, Stream B from `closeSessionTab` (both are additive one-liners; if not yet present when you merge, add them in your own report as a follow-up for the controller).

**Findings fixed:** A4-03, A4-06, A4-09, A4-19, A4-16, A7-44, A4-18, A4-20, A4-25, A4-26, A5-36, A4-24 (panel part), A7-49.

- [ ] **Step 1:** RED — Playwright: Stop during a `tool_calls` reply leaves every call id answered in the next request; two tabs: a turn in A does not disable B's input; closing a tab with a pending card re-enables the input; a 1.5 MB tool result is stored truncated with the marker. Rust: `openai_body` omits `{content:null, tool_calls:null}` messages; `max_completion_tokens` chosen for `https://api.openai.com/v1`.
- [ ] **Step 2:** Implement.
- [ ] **Step 3:** Verification green.
- [ ] **Step 4:** Commit `fix(assistant): repair conversation history, per-tab state, bounded context (…)`.

### Task 14: MCP and provider settings round-trip

**Files:**
- Modify: `src-tauri/src/assistant/mcp.rs` (`mcp_list_servers` adds `auth_header_name`, `auth_env_var`, `has_secret`, `protocol_version`; `mcp_save_server` keeps `auth_env_var` when the arg is absent, rejects duplicate sanitized names, refuses bearer/custom-header servers with no auth source; `build_name_map` keyed by server id; `mcp_remove_server` best-effort teardown with a 5 s timeout then always deletes; SSE incremental parse returning on the matching id (if the existing tests make this safe — otherwise document as deferred)), `src/renderer/mcp.js` (prefill from the new fields; warn when URL/auth change discards the secret; `exposed_name` used; busy/disabled on Save/Test/Remove; `mcpLoadSettings` → `mcpRenderTools`; "enabled/total" count; unconfirmed badge "review and re-save before connecting"; Test failure refreshes the row with the stored error; "Review tools" row action; loopback check mirrors Rust (`localhost|::1|127.*`) and queries preserved or rejected explicitly; URL placeholder `https://mcp.example.com/mcp`), `src/renderer/assistant.js` (provider presets set provider+URL+placeholder; Test uses the visible form via a `assistant_test_connection(provider?, baseUrl?, model?, apiKey?)` override or saves first - choose "saves first" and label the button "Save & test"; "Remove stored key" → `clearApiKey:true`; origin change requires a new key or an explicit confirm; `#aiStatus` written; dirty-form guard on reload), `src-tauri/src/assistant/mod.rs` (`assistant_save_config` origin-change handling), `src/renderer/index.html` (settings section: `[OI]` → `OpenAI` (R8), model placeholder, Remove-key button, separate label for the preset select, `role="alert"` on URL error, status dot text label), `scripts/check-renderer-ui.js`

**Interfaces:**
- Produces: `mcp_list_servers` rows `{…, auth_header_name, auth_env_var, has_secret, protocol_version}`; `assistant_save_config(…, clearApiKey?)` honoured by the UI.

**Findings fixed:** A4-07 / A7-30, A4-08, A4-11 / A8-20, A4-12, A4-13 / A7-33 / A8-13, A4-14, A4-15, A4-22 / A8-10 / A1-39 / A5-29 (assistant part), A4-23, A4-24 (settings part), A4-27 / A7-51, A7-50 (if safe), A8-27 (protocol version shown; "Fix auth" affordance = the inline warning).

- [ ] **Step 1:** RED — Rust: `mcp_save_server` with absent `auth_env_var` keeps the stored binding; duplicate name rejected; `mcp_remove_server` against an unreachable origin deletes the record within the timeout. Playwright: editing an env-var server and saving posts the same `auth_env_var`; Ollama preset sets provider `openai` + URL; "Remove stored key" posts `clearApiKey:true`; double-click Save posts once; tool name longer than 64 chars uses `exposed_name`.
- [ ] **Step 2:** Implement.
- [ ] **Step 3:** Verification green.
- [ ] **Step 4:** Commit `fix(mcp): settings round-trip, busy states, exposed names, provider name (…)`.

---

# Stream D - docs, CI and the audit record (runs on the merged branch)

### Task 15: Documentation, CI and changelog reflect the code

**Files:**
- Modify: `README.md`, `CHANGELOG.md` (`[Unreleased]` → `## [1.9.2] - 2026-10-09` with Added/Fixed/Security/Docs sections listing every fix by finding ID), `docs/ARCHITECTURE.md` (regenerate the IPC table from `lib.rs`; renderer file list; Argon2id; DevTools; views; schema), `docs/SECURITY.md`, `docs/PRIVACY.md` (AI provider + MCP destinations; version pin removed; correct paths; audit events that exist; KDF clamping; http policy; SFTP path boundary; dialog claims), `docs/MCP-SMOKE-TEST.md` (steps 4/13/18/20 vs the fixed UI; `scripts/mcp-smoke-server.py` image block), `CONTRIBUTING.md` (Node version, clippy gate, naming conventions, WSL note for Windows developers), `.github/workflows/ci.yml` (add a `windows-latest` Rust job running `cargo test`; renderer job unchanged), delete `scripts/refactor_tabs.py`, `scripts/cdp-fileops.js` (and either fix or delete `scripts/cdp-e2e-2.js`, `scripts/cdp-featurepass.js`), `src/renderer/vendor/VENDOR.md` only if touched, `docs/audit/2026-10-09/README.md` (index: every finding ID → status Fixed-in-commit / Deferred (reason) / Not-a-flaw (reason)).

**Findings fixed:** A8-04, A8-05, A8-06, A8-07, A8-08, A8-09, A8-19, A8-21, A8-22, A8-23 (remaining comment items), A8-27, A8-28, A6-07, A7-58, A7-56 (CI matrix), A8-12 (SECURITY/PRIVACY claim corrected unless Stream A exposed the passphrase for OpenSSH/PPK exports - check the merged code), A8-13/A8-16 copy, R9 docs, R10 deferred list.

- [ ] **Step 1:** Read the merged code for every claim before writing it (the audit's A8 file lists the exact claim/code pairs).
- [ ] **Step 2:** Write the docs; generate the finding index by scanning `git log` bodies for IDs.
- [ ] **Step 3:** `node scripts/check-renderer-globals.js`, `npm run test:ui`, Rust verification still green; CI YAML validated with `node -e "require('js-yaml')"`-free check: just `python -c "import yaml,sys;yaml.safe_load(open('.github/workflows/ci.yml'))"` if python is available, else careful review.
- [ ] **Step 4:** Commit `docs: v1.9.2 flaw remediation - truthful docs, audit index, Windows CI`.

### Task 16: In-page drag and drop that works on Windows

**Files:**
- Modify: `src/renderer/sftp.js` (pane-to-pane transfer/move drag: replace the HTML5 `dragstart/dragover/drop` wiring with pointer events — `pointerdown` on a row + movement threshold starts a drag, a ghost element follows the pointer, `pointerup` over a folder row / the other pane resolves the target; Escape cancels; keep the OS-file drop path on Tauri's `onDragDropEvent`), `src/renderer/app.js` (category tree `attachCatDnD`: same pointer-based approach with the before/into/after zones computed from the pointer Y), `src/renderer/styles.css` (drag ghost + drop-target styles), `scripts/check-renderer-ui.js`
- Test: Playwright pointer sequences (`page.mouse.down/move/up`) for a remote→folder move and a category re-parent

**Interfaces:** none new.

**Findings fixed:** A3-23 (HTML5 DnD is dead on Windows while `dragDropEnabled` is true, and OS-file drops need it true — so in-page DnD moves to pointer events), A2-07 (its zone logic, already fixed in Task 3, moves into the pointer handler).

- [ ] **Step 1:** RED — Playwright: dragging row `a.txt` onto folder `dir/` with pointer events posts `sftp_rename`/move with `dir/a.txt`; dragging category `C` onto `A` posts `newParentId: A`; Escape mid-drag posts nothing.
- [ ] **Step 2:** Implement; delete the HTML5 handlers it replaces.
- [ ] **Step 3:** Renderer verification green.
- [ ] **Step 4:** `fix(ui): pointer-based drag and drop for SFTP panes and categories (A3-23 A2-07)`.
