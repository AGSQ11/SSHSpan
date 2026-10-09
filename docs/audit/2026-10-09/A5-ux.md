# A5 - UX / ease-of-use audit

1. **Counts:** 47 findings - Critical 1, High 8, Medium 24, Low 14 (IDs are unique; the file is ordered by severity, so A5-37/38 sit with the Highs, A5-39/40/42/45/46 with the Mediums and A5-41/43/44/47 with the Lows).
2. **Covered:** first run / vault create-unlock-lock / wrong password / auto-lock; keys (generate every type, import, export, rename, delete, search, detail, bulk, categories tree/picker); servers (add/edit/delete, connect incl. password prompt and failures, Test, tabs, Files/Split, 880x560 / 1100x720 / 1600x1000 layouts); Deploy sheet; all seven Settings sections (masked fields, audit log, known hosts, backup/restore, Bitwarden, AI assistant, MCP form); command palette; updater; global keyboard/focus/Escape stacking, toasts, loading states, terminology, empty states; a reject pass (IPC failures on every view).
3. **Not covered / limits:** run in headless Chromium against a stateful fake `invoke` (`scratch/A5/fake-backend.js`), not WebView2/WebKitGTK; no cargo, so backend timings (Argon2id, RSA keygen) and the exact Rust results of ECDSA/encrypted-export/import calls are established by reading, not running; no live Bitwarden, MCP or real SSH/SFTP (transfer queue, drag-drop and SFTP logic belong to A3); no screen-reader pass; Linux tray behaviour inferred.
4. **Method:** read app.js / sftp.js / terminal.js / assistant.js / mcp.js / index.html / styles.css plus the Rust handler behind every journey, then drove the real page with Playwright (success pass, slow-IPC pass, reject pass). Drivers `t*.js`, harness and screenshots are in `.superpowers/audit/scratch/A5/`.
5. **Quick wins (outsized ease-of-use payoff):** (a) replace every native `confirm()` with the existing `confirmModal` (A5-01); (b) focus the connect password field after the terminal's focus timer and add it to the Escape chain (A5-02); (c) keep the saved password when editing a server and say so in the dialog (A5-03); (d) collapse the empty Transfers panel and fold the SFTP toolbar so Files shows files at 1100x720 (A5-07); (e) three one-line fixes: ECDSA curve values `p256/p384/p521` (A5-37), refuse an empty passphrase for "PKCS#8 encrypted" (A5-38), default auto-lock to 15 when unset (A5-06).

---

## A5-01: Every `confirm()` guard in the app is silently bypassed - tauri-plugin-dialog replaces `window.confirm` with an async stub
- **Severity:** Critical
- **Category:** ux
- **Location:** `src-tauri/src/lib.rs:45` (`.plugin(tauri_plugin_dialog::init())`); `src-tauri/capabilities/default.json` (no `dialog:*` permission); call sites `src/renderer/app.js:588, 1696, 1725, 2179, 2410, 2884, 2957, 3615, 3810, 4299`, `terminal.js:667`, `sftp.js:3580`, `mcp.js:246`
- **Evidence:** `tauri-plugin-dialog` 2.7.3 (`Cargo.lock:6564`) calls `builder.js_init_script(include_str!("init-iife.js"))` (`src/lib.rs:200`); Tauri 2.11.5 prepends every plugin init script to each webview's main frame (`manager/webview.rs:131-202`). That script is `window.alert=function(i){n("plugin:dialog|message",..)}, window.confirm=async function(i){return await n("plugin:dialog|confirm",{message:i.toString()})}` - an `async` function, so `confirm(...)` returns a Promise (always truthy) and `if (!confirm(...)) return;` can never return. The app's ACL deliberately grants no dialog permission ("the dialog grants were removed...", `capabilities/default.json`), and 2.7.x no longer has a `confirm` command (`build.rs: COMMANDS = ["open","save","message"]`), so the invoke rejects: no dialog is ever drawn. Reproduced in the real renderer (`scratch/A5/t1-confirm.js`): with a plain browser `confirm()` and the user answering Cancel, `key_delete`/`server_delete`/`known_hosts_forget`/`vault_backup_restore` are never called; with the plugin's exact init script injected (and `__TAURI_INTERNALS__.invoke` rejecting as the ACL would), the key is deleted, the bulk selection is deleted, the server is deleted, the pinned host key is forgotten and the backup restore runs - with no dialog and the only trace an unhandled rejection (`ialog|confirm not allowed by ACL`).
- **Why it is a flaw:** the user-visible safety net for permanent actions does not exist at runtime. One mis-click on the trash icon beside "Rename" permanently deletes a private key (the Settings toggle "Confirm before deleting a key" is a no-op, and there is no undo); the selection-bar "Delete" removes every ticked key, including ones hidden by the current search filter; "Restore from backup" overwrites entries on click; "Forget host" drops a TOFU pin; closing a live session tab (x) kills the shell; a multi-line paste executes without the review prompt; MCP server removal proceeds unasked; Bitwarden's "Remote changes need your approval ... Apply them now?" is auto-approved, so remote versions overwrite local keys with no consent (app.js:2410-2411); and "Settings > Check now" with an update available is auto-approved too, so it downloads and launches the installer and the app exits ~2.5 s later with live sessions and transfers (app.js:3615-3622). The authors' own copy ("Confirm before deleting a key", "Review clipboard content before running commands") promises protection the build does not give.
- **Proposed fix:** stop using the native `confirm`. `confirmModal(title, message, okLabel)` already exists (app.js:923, promise-based, Escape-aware) - replace each `if (!confirm(x)) return;` with `if (!(await confirmModal(title, x, 'Delete'))) return;` (every call site is already inside an `async` function except `closeSessionTab`, which needs to become `async`). Alternatively drop the dialog plugin's JS shim, but the in-app modal is the better UX in any case.
- **Confidence:** confirmed (plugin source + Tauri injection path read; behaviour reproduced in the renderer with the shipped init script). Not run inside a real WebView2/WebKitGTK window.
- **Effort:** M

## A5-02: The connect password prompt never receives keyboard focus - typed passwords vanish and Escape is dead
- **Severity:** High
- **Category:** ux
- **Location:** `src/renderer/app.js:3646-3655` (askConnectPassword), `app.js:4183-4190` (openSessionTab), `src/renderer/terminal.js:390-402` (showTabTerminal), `terminal.js:541-543`, `app.js:3541-3544`, `app.js:3401-3417`
- **Evidence:** `openSessionTab` calls `activateSessionSurface(tabId)` (-> `showTabTerminal`, which schedules `rec.term.focus()` at +60 ms, terminal.js:397-400) and then `askConnectPassword`, which schedules `inp.focus()` at +50 ms (app.js:3653). The terminal's later timer wins. Reproduced in Chromium (`scratch/A5/t5b-pwprompt.js`) for all three entry paths (click Connect, double-click row, Enter on row): after the modal opens `document.activeElement` is `xterm-helper-textarea`; typing `hunter2-secret` leaves `#connectPwInput` empty (keystrokes are dropped by `if (!rec.sessionId) return;`, terminal.js:542); Enter does nothing; Escape does nothing because the Escape handler is bound only to the input (app.js:3541-3544) and `connectPwModal` is absent from the global Escape chain (app.js:3402-3417). The only recovery is clicking into the field.
- **Why it is a flaw:** every connect to a password / keyboard-interactive server without a saved password (the normal case for legacy hosts) starts with a prompt that looks ready but swallows the password; keyboard-only users cannot complete or cancel it at all, and the failure is silent (no caret, no error).
- **Proposed fix:** have `showTabTerminal` skip its deferred `term.focus()` while `modalStack.length > 0` (or call `inp.focus()` from a `setTimeout(..., 120)` after it), and add `closeConnectPwModal(null)` to the document Escape handler.
- **Confidence:** confirmed (reproduced; the timers are plain JS so WebView2 behaves the same)
- **Effort:** S

## A5-03: Editing a password server silently deletes its saved password
- **Severity:** High
- **Category:** ux
- **Location:** `src/renderer/app.js:3856-3857` (openServerModal resets `srvPassword`/`srvSavePw`), `app.js:3909` (submitServerModal), `src-tauri/src/commands/server.rs:108-114, 139`, `src-tauri/src/db/mod.rs:1655, 1661`
- **Evidence:** opening Edit sets `srvPassword.value = ''` and `srvSavePw.checked = false` regardless of whether the server has a stored password; Save sends `savedPassword: (method !== 'publickey' && srvSavePw.checked) ? srvPassword.value : null` (app.js:3909). `server_save` computes `saved_sealed = None` for a null/empty password and assigns `existing.saved_password = saved_sealed` (server.rs:139); `update_server` writes that column unconditionally (`saved_password = ?`, db/mod.rs:1655/1661). Reproduced against the fake backend that mirrors this: Edit of a host with `hasSavedPassword: true` shows an empty password box and an OFF "Save password" toggle (`scratch/A5/server-edit-saved-password.png`), and Save sends `savedPassword: null`, after which the saved password is gone. The field label even reads "Password (optional, only used at connect time)".
- **Why it is a flaw:** renaming a server, changing its port or moving it to a category - any edit - silently destroys the credential the user asked the vault to remember. The next connect just prompts for the password; for a long random password the user may not have it anywhere else. Nothing in the dialog says a password is stored or that leaving the field blank removes it.
- **Proposed fix:** when the server has a saved password, show "A password is saved - leave blank to keep it" and a separate "Remove saved password" control; send an explicit `clearSavedPassword` flag and make `server_save` keep the existing `saved_password` when the new value is absent and the flag is false.
- **Confidence:** confirmed (code path read end to end; renderer half reproduced)
- **Effort:** S

## A5-04: The Deploy sheet's "What this will write" preview is not what `key_deploy` writes (alias/HostName/User/Port are ignored, markers do not exist)
- **Severity:** High
- **Category:** ux
- **Location:** `src/renderer/app.js:2140-2168` (previewConfig), `app.js:2170-2239` (deployConfig, esp. 2192 and 2198-2210), `src-tauri/src/commands/mod.rs:2035-2075`, `src-tauri/src/ssh/mod.rs:120-183`, `src-tauri/src/config/mod.rs:113-162`, `src/renderer/index.html:666, 711-715`
- **Evidence:** the preview renders `Host <alias> / HostName <alias> / User <user> / Port <port>` between `# >>> SSHSpan managed >>>` markers from the Host alias / User / Port fields. `deployConfig` calls `key_deploy` with `{ ids, passphrase, strictHostKey }` only (app.js:2192); `key_deploy` passes `Some(&key.name), None, None, None` as alias/hostname/user/port to `SshService::deploy_key` (commands/mod.rs:2066-2075), and `to_config_string` emits no marker lines (config/mod.rs:113-162). Reproduced (`scratch/A5/t9-deploy.js`): after typing `web01.prod` / `deploy` / `2222` the preview shows `Host web01.prod ... User deploy ... Port 2222`, but the recorded IPC call is `{"ids":["k1"],"strictHostKey":true}`; the real block is `Host prod-web` + `IdentityFile` + `IdentitiesOnly` only, with no HostName at all (so `ssh prod-web` would resolve the key name as a hostname). Even the IdentityFile line can differ: the preview uses the renderer's `safeFileName` (keeps dots, app.js:226-228) while the file is written with Rust's `sanitize_filename` (dots become `_`, ssh/mod.rs:279-289), so a key named `prod.web` previews `~/.ssh/sshspan_prod.web` but is written as `sshspan_prod_web`. With "Also save these as servers" ticked the alias is stored as the server's *hostname* (app.js:2217) - there is no separate HostName field - and the "Host alias and User required" check runs only after the keys were written and the sheet closed (app.js:2198-2210), so the user must reselect the keys and deploy again.
- **Why it is a flaw:** the sheet's central promise (live, accurate preview of what will be written) is false, three of its four inputs do nothing for the SSH config, and a user who relies on the preview ends up with a config entry that cannot reach the host.
- **Proposed fix:** pass `hostAlias`, `hostname`, `user`, `port` through `key_deploy` (the Rust function already accepts them) and add a distinct HostName field; or drop the fields and render the preview from a backend dry-run so it cannot drift. Remove the marker text unless markers are actually written. Validate alias/user before writing anything.
- **Confidence:** confirmed
- **Effort:** M

## A5-05: Every "~/.ssh/config" claim points at a private app file: the Config import reads the wrong file and Deploy's output is never seen by `ssh`
- **Severity:** High
- **Category:** ux
- **Location:** `src/renderer/index.html:188, 666`, `src/renderer/app.js:2242-2247`, `src-tauri/src/commands/mod.rs:2437-2441`, `src-tauri/src/config/mod.rs:259-267`, `src-tauri/src/ssh/mod.rs:109-185`, `README.md:13`
- **Evidence:** the server-list button is titled "Import a Host block from ~/.ssh/config". `ssh_config_list_hosts` uses `SshConfigService::new()`, whose path is `ProjectDirs("org","sshspan","SSHSpan").config_dir()/ssh/config` (on Windows `%APPDATA%\sshspan\SSHSpan\config\ssh\config`); `~/.ssh/config` is used only if ProjectDirs fails. Deploy writes its Host blocks to that same private file. OpenSSH reads it only if the user adds an `Include` line to `~/.ssh/config`; no UI text or doc says so (no `Include` anywhere in the repo). The deploy sheet subtitle says "adds a matching Host block to your SSH config" and README.md:13 says "keys into `~/.ssh/config`". The toast on an empty result does print the real path ("No Host blocks found in C:\Users\...\AppData\Roaming\sshspan\SSHSpan\config\ssh\config.", app.js:2246), which is how the mismatch surfaces.
- **Why it is a flaw:** a sysadmin with 20 hosts already in `~/.ssh/config` clicks "Config" to import them and always gets an empty list - the main onboarding path for existing servers does not exist. After "Deploy" the keys sit in `~/.ssh` but `ssh`, `scp`, `git` and Ansible never learn about the Host block, and nothing tells the user to wire it up.
- **Proposed fix:** make `ssh_config_list_hosts` parse the user's real `~/.ssh/config` (read-only, following `Include`) and keep the label; for Deploy either write the managed block into `~/.ssh/config` between markers (what the copy says) or show a one-time "Add `Include <path>` to ~/.ssh/config" step with a Copy button.
- **Confidence:** confirmed (code reading; behaviour not exercised against a real config dir)
- **Effort:** M

## A5-06: Fresh installs show "Lock the vault when idle: 15" but auto-lock is off (sidebar says so), contradicting README and Rust
- **Severity:** High
- **Category:** ux
- **Location:** `src/renderer/app.js:2510, 3566-3570, 3603-3607`, `src-tauri/src/commands/mod.rs:433-447`, `README.md:15`
- **Evidence:** `settings_get` returns only rows that exist, so on a fresh install `state.settings.autoLockMinutes` is undefined. `resetAutoLockTimer` does `parseInt(undefined) -> NaN -> !mins -> no timer` (app.js:3568-3569), while the Settings row renders `state.settings.autoLockMinutes || 15` (app.js:2510) and README.md:15 promises "auto-locks after 15 minutes". The Rust watchdog treats an absent value as 15 (`unwrap_or(15)`, mod.rs:447) although its own doc comment says "0/absent disables it" (mod.rs:433-434), and it measures renderer *heartbeats* (sent every 30 s regardless of user activity, app.js:3603-3607), so it never fires while the page is alive. Reproduced (`scratch/A5/t2-autolock.js`, case B): sidebar `auto-lock off`, Settings field `15`; the vault never locks. Only after the user edits the field does the countdown start (case C).
- **Why it is a flaw:** the user sees "15" in Settings and the docs say 15, so they believe the vault re-seals itself; in reality it stays unlocked indefinitely (and with close-to-tray, A5-24, even when the window is hidden). That is a false sense of security on a key manager.
- **Proposed fix:** treat an undefined setting as 15 in `resetAutoLockTimer` (distinguish explicit `0`), or write the default row on first run; make the Rust comment and default agree.
- **Confidence:** confirmed
- **Effort:** S

## A5-07: The Files (SFTP) view is unusable at the default and minimum window sizes: 37 px (default) / 0 px (880x560) left for the file list
- **Severity:** High
- **Category:** ui
- **Location:** `src/renderer/styles.css:1525-1527` (toolbar wraps), `styles.css:1572` (`.sftp-tablewrap`), `styles.css:1660-1666` (`.sftp-queuepanel { flex:none; height:220px; min-height:120px }`), `src/renderer/sftp.js:2982-3011` (resizable handle)
- **Evidence:** measured in Chromium with a 30-entry listing (`scratch/A5/t17-sftp-height.js`): 1100x720 (the shipped default) -> file-list wrapper `h=37`, 0 fully visible rows (`sftp-height-1100x720.png`: only the column header is visible while the status bar says "30 items"); 880x560 (the shipped minimum) -> `h=0`; even dragging the Transfers panel to its 120 px minimum cannot help there (300 px surface - 108 px toolbar - path/status chrome - 120 px queue < 0). At 1600x1000 it is 355 px (9 rows) with half the pane an empty Transfers table. Causes: 12 labelled toolbar buttons wrap to three rows (108 px) and the transfer queue is a fixed 220 px even when empty. Secondary at 880 px: the terminal header clips the Disconnect button (`.terminal-head` scrollWidth > clientWidth; "x Disc" cut off in `min-servers-session.png`).
- **Why it is a flaw:** the first thing a user sees after clicking Files is an apparently empty directory; the file list is the whole point of the mode. Nothing hints that the Transfers handle can be dragged.
- **Proposed fix:** collapse the transfers panel to its header bar while the queue is empty (expand on first job), cap the default at ~25% of the surface, and fold secondary toolbar buttons (Compare, Sync browse, Columns, Log, Dual) into a "..." overflow or icon-only buttons below ~1000 px.
- **Confidence:** confirmed (Chromium stand-in; layout is plain CSS flex so WebView2/WebKitGTK should match; this likely overlaps A1)
- **Effort:** M

## A5-37: Generating an ECDSA key always fails: the dialog sends `ecdsa-nistp256/384/521`, the backend only knows `ecdsa-p256/p384/p521`
- **Severity:** High
- **Category:** ipc
- **Location:** `src/renderer/index.html:574-580`, `src/renderer/app.js:2073-2078`, `src-tauri/src/crypto/keys.rs:63-82`, `src-tauri/src/commands/mod.rs:2354`, `README.md:140`
- **Evidence:** the Curve select's values are `nistp256` / `nistp384` / `nistp521` and `submitKeyModal` builds `keyType: 'ecdsa-' + curve`. `key_create_with_categories` begins with `KeyType::from_db_tag(&key_type)?`, whose accepted strings are `rsa`, `ed25519`, `ecdsa`, `ecdsa-p256`, `ecdsa-p384`, `ecdsa-p521`; anything else bails with "Unknown key type: ...". Captured at the IPC boundary (`scratch/A5/t20-export-ecdsa.js`): the three curves send `ecdsa-nistp256`, `ecdsa-nistp384`, `ecdsa-nistp521`. `scripts/check-ipc-args.js` compares argument names only, and the Rust tests build `KeyType` directly, so nothing exercises this string. (The Rust call itself was not run - cargo is off-limits - the accept-list is exhaustive.)
- **Why it is a flaw:** ECDSA is one of the three advertised key types (README "ECDSA (nistp256/384/521)") and every attempt ends in an "Unknown key type: ecdsa-nistp256" toast with the dialog left open, which reads as "the generator is broken".
- **Proposed fix:** make the select values `p256`/`p384`/`p521` (matching the `|| 'p256'` fallback already in the code) or accept the `nistp*` spellings in `from_db_tag`; add a test that feeds every UI key-type string through `key_create_with_categories`.
- **Confidence:** confirmed (renderer payload reproduced; backend accept-list read)
- **Effort:** S

## A5-38: Exporting "PKCS#8 PEM, encrypted" with an empty passphrase silently writes an UNENCRYPTED private key and reports "Exported pkcs8-encrypted"
- **Severity:** High
- **Category:** ux
- **Location:** `src/renderer/app.js:1780-1784, 1817-1831, 1846-1868`, `src/renderer/index.html:171-172`, `src-tauri/src/commands/mod.rs:1928-1941`, `src-tauri/src/crypto/keys.rs:389-399`
- **Evidence:** the format row reads "PKCS#8 PEM, encrypted - Wrapped with a passphrase you choose below" with a "Sealed" risk chip; the passphrase box only has the placeholder "Required for an encrypted export" and `exportSelected` never checks it. Reproduced (`t20-export-ecdsa.js`, `export-pkcs8-encrypted.png`): choosing it and pressing "Choose where to save..." with the box empty calls `key_export_to_file` with `{"format":"pkcs8-encrypted","passphrase":""}` and the toast says "Exported pkcs8-encrypted to ...". On the Rust side `key_export_to_file` filters an empty passphrase to `None` (mod.rs:1928) and treats `pkcs8-encrypted` exactly like `pkcs8` (mod.rs:1934-1936); `export_pkcs8_private` then emits a plain `-----BEGIN PRIVATE KEY-----` when there is no passphrase (keys.rs:394-398).
- **Why it is a flaw:** the user asked for an encrypted copy, is told it was exported as encrypted, and gets a plaintext private key file (0600/ACL-protected, but exactly what the "Sealed" chip said it would not be) - a silent security downgrade on the app's most sensitive action.
- **Proposed fix:** require (and confirm) a non-empty passphrase when the format is `pkcs8-encrypted` (keep the button disabled until typed) and make `key_export_to_file` reject `pkcs8-encrypted` with no passphrase; label the toast with what was actually written.
- **Confidence:** confirmed (renderer reproduced; backend path read)
- **Effort:** S

## A5-08: Cancelling the Unlock / Create-vault dialog is pointless: it pops back up by itself within 10 s, resets the fields and steals focus
- **Severity:** Medium
- **Category:** ux
- **Location:** `src/renderer/app.js:4545-4548` (10 s poll), `app.js:1065-1096` (refreshVaultStatus), `app.js:1021-1061` (showVaultModal), `app.js:3164-3167` (Cancel handler)
- **Evidence:** the poll calls `refreshVaultStatus(true)` every 10 s; while `!s.unlocked` it unconditionally calls `showVaultModal('unlock')` (or `'create'`), and because the backdrop is hidden after Cancel, `reopening` is true, so the password fields are cleared and `pw.focus()` runs. Reproduced twice (`t4-vault.js` create mode, `t14-misc.js` unlock mode): after Cancel the modal re-appears after ~9 s with no user action, even while the user is reading Settings, and the same loop wipes a half-typed "Change master password" dialog (mode switches back to unlock). The Cancel toast promises "Vault stays locked - unlock it any time."
- **Why it is a flaw:** the app advertises that Settings, Backup and the palette work while locked, but every 10 s a modal covers the window and takes keyboard focus; Cancel looks like it works and does not.
- **Proposed fix:** remember the dismissal (`state.vaultPromptDismissed = true` on Cancel) and only auto-show the dialog on a transition into the locked state or when the user triggers an unlock (nav click, palette, Ctrl+N); never switch a dialog the user is in (`mode === 'change'`) to another mode from the poll.
- **Confidence:** confirmed
- **Effort:** S

## A5-09: Locking (button, Ctrl+L, tray, idle timer) silently kills every live SSH session and discards terminal scrollback; neither the confirm nor the Settings copy says so
- **Severity:** Medium
- **Category:** ux
- **Location:** `src/renderer/app.js:3552-3558, 3572-3578, 3447, 1179-1215`, `src/renderer/index.html:290`, `app.js:2519-2520`, `src-tauri/src/commands/mod.rs:378-404`
- **Evidence:** `lockNow()` has no confirmation; `lock_vault_internal` runs `SessionRegistry::kill_all()`, stops SFTP/edit watchers and pauses the transfer queue (mod.rs:384-394); `clearConnectView()` then disposes every xterm instance (app.js:1194-1203), so the scrollback is gone. Reproduced (`t3-terminal-keys.js`): with one live session, Ctrl+L outside the terminal -> 0 dialogs, IPC `vault_lock, vault_status, terminal_disconnect`, 0 sessions, 0 tabs, and a lone toast "Vault locked." The idle timer resets only on keydown/mousedown/wheel/touchstart (app.js:3537-3540), so a shell that is busy running a long build, restore or `tail -f` with nobody typing counts as idle. The Settings help text only says "Minutes of inactivity before the vault seals itself".
- **Why it is a flaw:** a sysadmin who leaves a 20-minute job running, or who presses Ctrl+L out of terminal habit while focus is on the page, loses every session and its on-screen output with no warning; after an idle lock the user returns to an unlock prompt and no explanation of what happened to their tabs.
- **Proposed fix:** if any session/transfer is live, confirm manual locks ("Locking closes 3 sessions and pauses 2 transfers"), show a 60 s "locking soon - move the mouse to stay unlocked" toast before the idle lock, count terminal output / active transfers as activity (or add a "keep unlocked while sessions are live" option), and state the consequence in the Settings description.
- **Confidence:** confirmed
- **Effort:** M

## A5-10: Connecting gives no progress, shows the wrong status ("Ready."), cannot be cancelled, and closing the tab mid-connect leaves a hidden live session
- **Severity:** Medium
- **Category:** ux
- **Location:** `src/renderer/app.js:3117-3123, 4162-4211, 4295-4325`, `src/renderer/terminal.js:405-418, 479-609`, `src-tauri/src/ssh_client/mod.rs:559-578`
- **Evidence:** `openSessionTab` sets "Connecting to host:port..." (app.js:4186) but also fires `switchView('connect')` un-awaited; its `await loadServers()` then writes `'Ready. (build v14-tabs)'` into the same status strip (app.js:3122), overwriting it. With a 4 s artificial connect (`t5-connect.js`): at 1.5 s the strip reads "Ready. (build v14-tabs)", Disconnect and Reconnect are both hidden (app.js:4184-4185), no spinner exists anywhere, and the terminal shows only the grey "xterm ready ... connecting" trace. There is no connect timeout in the Rust path (`client::connect(...)` and `authenticate(...)` are awaited bare; only keepalive is configured, ssh_client/mod.rs:398-408), so a black-holed host waits out the OS TCP timeout. Closing the tab (x) during that wait runs `closeSessionTab`: not live, so no confirm and no `terminal_disconnect`; `destroyTabTerminal` drops the record; when the backend finally connects, `terminalConnectInTab` still assigns `rec.sessionId`, starts a 1.2 s `terminal_list` poll that is never cleared, and `openSessionTab` writes "Connected to ... - streaming" to the status strip. Reproduced: backend sessions = 1, UI tabs = 0, `terminal_disconnect` calls = 0, nav live-count = 0.
- **Why it is a flaw:** the user cannot tell whether the app is working, hung or idle, has no way to abort, and a session opened after they gave up stays alive on the server (invisible, uncloseable until lock/quit) - which for a production host is exactly what a sysadmin does not want.
- **Proposed fix:** set the strip/title to "Connecting..." and show Cancel (and a spinner) while `tab.connecting`; add a `tokio::time::timeout` (e.g. 15 s connect, 30 s auth) with a clear message; on cancel/close mid-connect mark the tab cancelled so a late `sessionId` is passed straight to `terminal_disconnect`.
- **Confidence:** confirmed (UI half reproduced; missing timeout read in Rust)
- **Effort:** M

## A5-11: Every successful connect prints developer diagnostics in the terminal, including "the IPC Channel is not delivering"
- **Severity:** Medium
- **Category:** ux
- **Location:** `src/renderer/terminal.js:226-235, 510, 576-579`
- **Evidence:** `trace()` writes grey lines into the xterm buffer. On every connect the scrollback begins with `[sshspan] xterm ready (80x24) - connecting to ... (auth=publickey)`, `[sshspan] session established (id=sess-100...) - waiting for remote output` and, because `gotFirstData` is always still false at that instant, `[sshspan] NOTE: no channel data yet. If this is the last line you see, the IPC Channel is not delivering.` (see `connect-session-open.png`; the lines also wrap badly in split mode and are included by "Copy all to clipboard").
- **Why it is a flaw:** an alarming internal error message appears on every healthy session and stays in the scrollback; end users cannot act on it and will assume something is broken.
- **Proposed fix:** drop the three developer traces (keep failures such as `CONNECT FAILED`), or print them only when a debug setting is on; the Rust-side "Connecting.../Connected ..." banner already tells the user what they need.
- **Confidence:** confirmed
- **Effort:** S

## A5-12: No "working" state anywhere for multi-second operations, double-submit creates duplicates, and the slowest commands run synchronously on the UI thread
- **Severity:** Medium
- **Category:** ux
- **Location:** `src/renderer/app.js:2068-2106, 2380-2389, 2861-2877, 3611-3630, 1217-1246`, `src/renderer/index.html:567-573`, `src-tauri/src/commands/mod.rs:467-468, 601-649, 1171-1172, 1731-1732, 2035-2036, 2341-2342, 1350-1356`, `src-tauri/src/crypto/vault.rs:160-169`, `src-tauri/src/crypto/keys.rs:143-145`
- **Evidence:** with a 2.5-3 s artificial IPC delay (`t6-keys.js`, `t10-settings.js`, `t13-updater.js`, `t4b-vault.js`) New key "Create", BW/AI "Test connection", "Create backup", "Check now" and vault "Unlock" keep their label, stay enabled and show nothing; double-clicking fired two `key_create_with_categories` calls (two keys) and two `bitwarden_test_connection` calls; clicking "Files" while a slow `sftp_open` is in flight leaves the Shell/Files/Split control on "Shell" with no indicator and a second click issues a second `sftp_open` (`t22-sftp-slow.js`, sftp.js:117-145). Only `bwSyncNow` (app.js:2392-2394, with a "Syncing..." status) and the server dialog's Save (re-entrancy guard, app.js:3916-3919) protect against re-entry. On the Rust side the repo itself documents that "Tauri runs a synchronous command on the MAIN thread" (mod.rs:1350-1356); `key_create_with_categories`, `key_import`, `vault_change_password`, `vault_backup_create/restore` and `key_deploy` are plain `pub fn`s that run Argon2id (64 MiB, t=3, p=4 per `vault.rs:30-33`; the `seal` doc says "deliberately not cheap ... never in a list/loop") - `vault_change_password` does two derivations per key and per saved server password (`migrate_vault_records`, mod.rs:601-649) - and the Bits list offers RSA 4096 (preselected) and 8192 through the pure-Rust `RsaKeypair::random` (keys.rs:143-145) with no hint that this takes long.
- **Why it is a flaw:** with ~30 keys, "Change master password" or a restore can take many seconds, and RSA 4096/8192 generation plausibly tens of seconds to minutes, during which the window may stop repainting/responding (main-thread command) and the buttons look idle, inviting a second click.
- **Proposed fix:** one shared `withBusy(button, labelWhileBusy, fn)` wrapper (disable, "Generating...", spinner, ignore re-entry) for all awaited primary actions; mark the heavy commands `#[tauri::command(async)]` and run the crypto in `spawn_blocking`; add "RSA 4096+ can take a minute" under the Bits list.
- **Confidence:** busy-state absence and double-submit confirmed; freeze duration likely (not measured - cargo is off-limits)
- **Effort:** M

## A5-13: At <=900 CSS px the whole category tree is hidden, so categories cannot be created, renamed, deleted or filtered - and that width is reached at the default window with UI scale >= 125%
- **Severity:** Medium
- **Category:** ux
- **Location:** `src/renderer/styles.css:836-855`, `src/renderer/index.html:88-91, 35-41`, `src/renderer/app.js:2526-2545`
- **Evidence:** `@media (max-width: 900px) { ... .cat-panel { display: none !important; } }` - the comment justifies it with "The Keys page keeps its own 'All categories' filter button", but that button no longer exists (index.html:88-91 says the tree is now the only filter; no `catFilterBtn` element in the markup). Measured (`t19-narrow.js`): at 901 px the panel and its "+" button are visible; at 900 and 880 px both are `display:none`, and the Keys toolbar holds only the type select and "New key". The app implements "Interface scale" with webview zoom (app.js:205-217), which shrinks the CSS viewport: 1100 px / 1.25 = 880 CSS px, so a 125%+ scale puts even the default window in this layout; the shipped minimum window is 880 px wide. The new-category picker text ("Create one in the sidebar", app.js:868) then points at a control that is not on screen. (Existing categories can still be filtered through the Ctrl+K palette, nothing else.)
- **Why it is a flaw:** organising 30 keys into categories is impossible for those users, with no hint why the feature disappeared.
- **Proposed fix:** keep the tree reachable below 900 px (an off-canvas drawer toggled from a "Categories" button in the Keys toolbar, or a category `<select>` filter plus a "New category" button), and fix the stale CSS comment.
- **Confidence:** confirmed
- **Effort:** M

## A5-14: Below ~970 CSS px the key detail pane drops under the entire key list, so selecting a key appears to do nothing and Copy / Export / Rename / Delete are a long scroll away
- **Severity:** Medium
- **Category:** ux
- **Location:** `src/renderer/styles.css:370-375, 377, 846-847`
- **Evidence:** `.keys-layout` is a wrapping flex row; below ~970 px (measured: side by side at 980, stacked at 960) and always under the 900 px media rule (`flex-direction: column`) the pane is placed after the list. At 880x560 with 12 keys the detail pane's top is at y=1098 while the viewport is 560 high (`t11-minsize.js`; `min-keys-selected.png` shows the row highlighted and nothing else changing). The same applies at the default window with UI scale >= 125% (1100/1.25 = 880 CSS px).
- **Why it is a flaw:** clicking a key is the way to reach its public key, fingerprint, export and delete actions; at the minimum window size the response to the click is off-screen.
- **Proposed fix:** under the stacking breakpoint show the detail as a slide-over/modal sheet (or scroll it into view on selection), or cap `.key-list-col` height with its own scroll so the pane stays visible.
- **Confidence:** confirmed
- **Effort:** M

## A5-15: At 880x560 the New key / New server dialogs push Create / Save below the fold, and Enter does not submit the key dialog
- **Severity:** Medium
- **Category:** ui
- **Location:** `src/renderer/styles.css:700-709, 732-737`, `src/renderer/index.html:605-609, 824-827`, `src/renderer/app.js:3301-3311` (no Enter handler for the key modal)
- **Evidence:** `.modal` is `max-height: calc(100vh - 60px); overflow: auto` and the footer is an ordinary last child, so it scrolls with the body. Measured at 880x560 (`t11-minsize.js`, `min-newkey.png`, `min-servermodal.png`): New key with type RSA -> modal bottom 530, footer bottom 551 (Create is cut off, `scrolls: true`); New server -> footer not visible without scrolling the dialog. The key dialog has no Enter-to-submit (the vault, prompt, server and connect-password dialogs all have it): pressing Enter in Name with a filled form creates nothing (`t12-keyboard.js`).
- **Why it is a flaw:** at the supported minimum height a user filling the form has no visible primary button and no keyboard shortcut for it; nothing hints that the dialog scrolls.
- **Proposed fix:** make `.modal-footer` sticky (`position: sticky; bottom: 0`) or make `.modal-body` the scroll container with a pinned header/footer; add Enter-to-submit on single-line fields of the key dialog.
- **Confidence:** confirmed
- **Effort:** S

## A5-16: The audit log shows only the newest 200 rows with no search, filter or paging
- **Severity:** Medium
- **Category:** ux
- **Location:** `src/renderer/app.js:2976-3023`, `src/renderer/index.html:478-497`
- **Evidence:** `loadAudit` asks for `limit: 200` once and renders them; the chip then reads "newest 200 of 350" and there is no control to see the other 150 (`t10-settings.js`: 0 filter/search inputs, 0 next/older buttons, event #349 unreachable; `settings-audit-350.png`). The only way to see the rest is "Export as CSV..." (and the log can hold 10,000 rows, app.js:2995). A failed load leaves an empty table plus a toast, with no inline error or retry.
- **Why it is a flaw:** the log exists so an admin can answer "who deployed/exported/deleted what and when"; at 200 rows that is a few hours of normal use, and finding one event means exporting everything to a spreadsheet.
- **Proposed fix:** add an event-type select + text filter (server side via `audit_list` params) and an "Older" / "Load more" button; show an inline error row with Retry on failure.
- **Confidence:** confirmed
- **Effort:** M

## A5-17: Command palette: multi-word queries find nothing, results are unranked, and most destinations are not searchable
- **Severity:** Medium
- **Category:** ux
- **Location:** `src/renderer/app.js:1901-1950, 1952-1999`
- **Evidence:** `renderPalette` keeps an item when any one term contains the whole query as a substring (`some(t => t.toLowerCase().includes(q))`), and results keep the fixed group order Servers, Keys, Categories, Actions. With 20 servers / 10 keys (`t7-palette.js`): "prod web" -> 0 results although key `prod-web` exists; "eu1 web" -> 0 although server `web-00.eu1` exists (the query must appear contiguously in one field); "lock" lists a key before the Lock action; "deploy" lists the Deploy action last (17th of 17). The action list is only New key, New server, Deploy, Audit log, Settings, Lock - so "backup", "known hosts", "bitwarden", "password", "update", "export" return nothing (0 results). "Deploy keys (select some first)" is offered when nothing is selected and only toasts when run. The empty message `Nothing matches "..."` offers no next step.
- **Why it is a flaw:** the palette is the only keyboard path to hosts and settings; with 20 servers a sysadmin types fragments and expects them to match anywhere and the best match first.
- **Proposed fix:** tokenise the query and require every token to match (case-insensitive, `-`/`.`/`_` treated as separators), rank name-prefix > word-start > substring and put exact action matches first, and add the missing destinations (each Settings section, Change master password, Check for updates, Export key, Disconnect).
- **Confidence:** confirmed
- **Effort:** M

## A5-18: Restoring a backup made under another master password asks for that password in a plain-text field and leaves it in the DOM
- **Severity:** Medium
- **Category:** ux
- **Location:** `src/renderer/app.js:2879-2903, 904-914`, `src/renderer/index.html:842`
- **Evidence:** the "Backup password" flow reuses the generic rename prompt, whose input is `<input type="text" id="promptInput">` (index.html:842) - the old master password is echoed in clear text on screen. `closePrompt` only hides the modal (app.js:914); the value stays in the hidden input until the next `promptModal` call overwrites it. The prompt also `trim()`s the value (app.js:3387), so a password with leading/trailing spaces can never match.
- **Why it is a flaw:** it is the most sensitive string in the product, typed over a shoulder-surfable field in a dialog that looks like a rename box.
- **Proposed fix:** give `promptModal` a `secret: true` option (`type="password"`, no trim, cleared on close) and use it here.
- **Confidence:** confirmed
- **Effort:** S

## A5-19: A private key (and its passphrase) pasted into the Import form survives Cancel, Escape, lock and auto-lock
- **Severity:** Medium
- **Category:** ux
- **Location:** `src/renderer/app.js:2017-2026, 2068-2106, 1250-1261`
- **Evidence:** `closeKeyModal` only resets the file hint; the Import fields are cleared solely after a successful create/import (app.js:2100-2101). `clearKeysUI`, run on lock, does not touch the form. Reproduced (`t14-misc.js`): paste a PEM + passphrase, press Escape, lock (Ctrl+L), unlock, reopen New key > Import -> the PEM and `my-key-passphrase` are still there. Elsewhere the code is careful ("Never leave submitted passwords in the DOM inputs", export passphrase cleared on tab switch, deploy passphrase cleared on close).
- **Why it is a flaw:** the app's central promise is that private keys are sealed at rest and gone from the renderer on lock; an abandoned paste is the one place plaintext key material survives the lock boundary and is shown to whoever unlocks next. The same applies to `srvPassword` / `connectPwInput` (cleared only on next open).
- **Proposed fix:** clear Generate/Import fields (and passphrase inputs) in `closeKeyModal`, `closeServerModal`, `closeConnectPwModal` and in the lock path.
- **Confidence:** confirmed
- **Effort:** S

## A5-20: The server "Test" button cannot test a password server that has no saved password, and offers no prompt
- **Severity:** Medium
- **Category:** ux
- **Location:** `src/renderer/app.js:4139-4155`, `src-tauri/src/commands/terminal.rs:310-330`
- **Evidence:** `testSelectedServer` calls `server_test` with `{ serverId }` only, although the command accepts `prompt_password`; `resolve_for_server` then has no password for `password`/`keyboard-interactive` hosts and the handshake reports "No password available for this session." Reproduced (`t5c-connect-fail.js`): selecting a password server and pressing Test shows no prompt, status strip "Connection test failed." and that toast. The same button works for key hosts, so the failure looks like a connectivity problem.
- **Why it is a flaw:** the Connect button prompts correctly for the same server, so Test appears broken exactly for the hosts users most want to verify.
- **Proposed fix:** reuse `askConnectPassword` in `testSelectedServer` for password/kbd-int servers without a saved password and pass `promptPassword`.
- **Confidence:** confirmed
- **Effort:** S

## A5-21: When loading fails the UI shows an empty state ("No keys yet", "No saved servers yet", a blank Settings page) instead of an error with Retry
- **Severity:** Medium
- **Category:** ux
- **Location:** `src/renderer/app.js:1597-1604, 3664-3675, 2458-2466`
- **Evidence:** `loadKeys` and `loadServers` set `state.keys = []` / `state.servers = []` in their catch blocks and only add a toast, so `renderKeyList`/`renderServerList` display the first-run empty state; `loadSettings` returns early leaving the General section empty. Reproduced with every IPC rejecting (`t18-reject-all.js`): Servers shows "No saved servers yet. Create one with New, or right-click a key ...", Settings is blank, and every failing call adds its own identical toast (four "Backend unavailable" toasts were stacked after visiting just Servers and Settings; identical toasts are not de-duplicated, app.js:50-87). No inline error, no Retry.
- **Why it is a flaw:** a transient DB/IPC failure reads as "all my keys/servers are gone" and invites the user to re-create data; the one actionable message is a 9 s toast.
- **Proposed fix:** keep a `loadError` per view and render an error card ("Could not load keys: <message> [Retry]") instead of the empty state; collapse duplicate toasts.
- **Confidence:** confirmed
- **Effort:** S

## A5-22: Updating gives no progress, no notice that the app is about to exit, and does not check for live sessions or transfers
- **Severity:** Medium
- **Category:** ux
- **Location:** `src/renderer/app.js:3611-3630`, `src-tauri/src/commands/updater.rs:437-441, 735-741`
- **Evidence:** "Check now" has no busy state (a second click while the first check is in flight simply fires another `update_check`, `t13-updater.js`); when an update exists the only feedback is a 3.8 s toast "Downloading installer..." while the backend streams up to the 600 s timeout with no progress, then launches the installer and calls `app.exit(0)` 2.5 s later (updater.rs:735-741). The renderer shows nothing after `update_download_and_run` resolves, and the updater does not look at live sessions or the transfer queue (no `SessionRegistry`/queue reference in updater.rs). Offline failures surface as the raw reqwest text ("Could not reach GitHub: error sending request for url (https://api.github.com/...): client error (Connect)") as a 9 s toast only. The pre-update confirm is the bypassed native `confirm` (A5-01), so today none of this is even consented to.
- **Why it is a flaw:** the window vanishes without warning and kills open shells and running transfers; users on a slow link stare at an unchanged page for minutes.
- **Proposed fix:** show an in-app update dialog (version, notes, live-session/transfer warning, Install / Later), a progress bar fed by download events, an "SSHSpan will close to install" message before exit, and plain-language offline text ("Could not reach GitHub - check your connection").
- **Confidence:** confirmed (code + reproduced renderer half)
- **Effort:** M

## A5-23: Keyboard-only use is broken in several places: key rows and category nodes are not focusable, buttons show no focus ring, focus is lost after the key dialog, and Escape is inconsistent
- **Severity:** Medium
- **Category:** a11y
- **Location:** `src/renderer/styles.css:93`, `src/renderer/app.js:1457-1547, 460-516, 4338-4361, 140-164, 2017-2021, 3392-3395, 3541-3544, 633-675, 1121-1165`, `src/renderer/assistant.js:167-181`
- **Evidence:** (1) `button:focus-visible, input:focus-visible, ... { outline: none; }` (styles.css:93) and no replacement ring exists for nav items, ghost/primary/danger/icon buttons, tabs or segmented buttons: pixel comparison before/after keyboard focus is identical for 5 of 5 buttons while inputs do change (`t15-focusring.js`). (2) `.key-row`, `.cat-node` and `.term-tab` are `<div>`/`<span>` with click handlers and no `tabindex`; Tab order from the nav goes to checkboxes and Connect buttons but never to a row (`t12-keyboard.js`: all rows `tabIndex -1`), so a key cannot be selected to reach its detail pane by keyboard (public-only keys have no Connect button either); the category tree and tab chips (including the "x" close) are mouse-only. (3) `modalDidOpen` records `document.activeElement` after `openKeyModal` has already focused `genName` (app.js:2017-2021, microtask ordering), so the "opener" is inside the dialog and focus falls to `<body>` after the New key dialog closes (server dialog returns focus correctly). (4) Escape: the rename/prompt dialog and the connect-password dialog close only when their input has focus (app.js:3392-3395, 3541-3544), the YOLO dialog ignores Escape entirely (assistant.js:167-181), and the category menu and the vault menu ignore Escape and never take focus (`aria-expanded` stays true). Stacked layers work: palette over a dialog closes first, the picker over the key dialog closes first.
- **Why it is a flaw:** a keyboard user cannot see where focus is, cannot open a key's details, and loses their place after dialogs; Escape works until focus moves to a button.
- **Proposed fix:** add a global `:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px }` for buttons/tabs/rows; give rows `tabindex="0"` + Enter/Space handlers (and role/aria-selected); capture the opener before focusing in `openKeyModal` (or have `modalDidOpen` use the pre-open element); move Escape handling for prompt/connect-password/YOLO into the global handler; make menus focus their first item and close on Escape.
- **Confidence:** confirmed
- **Effort:** M

## A5-24: Closing the window silently hides the app to the tray with the vault unlocked and sessions running; there is no notice, setting or in-app Quit
- **Severity:** Medium
- **Category:** ux
- **Location:** `src-tauri/src/lib.rs:226-240, 270-325`, `docs/ARCHITECTURE.md:43-47`
- **Evidence:** `CloseRequested` is intercepted (`prevent_close(); window.hide()`) unless `QUITTING` is set, which only the tray's Quit item sets; the vault "deliberately stays unlocked" (lib.rs:229-231) and live SSH sessions keep running. The behaviour is documented only in `docs/ARCHITECTURE.md`; the renderer has no one-time notice, no "Close to tray" setting and no File > Quit / palette Quit. On Windows the tray icon often lives in the overflow flyout, and on Linux desktops without a status-notifier host (stock GNOME) there may be no visible tray at all (relaunching the app does restore the window via the single-instance plugin).
- **Why it is a flaw:** pressing X looks like quitting; combined with A5-06 (auto-lock effectively off) the vault stays unlocked and hosts stay connected indefinitely with the app out of sight.
- **Proposed fix:** make close-to-tray a setting (default: ask once with "Close to tray / Quit"), show a toast/notification the first time ("SSHSpan is still running in the tray"), add Quit to the vault menu and palette, and offer to lock on hide.
- **Confidence:** confirmed for the behaviour, likely for the stock-GNOME consequence
- **Effort:** M

## A5-25: Key names are not unique and deployed filenames collapse punctuation, so a double-submit or a second key with a similar name silently overwrites the first key's deployed file
- **Severity:** Medium
- **Category:** ux
- **Location:** `src-tauri/src/db/mod.rs:366-381`, `src-tauri/src/ssh/mod.rs:90-104, 279-289`, `src/renderer/app.js:2068-2106, 3259-3273` (rename prompt), `src-tauri/src/commands/mod.rs:1999-2022`
- **Evidence:** the `keys` table has no UNIQUE constraint on `name`, create/import/rename perform no duplicate check, and the renderer lets a double-click on Create submit twice (two keys created in `t6-keys.js`, A5-12). `deploy_key` writes `~/.ssh/sshspan_<sanitize_filename(name)>` where every character outside `[A-Za-z0-9_-]` becomes `_`, so `prod.web`, `prod_web` and `prod@web` (all valid names) - or two keys both called `prod-web` - target one file; `write_secret_file` overwrites it and both rows then show "Deployed" with the same path.
- **Why it is a flaw:** re-deploying "prod-web" after generating a replacement silently replaces the previous deployed private key, so anything still using `IdentityFile ~/.ssh/sshspan_prod-web` changes identity without warning; the deploy sheet never says it will overwrite an existing file.
- **Proposed fix:** reject duplicate (case-insensitive) names in create/import/rename (with a friendly message), have the deploy sheet list "will overwrite: <path>" for existing files, and disambiguate filenames (suffix with the key id) when sanitising collapses characters.
- **Confidence:** confirmed
- **Effort:** M

## A5-26: Servers that use a passphrase-protected .pem file always fail with "The key is encrypted", and the Deploy sheet offers the combination that guarantees it
- **Severity:** Medium
- **Category:** ux
- **Location:** `src-tauri/src/ssh_client/mod.rs:424-429`, `src-tauri/src/commands/terminal.rs:93-107`, `src/renderer/index.html:805-808, 687-694`, `src/renderer/app.js:2184-2227`
- **Evidence:** for a `pemPath` server `resolve_for_server` reads the file and `authenticate` calls `decode_secret_key(pem, None)`; russh returns `Error::KeyIsEncrypted` ("The key is encrypted", russh 0.63.2 `keys/format/openssh.rs:9-14`), surfaced as "Could not decode the selected private key: The key is encrypted". There is no passphrase prompt in the connect flow (`terminal_connect` takes no passphrase) and the server dialog's ".pem file on disk" row says nothing about this limit. The Deploy sheet's "Put a passphrase on the written key files" + "Also save these as servers" registers servers with `pemPath` pointing at the now-encrypted files (app.js:2184-2227), so those servers can never connect from SSHSpan.
- **Why it is a flaw:** sysadmins' existing `~/.ssh` keys are usually passphrase-protected; the app accepts them, saves the server, and then fails at connect time with a message that does not say what to do (import the key into the vault, where the passphrase is handled).
- **Proposed fix:** detect an encrypted PEM when saving the server (or on connect) and either prompt for the passphrase or say "This key file is passphrase-protected - import it into the vault (Keys > New key > Import) or remove the passphrase"; hide "Also save these as servers" when a deploy passphrase is set.
- **Confidence:** likely (library behaviour and call path read; not run against a real encrypted key)
- **Effort:** M

## A5-39: The Import dialog (and README) promise PKCS#8, SPKI-public and authorized_keys import, but `key_import` accepts only OpenSSH private keys and PuTTY .ppk
- **Severity:** Medium
- **Category:** ux
- **Location:** `src/renderer/index.html:594`, `README.md:142-144`, `src-tauri/src/commands/mod.rs:1743-1751`
- **Evidence:** the textarea label reads "Paste key material (OpenSSH / PKCS#8 / PEM private key, PuTTY .ppk v3, SPKI public PEM, or authorized_keys line)". `key_import` only branches on `-----BEGIN OPENSSH PRIVATE KEY-----` and `looks_like_ppk`; everything else (`BEGIN RSA PRIVATE KEY`, `BEGIN PRIVATE KEY`, `BEGIN ENCRYPTED PRIVATE KEY`, `BEGIN PUBLIC KEY`, an `ssh-ed25519 AAAA...` line) returns "Unsupported key format. Expected an OpenSSH private key (-----BEGIN OPENSSH PRIVATE KEY-----) or a PuTTY .ppk file." after the user presses Import. There is no other import path in the repository (`import_openssh_private` and `import_ppk` are the only importers).
- **Why it is a flaw:** the keys a sysadmin already has are very often PKCS#1/PKCS#8 PEMs (cloud-provider `.pem` files, OpenSSL-generated keys); the dialog says they work and they do not.
- **Proposed fix:** either add PKCS#1/PKCS#8/SPKI/authorized_keys parsing (`crypto/pkcs8.rs` currently has only the exporters) or correct the label and README to the two supported formats and detect other headers client-side with an explanatory message.
- **Confidence:** confirmed by code reading (likely overlaps a Rust-logic finding)
- **Effort:** M

## A5-40: The Files view has no Upload button or menu item; uploading needs OS drag-and-drop or the hidden "Dual" local pane
- **Severity:** Medium
- **Category:** ux
- **Location:** `src/renderer/sftp.js:237-312` (toolbar), `sftp.js:1297-1310` (remote context menu exists only on rows), `sftp.js:2268` ("Upload" only in the local-pane menu), `sftp.js:3413-3461` (OS drop), `sftp.js:535-536` (drop hint)
- **Evidence:** the remote toolbar buttons are Up, Refresh, Folder, File, Bookmarks, Search, Hidden, Columns, Dual, Log, Compare, Sync browse (`t16-sftp.js`); none uploads. The remote pane's `contextmenu` handler returns unless the click lands on a row, so right-clicking empty space shows nothing; "Upload" / "Upload folder" appear only in the *local* pane's menu, which exists only after toggling "Dual". The one affordance for dropping files ("Drop files to upload to the current remote directory") is visible only while a drag is already in progress.
- **Why it is a flaw:** the most common SFTP task - "put this file on the server" - has no visible control; users coming from FileZilla/WinSCP will look for Upload and not find it.
- **Proposed fix:** add an "Upload..." toolbar button (multi-file native picker command) and an empty-area context menu (Upload, New folder, New file, Refresh); show the drop hint permanently as a muted line when the listing is empty.
- **Confidence:** confirmed
- **Effort:** M

## A5-42: With a category filter active, a newly generated key or newly saved server is created but does not appear in the list
- **Severity:** Medium
- **Category:** ux
- **Location:** `src/renderer/app.js:438-456, 2068-2106, 3891-3931, 3699-3700`, `src/renderer/index.html:582-586, 816-820`
- **Evidence:** `filteredKeys()` / `renderServerList()` narrow the pool to the active category first. Reproduced (`t23-filter-newkey.js`): with sidebar category "Production" active, generating `brand-new` (no category chosen) toasts "Key generated.", bumps the count chip to "3 keys", and leaves the list at one row with the detail pane still on `prod-web`; saving `new-box` while the host category "EU" is active toasts "Server saved." and the terminal header shows `new-box` but the list still holds only `web-1`. The only cue is the breadcrumb "Keys / Production  Clear filter" above the list. The creation dialogs do not preselect the active category.
- **Why it is a flaw:** the user does exactly what the product asks, gets a success toast, and cannot find the result; people re-create it or assume the save failed.
- **Proposed fix:** preselect the active category in the New key / New server dialogs (or clear the filter after a create and select the new row), and when a created item is hidden by the filter say so in the toast ("Created - hidden by the current filter. Show all").
- **Confidence:** confirmed
- **Effort:** S

## A5-45: The "Confirm multi-line pastes" guard does not cover plain Ctrl+V or middle-click paste
- **Severity:** Medium
- **Category:** ux
- **Location:** `src/renderer/terminal.js:237-276` (wireTerminalClipboard), `terminal.js:656-671` (terminalPaste), `src/renderer/app.js:2563-2574`
- **Evidence:** the guard lives only in `window.terminalPaste`, which is reached from Ctrl+Shift+V (terminal.js:266-272), right-click on xterm's textarea (terminal.js:252-261) and the context-menu "Paste". A normal paste (Ctrl+V, middle-click, Edit menu) fires the browser `paste` event on xterm's helper textarea and xterm sends the text straight to `onData`. Reproduced (`t25-paste.js`) with the setting on: a native paste event carrying `echo one / rm -rf /tmp/demo / shutdown -h now` produced no dialog and one `terminal_send` of `echo one\rrm -rf /tmp/demo\rshutdown -h now\r`. (This is independent of A5-01: even with a working confirm the native paste path never reaches it.)
- **Why it is a flaw:** the setting is described as "A pasted newline runs the line. This catches a copied block before it executes", but the most common paste gesture on Windows - Ctrl+V - bypasses it, so users believe they are protected when they are not.
- **Proposed fix:** register a capture-phase `paste` listener on `t.textarea` that calls `preventDefault()`/`stopPropagation()` and routes `ev.clipboardData.getData('text')` through `terminalPaste`, so every paste path shares the guard.
- **Confidence:** confirmed
- **Effort:** S

## A5-46: While any Files/Split tab is active, Ctrl+A is hijacked in every text field in the app (selects all files instead of the text)
- **Severity:** Medium
- **Category:** ux
- **Location:** `src/renderer/sftp.js:1449-1470` (and the same pattern for Ctrl+Y at 3818-3826, which is "Redo" in Windows text fields)
- **Evidence:** the document-level keydown handler runs for any Ctrl/Cmd+A when `sftpPanelVisible(active)` (the active tab's mode is not `ssh`); it checks neither `ev.target` nor which view is showing, calls `ev.preventDefault()` and selects every row. Reproduced (`t26-ctrla.js` and an inline probe): with a Files tab active, Ctrl+A in the remote path box, in the rename prompt (`a.log` typed, nothing gets selected), in the assistant input, and - after switching to the Keys view - in the Keys search box leaves the text unselected and selects both file rows in the background.
- **Why it is a flaw:** "select the old name and type a new one" in the rename dialog, or select-all in any field, silently stops working for the whole app as soon as a Files tab has been opened, and the file selection changes behind the user's back (which matters because Delete acts on the selection).
- **Proposed fix:** return early when `ev.target.closest('input, textarea, select, [contenteditable]')` or when the Connect view/a modal is not the focus context; better, scope the handler to keydowns whose target is inside `#sftpPanel-<tab>`'s table/wrapper.
- **Confidence:** confirmed
- **Effort:** S

## A5-27: A search or filter with no matches leaves a blank list (and, for Keys, a stale detail pane) with no message or "clear filter"
- **Severity:** Low
- **Category:** ux
- **Location:** `src/renderer/app.js:1337-1352, 3692-3712`
- **Evidence:** `renderKeyList` returns early on `rows.length === 0` and only the "No keys yet" empty state exists, shown when the *vault* is empty (`emptyState.hidden = total > 0`); `renderServerList` likewise only handles `state.servers.length === 0`. Searching "zzzz" in Keys leaves an empty column while the detail pane still shows `prod-web-1` (`keys-search-no-results.png`); searching servers shows a blank list (`server-search-no-results.png`).
- **Why it is a flaw:** an empty pane is indistinguishable from a rendering failure, and the detail pane contradicts the list.
- **Proposed fix:** render a "No keys match 'zzzz' - Clear search" row (and clear/hide the detail pane when the selected key is filtered out); same for servers.
- **Confidence:** confirmed
- **Effort:** S

## A5-28: Editing or deleting a server is only possible through a right-click menu that nothing on screen advertises
- **Severity:** Low
- **Category:** ux
- **Location:** `src/renderer/app.js:3759-3786, 3794-3826`, `src/renderer/index.html:182-197, 199-220`
- **Evidence:** each server row exposes one button, "Connect"/"Open" (`t8-servers.js`: `buttons: ["Connect"]`); Edit and Delete exist only in `openServerContextMenu`, and neither the terminal header nor the palette offers them. The empty-state hint mentions only "New" and a key-row right-click.
- **Why it is a flaw:** the first time a user needs to fix a typo in a host name they have to guess to right-click.
- **Proposed fix:** add a "..." (row actions) button on each server row that opens the same menu, and an "Edit" button in the terminal header for the selected server.
- **Confidence:** confirmed
- **Effort:** S

## A5-29: User-visible copy defects: `[OI]` placeholders in the AI provider list, an internal build marker ("v14-tabs") instead of the app version, and a wrong KDF named in the create-vault dialog
- **Severity:** Low
- **Category:** ux
- **Location:** `src/renderer/index.html:370, 379, 400`, `src/renderer/app.js:4481-4482, 4520, 3122`, `app.js:1045`, `src-tauri/src/crypto/vault.rs:30-33`
- **Evidence:** the provider select reads "[OI]-compatible (chat/completions)", the preset list's first entry is "[OI]" and the hint says "Works with [OI], OpenRouter, ..." (looks like a find/replace artefact; it is also in README.md:55, 180-182). The sidebar header shows "KEYS & SESSIONS - V14-TABS" and the status strip "Ready. (build v14-tabs)" (`window.__SSHPAN_BUILD__ = 'v14-tabs'`); the real version (1.9.1) appears nowhere except the "latest version" toast. The create-vault dialog says the password protects keys with "(scrypt + AES-256-GCM)" while `vault.rs:32` derives the key with Argon2id.
- **Why it is a flaw:** the provider picker is unreadable to anyone who does not already know what `[OI]` means, the version a support request needs is not shown, and a security product's first-run dialog should not name the wrong KDF.
- **Proposed fix:** restore the provider name in the three labels; show `CARGO_PKG_VERSION` (expose via a command or the existing `current_version`) in the sidebar/Settings and drop the build marker; change the copy to "Argon2id + AES-256-GCM".
- **Confidence:** confirmed
- **Effort:** S

## A5-30: Port fields coerce bad input silently or fail with a raw serde error
- **Severity:** Low
- **Category:** ux
- **Location:** `src/renderer/app.js:3894, 2145, 2219`, `src/renderer/index.html:677, 790`, `src-tauri/src/commands/server.rs:55`
- **Evidence:** both dialogs use `parseInt(value, 10) || 22`; the `min`/`max` attributes are not enforced because there is no `<form>`. Reproduced (`t8-servers.js`): `0` saves as port 22 with "Server saved."; `1.5` saves as 1; `-1` and `65536` reach Rust, which rejects them with the toast "invalid args `port` for command `server_save`: invalid value: integer `65536`, expected u16".
- **Why it is a flaw:** a mistyped port is either silently changed or answered with an internal deserialisation message.
- **Proposed fix:** validate 1-65535 in the renderer (inline message next to the field) before calling the backend.
- **Confidence:** confirmed
- **Effort:** S

## A5-31: Inconsistent terminology across the primary surfaces
- **Severity:** Low
- **Category:** ux
- **Location:** `src/renderer/index.html:32, 201, 222`, `src/renderer/app.js:528, 541, 748, 1466, 4386-4388`
- **Evidence:** the same concept is "Servers" (nav, title, palette), "Connect" (view id, buttons), "Hosts" (sidebar "Host categories", "Uncategorized hosts", breadcrumb root "Hosts" while on the Servers view, "Known hosts", deploy "Host alias") and "connection" (title "No connection", tab-add tooltip "New connection"). A selected server that was never connected shows a "Reconnect" button in the terminal header (app.js:4386-4388) while its row says "Connect". The key-row checkbox is titled "Include in deploy" (app.js:1466) but the same selection feeds the selection bar's "Delete" and "Add to category". "Deploy" in SSH usage normally means installing a public key on a server (ssh-copy-id), whereas here it writes private keys and a Host block locally; only the sheet subtitle explains it. The disabled "Servers" nav item keeps the tooltip "Servers (Ctrl+2)" with no hint that the vault must be unlocked.
- **Why it is a flaw:** small label drift makes the product harder to learn, and "Deploy" invites the wrong mental model for a destructive-feeling file write.
- **Proposed fix:** pick Servers/Server throughout (breadcrumb root "Servers"), label the button "Connect" until a session has existed, rename the checkbox title to "Select", rename the action "Write to ~/.ssh..." or "Export to SSH config...", and set the locked nav tooltip to "Unlock the vault to use Servers".
- **Confidence:** confirmed
- **Effort:** S

## A5-32: Settings controls flip before the save succeeds and stay flipped on failure; the auto-lock field accepts anything
- **Severity:** Low
- **Category:** ux
- **Location:** `src/renderer/app.js:2506-2519, 2547-2561, 2563-2574` (and the other `settings_set` handlers through 2831)
- **Evidence:** every row changes its control first and then calls `settings_set`; on rejection the handler only toasts. Reproduced (`t10-settings.js`): with `settings_set` failing ("Disk is read-only."), unticking "Confirm before deleting a key" leaves the toggle off while `state.settings.confirmDelete` stays `true`, so the screen and the effective setting disagree until the next visit. The auto-lock number input has `min`/`max` attributes but no validation: an empty value is stored as `''` (auto-lock silently off) and still toasts "Auto-lock updated.".
- **Why it is a flaw:** the user believes a safety setting changed when it did not.
- **Proposed fix:** revert the control (and show the error inline) in each catch block; validate and clamp the auto-lock value before saving.
- **Confidence:** confirmed
- **Effort:** S

## A5-33: Terminal right-click menu: "New session" and "Duplicate session" are the same action, and "Restart session" kills a live shell with no confirmation
- **Severity:** Low
- **Category:** ux
- **Location:** `src/renderer/app.js:1263-1307` (esp. 1291-1293, 4243-4269), `src/renderer/terminal.js:486-498`
- **Evidence:** both "New session" and "Duplicate session" call `openSessionTab(srv)`; "Restart session" calls `reconnectActiveTab()`, which tears down the live session (`terminal_disconnect` of the old id) and reconnects in the same tab. It sits one row above "Switch to SFTP", next to harmless items such as "Reset terminal".
- **Why it is a flaw:** one stray click ends whatever is running in the shell.
- **Proposed fix:** drop the duplicate entry; confirm "Restart session" when a session is live (using `confirmModal`, see A5-01).
- **Confidence:** confirmed
- **Effort:** S

## A5-34: Bulk selection has no Select all, keeps hidden (filtered-out) keys selected, and deleting the open key auto-opens another key's Delete button
- **Severity:** Low
- **Category:** ux
- **Location:** `src/renderer/app.js:1457-1473, 1320-1335, 1715-1743, 1597-1615`, `src/renderer/index.html:108-115`
- **Evidence:** selection lives in `state.deploySelected` and is never pruned when the search/type filter hides rows, so "3 keys selected" can include rows that are not on screen and the selection-bar Delete/Deploy acts on all of them; there is no select-all/group-select control (a 30-key deploy is 30 clicks; no shift-click range). After deleting the key shown in the detail pane, `loadKeys()` selects `state.keys[0]` and shows its Delete button where the previous one was (app.js:1608-1612).
- **Why it is a flaw:** with the confirm unavailable (A5-01) these make bulk operations error-prone for a 30-key vault.
- **Proposed fix:** add a "select all (visible)" checkbox per group/toolbar, show "(N hidden by filter)" in the selection bar or clear selection on filter change, and do not auto-select another key after a delete.
- **Confidence:** confirmed (by code)
- **Effort:** S

## A5-35: Credential fields: no reveal toggle anywhere, and Bitwarden gives no sign that a master password is already stored
- **Severity:** Low
- **Category:** ux
- **Location:** `src/renderer/app.js:2321-2353, 2355-2374`, `src-tauri/src/commands/mod.rs:2447-2462`, `src/renderer/index.html:623-625, 392, 455, 645`
- **Evidence:** the vault create/change fields, Bitwarden master password, AI API key, MCP secret and connect password are all `type="password"` with no show/hide control (`t10-settings.js`: none present). The AI key shows "key stored" with a check mark (`aiKeyHint`), but `bitwarden_get_config` returns no has-password flag, so after Save the field is simply empty with the placeholder "Your Bitwarden master password"; a missing password only surfaces later as "No master password stored. Re-save the sync settings." (mod.rs:2528).
- **Why it is a flaw:** choosing a no-recovery master password without being able to check what was typed invites typos, and users cannot tell whether Bitwarden is fully configured.
- **Proposed fix:** add an eye toggle to every password input and return `has_master_password` so the Bitwarden form can show "password stored (leave blank to keep)".
- **Confidence:** confirmed
- **Effort:** S

## A5-36: First use of the AI assistant is a dead end: the panel opens empty and the "not configured" error offers no link to Settings
- **Severity:** Low
- **Category:** ux
- **Location:** `src/renderer/assistant.js:683-688, 713-716, 862-865`, `src/renderer/index.html:230-254`, `src-tauri/src/assistant/mod.rs:184-189`
- **Evidence:** opening the panel (`assistant-first-open.png`) shows only the access-level selector and an input; there is no setup hint. Sending a message fails with "AI assistant is not configured - open Settings > AI assistant." (mod.rs:184-186) shown in the panel and as a toast, with no button. `window.assistantOpenSettings` (assistant.js:862-865) exists but nothing calls it.
- **Why it is a flaw:** the user has to find the Settings section on their own, after typing a question.
- **Proposed fix:** on open, if `assistant_get_config` reports no key/model, render a "Set up the assistant" card whose button calls `assistantOpenSettings()`; make the error toast clickable the same way.
- **Confidence:** confirmed
- **Effort:** S

## A5-41: "Use this key to connect..." lists password servers, where the chosen key is silently ignored
- **Severity:** Low
- **Category:** ux
- **Location:** `src/renderer/app.js:4002-4087, 4089-4135`, `src-tauri/src/commands/terminal.rs:92-114`
- **Evidence:** `hostPickerTree()` / `buildHostPickerLevel` list every saved server regardless of `authMethod`, and the click passes `overrideKeyId`; `resolve_for_server` applies `override_key_id` only inside the `publickey` branch, so for a `password` / `keyboard-interactive` server the key is dropped and the user gets the password prompt instead.
- **Why it is a flaw:** the user explicitly chose a key and the app answers with an unrelated password prompt, with no explanation.
- **Proposed fix:** show only publickey servers in this picker (or badge password servers "uses password") and say "this server uses password login" if one is chosen.
- **Confidence:** confirmed (by code)
- **Effort:** S

## A5-43: There is no way in the UI to remove a deployed key file; deleting a key leaves its private key on disk
- **Severity:** Low
- **Category:** ux
- **Location:** `src-tauri/src/commands/mod.rs:2099-2155` (`key_remove_deployed`), `src-tauri/src/lib.rs:122`, `src/renderer/app.js:1692-1709, 1515-1521`
- **Evidence:** `key_remove_deployed` is implemented (with path-containment checks) and registered as an IPC command, but no renderer file calls it (searched `src/renderer`: no reference). The detail pane shows "Deployed: <path>" and the row a "Deployed" chip, yet offers no "Remove deployed copy"; the delete confirmation merely says "Deployed copies on disk are not removed." (app.js:1696) - and that confirmation is itself bypassed (A5-01).
- **Why it is a flaw:** after deploying and later deleting/rotating a key, the private key file keeps living in `~/.ssh` with no in-app way to clean it up, which a key manager should do.
- **Proposed fix:** add "Remove deployed copy" to the detail pane (and offer it in the delete confirmation as a checkbox "Also delete the deployed file").
- **Confidence:** confirmed
- **Effort:** S

## A5-44: Terminal-maximized mode tells you to "press Esc" to restore, but Esc goes to the remote shell and the window stays maximized
- **Severity:** Low
- **Category:** ux
- **Location:** `src/renderer/app.js:4224-4240, 3415` (hint and Escape branch), `src/renderer/terminal.js:460-464`, `src/renderer/styles.css:1268-1291`
- **Evidence:** `toggleTermMax` sets the status strip to "Terminal maximized - press Esc or <> to restore." and then focuses the terminal (`fitActiveTerminalAndFocus`). The restore-on-Escape branch lives in the document keydown handler (app.js:3415), but xterm consumes Escape when it has focus. Reproduced (`t24-termmax.js`): after maximizing, pressing Escape leaves `#app.term-max` set and sends one `terminal_send` (the Esc byte) to the remote session. The only on-screen way out is the 26 px "<>" button drawn at 35% opacity in the corner (Ctrl+1/2/3 also leave the view).
- **Why it is a flaw:** the instruction on screen does not work, and the keystroke leaks into whatever runs remotely (it leaves insert mode in vim, for example).
- **Proposed fix:** handle the restore key in a capture-phase listener or via `term.attachCustomKeyEventHandler` (e.g. Ctrl+Shift+M), change the hint to the real shortcut, and raise the button's resting opacity.
- **Confidence:** confirmed
- **Effort:** S

## A5-47: The SFTP "target file already exists" dialog pre-selects Overwrite for every file and focuses Continue, so a reflexive Enter overwrites them all
- **Severity:** Low
- **Category:** ux
- **Location:** `src/renderer/sftp.js:2752` (`rb.checked = act === 'overwrite'`), `sftp.js:2810-2811` (`applyBtn.focus()`), compare `sftp.js:1604-1606`
- **Evidence:** every conflicting item starts on the Overwrite radio and the dialog opens with the primary "Continue" button focused, so Enter/Space applies Overwrite to the whole batch (and "Always use this action" would persist the first row's choice as the default for all future transfers, silently skipping this dialog). The sibling delete dialog deliberately focuses Cancel with the comment "a reflexive Enter or Space on a delete prompt must not be the thing that deletes".
- **Why it is a flaw:** overwriting a remote production file is exactly as irreversible as deleting it; the two dialogs should share the same safety stance.
- **Proposed fix:** default the radios to Skip (or "Overwrite if source is newer") and focus Cancel, or at least require choosing an action when more than one file conflicts.
- **Confidence:** confirmed (by code)
- **Effort:** S

## Notes for the controller

- **Overlap warnings:** A5-07 and A5-13/14/15 are layout findings A1 may also report; A5-10 (leaked session) and A5-37/A5-39 (ECDSA string, import formats) touch A3/A2 territory; they are kept here because each has a direct, user-visible UX consequence and I reproduced the renderer half.
- **Not verified (flagged rather than guessed):** (1) public-key export uses an anchor download of a blob (app.js:230-240, 1861); no download handler is registered in `src-tauri` (wry's WebKitGTK path only wires one when a handler is set), so on Linux the export may be cancelled while the success toast still shows - I could not test WebKitGTK; (2) real WebView2 behaviour of `window.confirm` after the dialog plugin's shim (A5-01 is established from plugin and Tauri source, and reproduced with the shim's exact script against a rejecting `__TAURI_INTERNALS__`); (3) actual Argon2id/RSA timings.
- **Done well (no finding):** Escape closes the topmost of palette / category picker / dialog correctly; toasts are dismissible, stack (max 4) and errors linger 9 s; export formats carry Secret/Sealed/Public risk chips and private keys are written by Rust, never through the webview; the SFTP delete dialog focuses Cancel and offers a session-scoped (never persisted) "don't ask again"; the deploy confirmation prints the real target paths; vault errors ("Incorrect master password.", throttle message) are clear; the server dialog has a re-entrancy guard.

