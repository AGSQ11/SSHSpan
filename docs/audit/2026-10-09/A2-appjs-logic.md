# A2 - app.js JS-logic audit (SSHSpan 1.9.1, main @ 1ca864f)

- **Counts:** 53 findings - Critical 1, High 6, Medium 22, Low 24. Ordered by severity, then id (ids are stable cross-references, not a ranking).
- **Covered:** all 4551 lines of `src/renderer/app.js` read top to bottom; every IPC call checked against its `#[tauri::command]` (`commands/mod.rs`, `server.rs`, `terminal.rs`, `updater.rs`, `bitwarden/sync.rs`, `db/mod.rs`, `crypto/keys.rs`, `ssh/mod.rs`, `config/mod.rs`); the terminal.js connect/teardown path where app.js depends on it.
- **Not covered:** sftp.js / assistant.js / mcp.js bodies (other auditors); Rust internals beyond the command contracts; real WebView2 / WebKitGTK behaviour (headless Chromium stand-in with a stubbed `window.__TAURI__`); a handful of items are marked `suspected` where behaviour is platform-dependent.
- **Method:** `confirmed` = proven by reading against the Rust source, or reproduced in headless Chromium (driver: `.superpowers/audit/scratch/A2/drive.js`, ~40 scenarios; fake clock for the timer cases).
- **Checked and clean (no finding):** every `el('...')` id (184 distinct) exists in index.html or is created dynamically; response field names/casing the renderer reads match what Rust emits for all ~45 commands app.js calls (snake_case for `Category`/key rows, camelCase for server/known-host/audit/update shapes); every `innerHTML` site interpolates only `escapeHtml(...)`, `ico(...)` or static strings; toasts use `textContent`; IPC errors arrive as plain strings so `e.message || String(e)` never prints `[object Object]`; no `JSON.parse`/`eval`/`Promise.all`/`localStorage` in app.js; `settingOn()` is used for the settings that are stored as `"true"/"false"`; `listen()` is subscribed once for the page lifetime.

## A2-01: Idle auto-lock can never fire - the 10-second status poll re-arms the idle timer
- **Severity:** Critical
- **Category:** js-logic
- **Location:** `src/renderer/app.js:1095`, `src/renderer/app.js:3566-3579`, `src/renderer/app.js:4546-4548`, `src/renderer/app.js:3603-3607`; `src-tauri/src/commands/mod.rs:406-465`
- **Evidence:** `refreshVaultStatus()` ends with an unconditional `resetAutoLockTimer();` (1095). `resetAutoLockTimer()` does `clearTimeout(autoLockTimer)` then `autoLockDeadline = Date.now() + mins*60*1000` and a fresh `setTimeout(..., mins*60*1000)`. `main()` runs `setInterval(() => { refreshVaultStatus(true)... }, 10000)` (4546). So every 10 s the deadline is pushed a full `mins` into the future, regardless of user activity. The backend watchdog does not compensate: it locks only when `ActivityTracker` is stale, and `ActivityTracker` is touched by the `heartbeat` command, which the renderer fires every 30 s unconditionally (3603-3607), so it is never stale while the webview lives. Reproduced with a fake clock: `autoLockMinutes='1'`, user idle, 105 s of fake time, 11 `vault_status` polls: sidebar stayed at `locks in 0:55`, `vault_lock` was never invoked.
- **Why it is a flaw:** the headline security control ("Lock the vault when idle", with a visible countdown) never locks. An unattended unlocked vault stays unlocked indefinitely, with live SSH sessions and decryptable keys. The countdown the user watches never reaches zero either.
- **Proposed fix:** in `refreshVaultStatus` call `resetAutoLockTimer()` only on a state transition (`if (!wasUnlocked && s.unlocked) resetAutoLockTimer()`), or drop the call and rely on the activity listeners (4537-4540) plus the explicit calls after unlock/settings change. Separately make the `heartbeat` conditional on recent activity if the backend watchdog is meant to be a second line of defence. Fix A2-53 together with this one: keystrokes typed into a terminal do not reach the bubble-phase activity listeners, so the moment the timer works a user who is typing in a shell (no mouse) will be locked out and every live SSH session killed.
- **Confidence:** confirmed (reproduced)
- **Effort:** S

## A2-02: Generating an ECDSA key always fails - the curve select sends `nistp256`, Rust accepts only `p256`
- **Severity:** High
- **Category:** js-logic
- **Location:** `src/renderer/app.js:2073-2077`; `src/renderer/index.html:575-579`; `src-tauri/src/crypto/keys.rs:73-82`; `src-tauri/src/commands/mod.rs:2354`
- **Evidence:** the payload is built as ``keyType: el('genType').value === 'ecdsa' ? `ecdsa-${el('genCurve').value || 'p256'}` : ...``. The `#genCurve` options are `nistp256 | nistp384 | nistp521`, so the payload is `keyType: "ecdsa-nistp256"` (captured in the driver). `KeyType::from_db_tag` accepts only `"ecdsa" | "ecdsa-p256" | "ecdsa-p384" | "ecdsa-p521"` and otherwise bails `Unknown key type: ecdsa-nistp256`. No normalisation exists anywhere (`grep nistp` finds only the `<option>`s, README claims, and wire-algorithm names). The `|| 'p256'` fallback never triggers because the select always has a value.
- **Why it is a flaw:** one of the three advertised key types (README: "ECDSA (nistp256/384/521)") cannot be created at all; the user gets a raw "Unknown key type: ecdsa-nistp256" toast. `check-ipc-args.js` cannot catch it (argument names match; the value domain does not).
- **Proposed fix:** change the option values to `p256|p384|p521` (keeping the visible labels), or map `nistpNNN -> pNNN` in `submitKeyModal`. Add a UI check that submits each curve.
- **Confidence:** confirmed
- **Effort:** S

## A2-03: "PKCS#8 PEM, encrypted" export with an empty passphrase silently writes the key UNENCRYPTED and reports success
- **Severity:** High
- **Category:** security
- **Location:** `src/renderer/app.js:1846-1868`, `1820-1831`; `src/renderer/index.html:172`; `src-tauri/src/commands/mod.rs:1928`, `1934-1936`; `src-tauri/src/crypto/keys.rs:389-398`
- **Evidence:** `exportSelected()` sends `{ format: 'pkcs8-encrypted', passphrase: '' }` when the field is blank (driver payload: `{"id":"k1","format":"pkcs8-encrypted","passphrase":""}`) and never validates it. Rust: `let pass = passphrase.as_deref().filter(|p| !p.is_empty());` then `"pkcs8" | "pkcs8-encrypted" => keys::export_private_key(&key_data, KeyFormat::Pkcs8, pass)`; `export_pkcs8_private` emits `pem_wrap("PRIVATE KEY", ...)` when `pass` is `None`. The UI then toasts `'Exported pkcs8-encrypted to ' + r.path`. The field only carries the placeholder "Required for an encrypted export" (index.html:172); nothing enforces it (compare `deployConfig`, which does enforce a non-empty passphrase at 2186).
- **Why it is a flaw:** the user chose the "Sealed" format specifically to avoid leaving a plaintext private key on disk; they get exactly that, with a success message that says the opposite. Security-relevant silent downgrade.
- **Proposed fix:** in `exportSelected`, if `SEALED_EXPORT_FORMATS.includes(format) && !passphrase` toast an error and focus `#detailExportPass` before calling Rust; in `key_export_to_file` reject `pkcs8-encrypted` when the passphrase is empty (defence in depth).
- **Confidence:** confirmed
- **Effort:** S

## A2-04: Editing a saved password-auth server silently deletes its saved password
- **Severity:** High
- **Category:** js-logic
- **Location:** `src/renderer/app.js:3856-3857`, `3909`; `src-tauri/src/commands/server.rs:108-114`, `139`
- **Evidence:** `openServerModal` always does `el('srvPassword').value = ''; el('srvSavePw').checked = false;` even when `srv.hasSavedPassword` is true. `submitServerModal` then sends `savedPassword: (method !== 'publickey' && el('srvSavePw').checked) ? el('srvPassword').value : null` -> `null`. Rust: `saved_sealed = match saved_password { Some(p) if !p.is_empty() => Some(seal), _ => None }` and on update `existing.saved_password = saved_sealed;`. Reproduced: editing a `hasSavedPassword:true` server (rename only) posts `savedPassword:null`.
- **Why it is a flaw:** any edit - even renaming - of a password/keyboard-interactive server erases the stored password with no warning; the user is prompted at every connect afterwards (`!srv.hasSavedPassword`). Silent data loss in a routine action.
- **Proposed fix:** in the modal, when editing a server with `hasSavedPassword`, show "Saved password kept - type to replace" and check `srvSavePw` by default; make Rust keep the existing sealed value when `saved_password` is `None` on update and add an explicit clear flag (or send `savedPassword: ''` only for an explicit clear).
- **Confidence:** confirmed
- **Effort:** S

## A2-05: Deploy sheet's Host alias / User / Port fields and live "What this will write" preview do not match what `key_deploy` writes
- **Severity:** High
- **Category:** js-logic
- **Location:** `src/renderer/app.js:2140-2168` (preview), `2192` (call), `2297-2302` (Copy config); `src/renderer/index.html:675-677`, `704-716`; `src-tauri/src/commands/mod.rs:2066-2075`; `src-tauri/src/ssh/mod.rs:120-183`
- **Evidence:** the preview builds `Host ${alias}` / `HostName ${alias}` / `User ${user}` / `Port ${port}` from `#cfgHost/#cfgUser/#cfgPort`. The actual call is `call('key_deploy', { ids, passphrase, strictHostKey })` - host/user/port are never sent. Rust: `SshService::deploy_key(&key.name, ..., Some(&key.name), None, None, None, strict_host_key)`, i.e. alias = key name, hostname/user/port = `None`; the written stanza has `IdentityFile`, `IdentitiesOnly`, `ForwardAgent no`, optional `StrictHostKeyChecking` only. The fields only feed the optional "Also save these as servers" bridge (2204-2227).
- **Why it is a flaw:** the sheet advertises "What this will write ... updates as you type" and "Copy config" copies it, but the real SSH config block is different (different `Host` token, no `HostName/User/Port`). Two more mismatches in the same preview: it wraps the blocks in `# >>> SSHSpan managed >>>` / `# <<< SSHSpan managed <<<` markers (app.js:2167, also promised by index.html:713 and docs/ARCHITECTURE.md:87) but `SshConfig::to_config_string` (config/mod.rs:113-162) emits no markers; and the file written is `ProjectDirs config_dir/ssh/config` (config/mod.rs:259-262), not `~/.ssh/config`, so OpenSSH never reads it and `ssh <alias>` cannot work from this block. The preview is the user's only way to audit a write into their SSH setup.
- **Proposed fix:** either extend `key_deploy` with `hostAlias/hostname/user/port` and pass `cfgHost/cfgUser/cfgPort`, or make `previewConfig` render exactly what Rust writes (alias = key name, no HostName/User/Port, no markers) and remove the dead inputs / relabel them as "for Servers registration only". Reword index.html:666/713 to say the block goes to SSHSpan's own config file.
- **Confidence:** confirmed
- **Effort:** M

## A2-06: The "Change master password" dialog is closed by the 10-second status poll while the user is typing
- **Severity:** High
- **Category:** js-logic
- **Location:** `src/renderer/app.js:1089-1094`, `3320`, `1142`, `4546-4548`
- **Evidence:** the poll calls `refreshVaultStatus(true)`; when the vault is unlocked it takes the final branch `else { hideVaultModal(); if (!wasUnlocked || !silent) await loadKeys(); }`. `showVaultModal('change')` is only valid while unlocked, so the next poll hides it. Reproduced with a fake clock: open change mode, fill the current-password field, advance 10.5 s -> `#vaultModal.hidden === true`, fields lost on reopen (`reopening` resets them, 1037). The comment at 1023-1028 shows the same poll/clear class was already fixed for unlock/create but not for change mode.
- **Why it is a flaw:** the dialog vanishes without a message within 10 s (3 passwords to enter); users pasting from a manager barely finish, others lose input repeatedly. The only way to change the master password is effectively a race against the poll.
- **Proposed fix:** in the unlocked branch hide the modal only when `state.vaultMode !== 'change'` (or only when transitioning from locked), e.g. `else { if (state.vaultMode !== 'change') hideVaultModal(); ... }`.
- **Confidence:** confirmed (reproduced)
- **Effort:** S

## A2-07: Category drag-and-drop never nests and cannot reorder reliably - drop zone classes are cleared before they are read
- **Severity:** High
- **Category:** js-logic
- **Location:** `src/renderer/app.js:705-729` (cleared at 709, read at 711-712); `src-tauri/src/commands/mod.rs:2255-2299`
- **Evidence:** the `drop` handler runs `row.classList.remove('drop-before','drop-after','drop-into');` (709) and then `const before = row.classList.contains('drop-before'); const into = row.classList.contains('drop-into');` (711-712) - both are always false. Reproduced: dropping on the top 10 %, middle and bottom 10 % of "Alpha" all post the identical `{ id:'C', newParentId:null, sortIndex:1 }` although the row carried `drop-before` / `drop-into` at drop time. Even the "after" path is unsound: `newSortIndex = cat.sort_index + 1` collides with the next sibling (Rust only stores the integer, no renumbering), so ties are broken by name.
- **Why it is a flaw:** the tree highlights "drop into" and "drop before", then does neither: nesting by drag is impossible, reordering depends on names. (Only Move to... in the row menu works for reparenting.)
- **Proposed fix:** read `before`/`into` before the `remove(...)` call, or compute the zone from `e.clientY` in `drop`. Renumber siblings (assign contiguous `sort_index` to the new sibling list and send each, or add a Rust `category_reorder`).
- **Confidence:** confirmed (reproduced)
- **Effort:** M

## A2-08: Bitwarden sync reports success and "Nothing to sync." while ignoring per-item errors and server counters
- **Severity:** Medium
- **Category:** js-logic
- **Location:** `src/renderer/app.js:2402-2423`; `src-tauri/src/bitwarden/sync.rs:501-517`
- **Evidence:** the Rust result carries `errors: [...]` (key push/pull/decrypt/import failures and server failures, sync.rs:174,215,226,248,255,282,297,436,469,478,494), `remoteDeleted`, `serversPushed`, `serversUpdatedRemote`, `serversPulled`, `serversUpdatedLocal`. `bwSyncNow` only reads `pushed, pulled, updatedRemote, updatedLocal, linked, conflicts, skippedOverwrites, skippedNew`, then unconditionally shows `toast('Sync complete.', 'ok')`.
- **Why it is a flaw:** (1) a sync where some keys failed to decrypt/push is reported as complete; (2) a sync that only pushed/pulled servers reports "Nothing to sync."; (3) remote deletions are never surfaced. A backup/sync feature must not hide failures.
- **Proposed fix:** include the server counters and `remoteDeleted` in `parts`; if `s.errors.length`, set the status to `err`/warn, toast "Sync finished with N error(s)" and show the first few messages.
- **Confidence:** confirmed
- **Effort:** S

## A2-09: Locking the vault leaves open modals and pasted secrets (private-key PEM, passphrases) in the DOM
- **Severity:** Medium
- **Category:** security
- **Location:** `src/renderer/app.js:3552-3558`, `1085-1096`, `1250-1261`, `1179-1215`
- **Evidence:** `lockNow()` -> `refreshVaultStatus()` -> locked branch only runs `clearKeysUI(); clearConnectView(); showVaultModal('unlock')`. Reproduced: open the Import tab, paste a PEM and passphrase, `lockNow()`: `#modalBackdrop` stays open, `#importPem.value.length === 76`, `#importPass.value.length === 13`, vault modal opens on top. Other secret-bearing fields untouched on lock: `#srvPassword`, `#connectPwInput`, `#keyPassphraseInput`, `#detailExportPass`, `#bw_master_password`. The Cancel / Esc / backdrop path has the same gap: `closeKeyModal()` (2023-2026) only hides the dialog and resets the hint; the PEM and passphrase are cleared only after a successful create/import (2100-2101).
- **Why it is a flaw:** the lock (manual, tray, Ctrl+L) is meant to put secrets out of reach; the half-typed private key stays visible behind the unlock dialog and, after anyone unlocks, is still sitting in the open Import form.
- **Proposed fix:** on every transition to locked: close `modalBackdrop/deployModal/serverModal/connectPwModal/paletteModal/pickerModal/promptModal`, blank the password/PEM inputs listed above, and clear `configPreview`.
- **Confidence:** confirmed (reproduced)
- **Effort:** S

## A2-10: "Cancel" on the unlock/create dialog is undone by the poll within 10 s and the dialog steals focus again
- **Severity:** Medium
- **Category:** ux
- **Location:** `src/renderer/app.js:3164-3167`, `1085-1091`, `1060`, `4546-4548`
- **Evidence:** Cancel does `hideVaultModal(); toast('Vault stays locked - unlock it any time.')`. The next `refreshVaultStatus(true)` finds `!s.unlocked`, calls `showVaultModal('unlock')`, and because the backdrop is hidden `reopening` is true so it re-focuses the password field (1060). Reproduced: Cancel -> hidden; after 10.5 s -> visible again.
- **Why it is a flaw:** the toast promises the opposite of what happens; the dialog pops over whatever the user is doing (e.g. typing in Settings) every 10 s, making the app unusable while locked (e.g. to read the audit log or settings).
- **Proposed fix:** remember the dismissal (`state.vaultDismissed = true`) and only auto-open on the locked-transition; clear the flag on unlock or on an explicit open (menu, Ctrl+N, palette).
- **Confidence:** confirmed (reproduced)
- **Effort:** S

## A2-11: "Test connection" never asks for a password, so it always fails for password / keyboard-interactive servers without a saved password
- **Severity:** Medium
- **Category:** js-logic
- **Location:** `src/renderer/app.js:4139-4155`, `3470-3473`, contrast `4188-4196`; `src-tauri/src/commands/terminal.rs:310-330`; `src-tauri/src/ssh_client/mod.rs:449-453`
- **Evidence:** `testSelectedServer` calls `call('server_test', { serverId: srv.id })` only; `server_test` accepts `promptPassword` and `resolve_for_server` leaves `password = None` when neither a prompt nor a saved password exists; `authenticate` then fails with `No password available for this session.` (after opening a connection and raising the host-key dialog). `openSessionTab` has the prompt (`srv.authMethod !== 'publickey' && !srv.hasSavedPassword`).
- **Why it is a flaw:** the Test button is broken for exactly the servers that need typed passwords and shows a confusing backend error.
- **Proposed fix:** reuse `askConnectPassword` in `testSelectedServer` and pass `promptPassword`.
- **Confidence:** confirmed
- **Effort:** S

## A2-12: Closing a session tab while its connect is in flight leaks the SSH session (never disconnected) and the status strip claims "Connected"
- **Severity:** Medium
- **Category:** js-logic
- **Location:** `src/renderer/app.js:4295-4305`, `4198-4204`; `src/renderer/terminal.js:567-576`, `586-597`
- **Evidence:** `closeSessionTab` disconnects only `if (live)` where `live = window.tabSessionLive(tabId)` is `!!rec.sessionId`, which is `null` until `terminal_connect` resolves; it then `destroyTabTerminal`s and deletes the tab. When `terminal_connect` resolves, `terminalConnectInTab` still does `rec.sessionId = sessionId` on the orphaned record and starts a 1.2 s `terminal_list` poll, and `openSessionTab` does `tab.sessionId = sessionId; ... terminalSetStatus('Connected to ...')`. Reproduced: open tab, close it, resolve the pending connect -> zero `terminal_disconnect` calls, strip reads `Connected to h.example:22 - streaming`.
- **Why it is a flaw:** an authenticated shell stays open on the remote host with no UI handle (until app exit or vault lock); a slow host or a pending host-key dialog makes this easy to hit.
- **Proposed fix:** after the `await` in `terminalConnectInTab`/`openSessionTab`, if the tab/record no longer exists call `terminal_disconnect(sessionId)` and bail; or give `closeSessionTab` a `cancelled` flag the connect path checks.
- **Confidence:** confirmed (reproduced with stub)
- **Effort:** S

## A2-13: The backup-restore password prompt is a plain-text input - the old master password is shown in clear
- **Severity:** Medium
- **Category:** security
- **Location:** `src/renderer/app.js:2892-2900`, `906-913`; `src/renderer/index.html:842`
- **Evidence:** `backupRestore()` asks "Enter the one that was active when the backup was taken" through the generic `promptModal`, whose field is `<input type="text" id="promptInput">`. The OK handler also does `const v = el('promptInput').value.trim();` (3387), so a password with leading/trailing spaces is silently altered before it is sent to `vault_backup_restore`.
- **Why it is a flaw:** a master password is typed visibly (shoulder-surfing, screen share), unlike every other password field in the app (`type="password"` at index.html:623-625, 645), and a password containing edge whitespace can never be entered correctly (the vault modal itself does not trim, 1220).
- **Proposed fix:** give `promptModal` a `secret` option that sets `promptInput.type = 'password'` and skips `trim()` (and resets both in `closePrompt`), or reuse the `connectPwModal` pattern.
- **Confidence:** confirmed
- **Effort:** S

## A2-14: Settings show defaults that are not what is applied (auto-lock "15" vs off; parallel transfers "2" vs 4), and values are saved unvalidated
- **Severity:** Medium
- **Category:** js-logic
- **Location:** `src/renderer/app.js:2506-2518`, `2510`, `2600-2602`, `3568-3569`; `src-tauri/src/commands/mod.rs:429-447`, `2789-2810`, `2836-2855`; `src-tauri/src/sftp/queue.rs:573-585`; `README.md:15`
- **Evidence:** `collect_settings` returns only stored keys (no defaults). Auto-lock: the Settings row shows `state.settings.autoLockMinutes || 15` (2510) but the timer does `parseInt(undefined, 10)` -> `NaN` -> `!mins` -> "auto-lock off". Reproduced with `settings_get: {}`: sidebar `auto-lock off`, Settings input `15`. The Rust watchdog uses `.unwrap_or(15)` although its doc comment says "`autoLockMinutes` of 0/absent disables it, matching the renderer's semantics" (434-435); app.js:3600-3602 repeats that claim and README:15 promises "auto-locks after 15 minutes". Parallel transfers: the row shows `state.settings.sftpParallel || 2` and the handler falls back to 2, but `parallel_limit()` uses `.unwrap_or(4)`. Validation: the auto-lock `change` handler persists `String(autoLock.value)` verbatim (`''`, `-5`, `1.5` all succeed with "Auto-lock updated."), and `settings_set` validates only the key, never the value shape.
- **Why it is a flaw:** the UI states a protection level and a transfer concurrency that are not in effect, and renderer, backend, comments and README each disagree about the default; invalid input is accepted with a success toast (and `''` means "off" to the renderer but 15 to Rust).
- **Proposed fix:** one default per setting shared by both sides (`parseInt(v,10)` -> NaN means 15; UI default 4 for transfers), or persist the defaults at first run; clamp/parse `autoLockMinutes` to an integer 0-1440 before saving and validate value shapes in `settings_set`; fix the Rust comment. Treat an explicit `0` as off.
- **Confidence:** confirmed
- **Effort:** S

## A2-15: `openCategoryPicker({ scope })` permanently changes `state.categoryScope`, so categories get created/filtered in the wrong scope
- **Severity:** Medium
- **Category:** js-logic
- **Location:** `src/renderer/app.js:780-784`, `799-807`, `3281-3286`, `3523-3528`, `578-583`, `2017-2021`, `1940`, `3442-3446`
- **Evidence:** `openCategoryPicker` does `state.categoryScope = scope; rebuildCategoryIndex();` and `closeCategoryPicker` never restores it. The New-key modal (`scope: 'key'`) can be opened from the Servers view (palette "New key...", Ctrl+N both call `openKeyModal()` without switching view); the server modal (`scope: 'host'`) can be opened from the Keys view ("New server with this key..."). Reproduced: on Servers view, open New key -> Browse categories -> Cancel: `state.categoryScope === 'key'` while the sidebar title still reads "Host categories"; then `+` in the sidebar posts `category_create` with `scope:'key'`, so the new host-looking category is created as a KEY category and disappears from the host tree after `loadCategories()` re-syncs the scope. Mirror case, the more common path (Keys view -> right-click key -> "Use this key to connect..." -> "New server with this key..." -> Category "Browse" -> Cancel): `state.categoryScope` stays `'host'` while `state.view === 'keys'` (reproduced), so the key detail pane's "+ Add" chip then offers only HOST categories (`["HostCat"]`), picking one makes `key_set_categories` reject with `Unknown category: <id>` (Rust validates `c.scope == "key"`, mod.rs:2318-2329), and `setActiveCategory` runs `renderServerList()` instead of `renderKeyList()`.
- **Why it is a flaw:** categories land in the wrong scope; sidebar clicks stop filtering the visible list.
- **Proposed fix:** save/restore the previous scope around the picker (`state.pickerPrevScope`), or pass the scope into `renderPickerTree`/`childrenOfScoped` instead of mutating global state.
- **Confidence:** confirmed (reproduced)
- **Effort:** S

## A2-16: The bandwidth-limit "Unlimited" pill does nothing - it toggles twice (handler + enclosing `<label>`) and sends two writes
- **Severity:** Medium
- **Category:** js-logic
- **Location:** `src/renderer/app.js:2658-2664`, `2685-2690`, `2475-2504`; `src/renderer/styles.css:593`
- **Evidence:** the checkbox is `opacity:0; pointer-events:none` (css:593), so the span `bpsUnlimitedTag` is the only visible control; its handler does `bpsUnlimited.checked = !bpsUnlimited.checked; dispatchEvent(new Event('change'))`. `mkRow` wraps every control in `<label class="settings-row">`, and a click on the span also triggers the label's activation, toggling the (first labelable) checkbox a second time. Reproduced: one click on the pill -> `settings_set sftpMaxBps` values `["524288","0"]`, checkbox state unchanged.
- **Why it is a flaw:** the limit field can never be enabled via the pill; each click applies a 512 KB/s limit for an instant then removes it, with two toasts. (Clicking the row's title text toggles it, by accident.)
- **Proposed fix:** drop the manual click handler on the tag (label activation already does it) or call `ev.preventDefault()` in it.
- **Confidence:** confirmed (reproduced)
- **Effort:** S

## A2-18: No in-flight guard on async submit buttons - double-click creates duplicate keys (and double vault submits)
- **Severity:** Medium
- **Category:** js-logic
- **Location:** `src/renderer/app.js:2068-2106` (`submitKeyModal`), `1217-1246` (`submitVaultModal`), `3163`, `3168-3172`, `3310`; contrast `3916-3930` (`submitServerModal._busy`); `src-tauri/src/db/mod.rs:366-381`
- **Evidence:** `#modalPrimary`, `#vaultPrimary` are not disabled while the IPC call is pending and there is no busy flag (the server modal has one, with a comment explaining exactly this bug). Reproduced: with a 500 ms `key_create_with_categories`, a double-click issues 2 calls. `keys.name` has no UNIQUE constraint, so two identical keys are stored (same `Host` alias and `sshspan_<name>` file on deploy: the second deploy overwrites the first). Vault create/unlock: Enter auto-repeat re-enters `submitVaultModal`; a second `vault_create` returns "A vault already exists on this machine." right after the success toast.
- **Why it is a flaw:** RSA-4096 generation takes seconds, so a second click is likely; duplicates and spurious error toasts.
- **Proposed fix:** share the `_busy`+`disabled` pattern from `submitServerModal` across `submitKeyModal`, `submitVaultModal`, `deployConfig`, `backupCreate/Restore`, `bwTest`, `manualUpdateCheck`.
- **Confidence:** confirmed (reproduced for key create)
- **Effort:** S

## A2-19: Picking a `.pem` path for a server reads the whole file and ships its plaintext into the WebView
- **Severity:** Medium
- **Category:** security
- **Location:** `src/renderer/app.js:3505-3510` (and header claim at `6`); `src-tauri/src/commands/mod.rs:2941-2960`
- **Evidence:** the renderer only needs the path (`el('srvPemPath').value = r.path`), but `system_select_file` does `fs::read_to_string(&path_str)` and returns `{ path, name, text }`. For "Select .pem file" that file is a private key. The file header promises "Private key material never reaches this process".
- **Why it is a flaw:** an unencrypted private key crosses IPC into renderer memory just to fill a text box; also reads arbitrarily large files (a multi-GB pick is read fully into memory).
- **Proposed fix:** add a `system_pick_file_path` (or `readText:false` option) that returns only the path; reserve `system_select_file` for the explicit Import/backup flows, with a size cap.
- **Confidence:** confirmed
- **Effort:** S

## A2-20: Several `async` callbacks have no `try/catch`; rejections are only logged, never shown (e.g. adding a category)
- **Severity:** Medium
- **Category:** js-logic
- **Location:** `src/renderer/app.js:623-629`, `578-583`, `3386-3391`, `4476-4479`, `1597-1606`, `2905-2926`
- **Evidence:** `addCategoryPrompt` passes an async callback to `promptModal` that awaits `createCategory(...)` with no try/catch; `promptOkBtn` calls `cb(v)` without awaiting/catching; the global `unhandledrejection` handler only appends to `window.__bootErrors`. Reproduced: `category_create` rejecting ("A category parent must use the same key/host scope.") -> zero toasts, one `unhandled rejection` entry. Same pattern: `loadKeys()` awaits `loadCategories()` unguarded (a `category_list` failure aborts `refreshVaultStatus` and, at boot, the whole `main()` before the poll/auto-lock wiring); `finishRestore` fires `loadKeys(); loadServers();` unawaited/uncaught.
- **Why it is a flaw:** a failed save looks like nothing happened; at boot a single failed call leaves the app half-initialised (no poll, no activity listeners).
- **Proposed fix:** wrap `addCategoryPrompt`'s body and `loadCategories()` callers in try/catch; make the `unhandledrejection` handler also `toast('Unexpected error: ' + msg, 'err')`; guard the boot `await refreshVaultStatus()`.
- **Confidence:** confirmed (reproduced for addCategoryPrompt)
- **Effort:** S

## A2-21: Terminal context menu (and server/ssh-config menus) are not clamped to the viewport
- **Severity:** Medium
- **Category:** ux
- **Location:** `src/renderer/app.js:1299-1301`, `3818-3820`, `2286-2288`, `1573-1574`; helper exists at `3977-3982`
- **Evidence:** `openTerminalContextMenu(x,y,...)` sets `left/top` to the click point and appends; `.ctx-menu` is `position:fixed` with `max-height` but no placement logic. Reproduced: right-click 80 px from the bottom-right of a 1400x900 window -> menu `top:820 bottom:1129 right:1560` (clipped on both axes). `positionCtxMenuAt` is already written (used only by the host picker).
- **Why it is a flaw:** the terminal fills most of the window, so right-clicking its lower half hides "Reset terminal / Restart session / Switch to SFTP" off screen with no way to scroll (fixed position).
- **Proposed fix:** call `positionCtxMenuAt(menu, x, y)` after `appendChild` in all four menu builders.
- **Confidence:** confirmed (reproduced)
- **Effort:** S

## A2-22: Global shortcuts ignore open modals; Ctrl+N flips the Create-vault dialog to "Unlock" and wipes the typed password
- **Severity:** Medium
- **Category:** ux
- **Location:** `src/renderer/app.js:3401-3448`, `3442-3446`, `1029-1037`
- **Evidence:** the keydown handler never consults `modalStack`/open modals. Reproduced: (a) with no vault and the Create dialog showing a typed password, `Ctrl+N` -> `showVaultModal('unlock')` -> title "Unlock vault", mode `unlock`, password field cleared (`reopening` is true because the mode changed); (b) with the New-key modal open, `Ctrl+2` switches the view behind it and `Ctrl+L` locks the vault (Import modal stays open, see A2-09). `Ctrl+1/2/3/,/K/N` all stack views/modals under or over open dialogs.
- **Why it is a flaw:** an accidental chord destroys input or changes state behind a dialog; the unlock mode on a vault that does not exist is a dead end until the next poll.
- **Proposed fix:** early-return in the shortcut handler when `modalStack.length` is non-empty (except `Ctrl+K` handled explicitly and Escape); in the `Ctrl+N` branch use `state.hasVault ? 'unlock' : 'create'`.
- **Confidence:** confirmed (reproduced)
- **Effort:** S

## A2-43: Servers -> "Config" import is described as importing from `~/.ssh/config` but reads SSHSpan's private managed file
- **Severity:** Medium
- **Category:** ux
- **Location:** `src/renderer/app.js:2242-2295`, `3461`; `src/renderer/index.html:188`; `src-tauri/src/commands/mod.rs:2436-2441`; `src-tauri/src/config/mod.rs:259-263`
- **Evidence:** the button title reads "Import a Host block from ~/.ssh/config". `ssh_config_list_hosts` -> `SshConfigService::new()` -> `ssh_config_path()` = `ProjectDirs config_dir/ssh/config` (the app's own file). Nothing else writes to or includes the user's `~/.ssh/config` (grep for `Include`/`.ssh/config` in src-tauri finds only comments). The file only contains blocks SSHSpan itself deployed, which carry no `HostName/User/Port` (A2-05), so an import yields `host = <key name>`, empty username.
- **Why it is a flaw:** a user with a populated `~/.ssh/config` clicks "Config" and always gets `No Host blocks found in <appdir>/ssh/config.` (the toast does name the real path, contradicting the tooltip); the feature cannot import the hosts users actually have. Wildcard blocks (`Host *`, `Host *.example.com`) that do appear are offered as importable servers named `*`.
- **Proposed fix:** make `ssh_config_list_hosts` read `~/.ssh/config` (read-only, skip wildcard/negated patterns and `Match` blocks) or rename the button/tooltip to what it does; filter patterns containing `*`, `?` or `!`.
- **Confidence:** confirmed (by reading)
- **Effort:** M

## A2-44: "Reconnect" opens a new tab for the SELECTED server, not for the ended tab it sits beside
- **Severity:** Medium
- **Category:** js-logic
- **Location:** `src/renderer/app.js:3466-3469`, `4370-4397`, `4243-4269`
- **Evidence:** `#termReconnectBtn` is shown by `updateTerminalHead()` for the ACTIVE tab when its session ended (`hidden = live`, 4380) and its handler is `const srv = currentSelectedServer(); if (srv) openSessionTab(srv);`. `currentSelectedServer()` is `state.connectSelectedId`, which follows the last server-list row clicked, not the active tab. `reconnectActiveTab()` (same tab, keeps scrollback) is reachable only from the terminal context menu's "Restart session". Reproduced: tab for "alpha" ended, "bravo" selected in the list, click Reconnect -> `terminal_connect` for `bravo`, new tab appended, dead alpha tab untouched (tabs: `["sA","sB"]`). It also drops the `overrideKeyId` the first connect used.
- **Why it is a flaw:** the header says "alpha", the button says "Reconnect", and it connects (and may prompt for credentials / raise a host-key dialog) for a different host.
- **Proposed fix:** when an active tab exists call `reconnectActiveTab()`; keep `openSessionTab(currentSelectedServer())` only for the no-tab case (label it "Connect"); remember `overrideKeyId` on the tab record and reuse it.
- **Confidence:** confirmed (reproduced)
- **Effort:** S

## A2-46: Deploying two keys that share a name (or sanitize to the same filename) overwrites the first key's deployed file with the second's
- **Severity:** Medium
- **Category:** rust-logic
- **Location:** `src/renderer/app.js:2140-2168`, `2170-2201`; `src-tauri/src/commands/mod.rs:2047-2090`; `src-tauri/src/ssh/mod.rs:89-104`, `279-288`; `src-tauri/src/db/mod.rs:366-381` (no UNIQUE on `keys.name`); `src-tauri/src/crypto/keys.rs:238-260`
- **Evidence:** key names are not unique (the schema has no constraint; `validate_key_name` only checks shape, and the double-submit in A2-18 produces identical names), and they may contain punctuation (`.`, `:`, `_` ...). `deploy_key` writes `~/.ssh/sshspan_<sanitize_filename(name)>` where every non-alphanumeric, non-`-`/`_` character becomes `_` (ssh/mod.rs:279-288), through `write_secret_file`, which replaces an existing file. So keys `laptop` + `laptop`, or `a.b` + `a_b`, resolve to the same path; `key_deploy` reports success for both, marks both records `deployed` with the same `deploy_path`, and the second private key replaces the first on disk. The preview (`safeFileName`: ASCII-only `\w`, keeps `.`, joins with `-`) shows different file names than Rust writes (`my.key` -> `sshspan_my.key` in the preview vs `sshspan_my_key` on disk; `héllo` -> `h-llo` vs `héllo`), so it cannot reveal the collision.
- **Why it is a flaw:** a server authorised for key A silently starts being offered key B; the vault copy is intact, but the Deployed chip on A is now false. The deploy sheet's preview is the only pre-write check and is wrong for any name containing `.` or non-ASCII characters.
- **Proposed fix:** make the deploy filename injective (append a short key-id suffix), preflight all destinations for duplicates/existing foreign files before writing, return the real path per key, and have `previewConfig` use the same mapping (ideally a `key_deploy_preview` command so both sides share one implementation).
- **Confidence:** confirmed (by code path)
- **Effort:** M

## A2-47: Bitwarden sync overwrites/imports SERVERS without the confirm-first gate, reports none of it, and no sync run is audited
- **Severity:** Medium
- **Category:** security
- **Location:** `src-tauri/src/bitwarden/sync.rs:460-497`, `973-1100`, `501-517`; `src-tauri/src/commands/mod.rs:2579-2657`; `src/renderer/app.js:2391-2423`; `docs/SECURITY.md:169-178`
- **Evidence:** for keys the sync honours `allow_remote_overwrite` (`sync.rs:220`, `331`) and reports `skippedOverwrites` / `skippedNew`, which is all `bwSyncNow` asks the user about (app.js:2402-2413). The server half of `run_sync` has no such gate: `pull_remote_server` (host, port, username, saved password, key link, category) runs whenever the remote is newer (`sync.rs:472-481`) and `pull_new_server` imports every unmatched Login in the servers folder (`sync.rs:484-497`), both unconditionally. The result JSON has no server skip counters, only already-applied counts (`serversPulled`, `serversUpdatedLocal`), which the renderer discards (A2-08). Separately, SECURITY.md:177 lists `sync.push`, `sync.pull`, `sync.run`, `sync.error` audit events, but the only sync audit calls in the code base are `sync.config` (mod.rs:2508) and `sync.folder_migrated` (sync.rs:90); `bitwarden_sync` writes nothing to the audit log.
- **Why it is a flaw:** a changed or injected remote entry silently redirects a saved server (`host`) or adds a new one - and its saved password is sealed under the local vault - while the user is told "Sync complete." / "Nothing to sync."; the documented "Sync is confirm-first" guarantee holds for keys only, and the audit log, which Settings presents as the record of sensitive actions, has no trace of any sync.
- **Proposed fix:** pass `allow_remote_overwrite` into the server passes and count `skippedServerOverwrites` / `skippedServerNew`; extend the renderer confirm to include them; add `sync.run` (summary counts) and `sync.error` audit rows in `bitwarden_sync`, or correct SECURITY.md.
- **Confidence:** confirmed (by reading)
- **Effort:** M

## A2-48: Backup create/restore stream the whole sealed backup through the WebView, contradicting the `vault_export` comment and the file header
- **Severity:** Medium
- **Category:** security
- **Location:** `src/renderer/app.js:6`, `2861-2903`; `src-tauri/src/commands/mod.rs:1002-1009`, `1121-1165`, `2941-2960`
- **Evidence:** the comment on the deliberately unregistered `vault_export` says returning every key's `private_key_encrypted` blob "hands a compromised renderer the entire keystore to attack offline" and that `vault_backup_create` "is the supported export path and keeps the material in the backend". It does not: `vault_backup_create` returns `{ "json": document, "filename", "counts" }` where `document.sealed` is the sealed payload holding every key blob, saved server password and MCP secret, and `backupCreate()` forwards `r.json` back through `system_write_text_file`. Restore is symmetric: `system_select_file` reads the file in Rust and returns `text` to the renderer, which returns it as `payloadJson`.
- **Why it is a flaw:** the exposure the Rust comment cites as the reason for removing `vault_export` is the one `vault_backup_create` has, so a script injected into the renderer can read the full encrypted vault (offline attack against the master password) without any file access, and the app's own header ("Private key material never reaches this process") and comment make a claim the code does not keep.
- **Proposed fix:** add `vault_backup_save_to_file` / `vault_backup_restore_from_file` that run the save/open dialog and read/write in Rust (the `key_export_to_file` pattern, with the generation check) and return only counts; then remove `json` from `vault_backup_create`'s result and `text` from `system_select_file`'s (see A2-19).
- **Confidence:** confirmed (the data flow); impact is ciphertext, hence Medium
- **Effort:** M

## A2-51: If the SSHSpan_Servers folder cannot be created, every folder-less Login in the user's Bitwarden vault is imported as a server (and servers are pushed to the vault root)
- **Severity:** Medium
- **Category:** rust-logic
- **Location:** `src-tauri/src/bitwarden/sync.rs:95-108`, `402-412`, `426-440`, `484-497`
- **Evidence:** `servers_folder_id = match servers_folder { Some(f) => Some(f.id), None => client.create_folder(..).await.ok().and_then(...) }` - any creation failure (network blip, 429, server error) is swallowed into `None`. The remote-server filter then reads `c.cipher_type == 1 && c.deleted_date.is_none() && c.organization_id.is_none() && c.folder_id.as_ref() == servers_folder_id.as_ref()`; with `servers_folder_id == None` this is `None == None`, true for every personal Login that is in no folder. Pass 2 then calls `pull_new_server` for each (username and password decrypted and re-sealed into the local vault, `bitwarden_id` linked; the host comes from `server_host_port`, which splits the first URI on its last `:`, so `https://example.com/login` becomes host `https`, port 22). The push side passes the same `None` folder to `push_local_server`, creating Login items with saved passwords at the vault root. Nothing aborts the server pass when the folder id is `None`. The renderer reports only "Sync complete." (A2-08/A2-47).
- **Why it is a flaw:** one transient error turns a scoped sync into an import of the user's entire non-foldered password vault into SSHSpan (and the reverse), silently, with the confirm-first prompt not applying to servers (A2-47). The same fallback applies to the keys folder (`folder_id`), where keys would be pushed to the vault root.
- **Proposed fix:** if either folder id is `None` after the create attempt, skip that pass (or fail the sync with the create error); never use `None == None` as a folder match; surface create-folder errors in `errors`.
- **Confidence:** likely (logic proven by reading; trigger is a failed `create_folder`)
- **Effort:** S

## A2-53: Keystrokes typed into a terminal never reach app-level handlers: "Esc to restore", Ctrl+Shift+1/2/3 and the idle-timer reset are all dead while a terminal has focus
- **Severity:** Medium
- **Category:** js-logic
- **Location:** `src/renderer/app.js:3401-3434`, `3415`, `4232`, `4537-4540`; `src/renderer/terminal.js:262-274`, `326-329`; `src/renderer/vendor/xterm.js` (5.5.0)
- **Evidence:** all app shortcuts and the auto-lock activity listeners (`['keydown','mousedown','wheel','touchstart']`, 4537-4539) are bubble-phase `document` listeners. Reproduced with the vendored xterm 5.5.0 and focus in `.xterm-helper-textarea`: of `a, Enter, ArrowUp, Backspace, Tab, Ctrl+C, Escape, x` every key reaches `document` in the CAPTURE phase, but the BUBBLE phase sees only the bare `Control` keydown (xterm cancels the rest). Consequences, all reproduced: (1) after `toggleTermMax()` the code focuses the terminal (`fitActiveTerminalAndFocus`) and the strip says "Terminal maximized - press Esc or <> to restore."; pressing Escape leaves `term-max` on. (2) `Ctrl+Shift+2` with the terminal focused leaves the tab in `ssh` mode although the mode buttons advertise Ctrl+Shift+1/2/3 (3419-3434). (3) typing in a terminal does not reset the idle timer; mouse events do bubble (`mousedown`, `wheel` observed).
- **Why it is a flaw:** two advertised shortcuts only work when focus is outside the terminal, i.e. never in the place they are needed; and once A2-01 is fixed, a user who is typing in a shell without touching the mouse will be auto-locked after N minutes, which kills every live SSH session and destroys the terminals (`lock_vault_internal`, `clearConnectView`).
- **Proposed fix:** register the app-level keydown handlers and the idle-timer reset in the capture phase (`document.addEventListener('keydown', h, true)`), or let xterm pass them through via `term.attachCustomKeyEventHandler(ev => !isAppShortcut(ev))`; keep Esc going to the shell and change the status text to point at the `<>` button; decide whether live sessions/transfers should defer the auto-lock.
- **Confidence:** confirmed (reproduced)
- **Effort:** S

## A2-54: Deleting a host category leaves its servers pointing at the dead id - they vanish from every category view and editing one fails to save until the next launch
- **Severity:** Medium
- **Category:** rust-logic
- **Location:** `src-tauri/src/db/mod.rs:1299-1339` (`delete_category`), `575` (the only cleanup, a startup migration); `src-tauri/src/commands/server.rs:95-104`; `src/renderer/app.js:585-597`, `3866-3872`, `3909-3910`, `3698-3699`
- **Evidence:** `delete_category` re-parents children and deletes `key_categories` rows but never touches `servers.category_id` (no foreign key on that column, db/mod.rs:550); `server_list` returns the stale `categoryId`; `deleteCategory()` only re-renders the (stale) `state.servers`. Reproduced with a server whose `categoryId` names a missing category: it is listed under "All" but not under "Uncategorized hosts" (`!s.categoryId` is false) and under no category node; the edit dialog renders one blank chip (`catPathString` of an unknown id is `''`); Save sends `categoryId: "DEAD"` and `server_save` rejects it with `Server category must be a host category.` (it requires `c.id == cid && c.scope == "host"`). The confirm text only promises "keys using this category will become Uncategorized", and the dangling ids are cleared solely by `UPDATE servers SET category_id = NULL ...` in `migrate()` at the next launch.
- **Why it is a flaw:** after deleting a host category that contains servers, those servers are orphaned from the category UI and cannot be edited (rename, change password, ...) until the user notices the invisible chip and removes it, or restarts the app.
- **Proposed fix:** in `delete_category` also run `UPDATE servers SET category_id = NULL WHERE category_id = ?` (or move them to the parent) inside the same transaction, include them in the confirm text, and have the renderer reload servers after a host-scope delete; treat an unknown `categoryId` as null in `openServerModal`.
- **Confidence:** confirmed (renderer side reproduced; Rust side by reading)
- **Effort:** S

## A2-17: Breadcrumb / "Clear filter" is not refreshed on view switch, so it lingers in Settings and on the wrong scope in Servers
- **Severity:** Low
- **Category:** js-logic
- **Location:** `src/renderer/app.js:3084-3127` (no `updateBreadcrumb()`), `734-775`; `src/renderer/index.html:63`
- **Evidence:** `#breadcrumb` lives in the shared top bar. Reproduced: on Keys select category "Alpha", then `switchView('settings')` -> breadcrumb still visible with text `Keys/AlphaClear filter` beside the "Settings" title. In Servers it keeps showing the key path; its "Clear filter" calls `setActiveCategory('all')` for the host scope and clears nothing.
- **Why it is a flaw:** stale, misleading chrome; the filter cannot be cleared from where it is shown.
- **Proposed fix:** call `updateBreadcrumb()` at the end of `switchView` (after the scope is set).
- **Confidence:** confirmed (reproduced)
- **Effort:** S

## A2-23: Category tree counts are direct-only, but selecting a category lists every descendant's keys/hosts
- **Severity:** Low
- **Category:** js-logic
- **Location:** `src/renderer/app.js:381-394`, `492-493`, `414-427`, `438-447`, `3681-3699`
- **Evidence:** `catNodeEl` shows `categoryCount(cat.id)` = `directKeyCount` / `directHostCount` (exact membership only), while `filteredKeys()` / `renderServerList()` use `keysInCategoryRecursive` / `hostsInCategoryRecursive`. A recursive `totalKeyCountFor` exists but is never called. Reproduced: Prod (child EU holds 1 key) shows count `0`; clicking Prod lists 1 key.
- **Why it is a flaw:** the badge contradicts the list it filters ("Prod 0" opens a populated list). 
- **Proposed fix:** show the recursive count (de-duplicated by key id, unlike `totalKeyCountFor`, which double-counts a key filed under both a parent and a child) or label the badge "direct".
- **Confidence:** confirmed
- **Effort:** S

## A2-24: User-visible build marker is a stale dev label (`v14-tabs`) instead of the app version (1.9.1)
- **Severity:** Low
- **Category:** ux
- **Location:** `src/renderer/app.js:4481-4482`, `4520`, `3122`; `src-tauri/tauri.conf.json:4`
- **Evidence:** `window.__SSHPAN_BUILD__ = 'v14-tabs';;;` drives `document.title`, the sidebar brand line ("KEYS & SESSIONS - v14-tabs", observed) and the Servers status strip ("Ready. (build v14-tabs)", observed). The app is 1.9.1 (tauri.conf.json, Cargo.toml, package.json); `window.__SSHPAN_TERMINAL_JS__` is likewise `'loaded-v14-tabs'` (terminal.js:24).
- **Why it is a flaw:** every screen shows a build id that matches no release; bug reports will quote it.
- **Proposed fix:** read the real version once (e.g. a `app_version` command or the existing `update_check` `current`) and display `v1.9.1`; delete the dead `v14` marker.
- **Confidence:** confirmed
- **Effort:** S

## A2-25: The terminal status strip is overwritten with "Ready. (build ...)" on every visit to Servers and during every connect
- **Severity:** Low
- **Category:** ux
- **Location:** `src/renderer/app.js:3117-3123`, `4162-4167`, `4186`, `4141-4152`
- **Evidence:** `openSessionTab` sets `terminalSetStatus('Connecting to ...')` right after calling `switchView('connect')` (4167, not awaited); `switchView` then `await loadServers()` and finally sets `#termStrip` to `'Ready. (build ...)'`. Reproduced: with `terminal_connect` pending the strip reads `Ready. (build v14-tabs)`. Switching Settings -> Servers does the same while a session is live. `testSelectedServer` also writes "Connection test failed."/"Connection OK" over the live session's status.
- **Why it is a flaw:** the only connection-progress indicator lies while connecting, and live-session status is lost on navigation.
- **Proposed fix:** only write the idle text when there is no active tab; do not call `switchView` from `openSessionTab` when already on Connect; scope test status to a separate element or a toast.
- **Confidence:** confirmed
- **Effort:** S

## A2-26: A search/filter with no matches leaves a blank list with no message (keys and servers)
- **Severity:** Low
- **Category:** ux
- **Location:** `src/renderer/app.js:1337-1352`, `3692-3712`
- **Evidence:** `renderKeyList` does `if (rows.length === 0) return;` after clearing the list and hiding the empty state only when `total > 0`; there is no "no matches" element in index.html. Reproduced: typing `zzzz-no-match` leaves `#keyList` with 0 children and `#emptyState` hidden (count chip still says "1 key"). `renderServerList` likewise renders an empty `<div>` when the search/category filter excludes everything.
- **Why it is a flaw:** indistinguishable from a broken list.
- **Proposed fix:** render a "No keys match ..." / "No servers match ..." row with a "Clear filter" action.
- **Confidence:** confirmed
- **Effort:** S

## A2-27: Category row menu shows no icons - `data-ico` spans are created after `injectIcons()` already ran
- **Severity:** Low
- **Category:** ui
- **Location:** `src/renderer/app.js:645-659`, `289-300`
- **Evidence:** `openCatMenu` builds `<span data-ico="pencil"></span>` etc. via `innerHTML`; `injectIcons()` runs once at boot (4484). Reproduced: the four spans have `innerHTML.length === 0`.
- **Why it is a flaw:** every other context menu uses `ico(...)` inline; this one is the odd one out and renders blank icon slots.
- **Proposed fix:** build the buttons with `${ico('pencil')}<span>Rename</span>` like `openVaultMenu` does.
- **Confidence:** confirmed
- **Effort:** S

## A2-28: ECDSA keys get a grey list avatar (no `ecdsa` mapping) while the detail pane tints them
- **Severity:** Low
- **Category:** ui
- **Location:** `src/renderer/app.js:308-317`, `1474`, `1633`; `src-tauri/src/crypto/keys.rs:63-71`; `src/renderer/styles.css:424-427`
- **Evidence:** `keyAvatar` looks the DB tag up in `{ ed25519, 'ed25519-sk', rsa, ecdsa }`, but stored tags are `ecdsa-p256/p384/p521`, so `dataset.type === ''` (grey). The detail pane uses `key_type.split('-')[0]`. Reproduced: list `""`, detail `"ecdsa"` for `ecdsa-p256`.
- **Why it is a flaw:** inconsistent type colouring; the `ed25519-sk` entry is for a type the app cannot store.
- **Proposed fix:** use `String(kind).split('-')[0]` in `keyAvatar`, as `typeBadge`/detail do.
- **Confidence:** confirmed
- **Effort:** S

## A2-29: Async loaders clear-then-await-then-append, so overlapping calls duplicate rows; `selectKey` has no stale-response guard; `loadKnownHosts` hides failures
- **Severity:** Low
- **Category:** js-logic
- **Location:** `src/renderer/app.js:2927-2972` (known hosts; also invoked from `2855` and `3109`, i.e. twice per Settings open), `2976-3023` (audit), `2321-2353` (Bitwarden grid), `1617-1690` (`selectKey`)
- **Evidence:** reproduced with delayed stub replies: two overlapping `loadKnownHosts()` leave 2 rows for 1 host; two out-of-order `key_get` calls leave `state.selectedId === 'B'` while the pane shows key A, so Delete/Export/Rename (which act on `selectedId`) target a different key than the one displayed. `loadKnownHosts`'s `catch` sets the "No hosts pinned yet" empty state and a blank table on error (no toast). In the real app these calls are FIFO main-thread commands, so exposure is narrow (hence Low), but nothing in the renderer guarantees the order.
- **Why it is a flaw:** duplicate rows; a failure presented as "nothing pinned"; a theoretical wrong-key action.
- **Proposed fix:** build rows into a fragment and `replaceChildren` after the await; keep a per-loader request counter and drop stale results (`if (id !== state.selectedId) return;` in `selectKey`); toast in the `known_hosts_list` catch; drop the duplicate `loadKnownHosts()` in `loadSettings`.
- **Confidence:** confirmed (stub), likely rare in practice
- **Effort:** S

## A2-30: After a backup restore the renderer keeps stale settings (auto-lock, confirm-delete, update check) and stale Settings rows
- **Severity:** Low
- **Category:** js-logic
- **Location:** `src/renderer/app.js:2905-2926`; `src-tauri/src/db/mod.rs:2345-2358`
- **Evidence:** `restore_backup` writes every `settings` key into the `config` table, but `finishRestore` only reloads keys and servers; `state.settings` and the rendered Settings controls keep the pre-restore values until the Settings view is reopened. `resetAutoLockTimer`, `deleteSelected*` (`confirmDelete`) and `terminalSetting()` read `state.settings`.
- **Why it is a flaw:** the app behaves per old settings while the DB holds the restored ones; the next toggle re-persists the stale value for that key.
- **Proposed fix:** in `finishRestore` re-run `state.settings = await call('settings_get'); applyUiScale(...); resetAutoLockTimer(); loadSettings();`.
- **Confidence:** confirmed (by reading)
- **Effort:** S

## A2-31: "N child(ren) reassigned" after deleting a category is wrong - the backend returns every child of the deleted node's parent
- **Severity:** Low
- **Category:** js-logic
- **Location:** `src/renderer/app.js:595`; `src-tauri/src/db/mod.rs:1325-1337`
- **Evidence:** after re-parenting, `delete_category` selects `id FROM categories WHERE parent_id IS <parent>` (siblings included; for a root node that is EVERY root category of BOTH scopes) and returns it as `reassigned`; the renderer prints `res.reassigned.length`.
- **Why it is a flaw:** deleting a leaf root category with 5 other root categories toasts "5 child(ren) reassigned".
- **Proposed fix:** capture the child ids before the `UPDATE` and return those.
- **Confidence:** confirmed (by reading)
- **Effort:** S

## A2-32: Audit-log CSV export does not neutralise spreadsheet formulas
- **Severity:** Low
- **Category:** security
- **Location:** `src/renderer/app.js:3028-3031`, `3041-3044`; `src-tauri/src/crypto/keys.rs:238-260`; `src-tauri/src/commands/server.rs:68-70`
- **Evidence:** `csvField` only quotes and doubles `"`. The `detail` column carries key names (`validate_key_name` allows a leading `=`, `+`, `-`, `@`), server names/hosts (`server.save` -> `"{name} @ {host}:{port}"`, names only trimmed) and file paths. A cell such as `=HYPERLINK(...)` is evaluated by Excel/LibreOffice when the exported file is opened.
- **Why it is a flaw:** classic CSV injection; exposure needs a crafted name (own input, or one synced from Bitwarden), hence Low.
- **Proposed fix:** prefix cells that start with `= + - @ \t \r` with a single quote (OWASP guidance) inside `csvField`.
- **Confidence:** suspected (reachability depends on name provenance)
- **Effort:** S

## A2-33: "Also save these as servers" validates alias/user only AFTER the deploy and after the sheet has closed
- **Severity:** Low
- **Category:** js-logic
- **Location:** `src/renderer/app.js:2192-2209`
- **Evidence:** the order is `key_deploy` -> `closeDeploySheet()` -> `state.deploySelected.clear()` -> `loadKeys()` -> only then `if (!alias || !user) { toast('Enter a Host alias and User to register servers.', 'info'); return; }`.
- **Why it is a flaw:** the keys are already written, the dialog is gone, so the hint asks the user to fill fields they can no longer reach and the register toggle silently does nothing.
- **Proposed fix:** validate `deployRegisterToggle` + alias/user before the confirm/`key_deploy`.
- **Confidence:** confirmed
- **Effort:** S

## A2-34: Dead and copy-pasted code
- **Severity:** Low
- **Category:** js-logic
- **Location:** `src/renderer/app.js:393`, `396-406`, `414-416`, `996`, `1013`, `1192`, `1291-1292`, `1457`, `2299`, `3858`, `4438`
- **Evidence:** `categoryIdsForScope`, `totalKeyCountFor`, `keysInCategory` have no callers; `state.activeCategoryId` (property) and `state._pendingConnectKey` are written but never read; "New session" and "Duplicate session" in the terminal menu run the identical `openSessionTab(srv)`; `keyRowEl(k, groupKeys)` ignores `groupKeys`; `setConnectAuthMethod(srv ? srv.authMethod : (keyId ? 'publickey' : 'publickey'))` has two identical branches; `copyConfig` says "preview first" though the preview is always live; the comment header at 4438 is duplicated/garbled and sits above `systemPaths` instead of `escapeHtml`; `wire()` ends with `if (typeof initTerminal === 'function') initTerminal();` (3549) but terminal.js is loaded after `wire()` runs (4511), so the call never happens (it is a no-op stub there anyway, terminal.js:617); the `vault-locked-by-watchdog` event the Rust watchdog emits (commands/mod.rs:461) has no listener.
- **Why it is a flaw:** misleading dead branches (the unused recursive counter is the one the tree badge should have used, A2-23).
- **Proposed fix:** delete or wire them; make "Duplicate session" distinct or drop it.
- **Confidence:** confirmed
- **Effort:** S

## A2-35: "Use this key to connect" lists password / keyboard-interactive servers, but the key override is silently ignored for them
- **Severity:** Low
- **Category:** js-logic
- **Location:** `src/renderer/app.js:4040-4087`, `4189-4196`; `src-tauri/src/commands/terminal.rs:93-95`
- **Evidence:** the host picker offers every saved server and calls `openSessionTab(s, { overrideKeyId })`; `resolve_for_server` applies `override_key_id` only when `auth_method == "publickey"`. For a password server the user gets a password prompt and connects with the password.
- **Why it is a flaw:** the action's promise ("connect with this key") is not honoured and nothing says so.
- **Proposed fix:** filter the picker to `authMethod === 'publickey'` servers (or show them disabled with a hint), or let the override switch the method.
- **Confidence:** confirmed
- **Effort:** S

## A2-36: Category picker keyboard: ArrowUp from the initial state lands on the second-to-last row
- **Severity:** Low
- **Category:** js-logic
- **Location:** `src/renderer/app.js:3363-3371`, `788`, `3354`
- **Evidence:** `state.pickerActive` starts (and resets on every input) at `-1`; `(state.pickerActive + delta + rows.length) % rows.length` with `delta = -1` gives `n-2`. Reproduced: 4 rows, one ArrowUp highlights "CatC" (expected "CatD").
- **Why it is a flaw:** off-by-one in keyboard navigation.
- **Proposed fix:** treat `-1` specially: `pickerActive < 0 ? (delta < 0 ? rows.length - 1 : 0) : ...`.
- **Confidence:** confirmed
- **Effort:** S

## A2-37: The New-key modal carries state over: previous categories stay selected and it reopens on the last-used tab
- **Severity:** Low
- **Category:** ux
- **Location:** `src/renderer/app.js:3292-3298`, `2017-2026`, `2099-2102`
- **Evidence:** after a successful create the code clears name/comment/PEM fields but not the closure `store = { generate: [], import: [] }` behind the category chips, so the next key silently inherits them (reproduced: chips `["Prod"]` on the second open). `openKeyModal()` never calls `switchTab('generate')`, so after using Import the "New key" button opens the Import tab and focuses the hidden `#genName` (reproduced).
- **Why it is a flaw:** keys can be filed under the wrong categories without the user noticing; the dialog does not open where the button implies.
- **Proposed fix:** reset `store` and call `switchTab('generate')` in `openKeyModal()` (or in `closeKeyModal()`).
- **Confidence:** confirmed
- **Effort:** S

## A2-39: Server port is not range-checked in the renderer, so an invalid port surfaces as a raw serde error
- **Severity:** Low
- **Category:** js-logic
- **Location:** `src/renderer/app.js:3894`, `2219`, `2145`; `src-tauri/src/commands/server.rs:55`; `src/renderer/index.html:677`, `790`
- **Evidence:** `parseInt(el('srvPort').value, 10) || 22` accepts 70000 / -5 (the `min/max` attributes only constrain the spinner). `server_save` takes `port: Option<u16>`; Tauri rejects out-of-range values with a ``invalid args `port` for command ...: invalid value ... expected u16`` string that the catch shows verbatim.
- **Why it is a flaw:** an internal argument-decoding message is shown to the user; for 0 the renderer silently substitutes 22.
- **Proposed fix:** validate `1 <= port <= 65535` in `submitServerModal` (and the deploy "register" path) with a friendly toast.
- **Confidence:** likely
- **Effort:** S

## A2-40: Escape handling gaps - prompt / connect-password dialogs leak the keystroke to the global handler and ignore Escape when a button has focus
- **Severity:** Low
- **Category:** ux
- **Location:** `src/renderer/app.js:3392-3395`, `3541-3544`, `3401-3418`
- **Evidence:** the `#promptInput` and `#connectPwInput` handlers close their dialog on Escape but do not `stopPropagation()`, so the document handler also runs. Reproduced: with the terminal maximized, Escape in the password prompt closes the prompt AND exits maximize. Conversely, Escape with focus on a prompt's OK/Cancel button does nothing (reproduced: prompt stays open) because neither `promptModal` nor `connectPwModal` is in the global Escape chain.
- **Why it is a flaw:** one keypress can unwind two layers; another does nothing.
- **Proposed fix:** add both modals to the global Escape chain (cancelling `connectPw` with `null`) and `stopPropagation()` in the input handlers, as the picker already does.
- **Confidence:** confirmed
- **Effort:** S

## A2-41: Update check says "You are on the latest version" when a newer release exists but has no installer for this OS
- **Severity:** Low
- **Category:** js-logic
- **Location:** `src/renderer/app.js:3611-3630`; `src-tauri/src/commands/updater.rs:341-350`
- **Evidence:** Rust returns `available: available && asset_url.is_some()`, so a newer tag without a matching asset yields `available:false` with `version` set; the renderer treats `!r.available` as "latest".
- **Why it is a flaw:** wrong message; the user is told they are current while a release exists.
- **Proposed fix:** return `newer: bool` separately (and surface "version X exists but has no installer for this platform").
- **Confidence:** confirmed (by reading)
- **Effort:** S

## A2-42: Public-key exports use a blob `<a download>` that may silently do nothing under WebKitGTK, yet always toast "Exported"
- **Severity:** Low
- **Category:** js-logic
- **Location:** `src/renderer/app.js:230-240`, `1858-1862`
- **Evidence:** `download()` clicks a detached anchor on a `URL.createObjectURL` blob and the caller toasts `'Exported ' + format + '.'` without any confirmation. The same file already documents WebKitGTK clipboard quirks (242-249), and its other file outputs (backup, audit CSV, private-key export) go through `system_pick_save_path` + a Rust write. Smaller: `EXPORT_EXT['public-pem']` is `.pub` (1757-1763) although the content is an SPKI PEM, not the OpenSSH public-key format tools expect from a `.pub` file.
- **Why it is a flaw:** on Linux the public-key / authorized_keys export may write nothing while reporting success (not verifiable in this environment).
- **Proposed fix:** route public exports through `system_pick_save_path` + `system_write_text_file` like the other exports (or offer Copy only).
- **Confidence:** suspected (platform behaviour not testable here)
- **Effort:** S

## A2-45: A cyclic category graph restored from a backup makes categorized keys disappear and makes the palette fail
- **Severity:** Low
- **Category:** js-logic
- **Location:** `src/renderer/app.js:371-377`, `1363-1419`, `1929-1936`; `src-tauri/src/db/mod.rs:2107-2135`
- **Evidence:** backup restore accepts every category's `parent_id` verbatim; no existence or cycle validation. In the default grouped key list, `rootCats` includes only null/missing-parent nodes, so a pure A<->B cycle has no root; categorized keys in it enter no group and are not "Uncategorized". Reproduced with A.parent=B, B.parent=A, key k1 linked to A: `state.keys.length === 1`, zero rendered rows/groups. `paletteCandidates` calls `catPathString` on each category; `catPath` has no visited set: measured `catPathString('A')` on the 2-cycle blocks the renderer main thread for about 3 s (growing an array to the engine limit) and then throws `Invalid array length`; `openPalette()` therefore freezes the window and ends with an open, empty palette (`paletteRows: 0`, error captured in `window.__bootErrors`). `keyRowEl`'s `distinctTop` walk (1491-1493) has the same unbounded cycle for a multi-category key.
- **Why it is a flaw:** a backup can make keys unreachable from the UI and break the command palette; app-side CRUD prevents new cycles but restore is a confirmed input path.
- **Proposed fix:** validate/repair parent links during restore (same-scope, existing parent, acyclic); add visited sets to `catPath`, the distinct-top walk and any recursive UI traversal; treat rootless components as roots (or show them under "Uncategorized / invalid categories").
- **Confidence:** confirmed (reproduced)
- **Effort:** M

## A2-49: Change-password dialog: the first field is the NEW password but is labelled "Master password", and "Current password" comes last
- **Severity:** Low
- **Category:** ux
- **Location:** `src/renderer/app.js:1021-1061`, `1229-1234`; `src/renderer/index.html:623-625`
- **Evidence:** `showVaultModal('change')` only swaps the title, text and button; the DOM order and placeholders are the shared ones: `vaultPassword` ("Master password") -> `vaultPasswordConfirm` ("Confirm password") -> `vaultPasswordCurrent` ("Current password"). In `change` mode `vaultPassword` is submitted as `newPassword`, and the first field is the one focused (1060). A user who types the password they know into the first box gets "Passwords do not match." or, once matching, "Current master password is incorrect." with the wrong field selected (`pwEl.select()`, 1244).
- **Why it is a flaw:** an easy way to mis-enter the one credential whose loss is unrecoverable ("There is no recovery"); the failure counts toward the unlock throttle (`vault_change_password` calls `throttle.record_failure`).
- **Proposed fix:** in change mode reorder or relabel: set `placeholder`s per mode ("New master password" / "Confirm new password"), put `vaultPasswordCurrent` first and focus it.
- **Confidence:** confirmed
- **Effort:** S

## A2-50: Context menus (key, server, terminal, vault, category, ssh-config import) ignore Escape and leave `aria-expanded="true"`
- **Severity:** Low
- **Category:** a11y
- **Location:** `src/renderer/app.js:1122-1165`, `1263-1307`, `1550-1595`, `3794-3826`, `2242-2295`, `641-675`, `3401-3418`
- **Evidence:** every one of these menus is dismissed only by a `mousedown` outside it; the global Escape chain has no branch for them (only the host picker installs a `keydown` handler, 4121-4134). `openVaultMenu` sets `aria-expanded="true"` on the anchor and resets it only in `onVaultMenuOutside`, so choosing an item leaves it `true`; mousedown on the anchor closes the menu and the following click reopens it, so the button cannot toggle it shut. No menu moves focus into itself or supports arrow keys.
- **Why it is a flaw:** keyboard-only users can open (via the Connect button / context-menu key) a menu they cannot dismiss or operate without the mouse.
- **Proposed fix:** one shared helper that registers Escape and outside-click together, focuses the first item, supports Up/Down, and resets `aria-expanded` on close.
- **Confidence:** confirmed (by reading)
- **Effort:** M

## A2-52: Bitwarden "Test connection" / "Sync now" use the SAVED config; edits in the visible form are silently ignored
- **Severity:** Low
- **Category:** ux
- **Location:** `src/renderer/app.js:2321-2353`, `2380-2389`, `3323-3334`; `src-tauri/src/commands/mod.rs:2513-2549`
- **Evidence:** `bwTest()` calls `bitwarden_test_connection` with no arguments; Rust reads the stored `server_url`, `email` and sealed master password. A user who fills the form and presses "Test connection" before "Save" (the natural order) gets `No server URL configured.` or `No master password stored. Re-save the sync settings.`; after changing only the URL on an already-configured account, the test still hits the old server and reports `Connection OK.` The form does not say which values are being tested.
- **Why it is a flaw:** a misleading success for the wrong configuration, and a dead end on first use.
- **Proposed fix:** have "Test connection" save first (or accept the form values as optional overrides) and label the status line with the server and account that were actually tested (`server`/`account` are already returned by Rust and discarded).
- **Confidence:** confirmed
- **Effort:** S
