# A7 - Rust backend logic audit

- **Counts:** Critical 1 | High 9 | Medium 28 | Low 21 (total 59); findings are ordered by severity, ids are sequential in that order.
- **Covered (read in full):** commands/mod.rs, commands/sftp.rs, commands/terminal.rs, commands/server.rs, commands/updater.rs, lib.rs, main.rs, db/mod.rs, sftp/mod.rs, sftp/queue.rs, ssh_client/mod.rs, ssh/mod.rs, config/mod.rs, bitwarden/sync.rs, bitwarden/mod.rs, assistant/mod.rs, assistant/mcp.rs (non-test part), crypto/keys.rs, crypto/putty.rs, crypto/pkcs8.rs, crypto/vault.rs, crypto/utils.rs, tauri.conf.json, capabilities/default.json; every `#[tauri::command]` was matched to its renderer call site (argument types, response fields, error strings). Dependency sources (russh 0.63.2, russh-sftp 2.4.0, sqlx-sqlite 0.8.6, tauri 2.11.5, ssh-key 0.6.7) were read where a claim depended on them.
- **NOT covered:** bitwarden/ssrf.rs and crypto/bitwarden.rs (security reviewer's area; only skimmed), the `#[cfg(test)]` half of assistant/mcp.rs and the bodies of tests/mcp_integration.rs (names only), examples/, scripts/. No Rust was compiled or run (hard rule); the one empirical check was the Windows `icacls` sequence from A7-01, run directly against a scratch file under .superpowers/audit/scratch/A7/.
- **Confidence notes:** items marked `likely`/`suspected` depend on platform or third-party behaviour that could not be executed here (Windows UAC/CreateProcess semantics, console-window flashing, notify event mapping for atomic-save editors, provider API validation, SQLite lock timing).
- **Method:** read-only review by reading; severity per AUDIT-CONTEXT.md; renderer-only issues are left to the other auditors unless the root cause is in Rust or the contract.

---

## A7-01: On Windows every private-key write fails: `icacls /grant:r <bare SID>:F` is rejected, so key deploy, private-key export and backup export can never succeed
- **Severity:** Critical
- **Category:** rust-logic
- **Location:** `src-tauri/src/ssh/mod.rs:299-358` (`restrict_windows_file`, grant at 345-355), `ssh/mod.rs:58-67` (`write_secret_file` deletes the file on error), callers `commands/mod.rs:1445` (`system_write_text_file`: backup + CSV export), `commands/mod.rs:1967` (`key_export_to_file`), `ssh/mod.rs:101` (`deploy_key` -> `key_deploy`)
- **Evidence:** the code parses the user's SID from `whoami /user /fo csv` and runs `icacls <path> /grant:r <SID>:F` with the SID as a bare string (`format!("{}:F", sid)`), after `icacls <path> /inheritance:r`. I reproduced exactly this sequence on this Windows 11 build (22631) against a scratch file: `/inheritance:r` succeeds (leaving an EMPTY DACL), then `/grant:r S-1-5-21-62050738-523915034-210444172-1001:F` fails with `S-1-5-21-...-1001: No mapping between account names and security IDs was done.` (exit 1332 / 52). The same call with the documented `*` prefix (`/grant:r *S-1-5-21-...-1001:F`) succeeds and yields `RYZEN-MAIN\Andrei:(F)`. `git show 4901d47` shows the original code wrapped both icacls calls in `let _ =` (failure silently ignored, so keys were left with an empty DACL); `git show 4683aeb` (2026-09-12, "fix audit findings") made them fail-closed (`bail!` on non-zero status) without changing the SID spelling. From that commit on, `restrict_windows_file` always errors, `write_secret_file` removes the file and returns `Could not restrict permissions on <path>: icacls /grant:r failed: ...`.
- **Why it is a flaw:** on Windows, the primary platform, three headline features are dead: Deploy (`key_deploy`), private-key export to file (all four formats), and Backup creation (`vault_backup_create` -> `system_pick_save_path` -> `system_write_text_file`; the audit CSV export uses the same command). The user gets the cryptic icacls error and no file. CI never sees it: `ci.yml` runs `cargo test` on ubuntu-latest only, the only secret-file tests are `#[cfg(unix)]` (`ssh/mod.rs:371-432`), and `tests/integration.rs:618-651` (`key_deploy_creates_files`) discards the result (`let _ = result;`), so even the Windows leg of `release.yml` would not notice.
- **Proposed fix:** use `format!("*{}:F", sid)` (or resolve the account name with `%USERDOMAIN%\%USERNAME%`), and grant before removing inheritance (or use `/inheritance:r /grant:r *SID:F` in ONE icacls invocation) so a failure can never leave an empty DACL. Add a `#[cfg(windows)]` test that writes a file via `write_secret_file` and asserts `icacls` shows exactly one ACE for the current user, and run `cargo test` on `windows-latest` in `ci.yml`.
- **Confidence:** confirmed (the exact icacls call reproduced on Windows 11; the Rust binary itself was not executed because cargo must not be run)
- **Effort:** S

## A7-02: Generating an ECDSA key from the UI always fails ("Unknown key type: ecdsa-nistp256")
- **Severity:** High
- **Category:** ipc
- **Location:** `src/renderer/index.html:574-580`, `src/renderer/app.js:2073-2076`, `src-tauri/src/crypto/keys.rs:73-82`, `src-tauri/src/commands/mod.rs:2354`
- **Evidence:** the curve `<select id="genCurve">` has option values `nistp256` / `nistp384` / `nistp521`. `submitKeyModal` (app.js:2073-2076) builds the key type as the string "ecdsa-" followed by the selected curve value (fallback `'p256'` only if empty), i.e. `"ecdsa-nistp256"`. `key_create_with_categories` does `KeyType::from_db_tag(&key_type)`, and `from_db_tag` only accepts `"rsa" | "ed25519" | "ecdsa" | "ecdsa-p256" | "ecdsa-p384" | "ecdsa-p521"`; anything else hits `other => anyhow::bail!("Unknown key type: {other}")`. `call()` (app.js:22) forwards args untouched, and the select always has a value so the `|| 'p256'` fallback never fires. `scripts/check-ipc-args.js` checks argument NAMES only, and the integration tests call `generate_key_pair` directly with `KeyType::EcdsaP256`, so nothing exercises this path.
- **Why it is a flaw:** README.md:140 and the New Key dialog advertise ECDSA (nistp256/384/521). Every attempt, for every curve, ends in a toast "Unknown key type: ecdsa-nistp256" and no key is created. ECDSA generation is unusable from the shipped UI.
- **Proposed fix:** make the contract one-sided. Either change the `<option value>`s to `p256|p384|p521`, or accept the SSH names in `KeyType::from_db_tag` (`"ecdsa-nistp256" | "ecdsa-p256"` etc.). Add a Rust unit test that feeds every `genCurve` option value through `from_db_tag`.
- **Confidence:** confirmed
- **Effort:** S

## A7-03: `key_import` only accepts OpenSSH and PPK; the README/UI promise PKCS#8, PEM, SPKI and authorized_keys, and SSHSpan cannot re-import its own PKCS#8 export
- **Severity:** High
- **Category:** rust-logic
- **Location:** `src-tauri/src/commands/mod.rs:1743-1751`, `src-tauri/src/crypto/pkcs8.rs:19,31,244` (export-only API), `README.md:142-143`, `src/renderer/index.html:594`
- **Evidence:** `key_import` branches on `pem.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----")`, then `crypto::putty::looks_like_ppk(pem)`, otherwise `return Err("Unsupported key format. Expected an OpenSSH private key ... or a PuTTY .ppk file.")`. `pkcs8.rs` exposes only `private_key_to_pkcs8_der`, `public_key_to_spki_der`, `encrypt_private_key_info_pbes2_der` - no parser. A repo-wide search finds no importer for `BEGIN PRIVATE KEY`, `BEGIN RSA PRIVATE KEY`, `BEGIN EC PRIVATE KEY`, `BEGIN ENCRYPTED PRIVATE KEY`, SPKI public PEM or an `authorized_keys` line. Meanwhile README.md:142 says "Import - ... OpenSSH private (incl. passphrase-protected), PKCS#8 PEM, PEM public, `authorized_keys` lines, and PuTTY `.ppk` v3 and legacy v2" and index.html:594 tells the user to paste "OpenSSH / PKCS#8 / PEM private key, PuTTY .ppk v3, SPKI public PEM, or authorized_keys line".
- **Why it is a flaw:** the most common key file in the wild (`-----BEGIN RSA PRIVATE KEY-----`, e.g. AWS EC2 `.pem`) and the app's OWN "PKCS#8 PEM" / "PKCS#8 PEM, encrypted" exports are rejected on import, so the export -> import round trip the feature set implies does not exist. The user sees "Unsupported key format" for formats the dialog told them to paste.
- **Proposed fix:** either add parsers (the `ssh-key`/`pkcs8`/`rsa`/`p256` crates already in Cargo.toml can decode PKCS#1/PKCS#8 and PBES2 `ENCRYPTED PRIVATE KEY`; wrap into `PrivateKeyData`), or correct README.md:142-143 and index.html:594 to list only OpenSSH + PPK. Add an integration test: export each format, import it back, compare fingerprints.
- **Confidence:** confirmed
- **Effort:** L (parsers) / S (doc correction)

## A7-04: Deploy ignores the Host alias / User / Port the dialog collects, writes a different block than the preview shows, and writes it to a file OpenSSH never reads
- **Severity:** High
- **Category:** ipc
- **Location:** `src/renderer/app.js:2140-2168` (preview), `src/renderer/app.js:2192` (`call('key_deploy', { ids, passphrase, strictHostKey })`), `src/renderer/index.html:666,675-677,711-713`, `src-tauri/src/commands/mod.rs:2036-2075`, `src-tauri/src/ssh/mod.rs:76-193`, `src-tauri/src/config/mod.rs:113-162,259-267`
- **Evidence:** the Deploy sheet has inputs `cfgHost`, `cfgUser`, `cfgPort`, and its preview prints `Host <alias> / HostName <alias> / User / Port / IdentityFile / IdentitiesOnly yes / StrictHostKeyChecking`, wrapped in `# >>> SSHSpan managed >>>` markers. `deployConfig()` sends only `ids`, `passphrase`, `strictHostKey`; `key_deploy` has no host/user/port parameters and calls `SshService::deploy_key(&key.name, &priv, &pub, Some(&key.name), None, None, None, strict_host_key)`, so hostname/user/port are always `None` and the alias is the key name. The block is serialized by `SshConfig::to_config_string`, which emits no `# >>> SSHSpan managed >>>` markers. `ssh_config_path()` returns `ProjectDirs(...).config_dir()/ssh/config` (app-private dir), not `~/.ssh/config`; nothing adds an `Include`. The only things the typed alias/user/port feed are the optional "also save as servers" step (app.js:2204-2227).
- **Why it is a flaw:** (1) the "What this will write" preview is not what is written (different alias, no HostName/User/Port, no markers); the user's alias/user/port input is silently discarded for the SSH-config half. (2) The generated block has no `HostName`, so even if included it only associates an IdentityFile with a host literally named after the key. (3) The block lands in a file OpenSSH does not consult (the confirm text at app.js:2179-2181 does print the real path, but the modal subtitle at index.html:666 still says it "adds a matching Host block to your SSH config", and docs/ARCHITECTURE.md:87 and REWRITE-ROADMAP.md:22 claim a managed block in `~/.ssh/config`). Net effect: Deploy only really delivers the private key file in `~/.ssh/sshspan_<name>`.
- **Proposed fix:** decide the contract. Either (a) add `host`, `user`, `port` params to `key_deploy`, pass them to `deploy_key`, write a marker-delimited managed block into the real `~/.ssh/config` (replace-in-place between markers, preserve the rest of the file byte-for-byte), or (b) drop the fields/preview and state plainly that Deploy writes key files only. Align index.html:666, ARCHITECTURE.md:87, REWRITE-ROADMAP.md:22.
- **Confidence:** confirmed
- **Effort:** M

## A7-05: Choosing "PKCS#8 PEM, encrypted" with an empty passphrase silently writes an UNENCRYPTED private key
- **Severity:** High
- **Category:** rust-logic
- **Location:** `src-tauri/src/commands/mod.rs:1928,1934-1936`, `src-tauri/src/crypto/keys.rs:389-399`, `src/renderer/app.js:1773,1849-1853`
- **Evidence:** `key_export_to_file` computes `let pass = passphrase.as_deref().filter(|p| !p.is_empty());` and maps BOTH `"pkcs8"` and `"pkcs8-encrypted"` to `export_private_key(&key_data, KeyFormat::Pkcs8, pass)`. `export_pkcs8_private` encrypts only `if let Some(pass) = passphrase.filter(|p| !p.is_empty())`, otherwise `pem_wrap("PRIVATE KEY", &der)`. The renderer shows the passphrase box for `pkcs8-encrypted` (app.js:1773) but `exportSelected()` (app.js:1849-1853) passes `detailExportPass.value` through without requiring it to be non-empty.
- **Why it is a flaw:** a user who picks the format whose label and sub-text say "encrypted - wrapped with a passphrase you choose below" (risk chip "Sealed") and forgets/skips the passphrase gets a plaintext `-----BEGIN PRIVATE KEY-----` file, with a success toast "Exported pkcs8-encrypted to <path>". The format name promises a protection the backend does not enforce.
- **Proposed fix:** in `key_export_to_file`, when `format == "pkcs8-encrypted"` and `pass.is_none()`, return `Err("A passphrase is required for encrypted PKCS#8 export.")` before opening the save dialog; also disable the button in the renderer until the field is non-empty. Conversely reject a non-empty passphrase for the formats that ignore it, or document it.
- **Confidence:** confirmed
- **Effort:** S

## A7-06: "Edit in system editor" can never open an extension-less remote file (authorized_keys, known_hosts, hosts, fstab, sshd_config, Makefile, Dockerfile ...)
- **Severity:** High
- **Category:** rust-logic
- **Location:** `src-tauri/src/sftp/mod.rs:340-345,359-386` (`path_has_inert_extension`, `staged_file_name`), `src-tauri/src/commands/mod.rs:2910-2915` (opener gate), `src-tauri/src/commands/sftp.rs:669-675`, `src/renderer/sftp.js:2867-2876`; tests `sftp/mod.rs:672-689` and `732-737`
- **Evidence:** `staged_file_name` keeps names without a usable extension in "suffix form": `_ => ... format!("{base}-{id}")`, i.e. `Makefile` stages as `Makefile-<uuid>` (the unit test `staged_name_no_extension_uses_suffix` even asserts `!a.contains('.')`). `sftp_open_for_edit` downloads to `<sid8>-<that name>` and starts the watcher, then the renderer calls `system_open_external({url: localPath})`. That command refuses unless `path_has_inert_extension(&resolved)`, which is `path.extension()...unwrap_or(false)`, so a path with no extension is rejected (the unit test `inert_extension_gate_blocks_executables` asserts `!path_has_inert_extension("x")`). The doc comment at sftp/mod.rs:337-339 says "A staged file produced by `staged_file_name` always satisfies this" - false for every extension-less name, for bare inert dotfiles (`.conf` stages as `.conf-<uuid>`), and for over-long "extensions". Each half is unit-tested alone; the composition is not.
- **Why it is a flaw:** the SFTP "Edit" action fails with "system_open_external refuses to open non-text staged files (possible executable)" for the files people most often edit on servers: `~/.ssh/authorized_keys` (this is an SSH key manager), `known_hosts`, `/etc/hosts`, `/etc/fstab`, `sshd_config`, `crontab`, `Makefile`, `Dockerfile`. The failed attempt also leaves the staged copy and a live watcher registered until session close.
- **Proposed fix:** make the staged name always end in an inert extension (`{base}-{id}.txt` in the no-extension arm and for dotfile arms), keeping the allowlist semantics; update `staged_name_no_extension_uses_suffix`; add a composition test `path_has_inert_extension(Path::new(&staged_file_name(x)))` over a list of extension-less names.
- **Confidence:** confirmed
- **Effort:** S

## A7-07: Editing a saved password/keyboard-interactive server silently deletes its saved password
- **Severity:** High
- **Category:** ipc
- **Location:** `src/renderer/app.js:3856-3857,3903-3912`, `src-tauri/src/commands/server.rs:107-114,126-147`
- **Evidence:** `openServerModal` always resets `srvPassword.value = ''` and `srvSavePw.checked = false` (it cannot know the password; `server_to_json` only exposes `hasSavedPassword`). `submitServerModal` sends `savedPassword: (method !== 'publickey' && srvSavePw.checked) ? srvPassword.value : null`, so an edit that does not retype the password sends `null`. `server_save` computes `saved_sealed = None` for `None`/empty and, for an existing id, does `existing.saved_password = saved_sealed;` - overwriting the stored sealed password with `None` unconditionally. The Rust command has no way to express "leave unchanged".
- **Why it is a flaw:** renaming a server, changing its host/port/category, or fixing a typo in the username silently discards the saved credential; `hasSavedPassword` flips to false and the next connect prompts for the password. The user is never told.
- **Proposed fix:** in `server_save`, treat `saved_password: None` on an existing server as "keep the current sealed value" and accept an explicit clear (`Some("")` or a new `clear_saved_password: Option<bool>`); in the renderer pre-check "Save password" with a "(unchanged)" placeholder when `srv.hasSavedPassword`, and only send a value when the user typed one or unchecked the box. Still clear it when the auth method changes to `publickey`.
- **Confidence:** confirmed
- **Effort:** S

## A7-08: Terminal output is decoded with `from_utf8_lossy` per SSH data packet, so multi-byte characters split across packets turn into U+FFFD
- **Severity:** High
- **Category:** rust-logic
- **Location:** `src-tauri/src/ssh_client/mod.rs:693-710`
- **Evidence:** the session task does `Some(ChannelMsg::Data { data }) => { let text = String::from_utf8_lossy(&data); on_data.send(text.to_string()) ...` and the same for `ExtendedData`, with no carry-over buffer between messages. SSH channel data is cut at arbitrary byte boundaries (PTY read buffers, channel max-packet size), not at UTF-8 character boundaries.
- **Why it is a flaw:** any burst of non-ASCII output larger than one packet (cat/tail of UTF-8 text, `ls` of Unicode names, `htop`/`mc`/`tmux` box-drawing characters which are 3 bytes each, CJK output) can have a character cut in two; both halves become permanent replacement characters in xterm. The corruption is already baked in before the text reaches the renderer.
- **Proposed fix:** keep a per-session `Vec<u8>` tail. On each message append, use `std::str::from_utf8` on the buffer, send the valid prefix, and keep the incomplete suffix (at most 3 bytes) for the next message (emit U+FFFD only for genuinely invalid sequences via `Utf8Error::error_len()`). Alternatively send raw bytes (`Channel<Vec<u8>>`/base64) and let xterm's `write(Uint8Array)` decode. Add a unit test that splits "e-acute, euro sign, emoji" at every byte offset.
- **Confidence:** confirmed (decoding bug is in the code; frequency depends on output volume)
- **Effort:** S

## A7-09: Folder uploads through the transfer queue never create the remote directories, so every file in an uploaded folder fails with "No such file"
- **Severity:** High
- **Category:** rust-logic
- **Location:** `src-tauri/src/commands/sftp.rs:830-922` (`expand_upload`), `commands/sftp.rs:1204-1231` (Upload arm of `sftp_queue_add`), `src-tauri/src/sftp/queue.rs:1564-1628` (Upload leg of `run_job`) versus `queue.rs:150-177,1376` (`ensure_remote_dir`, called only by `run_server_copy`); renderer `src/renderer/sftp.js:2268-2274,2532-2588,3573,3621`
- **Evidence:** the renderer's "Upload folder", multi-select upload and drag/drop of a directory all call `queueUploads(...)` -> `sftp_queue_add(direction:"upload")` (the comment at sftp.js:2265 wrongly says "sftp_upload walks a directory itself"; `sftp_upload` is never called). `expand_upload` recurses the local tree and emits one `QueuedItem` per FILE with `remote = <remote_dir>/<name>`; no SFTP call is made, no `mkdir`. `run_job`'s Upload leg goes straight to `sftp.open_with_flags(&rpart, CREATE|TRUNCATE|WRITE)` on `<remote>/<file>.part`. `ensure_remote_dir` exists but its only call site is the server-to-server leg. The only code that does `create_dir` for uploads is `upload_directory` (commands/sftp.rs:598-646), reachable only through the unused `sftp_upload` command. CHANGELOG.md:961 still promises "Dragging a local folder ... recursively creates the remote directory tree".
- **Why it is a flaw:** uploading a folder that does not already exist on the server (the normal case) fails for every file with `remote open failed: No such file (code 2)`, classified Terminal (`classify_error` "no such file"), so each file lands in Failed. Nested subfolders of an existing folder fail the same way.
- **Proposed fix:** call `ensure_remote_dir(&sftp, &remote)` in the Upload leg of `run_job` before `open_with_flags` (as `run_server_copy` does), or create the directory tree once in `sftp_queue_add` before enqueueing. Add a test that expands a nested temp tree and asserts remote parents are created.
- **Confidence:** confirmed
- **Effort:** S

## A7-10: Windows self-update spawns the NSIS installer with `CreateProcess`, but the bundle is configured `installMode: "both"` (elevation required), so it fails with os error 740
- **Severity:** High
- **Category:** rust-logic
- **Location:** `src-tauri/src/commands/updater.rs:686-699` (spawn), `updater.rs:118-126` (prefers `_x64-setup.exe`), `src-tauri/tauri.conf.json:38-42`; tauri-utils 2.9.3 `config.rs:830-840`
- **Evidence:** `update_download_and_run` launches the downloaded installer with `std::process::Command::new(&dest).spawn()` (only the `.msi` branch goes through `msiexec`). `pick_asset_for_os` prefers `*_x64-setup.exe` (NSIS), and tauri.conf.json sets `"nsis": { "installMode": "both" }`, which the Tauri docs state "will require Administrator access even if the user wants to install it for the current user only". `CreateProcess` (what `Command::spawn` uses) cannot start an executable whose manifest requires elevation from a non-elevated process: it returns ERROR_ELEVATION_REQUIRED (740). SSHSpan normally runs unelevated. README.md:256 describes the NSIS installer as "per-user", which contradicts the `both` setting (per-user is Tauri's default `currentUser`, which needs no elevation). On any failure after the download (spawn included) the downloaded installer is left behind (see A7-42).
- **Why it is a flaw:** "Check now" -> "Download and run the installer" downloads and verifies up to 100 MB and then fails with `The requested operation requires elevation. (os error 740)`; the Windows in-app update path would never complete for a normally launched app.
- **Proposed fix:** launch through the shell so UAC can prompt: `opener::open(&dest)` (ShellExecuteW "open") or `Command::new("cmd").args(["/C","start","",path])`; or switch the installer to `installMode: "currentUser"` and keep a separate per-machine package.
- **Confidence:** likely (Tauri's own documentation of `both` + well-known `CreateProcess` behaviour; not executed on a real update)
- **Effort:** S

## A7-11: Settings defaults disagree between the UI and the backend: auto-lock shows 15 min but is OFF, parallel transfers shows 2 but runs 4, and the watchdog's lock event has no listener
- **Severity:** Medium
- **Category:** ipc
- **Location:** `src-tauri/src/commands/mod.rs:430-447,461,2730-2755`, `src-tauri/src/sftp/queue.rs:576-585`, `src/renderer/app.js:2510,2596-2600,3566-3569,3598-3607,4532`
- **Evidence:** (1) Rust: `get_config("setting.autoLockMinutes")...unwrap_or(15)`, while the doc comment above says "`autoLockMinutes` of 0/absent disables it, matching the renderer's semantics". Renderer: `autoLock.value = state.settings.autoLockMinutes || 15` (displays 15 when unset), but `resetAutoLockTimer()` does `parseInt(state.settings.autoLockMinutes, 10)`; for an unset value that is `NaN`, `!mins` is true, so auto-lock is disabled and the sidebar prints "auto-lock off". Nothing persists a default (`settings_get` returns only keys that were written). The heartbeat is an unconditional `setInterval(..., 30000)` (app.js:3603-3607), so `ActivityTracker.elapsed()` can never reach `mins*60` while the webview is alive - the watchdog only covers a hung webview, so its "15" default never protects an idle-but-healthy session. (2) `sftpParallel`: the Settings row shows `state.settings.sftpParallel || 2` while `parallel_limit()` (queue.rs:576-585) does `.unwrap_or(4)` when unset, so with no stored value the UI says 2 and 4 transfers run. (3) The watchdog emits `vault-locked-by-watchdog` (mod.rs:461) but no renderer code listens for it (only `vault-lock-requested` at app.js:3451), so the UI keeps showing "unlocked" until the 10 s status poll.
- **Why it is a flaw:** on a fresh install the Settings page tells the user the vault locks after 15 idle minutes while it never does until they edit the field once and re-enter 15; the parallel-transfer control misreports what is happening.
- **Proposed fix:** pick one default per setting and make it explicit: have `collect_settings` return `autoLockMinutes: "15"` / `sftpParallel: "4"` (or the UI's values) when unset and share the constants; make the UI show "off" when unset; fix the Rust comment; add a `listen('vault-locked-by-watchdog', refreshVaultStatus)`.
- **Confidence:** confirmed
- **Effort:** S

## A7-12: Key generation (RSA 4096 is the default, 8192 is offered) runs as a synchronous command on the Tauri main thread and freezes the whole window
- **Severity:** Medium
- **Category:** perf
- **Location:** `src-tauri/src/commands/mod.rs:1671-1678,2341-2349` (`pub fn key_generate`, `pub fn key_create_with_categories`), `src-tauri/src/crypto/keys.rs:143-146`, `src/renderer/index.html:567-573`, comment at `commands/mod.rs:1351-1356`
- **Evidence:** both generators are plain `pub fn` (not `async`) and call `keys::generate_key_pair(kt, bits, ...)` which runs `RsaKeypair::random(&mut rng, bits)` with `bits.clamp(2048, 16384)`. The New Key dialog preselects 4096 and offers 8192. The codebase itself documents the premise at commands/mod.rs:1351-1356: "Tauri runs a synchronous command on the MAIN thread". The pure-Rust `rsa` crate takes seconds (4096) to minutes (8192) for prime search.
- **Why it is a flaw:** while the command runs the event-loop thread cannot repaint or answer window messages: the app shows "Not Responding", the Create button gives no progress, and the tray/lock/quit handlers are also stuck. Users are likely to kill the process mid-generation. The same pattern applies to other CPU-bound sync commands (see A7-13).
- **Proposed fix:** make RSA generation `async` and run it in `tauri::async_runtime::spawn_blocking` (or `#[tauri::command(async)]`), return when done, and have the renderer show a busy state. Also clamp the IPC `bits` to the set the UI offers (3072/4096/8192) rather than 2048-16384, since 16384 is effectively a hang.
- **Confidence:** likely (premise is Tauri's documented sync-command behaviour and the code's own comment; absolute timings not measured because cargo must not be run)
- **Effort:** S-M

## A7-13: Bulk vault operations run N x Argon2id (64 MiB, t=3) on the main thread: password change and backup restore scale linearly with key count
- **Severity:** Medium
- **Category:** perf
- **Location:** `src-tauri/src/crypto/vault.rs:30-41,160-169` (doc: "never in a list/loop"), `src-tauri/src/commands/mod.rs:467-582,601-649` (`vault_change_password`/`migrate_vault_records`), `1171-1299` (`vault_backup_restore` re-seal loops), `2036-2097` (`key_deploy` loop)
- **Evidence:** every `seal`/`unseal` calls `VaultKey::derive_from_password` = Argon2id with `Params::new(65536, 3, 4, Some(32))` and a fresh salt. `migrate_vault_records` does one `unseal` + one `seal` per key and per saved-password server; `vault_change_password` adds the Bitwarden/assistant/MCP blobs; `vault_backup_restore` does `unseal(bp)` + `seal(pw)` per key (plus up to a third `unseal(pw)` for the "already usable" branch). All three are sync `pub fn` commands, i.e. run on the main thread. `seal`'s own doc says it is "deliberately not cheap; only call it for single-key operations ... never in a list/loop".
- **Why it is a flaw:** with ~100 keys the change-password or restore call blocks the window for tens of seconds with no progress indication.
- **Proposed fix:** make these commands `async` and run the loop under `spawn_blocking`; better, derive the vault key once per password and use the cheap AES-GCM per record for bulk re-encryption (needs a format that separates KDF from per-record encryption, so at minimum do the loop off the main thread). Emit progress events.
- **Confidence:** likely
- **Effort:** M

## A7-14: Host-key mismatch and "user declined" are indistinguishable; the friendly mismatch message in `terminal_connect` can never be produced
- **Severity:** Medium
- **Category:** rust-logic
- **Location:** `src-tauri/src/commands/terminal.rs:199-211`, `src-tauri/src/ssh_client/mod.rs:195-213,260-278,560-562`, russh `src/lib_inner.rs:132-134` (`#[error("Unknown server key")]`)
- **Evidence:** `TerminalHandler::check_server_key` returns `Ok(false)` both for a pinned-key MISMATCH (line 212) and for a declined first-trust dialog (lines 264-278). russh converts either into `Error::UnknownKey`, whose Display is "Unknown server key"; `start_interactive` wraps it as "Connection failed: Unknown server key". `terminal_connect` then tries to prettify the message with `msg.contains("Key exchange failed")`, `msg.to_lowercase().contains("host key")` (the "Host key mismatch ... possible MITM" text) and `contains("unknown key") || contains("not trusted")`. "connection failed: unknown server key" contains none of these ("unknown key" is not a substring of "unknown server key"), so the user always sees the raw "Connection failed: Unknown server key". `server_test` has the same dead mapping (terminal.rs:384-391).
- **Why it is a flaw:** the one event that must be loud - a changed host key - looks identical to clicking Refuse. The only record is an audit-log row. The "forget it in known_hosts and retry" guidance (and the MITM warning) is unreachable code.
- **Proposed fix:** make the handler record why it refused (e.g. an `Arc<Mutex<Option<HostKeyOutcome>>>` shared with the connect call, or a dedicated error type with `type Error = anyhow::Error`) and map `Mismatch` / `Declined` to distinct messages in `terminal_connect` and `server_test`; do not rely on substring matching of russh's Display text.
- **Confidence:** confirmed
- **Effort:** M

## A7-15: No connect or handshake timeout: an accept-and-stall server hangs "Connecting..." and "Test connection" forever
- **Severity:** Medium
- **Category:** rust-logic
- **Location:** `src-tauri/src/ssh_client/mod.rs:398-408,560-562`, `src-tauri/src/commands/terminal.rs:339-353`, russh `src/client/mod.rs:1083-1096,1121,1157`
- **Evidence:** `base_client_config()` sets `inactivity_timeout: None` (documented as "interactive shell can sit idle"), but russh uses that same field as the only timer during the handshake. `client::connect` does `TcpStream::connect(addrs).await` (OS timeout, ~21 s on Windows, ~2 min on Linux, and sequential per resolved address), then `read_ssh_id().await` and `kex_done_signal_rx.await` with no deadline. Neither `start_interactive` nor `server_test` wraps them in `tokio::time::timeout`. The renderer's terminal.js:567-568 simply awaits `terminal_connect`.
- **Why it is a flaw:** pointing a server entry at a port that accepts TCP but never sends an SSH banner (tarpit, wrong service, overloaded host, middlebox) blocks the connect/test spinner indefinitely with no way to cancel; unreachable hosts can take minutes.
- **Proposed fix:** wrap `client::connect(...)` + `authenticate(...)` in `tokio::time::timeout(Duration::from_secs(20..30), ...)` for both `start_interactive` and `server_test`, with a clear "timed out connecting to host:port" message; keep `inactivity_timeout: None` for established shells.
- **Confidence:** confirmed
- **Effort:** S

## A7-16: Recursive folder download aborts entirely on the first dangling symlink and follows directory symlinks
- **Severity:** Medium
- **Category:** rust-logic
- **Location:** `src-tauri/src/commands/sftp.rs:1064-1067,1120-1144,1266-1279`
- **Evidence:** `expand_download` classifies every entry with `sftp.metadata(&remote)` (SSH_FXP_STAT, which FOLLOWS symlinks) and propagates failure with `.map_err(|e| format!("stat {remote}: {e}"))?`. The error bubbles out of the recursion (`.await?` at 1143) and `sftp_queue_add` returns it at 1278 before `q_enqueue` is reached, so nothing is queued. A dangling symlink therefore fails the whole folder with "stat /x/y: No such file". A symlink to a directory is `is_dir()` after the follow and is recursed into (copying the target tree, or looping until the server returns ELOOP). The sibling walkers are deliberately robust: `remove_remote_tree` tolerates per-child errors, `expand_server_copy` and `sftp_dir_size` classify from the listing's lstat attributes and skip symlinks.
- **Why it is a flaw:** dangling symlinks are common in home directories and web roots, so "download folder" fails for ordinary trees, with an error that does not say which folder entry caused it; symlinked directories get silently duplicated or loop.
- **Proposed fix:** classify children from the `read_dir` entry attributes (`entry.metadata().file_type()`) like `expand_server_copy`, skip (and report) symlinks, and downgrade a per-child failure to a warning that is counted in the result instead of aborting the batch; only `stat` the user-selected root.
- **Confidence:** confirmed
- **Effort:** M

## A7-17: Paused or restored transfers can never be resumed after a reconnect: jobs keep the dead session id and nothing re-binds them
- **Severity:** Medium
- **Category:** rust-logic
- **Location:** `src-tauri/src/sftp/queue.rs:2293-2368` (`restore_pending`), `queue.rs:380-400` (`to_row` stores `session_id`), `src/renderer/sftp.js:2919-2934,3315-3329,3381-3388`
- **Evidence:** `SessionHandle.session_id` is a fresh `Uuid::new_v4()` per connection. `restore_pending` restores jobs as `Paused` with their OLD `session_id` and the message "Session closed before restart - reconnect to "<server>" and resume." The renderer decides resumability with `sftpQueueJobResumable(j)` = some live tab has `t.sessionId === j.sessionId`, which can never become true for a new connection, so the Resume button is permanently `disabled` ("Reconnect to X to resume") and the banner keeps telling the user to reconnect. No code anywhere maps a restored/paused job to the new session (a search for any rebind finds none; `cancel_for_session` is also defined but never called). The same happens within one run: pause -> connection drops/vault locks (`lock_vault_internal` kills all sessions) -> reconnect -> the paused job is orphaned.
- **Why it is a flaw:** the persistence feature advertises "reconnect and resume" but the only possible outcomes are Cancel or re-queueing by hand. The `.part` files it exists to preserve are only reused if the user starts the transfer again.
- **Proposed fix:** persist the saved-server id (not only the per-run session id) with each job and, on `sftp_open`/`terminal_connect` for that server, rebind `session_id` of Paused jobs of that server to the new session (and make `sftpQueueJobResumable` match on server id); or drop the "reconnect to resume" wording and offer "Re-queue" which re-enqueues with `Resume` mode. Remove or wire up the dead `cancel_for_session`.
- **Confidence:** confirmed
- **Effort:** M

## A7-18: Queue transfers never check that the expected number of bytes was copied: a short read/EOF is reported as Done
- **Severity:** Medium
- **Category:** rust-logic
- **Location:** `src-tauri/src/sftp/queue.rs:945-947,970-977,1618-1628,1802-1822,1395-1419`; contrast `src-tauri/src/commands/sftp.rs:538-542`
- **Evidence:** `copy_with_progress` breaks out of its loop when `reader.read` returns 0 and returns `Ok(done)` even if `done < max_read`. The upload leg (`...copy_with_progress(...).await?;`), the download leg (1802-1812) and ServerCopy leg 2 discard that count; for downloads the code then flushes, fsyncs and `rename(.part -> final)`s, and `finish_job(Done)` runs. The close-failure paths compare sizes, but the normal path does not. The one-off `download_to` used by `sftp_download`/edit does check `done < size` ("download incomplete") - the queue, which handles all real transfers, does not. `verify` is off by default.
- **Why it is a flaw:** if the remote file is truncated/rotated mid-download (logs), a server returns early EOF, or a local source shrinks during an upload, the job ends as "Done" with a short destination file and no warning - silent data loss.
- **Proposed fix:** capture the return value and compare to `max_read` (when it is `Some(n)` with `n != u64::MAX`); on mismatch return `Err(format!("incomplete transfer: got {done} of {expected} bytes"))` before the rename. Add unit tests with an in-memory reader that EOFs early.
- **Confidence:** confirmed
- **Effort:** S

## A7-19: The "edit and auto-sync" watcher is not debounced, truncates the remote file in place, swallows every error and never conflict-checks
- **Severity:** Medium
- **Category:** rust-logic
- **Location:** `src-tauri/src/commands/sftp.rs:690-743`
- **Evidence:** every notify event that is `Modify(Data|Any|Metadata)` for the staged path spawns its own task that sleeps 700 ms and uploads - the comment says "Debounce" but there is no coalescing, so one save (often 2-3 events, plus attribute events from AV/indexers) triggers 2-3 concurrent uploads of the same file to the same remote path. Each does `sftp.create(&remote)` (CREATE|TRUNCATE) and `tokio::io::copy`, truncating the live remote file before the new bytes arrive; failures are dropped (`Err(_) => return`, and the copy result is only checked with `.is_ok()` to print on success); `rf` is never closed/shut down before the task ends (compare `upload_one_file`, which awaits `close()`); russh-sftp 2.4.0's own `File` docs say "On drop the handle is closed as well, but the reply is not awaited, so pending write errors and the close status are silently discarded", and `poll_write` only queues writes up to `max_concurrent_writes`, so `tokio::io::copy` returning Ok does not mean the data landed; there is no check that the remote file is unchanged since download. The watch is also registered on the FILE path (`watcher.watch(&local, NonRecursive)`, line 746) and only `Modify(Data|Any|Metadata)` events are accepted (lines 697-705): editors that save atomically (write temp + rename over: vim, gedit, Kate, Sublime, Office) generate `Modify(Name)`/`Create`/`Remove` events and, on inotify, drop the watch on the replaced inode, so such a save is never uploaded (suspected: depends on notify's per-platform event mapping).
- **Why it is a flaw:** a connection drop mid-sync leaves a truncated remote file while the editor shows a saved file and no error is surfaced; two overlapping uploads can interleave truncate/write on the same remote path; a concurrent remote change is overwritten without warning; for atomic-save editors the toast "Editing X - saves upload automatically" is simply untrue.
- **Proposed fix:** keep one `Arc<Mutex<Option<JoinHandle>>>`/generation counter per watch so only the last event within the window uploads; upload to `<remote>.sshspan-tmp` then rename (or use the queue's `.part` logic), `shutdown().await` the file, emit a toast/event on success AND failure, and compare remote mtime/size captured at download time before overwriting (prompt on mismatch). Watch the PARENT directory and accept `Create`/`Modify(Name(To))` events for the staged name; ignore `ModifyKind::Metadata`.
- **Confidence:** confirmed (debounce, error handling, close); suspected (atomic-save editors)
- **Effort:** M

## A7-20: Recursive chmod applies SETSTAT to symlinks (changing their targets, including directories) and aborts on the first error
- **Severity:** Medium
- **Category:** rust-logic
- **Location:** `src-tauri/src/commands/sftp.rs:2022-2064,2088-2096`
- **Evidence:** `chmod_tree` reads each child's `entry.metadata().is_dir()` from the READDIR (lstat) attributes, so a symlink reports `is_dir() == false` and is handled as a "file": `if (is_dir && apply_dirs) || (!is_dir && apply_files) { chmod_one(&sftp, &child, mode).await?; ... }`. SSH_FXP_SETSTAT follows symlinks on OpenSSH's sftp-server, so the target's mode changes - including a symlink that points at a directory (it receives a file mode such as 0644 and loses its search bit) or at a path outside the tree. The `?` also stops the whole walk at the first refused entry, leaving a half-applied tree with no count of what changed.
- **Why it is a flaw:** "chmod -R 644 on files" over a deployment tree containing `storage -> ../shared/storage` style links breaks the shared directory; GNU `chmod -R` skips symlinks for exactly this reason.
- **Proposed fix:** skip entries where `entry.metadata().is_symlink()`; collect per-entry errors into a list and keep walking, returning `{changed, failed:[...]}`.
- **Confidence:** likely
- **Effort:** S

## A7-21: `sftp-search` results carry no request id and the walk cannot be cancelled, so overlapping searches cross-contaminate and a stale "done" kills the live listener
- **Severity:** Medium
- **Category:** ipc
- **Location:** `src-tauri/src/commands/sftp.rs:1664-1791`, `src/renderer/sftp.js:1918-1963`
- **Evidence:** `sftp_search` spawns a detached walk (up to 120 s / 200k entries) and returns `{ok:true}`; every emitted event is `{sessionId, path, name, isDir, ...}` / `{sessionId, done:true,...}` with no search id. `runSearch` registers a listener filtered only by `p.sessionId !== tab.sessionId`, and on a `done` payload calls `sftpDisposeSearch(tabId)` and prints the summary. Starting a second search while the first walk is still running: the old walk's matches are appended to the new result list under the new query, and the old walk's `done` event disposes the new listener and writes the old totals into the status line, dropping the rest of the new search's results.
- **Why it is a flaw:** refining a query in a large tree (the normal way to use search) produces mixed/wrong results and a premature "N match(es)" status.
- **Proposed fix:** have the renderer generate a `searchId`, pass it to `sftp_search`, echo it in every event, ignore events with a different id, and keep a per-session cancel flag (`AtomicBool`/generation) that `walk_search` checks so a new search or tab close stops the old walk.
- **Confidence:** confirmed
- **Effort:** M

## A7-22: Deploy has no inverse: `key_remove_deployed` is never called, deleting a deployed key leaves its plaintext private key in `~/.ssh`, and the config stanza is never removed
- **Severity:** Medium
- **Category:** rust-logic
- **Location:** `src-tauri/src/commands/mod.rs:1979-1989,2099-2155`, `src-tauri/src/ssh/mod.rs:195-219` (`SshService::remove_key`, unused), `src/renderer/app.js:1696,1726`
- **Evidence:** a search of `src/renderer` finds no call to `key_remove_deployed`. `key_delete` only deletes the DB row; the confirm text says "Deployed copies on disk are not removed." and nothing else removes `~/.ssh/sshspan_<name>` (private key, optionally unencrypted) and `.pub`, or the `Host` stanza in the app config file. Where the command exists, it ignores filesystem errors (`let _ = fs::remove_file(deploy_path)`, `let _ = fs::remove_file(format!("{}.pub", ...))`) and still sets `deployed=false`, never calls `SshService::remove_key` (which is the only code that edits the config), and writes no audit row on success.
- **Why it is a flaw:** the app writes a decrypted private key to disk on Deploy and offers no way to take it back; after deleting the vault entry the key file is orphaned forever with the DB no longer tracking `deploy_path`. If the file cannot be deleted (locked, permission), the record says "not deployed" while the secret remains.
- **Proposed fix:** expose "Remove deployed copy" in the key detail pane (calls `key_remove_deployed`), have `key_delete` call the same helper when `deployed` is true (or at least offer it in the confirm), report removal failures instead of discarding them, remove the stanza via `SshService::remove_key`, and audit it.
- **Confidence:** confirmed
- **Effort:** M

## A7-23: Bitwarden sync never refreshes its change-tracking metadata after an update push: edited items are re-pushed and counted as conflicts on every sync, and remote edits to them can never be pulled
- **Severity:** Medium
- **Category:** rust-logic
- **Location:** `src-tauri/src/bitwarden/sync.rs:192-210,596-608,446-471,867-885`, `src-tauri/src/commands/mod.rs:614-616,2078-2081,2330-2331`
- **Evidence:** change detection is `local_changed = row.updated_at > bitwarden_updated_at` and `remote_changed = cipher.revisionDate > bitwarden_revision_ts`. The CREATE branches record the new cipher id and revision (`db.update_key_sync_meta(...)` at 607; `updated.bitwarden_*` + `db.update_server` at 880-884), but the UPDATE branches (`client.update_cipher(bw_id, &cipher).await?;` at 598 and 868) discard the response and write nothing back. After the first update push `bitwarden_updated_at` stays older than `updated_at` (still "local changed") and the server has bumped `revisionDate` past the stored value (also "remote changed"), so every later sync takes the `local_changed` branch, re-unseals (Argon2id) and re-uploads the private key, and increments `conflicts`. Because the pull branch only runs when `!local_changed`, remote edits are shadowed forever. `updated_at` is bumped by `key_rename`, `key_deploy`/`key_remove_deployed` (mod.rs:2078-2081,2146-2149) and, for EVERY key, by `migrate_vault_records` (mod.rs:614-616) - so a master-password change makes every key permanently "locally changed". Conversely `set_key_categories`/`category_rename` never touch `keys.updated_at`, so category edits alone are never detected and never reach the cipher `notes`.
- **Why it is a flaw:** the status line reports phantom conflicts and re-uploads secrets on every sync; edits made in Bitwarden to any key that was ever modified locally are never applied; category changes silently do not sync although the docs say category metadata is pushed.
- **Proposed fix:** capture the `update_cipher` response (`revisionDate`) and call `update_key_sync_meta`/set the server's `bitwarden_updated_at`/`bitwarden_revision_ts` after every successful push; do not use `updated_at` for deploy/re-seal bookkeeping (add a separate `content_changed_at`), and bump it when categories change.
- **Confidence:** confirmed
- **Effort:** M

## A7-24: `bitwarden_sync` per-item errors, server counters and remote-deleted counts are never shown: every run ends in "Sync complete."
- **Severity:** Medium
- **Category:** ipc
- **Location:** `src-tauri/src/bitwarden/sync.rs:142,174,215,226,248-298,383-385,501-517`, `src/renderer/app.js:2401-2422`
- **Evidence:** `run_sync` returns `Ok` with `"errors": [...]` whenever individual items fail (unseal failure, invalid private-key format, HTTP error from the server, DB insert failure) and with `serversPushed/serversUpdatedRemote/serversPulled/serversUpdatedLocal/remoteDeleted`. `bwSyncNow` reads only `pushed, pulled, updatedRemote, updatedLocal, linked, conflicts, skippedOverwrites, skippedNew`, then shows `toast('Sync complete.', 'ok')`. A search of `src/renderer` finds no use of `errors`, `serversPushed`, `serversPulled`, `serversUpdatedRemote`, `serversUpdatedLocal`, `remoteDeleted` or the persisted `last_result`.
- **Why it is a flaw:** a sync in which every key failed to upload still toasts success; a run that only synced servers prints "Nothing to sync."; users who rely on Bitwarden as the backup copy are never told items are missing there.
- **Proposed fix:** include the server counters in the summary, show `errors.length` with the first few `{name,error}` pairs (and use a warning status/toast when non-empty), and surface `remoteDeleted`.
- **Confidence:** confirmed
- **Effort:** S

## A7-25: `restore_backup` writes audit rows through a second pooled connection while its own write transaction is open, so each sanitized key name costs a 5 s busy wait on the main thread and the audit row is dropped
- **Severity:** Medium
- **Category:** rust-logic
- **Location:** `src-tauri/src/db/mod.rs:2103,2127-2134,2153-2163`, `src-tauri/src/commands/mod.rs:1171-1316` (sync command), sqlx-sqlite 0.8.6 `src/options/mod.rs:201`
- **Evidence:** `restore_backup` opens `let mut tx = self.pool.begin()` and inserts categories first; inside the key loop, for a name that fails `validate_key_name`, it calls `self.add_audit("keys.name_sanitized", ...)` BEFORE the key INSERT. `add_audit` acquires a different connection from the pool and runs `INSERT INTO audit_log`. SQLite allows one writer: once the open transaction has executed any INSERT it holds the write lock, so the second connection waits for `busy_timeout` (sqlx default 5 s, per the 0.8.6 source) and returns "database is locked", which `let _ =` discards. The calling thread is blocked in `block_in_place`/`block_on` for those 5 s, and `vault_backup_restore` is a sync command (main thread).
- **Why it is a flaw:** restoring a backup from an older version (names with spaces, the exact case the sanitizer exists for) freezes the window for 5 s per offending key after the first write and loses the audit trail of the renames. No test restores a payload with an invalid name.
- **Proposed fix:** collect the `(raw, sanitized)` pairs in a Vec inside the transaction and write the audit rows after `tx.commit()` (or use `sqlx::query(...).execute(&mut *tx)` for the audit insert). Add a restore test with names containing spaces.
- **Confidence:** likely (SQLite single-writer semantics + sqlx defaults; not executed because cargo must not be run)
- **Effort:** S

## A7-26: "Import a Host block from ~/.ssh/config" reads SSHSpan's private config file, never the user's real `~/.ssh/config`
- **Severity:** Medium
- **Category:** ipc
- **Location:** `src/renderer/index.html:188`, `src/renderer/app.js:2241-2246`, `src-tauri/src/commands/mod.rs:2436-2441` (`ssh_config_list_hosts`), `src-tauri/src/config/mod.rs:196-208,259-267`
- **Evidence:** the button title says "Import a Host block from ~/.ssh/config" and the toast for an empty result is `No Host blocks found in <systemPaths().sshConfig>`. `ssh_config_list_hosts` builds `SshConfigService::new()`, whose path is `ProjectDirs("org","sshspan","SSHSpan").config_dir()/ssh/config` (an app-private file that only `key_deploy` ever writes, see A7-04); `get_ssh_dir()` (which points at `~/.ssh`) is used only for deployed key files. The user's actual `~/.ssh/config` is never opened.
- **Why it is a flaw:** the Config import button cannot show any of the user's existing hosts; for most users it reports "No Host blocks found in C:\Users\...\AppData\Roaming\sshspan\SSHSpan\config\ssh\config". The one feature whose purpose is to onboard existing SSH hosts does not do it. (If it were pointed at the real file, `SshConfig::parse` also drops `Include`, `Match`, comments and any directive before the first `Host`, and collapses repeated directives into a HashMap, so the parser would need work too.)
- **Proposed fix:** add a read-only `ssh_config_import_hosts` that parses `~/.ssh/config` (and optionally `Include`d files); keep the managed file separate. Fix the tooltip/docs either way.
- **Confidence:** confirmed
- **Effort:** M

## A7-27: Restoring a backup drops each key's Bitwarden revision metadata (JSON numbers read as strings), so the next sync treats every linked key as changed on both sides and overwrites the remote copy
- **Severity:** Medium
- **Category:** rust-logic
- **Location:** `src-tauri/src/db/mod.rs:2148,2200-2201` (`restore_backup` keys), `db/mod.rs:33-36` (`KeyRecord.bitwarden_revision_ts/bitwarden_updated_at: Option<i64>`), `src-tauri/src/commands/mod.rs:1128,1139-1146` (`vault_backup_create`), `src-tauri/src/bitwarden/sync.rs:192-210`
- **Evidence:** `vault_backup_create` serializes `Vec<KeyRecord>` with serde, so the two metadata fields are JSON numbers (or null). `restore_backup` reads them with `s("bitwarden_revision_ts")` / `s("bitwarden_updated_at")`, where `s = |f| k.get(f).and_then(|v| v.as_str())`; `as_str()` returns `None` for numbers, so NULL is bound. (Servers carry these as `Option<String>`, which is why the existing test `restore_backup_preserves_server_bitwarden_linkage` passes while no test covers keys.) `bitwarden_id` (a string) IS restored, so a restored key stays linked but with `bitwarden_updated_at = NULL`.
- **Why it is a flaw:** in `run_sync` a linked key with NULL metadata gets `local_changed = updated_at > 0` and `remote_changed = revisionDate > 0`, both true, so every restored key is counted as a conflict and "local wins": the sync re-uploads (overwrites) the Bitwarden cipher for all restored keys, even where the remote copy is newer; later remote edits are shadowed (see A7-23).
- **Proposed fix:** read the fields with `.and_then(|v| v.as_i64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))` and bind them as strings like the writer; add a backup -> restore -> sync-metadata round-trip test for keys.
- **Confidence:** confirmed
- **Effort:** S

## A7-28: Deleting a key or a host category leaves dangling references: category counts stay inflated and a deleted host category's servers vanish from every category view until restart
- **Severity:** Medium
- **Category:** rust-logic
- **Location:** `src-tauri/src/db/mod.rs:745-753` (`delete_key`), `db/mod.rs:1299-1341` (`delete_category`), `db/mod.rs:575-577` (only cleanup, at startup), `src/renderer/app.js:381-412,3698-3699`
- **Evidence:** `delete_key` runs only `DELETE FROM keys WHERE id = ?`; the `key_categories` rows for that key are not removed (`key_categories` has no FK). `category_list` returns the full join table as `allKeyCategories`, and the renderer's `directKeyCount`/`totalKeyCountFor` count `Object.values(state.keyCategories)` entries, so a deleted key keeps being counted in every category it belonged to. `delete_category` re-parents child categories and deletes the join rows but never touches `servers.category_id`; for a host-scope category, its servers keep pointing at the deleted id. `renderServerList` filters `Uncategorized` with `!s.categoryId`, so those servers match neither "Uncategorized" nor any existing category; they only show under "All" until the next launch, when the migration at db/mod.rs:575 nulls the dangling ids.
- **Why it is a flaw:** the sidebar says "Production (3)" while the list shows 2 keys; after deleting a host category the servers seem to have disappeared (the confirm text promises items "become Uncategorized"). The join table also grows forever.
- **Proposed fix:** in `delete_key`, `DELETE FROM key_categories WHERE key_id = ?` in the same transaction; in `delete_category`, `UPDATE servers SET category_id = <deleted node's parent or NULL> WHERE category_id = ?`; run the same cleanup in the startup migration for existing databases.
- **Confidence:** confirmed
- **Effort:** S

## A7-29: MCP rug-pull defence is silent: a changed tool is disabled with its old pin kept, the renderer's "Definition changed" warning is unreachable, the change list is discarded, and the old `auto_approve` flag survives re-approval
- **Severity:** Medium
- **Category:** rust-logic
- **Location:** `src-tauri/src/assistant/mcp.rs:1207-1243` (`merge_tools`), `mcp.rs:1181,1713-1729` (`connect_server` returns `changed`, `mcp_test_connection` binds `_changed`), `mcp.rs:1469-1486` (`tool_view`), `mcp.rs:1749-1764` (`mcp_set_tool_state`), `src/renderer/mcp.js:445-474,499-513`
- **Evidence:** when a stored tool's definition hash differs from its pin, `merge_tools` returns `(false, p.auto_approve, p.pin_hash.clone())`: `enabled=false`, pin KEPT, `auto_approve` KEPT. The renderer shows the warning only when `t.enabled && !t.pinned` (`needsReapprove`), but the backend produces `!enabled && pinned`, so that condition can never be true (nothing else yields `enabled && !pin`). `mcp_test_connection` throws away the `changed` list that `connect_server` computed, so the UI is never told which tools changed; only an audit row exists. When the user later toggles Enable on, `mcpToolRow` calls `setToolState(true, t.auto_approve)` with the OLD stored `auto_approve` (true), and `mcp_set_tool_state` stores `entry.auto_approve = auto_approve && enabled`, re-pinning the new definition hash.
- **Why it is a flaw:** the whole point of the pin is that a changed definition needs a fresh, explicit approval. Here the tool just silently turns off (no explanation), and when the user switches it back on it silently regains auto-approve for the NEW, unreviewed definition, so later calls run without a confirmation card.
- **Proposed fix:** in `merge_tools` clear `auto_approve` (and keep a `definition_changed` flag in the record/`tool_view`) when the hash differs; return `changed` from `mcp_test_connection` and show it; have the renderer render the warning off that flag and pass `auto_approve=false` when re-enabling.
- **Confidence:** confirmed
- **Effort:** M

## A7-30: The MCP edit form cannot round-trip auth settings: `mcp_list_servers` omits `auth_env_var`, `auth_header_name` and "has secret", so editing silently drops an env-var binding and a URL edit silently drops the stored secret
- **Severity:** Medium
- **Category:** ipc
- **Location:** `src-tauri/src/assistant/mcp.rs:1499-1516` (list shape), `mcp.rs:1627-1657` (`mcp_save_server`), `src/renderer/mcp.js:343-369,388-398`
- **Evidence:** the list response contains `id,name,url,auth_type,confirmed,loopback_insecure,status,tool_count,tools` only. `mcpOpenForm(sv)` reads `sv.auth_env_var` (always undefined), sets `mcpHeaderName` to `''` and `mcpSecretSource` to `'stored'`, and hints "Stored secret: leave blank to keep the current one." On Save, an env-var server sends `auth_secret: null, auth_env_var: null`; in `mcp_save_server` the non-secret branch executes `record.auth_env_var = auth_env_var;` (None) and the record keeps no secret, so the env-var binding is erased with a "MCP server saved." toast; the next connect fails "No auth source configured". A custom-header server gets `Custom header auth requires a header name.` because the stored name is not returned. If the user edits only the URL, `origin_changed` triggers `record.auth_secret = None` (credential origin binding), contradicting the hint that blank "keeps the current one".
- **Why it is a flaw:** any edit (even renaming) of an env-var-auth server breaks it; users get no indication of which source is configured or that a secret was cleared.
- **Proposed fix:** return `auth_header_name`, `auth_env_var` (a name, not a secret) and `has_secret` from `mcp_list_servers`; prefill the form from them; make `mcp_save_server` keep `auth_env_var` when the argument is absent; warn in the UI when changing the URL/auth type will discard the stored secret.
- **Confidence:** confirmed
- **Effort:** S

## A7-31: If the vault database cannot be opened or migrated at startup the app dies silently: no window, no tray, no message
- **Severity:** Medium
- **Category:** rust-logic
- **Location:** `src-tauri/src/lib.rs:53-55` (`AppState::new(app.handle())?` in `setup`), `src-tauri/src/db/mod.rs:296-345,362-675`, `src-tauri/src/main.rs:4-7` (`windows_subsystem = "windows"`), tauri 2.11.5 `src/app.rs:1424-1426` (`panic!("Failed to setup app: {e}")`)
- **Evidence:** Tauri runs the setup hook on `RuntimeRunEvent::Ready` and converts any `Err` into `panic!("Failed to setup app: {e}")`. The main window is created `visible: false` and is only shown at the END of setup (`lib.rs:96-98`), and in release builds on Windows the console is detached, so the panic text goes nowhere. `Database::new` fails on: unwritable data dir, a locked/corrupt `sshspan.db`, a failing `CREATE TABLE/INDEX` (disk full), a failed 0600 chmod on Unix (propagated at db/mod.rs:333-340), or `ProjectDirs` returning None.
- **Why it is a flaw:** the user double-clicks SSHSpan and nothing ever appears; there is nothing to report or fix. The next launch behaves the same.
- **Proposed fix:** catch the error in `setup`, show a native dialog (`tauri_plugin_dialog` message dialog) with the cause and the database path, and exit cleanly; optionally offer to rename the corrupt DB aside.
- **Confidence:** confirmed (code path; triggering conditions are realistic)
- **Effort:** S

## A7-32: Deploying with a passphrase and "also save as servers" registers servers the built-in client can never connect to; PEM-path servers have no passphrase support
- **Severity:** Medium
- **Category:** ux
- **Location:** `src/renderer/app.js:2184-2227`, `src-tauri/src/commands/terminal.rs:93-107`, `src-tauri/src/ssh_client/mod.rs:424-430`
- **Evidence:** the Deploy dialog offers "Put a passphrase on the written key files" and "Also save these as servers in SSHSpan"; with both ticked `deployConfig` calls `server_save` with `pemPath: k.file` (the passphrase-encrypted file). At connect time `resolve_for_server` reads that file as text and `authenticate` calls `decode_secret_key(pem, None)`; there is no passphrase argument anywhere (`ConnectParams` has no field, the connect modal has no prompt for it), so an encrypted key fails with "Could not decode the selected private key: ...". The same applies to any user-chosen `.pem` path that is passphrase-protected, which is the common state of keys in `~/.ssh`.
- **Why it is a flaw:** the app's own two checkboxes combine into servers that always fail to connect with an error the user cannot act on.
- **Proposed fix:** either support passphrases (prompt like the password prompt and pass `Some(pass)` to `decode_secret_key`), or disable "Also save as servers" when a passphrase is set, and tell the user to use vault keys for the built-in client.
- **Confidence:** confirmed
- **Effort:** M

## A7-33: Stored API key for the AI assistant cannot be removed from the UI: `clear_api_key` is never sent
- **Severity:** Medium
- **Category:** ipc
- **Location:** `src-tauri/src/assistant/mod.rs:104-116,147-157`, `src/renderer/assistant.js:773-791`, `src/renderer/index.html:392-393`
- **Evidence:** `assistant_save_config` treats a blank `api_key` as "keep the stored key" and added `clear_api_key: Option<bool>` precisely so a key can be removed ("which otherwise made a stored key impossible to remove"). `aiSaveConfig` never passes `clearApiKey` (no occurrence in `src/renderer`), the field's placeholder says "Leave blank to keep the stored key", and there is no Remove/Clear control.
- **Why it is a flaw:** once saved, the sealed provider key can only be replaced, never deleted, short of wiping the database.
- **Proposed fix:** add a "Remove stored key" button that calls `assistant_save_config` with `clearApiKey: true`.
- **Confidence:** confirmed
- **Effort:** S

## A7-34: `sftp_download` ("Download as...") writes straight to the chosen path, so a failed download destroys the file it was replacing
- **Severity:** Medium
- **Category:** rust-logic
- **Location:** `src-tauri/src/commands/sftp.rs:463-473,489-552`, `src-tauri/src/sftp/mod.rs:470-483` (`create_transfer_file` unlinks the existing file first); renderer `src/renderer/sftp.js:2856-2865`
- **Evidence:** `download_to` calls `create_transfer_file(local)` (remove existing file, `create_new`), then streams into it. Any later error (`describe_download_read_error`, `local write failed`, `download incomplete`) returns `Err` without restoring or deleting anything. The queue path stages `<dest>.part` and renames only after success; this single-file path does not. `sftp_open_for_edit` shares `download_to`.
- **Why it is a flaw:** the user picks an existing file in the native save dialog, confirms "replace", the connection drops halfway, and the original is gone, replaced by a truncated file with the same name.
- **Proposed fix:** write `<local>.part` and `rename` on success (reuse the queue's helper), deleting the `.part` on failure.
- **Confidence:** confirmed
- **Effort:** S

## A7-35: Download "Resume" re-reads the whole already-downloaded prefix from the server (and ignores pause, cancel and the bandwidth cap while doing so), because the code wrongly believes russh-sftp cannot seek
- **Severity:** Medium
- **Category:** perf
- **Location:** `src-tauri/src/sftp/queue.rs:232-256` (`discard_exact`, doc at 233-236), `queue.rs:1761-1773` (call site), russh-sftp 2.4.0 `src/client/fs/file.rs:212-269` (`impl AsyncSeek for File`)
- **Evidence:** the doc comment states "russh-sftp's `File` exposes no offset-taking read, so skipping a prefix on the remote side means issuing reads and discarding the data locally". In the vendored crate, `File` implements `AsyncSeek`; `SeekFrom::Start(pos)` is a free local assignment (`Box::pin(future::ready(Ok(pos)))`) and every `poll_read` issues `session.read(handle, self.pos, len)`. The resume path calls `discard_exact(&mut rf, offset)` instead, a read loop in 256 KiB chunks. That loop never checks the `cancel`/`pause` flags and never calls `throttle_bandwidth`, and it emits no progress (the job sits at its old `bytes_done`).
- **Why it is a flaw:** resuming a 10 GB download at 9.9 GB transfers 9.9 GB again before the first new byte (as slow as starting over, only the local disk write is saved), the job looks frozen at its old progress, Pause/Cancel do nothing for minutes, and the shared bandwidth limit is bypassed.
- **Proposed fix:** `use tokio::io::AsyncSeekExt; rf.seek(SeekFrom::Start(offset)).await?` instead of `discard_exact` (keep `discard_exact` only as a fallback if seek errors), and delete the false comment.
- **Confidence:** confirmed
- **Effort:** S

## A7-36: "Preserve timestamps" is silently ignored for downloads; the stated reason ("std has no portable mtime setter") is outdated
- **Severity:** Medium
- **Category:** rust-logic
- **Location:** `src-tauri/src/sftp/queue.rs:1856-1862`, `src-tauri/src/commands/sftp.rs:1093-1095`, `src-tauri/src/sftp/mod.rs:917-921` (test already uses `File::set_modified`), `src/renderer/sftp.js:565-600,2465,2525`, `README.md:211`
- **Evidence:** the transfer toolbar toggle is titled "Preserve timestamps of transferred files" and the renderer passes `preserveTs` for downloads and uploads. For downloads `expand_download` sets `preserve_ts: None` and the download leg of `run_job` applies nothing, with the comment "std has no portable mtime setter (Windows needs SetFileTime; adding a crate for it is out of scope)". `std::fs::File::set_modified` is stable and portable (Rust 1.75+), and this crate's own test module calls it (`sftp/mod.rs:917-921`). The remote mtime is already available from the `metadata(&remote)` stat made at queue.rs:1706.
- **Why it is a flaw:** README says file timestamps "can be preserved across transfers"; with the toggle ON, every downloaded file still gets "now" as its mtime, which breaks `rsync`-style comparisons and the "compare" feature that relies on mtimes.
- **Proposed fix:** after the final rename, `std::fs::OpenOptions::new().write(true).open(&local)?.set_modified(UNIX_EPOCH + Duration::from_secs(remote_mtime))` when `preserve_ts` is set; thread `preserve_ts: Some(preserve_ts)` through `expand_download`.
- **Confidence:** confirmed
- **Effort:** S

## A7-37: There is no in-app Quit: closing the window only hides it and the tray menu is the sole exit, so on desktops without a visible tray the app can never be closed
- **Severity:** Medium
- **Category:** ux
- **Location:** `src-tauri/src/lib.rs:226-240` (CloseRequested -> `prevent_close()` + `hide()` unless `QUITTING`), `lib.rs:268,300-305` (`QUITTING` is set only by the tray's Quit item), `lib.rs:271-325` (`create_tray`), `CHANGELOG.md:252-255` ("Quit (tray menu) is now the only exit"); no quit command in `generate_handler!` and no quit control in `src/renderer`
- **Evidence:** the window-close handler cancels every close request unless `QUITTING` is true, and the only code that sets it is the tray menu's "quit" arm. A search of `src/renderer` for quit/exit finds nothing, and no registered command exits the app (the updater's `app.exit(0)` runs only after an update). The tray icon is created unconditionally with `?`; whether it is actually displayed depends on the desktop (GNOME without the AppIndicator extension, some Wayland/minimal setups show no tray at all).
- **Why it is a flaw:** on such systems the X button and Alt+F4 hide the window into a tray the user cannot see, the process keeps running with the vault unlocked (auto-lock is effectively off until the user sets it, see A7-11), and there is no way to exit short of `kill`; relaunching only re-shows the hidden instance (single-instance plugin).
- **Proposed fix:** add an in-app Quit (menu item/shortcut such as Ctrl+Q wired to a command that sets `QUITTING` and calls `app.exit(0)`), and make window-close honour a "minimize to tray vs quit" setting; fall back to real exit when no tray host is present.
- **Confidence:** likely (code path confirmed; depends on the desktop environment)
- **Effort:** S

## A7-38: "Test connection" never prompts for a password, so it always fails for password and keyboard-interactive servers whose password is not saved
- **Severity:** Medium
- **Category:** ipc
- **Location:** `src/renderer/app.js:4139-4155` (only `server_test` call site), `src-tauri/src/commands/terminal.rs:309-330` (`prompt_password: Option<String>`), `terminal.rs:108-114`, `src-tauri/src/ssh_client/mod.rs:449-454`
- **Evidence:** `testSelectedServer` calls `call('server_test', { serverId: srv.id })` with no `promptPassword`, unlike `openSessionTab` (app.js:4188-4196) and the reconnect path (4249-4252), which ask for the password first when `srv.authMethod !== 'publickey' && !srv.hasSavedPassword`. For such a server `resolve_for_server` finds neither a prompt password nor a saved one, `ResolvedConnection.password` is `None`, and `authenticate` returns `No password available for this session.`; `server_test` turns that into `{ok:false, error}` and the toast shows it.
- **Why it is a flaw:** the per-server Test button (advertised in README.md:177) is unusable for the common password-without-saved-password case, and the error does not tell the user what to do.
- **Proposed fix:** make `testSelectedServer` reuse `askConnectPassword` and pass `promptPassword`, or have `server_test` return a typed "password required" error that the renderer answers with the prompt.
- **Confidence:** confirmed
- **Effort:** S

## A7-39: A local key whose Bitwarden cipher was deleted can never be re-created: sync calls `update_cipher` on the dead id on every run
- **Severity:** Low
- **Category:** rust-logic
- **Location:** `src-tauri/src/bitwarden/sync.rs:152-178,393-400,596-608`
- **Evidence:** Pass 1 finds the cipher by `bitwarden_id` or fingerprint among non-deleted remote ciphers; when neither matches it takes the "Push new item" path and calls `push_local_key`, which does `if let Some(ref bw_id) = row.bitwarden_id { client.update_cipher(bw_id, ...) } else { create_cipher(...) }`. For a key whose cipher was deleted/trashed remotely, `bitwarden_id` is still `Some`, so the call is an UPDATE of a non-existent (or trashed) id and fails every run; `remote_deleted` is only counted.
- **Why it is a flaw:** with errors hidden (A7-24) the key silently stays out of the Bitwarden vault; there is no UI to clear the stale link.
- **Proposed fix:** when no remote counterpart exists, clear `bitwarden_id` (or create instead of update) before pushing, and surface the "remote copy was deleted" case to the user.
- **Confidence:** confirmed
- **Effort:** S

## A7-40: `delete_category` reports siblings (and other scopes' roots) as "reassigned children"
- **Severity:** Low
- **Category:** rust-logic
- **Location:** `src-tauri/src/db/mod.rs:1325-1337`, `src/renderer/app.js:595`
- **Evidence:** after re-parenting the children, the function selects `SELECT id FROM categories WHERE parent_id IS ? OR (parent_id IS NULL AND ? IS NULL)` bound to the deleted node's parent. That returns EVERY category under that parent (the deleted node's pre-existing siblings plus the re-parented children), and for a deleted root node every root category of every scope. The renderer shows "`N child(ren) reassigned.`" from this list.
- **Why it is a flaw:** deleting a childless root category among four others toasts "4 child(ren) reassigned" although nothing moved.
- **Proposed fix:** collect the child ids BEFORE the `UPDATE ... SET parent_id` (`SELECT id FROM categories WHERE parent_id = ?`) and return those. (While here, also `UPDATE servers SET category_id = NULL WHERE category_id = ?` for host categories; today dangling server category ids only get cleaned by the next startup migration.)
- **Confidence:** confirmed
- **Effort:** S

## A7-41: Backup & restore says "your entire vault" but drops SFTP bookmarks, Bitwarden settings and AI-assistant settings
- **Severity:** Low
- **Category:** rust-logic
- **Location:** `src-tauri/src/commands/mod.rs:1115-1146,2783-2810`, `src-tauri/src/commands/sftp.rs:1795-1823`, `src/renderer/index.html:320`
- **Evidence:** `vault_backup_create` serializes keys, categories, servers, known_hosts, `collect_settings` (only the `SETTINGS_KEYS` allowlist plus `sftpLocalDir:*`) and MCP servers. SFTP bookmarks live in `config` under `sftp.bookmarks.<server_id>` (sftp.rs:1797,1816), the Bitwarden config in the `bitwarden_config` table and the assistant settings in `assistant_config`; none of them is read by `vault_backup_create` and `restore_backup` has no branch for them. The card text says "Exports your entire vault - keys (still encrypted), categories, saved servers, known hosts, and settings".
- **Why it is a flaw:** after restoring on a new machine the servers come back (same ids) but their bookmarks are gone, and sync/assistant must be configured again, with no hint in the UI; the sealed Bitwarden/assistant secrets would have been re-sealed like the others had they been included.
- **Proposed fix:** include `sftp.bookmarks.*` (use `list_config_prefix`) and, if desired, the sealed Bitwarden/assistant rows in the payload with the same re-seal handling, or reword the card to list exactly what is and is not covered.
- **Confidence:** confirmed
- **Effort:** M

## A7-42: The updater leaves partial or finished installers in the temp directory on every failure and after every success
- **Severity:** Low
- **Category:** rust-logic
- **Location:** `src-tauri/src/commands/updater.rs:578-611` (create + stream), `updater.rs:686-749` (launch), `updater.rs:613-616,624,635,660,669,676` (the only removals)
- **Evidence:** the destination file is created at line 578; the paths that return early WITHOUT deleting it are: `Content-Length > MAX_INSTALLER_BYTES` (587-593, leaves a 0-byte file), a chunk read error (594-598), `downloaded > MAX_INSTALLER_BYTES` (600-604, up to 512 MiB), `write_all` / `flush` errors (606-610), a failed `Command::spawn` / `opener::open` / AppImage `set_permissions`/`rename` (688-733). Removals exist only for the empty-body, digest-mismatch and signature-failure cases. A successful run never removes the installer either (it must outlive the process) and nothing prunes `sshspan-*-update-*` on the next start. For an AppImage update the leak sits in the application's own directory.
- **Why it is a flaw:** flaky connections leave up to 512 MiB of partial installer per attempt in `%TEMP%`/`/tmp`; successful updates leave a 60-100 MB installer behind forever.
- **Proposed fix:** wrap the download in a guard that removes `dest` on any `Err`; on startup delete `sshspan-*-update-*` files older than a day (like `prune_stale_stage_files`).
- **Confidence:** confirmed
- **Effort:** S

## A7-43: Every Windows secret write spawns three console programs from a GUI process with no `CREATE_NO_WINDOW`, flashing console windows
- **Severity:** Low
- **Category:** ux
- **Location:** `src-tauri/src/ssh/mod.rs:304-308,334-337,345-349`; no `creation_flags` anywhere in `src-tauri/src` (search for `CREATE_NO_WINDOW`/`creation_flags` is empty)
- **Evidence:** `restrict_windows_file` runs `whoami`, `icacls` and `icacls` via `std::process::Command` from a binary built with `windows_subsystem = "windows"` (main.rs:4-7). A GUI-subsystem parent has no console, so Windows allocates a new console window for each console-subsystem child unless `CREATE_NO_WINDOW` is set.
- **Why it is a flaw:** each deploy / private export / backup export flashes up to three black console windows (and can steal focus), which looks alarming during a security-sensitive operation. (Moot while A7-01 makes the call fail, but it returns once that is fixed.)
- **Proposed fix:** `use std::os::windows::process::CommandExt; cmd.creation_flags(0x0800_0000);` on every spawn, or replace the whole routine with the Win32 ACL APIs (`SetNamedSecurityInfoW`) via the `windows` crate.
- **Confidence:** likely
- **Effort:** S

## A7-44: An empty model reply is stored in the chat history as `{content:null, tool_calls:null}`, which both providers reject, so every later turn on that tab fails
- **Severity:** Low
- **Category:** ipc
- **Location:** `src/renderer/assistant.js:689-692`, `src-tauri/src/assistant/mod.rs:309-311,418-428`
- **Evidence:** after each reply the renderer pushes `{ role:'assistant', content: text || null, tool_calls: calls.length ? calls : null }` even when both are empty. `openai_body` then emits `{"role":"assistant","content":null}` (invalid without tool calls) and `anthropic_body` emits `{"role":"assistant","content":[]}` (Anthropic: "all messages must have non-empty content except the optional final assistant message"). A model returning an empty completion (common with small local models and with Anthropic `end_turn` with no blocks) therefore poisons the conversation; every subsequent `assistant_chat` returns a provider 400 until the tab history is cleared.
- **Why it is a flaw:** one empty reply makes the assistant unusable for that tab with an opaque "Provider error (400)".
- **Proposed fix:** do not append an assistant message with neither text nor tool calls (show "model returned nothing"), and drop such entries when building the request in `openai_body`/`anthropic_body`.
- **Confidence:** likely (request shaping proven from the code; provider validation per their public API rules)
- **Effort:** S

## A7-45: Imported key comments are stored and re-emitted verbatim; a newline in an OpenSSH-binary comment injects extra lines into `authorized_keys` text, `.pub` files and PPK headers
- **Severity:** Low
- **Category:** security
- **Location:** `src-tauri/src/crypto/keys.rs:196,376-386,650-661` and `crypto/putty.rs:656`; ssh-key 0.6.7 `public.rs:288-290` (`String::decode`, no character validation); `src-tauri/src/commands/mod.rs:1745-1757,1857`
- **Evidence:** `import_openssh_private` copies `key.comment()` straight into `PrivateKeyData.comment`; the OpenSSH private-key binary stores the comment as a length-prefixed string that ssh-key decodes without rejecting control characters. `export_openssh_public` formats `"{algo} {b64} {comment}"` and `key_import` stores that as `public_key`; the "authorized_keys" export returns it verbatim, `deploy_key` writes it to the `.pub` file, and `export_ppk` writes `Comment: {comment}\n`. Key NAMES go through `validate_key_name`; comments get no equivalent.
- **Why it is a flaw:** a crafted key file whose comment is `x\nssh-ed25519 AAAA... attacker` makes the "authorized_keys line" the user copies to a server contain a second, attacker-chosen key line; in a PPK it breaks the header structure.
- **Proposed fix:** sanitize/validate the comment on import (reject or replace control characters, cap length) and again in the export functions.
- **Confidence:** likely
- **Effort:** S

## A7-46: Host-key fingerprints use two different formats: keys show `SHA256:<unpadded>`, the trust dialog shows `SHA256:<padded with =>` and the Known Hosts table shows a bare padded string
- **Severity:** Low
- **Category:** ux
- **Location:** `src-tauri/src/crypto/utils.rs:27-30` (unpadded), `src-tauri/src/ssh_client/mod.rs:346-361,193,227,268` (padded, label added only in the dialog), `src-tauri/src/commands/terminal.rs:414-419` (`fingerprintSha256` = raw column)
- **Evidence:** `ssh_fingerprint_sha256` documents "matches `ssh-keygen -lf` exactly" (`Base64Unpadded`, `SHA256:` prefix). `fingerprint_of_blob` uses padded `Base64::encode_string`; `add_known_host` stores that value without the `SHA256:` prefix; `known_hosts_list` returns it as is; the native dialog prepends `SHA256:`. A 32-byte digest always encodes to 44 chars with one trailing `=`.
- **Why it is a flaw:** the one place a user compares a fingerprint against the server administrator's `ssh-keygen -lf` output (the first-trust dialog) shows an extra `=`, and the Known Hosts table omits the label; a copy/paste or programmatic comparison against OpenSSH output fails.
- **Proposed fix:** make `fingerprint_of_blob` return the unpadded form and have every consumer use `ssh_fingerprint_sha256`'s convention (label included); migrate stored rows once.
- **Confidence:** confirmed
- **Effort:** S

## A7-47: Staged "edit in system editor" copies of remote files are not removed when the app quits
- **Severity:** Low
- **Category:** rust-logic
- **Location:** `src-tauri/src/lib.rs:251-260` (`ExitRequested` handler), `src-tauri/src/sftp/mod.rs:85-103` (`EditRegistry::stop_all` doc claims it covers "shuts down"), `commands/mod.rs:386-387`
- **Evidence:** `EditRegistry::stop_all` (which deletes the staged files) is called from `lock_vault_internal` and nowhere on exit. The `ExitRequested` arm only clears the vault password and `kill_all`s sessions; the tray "Quit" path and the updater's `app.exit(0)` run no other teardown. Staged copies are only pruned when a later `sftp_open_for_edit` runs and the files are older than 24 h.
- **Why it is a flaw:** after "edit remote `.env`/config in an external editor" and quitting, the plaintext remote file (possibly containing secrets) stays in the temp directory up to a day or longer; the doc comment claims otherwise.
- **Proposed fix:** call `EditRegistry::stop_all()` (and cancel transfer workers) from the `ExitRequested`/`Exit` handler; also prune the staging dir at startup.
- **Confidence:** confirmed
- **Effort:** S

## A7-48: Blocking local filesystem and DNS work runs on the main thread or an async worker: `sftp_local_list`, `sftp_local_remove`, `bitwarden_save_config`, `system_select_file`
- **Severity:** Low
- **Category:** perf
- **Location:** `src-tauri/src/commands/sftp.rs:1845-1893,1949-1973` (sync `pub fn`, so Tauri runs them on the main thread), `src-tauri/src/commands/mod.rs:2465-2480` (sync `bitwarden_save_config` -> `resolve_safe_server_url`), `src-tauri/src/bitwarden/ssrf.rs:199-217` (blocking `to_socket_addrs`), `src-tauri/src/commands/mod.rs:2941-2963` (`async fn` calling `fs::read_to_string` with no size limit)
- **Evidence:** `sftp_local_list` does `read_dir` + per-entry `metadata`; `sftp_local_remove` does `remove_dir_all`; both are non-async commands. `bitwarden_save_config` is a plain `pub fn` that calls `resolve_safe_server_url`, which performs a synchronous system DNS lookup (`format!("{hostname}:0").to_socket_addrs()`); the same blocking `default_dns_lookup` is also called inside the async `ResolvingDnsResolver::resolve` future. `system_select_file` is async but reads the whole chosen file into a `String` on the runtime worker and returns it through IPC; it is the loader for key import and backup restore.
- **Why it is a flaw:** listing a huge directory or an unresponsive network/removable drive, recursively deleting a large tree, or saving a Bitwarden URL whose DNS is slow or typo'd (resolver timeouts of several seconds) freezes the whole window; picking a multi-GB file by mistake reads it all into memory and the webview; a non-UTF-8 file fails with only "stream did not contain valid UTF-8".
- **Proposed fix:** make these commands `async` and run the I/O/DNS in `tokio::task::spawn_blocking` (or `tokio::net::lookup_host`); cap `system_select_file` at a few MiB with a clear error.
- **Confidence:** likely
- **Effort:** S-M

## A7-49: Read-modify-write across awaits: `start_interactive` and `connect_server` save stale full-row snapshots over concurrent edits
- **Severity:** Low
- **Category:** rust-logic
- **Location:** `src-tauri/src/ssh_client/mod.rs:761-764`, `src-tauri/src/assistant/mcp.rs:1149-1194`
- **Evidence:** `start_interactive` ends with `let mut server = params.server; server.last_connected_at = Some(now); db.update_server(&server)`; `params.server` was loaded before the handshake (and before the blocking native host-key dialog), and `update_server` rewrites every column. `connect_server` loads `record` before the network round trips (each up to the 60 s `CALL_TIMEOUT`), builds `updated` from it, and `save_mcp_server(&updated)` overwrites the whole JSON row, including every tool's `enabled`/`pin_hash`.
- **Why it is a flaw:** an edit or tool toggle made while a connect/test is in flight is silently reverted when the connect finishes (for MCP, a tool the user just DISABLED can come back enabled); a concurrent Bitwarden sync's link metadata on a server row can be clobbered the same way.
- **Proposed fix:** use targeted statements (`UPDATE servers SET last_connected_at = ? WHERE id = ?`) and re-read the MCP record immediately before merging tools.
- **Confidence:** likely
- **Effort:** S

## A7-50: SSE tool responses are buffered until the stream closes, so a server that keeps the stream open makes every MCP call time out after 60 s
- **Severity:** Low
- **Category:** rust-logic
- **Location:** `src-tauri/src/assistant/mcp.rs:683-690` (doc), `mcp.rs:729-758` (`read_response`), `mcp.rs:668-681` (`read_capped` loops until EOF), `mcp.rs:58,511-517`
- **Evidence:** the doc says "read events until the response with `want_id` arrives", but for `text/event-stream` the code calls `read_capped` (reads to EOF), then parses all events. The Streamable HTTP spec only says a server SHOULD close the stream after the response; servers that leave it open for notifications never finish the read, and the whole request hits the client-wide 60 s timeout (`origin_client`).
- **Why it is a flaw:** `tools/list` and `tools/call` against such servers always fail with a read timeout even though the answer arrived immediately.
- **Proposed fix:** parse the SSE stream incrementally (`resp.chunk()` -> split events) and return as soon as the matching id is seen; keep the 2 MiB cap per request.
- **Confidence:** likely
- **Effort:** M

## A7-51: Removing an MCP server whose host is unreachable fails the first time (60 s hang), and only a second click removes it
- **Severity:** Low
- **Category:** ux
- **Location:** `src-tauri/src/assistant/mcp.rs:1675-1711`
- **Evidence:** `mcp_remove_server` calls `remove_session(&id)` (state removed immediately), then `delete_session(...).await.map_err(CmdError)?` with the 60 s client timeout; any transport error aborts BEFORE `db.delete_mcp_server`. The retry finds no session and succeeds.
- **Why it is a flaw:** the most common reason to remove a server entry is that it is down; the user waits up to 60 s, gets "MCP session teardown ... failed", the entry is still listed, and must press Remove again.
- **Proposed fix:** attempt the DELETE with a short timeout and treat failure as a warning (audit it) while still deleting the record.
- **Confidence:** confirmed
- **Effort:** S

## A7-52: Master-password length rule counts bytes, not characters
- **Severity:** Low
- **Category:** rust-logic
- **Location:** `src-tauri/src/commands/mod.rs:306,473`
- **Evidence:** `if password.len() < 8` / `new_password.len() < 8` use `String::len()` (UTF-8 bytes) while the messages say "at least 8 characters".
- **Why it is a flaw:** a 3-character CJK or 4-character emoji password (9 / 16 bytes) is accepted as "8 characters".
- **Proposed fix:** use `password.chars().count() < 8` (or `graphemes` if the dependency is acceptable).
- **Confidence:** confirmed
- **Effort:** S

## A7-53: Missing tests - cryptographic key-format conversions (PPK v2/v3 import/export, PKCS#8 export parse-back, comment handling)
- **Severity:** Low
- **Category:** rust-logic
- **Location:** `src-tauri/src/crypto/putty.rs:780-904` (only Argon2 bound checks), `crypto/pkcs8.rs:380-413` (only Ed25519 DER shape), `src-tauri/tests/integration.rs:290-296` (format enum equality only)
- **Evidence:** no test exports to PPK and re-imports it, imports a PuTTYgen-generated v2 or v3 file (encrypted and not), checks the PPK MAC against a known vector, or parses `export_pkcs8_private` output (RSA/ECDSA/Ed25519, encrypted and plain) with an independent decoder; no test covers comments containing spaces/newlines (A7-45) or the missing PKCS#8/PEM import promised in README.md:142 (A7-03).
- **Why it is a flaw:** the hand-written PPK reader/writer and PBES2/Ed25519 DER encoders are exactly where a one-byte error silently produces files other tools reject.
- **Proposed fix:** add round-trip tests per key type/format plus checked-in vectors from PuTTYgen and `openssl pkcs8 -topk8`.
- **Confidence:** confirmed
- **Effort:** M

## A7-54: Missing tests - SFTP transfer queue behaviour (folder expansion, short transfers, state transitions, restore)
- **Severity:** Low
- **Category:** rust-logic
- **Location:** `src-tauri/src/sftp/queue.rs:2384-2584` (pure helpers only), `src-tauri/src/commands/sftp.rs:2386-2901`
- **Evidence:** the tests cover `part_alignment`, `classify_error`, `backoff_delay`, `rate_bucket_step`, `is_dispatchable` and name sanitizers, but nothing runs `enqueue`/`dispatch`/`run_job`/`cancel_job`/`pause_job`/`resume_job`/`handle_job_failure`/`restore_pending`, although every one is generic over `tauri::Runtime` (so `tauri::test::mock_app()` could drive them once tauri's `test` feature is added to dev-dependencies; Cargo.toml currently lists only `http` there), and `copy_with_progress` is never run against an in-memory reader that EOFs early (A7-18) or a folder tree (A7-09). `cancel_for_session`/`session_busy` are dead code (A7-17).
- **Why it is a flaw:** the three queue bugs above (no remote mkdir, silent short copies, un-resumable restored jobs) survive because only leaf functions are tested.
- **Proposed fix:** add a mock-runtime queue test suite (state machine, restore, folder upload expansion + mkdir, short-read detection) using an in-memory SFTP stub or the existing `examples/dev-sshd.rs`.
- **Confidence:** confirmed
- **Effort:** L

## A7-55: Missing tests - persistence round trips and sync decision logic (backup restore for keys, `run_sync` matrix, delete cleanup, MCP merge)
- **Severity:** Low
- **Category:** rust-logic
- **Location:** `src-tauri/src/db/mod.rs:2836-2901` (restore tests cover deployment state and server linkage only), `src-tauri/src/bitwarden/sync.rs:1103-1205` (helpers only), `src-tauri/src/assistant/mcp.rs` `merge_tools`/`changed_enabled_tools`
- **Evidence:** no test restores a `vault_backup_create` payload for keys and checks `bitwarden_*` metadata (A7-27), nothing exercises `run_sync` with a mock server (the local/remote change matrix, conflicts, update-push metadata A7-23), nothing asserts `delete_key`/`delete_category` leave no dangling rows (A7-28), and `merge_tools` has no test for `auto_approve` after a definition change (A7-29).
- **Why it is a flaw:** these are exactly the data-fidelity paths where user data silently diverges.
- **Proposed fix:** add backup create -> restore -> compare tests per table, a `wiremock`-style Bitwarden fixture for `run_sync`, and migration/delete invariants.
- **Confidence:** confirmed
- **Effort:** L

## A7-56: Missing tests - Windows-only code paths and renderer/backend input contracts
- **Severity:** Low
- **Category:** rust-logic
- **Location:** `.github/workflows/ci.yml:25,72` (ubuntu only), `src-tauri/src/ssh/mod.rs:58-67,299-358`, `src-tauri/src/commands/mod.rs:1456-1465,1509-1539`, `src-tauri/tests/integration.rs:618-651`
- **Evidence:** all `#[cfg(windows)]` code (`restrict_windows_file`, Windows `path_starts_with`/`is_system_path` branches) is compiled out of CI; the one test that calls `deploy_key` writes into the REAL `~/.ssh` and app config dir and asserts nothing (`let _ = result;`, an unused temp dir). No test feeds the renderer's actual option values (`genCurve` values, settings default strings) through `KeyType::from_db_tag` or `server_save`, so A7-02, A7-11 and A7-07 pass CI.
- **Why it is a flaw:** the platform most users run is untested, and the one deploy test pollutes a developer's real SSH directory while proving nothing.
- **Proposed fix:** add `windows-latest` to the CI test matrix, make `SshService::deploy_key` take the target directories as parameters so the test can use a temp dir and assert file mode/ACL, and add contract tests for the renderer-facing enums.
- **Confidence:** confirmed
- **Effort:** M

## A7-57: Remote names that collide after local sanitisation or case-folding overwrite each other, and two jobs can write the same `.part` file concurrently
- **Severity:** Low
- **Category:** rust-logic
- **Location:** `src-tauri/src/commands/sftp.rs:961-1016` (`sanitize_remote_name`), `commands/sftp.rs:1051-1147` (`expand_download`), `src-tauri/src/sftp/queue.rs:1731-1801` (`<local>.part` staging)
- **Evidence:** `sanitize_remote_name` maps `: * ? " < > |` and control characters to `_` and strips trailing dots/spaces, and `expand_download` joins the result under the destination without checking whether another queued job already targets the same local path. On Windows (and default macOS volumes) names that differ only by case are the same file. So `a:b` and `a_b`, or `README` and `readme`, in one remote directory become two jobs for one local path with the same `<name>.part`; with `sftpParallel` up to 4 they run concurrently, each doing `create_transfer_file` (unlink + `create_new`) on that `.part`.
- **Why it is a flaw:** one of the files is silently lost, or the interleaved writers produce a corrupted file that passes the size check; common when downloading a Linux repository onto Windows.
- **Proposed fix:** track a set of case-folded local target paths per `sftp_queue_add` batch and, on a collision, either rename (`name (1)`), skip with a visible warning, or serialise the jobs.
- **Confidence:** likely
- **Effort:** M

## A7-58: Docs promise that 1.x (Electron) vaults "migrate in place", but the Rust app uses a different file location and schema and contains no importer
- **Severity:** Low
- **Category:** docs
- **Location:** `docs/ARCHITECTURE.md:76,126`, `docs/REWRITE-ROADMAP.md:57`, `CHANGELOG.md:1015`, `src-tauri/src/db/mod.rs:362-420,2998-3012`; legacy schema from `git show 4901d47^:src/main/services/database.js` lines 39-57,79-81
- **Evidence:** the docs say existing vaults "migrate without re-entry" / "same vault file, in-place migration" / "1.x vaults upgrade in place". The legacy app stored `~/.sshspan/sshspan.db` with a `keys` table of `(id, name, type, bits, comment, fingerprint, privateKeyPem, publicKeyPem, publicAuthorizedKey, encrypted, passphrase, createdAt, updatedAt, ...)` and an `audit(ts,event,detail)` table. The Rust app opens `ProjectDirs("org","sshspan","SSHSpan").data_dir()/sshspan.db` (a different directory) and creates a `keys` table with different columns (`key_type`, `private_key_encrypted`, `fingerprint_sha256`, ...) and `audit_log`; its `migrate()` only adds Rust-era columns, and nothing in `src-tauri/src` reads `~/.sshspan` or the legacy columns. Had both files been the same, `CREATE TABLE IF NOT EXISTS keys` would be skipped and every `row.get("key_type")` would panic on the legacy table.
- **Why it is a flaw:** a user following the documented upgrade path from the Electron app finds an empty vault and no way to import their old keys; the docs describe a feature that does not exist.
- **Proposed fix:** either implement a one-time importer for `~/.sshspan/sshspan.db` (map columns, re-seal private keys under the new master) or correct the three documents.
- **Confidence:** confirmed
- **Effort:** S (docs) / L (importer)

## A7-59: Deployed key file names come from a lossy sanitiser, so two different keys can overwrite each other's deployed private key
- **Severity:** Low
- **Category:** rust-logic
- **Location:** `src-tauri/src/ssh/mod.rs:90-92,279-289` (`sanitize_filename`), `src-tauri/src/crypto/keys.rs:238-260` (`validate_key_name`), `src-tauri/src/commands/mod.rs:2066-2085`
- **Evidence:** `deploy_key` names the file `sshspan_{sanitize_filename(key_name)}` where every character that is not alphanumeric, `-` or `_` becomes `_`. `validate_key_name` accepts a much wider set (`.`, `*`, `!`, `#`, `+`, `~`, Unicode letters, ...), so `github.com` and `github_com`, `web*prod` and `web_prod`, or (on Windows) `Prod` and `prod` map to the same path. `write_secret_file` replaces whatever is there, and both key records then carry the same `deploy_path`.
- **Why it is a flaw:** deploying the second key silently replaces the first key's private file (the first key's `Host` stanza now points at the wrong key and authentication fails), and `key_remove_deployed` on either record would delete the other's file.
- **Proposed fix:** include a short stable id in the file name (`sshspan_<name>_<id8>`) or detect an existing `deploy_path` owned by a different key id and refuse/rename.
- **Confidence:** confirmed
- **Effort:** S
