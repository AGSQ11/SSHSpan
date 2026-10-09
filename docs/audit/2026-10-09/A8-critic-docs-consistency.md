# A8 - Code critic: docs/code truthfulness, in-app copy, code structure, CI scripts

**Counts:** Critical 0 · High 6 · Medium 15 · Low 8 (29 findings).
**Covered:** README, CHANGELOG (1.9.1/1.9.0/1.8.0/1.7.3), docs/ARCHITECTURE, SECURITY, PRIVACY, MCP-SMOKE-TEST, REWRITE-ROADMAP, CONTRIBUTING, vendor/VENDOR.md, package.json, tauri.conf.json, Cargo.toml, ci.yml; every claim cross-read against `src/renderer/*`, `src-tauri/src/**`, `scripts/*`. In-app copy in index.html + all five renderer scripts (every `toast()`, label, placeholder, tooltip). Structure: duplicated/diverged logic, dead code (scratch scripts under `.superpowers/audit/scratch/A8/`), comment-vs-code, event/IPC names, CI script coverage.
**Not covered:** release.yml internals, vendor code, runtime behaviour that needs a live Tauri/WebView2 process (one finding, A8-18, is therefore "likely" not "confirmed"), installer sizes, the `screenshots/` content vs current UI (files exist; README already discloses they are stale).
**Headline:** on a fresh install the documented 15-minute idle auto-lock is off while Settings displays 15 (A8-00); the deploy sheet's live "What this will write" preview is fiction (A8-01); the Servers-view "Import from ~/.ssh/config" never reads `~/.ssh/config` (A8-02); the three keyboard-compatibility settings write into the local display instead of the SSH session (A8-03); SECURITY/PRIVACY claim audit coverage and network-destination lists that the code does not deliver (A8-04, A8-05).

---

## A8-00: README/SECURITY/Settings say the vault auto-locks after 15 idle minutes by default; with the setting unset (every fresh install) the renderer timer is off and the backend watchdog is neutralised by the unconditional heartbeat
- **Severity:** High
- **Category:** js-logic
- **Location:** `src/renderer/app.js:3566-3569` (`parseInt(undefined)` -> NaN -> `!mins` -> "auto-lock off"), `src/renderer/app.js:2510` (Settings row displays `state.settings.autoLockMinutes || 15`), `src/renderer/app.js:3598-3607` (comment "0/absent still disables auto-lock (the backend reads the same setting)"; heartbeat every 30 s unconditionally), `src-tauri/src/commands/mod.rs:440-457` (watchdog: absent -> `unwrap_or(15)`, fires only when no heartbeat for 15 min), `src-tauri/src/commands/mod.rs:2789-2810` (`collect_settings` returns only keys present in the DB; nothing seeds `setting.autoLockMinutes`); claims `README.md:15-16`, `docs/SECURITY.md:93-94`, `docs/PRIVACY.md:105-106`; test `scripts/check-renderer-ui.js:719` seeds `autoLockMinutes: 15` so the fresh-install state is never exercised
- **Evidence:** `grep -rn 'set_config("setting.' src-tauri/src` shows only `sftpMaxBps` is ever written by the backend; the DB has no `setting.autoLockMinutes` row until the user edits the Settings control. On that state: the vault chip reads "auto-lock off" (app.js:3588) while the Settings row one click away shows "15"; the renderer never schedules `lockNow`; the backend watchdog's `ActivityTracker` is touched by the 30-second heartbeat whether or not the user is active (3603-3607), so it can only fire for a hung webview, never for an idle user. The in-code comment claims renderer and backend agree on "absent = disabled"; the backend actually treats absent as 15.
- **Why it is a flaw:** The documented security default ("auto-locks after 15 minutes of inactivity", the "primary UX path" per mod.rs:431) is not in effect for anyone who has not opened Settings and changed the value, and the Settings UI states the opposite. Three places disagree (chip: off; row: 15; backend: 15-but-inert).
- **Proposed fix:** Default in one place: have `collect_settings` (or `vault_create`) emit `autoLockMinutes = "15"` when absent, or change app.js:3568 to `parseInt(state.settings.autoLockMinutes ?? '15', 10)`; make the heartbeat carry real activity (send it from the activity listener at app.js:4537-4539, throttled) so the backend watchdog is an idle watchdog as its doc claims; fix the comment at 3601-3602; remove the `autoLockMinutes` seed from the UI test's default reply so the fresh state is covered.
- **Confidence:** confirmed (code reading)
- **Effort:** S

---

## A8-01: Deploy sheet's live preview ("What this will write") does not describe what the backend writes
- **Severity:** High
- **Category:** js-logic
- **Location:** `src/renderer/app.js:2140-2168` (previewConfig), `src/renderer/app.js:2170-2192` (deployConfig sends only `{ids, passphrase, strictHostKey}`), `src/renderer/index.html:666`, `src/renderer/index.html:675-677`, `src/renderer/index.html:705-715`; backend `src-tauri/src/commands/mod.rs:2035-2075` (`SshService::deploy_key(&key.name, ..., Some(&key.name), None, None, None, strict_host_key)`), `src-tauri/src/ssh/mod.rs:76-193`, `src-tauri/src/config/mod.rs:113-162` (`to_config_string`), `src/renderer/app.js:226-228` vs `src-tauri/src/ssh/mod.rs:279-289` (two different name sanitizers)
- **Evidence:** The sheet header says "What this will write ... updates as you type" and renders, per key:
  `Host <alias>` / `HostName <alias>` / `User <user>` / `Port <port>` / `IdentityFile ~/.ssh/sshspan_<safeFileName(name)>` / `IdentitiesOnly yes` / `StrictHostKeyChecking yes|no`, wrapped in `# >>> SSHSpan managed >>>` ... `# <<< SSHSpan managed <<<` (app.js:2152-2167). `deployConfig()` then calls `key_deploy` with `{ ids, passphrase, strictHostKey }` only (app.js:2192) - the alias, user and port inputs are never transmitted (they are only reused for the optional "Also save as servers" step, 2204-2227). `key_deploy` passes `host_alias = Some(&key.name)`, `hostname = None`, `user = None`, `port = None` (mod.rs:2066-2075), and `to_config_string` emits `Host <key.name>` / `IdentityFile <absolute path>` / `IdentitiesOnly yes` / `ForwardAgent no` / `stricthostkeychecking yes|no` - no HostName, no User, no Port, no markers (ssh/mod.rs:159-182, config/mod.rs:123-159). The string `SSHSpan managed` does not occur anywhere in `src-tauri/`. The file name in the preview uses `safeFileName` (`[^\w.\-]+` -> `-`, 64-char cap) while Rust uses `sanitize_filename` (anything but alnum/`-`/`_` -> `_`, no cap): a key named `github.com` previews as `sshspan_github.com` and is written as `sshspan_github_com`. The preview also implies `~/.ssh/config` ("adds a matching Host block to your SSH config", index.html:666) while the backend writes to the app-config-dir file (A8-06).
- **Why it is a flaw:** The user types an alias/user/port, is shown a config block containing them, confirms, and gets a block that has none of them under a different `Host` name in a file OpenSSH does not read. `ssh <alias>` after deploying does not work as previewed. The sheet exists precisely to answer "what will this write?" (CHANGELOG 406-410) and the answer is wrong on five counts.
- **Proposed fix:** Either (a) extend `key_deploy` with `host_alias`, `hostname`, `user`, `port` and pass them through to `deploy_key` (which already accepts them), and have the backend return the exact text it wrote so the preview can be generated by the same code (`to_config_string`) - or (b) make the preview call a new `ssh_config_preview` command that runs `to_config_string` server-side. In both cases delete the fake markers and the renderer-side sanitizer, and show the real `IdentityFile` path (from `system_paths().deployDir` + Rust sanitizer).
- **Confidence:** confirmed (code reading, both sides)
- **Effort:** M

## A8-02: "Import a Host block from ~/.ssh/config" reads SSHSpan's own managed config, never the user's `~/.ssh/config`
- **Severity:** High
- **Category:** js-logic
- **Location:** `src/renderer/index.html:188` (tooltip "Import a Host block from ~/.ssh/config"), `src/renderer/app.js:2241-2246`, `src-tauri/src/commands/mod.rs:2437-2441` (`ssh_config_list_hosts` -> `SshConfigService::new()`), `src-tauri/src/config/mod.rs:197-199, 259-267` (`ssh_config_path()` = `ProjectDirs(...).config_dir()/ssh/config`), `CHANGELOG.md:317-320`, `docs/REWRITE-ROADMAP.md:244-246`
- **Evidence:** `ssh_config_list_hosts` reads through `SshConfigService::new()`, whose path is `ProjectDirs::from("org","sshspan","SSHSpan").config_dir().join("ssh").join("config")` (e.g. `%APPDATA%\sshspan\SSHSpan\config\ssh\config`); the `~/.ssh/config` branch (config/mod.rs:262-263) is only the fallback when ProjectDirs is unavailable. That file is written solely by `deploy_key` (ssh/mod.rs:185), so it can only ever contain Host blocks SSHSpan itself generated. The button tooltip, the code comment (app.js:2241 "Import a Host block from ~/.ssh/config"), CHANGELOG 1.9.0 ("Importing a host from `~/.ssh/config` warns about directives that are ignored") and the roadmap all describe importing the user's real SSH config. The ProxyJump/ProxyCommand/ForwardAgent warning (app.js:2273-2281) can never fire, because `deploy_key` never writes those directives.
- **Why it is a flaw:** The one feature that promises to pull existing hosts into SSHSpan cannot see any of them; a user with a populated `~/.ssh/config` gets "No Host blocks found in C:\Users\...\sshspan\SSHSpan\config\ssh\config" and no way to import. The warning code and changelog entry document behaviour that is unreachable.
- **Proposed fix:** Add a read-only command (or a parameter on `ssh_config_list_hosts`) that parses `dirs::home_dir()/.ssh/config` with the existing `SshConfig::parse`, and point `importFromSshConfig` at it; keep the managed file for writes. Or, if reading the user's config is not wanted, relabel the button/tooltip/changelog to "Import a Host block SSHSpan deployed" and delete the unreachable ProxyJump warning.
- **Confidence:** confirmed
- **Effort:** S

## A8-03: The three keyboard-compatibility settings write escape sequences into the local display, not into the SSH session
- **Severity:** High
- **Category:** js-logic
- **Location:** `src/renderer/terminal.js:105-140` (`buildKeyCompatibilityHandler`: `term.write('\x1b[7~')`, `term.write(CURSOR[event.key])`, `term.write(KEYPAD[...])`, each followed by `return false`), `src/renderer/terminal.js:541-549` (the only path to the remote is `t.onData(...) -> terminal_send`), `src/renderer/terminal.js:321-329` (comment: "Each branch writes the compatibility sequence and returns false so xterm does not also emit its own"); settings copy `src/renderer/app.js:2807-2844`; `CHANGELOG.md:198-202`
- **Evidence:** xterm's `Terminal.write()` renders data *to* the terminal (output direction); keystrokes reach the backend only through the `onData` subscription at terminal.js:541, which `write()` never fires. The vendored xterm 5.5.0 exposes `Terminal.input(data, wasUserInput)` -> `coreService.triggerDataEvent` (vendor/xterm.js), which is the API that would deliver bytes to `onData`. With "Home and End key mode: rxvt" the handler writes `ESC[7~` into the local buffer (ignored by the parser) and returns `false`, so nothing is sent to the remote - Home/End become dead keys. With "Disable application cursor keys" each arrow writes `ESC[A..D` locally, moving the *local* cursor without sending anything - arrows become dead keys that corrupt the display. Same for the keypad option. The 1.9.0 changelog says these settings "are now enforced per-terminal via `attachCustomKeyEventHandler`", and the Settings rows describe them as changing what the key *sends* ("Backspace key sends", "Switch to rxvt if those keys misbehave on an older host").
- **Why it is a flaw:** Enabling any of the three settings breaks the affected keys for every new terminal, the opposite of what the row text promises. The in-code comment describes an intent the code does not implement.
- **Proposed fix:** Replace each `term.write(seq)` in `buildKeyCompatibilityHandler` with `term.input(seq, true)` (or call `sendTerminalBytes(rec, seq)` directly); add a Playwright assertion in `scripts/check-renderer-ui.js` that with `terminalHomeEnd='rxvt'` a Home keydown results in a `terminal_send` of `1b 5b 37 7e` and no local buffer change.
- **Confidence:** confirmed (xterm API semantics + code reading)
- **Effort:** S

## A8-04: SECURITY.md and PRIVACY.md overstate audit-log coverage: no `sync.*` run events and no settings-change events are ever written
- **Severity:** High
- **Category:** docs
- **Location:** `docs/SECURITY.md:175-178` ("a remote deletion is only reported in the summary and audit log"; "Every sync action is audited (`sync.config`, `sync.push`, `sync.pull`, `sync.run`, `sync.error`)"), `docs/PRIVACY.md:80-81` ("every sync action is recorded in the local audit log"), `docs/PRIVACY.md:125-128` ("... sync actions, and settings changes"); code `src-tauri/src/commands/mod.rs:2579-2657` (`bitwarden_sync`: no `add_audit` call), `src-tauri/src/bitwarden/sync.rs:90, 731` (only `sync.folder_migrated` and `keys.name_sanitized`), `src-tauri/src/commands/mod.rs:2836-2855` (`settings_set`: no `add_audit`)
- **Evidence:** Enumerating every `add_audit("...")` literal in `src-tauri/src` yields 46 event names; the only `sync.*` names are `sync.config` (written on save) and `sync.folder_migrated`. There is no `sync.push`, `sync.pull`, `sync.run`, `sync.error`, and no `settings.*` event. `bitwarden_sync` stores the result in `bitwarden_config.last_result` and returns it, nothing more. A sync run that pushes private keys to the configured server therefore leaves no audit row; a remote deletion is only in `last_result`.
- **Why it is a flaw:** Both documents present the audit log as the user's means of reviewing what left the machine ("Review the audit log periodically...", SECURITY.md:364). A reader checking for unexpected sync activity will find nothing and conclude none happened. This is a security-relevant false claim.
- **Proposed fix:** Either write `sync.run` (with the counts), `sync.error`, and `settings.changed` entries from `bitwarden_sync` / `settings_set`, or correct the two documents to list exactly the events that exist (the enumeration above) and drop "settings changes".
- **Confidence:** confirmed
- **Effort:** S

## A8-05: PRIVACY.md says there are "exactly three kinds of outbound network connections, nothing else" - the AI provider and MCP servers are missing, and the document is pinned to v1.7.x
- **Severity:** High
- **Category:** docs
- **Location:** `docs/PRIVACY.md:5` ("(v1.7.x)"), `docs/PRIVACY.md:12-13, 51-52, 139-144`; contradicted by `docs/SECURITY.md:8-9, 101-110` (fourth and fifth destinations), `src-tauri/src/assistant/mod.rs:546-552` (`assistant_chat` posts the conversation to the configured provider), `src/renderer/assistant.js:507-516, 657-661` (last ~200 lines / 8 KiB of terminal scrollback are attached to every turn), `src-tauri/src/assistant/mcp.rs:511-517`
- **Evidence:** Since 1.9.0 the assistant sends the user's chat plus a snapshot of the live terminal (hostnames, prompts, command output) to a third-party model endpoint, and since 1.9.1 MCP tool calls carry user-approved arguments to arbitrary user-configured servers. SECURITY.md was updated to list these as destinations four and five; PRIVACY.md still says three, still says "no third party receives any of it, unless the user enables the optional sync below", and still describes the implementation as v1.7.x.
- **Why it is a flaw:** The privacy document is the one place a user is told what leaves the machine; terminal scrollback going to an LLM vendor is the most privacy-relevant flow the app has, and the document denies it exists ("nothing else").
- **Proposed fix:** Add sections for the AI provider (what is sent per turn: system prompt, chat, up to 200 lines / 8 KiB of terminal text, tool results; to the user-entered base URL; opt-in) and for MCP servers (tool arguments and results), update the "three kinds" count and the "no third party" sentence, and replace "v1.7.x" with the current version or remove the pin.
- **Confidence:** confirmed
- **Effort:** S

## A8-06: Three docs give three different, all-wrong locations for the vault database and the managed SSH config
- **Severity:** Medium
- **Category:** docs
- **Location:** `docs/ARCHITECTURE.md:27, 78, 86-88` (`~/.sshspan/sshspan.db`, `~/.sshspan/keys`, "managed block in `~/.ssh/config`"), `docs/SECURITY.md:65-66` (`%APPDATA%\SSHSpan\sshspan.db`, `~/.local/share/SSHSpan/sshspan.db`), `docs/PRIVACY.md:47, 49` (`%APPDATA%\SSHSpan\sshspan.db`, a macOS path, `%APPDATA%\SSHSpan\ssh\config`), `README.md:13-14` ("deploy keys into `~/.ssh/config`"); code `src-tauri/src/db/mod.rs:3010-3012` (`ProjectDirs::from("org","sshspan","SSHSpan").data_dir()/sshspan.db`), `src-tauri/src/config/mod.rs:259-267` (`.config_dir()/ssh/config`), `src-tauri/src/commands/mod.rs:2757-2766` (the `system_paths` doc comment: "Users make security decisions on those strings ... so a wrong one is a real defect, not a typo")
- **Evidence:** With the `directories` crate, `ProjectDirs::from("org","sshspan","SSHSpan")` resolves to `%APPDATA%\sshspan\SSHSpan\data\sshspan.db` and `%APPDATA%\sshspan\SSHSpan\config\ssh\config` on Windows, and `~/.local/share/sshspan/sshspan.db` / `~/.config/sshspan/ssh/config` on Linux. ARCHITECTURE names a `~/.sshspan/` layout that exists nowhere in the code; SECURITY has the wrong Windows path and the wrong Linux case; PRIVACY has the wrong Windows paths and a macOS path for a Windows/Linux-only app (package.json:46-49). README and ARCHITECTURE say Host blocks go into `~/.ssh/config`; nothing writes there (A8-01/A8-02). The project's own `system_paths` comment records that these exact strings were already found wrong once and moved to the backend "so they cannot drift again" - the documents were not updated.
- **Why it is a flaw:** SECURITY.md's operational guidance tells users to back up and protect "the app-data directory"; a user following the stated paths protects/backs up the wrong directory, and a user grepping `~/.ssh/config` for SSHSpan's Host blocks finds none.
- **Proposed fix:** Replace every literal path in the three docs with the derived form ("the platform app-data directory for `org.sshspan.SSHSpan` - shown under Settings > General > Vault file") and one correct example per platform; delete the macOS row; change README:13 to "deploy keys to `~/.ssh/` with a Host block in SSHSpan's managed config (shown in the deploy sheet)".
- **Confidence:** confirmed
- **Effort:** S

## A8-07: docs/ARCHITECTURE.md describes a codebase several releases old (IPC table, renderer files, KDF, DevTools, views, schema)
- **Severity:** Medium
- **Category:** docs
- **Location:** `docs/ARCHITECTURE.md:14-17, 23, 37-38, 55, 59-68, 75-76, 78-79, 113-123, 146, 149`; code `src-tauri/src/lib.rs:102-225`, `src-tauri/src/commands/mod.rs:1002-1036, 2421-2434`, `src-tauri/Cargo.toml:15-17`, `src-tauri/src/crypto/vault.rs:28-33`, `src-tauri/src/db/mod.rs:366-643`, `src/renderer/index.html:30-34`
- **Evidence:** (1) The IPC table lists 44 commands; `generate_handler!` registers 111. It names `vault_export`, `vault_import`, `ssh_config_write` as live commands - all three are deliberately *not* registered (mod.rs:1002-1009, 1031-1034, 2421-2427 say so) - and omits the entire SFTP (39), assistant (7), MCP (6), updater (2), backup (2) and `key_export_to_file`/`key_rename`/`audit_clear`/`system_paths`/`heartbeat` surface. (2) The renderer box lists app.js, terminal.js, icons.js, vendor/ - not sftp.js (3993 lines), assistant.js, mcp.js. (3) Line 75: "`seal()`/`unseal()`: bcrypt-pbkdf2 KDF ... Same scheme as the 1.x Node app, so existing vaults migrate without re-entry" - the KDF is Argon2id (vault.rs:32), there is no scrypt/bcrypt path anywhere in `src-tauri/`, so a Node-era vault cannot be opened; the vault.rs:29-31 comment "Matches Node.js crypto.scryptSync with N=65536" is equally false (Argon2id with m=65536 is not scrypt). (4) Line 37-38: "DevTools in release builds are safe" - Cargo.toml:15-16 compiles DevTools out ("No `devtools` feature: WebView2 DevTools must not ship in release builds"), as README:246 correctly says. (5) Line 146: "The five views (Keys, Connect, Deploy, Settings, Audit)" - since 1.8.0 there are two views plus Settings (index.html:25-34). (6) Lines 78-79/113-123: table list names `audit` (actual `audit_log`), omits `bitwarden_config`, `assistant_config`, `mcp_servers`, `transfer_queue`, the categories `scope` column and known_hosts `source`. (7) Line 149: "sqlx ... compile-time-checked queries" - no `query!`/`query_as!` macro is used anywhere; CHANGELOG:105-111 even blames the non-macro `query()` for a silent bug. (8) Line 23: "40+ handlers" (111). Line 28: "config/ - ~/.ssh/config parser/writer" (it parses the managed file, A8-02).
- **Why it is a flaw:** README:282-283 points contributors here for "the process/module layout". Almost every concrete statement is wrong; a contributor trusting it will call unregistered commands, look for files that do not exist and believe the vault format is scrypt-compatible.
- **Proposed fix:** Regenerate the IPC table from `lib.rs` (a 10-line node script, or make it a CI check like `check-ipc-args.js`), list all renderer files, fix KDF/DevTools/views/schema sentences, drop "compile-time-checked", and fix the vault.rs:29-31 comment ("Argon2id m=64 MiB, t=3, p=4; not compatible with the Node-era scrypt vaults").
- **Confidence:** confirmed
- **Effort:** M

## A8-08: SECURITY.md and PRIVACY.md say Bitwarden plain-HTTP is allowed for loopback; the code refuses all plain HTTP and all localhost names (and the same documents also say so two sentences later)
- **Severity:** Medium
- **Category:** docs
- **Location:** `docs/SECURITY.md:151-152` ("Plain `http://` is refused except for loopback targets (self-hosted Vaultwarden testing)") vs `docs/SECURITY.md:153-157, 185-186`; `docs/PRIVACY.md:60-62` (same contradiction in one bullet); code `src-tauri/src/bitwarden/ssrf.rs:247-272`
- **Evidence:** ssrf.rs:264-266 `if scheme == "http" { bail!("Server URL must use https://.") }` with a 15-line comment explaining that the loopback exception "was unreachable ... Removed rather than made to work", followed by the localhost/`.localhost`/`.local` rejection at 268-272. The Settings card (index.html:337-339) correctly says "private, LAN and localhost addresses are refused"; the two docs still carry the removed exception and contradict themselves within the same paragraph.
- **Why it is a flaw:** A self-hoster reading SECURITY/PRIVACY will try `http://127.0.0.1:8080`, be refused, and have no idea which of the two sentences to believe.
- **Proposed fix:** Delete the "except for loopback targets" clause in both docs (keep "HTTPS-only"), and note that the UI's MCP section, unlike Bitwarden, *does* allow loopback HTTP (mcp.rs:112-121) so the two features are not confused.
- **Confidence:** confirmed
- **Effort:** S

## A8-09: SECURITY.md says weak server-announced Bitwarden KDF parameters are "rejected rather than used"; the code silently clamps them in both directions
- **Severity:** Medium
- **Category:** docs
- **Location:** `docs/SECURITY.md:162-163`; code `src-tauri/src/crypto/bitwarden.rs:69-98` (`clamp_kdf_params`: `iterations.clamp(...)`, `memory.clamp(...)`), `src-tauri/src/bitwarden/mod.rs:244-246`; `CHANGELOG.md:594-599` (correctly says "clamped at both ends")
- **Evidence:** `clamp_kdf_params` returns `Ok` with clamped values for every in-range or out-of-range input; only an unknown `kdf_type` errors. A server announcing 100 000 PBKDF2 iterations is not rejected - the client derives with 600 000 and the login then fails with a wrong-hash error, which the user cannot distinguish from a mistyped password. The ceilings (10 M iterations, 1 GiB) described in the changelog are absent from SECURITY.md altogether.
- **Why it is a flaw:** The document describes a fail-loud behaviour the code does not have, and omits the ceiling that is the actual DoS defence.
- **Proposed fix:** Rewrite the bullet: "Server-announced KDF parameters are clamped per algorithm to [600k, 10M] PBKDF2 iterations / [2,16] passes, [16 MiB, 1 GiB], [1,16] lanes for Argon2id; a server outside the range therefore cannot authenticate." Optionally make the floor case an explicit error in `clamp_kdf_params` so the user gets an actionable message.
- **Confidence:** confirmed
- **Effort:** S

## A8-10: Literal "[OI]" placeholder tokens and a truncated placeholder ship in the Settings > AI assistant screen (and in README/CHANGELOG)
- **Severity:** Medium
- **Category:** ui
- **Location:** `src/renderer/index.html:370` (`<option value="openai">[OI]-compatible (chat/completions)</option>`), `src/renderer/index.html:379` (preset `[OI]`), `src/renderer/index.html:389` (`placeholder="gpt-4o-mini / "`), `src/renderer/index.html:400` ("Works with [OI], OpenRouter, ..."), `README.md:55, 180, 182`, `CHANGELOG.md:213, 260-261`, `src-tauri/src/assistant/mod.rs:276, 312, 776, 875` (comments)
- **Evidence:** Every occurrence sits where the provider name "OpenAI" belongs (`value="openai"`, preset URL `https://api.openai.com/v1`, "chat/completions"); the surrounding text survived, only the brand token was replaced with `[OI]`. The model placeholder ends in `" / "` with nothing after the slash. These are the default-selected option label and the status strip of a primary settings section.
- **Why it is a flaw:** Users see bracketed tokens and a half-sentence placeholder in the UI; README/CHANGELOG readers cannot tell which provider the default option targets. Reads as unfinished.
- **Proposed fix:** Replace `[OI]` with the intended provider name (or a neutral "OpenAI-style" if the brand is being avoided deliberately) in index.html, README, CHANGELOG and the Rust comments; complete the model placeholder (e.g. `gpt-4o-mini / claude-3-5-haiku-latest / llama3`).
- **Confidence:** confirmed
- **Effort:** S

## A8-11: The "Create your vault" dialog tells the user the vault uses scrypt; it uses Argon2id
- **Severity:** Medium
- **Category:** ui
- **Location:** `src/renderer/app.js:1045` ("It encrypts every private key at rest (scrypt + AES-256-GCM)"); code `src-tauri/src/crypto/vault.rs:30-33`; docs `docs/SECURITY.md:45-46`, `README.md:287`
- **Evidence:** `VaultKey::derive_from_password` uses `Argon2::new(Algorithm::Argon2id, ...)` with `Params::new(65536, 3, 4, ...)`. SECURITY.md and README both say Argon2id. The only place a user is told the algorithm inside the app - the moment they choose the password - names a different one.
- **Why it is a flaw:** A security claim shown at the single most security-relevant moment is wrong; it also contradicts the project's own security document.
- **Proposed fix:** Change the string to "(Argon2id + AES-256-GCM)" or drop the parenthetical.
- **Confidence:** confirmed
- **Effort:** S

## A8-12: Passphrase-protected OpenSSH and PuTTY exports are documented as available but unreachable from the UI
- **Severity:** Medium
- **Category:** ux
- **Location:** `docs/SECURITY.md:95-98` ("Exports ... can be passphrase-protected: OpenSSH format (aes256-ctr + bcrypt KDF), PKCS#8 PBES2 ..., or PuTTY PPK v3"), `docs/PRIVACY.md:114-115`; renderer `src/renderer/app.js:1768-1773` (`SEALED_EXPORT_FORMATS = ['pkcs8-encrypted']`), `src/renderer/app.js:1778-1779` (OpenSSH row sub "Unprotected."), `src/renderer/app.js:1820-1825` (passphrase field hidden and *cleared* for every non-PKCS#8 format); backend `src-tauri/src/commands/mod.rs:1928-1937` (`"openssh-private" => export_private_key(..., KeyFormat::OpenSsh, pass)`, `"ppk" => ... KeyFormat::Putty, pass`); `CHANGELOG.md:358-362`
- **Evidence:** The backend honours `passphrase` for OpenSSH and PPK exports. Since the 1.8.0 export redesign the renderer shows the passphrase field only for `pkcs8-encrypted` and wipes any typed value before calling `key_export_to_file`, so `pass` is always `None` for those two formats. The 1.8.0 changelog justifies this by saying the field was previously shown "for the four formats that ignore it" - but OpenSSH and PPK do not ignore it.
- **Why it is a flaw:** A documented security capability (encrypting the exported id_ed25519 / .ppk with its own passphrase) cannot be used; the UI explicitly labels the OpenSSH export "Unprotected" while SECURITY.md promises protection.
- **Proposed fix:** Add `openssh-private` and `ppk` to `SEALED_EXPORT_FORMATS` as *optional*-passphrase formats (field visible, may be left blank), relabel the rows ("Unprotected unless you set a passphrase"), or - if the product decision is to not offer it - remove the claim from SECURITY.md/PRIVACY.md.
- **Confidence:** confirmed
- **Effort:** S

## A8-13: CHANGELOG says the AI API key is "clearable on demand"; nothing in the renderer can clear it
- **Severity:** Medium
- **Category:** ux
- **Location:** `CHANGELOG.md:211-216` ("API key sealed ..., never returned over IPC, rotatable with it, and clearable on demand"); backend `src-tauri/src/assistant/mod.rs:104-116, 154` (`clear_api_key: Option<bool>` - "which otherwise made a stored key impossible to remove"); renderer `src/renderer/assistant.js:773-791` (sends `provider`, `base_url`/`baseUrl`, `model`, `api_key`/`apiKey` only), `src/renderer/index.html:391-394` (API key field, "Leave blank to keep the stored key"; no clear control)
- **Evidence:** `grep -rn clearApiKey src/renderer` returns nothing. The only way to drop a stored key is to overwrite it with another one; "Leave blank" keeps it by design.
- **Why it is a flaw:** A user who wants to revoke the assistant's credential (e.g. before sharing a backup/laptop) cannot, and the changelog says they can. The backend already implements the half the UI lacks.
- **Proposed fix:** Add a "Remove stored key" ghost button next to the API key field that calls `assistant_save_config` with `clearApiKey: true` (and the current provider/model), then refresh the "key stored" hint.
- **Confidence:** confirmed
- **Effort:** S

## A8-14: Settings shows "Parallel file transfers: 2" when the setting is unset while the backend runs 4 (README says 4)
- **Severity:** Medium
- **Category:** ui
- **Location:** `src/renderer/app.js:2600` (`sftpParallel.value = state.settings.sftpParallel || 2`), `src/renderer/app.js:2602` (`|| 2` fallback on parse), `src-tauri/src/sftp/queue.rs:573-585` (`parallel_limit` ... `.unwrap_or(4)`), `README.md:201-202` ("four transfers run in parallel by default (1-4 configurable)")
- **Evidence:** Two different defaults for one setting. On a fresh install the row displays 2 and the queue uses 4 until the user touches the control; typing a non-number saves 2.
- **Why it is a flaw:** The settings row states a value that is not in effect - exactly the class of "setting lies" the 1.9.0 changelog spent a release fixing.
- **Proposed fix:** Change both fallbacks in app.js to 4 (or better, have `collect_settings` return effective defaults so the renderer never guesses).
- **Confidence:** confirmed
- **Effort:** S

## A8-15: The MCP "definition changed - re-approve" notice can never render: the backend disables a changed tool, and the renderer only shows the notice for *enabled* unpinned tools
- **Severity:** Medium
- **Category:** js-logic
- **Location:** `src/renderer/mcp.js:445-446` (`needsReapprove = t.enabled && !t.pinned`), `src/renderer/mcp.js:469-474, 512-522`; backend `src-tauri/src/assistant/mcp.rs:1221-1223` (`Some(p) => (false, p.auto_approve, p.pin_hash.clone())` - enabled becomes false, the stale pin is kept), `src-tauri/src/assistant/mcp.rs:1476` (`"pinned": tool.pin_hash.is_some()`); docs `docs/MCP-SMOKE-TEST.md:89-93` (step 13 expects the notice), `CHANGELOG.md:25-27`, `README.md:30-31`
- **Evidence:** After a rug-pull the record arrives as `{enabled:false, pinned:true}`; `needsReapprove` is therefore `false`, the row gets no `changed` class, no "Definition changed" text, and the Enable toggle has no title hint. The tool simply appears switched off with no explanation. The only state that would trigger the notice (`enabled && !pinned`) cannot be produced by `merge_tools` (a tool is only enabled through `mcp_set_tool_state`, which pins it).
- **Why it is a flaw:** The rug-pull guard works, but its user-facing half is dead: the user sees a tool they approved silently disabled and may re-enable it without knowing the definition changed - defeating the purpose of demanding re-approval. Smoke-test step 13 would fail as written.
- **Proposed fix:** Expose the mismatch from the backend (`"changed": tool.pin_hash.is_some() && tool.pin_hash != tool.current_hash`) in `tool_view` and drive `needsReapprove` from that flag; or in the renderer compute `needsReapprove = !t.enabled && t.pinned && t.changed`. Add the case to `check-renderer-ui.js`.
- **Confidence:** confirmed
- **Effort:** S

## A8-16: README calls deployed Host blocks "reversible", but no UI path removes a deployment; `key_remove_deployed` and 10 other registered commands have no renderer caller
- **Severity:** Medium
- **Category:** ux
- **Location:** `README.md:231-234` ("manages reversible `Host` blocks"); `src-tauri/src/lib.rs:122` (`key_remove_deployed` registered), `src-tauri/src/commands/mod.rs:2099-2155`; `src/renderer/app.js:1518-1519` (Deployed chip, no action), `src/renderer/app.js:1696` ("Deployed copies on disk are not removed."); dead-IPC policy `src-tauri/Cargo.toml:19-24`
- **Evidence:** Every `call()/sftpCall()/aiCall()/mcpCall()` in the renderer uses a literal command name (only `app.js:23` and `sftp.js:19` forward a variable, and they are the wrappers). Cross-checking the 111 registered names against those literals leaves 11 commands nothing invokes: `key_generate`, `key_fingerprint`, `key_remove_deployed`, `ssh_config_read`, `terminal_keepalive`, `sftp_file_sha256`, `sftp_set_mtime`, `sftp_upload`, `sftp_close_edit`, `sftp_queue_resume_all`, `sftp_stage_path`. Deleting a key explicitly leaves the deployed files and Host block behind (app.js:1696), and nothing else calls `key_remove_deployed`, so a deployment can only be undone by hand. Cargo.toml:19-24 states the project's own rule: plugins/commands "never called from the renderer ... dead IPC surface ... were removed".
- **Why it is a flaw:** "Reversible" is false in the shipped UI; a user who deploys a key to the wrong machine has no in-app undo. The 11 live-but-uncalled commands widen the surface a compromised renderer can reach (`sftp_stage_path` + `sftp_upload` were part of the 1.7.3 escalation chain, CHANGELOG:422-429) for no product benefit.
- **Proposed fix:** Add an "Undeploy" action to the Deployed chip / key context menu that calls `key_remove_deployed`; then either wire or unregister each of the other 10 (keep `#[tauri::command]` fns out of `generate_handler!` with a doc comment, as `ssh_config_write` already does). Consider a CI assertion that every registered command has a renderer literal (a 15-line addition to `check-ipc-args.js`).
- **Confidence:** confirmed
- **Effort:** M

## A8-17: CI never checks the assistant's 7 IPC call sites (and hedges them with duplicate snake+camel keys); globals check skips assistant.js/mcp.js; the MCP contract check exists three times
- **Severity:** Medium
- **Category:** ipc
- **Location:** `scripts/check-ipc-args.js:25, 92` (JS_FILES lists assistant.js, but the site regex matches only `call|mcpCall|.invoke|invoke` - `aiCall(` is never matched); `src/renderer/assistant.js:56, 112, 159, 540, 683-688, 776-783`; `scripts/check-renderer-globals.js:28, 32` (FILES = app/sftp/terminal/icons only; OWNED prefixes lack `ai|mcp|assistant`); `scripts/check-renderer-ui.js:28-46` (`mcpContractProblems` + stale comment "its JS_FILES list never covered mcp.js"); `scripts/check-mcp-contract.js` (passes locally; referenced by neither `.github/workflows/ci.yml` nor `package.json`)
- **Evidence:** Running the check-ipc-args site regex over assistant.js matches 0 of its 7 `aiCall(...)` sites (scratch `aicall-sites.js`); CI reports "118 call sites" - none from the assistant. Because they are unchecked, the renderer sends both spellings everywhere: `{ tab_id, tabId }`, `{ session_id, sessionId, tab_id, tabId }`, `{ base_url, baseUrl, api_key, apiKey }`, `{ max_tokens, maxTokens }` - Rust declares only the snake_case params without `rename_all`, so only the camelCase keys are read and the snake ones are the "silently dropped" class the check exists for. Had the check seen these sites it would have failed on five unexpected args. The globals/duplicate-declaration check (whose stated purpose is catching a same-named top-level function in a later-loaded script replacing an earlier one) does not load the two scripts loaded *last* by app.js:4511. MCP contract checking is implemented in `check-ipc-args.js` (via `mcpCall`), again in `check-renderer-ui.js` (`mcpContractProblems`, whose comment claims check-ipc-args does not cover mcp.js - it now does), and a third time in the unwired `check-mcp-contract.js`.
- **Why it is a flaw:** The one renderer module with no static IPC coverage is the one that already shows the symptom (hedged duplicate keys). A future `const toast = ...` or `function openPalette` in assistant.js would silently replace app.js's and CI would stay green. Three divergent copies of one check will drift.
- **Proposed fix:** In `check-ipc-args.js` add `aiCall` to the site regex (then delete the snake_case duplicates in assistant.js); add assistant.js and mcp.js to `check-renderer-globals.js` FILES and `ai|mcp|assistant` to OWNED (extended run on the current tree is clean - scratch `globals-all.js`); delete `check-mcp-contract.js` and `mcpContractProblems` or make one of them *the* check and wire it into `ci.yml`; fix the stale comment.
- **Confidence:** confirmed
- **Effort:** S

## A8-18: Ctrl+Shift+1/2/3 (advertised in the Shell/Files/Split tooltips and "fixed" in 1.9.0) compare `ev.key` against digits, which Shift turns into `!` `@` `#` on US and most layouts
- **Severity:** Medium
- **Category:** js-logic
- **Location:** `src/renderer/app.js:3419-3434` (`['1','2','3'].includes(ev.key)` with `ev.shiftKey` required), `src/renderer/index.html:211-213` (tooltips "Terminal only (Ctrl+Shift+1)" ...), `CHANGELOG.md:188-189` ("the advertised Ctrl+Shift+1/2/3 shortcuts were dead" - listed as fixed), `scripts/check-renderer-ui.js` (no test presses these keys)
- **Evidence:** `KeyboardEvent.key` is the layout-mapped character *after* modifiers; with Shift held, the digit row produces `!`/`@`/`#` (US, UK), `!`/`"`/`§` (DE) etc., and on AZERTY the *unshifted* row already yields symbols. The handler therefore matches only on layouts where Shift+1 still reports "1". The physical-key property `ev.code === 'Digit1'` is layout-independent. The only automated check (`check-renderer-ui.js`) never exercises the shortcut; a Playwright synthetic `press('Control+Shift+1')` reports `key:'1'` (scratch `shift-digit-key.js`), which is why a test written that way would pass while real keyboards fail.
- **Why it is a flaw:** The tooltips advertise shortcuts that do not fire on a standard keyboard; the 1.9.0 changelog claims they were revived.
- **Proposed fix:** Match on `ev.code` (`{Digit1:'ssh', Digit2:'sftp', Digit3:'split'}[ev.code]`) and keep `ev.shiftKey && (ctrl||meta)`; document the key names consistently.
- **Confidence:** likely (browser key semantics well established; not reproduced on real hardware in this read-only audit)
- **Effort:** S

## A8-19: README's install section points at v1.7.3; CHANGELOG 1.9.0 has a truncated bullet and a duplicated "### Added" with six "Fixed" items under it; SECURITY.md has a garbled paragraph; README has an orphaned sentence
- **Severity:** Medium
- **Category:** docs
- **Location:** `README.md:251-257` ("current release is **v1.7.3**", `SSHSpan_1.7.3_x64-setup.exe` ...) vs `package.json:4` / `src-tauri/tauri.conf.json:4` (1.9.1); `CHANGELOG.md:227-228` (bullet ends mid-sentence: "A chat panel docked beside the"); `CHANGELOG.md:209-255` (first "### Added" contains the SFTP Columns, bandwidth-limit, conflict-dialog and hide-to-tray *fixes*) and `CHANGELOG.md:257-259` (second "### Added" with the completed assistant bullet); `docs/SECURITY.md:133-141` ("...fails the operation.\n Unix; on Windows NTFS inheritance is stripped..." - an editing residue sentence fragment); `README.md:168-173` (the host-key sentence "Any later fingerprint change is refused and recorded in the audit log." sits under the unrelated "Shell, Files or Split" bullet)
- **Evidence:** As cited. The 1.9.0 "### Added" block also lists `assistant` commands as "Seven Tauri commands" (correct: 7) but the duplicated heading makes the section read as two releases.
- **Why it is a flaw:** The README install table is the first thing a downloader follows and names files two minor versions old; Keep-a-Changelog readers will miss four fixes filed as additions; the SECURITY paragraph is unreadable at the exact point describing deployed-key permissions.
- **Proposed fix:** Update the install table to 1.9.1 (or make it version-agnostic: "latest release assets are named `SSHSpan_<version>_...`"); delete CHANGELOG:227-228, move 229-255 under "### Fixed", keep one "### Added"; rewrite SECURITY.md:133-141 as one paragraph; move README:173 up to the host-key bullet.
- **Confidence:** confirmed
- **Effort:** S

## A8-20: MCP renderer re-implements two backend rules and has already diverged from both (exposed tool-name truncation; loopback URL classification)
- **Severity:** Medium
- **Category:** js-logic
- **Location:** `src-tauri/src/assistant/mcp.rs:284-332` (`MAX_TOOL_NAME_LEN = 64`, `exposed_tool_name` truncates to 55 chars + `_` + 8-hex SHA-256), `src-tauri/src/assistant/mcp.rs:1481-1483` (`"exposed_name"` sent to the renderer with the comment "the renderer derives it identically"); `src/renderer/mcp.js:92, 123` (`'mcp__' + mcpSanitizeName(sv.name) + '__' + mcpSanitizeName(t.name)` - no truncation, `exposed_name` never read); `src/renderer/mcp.js:304-310` (`mcpIsLoopbackUrl`: `localhost|127.0.0.1|::1|[::1]|*.localhost`) vs `src-tauri/src/assistant/mcp.rs:112-121` (`localhost|127.0.0.1|::1|127.*`); `src-tauri/src/assistant/mcp.rs:287-288` ("MUST stay byte-for-byte identical to `mcpSanitizeName`" - true for the sanitizer, not for the name)
- **Evidence:** For `server="internal-knowledge-base-prod"`, `tool="search_documents_by_semantic_similarity"` the backend's canonical name is 64 chars with a hash tail while the renderer offers the model an 81-char name; OpenAI-compatible endpoints reject function names over 64 chars, and the backend's collision check (`mcp_set_tool_state`) reasons about a name the model never sees. For URLs: `http://127.0.0.2/mcp` is refused by the renderer ("only allowed on loopback addresses") but accepted by the backend; `http://dev.localhost:8080/mcp` passes the renderer and is then refused by the backend with a message that lists only `localhost/127.0.0.1/::1`.
- **Why it is a flaw:** Two copies of one rule with different outputs; one of them is unit-tested (Rust), the other is what the model/user actually experiences. The backend already ships `exposed_name` for exactly this reason and the renderer ignores it.
- **Proposed fix:** Use `t.exposed_name` in `mcpGetTools`/`mcpResolveTool` (fall back to local derivation only if absent); delete `mcpIsLoopbackUrl`'s own list in favour of a tiny `mcp_classify_url` call, or align both lists and add a shared test vector file both sides read.
- **Confidence:** confirmed (divergence); likely (provider rejection consequence)
- **Effort:** S

## A8-21: `scripts/` carries an unrunnable codemod and three CDP drivers that are broken or unwired; nothing documents or runs them
- **Severity:** Low
- **Category:** docs
- **Location:** `scripts/refactor_tabs.py:29-31` (asserts `connectToServer(` exists in app.js - it does not; `grep -n "function connectToServer" src/renderer/app.js` is empty, and the script's output rewires `termModeBtn`/`termModeLabel` which were replaced by `#termModeSeg` in 1.8.0), `scripts/cdp-fileops.js:9` (`ws.onmessage = ...` - `ws` is never declared: ReferenceError on load), `scripts/cdp-e2e-2.js`, `scripts/cdp-featurepass.js` (reference `t.log`, `.sftp-queueitem`, `#sftpQueuePanel` etc. from an older DOM); `package.json:31-42` and `CONTRIBUTING.md` reference none of them; `docs/REWRITE-ROADMAP.md:204-207, 252` describe the CDP method generically
- **Evidence:** As cited; the Python codemod is a one-shot migration from the v1.4 tab refactor that was committed instead of deleted.
- **Why it is a flaw:** A contributor exploring `scripts/` finds four files that look like tooling and cannot run; the one that could run (`refactor_tabs.py`) would rewrite `app.js` if its assertions were loosened.
- **Proposed fix:** Delete `refactor_tabs.py` and `cdp-fileops.js`; either fix and document `cdp-e2e-2.js`/`cdp-featurepass.js` under a "Manual e2e against the packaged app" section in CONTRIBUTING (they need the `WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS` setup from the roadmap) or delete them too.
- **Confidence:** confirmed
- **Effort:** S

## A8-22: CONTRIBUTING.md disagrees with CI and the manifests on Node version, clippy gate, and the IPC naming convention
- **Severity:** Low
- **Category:** docs
- **Location:** `CONTRIBUTING.md:7` ("Node.js 24+") vs `package.json:43-45` (`>=18`), `README.md:260` (">= 18"), `.github/workflows/ci.yml:84` (20), `release.yml:46` (24); `CONTRIBUTING.md:28, 56` (`cargo clippy ... -D warnings`) vs `ci.yml:62-69` (`-D clippy::correctness` *because* "the tree carries ~40 pre-existing style lints" and `-D warnings` "would mean a CI that fails on its first run"); `CONTRIBUTING.md:46` ("Keep command arguments in camelCase on the renderer wire") vs `src-tauri/src/assistant/mcp.rs:1543, 1731` (`rename_all = "snake_case"`) and `CHANGELOG.md:48-54`
- **Evidence:** As cited. A contributor following CONTRIBUTING's clippy line gets ~40 failures locally that CI does not report; one following the camelCase rule breaks `mcp_save_server`.
- **Why it is a flaw:** The contributor guide is the second document a new contributor reads and it contradicts the enforced pipeline on three counts.
- **Proposed fix:** State `Node >= 18 (CI uses 20, release uses 24)`; copy the exact clippy invocation from ci.yml; document the two naming conventions and point at `scripts/check-ipc-args.js` as the arbiter.
- **Confidence:** confirmed
- **Effort:** S

## A8-23: Stale or false in-code comments on security-relevant behaviour (five instances)
- **Severity:** Low
- **Category:** docs
- **Location:** (a) `src/renderer/app.js:6-7` ("Private key material never reaches this process; exports are explicit user-initiated downloads") vs `src/renderer/app.js:2044-2057` (`browseForImport` loads the private key file's text into the renderer) and `src/renderer/app.js:1852-1856` (private exports go through a backend save dialog, not downloads) - `docs/SECURITY.md:304-308` states the import caveat correctly; (b) `src-tauri/src/lib.rs:243-250` ("We therefore reuse the existing `vault_lock` teardown when the app is about to exit") vs `lib.rs:251-259` (clears the password store and `kill_all()` only - no `lock_vault_internal`, so no MCP `DELETE` teardown, no SFTP/edit/keepalive registry stop, no `vault.lock` audit row); (c) `src/renderer/terminal.js:142-144` and `src-tauri/src/commands/terminal.rs:424-429` ("The `terminalKeepaliveSeconds` setting remains stored but has no effect" / "is retained") vs `src-tauri/src/commands/mod.rs:2723-2755` (the key was removed from `SETTINGS_KEYS`; `settings_set` now rejects it); (d) `src-tauri/src/crypto/vault.rs:29-31` ("Matches Node.js crypto.scryptSync with N=65536, r=8, p=1") vs `vault.rs:32-33` (Argon2id; the two KDFs produce different keys, so nothing "matches"); (e) `src-tauri/src/commands/mod.rs:460-461` emits `vault-locked-by-watchdog` "so its UI reflects the lock" but no renderer file listens for that event (`grep -rn vault-locked-by-watchdog src/renderer` is empty; the only listener is `vault-lock-requested`, app.js:3451) - the UI learns of a watchdog lock only through the 10 s `refreshVaultStatus` poll (app.js:4546-4548)
- **Evidence:** As cited.
- **Why it is a flaw:** Each comment is the kind the project asks reviewers to trust ("the codebase has many deliberate, commented decisions"); these five would mislead a reader about the import boundary, exit teardown, a removed setting, the vault KDF lineage, and an event that is emitted into the void.
- **Proposed fix:** Rewrite (a) to match SECURITY.md; make (b) true by calling `lock_vault_internal` from `ExitRequested` (it is cheap and already nonblocking) or reword; delete (c); fix (d); for (e) either add `listen('vault-locked-by-watchdog', () => refreshVaultStatus(true))` in app.js or drop the emit.
- **Confidence:** confirmed
- **Effort:** S

## A8-24: Dead code: four renderer functions and one const with no callers; six Rust `pub fn`s/structs never referenced - and the live `key_remove_deployed` re-implements one of them differently
- **Severity:** Low
- **Category:** js-logic
- **Location:** JS: `src/renderer/app.js:393` (`categoryIdsForScope`), `:396-406` (`totalKeyCountFor`), `:414-416` (`keysInCategory`), `:2376-2378` (`loadBitwardenSync`, body is a comment), `src/renderer/assistant.js:32` (`AI_LEVEL_ORDER`). Rust: `src-tauri/src/ssh/mod.rs:196-219` (`SshService::remove_key`), `:222-253` (`list_deployed_keys`), `:256-260` (`get_config_hosts`), `:272-277` (`DeployedKeyInfo`), `src-tauri/src/config/mod.rs:235-256` (`add_host`, `remove_host`, `get_deployable_keys`), `src-tauri/src/crypto/vault.rs:20-22, 53-61` (`VaultKey::new`, `derive_auth_key`). Divergence: `src-tauri/src/commands/mod.rs:2130-2132` removes the two key files inline and never touches the managed config, whereas the dead `remove_key(key_name, Some(alias))` would also drop the `Host` stanza (ssh/mod.rs:211-216)
- **Evidence:** Scratch `unused-fns.js` (whole-renderer reference count including index.html and `window.*` exposure) lists exactly the five JS names; each Rust item has only its definition site in `src-tauri/` (`grep -rn` per name). `scripts/check-renderer-globals.js` checks undefined calls and duplicate declarations, not unused definitions, so none of this is caught. Because the crate is a `lib` with `pub` items, rustc's dead-code lint stays silent.
- **Why it is a flaw:** Two implementations of "undeploy" exist and the dead one is the complete one; when A8-16 wires undeploy, the natural call will leave a dangling `Host` block pointing at a deleted `IdentityFile`. The dead JS helpers invite the exact "two filteredKeys" class of bug the globals check was written for (`check-renderer-globals.js:152-156`).
- **Proposed fix:** Delete the JS helpers and `AI_LEVEL_ORDER`; delete `list_deployed_keys`/`get_config_hosts`/`DeployedKeyInfo`/`add_host`/`get_deployable_keys`/`derive_auth_key`/`VaultKey::new`; make `key_remove_deployed` call `SshService::remove_key(&key.name, Some(&key.name))` after its containment check so the stanza goes with the files. Optionally extend `check-renderer-globals.js` with an "unused top-level definition" pass (the scratch script is 40 lines).
- **Confidence:** confirmed
- **Effort:** S

## A8-25: Inconsistent terminology and casing in user-visible copy (Servers/Hosts/Connect; "New key"/"+ New Key"/"New Key"/"New Server"; three confirmation mechanisms)
- **Severity:** Low
- **Category:** ux
- **Location:** `src/renderer/index.html:32` (nav "Servers"), `src/renderer/app.js:748` (breadcrumb root "Hosts"), `src/renderer/app.js:528` ("Host categories"), `src/renderer/index.html:180` (`view-connect`), `README.md:94-98` ("Hosts/Connect view"), `src/renderer/index.html:782` ("New Server"), `index.html:94` ("New key"), `index.html:103` ("+ New Key"), `index.html:549` ("New Key"), `index.html:422` ("Add MCP server"), `index.html:324-325` ("Create backup...", "Restore from backup..."), `src/renderer/app.js:2309` ("Master Password") vs `index.html:294` ("Change master password..."), `index.html:796` ("Kbd-int"), `index.html:172` ("Required for an encrypted export") vs `index.html:597` ("required for encrypted keys"); confirmations: 14 native `window.confirm(` sites (`app.js:588, 1696, 1725, 2179, 2410, 2884, 2957, 3615, 3810, 4299; sftp.js:3580; mcp.js:246; terminal.js:667`) vs the in-app `confirmModal` used once (`app.js:3062`) vs `#deleteModal` (SFTP), while `docs/REWRITE-ROADMAP.md:208` records "Native `prompt()`/`confirm()` dialogs silently fail in WebView2. Use in-app modals."
- **Evidence:** As cited. The roadmap lesson is contradicted by 14 live `confirm()` sites that the 1.9.0 changelog describes as working dialogs (CHANGELOG:204-207), so either the lesson is wrong about `confirm()` or the sites are; the dash style is also mixed (`\u2014` em dash in `app.js:1045, 2299, 2055, 3597`-area toasts; " - " everywhere else).
- **Why it is a flaw:** One object (a saved SSH server) is called Servers, Hosts and Connect across nav, breadcrumb, category panel and README; button labels alternate Title Case and sentence case within one screen; "Kbd-int" is unexplained jargon on the auth selector; and the project's own lesson about native dialogs is either stale or unapplied.
- **Proposed fix:** Pick "Servers" (the nav label) everywhere - breadcrumb root, "Server categories", README; sentence-case every button/modal title ("New key", "New server", "+ New key"); expand "Kbd-int" to "Keyboard-interactive"; route the native `confirm()` sites through `confirmModal` (it already returns a Promise) and correct or delete roadmap lesson 9; standardise on " - ".
- **Confidence:** confirmed
- **Effort:** M

## A8-26: Stale/jargon copy: build marker "v14-tabs" on every screen, "preview first" after the Preview button was removed, an `/sse` placeholder for a transport the app refuses, and mixed path separators in the deploy hint
- **Severity:** Low
- **Category:** ui
- **Location:** `src/renderer/app.js:4481` (`window.__SSHPAN_BUILD__ = 'v14-tabs';;;`), `:4519-4520` (sidebar brand subtitle overwritten with "KEYS & SESSIONS · v14-tabs"), `:3122` ("Ready. (build v14-tabs)"), `src/renderer/terminal.js:24` (`'loaded-v14-tabs'`), `docs/REWRITE-ROADMAP.md:109-111, 142-144, 191-194` (the marker exists "so the exact shipped frontend is always identifiable"; "bump the version ... before every release build"); `src/renderer/app.js:2299` ("Nothing to copy - preview first." - the Preview button was removed in 1.8.0, `CHANGELOG.md:409-410`); `src/renderer/index.html:432` (`placeholder="https://mcp.example.com/sse"` while `CHANGELOG.md:18-19` and `docs/SECURITY.md:215-216` say HTTP+SSE is refused); `src/renderer/app.js:2441` (`p.deployDir + '/sshspan_<name>'` renders `C:\Users\x\.ssh/sshspan_<name>` on Windows)
- **Evidence:** As cited. The marker has not changed since the v1.4-era tab refactor (`scripts/refactor_tabs.py` is that refactor), so three releases later every build still identifies itself as "v14-tabs" - the control the roadmap describes is defunct. The static `index.html:22` "Key manager" subtitle is never shown.
- **Why it is a flaw:** Implementation jargon in the primary chrome on every screen; a placeholder that teaches the one URL shape the feature rejects; copy that references a control that no longer exists.
- **Proposed fix:** Derive the marker from `package.json`/`tauri.conf.json` at build (or drop it and show the real version via `app.getVersion()`), restore the "Key manager" subtitle; change app.js:2299 to "Select at least one key first."; change the MCP placeholder to `https://mcp.example.com/mcp`; join the deploy path with the platform separator (take it from `system_paths`).
- **Confidence:** confirmed
- **Effort:** S

## A8-27: docs/MCP-SMOKE-TEST.md expects UI behaviour the renderer does not implement and a mock response the mock does not produce
- **Severity:** Low
- **Category:** docs
- **Location:** `docs/MCP-SMOKE-TEST.md:37` (step 4: "status shows connected, protocol version `2025-11-25`") vs `src/renderer/mcp.js:412-425` (toast "MCP: N tools returned." and a status dot; `grep -n protocol src/renderer/mcp.js` finds only URL-scheme checks - the negotiated version is never displayed); `MCP-SMOKE-TEST.md:140-142` (step 20: "the UI offers to re-configure the auth source") vs `mcp.js` (error toast only; no re-configure affordance); `MCP-SMOKE-TEST.md:126-128` (step 18: `image_cat` should render "[image omitted]") vs `scripts/mcp-smoke-server.py:263-268` (every tool result, including `image_cat`, is wrapped as `{"type":"text","text": json.dumps(result)}` - the base64 arrives as *text*, so the client's image placeholder path is never exercised by this mock); step 13 (`MCP-SMOKE-TEST.md:89-93`) is covered by A8-15
- **Evidence:** As cited.
- **Why it is a flaw:** A manual QA pass following the checklist will "fail" steps 4, 13, 18 and 20 for reasons unrelated to the client's correctness, or - worse - a tester will tick them without looking.
- **Proposed fix:** Show the negotiated protocol version in the server row (the backend has it in `McpState`); add a "Fix auth..." button to the env-var error toast or drop that sentence; make `image_cat` return a real `{"type":"image", "data":..., "mimeType":...}` content block in the mock; fix step 13 via A8-15.
- **Confidence:** confirmed
- **Effort:** S

## A8-28: README "What's new"/Features copy drift: "Hosts/Connect view", `~/.ssh/config` deploy, and the YOLO/Execute text claim a "server-side execution gate matching the four access levels" that only distinguishes two
- **Severity:** Low
- **Category:** docs
- **Location:** `README.md:31-33` ("a server-side execution gate matching the four access levels"), `README.md:194-195` ("the backend independently re-checks the access level before anything reaches the SSH channel"); code `src-tauri/src/assistant/mod.rs:652-664` (`assistant_exec`: `level_permits_exec` - read/draft refused, execute/yolo allowed; Approve/Deny at *execute* is renderer-only, `src/renderer/assistant.js:571-578`), `src-tauri/src/assistant/mcp.rs:1857-1871` (`mcp_call_tool`: read/draft need `approved`, execute needs `approved || auto_approve`, yolo free - `approved` is a renderer-attested boolean); `docs/SECURITY.md:246-252` already states plainly that "the human approval itself is attested by the renderer"
- **Evidence:** For `assistant_exec` the backend cannot tell an approved execute-level command from an unapproved one - there is no `approved` argument at all (mod.rs:653-658); the "per-command Approve/Deny" promised at Execute (README:188) exists only in the renderer. SECURITY.md is honest about this boundary; the README's "matching the four access levels" and "independently re-checks" wording implies more.
- **Why it is a flaw:** Marketing copy stronger than the security document for the same control; a reader who stops at the README believes a compromised renderer cannot run commands at Execute level without a click.
- **Proposed fix:** Reword README:31-33 and 194-195 to match SECURITY.md ("the backend refuses commands at Read/Draft; at Execute the Approve/Deny card is enforced by the renderer"), or add an `approved: bool` to `assistant_exec` mirroring `mcp_call_tool` so the sentence becomes true.
- **Confidence:** confirmed
- **Effort:** S
