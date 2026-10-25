# SSHSpan architecture

**Last updated:** 2026-10-25  
**Status:** describes v1.10.0 and the PuTTY session import, which is not released yet (Unreleased
in the CHANGELOG). The import's passages - its row in the module table, the IPC count (111) and
the Servers group, its mention where the renderer shows `server_save`'s key-file warning, and the
PuTTY session import section - are checked against committed source at `a75b533`; everything else
against `6c19b1b`, and nothing else it describes has changed since (later changes are listed in
the CHANGELOG)  
**Platforms:** Windows and Linux  
**Entry points:** `src-tauri/src/main.rs`, `src-tauri/src/lib.rs`, `src/renderer/index.html`,
`src/renderer/app.js`

This document is written from the source layout and the command registration in `lib.rs`. File
names and numbers can be re-derived with the commands in the sections that quote them.

## System shape

```text
┌──────────────────────────────────────────────────────────────────────────┐
│ OS webview: WebView2 (Windows) / WebKitGTK (Linux)                      │
│ src/renderer/                                                           │
│                                                                          │
│ index.html + styles.css                                                  │
│ app.js ─┬─ terminal.js ─ vendored xterm.js                              │
│         ├─ sftp.js                                                       │
│         ├─ assistant.js ─ mcp.js                                         │
│         └─ icons.js                                                      │
│                                                                          │
│ Tauri invoke(command, args), ipc::Channel output, Tauri events           │
└───────────────────────────────┬──────────────────────────────────────────┘
                                │ typed JSON IPC
┌───────────────────────────────┴──────────────────────────────────────────┐
│ Rust/Tauri process: src-tauri/src/                                      │
│                                                                          │
│ commands/       IPC boundary and native dialogs                          │
│ crypto/         vault, SSH key formats, PPK, PKCS#8, Bitwarden crypto    │
│ db/             sqlx + SQLite schema/migrations                          │
│ ssh/            key deployment and restricted secret-file writes         │
│ ssh_client/     russh sessions, host-key trust, terminal channels        │
│ sftp/           SFTP registry, queue, staging and transfer workers       │
│ bitwarden/      HTTPS client, SSRF guard and sync                        │
│ assistant/      model-provider client and MCP Streamable HTTP client     │
│ config/         managed SSH config plus parser/serializer                │
└──────────────────────────────────────────────────────────────────────────┘
                                │
                SQLite, filesystem, SSH/SFTP, HTTPS
```

There is one application process. Tauri hosts the OS webview and Tokio runtime. The renderer has
no Node runtime and no build step. Release builds omit Tauri's `devtools` feature; debug builds
can use normal development tooling.

## Renderer modules

| Module | Purpose | Important dependencies |
| --- | --- | --- |
| `src/renderer/app.js` | boot, routing, vault gate and auto-lock, keys, categories, deploy sheet, servers and connect, settings, Bitwarden, backups, audit view, dialogs, menus, palette, updater | every renderer module; Tauri core/event APIs |
| `src/renderer/sftp.js` | remote/local browser with its splitters and pointer drag and drop, names as shown, queue UI, overwrite and edit-conflict prompts, chmod, search, bookmarks | `app.js` (menus, dialogs, `beginPointerDrag`), SFTP commands/events |
| `src/renderer/terminal.js` | xterm lifecycle, terminal input/output, links, paste, fit and tab records | vendored xterm/addons, terminal commands |
| `src/renderer/assistant.js` | per-tab conversation, provider loop, built-in tools, approval cards | terminal state, assistant commands, `mcp.js` |
| `src/renderer/mcp.js` | MCP server/settings/tool registry UI | MCP commands, assistant tool merge |
| `src/renderer/icons.js` | local SVG icon table | `app.js` injection helpers |
| `src/renderer/index.html` | three top-level views and all dialogs | all scripts |
| `src/renderer/styles.css` | complete renderer stylesheet | CSS custom properties |
| `src/renderer/vendor/` | pinned xterm 5.5.0, fit 0.10.0, web-links 0.11.0 | `VENDOR.md`, `check-vendor.js` |

The top-level views are **Keys**, **Servers**, and **Settings**. Deploy is a Keys action (a sheet
over the key list); Shell, Files, and Split are surfaces within a live server tab; the audit log is
a Settings section.

The renderer uses classic scripts in one global scope. `scripts/check-renderer-globals.js` checks
all of them for undefined project calls and duplicate globals. Dynamic text goes through
`textContent` or the project's escaping helper. Menus are built by one `openMenu` helper in `app.js`
(the key-to-host picker builds its own), and the in-app `confirmModal` and `promptModal` replace the
native `confirm()` and `prompt()` (the dialog plugin's `window.confirm` shim is always truthy,
A5-01). This architecture is simple but makes the large `app.js` and `sftp.js` files maintainability
liabilities; see [Large files and deferred splits](#large-files-and-deferred-splits).

## Rust modules and managed state

| Area | Files | Responsibility |
| --- | --- | --- |
| App lifecycle | `lib.rs`, `main.rs` | Tauri builder, handlers, tray, close-to-tray, exit teardown, startup-failure dialog |
| General commands | `commands/mod.rs` | vault, keys, categories, deploy, backups, settings, audit, system dialogs and files, the Bitwarden commands, `ssh_config_list_hosts`, `app_info`, `heartbeat` and the idle watchdog, shared helpers (`run_blocking`, `audit_or_warn`, the rotation lock, the pool helpers, the native credential question) |
| Server/terminal | `commands/server.rs`, `commands/terminal.rs`, `ssh_client/mod.rs` | server CRUD, connection/authentication, terminal registry, host keys |
| PuTTY import | `putty_sessions/mod.rs`, `putty_sessions/registry.rs` | PuTTY's saved sessions as servers to save: the registry reader (Windows only) and the listing rules (every platform); the command, `putty_list_sessions`, is in `commands/server.rs`. Not the PPK parser, which is `crypto/putty.rs` |
| SFTP | `commands/sftp.rs`, `sftp/mod.rs`, `sftp/queue.rs`, `sftp/testkit.rs` | SFTP IPC, edit sessions, local-path policy, bounded walks, persistent queue; the in-process test server |
| Crypto | `crypto/*.rs` | Argon2id/AES-GCM vault, SSH formats, PPK, PKCS#8, Bitwarden primitives |
| Persistence | `db/mod.rs` | schema, migrations, queries, transactions and the backup restore transaction |
| Deployment/config | `ssh/mod.rs`, `config/mod.rs` | secret files, deploy planning/apply/undeploy, managed SSH config, read-only parser of the user's config |
| Bitwarden | `bitwarden/mod.rs`, `bitwarden/ssrf.rs`, `bitwarden/sync.rs` | protocol client, URL/DNS guard, two-way sync (the Bitwarden commands themselves are in `commands/mod.rs`) |
| AI/MCP | `assistant/mod.rs`, `assistant/mcp.rs` | provider proxy, typing/exec gate, MCP Streamable HTTP, records and sessions |
| Updater | `commands/updater.rs` | release check, download, digest and signature verification, launch |

Tauri-managed state created in `lib.rs`:

- `AppState { db }`;
- `VaultPasswordStore` (zeroizing, memory-only master password);
- `DialogPathStore` (single-use native-dialog path grants);
- `UnlockThrottle`, `ActivityTracker`, and `VaultGeneration`;
- `VaultRotationLock` (master-password rotation vs. sealed-data writers);
- `CredentialQuestions` (one native credential question open at a time, app-wide, and per
  `QuestionKind` the host and time of the latest "no" for the 30-second wait);
- `AssistantLevels` and `McpState` (live MCP sessions, each bound to the settings it was set up
  with, and the tracked teardown tasks);
- `SessionRegistry`, `SftpRegistry`, `EditRegistry`, `KeepaliveRegistry`;
- persistent `TransferQueue`.

## IPC surface

`tauri::generate_handler!` registers **111 commands**. Default Tauri parameter mapping uses
camelCase on the JavaScript wire. `mcp_save_server` and `mcp_set_tool_state` explicitly use snake_case;
`scripts/check-ipc-args.js` is the enforced source of truth and also rejects renderer calls to
commands absent from `generate_handler!`. A command that takes `Option<T>` silently reads a
misspelled key as `None`, which is why that check exists.

| Group | Registered commands |
| --- | --- |
| App (2) | `app_quit`, `app_info` |
| Vault/backups (7) | `vault_create`, `vault_unlock`, `vault_lock`, `vault_change_password`, `vault_status`, `vault_backup_export_to_file`, `vault_backup_restore_from_file` |
| Keys/deploy (10) | `key_import`, `key_export`, `key_export_to_file`, `key_delete`, `key_rename`, `key_list`, `key_get`, `key_deploy`, `key_deploy_preview`, `key_remove_deployed` |
| Categories (8) | `category_list`, `category_create`, `category_rename`, `category_reparent`, `category_set_order`, `category_delete`, `key_set_categories`, `key_create_with_categories` |
| SSH config (1) | `ssh_config_list_hosts` |
| Servers (4) | `server_list`, `server_save`, `putty_list_sessions`, `server_delete` |
| Terminal/host keys (8) | `terminal_connect`, `terminal_send`, `terminal_resize`, `terminal_disconnect`, `terminal_list`, `server_test`, `known_hosts_list`, `known_hosts_forget` |
| Activity (1) | `heartbeat` |
| SFTP (37) | `sftp_open`, `sftp_list_dir`, `sftp_resolve_link`, `sftp_dir_size`, `sftp_mkdir`, `sftp_remove`, `sftp_rename`, `sftp_download`, `sftp_open_for_edit`, `sftp_close_edit`, `sftp_edit_resolve`, `sftp_chmod`, `sftp_get_permissions`, `sftp_touch`, `sftp_fs_info`, `sftp_keepalive_start`, `sftp_queue_add`, `sftp_queue_list`, `sftp_queue_cancel`, `sftp_queue_retry`, `sftp_queue_pause`, `sftp_queue_resume`, `sftp_queue_pause_all`, `sftp_queue_resume_all`, `sftp_queue_set_rate_limit`, `sftp_queue_clear_finished`, `sftp_server_copy`, `sftp_search`, `sftp_search_cancel`, `sftp_bookmarks_list`, `sftp_bookmarks_save`, `sftp_local_list`, `sftp_local_mkdir`, `sftp_local_rename`, `sftp_local_remove`, `sftp_local_open_folder`, `sftp_close` |
| Bitwarden (5) | `bitwarden_get_config`, `bitwarden_save_config`, `bitwarden_test_connection`, `bitwarden_sync`, `bitwarden_allow_sync` |
| Assistant (8) | `assistant_get_config`, `assistant_save_config`, `assistant_test_connection`, `assistant_chat`, `assistant_set_level`, `assistant_get_level`, `assistant_exec`, `assistant_type_text` |
| MCP (6) | `mcp_list_servers`, `mcp_save_server`, `mcp_remove_server`, `mcp_test_connection`, `mcp_set_tool_state`, `mcp_call_tool` |
| Settings/paths (3) | `settings_get`, `system_paths`, `settings_set` |
| Audit (2) | `audit_list`, `audit_clear` |
| System files/URLs (7) | `system_open_external`, `system_open_url`, `system_select_file`, `system_pick_file_path`, `system_pick_files`, `system_pick_save_path`, `system_write_text_file` |
| Updater (2) | `update_check`, `update_download_and_run` |

What the newer commands do:

- `app_quit` takes the same path as the tray's Quit; `app_info` returns `{ version, platform }`
  (`CARGO_PKG_VERSION` and the target OS) and replaced the stale `v14-tabs` marker.
- `system_pick_files` opens the native multi-file picker and returns the chosen paths; the Upload
  button queues them with one `sftp_queue_add` call.
- `system_pick_file_path` returns a path without reading the file; `system_select_file` reads a
  picked file as text, refusing one over 4 MiB, and its only caller is key import.
- `sftp_edit_resolve({ editId, conflictId, action })` settles an edit-sync conflict (see
  [Edit sync and conflicts](#edit-sync-and-conflicts)).
- `key_deploy_preview` returns the exact config text deploy will write (`configText`), the managed
  config's `Include` line (`includeLine`), the per-key files and refusals, `warnings`, and
  `legacyHostLines` (`[{ file, line, text, key, unreadable, writtenBySshspan }]`: every `Host` line
  of the user's own `~/.ssh/config` that names a host the deploy would write - not only the lines
  `ssh` would reject - with `unreadable` set for a line `ssh` cannot read at all and
  `writtenBySshspan` for one an older SSHSpan wrote). A quoted line is cut at 300 characters ("…"
  appended, 301 characters in all, in `text` and in the warnings that quote it); control characters
  are dropped, format and text-direction characters are kept for the renderer to spell out.
- `bitwarden_get_config` returns the saved settings and the last result, `hasMasterPassword` (never
  the sealed password itself) and `confirmed` (true while the stored destination is the allowed
  one).
- `bitwarden_sync({ allowRemoteOverwrite, approvalToken })` returns key and server counters,
  deletions, renames and `errors`. A sync only plans remote changes: when some wait for a
  confirmation it returns `pendingServers` and `pendingKeys` (each list capped at 500 entries, real
  changes first, `pendingTruncated` when cut) and an `approvalToken`, a SHA-256 over every pending
  change and over each item exactly as the vault served it. Applying them takes
  `allowRemoteOverwrite: true` plus the `approvalToken` that came with exactly that list; if this
  run's own fetch finds another list, nothing remote is applied and the result carries the new list,
  its new token and `approvalStale: true`, and `allowRemoteOverwrite` without a token applies
  nothing. More than 500 server changes, or more than 500 key changes, cannot be approved: the
  result comes back with no token and an `approvalRefused` sentence. Each pending server overwrite
  carries `changes` (`name`, `host`, `port`, `user`, `password`, `authMethod`, `linkedKey`,
  `category`; `category` is left out while SSHSpan has a category change of its own to upload for
  that server); a key whose categories differ counts as a real change. An item's fingerprint and
  public key come from its private key, and one whose claims do not match is reported in `errors` by
  name and not imported. Every item title or id that an error quotes (several items naming one
  server, an older copy, an item without a creation date, an unusable key, a failed pull) goes
  through `pending_text`: control, format and direction characters removed, 80 characters at most.
  The command reads the settings only through `settings_for_sync`, which refuses with
  `sync_refusal` - before anything is unsealed or sent, not even a login - while the stored
  destination is not the allowed one (see `bitwarden_save_config` below).
- `bitwarden_save_config({ serverUrl, email, masterPassword, folderName, serversFolderName })` is
  async: the URL check and the sealing run on the blocking pool, then one transaction stores the
  settings and the answer comes back as `{ ok, warning, confirmed }`. The settings carry
  `confirmed_destination`, the destination (a JSON array of the server URL and the account email,
  the email trimmed and lower-cased) the user allowed, and `confirmed()` is true only while the
  stored destination equals it. A save that leaves the destination as it was allowed asks nothing.
  Any other save is followed, on the blocking pool, by the native question ("SSHSpan - Sync with
  Bitwarden?": SSHSpan will upload the SSH private keys and saved server passwords, to the host
  and account it names, with the address on a line of its own; buttons "Don't allow", "Allow" and
  "Cancel", on the rules of the credential question below), and the command returns only when it
  is answered, so the renderer's Save stays busy. `settle_destination` takes the turn in
  `CredentialQuestions` and asks. It writes `confirmed_destination` only while no master-password
  change runs (`VaultRotationLock::try_shared`), and only inside the transaction that finds the
  vault still unlocked in the generation of the save (`VaultAtSave`) and the settings still on that
  destination. A "no", or an "Allow" within a second, clears `confirmed_destination` again if it
  holds this very destination (an earlier "Allow" for it, or an "Allow syncing..." asked again), so
  the later answer stands; during a master-password change such an answer is logged, not written.
  Both answers are audited without the account: an "Allow" as `sync.destination_allowed` and a "no"
  as `sync.destination_declined`, both with the detail `host=<host>`. An "Allow" within a second
  counts as a refusal: it is audited as `sync.destination_declined` with the detail
  `host=<host> answered=too-quickly` and does not start the 30-second wait described below. An
  "Allow" that comes after a lock, for settings that changed meanwhile, while the vault is being
  re-encrypted or when the answer cannot be stored (reasons 4 to 7 below) writes no row. When the
  destination ends not allowed, `confirmed` is
  false and `warning` says why, after any warning the save already had and joined by one space;
  each reason starts "Bitwarden sync stays off, because ":
  1. "uploading your keys and passwords to {host} was not allowed. Use "Allow syncing..." in
     Settings > Bitwarden to be asked again." (a "no", Esc, Cancel);
  2. "the question about uploading to {host} was answered within a second of opening - too fast to
     be a decision. Use "Allow syncing..." in Settings > Bitwarden to be asked again.";
  3. "another question about sending a credential was still open. Answer it, then use "Allow
     syncing..." in Settings > Bitwarden.";
  4. "the vault was locked while you were deciding. Unlock it, then use "Allow syncing..." in
     Settings > Bitwarden.";
  5. "the server or account changed while you were deciding. Use "Allow syncing..." in Settings >
     Bitwarden to be asked about the new one.";
  6. "the vault was being re-encrypted. Use "Allow syncing..." in Settings > Bitwarden when that has
     finished.";
  7. "allowing it could not be stored. Use "Allow syncing..." in Settings > Bitwarden to be asked
     again."

  A save with an account that is not one email address - at most 254 characters, exactly one "@"
  with a non-empty local part and domain, no whitespace, control, format or text-direction
  character, none of `( ) < > [ ] " ' , ; : \` - is refused with "Enter the Bitwarden account as
  one email address, like name@example.com." (`bitwarden_account` checks and trims it before the
  seal, and `apply_bitwarden_save` checks it again in the transaction that writes). The question
  then reads "SSHSpan will upload your SSH private keys and saved server passwords to this
  Bitwarden account when it syncs:", a blank line, the lines `Account: <email>`,
  `Server: <host>` and `Address: <server URL>`, a blank line and "Allow?"; when the allowed
  destination is another account's (`previous_account`), the line
  `This is not the account allowed before (<previous email>).` comes before "Allow?".

  After "Don't allow" or "Cancel" (Esc and closing the dialog included; an "Allow" within a second
  was no decision and is not recorded), no further question of the same kind is asked for 30
  seconds, whatever host, address or account it names. `CredentialQuestions` keeps one entry per
  `QuestionKind` (`McpCredential`, `AssistantKeyMove`, `BitwardenDestination`): the host the latest
  "no" of that kind named, and when. `declined_lately(kind)` gives that host while the "no" is
  less than 30 seconds old (`CREDENTIAL_DECLINE_BACKOFF`) and `record_decline(kind, host)` sets it;
  `settle_destination`, `settle_binding` and `save_config_confirmed` ask by their kind once they
  hold the turn. The kinds are independent, so a "no" to one holds back neither of the others, and
  the entries live in memory for the app's run. The answer names the host that was declined, which
  need not be the one asked about now: a save or "Allow syncing..." answers with an eighth reason,
  "uploading to {host} was declined a moment ago. Wait 30 seconds, then use "Allow syncing..." in
  Settings > Bitwarden."; `mcp_save_server` stores the server switched off with "The server was
  saved but stays switched off, because sending a credential to {host} was declined a moment ago.
  Wait 30 seconds, then save it again."; and `assistant_save_config` refuses the key move with
  "Sending the stored API key to {host} was declined a moment ago. Wait 30 seconds, then save
  again, or enter the API key for the new address."
- `bitwarden_allow_sync()` asks the same question again for the stored destination (the "Allow
  syncing..." button) and returns `{ ok, confirmed, warning }` with the same reasons. It fails with
  "Vault is locked." while the vault is locked and with "Save the Bitwarden sync settings first."
  while no server URL or account email is stored. A refused `bitwarden_sync` answers
  `Bitwarden sync is off until you allow it to upload your keys and passwords to the account <email> on <host>. Use "Allow syncing..." in Settings > Bitwarden.`
  `bitwarden_test_connection` is not gated: it uploads nothing. A one-time migration
  (`migrate_bitwarden_destination`, recorded in the `config` row `migration.bitwarden_destination`)
  marks settings that were saved before this check as allowed, so an upgrade asks nothing; a
  restore never writes Bitwarden settings, so it neither brings nor confirms a destination, and no
  sync starts by itself - there is no scheduled or automatic sync.
- `mcp_save_server`, `assistant_save_config` and the other saves return `warning` (a sentence, or
  `null`) when the change committed but a follow-up (an audit row, a session teardown) did not; for
  `mcp_save_server` it also says why a server stays switched off (not allowed, or answered within a
  second; a "no" less than 30 seconds ago; another question still open; the vault locked, being
  re-encrypted, or the settings changed or the server removed while it was asked; or the answer
  could not be stored). `mcp_save_server` also returns `confirmed`: a credential bound to a new
  address (a new server, another URL or variable, a restored or refused record) stays unconfirmed
  until the user answers a native question that Rust asks, and the call returns only after that.
  The dialog ("SSHSpan - Send a credential?") has the buttons "Don't allow", "Allow" and "Cancel";
  "Don't allow" is the default button on Windows only, because the GTK dialog on Linux
  sets no default; only "Allow" allows, Esc or closing the dialog is "not allowed", an "Allow"
  within a second of the dialog opening is not taken (the clock starts when the dialog is created
  on the main thread), only one question is open app-wide and a second is never queued
  (`CredentialQuestions`; an API-key move is refused, an MCP server saved meanwhile is stored
  switched off until it is saved again, the Bitwarden sync stays off), an "Allow" given after the
  vault locked - even if it was unlocked again, because the check is the vault generation
  (`VaultAtSave`) - or for settings that changed meanwhile confirms nothing, a later "Don't allow"
  is never undone by an earlier "Allow", and every value the question quotes is cleaned and
  capped. Both answers are audited (`mcp.credential_allowed`, `mcp.credential_declined`) without
  the value. `assistant_save_config`
  asks the same question ("SSHSpan - Send the API key?") before a stored API key moves to another
  provider or address and answers "Enter the API key for the new address." when it is declined; an
  "Allow" that arrives after a lock moves nothing and answers "The vault was locked while you were
  deciding - unlock it and save the settings again."; it ignores the renderer's
  `reuseKeyAtNewOrigin`, refuses a base URL with a control, format or text-direction character and
  stores the base URL in its parsed form. `key_delete`, `key_rename`, `category_create`,
  `category_delete`, `key_set_categories`, `key_create_with_categories` and `bitwarden_save_config`
  return the same `warning` field (the change was made, its audit row was not written; for
  `bitwarden_save_config` it also carries the reasons above), and `vault_lock` returns `{ ok,
  alreadyLocked }` (a lock of a locked vault writes no second audit row).
- `server_save` returns `{ ok, id, warning }`. `warning` is `null`, or - for a server that signs in
  with a key file (`publickey`, a `pemPath`, no vault key chosen) protected by a passphrase - the
  advice a connect to it would fail with: "This key file is protected by a passphrase, which
  SSHSpan cannot ask for when connecting. Import it under Keys (New key > Import asks for the
  passphrase) and choose that key for this server, or remove the passphrase from the file." The
  server is saved either way. The check (`key_file_warning`) reads at most 64 KiB
  (`KEY_FILE_CHECK_BYTES`) of a regular file and never opens a named pipe or another special file,
  because opening a pipe for reading waits for a writer; it recognises an encrypted OpenSSH key, an
  encrypted PKCS#8 key, a legacy PEM key with `Proc-Type: 4,ENCRYPTED` and a PuTTY key whose
  `Encryption:` is not `none`. The save (`store_server`) runs under the rotation guard
  (`VaultRotationLock`), the guard is released, and only then is the key file looked at; a path
  that starts with two separators (`\\...` or `//...`) is not looked at at all, because on Windows
  that opens a network connection to the share, hands it an NTLM sign-in and can stall. The
  renderer shows the warning, spelled out, as a warning toast of its own after the save report: at
  the server dialog (the ssh config import only prefills that dialog, and its Save is the
  dialog's), and at the deploy's "Also save these as servers" and the PuTTY import (one toast, a
  line `<server>: <warning>` for each server saved with a warning; a PuTTY import stopped by a
  vault lock says only how many, see [PuTTY session import](#putty-session-import)). On Windows
  `key_file_warning` first
  asks `ssh_client::key_path_refusal`, which answers `KEY_FILE_NOT_LOCAL`, "SSHSpan reads key files
  only from this computer's drives (like C:\...). Copy the key to a local folder, or import it
  under Keys.", for a path that is not on this computer's drives, and then the file is not
  touched; the server is saved all the same and the text is its `warning`.
  `windows_key_path_is_local`, pure and tested on every platform, accepts a drive letter, a colon
  and a separator (`C:\...`, `C:/...`, a mapped `Z:\...`) and the verbatim `\\?\C:\...` (the
  verbatim form takes only a backslash, so `\\?\C:/...` is refused), and refuses shares (`\\...`,
  `//...`, `\/...`, `/\...`, `\\?\UNC\...`), the object namespace (`\??\...`, a drive inside it
  too), devices (`\\.\...`), any other prefix (`\\?\Volume{...}`, `\\?\GLOBALROOT\...`) and every
  relative form (`key`, `\key`, `D:key`, `C:`). Connect and Test connection ask it too, in
  `resolve_for_server` (`commands/terminal.rs`) before `path.is_file()`, the
  `connect.pem_path_used` audit row and the read, and fail with the same text. On other platforms
  `key_path_refusal` answers nothing and the two-separator skip above stands.
- `category_set_order({ parentId, orderedIds })` renumbers one whole list in a single
  `BEGIN IMMEDIATE` transaction (`sort_index` 0, 1, 2, ... in that order) and never changes a
  parent. `parentId` names the list the tree shows; for `null` that is the top level as the tree
  shows it - categories with no parent, with a missing parent, or in or below a parent loop
  included. `orderedIds` must name every category of that list, once each, and a list that does not
  is refused ("The new order must name every category under that parent - reload the categories and
  try again."), as are an unknown id, a duplicate and a list mixing parents or scopes. It is refused
  while the vault is locked or being re-encrypted. A category whose saved parent is in the other
  scope (a host category under a key category after a restore, say) is not in its parent's list as
  the tree shows it: `shown_parent` counts a parent only when it is in the same scope, so such a
  category is part of the top level, and a reorder of that list is accepted instead of refused with
  "Those categories do not share a parent - reload the categories and try again.". A drag, Move up
  or Move down in the category tree sends one `category_set_order`, preceded by
  `category_reparent` when the parent changes (Move to... sends only `category_reparent`).
- `sftp_close_edit({ sessionId, remote, force })` is async. Without `force` it checks first, and
  closes only a copy the server has everything of (see [Edit sync and
  conflicts](#edit-sync-and-conflicts)); otherwise it closes nothing and answers `{ ok: false,
  unsynced: true, error }`.

These commands, among others, are `async` and run their work on the blocking pool through
`run_blocking`, so Argon2id, file and database waits never stall the main thread:
`vault_create`, `vault_unlock`, `key_import`, `key_export`, `system_write_text_file`,
`key_remove_deployed`, `key_deploy_preview`, `category_reparent`, `category_rename`,
`category_set_order`, `assistant_save_config`, `mcp_save_server`, `mcp_set_tool_state`,
`bitwarden_save_config`, `bitwarden_allow_sync` (both ask their native question there),
`server_save`, `sftp_local_mkdir` and `sftp_local_rename`. Commands that only read memory or a path
(`vault_status`, `heartbeat`, `app_info`, `system_paths`) and short single-statement queries
(`key_list`, `key_get`, `category_list`, ...) stay synchronous. The key unseal of Connect, Test and
the assistant runs inside `run_blocking`; every seal and unseal of a Bitwarden sync goes through
`seal_off_thread` / `unseal_off_thread`, and the master-key derivation of its sign-in (Argon2id or
PBKDF2) runs on the blocking pool too, at most two at once (`master_key_off_thread`, `KDF_SLOTS`;
`master_key_on_pool` is the only production caller of `derive_master_key`, and tests fail when it
runs anywhere but on the pool; Test connection and a sync share the two places, and a sign-in that
gets none within 30 seconds stops with "Another Bitwarden sign-in is still running. Try again when
it has finished."); the MCP connect and call unseal use `seal_on_pool` /
`unseal_on_pool`, and the lock's MCP teardown unseals through `spawn_on_pool`; a source-scan test
fails on a direct `crypto::vault` call in the sync or MCP code.

Removed surfaces: commands without a renderer caller are deleted, not just unregistered - the old
webview-transiting backup commands (`vault_backup_create`, `vault_backup_restore`, `vault_export`,
`vault_import`), `ssh_config_read` and `ssh_config_write`, `key_generate` and `key_fingerprint`,
the direct SFTP upload, staging, hash and mtime commands (`sftp_upload`, `sftp_stage_path`,
`sftp_file_sha256`, `sftp_set_mtime`) and `terminal_keepalive`. A Rust function is not reachable
from the renderer unless it appears in `generate_handler!`; `lib.rs` says at each removal why it
went.

### Events

Terminal output travels over the `ipc::Channel<String>` passed to `terminal_connect`, not over an
event. These events go to the renderer:

| Event | Emitted by | Payload | Renderer reaction |
| --- | --- | --- | --- |
| `sftp-queue` | `sftp/queue.rs` | `{ jobs: [...] }` (one job, or the whole list) | patches queue rows in place |
| `sftp-search` | `sftp_search` walk | one result or a final summary, each with a `searchId` | ignores events whose `searchId` is not the current one |
| `sftp-edit-sync` | edit watcher, periodic check, `sftp_edit_resolve` | `{ sessionId, editId, remote }` plus `{ ok: true }`, `{ ok: false, error }`, a conflict, or `{ ok: true, reloaded: true }` | toast, or the conflict prompt |
| `vault-locked-by-watchdog` | idle watchdog in `commands/mod.rs` | none | shows the locked state and disposes tabs |
| `vault-lock-requested` | the tray's Lock Vault, after Rust has already locked | empty string | shows the locked state |
| `window-hidden-to-tray` | the first close of a run that hides the window | none | the one-time tray notice |

## Persistence and platform paths

Paths come from `ProjectDirs::from("org", "sshspan", "SSHSpan")`, not hard-coded UI strings.
`system_paths` returns the exact database, managed-config, and deploy-directory paths.

| Platform | Data directory / database | Config directory / managed SSH config |
| --- | --- | --- |
| Windows | `%APPDATA%\sshspan\SSHSpan\data\sshspan.db` | `%APPDATA%\sshspan\SSHSpan\config\ssh\config` |
| Linux defaults | `~/.local/share/sshspan/sshspan.db` | `~/.config/sshspan/ssh/config` |

XDG overrides are honored on Linux. Debug builds also honor `SSHSPAN_DB`; the override is compiled
out of release builds. Settings are `setting.*` rows in the database `config` table; there is no
separate settings file. Key deployment writes `~/.ssh/sshspan_<name>` and `.pub` files. SSHSpan
never edits the user's `~/.ssh/config`; the user adds the generated quoted `Include` line.

## SQLite schema

Migrations use runtime `sqlx::query` calls and bound parameters; this project does not use the
compile-time `query!` macros. Queries name their columns: a `SELECT *` after an `ALTER TABLE`
panics on a pooled connection whose schema is older. The principal tables are:

| Table | Purpose / notable fields |
| --- | --- |
| `keys` | metadata, public key, sealed private blob, fingerprints, deploy state, Bitwarden metadata |
| `config` | master verifier, `setting.*`, SFTP bookmarks and other key/value state |
| `audit_log` | action, optional key id, details, timestamp; retained to 10,000 rows |
| `categories` | recursive key/server category tree with `scope` and `sort_index` |
| `key_categories` | many-to-many key/category links |
| `servers` | host/auth metadata, sealed optional password, category and Bitwarden metadata |
| `known_hosts` | `host:port` pin, key blob, fingerprint (`SHA256:` form), first-seen time, source |
| `bitwarden_config` | sync configuration as key/value rows; stored password is sealed; the `confirmed_destination` row holds the server and account the user allowed (a JSON array of the server URL and the trimmed, lower-cased email; empty or missing means none) |
| `assistant_config` | provider/model configuration; API key is sealed |
| `mcp_servers` | one JSON record per server, sealed auth secret, tool definitions/pins, confirmation state |
| `transfer_queue` | persistent queue jobs, state/progress, source/target server ids |
| `sync_category_marks` | per-row marks (kind, id, changed_at) of a category change waiting for the next Bitwarden sync; machine-local, not in backups |

The database file is not wholly encrypted. Sensitive columns are sealed; public keys,
fingerprints, hosts, settings, category metadata, queue metadata, and audit rows remain readable
to anyone who can read the file.

## Concurrency and consistency rules

These rules keep the vault consistent when commands overlap. New commands follow them.

- **`BEGIN IMMEDIATE` for read-then-write.** A transaction that reads a row and then writes it
  starts with `BEGIN IMMEDIATE`, so it holds the write lock before it reads. A deferred
  transaction that upgrades from read to write fails at once under a concurrent writer, and two
  such transactions can interleave. MCP record changes, assistant settings, category moves, the
  Bitwarden settings row and sync pulls, and the vault verifier creation all use it.
- **Conditional writes for sealed columns.** An update that re-seals a secret names the sealed
  value it read and changes nothing if the row moved, so a password rotation or a stale snapshot
  cannot write an old blob back.
- **`VaultRotationLock`.** A master-password change takes the write lock for the whole rotation.
  Every command that seals with the master password or rewrites a whole key, server or MCP row
  takes a shared guard (`try_shared`) before its first vault read and fails fast with "The vault
  is being re-encrypted - try again when it finishes."; an unlock is refused with the same
  message until the change finishes (`try_shared` never blocks). Connect, Test and the assistant
  take the guard before they read a sealed secret and unseal on the blocking pool, so during a
  password change they refuse at once instead of waiting.
- **`VaultGeneration`.** A lock increments the generation. Work that spans an await re-checks it
  and gives up if the vault locked meanwhile; a lock that lands during an unlock wins.
- **`run_blocking`.** Argon2id derivations and blocking file or database work run on the blocking
  pool, never on the main thread or an async worker.
- **`db::block`.** The synchronous database methods drive the async queries with one helper. From a
  plain thread it uses a cached runtime; from inside a task of the async runtime it uses
  `block_in_place`; from the root future of a multi-thread runtime's `block_on` (a runtime is
  entered but no task runs, as in the body of a multi-thread `#[tokio::test]`) it waits on a parker
  of its own, `block_on_own_parker`, because tokio's nested `block_on` parks on the very parker that
  root future waits on and could use up a wake-up meant for it; and on a current-thread runtime it
  does not, because that thread drives the runtime's timers and I/O, so `block_in_place` refuses
  there at once, as before.
- **Audit after commit.** A committed write whose audit row cannot be written reports success with
  a `warning` (`audit_or_warn`); returning an error would make a retry fail on the change that
  already happened.

## Core data flows

### Startup, unlock and lock

If the database cannot be opened or migrated, `lib.rs` shows a native dialog with the cause and
the database path, refuses every command (`refuse_after_failed_startup`) and exits cleanly.

`vault_unlock` runs on the blocking pool: it is refused while a rotation runs, holds the
`UnlockThrottle` attempt lock for the whole attempt (parallel guesses meet the throttle), verifies
the Argon2id PHC verifier (upgrading a legacy plaintext one), stores a zeroizing password, re-checks
`VaultGeneration` and audits the unlock. A manual, tray, or watchdog lock first increments
`VaultGeneration`, then kills SSH sessions, stops SFTP edit/keepalive state, clears SFTP handles,
pauses the queue, clears backend assistant levels, drains MCP state and ends each MCP session at the
endpoint it was set up with (one task per session; the secrets are unsealed on the blocking pool
from one zeroizing copy of the password), clears the password, and audits the lock. The renderer
then disposes tabs when it observes the locked state. The idle auto-lock is a renderer deadline
(last real input plus the configured minutes, 15 by default, `0` is off) with a warning 60 seconds
before; the backend watchdog is fed by a heartbeat that is sent only after activity.

### Exit, quit and the tray

Closing the window hides it to the tray and emits `window-hidden-to-tray` once; without a tray
(`create_tray` failed) closing quits. Quit comes from the tray, from `app_quit`, from the updater
handing over to an installer, or from closing a tray-less window. Every exit passes
`RunEvent::ExitRequested`, which runs `exit_teardown`: the same path as a lock (MCP sessions,
SFTP and edit registries and their staged copies, queue pause, password store), run once. The
exit then waits for the MCP session DELETEs that are still running, up to
`EXIT_TEARDOWN_BUDGET` (2 seconds), so a hung server cannot hold the app open.

### Master-password rotation

The change runs on a blocking worker with exclusive `VaultRotationLock` access. Every sealed
record is unsealed/resealed in memory; conditional updates and the verifier commit in one SQLite
transaction. The new password is installed while the lock remains held, and live MCP sessions
are re-bound to the new seal before any request can look at them. Its audit row is best-effort
after installation, so audit failure cannot reverse or strand a committed rotation. Commands that
seal or rewrite secrets take a shared guard and fail fast while rotation is active.

### Export, import, and backup

Private-key export and backup export open native save dialogs in Rust and call the shared
secret-file writer (restricted permissions, see [Validation boundaries](#validation-boundaries))
once the path has passed the write deny-list (`check_own_export`; `~/.ssh` allowed for these two;
the backup is checked before it is built). Their dialogs suggest a
bare file name: the key's name cut after its last `/`, `\` or `:`, with the format's extension
(`private_export_file_name`), and `sshspan-backup-<stamp>.json`. Public-key exports use the native
save dialog too, and every save dialog opens in the Downloads folder or home (see
[Local-path policy](#local-path-policy)). Backup restore
opens and reads the selected file in Rust; a restore that needs the backup's own password gets a
single-use, five-minute file grant for the retry. A backup holds keys (still sealed), categories,
servers, known-host pins, settings, MCP servers and SFTP bookmarks; it does not hold Bitwarden
sync settings, the assistant settings and key, the audit log or the queue. Restored MCP servers
come back unconfirmed, with every tool disabled. Key import is the explicit exception to "key
material stays in Rust": `system_select_file` returns up to 4 MiB of text to the renderer, which
passes it to `key_import`.

### Connect

The renderer passes a server id and an `ipc::Channel<String>`. Rust loads the server, unseals its
credential (the saved password only for the server's own account, under the rotation guard and
on the blocking pool), performs host-key verification through a native trust dialog,
authenticates, opens a PTY/shell, and stores a `SessionHandle`. Connecting has a 20-second limit
and authentication a 30-second limit, with time spent in the trust dialog excluded, and a
timed-out handshake shuts its socket down. A changed host key and a declined first-trust prompt
are distinct errors. Fingerprints are shown as `SHA256:` unpadded base64. Terminal bytes are
decoded with a per-session UTF-8 carry so a character split across packets survives, and stream
over the channel; input returns by `terminal_send`. The SSH library zeroizes the password it
takes, but builds the authentication packets in a buffer it clears without wiping and frees
keyboard-interactive answers unwiped (accepted limit, A6-11). A key file named by `pemPath` is read
by `resolve_for_server` (Connect and Test connection share it); a key file protected by a passphrase
is refused with advice (A5-26), and on Windows a key file that is not on one of this computer's
drives is refused before it is opened (see `server_save` above).

### Deploy and the managed SSH config

`key_deploy_preview` builds a plan with the same serializer deploy uses: the Host alias, HostName,
User and Port from the sheet, quoted and escaped so OpenSSH accepts every line, the files per key,
and refusals (another key's deploy file, a foreign file, an alias that belongs to another key,
pattern aliases). `key_deploy` writes the private key `~/.ssh/sshspan_<name>` with restricted
permissions from creation (see [Validation boundaries](#validation-boundaries)), the `.pub` file
beside it (a plain write) and the `Host` stanzas into
SSHSpan's managed config under the config directory, serialising writes to it; it returns the
`Include` line the user adds, quoted and with `%` doubled, at the top of their own `~/.ssh/config`.
SSHSpan never edits that file. `key_remove_deployed` removes the files and the stanza and deletes
only `sshspan_*` files directly in `~/.ssh`. `ssh_config_list_hosts` is the read-only direction: it
parses the user's real `~/.ssh/config` (one `Include` level, bounded globbing, `Match` blocks and
patterns skipped) with the same keyword rules as OpenSSH, so the Servers "Config" import offers real
hosts.

### PuTTY session import

`putty_list_sessions` (no arguments) lists PuTTY's saved sessions for the Servers "PuTTY" import.
It is registered on every platform and reads only on Windows; elsewhere it fails with "PuTTY's
saved sessions are read from the Windows registry, so this works on Windows only." It is refused
while the vault is locked (`require_unlocked`, before the registry is read: the list is an
inventory of hosts, accounts and key paths) and runs on the blocking pool (`run_blocking`). The
reader, `putty_sessions::read_sessions`, opens `HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions`
and each session's subkey for reading only (`KEY_READ`), queries only the ten values the listing
uses (`VALUE_NAMES`: `HostName`, `PortNumber`, `Protocol`, `UserName`, `UserNameFromEnvironment`,
`PublicKeyFile`, `ProxyMethod`, `PortForwardings`, `AgentFwd`, `X11Forward`) and writes nothing. A
value is read as a REG_SZ string or a 4-byte REG_DWORD; any other type counts as absent. No
`Sessions` key means no sessions; any other error on that key fails the listing with "Could not
read PuTTY's saved sessions: <OS error>", while a session subkey that cannot be opened is one
skipped entry, "could not be read (<OS error>)".

The rules (`build_listing`, tested on every platform) turn each subkey into a server or a skipped
entry. PuTTY's template for new sessions, "Default Settings", is not a session and is never
listed, not even as skipped. A subkey name is unescaped the way PuTTY escapes it (`%` and two hex
digits is that byte, any other `%` is itself) and decoded as UTF-8, or else with the system's ANSI
code page (`MultiByteToWideChar(CP_ACP)`), which older PuTTY wrote names in. Only SSH sessions are
offered (`Protocol` absent, empty or `ssh`, PuTTY's default). The host is `HostName` cleaned up the
way PuTTY does before it connects: trimmed; a user name before the last `@` split off; a colon that
is the only one outside square brackets dropped with what follows (two or more are an IPv6
address, kept); spaces and tabs removed; a bracketed IPv6 address stored without its brackets,
because SSHSpan connects with `TcpStream::connect((host, port))`, which takes a bare one, and any
other bracketed host skipped. The port is `PortNumber`, 22 when it is absent or 0. The user name is
the one before the `@`, else `UserName` (trimmed), else the local Windows user name (`USERNAME`)
when `UserNameFromEnvironment` is on, else none (`null`). `PublicKeyFile` (trimmed) is reported as
a path string only - nothing in the listing opens, stats or resolves it, and a test checks the
module's source for file-system calls - and makes `authMethod` `publickey` (`password` without
one). `notes` names what PuTTY uses and SSHSpan does not: `proxy` (`ProxyMethod` nonzero),
`portForwarding` (`PortForwardings` not empty), `agentForwarding` (`AgentFwd`) and `x11Forwarding`
(`X11Forward`), these booleans on when nonzero, as PuTTY reads them. `alreadySaved` is true when a
saved server has the same host (trimmed, ASCII case ignored), port and user name (trimmed, exact),
or, for a session without a user name, the same host and port. Sessions and skipped entries
(`{ name, reason }`) are sorted by name, case ignored.

Bounds: at most 1,000 sessions are listed (`truncated` beyond). Every subkey enumerated is one
session, so the reader enumerates at most 1,002: one more, to tell that there were more, and the
template. A REG_SZ with more than 8 KiB of data, its NUL included, is not read. For the five
string values that is too long, not absent: a too-long host, protocol, key file path or
`UserName` (when it would be used) skips the session, and a too-long `PortForwardings` is a
`portForwarding` note. A session is skipped, with its reason, when its name has a control
character or more than 256 characters, it is not an SSH session, its host once cleaned up is
empty, has a control character or more than 255 characters, or is bracketed without being an IPv6
address, its port is above 65535, its user name has more than 256 characters, its key file path
more than 4,095, or its subkey cannot be opened.

The renderer (`openPuttyImport` and `#puttyImportModal`) saves the ticked sessions one at a time
with `server_save`, as `saveDeployedAsServers` does: `{ id: null, name, host, port, username,
authMethod, keyId: null, pemPath: keyFile, savedPassword: null, categoryId: null, color: null }`,
the username taken from the session's row when Import is clicked. The import has no save command
of its own, so `server_save`'s checks and its key-file warning apply. Closing the dialog or a
vault lock stops an import before its next save; after a lock it reports counts only, and closing
the dialog empties it.

### SFTP

SFTP channels are derived from live SSH sessions. Queue jobs persist in SQLite, record the server id
so a restored or paused job rebinds to a new session of the same server, and restore as paused after
restart. A transfer that ends short of its expected size is an error. Folder downloads walk to depth
64 and at most 10,000 entries per picked item (a recursive chmod to depth 64 and 200,000 entries),
skip symlinks, and collect per-item warnings; `sftp_queue_add` returns one result per picked item. A
server that reports no file type bits is handled without assuming entries are files (deletes try
remove first and empty a folder only when it really is one). Downloads write `<name>.part`, sync to
disk and rename, and resume a local `.part` only when its length is a strict prefix of the remote
size; an upload's remote `.part` is checked with `FSTAT` and a read-back of its last 64 KiB before
bytes are appended.

#### Local-path policy

Local paths cross the IPC boundary as plain strings, so `commands/sftp.rs` checks them
(`SensitiveLocations`, resolved once per batch and reused for five seconds, compared in literal
and resolved spelling):

- every path built from a remote name is confined to the folder the user chose (`..`, absolute,
  drive- or UNC-prefixed, NUL and reserved Windows names are refused, and the deny-list is checked
  on the final path);
- for every access, including a dialog-approved path: the application data directory (the vault)
  and system directories are refused;
- for reads (an upload source): also SSHSpan's configuration folder and everything under
  `~/.ssh` except `*.pub`;
- for writes (download targets, new folders, renames, deletes): also SSHSpan's configuration folder,
  `~/.ssh`, startup folders and entries (the Windows Startup folders, autostart, systemd user units,
  launch agents), shell startup files and folders, user `PATH` folders under the home folder, and
  settings that run commands (git, PAM, editor and PowerShell startup files, Office startup folders,
  WindowsApps, Windows Terminal settings);
- deleting or moving a folder that holds a protected location (the home folder holds `~/.ssh`) is
  refused (`held_by`);
- SSHSpan's own program files and data are added for writes and deletes (and for moving,
  replacing or deleting a folder that holds them): the executable's folder (for a portable copy
  run directly from the home folder, Downloads, the Desktop or Documents, or from a drive root,
  only the executable and, on Windows, the DLLs beside it, so ordinary downloads there keep
  working), the running AppImage or `.app` bundle, and SSHSpan's local data, cache and
  webview-profile folders (the per-user folders named after the bundle identifier
  `org.sshspan.app`, which on Windows is the WebView2 user-data folder); reads from them stay
  allowed;
- a path picked in a save dialog - the "Download as..." target and the text exports (a public key,
  the audit log's CSV; `system_write_text_file`) - gets the same write deny-list as any other
  renderer-supplied path: `LocalAccess::Write` and `LocalAccess::DialogWrite` share one
  `SensitiveLocations::write_hit`, which names the kind of place (the vault, SSHSpan's
  configuration, `~/.ssh`, a startup folder, a shell startup file, program settings, folder
  settings, SSHSpan's own files), so a download and a text export differ only in the words of the
  refusal (an export gets one such as "... is off-limits for exports - choose another folder.").
  A download's one-use grant is used up when present but is not required and changes no rule: the
  target gets the full list either way (a text export, by contrast, is written only to a path
  picked in the dialog). `~/.config/user-dirs.dirs` and `user-dirs.locale` (in the XDG config
  folders) are on the deny-list for typed and picked paths alike, because a download over them
  could point the Downloads folder, where every save dialog opens, at a folder of the attacker's
  choosing;
- the private-key export and the vault backup, which Rust writes to a path picked in its own save
  dialog, get the same list in the words of an export: `check_own_export` is
  `validate_export_path` followed by `own_export_refusal`, which is `export_refusal` with `~/.ssh`
  allowed (`write_hit` is `write_hit_with(path, false)`, and `write_hit_with` skips only the
  `~/.ssh` check when told to). `key_export_to_file` writes through `write_key_export`, and the
  backup is checked before it is built, before its Argon2id seal. `~/.ssh` stays allowed for these
  two, because exporting a private key to `~/.ssh/id_...` is ordinary and the files are SSHSpan's
  own; the text exports still refuse it;
- every save dialog is built through `in_save_folder`, which opens it in the Downloads folder, or
  in the home folder when there is none (the first that is an existing folder; with neither the
  dialog keeps its own default), because GTK opens a dialog with no folder set in the working
  directory, so a suggested `.bashrc` was one Save and one "Replace?" away from the real one; and
  the suggested name of every one goes through `save_dialog_file_name`, which reduces it to a file
  name (its last part after `/`, `\` or `:`, cleaned, at most 200 characters, `file.txt` when
  nothing is left): `system_pick_save_path` does it for the renderer's name,
  `private_export_file_name` for a key's (a key may be named `/home/me/.ssh/config`, and the whole
  path suggested would open the dialog on that file) and the backup's own name passes through it
  too, so neither the page nor a key's name can steer the dialog's folder.

No SFTP command is bound to a native dialog: a single-file `sftp_download` consumes the one-use
grant of `system_pick_save_path` when there is one but accepts a target without it (the text
exports are the writes that need their grant). Queue destinations, queue upload sources,
local-pane mkdir/rename/delete and such a download target are deny-list checked, so this is a
deny-list and not a grant model (A6-02, Partial): a location the list does not name is still
reachable from a compromised renderer. `docs/SECURITY.md` states the limit.

#### Edit sync and conflicts

`sftp_open_for_edit` downloads the file to a staged local copy (always with an inert extension, so
extension-less files open; a second open of the same file in a session returns the same `editId`
with `reused: true`, except while a "Stop editing" of it is deciding, which is refused as
described below), starts a watcher, and records what the server had: size and modification
time, or a SHA-256 of the content on servers that report neither. A change to the staged copy is
coalesced and then checked against the server before anything is written:

1. The check compares the server's current size and time (or content hash) with the recorded
   baseline. Unchanged: the copy is uploaded to a fresh, exclusively created temp name beside the
   target, `LSTAT`-checked, and renamed over it (a planted file or link at the temp name is never
   written through, renamed into place or deleted), the baseline is re-taken and `sftp-edit-sync`
   reports `{ ok: true }`.
2. Changed, deleted or not checkable: nothing is uploaded. The event is
   `{ ok: false, conflict: true, conflictId, reason: "changed" | "deleted" | "unverifiable",
   error, remoteSize, remoteModifiedMs }`. Only the newest conflict of a session can be settled,
   and the periodic check does not repeat an unchanged conflict.
3. `sftp_edit_resolve({ editId, conflictId, action })` settles it. `overwrite` re-checks the
   server first and uploads; if the server changed again the new conflict comes back (and is
   emitted) with a new `conflictId`. `reload` downloads the server's version over the staged copy
   and re-baselines. A file deleted on the server is a conflict that Overwrite recreates.
4. A failed save is reported once. A periodic check catches saves the file watcher missed (the
   watcher reports an overflow as a Rescan flag, not as an error) and retries a failed one quietly
   with backoff, from 60 seconds up to 15 minutes, leaving at most one temp copy behind.

The renderer answers a conflict event with one prompt (`#editConflictModal` in `index.html`, driven
from `sftp.js`) that asks about one file at a time. Its text says that the file changed on the
server since it was opened, was deleted there, or could not be checked (the three `reason` values);
its buttons are Overwrite, Reload (disabled for a deleted file) and Cancel, and Overwrite and Reload
call `sftp_edit_resolve` with the event's `editId`, `conflictId` and the action. The renderer keeps
each edit's newest conflict only, in the order the files came up: a newer conflict for the file on
screen replaces the question, one for another file waits its turn and the prompt says how many wait.
For 750 ms after the prompt appears or changes, Overwrite and Reload take no click, and Cancel takes
none right after the prompt moved on to another file, so a click aimed at the previous question
cannot answer the new one. Cancel, Escape and a click outside leave the file as it is (its next save
asks again); a refused answer is shown in the prompt and a fresh conflict in an answer replaces the
question. A save or reload settled some other way, Stop editing, a vault lock, a session that ended
and a closed tab each drop the question.

`sftp_close_edit` ends one edit ("Stop editing"). Without `force` it first takes the edit's upload
turn (waiting at most 10 seconds for an upload or Reload that is running), then compares the SHA-256
of the staged copy with the last synced hash (the download, an upload or a Reload) and closes the
edit - stops the watcher and deletes the copy - only when they are equal; no open edit answers
`{ ok: true }` too. A copy that differs (a save still inside the 700 ms debounce, one whose upload
failed or was held back as a conflict, one whose watcher event was lost), an upload still running
after 10 seconds, or a copy that cannot be read or checked closes nothing and answers
`{ ok: false, unsynced: true, error }` with one of three sentences:
`<name> has changes that are not on the server. Stop editing and lose them?`,
`<name> is still being uploaded. Stop editing and lose any changes that do not reach the server?` or
`Could not tell whether the server has everything in <name> (<why>). Stop editing and lose any changes that are not on it?`.
The edit keeps running and its saves still sync; `force: true` closes at once. The renderer asks the
sentence in the confirmation dialog (Cancel focused, invisible and direction characters spelled out)
and sends `force: true` only after a yes. A check that runs longer than a second shows
`Checking <name> for changes that are not on the server…` in the strip under the panes, a second
Stop editing for the same file sends nothing meanwhile, and an answer that arrives after the vault
locked, or after the tab or its session changed, is dropped unasked. While the backend waits for the
upload turn and decides, the edit carries a `ClosingMark` (a counter in `EditSync.closing`, dropped
when the command returns, whatever it answers, or its caller goes away): `sftp_open_for_edit` does
not hand the edit to another open then, because the stop could end it and delete the copy that
open's editor has just been given. `reuse_open_edit` refuses with
`<name> is being closed - try again when it has stopped.`, the renderer's Edit says the same at once
and sends nothing, and an answer that keeps the edit (`unsynced`) drops the mark, so the file opens
again. `sftp_close` (the tab closing or the session ending), `terminal_disconnect` and the vault
lock still end every edit at once, unsynced saves included, and delete the staged copies (best
effort): the session is going away, so nothing could be uploaded any more. A save that lands in the
instant between the check and the close is not seen, the same race as the check-then-upload of a
save, and neither is an open that took the edit in the instant before the mark was set.

Edit sync needs write permission on the file's folder and replaces the file, so ownership, ACLs
and hard links are not kept; the size-and-time comparison has one-second resolution and one
round trip separates the check from the upload (see `docs/SECURITY.md`).

### Bitwarden sync

`bitwarden_test_connection` and `bitwarden_save_config` reuse the stored master password only when
the URL and account equal the saved ones, and the settings row is written in one transaction, so no
reader sees a new URL with an old password. `bitwarden_sync` reads its settings through
`settings_for_sync`, which refuses (`sync_refusal`) while the stored server and account are not the
destination the user allowed - before anything is unsealed or sent, not even a login (see
`bitwarden_save_config` under [IPC surface](#ipc-surface)) - then unseals the master password, logs
in (the prelogin's `kdfMemory` is in MiB and `kdf_from_prelogin` converts it to KiB with
`argon2_memory_kib`, saturating, before `clamp_kdf_params` applies the 16 MiB to 1 GiB bounds; a
prelogin number above 32 bits ends at the ceiling instead of being cut to 32 bits, and a KDF type
above 32 bits is refused), and runs the key and server passes: local changes are pushed with
conditional writes and revision and change marks are written back after every push and pull;
remote changes that would overwrite a
local row or add a new one are only planned: they come back as the pending lists with an
`approvalToken`, and a run applies them only when it is passed `allowRemoteOverwrite: true` and the
token of exactly that list (a run whose own fetch finds another list applies nothing and returns the
new list with a new token and `approvalStale: true`, and more than 500 server changes, or more than
500 key changes, cannot be approved); organisation items are reported, not duplicated; a server
carries its local id in the item so a lost link re-links instead of duplicating, never onto an item
another local server owns; undecryptable fields are errors; an imported key's fingerprint and public
key are derived from its private key. A run that stops part-way is reported as a failure with the
counts it reached. Every seal and unseal of a sync runs on the blocking pool (`seal_off_thread` /
`unseal_off_thread`), and so does the sign-in's master-key derivation (Argon2id or PBKDF2), at most
two at once (`connect_inner` calls `master_key_off_thread`, which waits up to 30 seconds
(`KDF_PERMIT_WAIT`) for one of two places (`KDF_PERMITS`, shared by Test connection and a sync) and
then fails with "Another Bitwarden sign-in is still running. Try again when it has finished."; the
place goes with the derivation into the blocking task, so it comes free when the derivation ends,
even if the caller stopped waiting).

A rename, move or delete of a category, or `key_set_categories`, writes a per-row category mark
(a row in `sync_category_marks`, not a bump of the whole row's `updated_at`); the sync uploads a
category-only change only while the remote item is unchanged, and otherwise lists the remote
change for approval (the approved pull keeps the local category) and uploads the category at the
next run, so an older password is never uploaded; a successful upload clears the mark (only up
to its timestamp, so a newer category change stays marked). The marks are machine-local and are
not in backups. A sync's comparisons read the categories, the keys' categories and the keys'
fingerprints once per pass (`SyncIndex`), not once per lookup.

`sync.run`, `sync.error` and `sync.key_renamed` audit rows record runs; server response text in
errors is cut to 300 characters, and the item titles and ids that the other error texts quote are
cleaned and cut to 80 (`pending_text`). The destination answers are audited as
`sync.destination_allowed` and `sync.destination_declined`, with the host only.

### Updater

`update_check` asks the GitHub releases API and reports `newerVersion` for every newer release;
`available` says whether a release has an installer for this platform, so a newer release without
one is not reported as "up to date". `update_download_and_run` takes only an exact release-asset URL
(six path segments, no query or fragment, the extension taken from the path), downloads to the temp
folder (an AppImage update, beside the running AppImage), checks the GitHub-computed SHA-256 digest,
verifies the minisign signature - the global signature first, then a trusted comment that must read
`SSHSpan release v<x>` for the tag in the URL - and only then launches the installer: on Windows a
setup `.exe` through one `ShellExecuteExW` call so UAC can elevate (a declined prompt reads as
cancelled), and an `.msi` (used when a release has no setup `.exe`) through `msiexec /i`, where a
declined prompt is not reported as cancelled; on Linux a `.deb` or `.rpm` is handed to the desktop's
opener and an `.AppImage` update replaces the running AppImage in place. A partial download is
deleted on every error and stale update files (exact generated names only) are pruned at start. The
renderer must ask the user first; the backend does not re-verify that.

### AI and MCP

The renderer owns conversation history and terminal snapshots; Rust owns provider credentials, HTTP,
and policy commands. The provider receives the user's chat, session metadata, bounded terminal
context (up to 200 lines or 8,192 characters), tool definitions, and tool results. The provider
client follows no redirects, accepts plain `http://` only for loopback and private addresses, and
refuses credentials in the base URL.

- **Typing and exec gate.** `assistant_type_text` enforces the tab's level (Draft or above), refuses
  line breaks, control characters other than a tab (C0, DEL, C1) and every Unicode format or
  default-ignorable character (`DISGUISING_CHARS`: Cf, Default_Ignorable, line and paragraph
  separators), caps the text at 4,096 characters, and audits it. `assistant_exec` applies the same
  character list, refuses TAB, and refuses below Execute; the approval click itself is attested by
  the renderer, which the backend cannot verify (YOLO needs no click).
- **MCP records.** A record (URL, auth, tool definitions and pins, confirmation state) is read,
  changed and written in one `BEGIN IMMEDIATE` transaction for save, tool toggle, connect and
  refresh, so a revoked approval cannot come back and a removed server is not re-created. URLs
  with a `?query` or `#fragment` are refused; loopback means a parsed `127.0.0.0/8`, `::1` or
  `localhost`.
- **Rug-pull binding.** Each tool definition is hashed (SHA-256 over canonical JSON). A changed
  definition is disabled with its auto-approve cleared and flagged `definition_changed`; every
  enable passes the `expected_hash` the user was shown (a compare-and-swap); the call gate (level
  and approval) runs again right before every `tools/call`, also after an initialize, a refresh
  or a session renewal, and a `tools/list_changed` announced with the initialize answer triggers
  the refresh.
- **Session binding and teardown.** A live session carries the settings it was set up with (URL,
  auth type, header name, sealed secret, environment-variable name). A request uses only a session
  bound to its record's current settings; a session set up with other settings is ignored and ended
  at its own endpoint with its own credential, whoever removes a session from the map ends it once.
  Locks, URL or auth edits, refused calls, failed connects and removal all end sessions this way. On
  a lock, a quit and a URL or credential edit the DELETEs run as tracked background tasks and the
  exit waits for them, up to two seconds (see Exit); removing a server waits up to five seconds
  (`REMOVE_TEARDOWN_TIMEOUT`) for its own DELETE and removes the record either way. A lock between a
  session's generation check and its registration leaves no session behind (the check runs under the
  sessions mutex), a session a registration replaces is ended where it was set up once the requests
  still using it have finished (and, when its settings are unchanged, with the header already
  resolved, so no unseal), a `tools/list_changed` announced with a session set-up survives a failed
  or refused call (a paged listing restarts at page 1 when its session was renewed halfway), at most
  four secrets are unsealed at once during a teardown, the teardowns share one zeroizing copy of the
  password, and at most 16 teardowns are pending at once (the rest are not sent and expire on their
  servers).
- **Request checks.** The stored record is checked right before every request that sets up or
  reuses a session (`not_contactable`: the server was removed, its URL or auth changed, or it is
  not confirmed). `establish_session` checks before each initialize and again once it is answered,
  before the new session is registered and `notifications/initialized` goes out; every
  `tools/list` page is checked, and so is the page asked again on a renewed session
  (`request_with_session`); the refreshes after a refused call and after a sent call are checked;
  and a call's first set-up and its renewal after a 404 ask the call gate first
  (`set_up_for_call`, which turns a set-up that fails because the server changed into the gate's
  refusal, audited as denied). A `tools/call` is gated right before it goes out (`regate_call`). A
  session whose server changed is ended where it was set up and never registered; a session the
  server dropped (404) is forgotten without a DELETE; a listing that fails says why and stores
  nothing. The checks run before a request, not during one: a request already out is not
  recalled. Two kinds of traffic are not checked against the stored record: the `-32601` answers
  to a server's own requests inside an open response (at most eight per response, each checked
  against the vault generation, sent to the same endpoint within the same exchange) and the
  session DELETEs, which only end sessions.
- **Results.** `mcp_call_tool` returns the raw content and the renderer wraps every result in the
  turn's untrusted-data block, tool names are keyed by server id and exposed under a
  64-character name, every call is audited by argument hash, and server-to-client requests during
  one response are capped (8) and vault-checked.

## Validation boundaries

- CSP: `script-src 'self'`, no inline/eval script, no remote renderer fetches.
- Dynamic renderer text uses `textContent` or project escaping; xterm consumes remote terminal
  control sequences by design, and links in terminal output ask first.
- Secret-file writes are 0600 from creation on Unix. Windows creates an empty unshared file, has
  one `icacls` call remove every inherited permission and give the current user full control, then
  writes; where the folder passes no permissions down, SYSTEM and Administrators keep the full
  control Windows gave the new file. The call grants no other account anything; with Windows'
  default settings, no other account has access.
- Bitwarden is HTTPS-only with DNS/address filtering (a configured system proxy resolves the host
  itself and bypasses the connect-time filter; see [SECURITY.md](SECURITY.md)), and a sync uploads
  only to the server and account the user allowed in a native question. MCP intentionally allows
  loopback HTTP; provider HTTP is limited to local/private addresses.
- Minisign verifies released asset bytes, not the integrity of the repository or signing workflow.
- DevTools are not compiled into release builds.

## Large files and deferred splits

The 800-line ceiling in `CONTRIBUTING.md` is soft. These files are past it (line counts at
`6c19b1b`; recount with `git show 6c19b1b:<path> | wc -l`), and splitting them was deferred
because a mechanical split in the same change as the fixes would have made the fixes unreviewable.

| File | Lines | Seam to cut when it is split |
| --- | ---: | --- |
| `src-tauri/src/commands/sftp.rs` | 13,160 | edit session (`EditSync`, conflict types, `edit_sync_event`, `upload_edited_file_as`, `periodic_rescan`, `sftp_open_for_edit`, `sftp_close_edit`, `sftp_edit_resolve`) to `commands/sftp/edit.rs`; local-path policy (`LocalAccess`, `Locations`, `Protected`, `SensitiveLocations`, `resolved_local_path`, the refusal helpers, `sanitize_remote_name`, `safe_join_under`) to `commands/sftp/local_policy.rs`; then remote walks (`plan_download`, `chmod_walk`, `remove_remote_tree`) and queue expansion |
| `src-tauri/src/commands/mod.rs` | 9,614 | by command cluster: vault and master-password hashing, backups, keys and deploy, categories, Bitwarden commands, audit, settings and system dialogs; the native credential question (`ask_native_confirmation`, `timed_question`, `CredentialQuestions`, `QuestionKind`, `dialog_text`) to `commands/native_dialog.rs`; the shared helpers (`VaultRotationLock`, `run_blocking`, the pool helpers, `audit_or_warn`) stay in `mod.rs` |
| `src-tauri/src/assistant/mcp.rs` | 9,375 | the test module (about half the file) to `assistant/mcp/tests.rs`; then session state and teardown (`McpState`, `register`, `end_replaced`, `start_teardowns`) to `assistant/mcp/sessions.rs`, the transport (`post_jsonrpc`, `read_response`, `classify_stream_message`) to `assistant/mcp/transport.rs`, and the credential binding (`binding_needs_confirmation`, `settle_binding`, `confirm_binding`, `decline_binding`) to `assistant/mcp/binding.rs` |
| `src-tauri/src/db/mod.rs` | 5,917 | by table group in creation order: keys and config, audit, Bitwarden and assistant, MCP, categories (the sync marks with them), servers and known hosts, queue |
| `src-tauri/src/bitwarden/sync.rs` | 5,277 | the test module (under half the file) to `bitwarden/sync/tests.rs`; then the pure planning (`plan_key_row_marked`, `plan_server_row_marked`) to `bitwarden/sync/plan.rs`, the pending lists and the approval (`approval_token`, `clean_item_text`) to `bitwarden/sync/approval.rs`, and the server helpers (`SyncIndex`, `server_changes`, `push_local_server`, `pull_remote_server`) to `bitwarden/sync/servers.rs` |
| `src-tauri/src/sftp/queue.rs` | 3,853 | no seam proposed yet |
| `src/renderer/app.js` | 8,448 | along its own section banners: category tree and the pointer drag helper that `sftp.js` shares (`beginPointerDrag`), vault gate and auto-lock, keys view and new-key modal, deploy sheet, Bitwarden sync settings, settings and backup, palette, audit view, servers (connect, server modal, host picker) and the update check |
| `src/renderer/sftp.js` | 5,439 | along its section banners: per-tab state and mode switching, the Split splitter, panel construction, names as shown, listing cache and windowed rendering, row interaction and context menu, chmod, search and bookmarks, local pane, downloads and uploads, overwrite conflicts, edit conflicts, queue panel, drag and drop (OS drops and pointer drags), compare and synchronized browsing |
| `src/renderer/styles.css` | 3,102 | no seam proposed yet |

Also past 800 lines (counts at `6c19b1b`): in `src-tauri/src`, `assistant/mod.rs` (3,267),
`ssh_client/mod.rs` (2,263), `ssh/mod.rs` (2,141), `commands/updater.rs` (2,081), `bitwarden/mod.rs`
(2,046), `config/mod.rs` (1,740), `sftp/mod.rs` (1,464), `crypto/keys.rs` (1,207),
`commands/server.rs` (1,106) and `crypto/putty.rs` (1,089); in `src/renderer`, `assistant.js`
(1,689), `index.html` (1,143), `mcp.js` (1,038; seams: registry, the agent-loop bridge, the settings
server list, the add/edit form, test connection and tool approval, load and wiring) and
`terminal.js` (965; seams: focus, wheel policy, keys, size, tabs). Test files may exceed the ceiling
when their size is justified by their role: `src-tauri/tests/mcp_integration.rs` (1,478),
`src-tauri/tests/integration.rs` (1,144) and the renderer suites and check scripts in `scripts/`
(the largest, `check-servers-ui.js`, has 3,609 lines).

## Related documents

- [Security model](SECURITY.md)
- [Privacy model](PRIVACY.md)
- [Contributing guide](../CONTRIBUTING.md)
- [MCP smoke test](MCP-SMOKE-TEST.md)
- [Remediation report](audit/2026-10-09/REPORT.md)
- [Finding disposition index](audit/2026-10-09/README.md)
