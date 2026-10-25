# Changelog

All notable changes to SSHSpan are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- **Dependency advisories.** `crypto-bigint` 0.7.5 -> 0.7.7 (RUSTSEC-2026-0387: operations meant
  to run in constant time could branch on secret values), `ctutils` 0.4.2 -> 0.4.5
  (RUSTSEC-2026-0385, the same kind of flaw), `rustls-webpki` 0.103.15 -> 0.103.16
  (RUSTSEC-2026-0382: certificate checks could accept distrusted intermediates) and `webpki-roots`
  1.0.9 -> 1.0.11 (RUSTSEC-2026-0381: distrusted emSign intermediates). The older `crypto-bigint`
  0.5.5 has no fixed release, so the elliptic-curve 0.13 line it came with is gone. The app used
  it only to generate an ECDSA key, import an ECDSA `.ppk` and export one as PKCS#8 (private or
  public); SSH sessions already used 0.7. Those now use `p256`/`p384`/`p521` 0.14, and a PPK import
  or PKCS#8 export gives the same bytes as before. (#90)
- **An MCP tool cannot pass for another on the approval card.** A tool's name and display name are
  the MCP server's choice and were shown as they are, so a text-direction override (U+202E) turned
  what followed it around and a zero-width space went unseen - on the card that approves a call
  too. The renderer now spells such characters out (`<U+202E>`), each name in a text-direction
  isolate of its own, on the approval card (its accessible name spelled out too), in the tools list,
  in the assistant's record of each call and in the notices that name a tool. That record also
  shows a call's result and the backend's warning with these characters marked, the result's line
  breaks kept. The card, that record and the schema notice spell out the server's own name too,
  since a backup restores it unchecked. The audit log still shows these names as stored. The model,
  the backend and the stored record still get every name and result as they are (see
  `docs/SECURITY.md`).
- **A server restored from a backup cannot pass for another in the MCP settings.** A server's name
  is checked when it is saved, not when a backup restores it, and the MCP settings showed it as
  stored: in its row, in the heading of its tools, in the question that removes it and in the
  notices that name it (the wait for the answer about its credential, its confirmation, a refusal
  to save another server whose tool names it would share, a removal warning). These now spell out
  invisible and text-direction characters (`<U+202E>`) too; in a sentence of the renderer's own the
  name is also kept in a text-direction isolate, and a refusal or warning the backend words is
  spelled out whole. A restore still keeps the name as it is - such an entry stays switched off
  until it is saved, and a save refuses the name - and the model, the backend and the stored record
  still get it as it is (see `docs/SECURITY.md`).

## [1.10.0] - 2026-10-18

Changes since v1.9.1: a flaw-remediation release driven by an eight-area internal audit on
2026-10-09. Of the audit's 307 findings (3 Critical, 55 High, 147 Medium, 102 Low), 298 are fixed,
7 are partly fixed, 1 is deferred and 1 is an accepted limitation. The
[audit report](https://github.com/AGSQ11/SSHSpan/blob/main/docs/audit/2026-10-09/REPORT.md)
explains the method, the verification and what is still open, and the
[finding index](https://github.com/AGSQ11/SSHSpan/blob/main/docs/audit/2026-10-09/README.md)
gives the status of every finding. Each entry under Added, Changed, Fixed and Security ends with
the commit that landed it and the audit findings it addresses; the index says which are only
Partial and what is still open.

**Highlights**

- **Confirmations work.** Every native `confirm()` guard was a no-op, so key and server deletes,
  backup restore, host-key forget, tab close, MCP removal, multi-line paste and update install ran
  unconfirmed. All 13 now wait for the in-app confirmation. (Critical, A5-01)
- **The idle auto-lock fires.** It never did, because the status poll re-armed its timer. The
  vault now locks the configured minutes after the last real input, 15 by default.
  (Critical, A2-01)
- **Private keys can be written on Windows.** Deploy, private-key export, backup export and the
  audit CSV export all failed on Windows. The file now gets its restricted permissions before the
  first byte is written. (Critical, A7-01)
- **The Bitwarden sync asks where it may upload.** A page that could save the sync settings could
  have sent every private key and saved server password to a server of its own. A sync now runs
  only against a server and account you allowed in a native question, and is refused before any
  network call until then; settings saved before this release keep syncing. (High, found by the
  final security review)
- **Credentials are bound to their destination in Rust.** Sending an MCP secret or environment
  variable to a new address, or moving the stored API key to another provider or address, needs a
  native question that the page cannot answer; a saved SSH password is used only for its own
  server and account; and a Bitwarden approval applies only the list it was shown.
- **SFTP local paths are confined.** A local path built from a remote name stays in the folder you
  chose, and a deny-list keeps writes away from SSHSpan's own folders, `~/.ssh`, startup folders,
  shell startup files, `PATH` folders and settings that run commands, for typed and dialog-picked
  paths alike (private-key exports and backups may still go to `~/.ssh`). It is a deny-list, not a
  grant model. (A6-02, Partial)
- **Keyboard and screen-reader access.** A visible focus ring, Enter and Space on key and category
  rows and session tabs, one menu system with arrow keys, Escape and focus return, real tab and
  radio semantics, and reduced motion. It has not been tested with a screen reader.

**Upgrading.** The database is migrated forward at the first start: a table for category sync
marks, server columns for an older transfer queue, stored host-key fingerprints rewritten to the
current format, and an existing Bitwarden sync destination counted as allowed, so the upgrade asks
nothing. There is no migration back, so make a backup first (Settings, Backup & restore) if you may
want to return to 1.9.1.

### Added

- **Quit.** Quit is in the vault menu, the command palette and `Ctrl+Q`. Closing the window
  hides SSHSpan to the tray with a one-time notice (without a tray, closing quits), and quitting
  from the window with live sessions or transfers asks first (the tray's Quit does not; in a
  focused terminal `Ctrl+Q` stays the shell's). (`863a024`, `d5e9d22`; A7-37, A5-24)
- **The real version.** The sidebar, the window title and Settings show the real version; the
  internal "v14-tabs" marker is gone. (`863a024`, `d5e9d22`; A2-24, A5-29, A8-26)
- **A startup failure dialog.** A database that cannot be opened or migrated shows a native
  dialog with the cause and the database path and exits cleanly; before, the app died with no
  window and no message. (`863a024`; A7-31)
- **Lock and quit questions.** A pinned warning shows the real time left 60 seconds before an
  idle lock. Locking or quitting from the window while sessions or transfers are live asks first
  (the tray's Lock and Quit and the idle lock do not); a second real `Ctrl+L` or `Ctrl+Q`
  answers yes and a held key never does. (`d5e9d22`; A5-09)
- **Saved-password controls.** The server dialog says when a password is saved and offers
  "Remove saved password". "Test connection" asks for a password when none is saved, every
  server row has a "..." menu that includes it, and only one test runs at a time. (`d5e9d22`;
  A2-04, A2-11, A5-03, A5-20, A5-28, A7-38)
- **Connect progress.** While a tab connects, its status line reads "Connecting to
  `<host>:<port>`…" and the terminal header has a Cancel button; each tab keeps its own status
  line. (`d5e9d22`; A5-10, A2-25, A3-27)
- **Link and paste review in the terminal.** Every link, OSC 8 or plain, asks first and shows the
  real site on its own line; only http and https open. Pasted text loses control characters and
  bracketed-paste markers, and every way of pasting goes through the multi-line review.
  (`7e5c5c5`, `d5e9d22`; A6-12, A3-11, A5-45)
- **Remove deployed copy.** The key pane can remove a key's deployed files and its `Host` stanza,
  and deleting a key offers to remove the deployed files. Only `sshspan_*` files directly in
  `~/.ssh` are ever deleted. (`46a9d1b`, `652aa5e`; A7-22, A5-43, A8-16)
- **Export passphrases.** OpenSSH and PuTTY exports take an optional passphrase, and the tab says
  the file is unprotected without one. (`652aa5e`; A8-12)
- **The deploy plan.** The deploy sheet shows what the backend will write - the config text, the
  files per key and every refusal - plus the `Include` line with a Copy button. (`46a9d1b`,
  `652aa5e`; A2-05, A5-04, A7-04, A8-01)
- **Empty results say so.** The key list and the server list show a "No keys match" or "No
  servers match" row with Clear filter, and the key list has a select-all for the keys shown.
  (`652aa5e`, `d5e9d22`; A2-26, A5-27, A5-34)
- **Stored API key removal.** Settings has "Remove stored key"; presets set the provider and the
  URL together; "Save & test" tests what is on screen; there is a New chat button; and until a
  provider, a model and an API key are saved the panel shows a "Set up the assistant" card with
  an "Open assistant settings" button. (`d589b51`; A4-13, A7-33, A8-13, A4-14, A5-36)
- **MCP server details.** `mcp_list_servers` returns the header name, the environment-variable
  name and whether a secret is stored, and the Edit form shows them; each row shows the enabled
  and total tool counts, the protocol version, a "Not confirmed" badge and the last connection
  test's error. (`d589b51`, `d33028d`, `3b0fcfb`; A4-07, A4-15, A7-30)
- **Bitwarden results.** A sync shows key and server counts, deletions, renames and the errors
  (the first 50, then "... and N more."), and the audit log records `sync.run`, `sync.error`
  and `sync.key_renamed`. Each error's name and reason are shown spelled out and in a text
  isolate of their own, so a direction character in an item's title cannot turn the advice
  around, and the item titles and ids that sync errors quote (several items naming one server, an
  older copy, an item without a creation date, an unusable key, a failed pull) lose control,
  format and direction characters and are cut at 80 characters, as the names in the approval list
  are. Every text the backend returns for the Bitwarden settings (a refused save, Test
  connection's answer, a sync's stop reason or refusal, a list too long to approve, the answers of
  "Allow syncing...") is shown spelled out. (`863a024`, `d5e9d22`, `6c19b1b`; A2-08, A7-24,
  A8-04)
- **Bitwarden pending changes by name.** A sync that would overwrite a local server or key, or add
  a new one, reports each by name before anything is applied (`pendingServers`, `pendingKeys`,
  `pendingTruncated`), and the confirmation lists them under the question: the address a server
  has here and the one it would get, the fingerprint a key has here and the one it would get, and
  new ones with their address or fingerprint, each value cleaned of control, invisible and
  text-direction characters and cut at 80 characters. (`cd11f97`, `d94ed2d`, `03dfa92`,
  `3b0fcfb`)
- **SFTP upload picker.** Upload opens a native multi-file picker, queues the picks with one call
  and reports each file; the toolbar has an Upload button and the empty area has a menu.
  (`863a024`, `463345c`, `11abb3e`, `d5e9d22`; A5-40)
- **Edit conflicts.** A save from an external editor is compared with the server's size and time;
  a file that changed or was deleted there is held back as a conflict and settled with
  `sftp_edit_resolve` (Overwrite or Reload). (`463345c`; A7-19)
- **Palette and audit log.** The command palette needs every word to match,
  ranks results and lists more destinations; the audit log has an event filter, a text filter and
  "Load older entries". (`53347df`; A5-16, A5-17)
- **Keyboard and screen-reader access.** A visible focus ring everywhere; key rows, category rows,
  chevrons and session tabs work with Enter and Space; menus are built by one helper with
  `role=menu`, arrow keys, Escape and focus return; tabs and radio groups have real semantics;
  password fields have a show and hide button that does not pollute their names; motion respects
  the reduced-motion setting. (`53347df`; A1-10, A1-11, A1-26, A1-36, A2-50, A5-23, A5-35)
- **Error cards with Retry.** When keys, servers or settings fail to load, an error card with Retry
  replaces the empty first-run state. (`c227218`; A5-21)
- **Native questions for credentials.** Saving an MCP server that binds a secret or an environment
  variable to an address it was not bound to before (a new server, another URL or variable, a
  record restored from a backup or refused before), moving a stored API key to another provider
  or address, and pointing the Bitwarden sync at a server or account you have not allowed (next
  entry) ask a native question that names the host (and the variable; the Bitwarden question names
  the account, the server and its address). Its buttons are "Don't allow", "Allow" and "Cancel";
  "Don't allow" is the default button on Windows, where a stray Enter answers it, while
  the GTK dialog on Linux sets no default button, so only a deliberate click on "Allow" can come
  early. Esc or closing the dialog means no; an "Allow"
  within a second of the dialog opening, after the vault locked (even if it was unlocked again), or
  for settings that changed meanwhile confirms nothing; only one such question is open at a time
  and a second is never queued (an API-key move is refused, an MCP server saved meanwhile is
  stored switched off until it is saved again, and a Bitwarden save meanwhile is stored but the
  sync stays off until it is allowed); a later "no" is never undone by an earlier "Allow"; and
  both answers are audited without the value (`mcp.credential_allowed`,
  `mcp.credential_declined`, `assistant.key_move_declined`, `sync.destination_allowed`,
  `sync.destination_declined`; an allowed key move is also named in the `assistant.config` row).
  Until it is allowed, an MCP server stays off and its row says "Not confirmed" with an "Allow
  sending..." button, and the key move is refused with "Enter the API
  key for the new address.". An "Allow" for the key move that arrives after a lock, even one
  followed by an unlock, moves nothing and says "The vault was locked while you were deciding -
  unlock it and save the settings again." After a "Don't allow" or "Cancel" (Esc and closing the
  dialog count as "Cancel"), no further question of the same kind is asked for 30 seconds,
  whatever host, address or account it names. The kinds are an MCP credential, a stored API key
  moved to another address and the Bitwarden upload; they wait separately, so a "no" to one holds
  back neither of the others. The wait is kept in memory: a lock does not clear it and a restart
  ends it. An MCP server saved in that window is stored switched off and says
  `The server was saved but stays switched off, because sending a credential to <host> was declined a moment ago. Wait 30 seconds, then save it again.`
  and a key move is refused with
  `Sending the stored API key to <host> was declined a moment ago. Wait 30 seconds, then save again, or enter the API key for the new address.`
  where `<host>` is the host of the question that was declined, which need not be the one asked
  about now. An "Allow" within a second was no decision and starts no wait, and once the 30
  seconds are over the next question is asked as before.
  The page cannot answer the question, and the assistant settings no longer send the key-reuse
  flag. (`03dfa92`, `3b0fcfb`, `6c19b1b`; A4-13)
- **Bitwarden sync asks before it uploads.** A sync uploads your SSH private keys (encrypted with
  your Bitwarden account key) and your saved server passwords, so it now runs only against a
  server and account you allowed. A save that sets a server URL or an account email other than
  the allowed one - the first save, a changed server, a changed email (the email is compared
  without regard to case or surrounding spaces) - stores the settings and then asks "SSHSpan -
  Sync with Bitwarden?": SSHSpan will upload your SSH private keys and saved server passwords to
  the server and account it names, with the server's address shown under it (the account comes
  first, on its own line, then the server and the address, labelled Account, Server and Address,
  and the dialog says when the account is not the one allowed before). The save returns once the
  question is answered, so Save stays busy while the dialog is open. Until the destination is
  allowed, a sync is refused before any network call - not even a login - with
  `Bitwarden sync is off until you allow it to upload your keys and passwords to the account <email> on <host>. Use "Allow syncing..." in Settings > Bitwarden.`
  Test connection still works, because it uploads nothing. A save that is not allowed shows why
  as a warning instead of "Bitwarden settings saved." (not allowed, answered within a second,
  declined less than 30 seconds ago, another question still open, the vault locked or being
  re-encrypted meanwhile, the server or account changed meanwhile, or the answer could not be
  stored). Settings > Bitwarden says
  `Not confirmed - SSHSpan will not sync with <host> until you allow it.`
  and offers "Allow syncing...", which asks the same question again (`bitwarden_allow_sync`; busy
  while the dialog is open; refused while the vault is locked and before any settings are
  saved); when "Allow syncing..." had the focus and the sync is now allowed, the focus moves on
  to Sync now (to Save or Test connection when Sync now cannot take it, and nowhere when you have
  already moved to a control that is still there). Settings saved before this change keep syncing:
  a one-time migration at the first start counts their destination as allowed, so an upgrade asks
  nothing. Going back to the server and account that are still the allowed ones asks nothing
  either (only the last destination allowed is kept, so returning to an earlier one after allowing
  another asks again), and a restored backup carries no Bitwarden settings, so it can neither
  bring nor confirm a destination. The audit rows `sync.destination_allowed` and
  `sync.destination_declined` hold the host only. An "Allow" within a second counts as a refusal and
  is logged as `sync.destination_declined` with `answered=too-quickly`, without starting the
  30-second wait that follows a "no". (`6c19b1b`)
- **Category order.** `category_set_order` renumbers one whole list of categories (it must name
  every category under that parent, restored loop roots included) in a single transaction without
  changing any parent; a partial list is refused. A drag, Move up or Move down in the category
  tree writes one `category_set_order` for the whole list as shown, preceded by
  `category_reparent` when the parent changes (Move to... sends only `category_reparent`), so a
  drop beside the root of a restored loop lands where it was dropped, no row you did not move
  changes place and a repeated drop is stable. A restored category whose saved parent is in the
  other scope (a host category under a key category, say) counts as top level in its own tree, as
  the tree shows it, so its top level can be reordered; every such reorder was refused with "Those
  categories do not share a parent - reload the categories and try again." and reloading could not
  help. (`03dfa92`, `3b0fcfb`, `6c19b1b`; A2-07, A2-45)
- **SFTP layout.** While the transfer queue is empty the file list shows at least 3 whole rows at
  the smallest window (880x560) and 5 at the default size (1100x720): the transfer panel is only its
  header until the first job, then takes at most 35% of the file area by default (its top edge
  resizes it, by pointer or with the arrow keys, up to 70%, and the file list always keeps its
  minimum height). A panel 900 px wide or less folds the permissions and owner columns, the local
  pane, the activity log, directory compare and synchronized browsing into a "More" menu and shows
  the other toolbar buttons as icons. In the queue grid the Route, Speed and ETA columns drop out at
  720 px or less and each job takes two lines at 480 px or less, with the row buttons still
  reachable, and Split mode stays inside its column. Each splitter (local and remote panes, and
  terminal and file browser in Split) lays out its two sides from one percentage, so they always
  fill the row, and is a separator the arrow keys move. Names stay on one line with an ellipsis and
  the full name on hover, the spinner, symlink and quick-find states are styled, the Local table
  drops the columns it never fills, the conflict dialog's close button shows its icon and has a
  name, and the search box has a name and a hint and no spellcheck or autofill. (`d94ed2d`; A1-01,
  A1-02, A1-03, A1-15, A1-16, A1-17, A1-28, A1-31, A1-34, A5-07)
- **Pointer-based drag and drop.** In-page drag and drop in the file browser and the category tree
  uses pointer events (a press that moves 5 px starts a drag, a ghost follows the pointer, the
  target is lit, Escape cancels, and the release of a drag is never also a click or a
  double-click), so it does not depend on the HTML5 `dragover` and `drop` events that the Windows
  webview does not deliver while OS file drops are enabled (the suites emulate that by removing
  those events). In the file browser, remote items dropped on a remote folder move there after a
  question, local items dropped on the remote side upload and remote items dropped on the local
  side download. Every drag has a menu alternative: a remote file's menu gains "Move to..."
  beside Download, a local file's menu has Upload, and the category menu gains "Move up" and
  "Move down", which `Alt+ArrowUp` and `Alt+ArrowDown` do on a focused row. (`d94ed2d`; A3-23)
- **Edit-conflict prompt.** A conflict opens one prompt that names the file and says it changed on
  the server since you opened it, was deleted there, or could not be checked, with Overwrite,
  Reload (disabled for a deleted file) and Cancel. It asks about one file at a time: a newer
  conflict for the file on screen replaces the question, a conflict for another file waits its
  turn and the prompt says how many wait. Overwrite and Reload take no click for 750 ms after the
  prompt appears or changes, so a click aimed at the last question cannot answer the new one.
  Cancel, Escape or a click outside leaves the file as it is (its next save asks again); a vault
  lock, a closed tab or a session that ended drops the question. (`d94ed2d`; A7-19)
- **Files and Split opening.** A second click on Files or Split while the file browser is opening
  waits for the same request instead of sending another `sftp_open`, the last click decides which
  surface is shown, and the Shell/Files/Split control shows that it is busy. (`d94ed2d`; A5-12)
- **Stop editing asks first.** "Stop editing" used to delete the local copy of an edited file
  whatever it held. `sftp_close_edit` now checks first, waiting up to 10 seconds for an upload or
  Reload of the file that is running, whether the server has everything in the local copy. A copy
  with changes the server lacks (a save still inside its 700 ms debounce, one that failed or was
  held back as a conflict, or one whose watcher event was lost), an upload still running after 10
  seconds, or a copy that cannot be read or checked closes nothing and deletes nothing, and the
  answer says why, with one of
  `<name> has changes that are not on the server. Stop editing and lose them?`,
  `<name> is still being uploaded. Stop editing and lose any changes that do not reach the server?`
  or
  `Could not tell whether the server has everything in <name> (<why>). Stop editing and lose any changes that are not on it?`.
  The page asks that question with Cancel focused, and only a yes sends `force: true`, which closes
  at once. A check that takes more than a second says
  `Checking <name> for changes that are not on the server…`, a second Stop editing meanwhile sends
  nothing, and an answer that arrives after the vault locked is dropped unasked. Two slow checks
  at once put back the strip's earlier text when the last one answers, not "Checking" the other
  file, and a lock cancels the one-second "Checking" line. Edit while that file's Stop editing is
  still deciding is refused, because the stop could otherwise delete the copy the editor has just
  been handed: the page says
  `<name> is being closed - try again when it has stopped.`
  at once and sends nothing, and the backend refuses it with the same words. Once Stop editing
  has asked about unsaved changes, the file opens again and gets the same edit; an open that took
  the edit in the very instant before Stop editing marked it as being closed is not caught.
  Closing the tab, disconnecting or losing the session, and locking the vault still end every
  edit at once. The backend's own texts in this flow (a refusal to open, a Stop editing answer
  that is not ok, a failed save-back, a refused answer to a conflict) are shown spelled out.
  (`03dfa92`, `3b0fcfb`, `6c19b1b`; A7-19)
- **Deploy warnings and Host lines.** The deploy sheet lists, under the plan, the preview's
  warnings ("Check before you deploy:") and every `Host` line of your own ssh config that names
  the target hosts, as `file:line - text`, marking the lines `ssh` cannot read and the lines an
  earlier SSHSpan wrote; the Deploy question repeats the warnings (six at most, then "...and n
  more"). Quoted text is spelled out and bounded: invisible and text-direction characters show as
  `<U+202E>`, a Host line's file, line and text are each isolated, and a Host line's file or text
  is cut at 300 characters and a warning at 800. The backend cuts a quoted line at 300 characters
  as well. (`03dfa92`, `3b0fcfb`; A2-05, A8-01)
- **Bitwarden last result.** The sync status line shows the last result: `Last sync stopped: <reason>`
  for a run that stopped part-way or failed (`it did not finish.` without a reason), or
  `Last synced: <time> - <n> errors, see the list below.` with the errors listed for a run with
  item errors, instead of reading "Last synced" after a stopped run. A sync that fails at login
  or at the vault fetch returns an error before any result is stored, so the line keeps the
  previous result. (`3b0fcfb`; A2-08)

### Changed

- **Settings show what is applied.** Settings show the effective defaults (auto-lock 15 minutes, 4
  parallel transfers), are validated in Rust, revert a control when a save is refused, and disable
  the security settings, with the reason, while the vault is locked. Clear log, Forget host and
  category edits are disabled while locked too. (`57993ba`, `c227218`; A2-14, A5-32, A5-06, A7-11,
  A8-14, A8-00)
- **"Config" import reads your real `~/.ssh/config`.** It is read-only, follows one level of
  `Include`, skips `Match` blocks and patterns, ends a broken `Host` line where it ends, runs off
  the main thread, names the file it read and is disabled while the vault is locked. Before, it
  read SSHSpan's own managed file. (`5e77b54`, `d5e9d22`; A2-43, A5-05, A7-26, A8-02)
- **Deploy writes what it previews, in a form OpenSSH accepts.** The Host alias, HostName, User and
  Port from the sheet are honoured; paths and values are quoted and escaped; aliases keep safe
  characters and pattern aliases (`*`, `?`, `!`) are refused; a leading `=` in HostName or User and
  `%` or `${` in User are refused; a deploy warns about `%` in the config path and about your own
  overlapping `Host` lines; writes to the managed config are serialised. A key is never written
  over another key's file or alias. SSHSpan still never edits your `~/.ssh/config`. (`46a9d1b`,
  `463345c`; A7-04, A2-46, A7-59, A5-25)
- **Save dialogs open in Downloads.** Every save dialog - "Download as...", the public-key and
  private-key exports, the audit log's CSV and the vault backup - opens in the Downloads folder,
  or in the home folder when there is none. GTK opens a dialog that has no folder set in the
  working directory, usually home, which left a suggested `.bashrc` (a hostile server's file name,
  or a compromised page's) one Save and one "Replace?" away from the real one. (`6c19b1b`;
  A6-02)
- **Key names and sizes.** Key names must be unique, ignoring case, on create, import and rename
  (existing duplicates stay readable); RSA sizes outside 2048-8192 are refused and the dialog says
  4096 and 8192 can take a minute; key generation runs off the UI thread. (`46a9d1b`, `652aa5e`;
  A5-25, A7-12, A5-12)
- **Fingerprints in one format.** Fingerprints use the `SHA256:` form that `ssh-keygen -lf` prints
  everywhere, and stored rows were migrated. (`5e77b54`; A7-46)
- **Connect limits and messages.** Connecting times out after 20 seconds and authentication after
  30 (time spent in the host-key dialog does not count); a changed host key and a declined
  first-trust prompt have different messages; a timed-out handshake closes its socket.
  (`5e77b54`; A7-14, A7-15)
- **Reconnect and Restart.** They act on the active tab and keep its key; Restart asks first on a
  live tab, ends the old session only after the password prompt and keeps the scrollback with a
  "reconnecting" line. (`d5e9d22`; A2-44, A3-10, A3-13, A3-14, A3-36)
- **Terminal and assistant defaults.** Restart resets the assistant to Read, and the Upload button
  opens the native picker instead of using the local-pane selection. Developer traces appear only
  behind a developer-tools switch. (`d5e9d22`; A5-11)
- **Terminology and copy.** Servers, Server categories and Keyboard-interactive are the terms on the
  main screens (the command palette and the Bitwarden confirmation still say "host category"); shown
  text is sentence case and uses " - " instead of an em dash (a scan checks it; a lone em dash still
  marks an empty value); the `[OI]` placeholder reads OpenAI. (`53347df`, `d589b51`, `d5e9d22`;
  A5-31, A8-25, A1-39, A8-10, A4-22)
- **The assistant panel no longer squeezes the terminal.** Below 1500 px, and in Split, it overlays
  the terminal; the maximize button no longer covers Send and the transcript is a live region.
  (`d589b51`; A1-03, A4-04, A4-24)
- **Pending approvals end with their tab.** Closing a tab or locking denies a pending approval
  card, resets the level to Read and drops late replies; a dropped session keeps the transcript
  but cancels the running turn; the busy state is per tab. (`d589b51`; A4-06, A4-09, A4-10, A4-19)
- **Approval cards show every argument.** Arguments and tool-event rows are shown in full (long
  values are marked and expand on request), invisible and text-direction characters are spelled out
  as `<U+XXXX>`, and a pending card, not its Approve button, takes the focus when it arrives while
  the focus is in the panel or nowhere (never from a terminal, a dialog or a field you are typing
  in). (`d589b51`, `d5e9d22`; A4-17)
- **MCP URLs.** A URL with a `?query` or `#fragment` is refused (the backend used to drop it
  silently), loopback means a parsed `127.0.0.0/8` address, `::1` or `localhost` rather than a name
  that starts with "127.", and IPv6 URLs keep their brackets. (`d589b51`, `863a024`, `cd11f97`;
  A4-23)
- **Transfers report per item.** `sftp_queue_add` returns one result per picked item, so one bad pick
  no longer sinks the batch and an item's error is never dropped; downloads sync to disk before the
  final rename. (`463345c`)
- **A smaller IPC surface.** Commands with no renderer caller are no longer registered:
  `key_generate`, `key_fingerprint`, `ssh_config_read`, `sftp_upload`, `sftp_stage_path`,
  `sftp_file_sha256`, `sftp_set_mtime` and `terminal_keepalive`; nor are `vault_backup_create` and
  `vault_backup_restore`, which carried the sealed vault through the page and were replaced by
  `vault_backup_export_to_file` and `vault_backup_restore_from_file`. The bodies of ten commands
  that were left in the code unregistered (`vault_export`, `vault_import`, `vault_backup_create`,
  `vault_backup_restore`, `ssh_config_write`, `sftp_upload`, `sftp_stage_path`, `sftp_file_sha256`,
  `sftp_set_mtime` and `terminal_keepalive`) are deleted with the helpers only they used.
  (`dc09f93`, `46a9d1b`, `5e77b54`, `57993ba`, `03dfa92`; A6-03, A8-16)
- **CI and checks.** Six new renderer suites (`test:safety`, `test:sftp`, `test:polish`,
  `test:assistant`, `test:keys`, `test:servers`) run in CI; `check-ipc-args.js` parses
  `generate_handler!`, reads payloads built in a variable, quoted keys and calls spread over
  several lines, and lists as unchecked every call whose command name or payload it cannot read
  statically (a variable command, a computed key, an aliased wrapper, a wrapper renamed in a
  destructuring pattern, in a function's, arrow's or method's parameter list or in a `catch (...)`
  clause) instead of claiming every argument name was checked; the MCP contract check runs as its
  own CI step and requires
  `mcp_save_server` to always send its credential fields; `check-renderer-hygiene.js` runs as its
  own CI step and in `test:polish` and fails on comments that cite the internal work labels it
  knows (`JU3`, `RU6b`, "fix round 1", `I1`, `M7`, "item 7"; other label shapes pass), on
  removed code that comes back and on error text built by hand in the shapes it knows; there is a
  `windows-latest` job for `cargo test` and the static checks (it passed on a runner for the first
  time on 2026-10-17, at `38e586e`; its first run had failed five tests that assumed Unix paths or
  a single ACL entry, which are fixed; its next run, at `fd4765d`, failed one test, because a
  database read gave up behind a run of writes on the loaded runner, since fixed; the job stays
  `continue-on-error`, so its failure does not fail the workflow, until it passes consistently);
  every job has a timeout. The release workflow's Windows tests get the Common-Controls 6 manifest
  the test executables need and, like the CI job, check out with LF line endings, which the tests
  that read source files need. The unreferenced `scripts/refactor_tabs.py` and `scripts/cdp-*.js`
  drivers were removed.
  (`7e5c5c5`, `11abb3e`, `c227218`, `53347df`, `d589b51`, `652aa5e`, `d5e9d22`, `11e7e30`,
  `3b0fcfb`, `6c19b1b`, #85; A7-56, A8-17, A8-21)
- **The MCP smoke mock answers like a real server.** `scripts/mcp-smoke-server.py` (developer
  tooling) answers `/mcp-listchanged` like `/mcp` and, for a tool call there, sends a
  `notifications/tools/list_changed` event before the JSON-RPC response; `image_cat` returns a real
  image content block; and the streamed branch of `/mcp` ends with a JSON-RPC response too. Steps
  19 and 26 of `docs/MCP-SMOKE-TEST.md` use them. (#85)
- **Clearer errors.** SFTP list, mkdir, remove, rename, stat, touch and statvfs errors name the
  status once (`<step> failed: <Status> (code <n>): <server message>` instead of "mkdir failed:
  Failure: Failure"). Connect, Test and the assistant refuse at once, with "The vault is being
  re-encrypted - try again when it finishes.", during a master-password change, as the other
  commands that read sealed secrets already did, and they unseal on the blocking pool. A
  committed change whose audit row cannot be written (key delete, rename and create, category
  create and delete, key categories, the Bitwarden settings) is reported as success with a
  warning, shown as a warning toast after the success, not as an error that makes a retry fail;
  nothing is retried. Locking an already locked vault writes no second audit row. The shared
  `errText` turns an `Error`, a backend string or an `{ error }` object into its message (and
  anything else into a short sentence), where about 90 hand-made copies showed "[object Object]"
  or threw on a null rejection; `check-renderer-hygiene.js` fails on the hand-made shapes it
  knows. (`03dfa92`, `3b0fcfb`)
- **Bitwarden sync names what changes.** Each pending server overwrite lists the settings it would
  change (name, host, port, user, password, authentication method, linked key, category) and the
  confirmation shows them ("host category" for the category), a key whose categories differ counts
  as a real change, real changes are listed before revision bumps so they cannot be cut off by the
  500-entry cap, more than 500 server changes, or more than 500 key changes, cannot be approved and
  the sync says so, and every quoted name is stripped of control, invisible and text-direction
  characters and capped at 80 characters (a name that shows nothing reads "(blank name)", spelled
  out). Server names pulled from Bitwarden are stored cleaned the same way, and comparing pending
  changes reads the categories once per pass instead of once per lookup, which took minutes for
  hundreds of servers. (`03dfa92`, `3b0fcfb`)
- **The file browser's own settings and caches.** A setting changed from the SFTP view (Columns,
  Keep times, Dual, Compare, the conflict dialog's "Always use this action") puts its control back
  and shows the backend's reason when the save is refused, and the local pane's "Set as default
  local directory" reports only a save that went through. After mkdir, new file, rename, delete,
  chmod or move, the cached listings of the folders that changed (and of a moved or deleted folder
  and everything under it) are dropped and the folder on screen is listed again if it is one of
  them, where before only whichever folder was on screen was refreshed. A drop onto the local side
  asks about an existing file like every download. (`d94ed2d`; A3-23 for the drop onto the local
  side)
- **Lock gating and confirmations.** The empty-keys "New key" button, the lock button while already
  locked, Bitwarden Save, Test and Sync, and Backup Create and Restore are disabled with a hint
  while the vault is locked like their neighbours, and the empty Keys view says "The vault is
  locked" with an Unlock button (or "No vault yet" with Create vault) instead of the first-run card.
  "Lock now" with no vault says "There is no vault to lock yet.", Ctrl+L or the idle timer on a
  locked vault does nothing, and the tray lock only refreshes the page, since the backend has locked
  already. The SFTP file, folder, local pane and Bookmarks menus are built by the shared menu
  helper, so focus moves in and back and arrows, Home, End, Escape and Tab work (a file row's menu
  already opened with Shift+F10 or the Menu key; what is new is the focus handling). A confirmation
  ignores the second click of a double-click, so a double-click on a menu item cannot answer the
  question that opens under the pointer. (`3b0fcfb`; A6-08, A5-09, A2-50)

### Fixed

Vault, dialogs and settings

- **Dialogs behave.** One Escape handler closes only the top layer, stacking follows open order,
  a dismissed unlock dialog stays dismissed, the change-password dialog is no longer closed by the
  status poll and labels its fields correctly, the confirmation dialog focuses Cancel, and a lock
  settles pending confirmations and closes every dialog. (`7e5c5c5`, `c227218`; A1-09, A1-23,
  A1-27, A1-30, A2-06, A2-10, A2-22, A2-40, A2-49, A5-08)
- **Secrets no longer linger in the page.** A lock blanks password and PEM fields, a private key
  pasted into the Import form does not survive Cancel or a lock, and the backup password prompt
  is masked and untrimmed. (`7e5c5c5`, `c227218`; A2-09, A2-13, A5-18, A5-19)
- **No double submits.** Create, Import, Export, Remove deployed copy, Deploy and the vault dialogs
  show a busy state, ignore a second click and keep keyboard focus, so a double click no longer
  creates two keys or two servers. (`7e5c5c5`, `c227218`, `652aa5e`, `d5e9d22`; A2-18, A5-12,
  A1-26)
- **Boot and errors.** Boot no longer aborts when one call fails, identical toasts collapse, and an
  asynchronous callback that fails shows its error instead of only logging it. (`c227218`; A2-20)
- **Notifications over a dialog.** A notification no longer blocks the dialog beneath it: clicks
  pass through to the dialog (except on the notification's × button), and a notification turns
  see-through while the pointer is over it or while it covers the control that has the keyboard
  focus, so buttons such as Create and Save can always be seen and clicked. A click on the part
  of a notification that lies over the dimmed backdrop does nothing, so it cannot close the
  dialog. Before, a few long notifications could cover a tall dialog's Create button for up to 9
  seconds. (#85)
- **Reads no longer fail behind a busy write.** A read or a write that finds another write in
  progress now waits up to 30 seconds for it to finish, instead of 5. Before, on a loaded machine
  (seen on Windows) a settings read could fail with "database is locked" behind a run of writes,
  for example during a sync. (#85)
- **Restoring a backup.** Restore keeps each key's Bitwarden revision metadata (numbers were read
  as strings), writes its audit rows after the commit instead of through a second connection while
  its own transaction was open, validates the restored settings, aborts if the vault locks
  meanwhile, and reloads keys, servers and settings afterwards. (`57993ba`, `c227218`; A7-27,
  A7-25, A2-30)
- **Small vault fixes.** The master-password length rule counts characters, not bytes; the
  create-vault dialog names Argon2id instead of scrypt; the audit CSV export neutralises
  spreadsheet formulas. (`57993ba`, `c227218`; A7-52, A8-11, A2-32)
- **Secret files on Windows.** Deploy, private-key export, backup export and the audit CSV export
  all failed on Windows because `icacls` was given a bare SID. The file is now created empty with
  no sharing, and one `icacls` call from the absolute System32 path (no console window) removes
  every inherited permission and gives the current user full control before any byte is written;
  a failed restriction removes the file. Where the folder passes permissions down (`~/.ssh` under
  the user profile normally does), the current user is then the only account with access. Where it
  passes none down (seen on the CI runner, an elevated administrator), SYSTEM and Administrators
  keep the full control Windows gave the new file, which OpenSSH accepts on a private key. The call
  grants no other account anything; with Windows' default settings, Users, Everyone and
  Authenticated Users get no access either way. Verified natively on Windows 11.
  (`57993ba`; A7-01, A7-43, A6-13)
- **No more freezes on slow work.** Key import, vault create and unlock, server save, local SFTP
  mkdir and rename, eight more commands and the Bitwarden settings save run off the main thread; the
  unlock throttle holds for parallel guesses and for the password-change check; a lock during an
  unlock wins; an unlock is refused with the same message until a re-encryption finishes; concurrent
  creates, imports and renames cannot overwrite each other; every read-then-write SQLite transaction
  takes the write lock first; DNS checks run off the async workers. (`cd11f97`, `863a024`; A5-12,
  A7-48)

Keys, categories and deploy

- **ECDSA keys can be generated.** The dialog sent curve names the backend refused. (`46a9d1b`,
  `652aa5e`; A2-02, A5-37, A7-02)
- **PuTTY and RFC 4716 exports.** Every passphrase-protected PuTTY export failed its own MAC check
  and could not be opened by PuTTY or SSHSpan; the RFC 4716 public export kept only the first word
  of the comment. An unencrypted `.ppk` import now verifies its MAC and a missing one is refused.
  (`46a9d1b`, `463345c`; A7-53)
- **Import errors help.** Unsupported formats are recognised locally and named, with the command
  to convert them; a private PEM in an unsupported format is not sent over IPC just to be refused.
  (`46a9d1b`, `652aa5e`; A5-39, A7-03)
- **The key list.** A key filtered out closes its detail pane and clears the export passphrase;
  nothing is auto-selected after a delete; a new key preselects the active category and is
  announced when a filter hides it; the key list rebuilt from the Servers view is no longer
  filtered by a server category; overlapping loads no longer duplicate rows; the New key dialog
  resets its category chips and returns focus to its opener. (`652aa5e`; A2-15, A2-29, A2-37,
  A5-23, A5-34, A5-42)
- **Categories.** Counts are recursive and de-duplicated; "N children reassigned" counts only real
  children; deleting a host category moves its servers to the parent and refreshes the list;
  deleting a key removes its category links; drop zones are read before they reset; a category
  dropped beside the root of a restored loop, or beside a row whose parent no longer exists, lands
  where it was dropped (see "Category order" under Added); the picker restores the category
  scope; a category loop restored from a backup no longer hides keys or freezes the app, and
  moving a category into one is refused. (`46a9d1b`, `652aa5e`, `cd11f97`, `d94ed2d`,
  `03dfa92`, `3b0fcfb`; A2-07, A2-23, A2-31, A2-45, A2-54, A7-28, A7-40)
- **Public key exports** go through the native save dialog, so a cancel exports nothing and the
  toast no longer claims success. (`652aa5e`; A2-42)
- **Deploy sheet.** Servers are saved before the sheet closes and a save error is shown.
  (`652aa5e`; A2-33, A7-32)

Servers and terminal

- **Editing a server keeps its saved password.** A blank password keeps it, "Remove saved password"
  clears it, switching to key login clears it, and a new key-login server stores none; port 0 is
  refused; the plaintext is wiped on every return path. (`5e77b54`; A2-04, A5-03, A7-07)
- **A tab closed mid-connect no longer leaks its session.** The session that arrives late is
  disconnected, an overlapping connect on one tab cannot orphan the first, and Cancel ends a
  pending connect. (`d5e9d22`; A2-12, A3-14, A5-10)
- **Terminal output is decoded across packets,** so a multi-byte character split between two SSH
  packets no longer turns into replacement characters. (`5e77b54`; A7-08, A3-32)
- **Terminal keys.** The key-compatibility and Backspace settings are sent to the session (they
  only changed the local display before); the view chords (`Ctrl+Shift+1`, `2`, `3`) work while the terminal
  has focus and never send NUL; there is one "[connection closed]" line; resizes are sent once per
  frame and only when the size changed; the bell flashes the tab; header controls go icon-only
  when the window is narrow instead of being clipped. (`d5e9d22`, `53347df`; A8-03, A3-26, A2-53,
  A8-18, A3-34, A1-38)
- **Leaving a maximized terminal.** Opening Settings or another view from a maximized terminal
  left the page clipped, with the sidebar and top bar gone and no way to scroll; leaving Connect
  now ends the maximized view. The MCP tool list scrolls on its own, and a long name a server sends
  no longer widens the settings panel. (#83, `7a21dd2`)
- **Status and focus.** Returning to Servers no longer overwrites the status strip with "Ready.
  (build ...)" or leaves focus on the page; the terminal's deferred focus no longer takes focus
  from a menu or a control you just reached; every successful connect no longer prints developer
  diagnostics. (`d5e9d22`; A2-25, A3-27, A5-11)
- **Server lists and menus.** Server rows no longer reserve invisible buttons, the `.pem` field is
  no longer squeezed, ports are checked from 1 to 65535 beside the field, "Use this key to
  connect" lists key-login servers only and says why others are missing, the command palette's
  "Connect" and "Switch to session" pick a live tab, the terminal menu's "Switch to terminal" and
  "Switch to SFTP" do what they say, and "New session" and "Duplicate session" are different
  actions. (`d5e9d22`, `53347df`; A1-20, A1-21, A2-35, A2-39, A3-31, A3-35, A5-30, A5-33, A5-41)
- **A new server starts in the active host category.** With a host category chosen in the filter,
  the form for a new server starts in it (the chip can still be removed), as a new key starts in
  the active key category; before, such a server was saved in no category and could not be found
  in the list it was added from. A saved server that the current filter hides is announced:
  "Server saved - it is hidden by the current filter. Clear the filter to see it." When the save
  also removed the saved password, the same sentence follows that report ("Server saved - its
  saved password was removed. It is hidden by the current filter. Clear the filter to see it.").
  (`6c19b1b`; A5-42)
- **A key file protected by a passphrase says what to do.** A server that signs in with a key
  file protected by a passphrase failed at the first connect with "Could not decode the selected
  private key: The key is encrypted", which does not say what to do, because a connect has no way
  to ask for the passphrase. A connect now says
  `This key file is protected by a passphrase, which SSHSpan cannot ask for when connecting. Import it under Keys (New key > Import asks for the passphrase) and choose that key for this server, or remove the passphrase from the file.`
  for OpenSSH, PKCS#8, traditional PEM (`Proc-Type: 4,ENCRYPTED`) and PuTTY key files alike. Saving
  a server that signs in with such a key file (and has no vault key chosen) saves it all the same
  and returns the same advice at once, as the `warning` that `server_save` returns beside `ok` and
  the server id. The check reads at most 64 KiB of a regular file and never opens a named pipe or
  another special file, so it cannot stall a save. The server dialog (the import from
  `~/.ssh/config` only prefills it) and the deploy's "Also save these as servers" show the warning
  as a warning toast of its own, in the backend's words spelled out, after the report that the
  server is saved (the deploy names the server in each line). The check runs after the save has
  released the guard that keeps a master-password change out, and a path that starts with two
  separators (`\\...` or `//...`) is not looked at, because on Windows a look would open a
  connection to the share and could stall. On Windows SSHSpan reads a key file only from this
  computer's drives: a path with a drive letter (`C:\...`, a mapped drive too) is read; every other
  spelling - a network or device path (`\\server\share\...`, `\??\UNC\...`, `\\.\...`), another
  prefix or a relative path (`key`, `D:key`) - is never opened. Saving such a server saves it and
  warns
  `SSHSpan reads key files only from this computer's drives (like C:\...). Copy the key to a local folder, or import it under Keys.`
  and Connect and Test connection refuse with the same text before the path is touched. Linux and
  macOS are unchanged. (`6c19b1b`; A5-26)
- **Maximized terminal.** The hint names the real way back instead of telling you to press Esc,
  which goes to the remote shell. (`d5e9d22`; A5-44)
- **The update dialog** names the version, warns about live work, allows one update run at a time
  and reports a newer release that has no installer for this platform instead of saying you are
  up to date. (`863a024`, `d5e9d22`; A2-41)

SFTP

- **Folder uploads create the remote folders first;** every file in a new folder used to fail with
  "No such file". A short read is an error ("incomplete transfer") instead of Done. (`dc09f93`;
  A7-09, A7-18)
- **Downloads.** "Download as..." writes `<name>.part` and renames, so a failed download no longer
  destroys the file it replaced; Resume seeks instead of re-reading the prefix (and now obeys
  pause, cancel and the bandwidth cap); timestamps are preserved on downloads when asked;
  same-named targets in a batch, including case-folded ones, get distinct names; jobs remember
  their server and resume after a reconnect or restart. (`dc09f93`, `11abb3e`; A7-34, A7-35, A7-36,
  A7-57, A7-17, A3-21)
- **Folder walks.** Folder downloads skip symlinks and special files, stop at depth 64 and 10,000
  entries, report per-item notes, and no longer abort on a dangling link. Recursive chmod skips
  symlinks, reports failures, never puts setuid, setgid or sticky on files, and the dialog shows
  and keeps those bits. (`dc09f93`, `11abb3e`, `5e77b54`; A3-28,
  A6-06, A7-16, A7-20, A3-20)
- **Edit in your editor.** Extension-less files such as `authorized_keys`, `Makefile` and `hosts`
  open; saves are coalesced and uploaded to a temporary name and renamed; the result, success or
  failure, is reported once; and a save the file watcher missed is caught by a periodic check and
  retried quietly with backoff. `.pub` no longer counts as an inert extension (it opens Publisher
  on Windows). (`dc09f93`, `463345c`, `cd11f97`; A3-24, A3-25, A7-06, A7-19, A6-14)
- **Servers that report no file types.** Entries without type bits are no longer assumed to be
  files: deletes try remove first and only empty a folder that really is one, never a link's
  target, and uploads and saves still finish. (`463345c`, `5e77b54`)
- **Navigation.** A failed folder open keeps the previous folder, listings are sequenced, a refresh
  never discards a navigation in flight, breadcrumbs follow what is shown, `.` and `..` are
  resolved, Up works on Windows drive roots and UNC paths, a local listing error is reported
  instead of jumping Home, and the overwrite pre-check is case-insensitive on Windows.
  (`11abb3e`; A3-04, A3-09, A3-15, A3-16, A3-17, A3-18, A3-19)
- **Selection and conflicts.** The selection is cleared on a folder change and pruned to visible
  rows, so Delete, Download and chmod cannot reach hidden files; delete prompts name the items;
  Rename picks a name that is actually free; the conflict dialog defaults to Skip with Cancel
  focused; "don't ask again" is separate for remote and local deletes. (`11abb3e`; A3-05, A3-06,
  A3-29, A5-47)
- **The queue.** Rows are patched in place so Pause and Cancel clicks survive progress events, an
  empty queue no longer re-requests itself forever, running and next jobs are never cut by the
  100-row cap, cancelled jobs are listed with Retry, and a finishing transfer no longer takes
  keyboard focus. (`11abb3e`; A3-02, A3-03, A3-07, A3-12, A3-33)
- **The browser.** OS drops are ignored unless the Files view is on screen, `Ctrl+A` and `Ctrl+Y`
  stay in text fields, context menus stay inside the window, a finished transfer refreshes its
  own tab's listing, the Preserve-timestamps toggle appears, and searches carry an id so a new
  search cancels the previous walk. (`11abb3e`, `dc09f93`; A3-22, A5-46, A1-04, A3-37, A1-25,
  A3-01, A7-21)
- **The transfer list in a small window.** While the note about paused transfers of a server that
  is not connected is showing, the transfer list keeps room for at least one job in the smallest
  window, in Files, Dual and Split, whatever the fonts: where room is short the note shares the
  panel's header line, and the panel grows into the file list (which scrolls) rather than leave no
  job row. Before, no job's Pause, Cancel or Retry could be reached there on Linux, or in Split on
  any platform. (#85; A1-02)

Assistant and MCP

- **Approvals reach the backend.** An MCP call carries `approved=true` only after the card was
  approved, and at Read and Draft the card is always shown; before, every approved call was
  refused. A stale-hash refusal reloads and shows the new definition instead of retrying.
  (`d589b51`; A4-01, A6-15, A4-05, A4-08)
- **Chat history.** Histories never send an unpaired tool call or an empty assistant message,
  every tool call gets a result even after a stop or a cap, history is trimmed in whole groups and
  bounded, markdown fences, ordered lists and lone `*` render correctly, api.openai.com gets
  `max_completion_tokens`, and the YOLO dialog answers Escape and names its target. (`d589b51`,
  `d33028d`; A4-03, A4-16, A4-18, A4-20, A4-21, A7-44)
- **MCP servers.** Editing keeps or clears credentials deliberately instead of dropping an
  environment-variable binding; sanitised names must be unique and a double-click on Save no
  longer creates two servers; removing an unreachable server works the first time; a server that
  speaks only legacy HTTP+SSE gets a clear "Streamable HTTP only" message; server-sent events are
  parsed as they arrive; a tool is resolved by server id and shown under its 64-character exposed
  name; tool lists and counts stay current. (`d33028d`, `d589b51`; A4-07, A4-11, A4-12, A4-15,
  A4-27, A7-30, A7-50, A7-51, A8-20)

Bitwarden, updates and lifecycle

- **Bitwarden sync keeps data.** Revision and change marks are written back after every push and
  pull (edited items were re-pushed as conflicts), edits made during a sync survive, items moved
  to another folder stay matched, organisation items are reported instead of duplicated, servers
  carry their local id so a lost link re-links instead of duplicating, server passes honour
  the allow-remote-overwrite confirmation, undecryptable fields are errors, category deletes mark
  keys and servers for sync, pulled key names are de-duplicated, a failed server-folder creation
  no longer imports every folder-less login, and a local key whose cipher was deleted can be
  re-created. Test connection uses the form on screen and says what it tested.
  (`863a024`, `d5e9d22`; A2-47, A2-51, A2-52, A7-23, A7-39)
- **Argon2id Bitwarden accounts can log in.** The prelogin answer's `kdfMemory` is in MiB, as
  Bitwarden and Vaultwarden send it and as the official Bitwarden SDK reads it (times 1024, in
  KiB), and SSHSpan read it as KiB. Every Argon2id account was therefore derived with the 16 MiB
  floor, so the master key was wrong and the login was refused unless the account used exactly 16
  MiB. The derivation now reproduces the SDK's known answers for Argon2id (the master key and the
  master password hash, at 4 iterations, 32 MiB and 2 lanes). The bounds are the same, 16 MiB to 1
  GiB, and a number too large for the unit ends at the ceiling instead of wrapping round to the
  floor. So does every prelogin number above 32 bits (iterations, memory, parallelism), which used
  to be cut to 32 bits before the bounds applied, and a KDF type above 32 bits is refused instead
  of being read as another type. PBKDF2 accounts were not affected by the unit. (`6c19b1b`)
- **Windows updates start with UAC.** The installer starts through one `ShellExecuteExW` call so
  the elevation prompt appears, and a declined prompt reads as cancelled; partial downloads are
  deleted on every error and stale update files are pruned at start. (`863a024`; A7-10, A7-42)
- **Exit runs the lock teardown.** Every exit ends MCP sessions, clears the SFTP and edit
  registries and staged copies, pauses the queue and wipes the password store; before, staged
  plaintext copies of remote files survived the process. (`863a024`; A6-09, A7-47)
- **Appearance.** Dialogs keep their buttons visible at 880x560 (scrolling body, pinned footer),
  categories are reachable as a drawer at 900 px and below, the vault chip is compact, the
  selection bar wraps, faint text is at least 4.5:1 and accent fills carry dark text, `color-scheme`
  is dark, truncated values have tooltips, and Settings rows are no longer `<label>` wrappers (the
  bandwidth "Unlimited" pill used to toggle twice). Key names no longer wrap mid-word, group
  Collapse hides its rows, a selected key in a long list brings its detail pane into view and the
  KEY MISSING badge is no longer success green. (`53347df`, `652aa5e`; A1-05, A1-06, A1-07, A1-08,
  A1-12, A1-13, A1-14, A1-18, A1-19, A1-22, A1-24, A1-35, A1-37, A1-40, A2-16, A5-13, A5-15)
- **Documentation matches the code.** README, SECURITY, PRIVACY, ARCHITECTURE, CONTRIBUTING and the
  MCP smoke test were rewritten from the code, and the rewrite roadmap got dated corrections: the
  KDF is Argon2id, not scrypt, and Electron-era (1.2.0 and earlier) vaults are not migrated; data
  and config paths; the managed SSH config; import formats; outbound connections; Bitwarden
  HTTPS-only; audit-log coverage; and the accepted limits. The CHANGELOG keeps its released
  sections, with the two Added lists of 1.9.0 merged into one, `[OI]` spelled OpenAI in the 1.9.0
  entry (the screen text is under Changed) and a dated correction for the 1.3.6 migration claim.
  (A6-07, A7-58, A8-04 to A8-10, A8-19, A8-22, A8-27, A8-28)
- **Transfer verification on servers without sizes.** With transfer verification on, a server that
  omits file sizes made every copy fail with a false "checksum mismatch" and deleted the fresh
  copy; an unknown size is now hashed to the end of the file, and a read that fails at the end is
  an error, never the digest of a part. (`03dfa92`)
- **Category changes never upload fields older than Bitwarden's.** Renaming, moving or deleting a
  category, or changing a key's categories, marks the category (not the whole row) for the next
  Bitwarden sync, which uploads the new category path only while the remote item is unchanged;
  when Bitwarden changed it too, that change is listed for approval first (the approved pull keeps
  the local category) and the category goes up at the next sync, so a password rotated in
  Bitwarden is never overwritten by an older one. The marks are kept on this computer and are not
  in backups. A category rename changes only the name, so it no longer reverts a move that
  committed meanwhile. (`03dfa92`; A7-23)
- **MCP sessions.** A tool-list change announced with a session set-up survives a failed or
  refused call, and a paged listing restarts at page 1 when its session was renewed halfway. A
  lock between a session's check and its registration leaves no session behind, a session that a
  registration replaces is ended where it was set up (once the requests still using it have
  finished), at most four secrets are unsealed at once at a lock, the teardowns share one
  zeroizing copy of the password, and at most 16 session teardowns are pending at once (the rest
  are not sent and expire on their servers). A server that is switched off, edited or removed while
  a request is out gets nothing more: the stored record is checked right before every set-up,
  listing page, renewal, refresh and call, and a set-up checks it again once its initialize is
  answered, so a session for a changed server is ended where it was set up and never registered.
  (`03dfa92`)
- **Small leftovers.** A new approval card takes focus only when focus is already in the assistant
  panel or on the page, so it no longer pulls you out of a terminal you are typing in; the SFTP
  search says which cap it hit ("stopped at 500 matches", "after scanning 200,000 entries" or
  "after 2 minutes"); "Send to" says "Queued" when the file is only queued; closing the assistant
  panel returns focus to its toggle; the audit export shows a busy state; the tray lock no longer
  calls the lock a second time; the Bookmarks button closes its menu on a second click; a bulk key
  delete says a repeated warning once; and an MCP save or server row without `confirmed: true`
  reads not confirmed. SFTP names that show nothing (blank, mark or format characters, U+2800,
  U+1D159) are spelled out whole, `~` is flagged, and single-character emoji, symbols and
  punctuation are not (an emoji written with a variation selector or a zero-width joiner is
  spelled out and flagged). The unused `window.terminalSendText` and `window.appQuit` are gone.
  (`3b0fcfb`; A2-18)

### Security

- **Confirmations work.** Every native `confirm()` guard was a no-op, because the dialog plugin
  replaces `window.confirm` with an asynchronous shim whose result is always truthy: key and server
  deletes, backup restore, host-key forget, tab close, MCP removal, multi-line paste and update
  install all ran unconfirmed. All 13 sites now wait for the in-app confirmation (Cancel focused,
  Escape means no), and a scan fails on any native call. (`7e5c5c5`; A5-01)
- **Idle auto-lock fires.** It never did: the ten-second status poll re-armed the idle timer and
  the heartbeat kept the backend watchdog fed. The deadline is now the last real input plus the
  configured minutes, the poll does not re-arm it, the heartbeat is sent only after activity,
  terminal typing counts, an absent or invalid setting means 15 minutes and `0` means off.
  (`7e5c5c5`, `57993ba`; A2-01, A3-08, A2-53, A5-06, A7-11, A8-00)
- **The sealed vault stays out of the page.** Backup and restore are Rust-owned native dialogs; a
  restore that needs the backup's own password gets a single-use, five-minute file grant. The
  `.pem` Browse returns a path without reading the file, and `system_select_file` refuses files over
  4 MiB. (`57993ba`, `c227218`; A6-03, A2-48, A6-04, A2-19, A7-41)
- **A rotation lock protects re-encryption.** Changing the master password runs off the main thread
  under a vault-wide lock. Commands that seal with the master password or rewrite a whole key,
  server or MCP row fail fast with "The vault is being re-encrypted - try again when it finishes."
  while it runs; the commit updates sealed columns conditionally and installs the new password
  before a best-effort audit, so no record can be left sealed under the wrong password.
  (`57993ba`; A7-13)
- **Locked means locked.** Key delete and rename, category edits, audit clear, known-hosts forget,
  the four security settings, MCP removal and tool toggles refuse while the vault is locked.
  (`57993ba`, `d33028d`; A6-08)
- **The AI cannot press Enter.** Typing from the assistant goes through `assistant_type_text`,
  which enforces the tab's level in Rust, refuses line breaks, control characters (C0, DEL, C1) and
  every Unicode format or default-ignorable character that could disguise reviewed text, caps the
  length at 4,096 characters and audits `assistant.type`. Before, an embedded newline ran a
  command at Draft level with no approval card and no audit row. `assistant_exec` uses the same
  character list and also refuses TAB. (`d33028d`, `d589b51`, `863a024`, `cd11f97`; A3-30, A4-02,
  A6-01)
- **MCP approvals are bound to the definition you reviewed.** A changed tool definition is disabled,
  its auto-approve is cleared and the tool is flagged; every enable names the definition hash the
  user was shown (a compare-and-swap, so a stale settings row cannot approve a new definition);
  the call gate runs again right before every `tools/call`, also after an initialize, a refresh or
  a session renewal. Records are read, changed and written in one transaction, so a revoked
  approval cannot come back, and sessions carry the URL and credential they were set up with and
  are ended at their own endpoint. (`d33028d`, `d589b51`, `cd11f97`; A4-05, A7-29, A8-15, A7-49)
- **MCP credentials stay with their origin.** A URL, auth type or header change drops the stored
  secret and any environment-variable binding that is not sent again, and a server may send at
  most eight requests of its own inside one response, each checked against the vault. (`d33028d`;
  A4-07)
- **Provider requests.** The assistant's provider client follows no redirects (a 3xx is an error
  naming the host), accepts plain `http://` only for loopback and private addresses and refuses
  credentials in the base URL; a stored API key never silently follows a new provider or origin;
  a saved URL that today's rules refuse is refused before the key is unsealed. (`d33028d`,
  `d589b51`, `cd11f97`; A6-10, A4-13)
- **The updater binds the signature to the release.** The signed trusted comment must name the
  release bound to the URL tag (`SSHSpan release v<x>`), so a validly signed older build cannot be
  installed as a newer one; release URLs must be exact release assets with no query or fragment.
  The signature detects tampered published assets and hostile mirrors; it does not defend against
  a compromised repository or release workflow. (`863a024`, `11e7e30`; A6-05)
- **The stored Bitwarden master password is not spent on a typed endpoint.** Test connection and
  save reuse it only for the server and account it was saved for, and the settings row is written
  in one transaction, so no reader sees a new URL with an old password. (`863a024`)
- **The Bitwarden sync uploads only where you allowed it.** A sync sends every SSH private key
  (encrypted with the Bitwarden account key) and every saved server password to the configured
  server and account, so a page that could save other Bitwarden settings could have sent them to a
  server of its own; this predates the release and was found by the final security review. The
  destination - the server URL and the account email (the email is compared without regard to
  case or surrounding spaces) - is now bound in Rust to what you allowed in a native question that
  the page cannot answer (see "Bitwarden sync asks before it uploads" under Added). A save that
  changes it stores the settings as not allowed and asks; a sync reads its settings only through
  one check and refuses before any network call while the destination is not allowed; "Allow
  syncing..." asks again; and a restored backup, which carries no Bitwarden settings, can neither
  bring a destination nor confirm one. The question follows the rules of the other credential
  questions (see "Native questions for credentials" under Added): one at a time, "Don't allow" as
  the default button on Windows, no "Allow" that counts within a second, after a lock,
  for settings that changed meanwhile, or while the vault is being re-encrypted, and no "no"
  undone by an earlier "Allow". An "Allow" that comes after a lock, for settings that changed
  meanwhile, while the vault is being re-encrypted or when the answer cannot be stored writes no
  audit row; one within a second is audited as `sync.destination_declined` with
  `answered=too-quickly`. The account must be one email address - at most 254 characters, exactly
  one "@" with something on each side, no space, control, format or text-direction character and
  none of `( ) < > [ ] " ' , ; : \` - or the save is refused with
  `Enter the Bitwarden account as one email address, like name@example.com.`
  (the account is quoted in the question and in the sync's refusal, and free text in it could add
  words to what you are asked). After "Don't allow" or "Cancel" (Esc and closing the dialog
  included), no further question about uploading is asked for 30 seconds, whatever server or
  account it names: a save or "Allow syncing..." inside that window leaves the sync off and says
  `Bitwarden sync stays off, because uploading to <host> was declined a moment ago. Wait 30 seconds, then use "Allow syncing..." in Settings > Bitwarden.`
  where `<host>` is the server that was declined, which need not be the one saved now. An "Allow"
  within a second was no decision and starts no wait. The MCP and API-key questions wait in the
  same way, each kind on its own (see "Native questions for credentials" under Added).
  (`6c19b1b`)
- **Bitwarden's key derivation cannot hold up the app.** Every Bitwarden master-key derivation -
  Argon2id at an account's own memory setting (up to 1 GiB, which is heavy work) and PBKDF2 alike -
  ran inline on the async worker that was signing in. It now runs on the blocking pool, at most two
  at once (Test connection and a sync share the two places), and a sign-in that gets none within
  30 seconds stops with
  `Another Bitwarden sign-in is still running. Try again when it has finished.` (`6c19b1b`)
- **Local paths are confined and protected.** Every local path built from a remote name is confined
  to the folder you chose; the vault's data directory and system directories are off-limits for
  every access, uploads also refuse SSHSpan's configuration folder and everything under `~/.ssh`
  except public keys, and writes, renames and deletes also refuse SSHSpan's configuration folder,
  `~/.ssh`, startup folders and entries (autostart, systemd user units, launch agents, the Windows
  Startup folders), shell startup files, user `PATH` folders and settings that run commands (git,
  PAM, editor, PowerShell, Office, WindowsApps, Windows Terminal); deleting or moving a folder that
  holds one of them is refused; folder downloads skip symlinks and stop at a depth and entry
  cap. A path picked in a save dialog - for "Download as..." and for the text exports (a public
  key, the audit log's CSV) - is held to the same deny-list as a typed path, and
  `~/.config/user-dirs.dirs` and `user-dirs.locale` are on the deny-list for typed and picked paths
  alike (a download over `user-dirs.dirs` could point the Downloads folder, where every save
  dialog opens, at a folder of the attacker's choosing). The private-key exports and the vault
  backup are held to it too, with one exception: `~/.ssh` stays allowed for them, because
  exporting a private key to `~/.ssh/id_...` is an ordinary thing to do (the text exports still
  refuse `~/.ssh`). The private-key export dialog also suggests only the last part of the key's
  name (after its last `/`, `\` or `:`), so a key named like a path, `/home/me/.ssh/config`, can no
  longer open the dialog on that file. This is a deny-list with confinement to the folder you
  chose, not a dialog-bound grant model (A6-02 stays Partial). (`dc09f93`, `463345c`,
  `6c19b1b`; A6-02, A6-06, A6-14)
- **Edit saves cannot be steered.** A save goes through a fresh, exclusively created temp file, so a
  file or link planted at the old predictable name is never written through, renamed into place
  or deleted; a resumed `.part` is checked before more bytes are appended. (`463345c`)
- **Exports and imports.** "PKCS#8 encrypted" is refused with an empty passphrase instead of
  silently writing an unencrypted key, and a newline in an imported key comment can no longer
  inject lines into `authorized_keys` text, `.pub` files or PuTTY headers. (`46a9d1b`, `652aa5e`;
  A2-03, A5-38, A7-05, A7-45)
- **Known hosts fail closed.** An unreadable `source` column used to fall back to "connection", which
  trusts silently; it now falls back to "imported", which asks again. (`5e77b54`)
- **Secret wiping.** Plaintext copies SSHSpan makes are zeroized, including the saved SSH password on
  every return path. The SSH library zeroizes the password it takes, but builds the
  authentication packets in a buffer it clears without wiping and frees keyboard-interactive
  answers unwiped, which is an accepted limit (A6-11). (`57993ba`, `5e77b54`)
- **A saved SSH password stays with its account.** An edit that changes the host, port, user name
  or authentication method of a server with a saved password (a switch between password and
  keyboard-interactive included), and brings no new password, is refused with "Enter the password
  for the new server or account." and nothing is written, unless the saved password is removed or
  the server switches to a key. The server is read, checked and written in one transaction, so a
  save that raced another save is refused the same way. Connect and Test use the saved password
  only for the server's own user name; connecting as another user does not. The edit dialog says
  at once "A changed server needs its password again" and Save stops at the password field until
  it is typed or the saved one removed; a key sign-in never asks. (`03dfa92`, `3b0fcfb`;
  A2-04, A5-03)
- **SSHSpan's own folders are write-protected.** The folder SSHSpan is installed in (for a portable
  copy run directly from a drive root, the home folder, Downloads, the Desktop or Documents only the
  executable and, on Windows, the DLLs beside it), the running AppImage and SSHSpan's local data,
  cache and webview-profile folders are refused for SFTP writes and deletes, and so is moving,
  replacing or deleting a folder that holds one of them; reads stay allowed. A path picked in a
  save dialog is held to the same deny-list, so it cannot replace the program files either. The
  suggested name of every save dialog, the private-key export's and the backup's included, is
  reduced to a file name (at most 200 characters, never a folder) and the dialog opens in the
  Downloads folder (or home), so neither the page nor a key's name can steer the dialog's folder.
  (`03dfa92`, `6c19b1b`; A6-02)
- **File dialog titles are cleaned.** The title the page gives a file dialog is cleaned like the
  text of a message dialog (no control characters, length capped). A NUL in a title used to abort
  SSHSpan on Linux. (`6c19b1b`)
- **A Bitwarden approval applies the list it was shown.** A sync only plans remote changes; each
  pending change carries a digest of the item exactly as the vault served it, and applying them
  needs the approval token of exactly that list. A list that changed between the dry run and the
  apply is not applied: the new list comes back with a new token and the page asks again (the
  question is shown three times at most; then nothing is applied and it says to sync again). A list
  too long to show (more than 500 server changes, or more than 500 key changes) cannot be approved:
  nothing is applied, no question is asked, and the status line and a toast say why. An item's
  fingerprint and public key are derived from its private key, an item that claims otherwise is
  refused by name and not imported, and pending names are cleaned of control, invisible and
  text-direction characters. (`03dfa92`, `3b0fcfb`)
- **What a native question can say.** An MCP environment-variable name must be 1 to 128 visible
  ASCII characters without spaces or `=` (a name kept from storage is checked too), and every
  value quoted in a question is cleaned of control, invisible and text-direction characters and
  capped in length, so none can rewrite the question; the dialog message also loses every NUL,
  which cut it short on Windows and aborted it under GTK. The assistant base URL refuses such
  characters and is stored in its parsed form (lowercase scheme and host, default port dropped).
  (`03dfa92`)
- **Unusual file names are spelled out.** Wherever the file browser shows a name (the lists, the
  path bar, questions, toasts and the activity log) its control, invisible, zero-width and
  text-direction characters, its unusual spaces and the dots that only stand in for "." are
  spelled out (`<U+202E>`, `\n`), and so are leading, trailing and repeated spaces; a name that
  shows nothing (blank, mark or format characters only, U+2800 and U+1D159 included) is spelled
  out whole, and a name that is nothing but dots, spaces and look-alikes of dots has those
  look-alikes and any combining marks spelled out too (a `..` with a combining mark on its last dot
  would otherwise still read as `..`). The listing flags such a name, and the name `~` (it can read
  as the home folder), with a "!" and says why on hover; single-character emoji, symbols and
  punctuation are visible content and are not flagged (an emoji written with a variation selector
  or a zero-width joiner is spelled out and flagged). Inside a sentence a name is also kept in its
  own text-direction isolate, so it cannot reorder the words around it. A file dropped onto a
  remote folder with a flagged name (from the OS or from the local pane) asks before it uploads,
  and a move names the folder and the folder it is in. (`d94ed2d`, `3b0fcfb`, `6c19b1b`)
- **Dependency advisories.** `quinn-proto` 0.11.17 -> 0.11.18 (RUSTSEC-2026-0338, -0340 and
  -0343, which can panic it) and `rustls` 0.23.45 -> 0.23.46 (RUSTSEC-2026-0346, -0347, -0348 and
  -0349: TLS secrets in `Debug` output, application data sent to the outer server after an ECH
  rejection, a 1 GiB allocation before authentication, and a downgrade to classical key exchange).
  Both are patched releases in `Cargo.lock`. (#85)
- **A release is no longer published without signatures when the signing key is missing.** In
  this repository the release workflow now stops with an error when the `MINISIGN_SECRET_KEY`
  secret is missing, before any installer is attached. It used to skip signing with a warning and
  publish installers that the updater, which refuses an unsigned release, cannot install. A fork,
  which has no such secret, still builds unsigned with the warning. Two gaps remain (see
  [SECURITY.md](https://github.com/AGSQ11/SSHSpan/blob/main/docs/SECURITY.md#updater)): a
  signature upload that fails after the installers are attached leaves a published release
  without signatures, and nothing checks a new signature against the public key the app embeds.
  Installed copies refuse such a release either way. (#85)

### Verification

- Before this work: 216 Rust library tests, 45 integration tests, 11 MCP integration tests and 76
  renderer UI assertions.
- Rust: 885 library, 48 integration and 20 MCP integration tests (953 in all; 950 at `6c19b1b`,
  before the two ACL table tests added with the Windows test fixes and the database wait test).
  Renderer: `test:ui` 75, `test:safety` 491, `test:sftp` 763, `test:polish` 283, `test:assistant`
  367, `test:keys` 431, `test:servers` 676 (3,086 checks in all, 2,935 at the documentation commit
  `e80b01e`; each number is the count of `ok` lines the suite prints). `test:ui` was 76 before its
  embedded MCP check moved to `check-mcp-contract.js`. The five static renderer checks pass;
  `check-ipc-args.js` reads 147 call sites against 110 commands.
- Rust checks ran in WSL2: formatting, Clippy (correctness) and `cargo test` on Linux, plus
  `cargo check --target x86_64-pc-windows-gnu --all-targets`, which type-checks Windows-only code
  and executes nothing. The library and both integration suites also ran natively on Windows 11,
  from test executables cross-built in WSL: 740 of 742 library tests (the other two read source
  files through a path the cross-build bakes in, and passed on the runner), 47 of 47 integration
  tests (the 48th is Unix-only) and 20 of 20 MCP integration tests. A `windows-latest` CI job
  (`cargo test` and the static renderer checks) is added with these changes. Its first run, on the
  pull request, passed the static checks and failed five library tests, none of them a product
  bug: three numbering tests spelled their paths with `/`, a download test used a base with no
  drive letter, and the ACL test expected one entry where SYSTEM and Administrators keep theirs.
  All five are fixed in test code. The ACL test now sets up two folders and writes a secret file
  into each. In one that passes permissions down it requires the user's entry alone; in one that
  passes none down it admits only the user, SYSTEM and Administrators. Two table tests pin both
  rules on every platform, and natively the test passes with `%TEMP%` as is and with `TEMP`
  pointed at a folder that passes nothing down (the native counts above were taken before the
  second table test was added). The job passed on a runner for the first time on 2026-10-17, at
  `38e586e`: the static checks passed, and `cargo test` ran 743 library, 47 integration and 20 MCP
  integration tests natively, none failing. Its next run, at `fd4765d`, failed one library test
  (742 passed): a database read gave up behind a run of writes on the loaded runner, since fixed
  (see "Reads no longer fail behind a busy write" under Fixed). A run at `b637fdc` failed one test
  that could fail at random on any platform (a wrong passphrase passing an AES-CBC padding check),
  since fixed in the test. The job then passed at `30d6af0`, at `52de6d4` and on `main` after the
  merge. It stays `continue-on-error` until it passes consistently.
- The renderer suites run in headless Chromium against a stubbed Tauri bridge. They do not exercise
  WebView2 or WebKitGTK rendering, native dialogs, the tray, screen readers, real SSH, SFTP,
  Bitwarden or MCP servers, or AI providers.
- Test coverage at `6c19b1b`: renderer 92.9% of lines (95.7% of the lines added since 1.9.1); Rust
  production code 72.0% (77.3% of added lines), below the 80% target, mainly because code that
  needs a running Tauri app runs in no test (the commands and the helpers that take an
  `AppHandle`, `State` or `Window`: 61% of the uncovered lines). Details:
  [REPORT.md, section 8.9](https://github.com/AGSQ11/SSHSpan/blob/main/docs/audit/2026-10-09/REPORT.md#89-coverage).

## [1.9.1] - 2026-09-23

Remote MCP servers for the AI assistant (static auth), the assistant panel
legibility fix, and the MCP audit remediation.

### Added

- **Remote MCP servers for the AI assistant.** The assistant can attach
  remote MCP servers over Streamable HTTP (MCP 2025-11-25; stdio and legacy
  HTTP+SSE are refused with a clear "unsupported transport" error) and use
  their tools alongside the built-in ones. Static auth: none, a bearer token,
  a custom header, or an environment variable by name (resolved at request
  time, never persisted). All MCP traffic goes through the Rust backend with
  guarded DNS/SSRF handling for discovered URLs and no redirect following;
  static secrets are sealed with the vault master password. Every tool starts
  disabled until the user approves it, its definition is pinned (SHA-256 over
  canonical JSON), and a changed definition disables it and demands
  re-approval - the rug-pull guard. Every MCP call respects the existing
  access levels (approval card at read/draft/execute unless the tool is
  auto-approve-flagged; free at yolo), the gate is enforced server-side,
  every result is wrapped as untrusted data, and every call is recorded in
  the audit log with the argument hash (not the arguments). Servers restored
  from a backup are inert until the URL and auth source are re-confirmed in
  the UI. Vault lock tears down sessions (DELETE with the session id) and
  drops decrypted secrets.

### Fixed

- **The assistant panel and YOLO dialog were illegible.** The active
  access-level button showed no label (accent text on an accent fill),
  "Enable YOLO" was red-on-red, the YOLO dialog's footer was unstyled
  (`modal-foot` vs the app's `modal-footer`), and stacked margins opened
  holes between the warning paragraphs. The active level is now filled with
  its own colour with dark text on it (the same treatment the Shell/Files/
  Split control already uses), the dialog uses the correct footer class with
  even spacing and a red-tinted icon chip, and long commands wrap instead of
  scrolling sideways in the 380px panel.

- **MCP save and tool-state commands had inconsistent argument casing.**
  `mcp_save_server` and `mcp_set_tool_state` now explicitly declare
  `rename_all = "snake_case"`, and the renderer sends the matching
  `auth_type`, `auth_header_name`, `auth_secret`, `auth_env_var`, and
  `auto_approve` keys. This resolves the runtime
  `missing required key authType` failure and prevents Tauri's automatic
  argument conversion from silently dropping auth configuration.

- **MCP static credentials could outlive their configured origin.** Editing
  a server URL, auth type, or custom header name now clears the stored
  sealed secret; stored-secret, environment-variable, and no-auth sources
  are mutually exclusive. Vault generation is rechecked before every
  credential-bearing MCP request, and lock/removal teardown resolves and
  attaches the auth header before clearing vault secrets (only HTTP 405 is
  ignored).

- **MCP tool definitions could reach the model without their schemas.**
  Bounded canonical `inputSchema` is now persisted, returned by `tool_view`,
  validated by the renderer, and forwarded as provider-facing
  `parameters_json`. The aggregate MCP tool cap is enforced transactionally
  while preserving built-in capacity, and backend/renderer name sanitization
  and collision rejection now use the same canonical algorithm. A
  `tools/list_changed` notification observed during pagination aborts the
  stale pass and refetches from the first page.

## [1.9.0] - 2026-09-21

A full code-audit remediation (26 findings, two of them critical) plus the
AI assistant (panel and backend), hardened against prompt injection.

### Security

- **The AI assistant no longer feeds raw terminal output to the model with
  system-level authority.** The system prompt used to embed the terminal
  snapshot directly, so anything printed on the remote (logs, files, MOTD,
  command output) reached the model as a system instruction - and in YOLO mode
  `run_command` executes with no approval, so injected text could steer
  commands. The snapshot is now delivered as a separate nonce-wrapped
  non-system block whose boundary the payload cannot forge (a fresh per-turn
  nonce, with the closing tag stripped from the text), tool results that carry
  remote output get the same wrapper, and the system prompt now states that
  terminal content is untrusted data and that only the user's own chat
  messages are instructions. The YOLO opt-in dialog warns that on-screen
  content can influence what the AI runs. Assistant replies also render
  markdown (headings, bold, lists, inline code) instead of showing raw `**`
  and `##` markers. Injection resistance is probabilistic - these defenses
  raise the cost, they are not a proof.

### Fixed

- **Bitwarden sync aborted every healthy run.** The `cancelled` closure in
  `bitwarden_sync` negated its unlocked flag, so an OPEN vault failed every
  sync with "Vault was locked; sync aborted." before any network work -
  the entire two-way sync feature was dead. The closure now uses the same
  `require_generation_current` predicate as every other lock-gated command;
  a regression test pins the gate's contract.

- **Restoring a backup silently dropped each server's Bitwarden linkage.**
  The servers `INSERT` bound 17 values against 14 placeholders, and sqlx's
  non-macro `query()` silently ignores the excess, so `bitwarden_id` /
  revision / updated came back NULL after a restore - and the next sync
  pushed duplicates of every server into the Bitwarden vault. The columns,
  placeholders, `ON CONFLICT` clauses, and binds now match, with a
  round-trip test.

- **A vault lock racing an in-flight SFTP open left a live channel behind.**
  `sftp_open` registered its channel after two awaits without re-checking
  the vault generation, so a lock landing mid-open left an authenticated
  channel in the locked vault's registry, usable again after the next
  unlock. The generation is now captured at entry and re-checked at the
  insert - the same pattern `terminal_connect` and `key_export_to_file`
  already used.

- **Master-password rotation stranded the AI assistant's sealed API key.**
  Every assistant call failed at unseal after a rotation while
  `has_api_key` still reported true. The key now rotates in the same
  transaction as the keys, server passwords, and the Bitwarden credential.

- **Right-click at the prompt pasted the clipboard with no confirmation.**
  xterm keeps its hidden helper textarea positioned on the cursor cell, so
  a right-click at the prompt hit it and pasted via the raw path, bypassing
  the multi-line paste confirmation - and the app's context menu opened on
  the same click, so choosing Paste double-pasted. The handler now routes
  through `terminalPaste` (confirmation and focus restoration) and stops
  the menu from opening on that click.

- **"Restart session" on a live tab doubled every keystroke and lost
  close-detection.** The old poll interval's closure killed the NEW handle,
  both keystroke subscriptions stayed attached, and the old SSH session was
  never disconnected - the tab showed live forever. The previous session is
  now torn down before reconnecting, and the subscription is stored on the
  tab record so teardown can actually dispose it (the cleanup was
  previously dead code - the field was never assigned).

- **The wheel printed `^[[A^[[A^[[B` garbage inside screen/tmux.** xterm
  converts wheel events into arrow keys when the buffer has no scrollback
  - always true in the alternate screen - and a multiplexer passes them to
  the inner program, which echoes them literally. Plain wheel events in
  the alternate screen are now swallowed unless the remote enabled mouse
  reporting (vim, htop, screen's `mousetrack on`), in which case they
  reach the app as real mouse events. Mouse modes are tracked by sniffing
  DECSET/DECRST 1000/1002/1003 in the output stream, with a carry so a
  sequence split across chunks is still recognized.

- **Window resizes and UI-scale changes stole focus into the terminal**
  from modals and inputs. `fitActiveTerminal` no longer focuses;
  maximize uses the new `fitActiveTerminalAndFocus`.

- **"Confirm before deleting a key" and "Check GitHub for new releases"
  had no effect.** The backend returns every setting as a string, so the
  stored `"false"` never matched the strict `!== false` guards (the delete
  confirmation always appeared; the boot update check always ran); the
  delete handler also never mirrored the value into state. A `settingOn()`
  helper normalizes string/boolean/undefined for both.

- **Split mode half-disabled the file browser.** Ten `mode !== 'sftp'`
  gates excluded split - which shows the full panel beside the shell - so
  Ctrl+A, OS file drops, two-pane drag & drop, uploads, compare/sync
  shortcuts, and the transfer-done auto-refresh were dead while navigation
  still worked. A `sftpPanelVisible()` helper now gates all ten sites.

- **Dual-pane state was never re-asserted on render.** A persisted-on pane
  opened invisible (its listing loaded and the status bar counted local
  items - nothing shown) and needed two clicks; queue-driven auto-open
  never lit the button. `applySftpDualChrome()` derives the pane, splitter,
  panel class, and button state from `tab.dualPane` on build, refresh,
  show, and toggle.

- **A batch of smaller renderer fixes from the same audit:** the SFTP
  Bookmarks button never opened its menu (`ev.currentTarget` is null after
  the await; the anchor rect is now captured before it); the local pane's
  Home choice was re-seeded to the remembered default by a falsy guard;
  recursive-search listeners hijacked each other across tabs (now
  per-tab, disposed on completion and session close); compare tints were
  lost on rows mounted by virtualized scrolling; the OS-drag overlay only
  appeared in the first tab ever built; virtualization cached the row
  height forever (jumpy scrollbar after a UI-scale change); the
  context-menu Select all selected only the mounted screenful; four
  swallowed `settings_set` failures now surface; group collapse survived
  no re-render; a session ending in Split mode stranded the tab with a
  dead file browser and no visible way out; the "+" tab button and the
  advertised Ctrl+Shift+1/2/3 shortcuts were dead; vault lock no longer
  leaks orphaned SFTP panel DOM; and the view-switch buttons all lit up
  after clicking Split (a document-wide `.seg-btn` selector that also
  matched the server modal's auth buttons).

- **The webview's own right-click menu (Back/Refresh/Print) appeared
  everywhere.** It is now suppressed app-wide except in text fields, where
  the native editing menu is kept.

- **The keyboard-compatibility settings were persisted but never applied**
  (rxvt Home/End, application cursor keys, application keypad) - they are
  now enforced per-terminal via `attachCustomKeyEventHandler`. Visual
  bell mode likewise was a no-op on the active tab (`bellStyle` was never
  set); it is now applied at creation and live.

- **Pasting from the terminal context menu lost focus** - the next
  keystrokes went nowhere until the terminal was clicked again. Focus is
  now restored after menu actions and after the multi-line paste
  confirmation dialog.

- **The SFTP "Columns" toggle never persisted.** The toolbar button wrote
  `sftpShowOwnerCols` through `settings_set`, but the key was absent from the
  backend's `SETTINGS_KEYS` allowlist, so every write was rejected with
  "Unknown setting" - and the call site swallowed the error. Hiding the
  permissions/owner columns therefore appeared to work and silently reverted on
  the next launch. The key is now allowlisted, and the write reports failures
  instead of discarding them.

- **Saved bandwidth limit and SHA-256 verify toggle reset on every launch.**
  Both rows read their persisted value through an optional
  `sftpSettingCacheGet/Set` pair on `window` that nothing ever defined, so the
  calls fell through to the default while the backend kept enforcing the real
  stored value. They now read `state.settings` like every other row.

- **Download-rename and Resume in the transfer conflict dialog were disabled
  with "needs the next backend update".** The backend has supported both for
  some time: the queue's download and upload legs already honor `ResumeMode`,
  and the renderer was already sending `localName` / per-item `resume` that the
  backend ignored. Both are now honored - `expand_download` applies a
  renderer-supplied `localName` through the same containment check as the
  derived basename, and `sftp_queue_add` reads a per-item `resume` so one batch
  can mix overwrite/skip/resume decisions. The stale UI disables are removed.

### Added

- **AI assistant backend.** Seven Tauri
  commands in the new `assistant` module: provider configuration for
  OpenAI-compatible or Anthropic-compatible servers (API key sealed with
  the vault master password, never returned over IPC, rotatable with it,
  and clearable on demand); a connection test with actionable errors; a
  non-streaming chat proxy that maps a normalized message/tool contract
  onto each provider's wire format; and per-tab access levels
  (read/draft/execute/yolo) held in memory only - cleared on vault lock,
  never persisted, so YOLO cannot survive a restart - with `assistant_exec`
  re-checking the level server-side before writing to the SSH channel and
  audit-logging every execution. 12 unit tests cover the wire shaping and
  response parsing for both providers, the level gate, and the sealed-key
  round-trip. The chat panel below is its frontend: the renderer owns the
  conversation, the five tools, and the agent loop; the backend stays a
  non-streaming proxy and the policy gate.

- **AI assistant (optional, off by default).** A chat panel docked beside the
  terminal (`Ctrl+Shift+A`) that talks to OpenAI-compatible or Anthropic-compatible
  providers - OpenAI, OpenRouter, Groq, Anthropic, or a local server such as
  Ollama / LM Studio - configured under Settings -> AI assistant. The assistant
  can read the live terminal, answer questions, and propose or run shell
  commands against the session. What it may do is a per-tab access level chosen
  on a color-coded control at the top of the panel: **Read** (advise only,
  commands arrive as cards you insert or run yourself), **Draft** (may type
  into your prompt, never presses Enter), **Execute** (runs commands behind a
  per-command Approve/Deny card), and **YOLO** (no confirmations, behind a
  deliberately scary opt-in dialog and a persistent red badge). The API key is
  sealed with the vault master password like every other stored secret, all
  provider traffic goes through the Rust backend (the page never fetches
  provider URLs), every AI-executed command is recorded in the audit log, and
  the backend independently re-checks the access level before a command reaches
  the SSH channel.

- **Local-pane file management.** The dual-pane local side could browse and
  upload but not manage: there was no local rename, delete, mkdir, or
  open-folder command at all, so a right-click there offered four entries
  against the remote pane's ten. Four new commands
  (`sftp_local_mkdir` / `sftp_local_rename` / `sftp_local_remove` /
  `sftp_local_open_folder`) are gated on an unlocked vault and on the same
  app-data and system-directory rules the transfer paths use, with every
  destructive action confirming first. The local menu now offers Rename, Delete,
  Open containing folder, and New folder.

- **Ctrl+A follows the pane you last clicked.** The select-all shortcut only
  ever touched the remote selection; with the local pane open it now selects in
  whichever pane was last clicked.

- **Audit log: export, clear, and a retention cap.** The table grew without
  bound while the UI could only ever display the newest 200 rows, so the oldest
  history was both invisible and unreclaimable. Inserts now trim to the newest
  10,000 entries, the panel reports the true total rather than implying the
  visible page is everything, "Export as CSV..." writes the full retained set
  through a native save dialog, and "Clear log" empties it behind a
  confirmation (recording the clear itself, so an emptied log still shows it was
  emptied).

- **`sftpResumeDefault` is reachable from Settings.** The backend has always
  read this key as the fallback for transfers that never reach the conflict
  dialog, but no UI could set it, leaving it pinned at "ask".

### Changed

- **Four settings that nothing read were removed from the allowlist.**
  `theme`, `sshKeysDir`, and `sshConfigPath` had no reader anywhere (the real
  paths are derived at runtime by `system_paths`), and
  `terminalKeepaliveSeconds` became inert when keepalives moved to the SSH
  protocol layer. All four were accepted, persisted, and copied into every
  backup while doing nothing. Backups carrying them are now filtered on restore
  against the same allowlist `settings_set` enforces.

- **Vault backups carry the full settings set.** `vault_backup_create` wrote a
  hand-maintained list of six keys, three of them the dead ones above; it now
  shares one collector with `settings_get`, so the two cannot disagree.

- **Importing a host from `~/.ssh/config` warns about directives that are
  ignored.** `ProxyJump`, `ProxyCommand`, and `ForwardAgent` are parsed and
  preserved on write but are not honored when connecting, so a user importing a
  bastion-hosted entry could believe they were connecting through it.

- **Closing the window now hides to the tray instead of exiting.** The app has
  always shipped a tray offering Show and Quit, but the X button killed the
  process and the tray with it. Quit (tray menu) is now the only exit, which is
  what the tray implied.

## [1.8.0] - 2026-09-14

A UX pass over the whole renderer, plus the Send-to scan fix and the rustls
advisory bump that landed after 1.7.3 was tagged.

### Changed

- **Navigation is two objects plus Settings.** Keys and Servers are the
  destinations. Deploy was a fifth nav item whose own copy read "Select keys to
  deploy using the checkboxes in the Keys view" - an instruction to go and
  operate a different view, which is what a task split at the wrong seam looks
  like. Selecting keys now raises an action bar in the list, and Deploy opens a
  sheet over it with that selection already loaded. The audit log moved into
  Settings. `switchView` no longer takes `config` or `audit`; Ctrl+3 is
  Settings and Ctrl+4/Ctrl+5 are gone.

- **The vault control absorbed the two topbar buttons.** "Change password" and
  "Lock" occupied the top-right of every view, including the audit log. Both
  now hang off the vault chip at the bottom of the sidebar, which also shows the
  auto-lock countdown - auto-lock was a setting with no feedback at all, so the
  vault could seal mid-task with no warning it was coming. The freed topbar
  space holds the Ctrl+K entry point.

- **One category filter surface.** The sidebar tree, an "All categories"
  toolbar button and a modal picker all filtered or assigned the same thing. The
  tree filters (and now hides itself outside Keys and Servers); chips assign,
  via a "+ Add" chip where the old "Browse categories..." button used to sit
  below them.

- **Key rows lead with the comment.** The row's second line was the full
  SHA-256 fingerprint - 50-odd undifferentiated base64 characters, on every row,
  in the one position a list is scanned by. The fingerprint moved to the detail
  pane, which is where it gets compared. Rows gained a Deployed chip and a
  Connect button; connecting with a key was previously reachable only by
  right-clicking, with nothing on screen saying so.

- **Export has its own tab.** It sat at the same visual weight as "Copy public
  key", with a passphrase box permanently on screen including for the four
  formats that ignore it and the two that carry no private key. Each format is
  now marked Secret, Sealed or Public, the passphrase field appears only for the
  format that uses one, and leaving the tab clears anything typed into it.

- **Sessions show Shell, Files or Split.** The old control was a single button
  labelled with the mode you would switch to, so it read "SFTP" while you were
  looking at the shell. It is a three-way control labelled with the surface you
  are on, and Split shows the terminal and the file browser at once.

- **The remote path is a breadcrumb.** It was a bare text field, so going up two
  directories meant editing a string. Segments are clickable; clicking the strip
  hands back the editable field.

- **Server rows carry their own state.** A live-session dot and a Connect button
  (Enter works too). Connecting used to be a double-click with no affordance,
  and whether a host already had a session open was visible only in the tab
  strip.

- **Settings is sectioned.** A section rail replaces one 760px-wide scroll,
  rows are two-column with a line saying what each setting costs you, and every
  toggle is the same component - Settings rendered raw browser checkboxes while
  the deploy options one screen away used the styled toggle.

### Added

- **Ctrl+K command palette.** One search across keys, servers and categories,
  plus actions that previously had no keyboard path at all (deploy the
  selection, open the audit log, lock, new key, new server). Enter opens,
  Ctrl+Enter connects in a new tab.

### Fixed

- **The key search box did nothing in the default grouped view.** `renderKeyList`
  filtered into `rows` and then walked `state.keys` anyway, so a query only ever
  had an all-or-nothing effect through the `rows.length === 0` bail. Typing a
  term that matched one key still listed the whole vault.

- **The Send-to folder scan no longer fails on a large, slow tree.** The
  server-to-server scan wrapped its whole recursive walk in a flat 120s
  timeout, so a big tree on a slow-but-advancing source blew the ceiling and
  returned "Folder scan timed out" - while the transfers it had already
  streamed into the queue kept running, making the error both fatal-looking
  and wrong. The bound is now progress-aware: the scan continues as long as
  new files keep being enqueued, and only a genuine stall (no progress for
  60s) aborts it, with an error that says so. (#73)

- **The deploy preview printed a literal `\n`.** `previewConfig` joined its
  lines on `'\\n'` - an escaped backslash - so the generated config rendered as
  one unreadable line. `deployConfig`, a few lines below, always used a real
  newline. The preview is also live now; it used to stay empty until you pressed
  a Preview button, making the first answer to "what will this write?" nothing.

### Security

- **rustls 0.23.43 -> 0.23.45 (RUSTSEC-2026-0285).** TLS 1.3 handshake messages
  were incorrectly accepted across encryption-level boundaries (medium).
  Upgraded to the patched release. (#73)

## [1.7.3] - 2026-09-14

### Security

- **Executable staging bypass closed (renderer-to-native escalation).** The
  "open staged file" command (`system_open_external`) verified only that the
  file lived inside the SSHSpan staging directory and was a regular file - it
  did not check the extension. A compromised renderer could stage remote bytes
  into `<staging>/x.exe` via `sftp_stage_path` + `sftp_download` and have the
  Windows shell execute them through this command. The opener now enforces the
  same inert editor/viewer extension allowlist the edit flow uses, at launch
  time, and refuses everything else before any OS call. Regression test added.

- **A vault lock now revokes in-progress operations, not just live sessions.**
  Previously, clearing the in-memory password store did not cancel work that
  had already copied it: an SSH connection that crossed the lock event could
  still authenticate and register a live session into the "locked" vault, and
  a long-running export or Bitwarden sync kept going. A new monotonic vault
  generation is captured before any network await; `start_interactive`
  re-checks it before registering (aborting by dropping the connection),
  `terminal_send` refuses while locked, `key_export_to_file` re-checks after
  the save dialog closes, and `bitwarden_sync` is cancelled mid-run by a
  generation-backed predicate polled at every push/pull. The lock bumps the
  generation FIRST, before any teardown.

- **Master-password rotation is now atomic and covers the Bitwarden
  credential.** Rotation previously issued separate pool-backed UPDATEs per
  record followed by a separate verifier write, with no encompassing
  transaction - an I/O error or crash part-way left some records sealed under
  the new password and the rest (plus the verifier) under the old, a vault
  that unlocks but cannot decrypt half its contents. It also never re-sealed
  the stored Bitwarden master password, silently stranding sync on the old
  password. All re-sealed records, the Bitwarden credential, and the verifier
  now commit in a single SQLite transaction (`apply_vault_rotation`): the
  database holds either the complete old state or the complete new state.
  Rollback and Bitwarden-re-seal regression tests added.

- **Download resume no longer follows a planted `.part` symlink.** The resume
  path used `metadata()` (which follows symlinks) to read the partial length,
  then opened with plain append mode: an attacker who could plant
  `dest/name.part -> victim` in a writable download folder would have remote
  bytes appended to the victim (the final rename then moved the link). Resume
  now lstat-checks the `.part` is a real regular file and opens it with
  `O_NOFOLLOW` (Unix), re-aligning the offset against the exact object opened;
  anything else starts the download over.

- **Recursive uploads re-check every descendant against the protected-path
  rule.** The app-data/system guard was applied only to the user-selected
  root; descendants were enqueued/uploaded without re-checking, so an allowed
  ancestor containing app data (or a symlink to it) would upload the vault
  database. Every expanded file - and symlink target - now re-passes the
  source authorization check in both the queued (`expand_upload`) and direct
  (`upload_directory`) paths.

- **Backup restore no longer trusts machine-local deployment paths.** A backup
  carries `deployed`/`deploy_path` verbatim; authenticated encryption of the
  backup does not make those local paths trustworthy, and `key_remove_deployed`
  would then delete the stored path (and its `.pub` sibling) anywhere the user
  could write. Restore now discards deployment state (and preserves an
  existing local deployment on re-import); `key_remove_deployed` additionally
  refuses to delete outside the managed `~/.ssh` directory and now requires an
  unlocked vault. Regression test added.

- **The updater resolves the release signature from the correct URL and binds
  the version to the asset.** The `.minisig` sibling was built by appending
  the suffix to the FINAL post-redirect CDN URL - GitHub serves the installer
  and its signature as separate release assets (each redirecting to its own
  signed object URL), so the suffix landed on the wrong object and mangled the
  signed query, breaking signed-update retrieval. The signature is now
  resolved from the original repo-pinned release URL. The claimed version is
  also bound to the release tag in the asset URL, so a compromised renderer
  cannot pair a future version number with an older (still signed) asset to
  force a silent downgrade.

- **Bitwarden Argon2id derivation now matches the official client.** The
  Argon2 salt was the raw normalized email; the official Bitwarden SDK first
  hashes the email with SHA-256 and uses that digest as the salt, so identical
  credentials produced different master keys and an Argon2-configured account
  could never authenticate. The salt is now `SHA-256(normalized email)`; the
  official SDK test vector is baked in as a regression test. (PBKDF2 accounts
  are unaffected - that path already used the raw email correctly.)

- **Tray "Lock Vault" now enforces the lock in the backend.** The tray handler
  previously only emitted `vault-lock-requested` to the renderer, which a hung
  or compromised webview could ignore; it now calls the backend teardown
  directly (kill sessions, stop watches, clear the password, bump the
  generation) and only then notifies the renderer.

- **Secret wiping extended.** Command-level Bitwarden master passwords
  (save/test/sync) and the serialized private-key export text are now wrapped
  in `Zeroizing` and wiped on drop, instead of living as freed heap.

- **Security documentation corrected.** `SECURITY.md` no longer overstates
  guarantees: the private-key file import path reads the file in the renderer
  (private text transits IPC/renderer memory), the password-rotation
  description matches the new atomic behavior, and the network summary now
  includes the user-initiated SSH/SFTP flows alongside the update check and
  Bitwarden sync.

### Added

- **SFTP transfer queue: pause/resume, auto-retry, throttle, persistence, and
  integrity verification.** Transfers can be paused and resumed (a paused job
  keeps its `.part` and continues rather than restarting), failed transfers
  auto-retry with a countdown and a retryable/terminal error classifier,
  total throughput can be rate-limited across all workers, unfinished
  transfers survive a restart (restored as paused), and completed transfers
  can be verified against a remote SHA-256 digest.
- **Richer remote listings and operations.** Symlink flags and target
  resolution, mode/uid/gid columns, a remote "Calculate size" action,
  on-demand remote file digest, and an in-app delete confirmation with
  visible delete feedback. The queue panel groups transfers by server and
  remote folder.
- **File-explorer usability.** Quick-find in panes, a working Columns toggle,
  a local-pane context menu, and stale listings are dropped after remote
  mutations.

### Fixed

- **Renderer stability.** Two globals in `terminal.js` were shadowing `app.js`
  functions; the category filter never applied (a duplicate `filteredKeys`);
  categorized keys were invisible in the default "all categories" view; the
  SFTP panel hit a `ReferenceError`; the queue refused an unrecognised
  transfer direction instead of silently defaulting to download; a call to a
  never-written function was removed.
- **Keys / Connect UX.** The connect picker no longer jumps away to Connect
  and follows the host category tree; the local pane context menu and Columns
  button now work.
- **UI safety and accessibility.** Destructive-prompt safety, modal focus
  handling, toast stacking, and the category picker no longer opens behind the
  host modal. User-reported 1.7.2 issues fixed: vault entry, backup freeze,
  AppImage launch, and UI scale.
- **CI / renderer tests.** The renderer test drives the real page in CI
  (not just parsing it), the SFTP local-list stub uses a neutral home path,
  and the Rust toolchain is pinned via the toolchain action input
  (dropping `rust-toolchain.toml`).

### Security (prior round, 2026-09-13/14 reviews)

- **Fixed a Windows path-guard bypass that allowed writing into (or reading
  from) the application data directory.** `std::fs::canonicalize` returns
  `\\?\`-prefixed paths on Windows, and `Path::starts_with` compares prefix
  components exactly, so a canonicalized target NEVER matched the plain
  `C:\Users\...\SSHSpan` app-data prefix - the guard fired only for paths that
  did not exist yet and passed exactly the targets whose parent directory
  existed (i.e. the cases where a write succeeds). A crafted SFTP download
  could overwrite the vault database, and an upload could read it. All
  local-target guards (`validate_sftp_local_path`, `validate_export_path`,
  `is_system_path`) now normalize with `dunce::canonicalize` (no verbatim
  prefix), compare case-insensitively (NTFS ignores case), and probe both
  the target and its parent. Regression tests cover the existing-file and
  lowercase-variant shapes.

- **Queued SFTP transfers now apply the same path gate as single-file
  transfers.** `sftp_queue_add` validated neither the renderer-supplied
  `dest_dir` (downloads) nor the upload sources - the single-file
  `sftp_download`/`sftp_upload` commands validated, the batch path skipped
  the check. Both now run `validate_sftp_local_path` before any filesystem
  work.

- **Host-key trust is now decided by the backend, not the renderer.** The
  `allow_tofu` boolean previously traveled over IPC: a compromised renderer
  could mint consent for an unpinned host. The trust prompt is now a native
  OS dialog raised inside the SSH handshake handler, showing the fingerprint
  BEFORE the decision; the renderer has no consent flag to forge. The
  `known_hosts_check` command was removed (dead surface).

- **Host-key pins imported from backups are untrusted until re-confirmed.**
  A crafted backup could previously plant pins for hosts the user never
  contacted, silently matching a MITM on first connect. Restored pins for
  previously-unknown hosts are now marked `imported` and require the user to
  confirm the fingerprint once on first use (then upgraded to a confirmed
  pin); a differing key for any stored anchor still hard-fails. The restore
  result reports `knownHostsImported`, and the dead `knownHostsReplaced`
  audit path was removed.

- **Bitwarden KDF parameters are clamped at both ends, per algorithm.**
  Server-supplied `kdfIterations`/`kdfMemory`/`kdfParallelism` previously
  had floors only; a hostile vault server could request an absurd work
  factor and burn CPU/RAM locally (the cost is paid during derivation,
  which no HTTP timeout covers). PBKDF2 iterations are clamped to
  [600k, 10M]; Argon2id to [2, 16] passes, [16 MiB, 1 GiB] memory,
  [1, 16] lanes; unknown KDF types are refused instead of guessed. The same
  clamps are re-applied at the crypto boundary.

- **Backend-enforced idle auto-lock.** `autoLockMinutes` was previously
  honored only by a renderer timer; a hung or crashed webview could leave
  the vault unsealed indefinitely. The renderer now heartbeats
  (`heartbeat` IPC) and a backend watchdog locks the vault - killing
  sessions, SFTP edits, and keepalives - when no heartbeat arrives for the
  configured interval.

- **Private-key export on Windows fails closed on ACL restriction failure.**
  The export previously warned and left the key with inherited (broad)
  permissions; it now deletes the written file and returns an error.

- **Updater fast-forward bound.** Release metadata is unsigned (only the
  installer bytes are), so version *numbers* are attacker-malleable on the
  network. `is_newer` now refuses implausibly large version jumps
  (> 1 major or > 12 minors ahead), defeating freeze attacks that replay an
  old signed asset under a huge version number. The `installer_ext`
  helper also matches `.msi` by exact suffix now.

- **Terminal hygiene.** The SFTP/terminal keepalive no longer writes a NUL
  byte into the PTY data channel (interactive programs received it as
  Ctrl-@); keepalives are SSH-protocol-level (russh, every 30 s) and the
  per-second renderer ping was removed. App-composed terminal banners now
  strip control characters from server-derived hostnames/usernames/server
  names so the app can never originate an injected ANSI escape sequence.

- **DialogPathStore grants expire.** A path approved in a save dialog is
  writable via `system_write_text_file` for 15 minutes instead of for the
  rest of the session.

### Removed

- Registered-but-unused Tauri plugins `sql`, `os`, `process`, `notification`,
  `opener`, and `updater` (and their capability grants) - dead IPC surface.
  The app uses the standalone `opener` crate for shell integration and its
  own minisign updater.

## [1.7.2] - 2026-09-12

### Security

- **Updater installers are now verified with embedded-key minisign signatures
  (enforced since key provisioning on 2026-09-12).** The updater previously
  verified the downloaded installer against the SHA-256 digest from the GitHub
  releases API - but the digest travels in the same API response as the
  download URL, so anyone able to alter the release (repository compromise,
  token theft) could replace the installer *and* its digest together. The
  release workflow signs every installer with
  [minisign](https://jedisct1.github.io/minisign/) and uploads the resulting
  `.minisig` files as release assets; `update_download_and_run` downloads the
  `.minisig` sibling through the same host-allowlist / redirect-revalidation /
  size-cap discipline as the installer and verifies it against a public key
  embedded in the app (key id `D67C45BA942239D8`, provisioned 2026-09-12).
  Verification is fail-closed: a missing, unparseable, or invalid signature
  deletes the downloaded installer and refuses to run it. Releases published
  before provisioning carry no `.minisig` and cannot serve as auto-update
  sources for provisioned builds. **This is the first signed release.**

- **Updater URL pinning.** The initial installer URL is pinned to
  `github.com/AGSQ11/SSHSpan/releases/download/...` - the previous host-only
  allowlist admitted any public GitHub repository as an update source - and
  the renderer-supplied version is sanitized before temp-filename
  interpolation.

- **Host-key trust is now a user decision.** Connecting to a host with no
  stored pin asks for explicit confirmation; the backend refuses unpinned
  hosts without it (StrictHostKeyChecking=yes equivalent) and records refused
  attempts in the audit log. Pins are scoped to `host:port`.

- **Private-key export no longer passes through the renderer.** Private
  formats are serialized by the backend straight into a user-chosen file
  (0600 from the first byte on Unix); `key_export` serves public material
  only. All exports are audited.

- **Post-XSS blast-radius reduction.** `system_write_text_file` only writes
  paths approved in a native save dialog; `system_open_external` only opens
  files from SSHSpan's staging dir; SFTP local paths also refuse system
  directories; the `SSHSPAN_DB` override is debug-build-only; per-command
  vault-password copies are zeroized.

- **Brute-force backoff.** Master-password verification (unlock and
  change-password) backs off after 5 consecutive failures (30 s doubling,
  15 min cap); legacy plaintext verifiers are compared in constant time and
  upgrade to Argon2id on first unlock.

- **SFTP staging and transfer hardening.** Staged-file names use an
  inert-extension allowlist (every unknown or binary extension stages as
  `.txt`); the staging dir refuses symlink pre-plants (random fallback);
  remote names are sanitized against traversal, drive letters, UNC and
  Windows device names before any local join; queued downloads are anchored
  under the canonical destination; the plain upload walk is symlink-cycle-safe.

- **SSH auth hardening.** RSA client-auth signatures are pinned to
  `rsa-sha2-256` (no legacy SHA-1 fallback); keyboard-interactive
  authentication answers one round of server prompts only; SSH auth secrets
  are zeroized in memory and the vault clears with sessions killed on exit.

- **Deploy and restore integrity.** Deployed private keys are written 0600
  from the first byte (Unix) and Windows ACL-restriction failures fail the
  deploy; backup restore excludes blobs that cannot be re-encrypted under the
  current password (no stranded keys) and surfaces known-host pin conflicts.

- **Bitwarden hardening.** HTTPS-only server URLs (loopback exempt), KDF
  floors (PBKDF2 ≥ 600k, Argon2id ≥ 16 MiB / t ≥ 2), confirm-first sync for
  remote overwrites, no-redirect policy, connect-time DNS-rebind filtering,
  and `known_hosts` restore protection.

- **CI/supply chain.** Third-party GitHub Actions are pinned to commit SHAs;
  unused Tauri plugin grants were removed; `PRIVACY.md`/`SECURITY.md` were
  rewritten against the actual implementation.

### Added

- **SFTP FileZilla-parity feature set:** resumable transfers with atomic
  `.part` staging; transfer-conflict dialog (Ask/Overwrite/Skip/Rename/Resume
  per direction, persistable defaults); directory comparison and
  synchronized browsing in dual-pane mode; two-pane drag & drop; timestamp
  preservation via setstat; UI density pass (editable path bars, pane
  headers, drop overlay, status bar, transfer queue table).

### Fixed

- **Send-to (server-to-server copy):** folders expand into per-file jobs with
  target parent-directory creation; the folder walk no longer follows
  symlinks, guards cycles, caps at 10k files and 120 s, and streams jobs so
  transfers start during the scan; fully-written `.part` uploads tolerate
  servers that fail CLOSE, with staged-size verification before the final
  rename; 256 KiB chunks and higher default parallelism fix latency-bound
  small-file throughput; recursive remote folder delete is resilient against
  unreadable children.
- **Transfer progress bar:** finished Send-to rows now fill to 100% (completed
  bytes were normalized to half the two-leg total), and single-file Send-to
  jobs get a real progress denominator.

## [1.7.1] - 2026-09-09

Security and stability patch release. A comprehensive review of the codebase
uncovered and resolved a critical key-export defect, several data-loss and
server-side request forgery (SSRF) risks, an unverified auto-update path, and a
cross-site scripting (XSS) vector, alongside a set of robustness fixes. **All
users are encouraged to update**, particularly anyone who exports private keys
or syncs with Bitwarden.

### Security

- **Critical: encrypted PKCS#8 export rewritten to real PBES2.** Exporting a
  private key in "PKCS#8 (encrypted)" form previously produced a file that
  (a) could never be decrypted back - the encryption salt was never written
  into the output, (b) derived the cipher IV from the same value as the
  encryption key, and (c) printed that IV in cleartext in the file header,
  disclosing half of the AES key and enabling fast offline passphrase
  guessing. The output was also a legacy OpenSSL PEM body mislabeled as
  PKCS#8, which standard tools refused to read. The exporter now emits a
  standards-compliant RFC 8018 PBES2 `EncryptedPrivateKeyInfo`: a fresh random
  salt and an independent random IV, both embedded in the file, with the key
  derived via PBKDF2-HMAC-SHA256 (100,000 rounds). Exports now decrypt
  correctly in OpenSSL, PuTTYgen, and other PBES2-aware tools, and no longer
  leak key material.
- **Bitwarden sync can no longer silently destroy keys or server passwords.**
  On an encryption (seal) failure during sync, the app previously wrote an
  *empty* value in place of a private key - and in the update path could
  overwrite a previously-good stored key - while reporting success. A
  decryption (unseal) failure during push could likewise send the encrypted
  blob to the server as if it were the key. Sync now skips or fails the
  affected item with a clear, logged error instead of writing placeholder or
  ciphertext data. The same protection now covers saved server passwords.
- **Closed a DNS-rebinding gap in the SSRF guard.** The Bitwarden server-URL
  check validated the host's IP address at configuration time, but the
  connection re-resolved DNS afterwards, so a hostile DNS answer could swap a
  safe address for an internal one at connect time. DNS resolution is now
  filtered again at connect time through a custom resolver, so a rebound
  private/link-local address can never be dialed.
- **Auto-update downloads are now verified and bounded.** The updater
  previously downloaded the installer into memory with no size limit, no
  integrity check, and followed redirects without re-validating the
  destination. It now streams the download to disk with a hard size cap,
  verifies the file's SHA-256 against the digest published with the GitHub
  release (refusing to run it on any mismatch), re-validates the host allow
  list on any redirect, rejects non-HTTPS URLs, and writes to a uniquely-named,
  exclusively-created temporary file. The release-manifest request is size
  capped as well, and the download host allow list no longer accepts
  look-alike domains.
- **Fixed cross-site scripting via `~/.ssh/config`.** A Host name from the
  user's SSH config was inserted into the import menu's HTML without escaping,
  so a malicious Host line could inject markup into the app window. The value
  is now escaped like the other fields.

### Fixed

- **Updater no longer offers the version you are already running.** The
  running version is now read from the packaged app metadata rather than a
  stale value, and the version comparison is more robust.
- **Database no longer panics on malformed timestamps.** Rows with an
  unparseable RFC3339 timestamp now fall back to the current time instead of
  crashing (five sites in keys, categories, and the audit log).
- **Changing the master password now re-encrypts saved server passwords.**
  Previously these were left encrypted under the old password and became
  unreadable after a password change (data loss). The master password is also
  scrubbed from memory on use.
- **PPK import hardened against denial of service.** PuTTY-PPK Argon2
  parameters (memory, passes, parallelism, salt length) are now bounded before
  allocation, so a crafted key file cannot force an out-of-memory abort.
- **Bitwarden HTTP layer hardened.** Redirects are no longer followed
  (a redirect could previously leak credentials to an internal host), response
  bodies are size capped, and a refresh token is only consumed after a
  successful request.
- **SFTP downloads no longer fail against strict servers.** Some SFTP servers
  answer a read that crosses end-of-file with a failure status instead of a
  short read; downloads now read only up to the known file size, so "Send to"
  and queued transfers succeed. Error messages for server-side failures are
  now clear instead of a doubled "Failure: Failure".
- **SFTP edit staging hardened.** Temporary copies of edited remote files are
  created with owner-only permissions and unpredictable names, and are cleaned
  up when the session closes, when the vault locks, or after 24 hours.
  (Correction 2026-10-17: "owner-only" is the staging folder's mode 0700 on
  Unix. On Windows the copies get no permissions of their own: they take those
  of the per-user temp folder, which by default gives access to the user,
  SYSTEM and Administrators.)

### Changed

- **Bitwarden client credentials are zeroed from memory on use.** The client
  master key, stretched key, user key, and access/refresh tokens are now wiped
  when the client is closed or dropped, matching how the vault master password
  is already handled.

### Verification

- Rust formatting, compilation, and the full test suite passed on the merged
  release state: 69 unit tests and 43 integration tests, including new
  coverage for the PBES2 export round-trip, sync error handling, the SSRF
  resolver, updater verification, and SFTP staging.
- The encrypted PKCS#8 export was additionally verified end-to-end by
  decrypting it with OpenSSL.
- Renderer syntax checks passed for the updated JavaScript.

## [1.7.0] - 2026-09-08

Feature release focused on PuTTY-grade terminal behavior and safer everyday SSH use.

### Added

- **Terminal context menu** - right-click inside the terminal or on a session tab to Copy, Copy All, Paste, Clear scrollback, Reset terminal, open a New session, Duplicate the current session, Restart the session, or switch between SSH and SFTP.
- **Copy All to Clipboard** - copies the active terminal buffer plus scrollback without manual selection.
- **Multi-line paste confirmation** - clipboard content containing line breaks asks before being sent to a live SSH session. The confirmation can be disabled in Settings.
- **Duplicate and restart sessions** - duplicate opens a new independent tab for the same saved server/auth; restart reconnects in the same tab while preserving tab identity and scrollback.
- **Configurable scrollback** - terminal scrollback can be set between 1,000 and 50,000 lines.
- **Terminal bell behavior** - choose visual, sound, or silent bell; background tabs receive a visible bell indicator.
- **Keyboard compatibility settings** - Backspace mode (`0x7f` or `0x08`), Home/End mode, application cursor-key mode, and application keypad mode are persisted for future terminal keymap compatibility.
- **SSH keepalive** - optional per-terminal keepalive interval (disabled by default), independent of SFTP keepalive.
- **Normal remote Tab completion** - interactive SSH now declares UTF-8 input and explicitly requests `TERM=xterm-256color`, allowing remote Bash/Zsh/Fish/readline completion to behave like PuTTY and normal terminals.

### Changed

- The README now documents the new terminal context menu, clipboard behavior, session utilities, settings, keepalive, and current release artifacts.

### Compatibility and safety

- Clipboard completion remains remote-shell-driven; SSHSpan does not fake local completion.
- Multi-line paste confirmation helps prevent clipboard-carried commands from running accidentally.
- Existing independent SSH/SFTP tab behavior from PR #14 is preserved.
- Alt-Enter fullscreen was intentionally excluded per request.

### Verification

- Rust formatting, compilation, and the full test suite passed: 4 unit tests and 42 integration tests.
- Renderer syntax checks passed for `app.js`, `terminal.js`, and `sftp.js`.
- Changes delivered in PR #17 and PR #18.

## [1.6.0] - 2026-09-08

Feature release focused on category organization and everyday picker usability.

### Added

- **Separate key and host categories** - categories now have an explicit `key` or `host` scope. The Keys view shows only key categories; the Hosts/Connect view shows only host categories, with independent filters and uncategorized counts.
- **Host category filtering** - saved servers can be filtered recursively through their host-category tree, including an explicit uncategorized-hosts entry.
- **Scope-safe assignments** - keys can only use key categories, servers can only use host categories, and category parents must stay within the same scope.
- **Scoped backup and restore** - category scope is preserved in vault backups. Older backups without scope continue to restore as key categories, while invalid cross-scope assignments are ignored safely.
- **Bitwarden host-category namespace** - server category paths are exported with a `Hosts-` prefix, such as `Hosts-Production/Web`, and the prefix is removed on import so host categories remain separate from key categories.
- **Compact category picker** - the picker now uses a bounded layout with a fixed search area, scrollable results, selected chips, remove/clear actions, empty states, and keyboard navigation.
- **Accessible picker interactions** - category selection now exposes combobox/listbox semantics, active-row navigation, `aria-selected` state, Escape dismissal, and focus restoration.

### Compatibility and safety

- Existing categories remain key categories during migration.
- Existing server references to old shared categories are cleared rather than silently reusing key categories as host categories.
- Legacy unprefixed Bitwarden server metadata is imported as host-scoped category data.

### Verification

- Rust formatting, compilation, and the full test suite passed: 4 unit tests and 42 integration tests.
- Renderer syntax checks passed for `app.js` and `sftp.js`.
- Changes delivered in PR #11 and PR #12.

## [1.5.0] - 2026-09-07

Feature release bringing the SFTP client to FileZilla parity: a background
transfer queue, dual-pane browsing, remote file permissions, recursive search,
per-server bookmarks, multi-select, and more.

### Added

- **Background transfer queue** - uploads and downloads run on dedicated SFTP
  channels over the live SSH connection, so browsing stays responsive during
  transfers. Queued/Failed/Done tabs with per-job progress bars, transfer
  speed, cancel and retry, aggregate status, and clear-finished. Two transfers
  run in parallel by default; configurable 1-4 in Settings. Double-clicking a
  remote file enqueues a download to the last-used directory; "Download as..."
  keeps the save dialog. Directory transfers expand recursively in both
  directions.
- **File permissions (chmod)** - dialog with an owner/group/other read/write/
  execute grid, live two-way octal sync, recursion, and files/directories/all
  targeting. Prefilled from the server's current mode.
- **Recursive remote search** - inline search bar over the current directory
  tree (case-insensitive, 500-result cap, depth-limited); results stream in
  live and clicking one navigates to its folder.
- **Per-server bookmarks** - save the current remote (and local) directory as
  a named bookmark via the toolbar star; one click navigates; right-click
  removes.
- **Dual-pane mode** - optional local pane alongside the remote listing with
  a draggable splitter. Drag a local file onto the remote pane (or
  double-click it) to enqueue an upload; double-click local folders to
  navigate. OS drag-and-drop onto the remote pane continues to upload.
- **Multi-select** - Ctrl-click, Shift-click ranges, Ctrl+A, and empty-area
  click to clear. Context-menu actions (download, delete, chmod) apply to the
  whole selection with batch-aware labels and a single confirmation.
- **Sortable columns** - Name/Size/Modified headers with ascending/descending
  indicators; directories always group first.
- **New file** - create an empty remote file from the context menu (refuses
  to overwrite an existing path).
- **Remote disk usage** - free/total space via `statvfs@openssh.com` shown
  beside the path bar; hidden automatically when the server lacks support.
- **Per-tab activity log** - timestamped connect/transfer/chmod/search/delete
  events, 200-line cap, failures mirrored into it.
- **SFTP keep-alive** - a 30-second round-trip keeps idle sessions alive
  through NATs and firewalls; stopped automatically on close, disconnect, or
  vault lock.
- **Settings** - parallel transfer count (1-4), show-hidden-files default,
  and the dual-pane preference persists across sessions.
- Context menu: Copy path, Copy `sftp://` URL, Select all, Download as....

### Fixed

- Remote entries whose names start with a dot are hidden by default.

### Maintenance

- dev-sshd test fixture now implements `stat`/`lstat`/`setstat`, making
  chmod, the new-file guard, and queue download expansion testable
  end-to-end.
- Verified by a 23-check CDP e2e suite against the live fixture (queue
  progress events, chmod round-trip, search, bookmarks, multi-select,
  hidden-file and sort behavior, dual-pane listing, settings round-trip)
  plus the full Rust test suite.


## [1.4.2] - 2026-09-07

### Fixed

- SFTP downloads now explicitly close and await remote handles before reporting success.
- SFTP uploads now explicitly close and await remote handles, surfacing local-open, remote-open, transfer, and close failures.
- Dragging a local folder into the SFTP browser now recursively creates the remote directory tree and uploads nested files.
- SFTP rows behave like file-manager entries: selectable, keyboard-focusable, double-clickable, and context-menu accessible.


## [1.4.1] - 2026-09-07

Patch release focused on closing audited feature gaps and making the release/development workflow truthful.

### Fixed

- Wired the Connect **Test** button to the existing server connectivity IPC and surfaced latency/errors.
- Passed the selected ECDSA curve through key generation (`p256`, `p384`, or `p521`).
- Made Deploy Preview represent the selected keys and current Host/User/Port/options instead of displaying the existing SSH config.
- Wired deploy-key passphrase encryption and `StrictHostKeyChecking` into deployment/config generation.
- Added missing renderer icons used by Connect and server controls.
- Prevented category selections from being cleared by an unrelated modal backdrop handler.
- Made master-password changes fail safely when a sealed key cannot be re-encrypted instead of silently leaving mixed-password vault data.
- Fixed root-category deletion so child categories are correctly reparented.
- Corrected the IPv4 tail parsing in IPv4-mapped IPv6 SSRF validation.

### Maintenance

- Replaced stale Electron-era contributor documentation with current Tauri/Rust instructions.
- Synchronized npm lockfile metadata and removed the unused Node `bcrypt-pbkdf` dependency.
- Made CDP e2e scripts use a configurable temporary directory.
- Aligned Linux release documentation with the deb/rpm artifacts and added Rust formatting checks to release CI.
- Removed unsupported macOS advertising until a macOS release job exists.


## [1.3.6] - 2026-09-05

The Node.js/Electron backend is fully replaced by a compiled **Rust core (Tauri v2)**, and
SSHSpan gains an **embedded SSH client**. Full migration story:
[`docs/REWRITE-ROADMAP.md`](docs/REWRITE-ROADMAP.md).

### Added

- **Connect - embedded SSH client** (russh 0.63 + xterm.js 5.5, both vendored/offline):
  - Saved servers with per-server username + SSH-key binding, auth methods
    (publickey / password / keyboard-interactive), optional password sealed with the vault
    master, latency test, last-connected tracking.
  - Interactive PTY terminal: full ANSI colors, 5000-line scrollback, live resize
    (incl. maximize-to-app with a floating `<>` toggle and `Esc` restore).
  - PuTTY behaviors: select-to-copy, right-click paste, Ctrl+Shift+C/V, blinking block cursor,
    solid accent selection highlight.
  - TOFU host-key pinning (`known_hosts` table); mismatch refuses the connection.
  - Right-click any key → **"Use this key to connect..."** (server's username + clicked key).
  - Vault-gated: locking the vault disconnects every live session.
  - Audit events: `connect.start/stop`, `server.save/delete`, `server.test_ok/fail`,
    `known_hosts.forget`.

### Changed

- **Backend rewritten from Node.js to Rust** (Tauri v2): crypto (`ssh-key`, AES-256-GCM +
  bcrypt-pbkdf2 vault sealing), SQLite via sqlx (same vault file, in-place migration),
  Bitwarden/Vaultwarden client (expand-only HKDF, Vaultwarden client-version gate,
  SSRF-safe URL validation), SSH deploy, and `~/.ssh/config` management.
  (Correction 2026-10-09: Electron-era (1.2.0 and earlier) vaults are not migrated in
  place. The Rust app keeps its vault in a different directory with a different schema,
  derives its keys with Argon2id instead of the Electron app's `scrypt` (the
  "bcrypt-pbkdf2 vault sealing" above is not what shipped), and has no importer for
  `~/.sshspan/sshspan.db`. To move over, export the keys from the Electron app as OpenSSH
  private keys or PuTTY `.ppk` files and import them into a new vault. See
  [`docs/SECURITY.md`](docs/SECURITY.md).)
- Renderer unchanged in spirit (plain HTML/CSS/JS, strict CSP, vendored xterm.js, generated
  Lucide icon sprite); DevTools enabled in release (the UI holds no secrets).
- Installers shrink from ~150 MB (Electron) to ~9 MB (NSIS).
- Removed the legacy Node/Electron backend (`src/main/`, Node test harnesses); Rust unit tests
  live in `src-tauri` (`cargo test`).

## [1.2.0] - 2026-09-02

### Added

- Import legacy PuTTY **version 2** `.ppk` files (PuTTY 0.52-0.74), encrypted or
  not, for all supported key types. v2 uses a SHA-1 based KDF and HMAC-SHA-1,
  which is weak but mandated by that format; it is accepted for **import only**,
  and exporting a v2 key writes the current **v3** format, so importing one
  quietly upgrades it.

## [1.1.1] - 2026-09-02

### Added

- Import keys from a file, not only by pasting: the Import tab has a
  "Browse for key file..." button that opens a native file picker
  (`.ppk`, `.pem`, `.key`, `.pub`, `.txt` and all files). The main process
  reads the chosen file and feeds it through the same import path as pasted
  material, so both routes behave identically; the name field pre-fills from
  the file name. Files larger than 512 KB are refused.

## [1.1.0] - 2026-09-02

### Added

- PuTTY key support (`.ppk`, version 3 - the format current PuTTYgen writes):
  import passphrase-protected or plain `.ppk` files, and export any stored key
  as a `.ppk` (encrypted with Argon2id + AES-256-CBC when a passphrase is
  given). Covers RSA, Ed25519 and ECDSA (nistp256/384/521). Import/export are
  wired into the Import tab and the Export format dropdown.
- Sidebar shows the real application icon instead of the `[SSH]` text badge,
  using an optimized 256x256 PNG derived from the app artwork
  (`scripts/make-sidebar-icon.js`, `npm run icon:sidebar`).

### Security

- PuTTY `.ppk` version 2 files are rejected with guidance to re-save them in a
  current PuTTYgen, because that format derives its key material and integrity
  check with SHA-1.
- The PPK MAC (HMAC-SHA-256 over the algorithm, encryption type, comment,
  public key and decrypted private blob) is verified timing-safely before any
  key material is returned, so a wrong passphrase or a tampered file never
  yields a usable key. Argon2 parameters from an incoming file are validated,
  with implausible memory requests refused.

## [1.0.8] - 2026-09-02

### Fixed

- Narrow-window layout: the keys list and detail pane squeezed each other
  instead of stacking (the detail pane had a hard `min-width: 340px` inside a
  non-wrapping flex row), and key rows overflowed because the renderer builds
  `.key-row-main/-name/-sub` while the stylesheet only defined
  `.key-info/.key-name/.key-sub`, leaving them unstyled with no truncation.
  The layout now wraps and stacks, long names and fingerprints ellipsize, and
  the sidebar collapses to icons under 900px / 620px breakpoints. Also fixed
  the unstyled "public only" badge (`.badge.ghost`) and made the topbar,
  toolbar, export row, deploy options, settings rows and audit table reflow
  instead of squashing.

## [1.0.7] - 2026-09-01

### Fixed

- Release notes: the changelog-section extraction used an awk dynamic regex
  in which the escaped brackets opened a character class, so no section ever
  matched and every release fell back to the generic "see CHANGELOG.md" text.
  It now uses an anchored literal-string comparison.

## [1.0.6] - 2026-09-01

### Fixed

- Linux CI: the release upload step failed with "Pattern 'release/*.AppImage
  release/*.deb' does not match any files" - space-separated globs are read as
  a single literal pattern. Artifact globs are one per line again, with an
  explicit job `name` so the Actions UI stays readable.

## [1.0.5] - 2026-09-01

### Fixed

- Linux CI: electron-builder rejected the deb build with "Please specify
  author 'email' in the application package.json" (required by deb package
  metadata). Added `author.email` to package.json.

## [1.0.4] - 2026-09-01

### Fixed

- Linux CI: `tests/smoke-app.js` hardcoded the Windows ssh-keygen path
  (`C:\Windows\System32\OpenSSH\ssh-keygen.exe`), so the app suite failed on
  the Linux runner. The test now resolves ssh-keygen per platform.
- Release workflow: single-line matrix `artifacts` values (multiline values
  produced garbled job names and unreadable logs).

## [1.0.3] - 2026-09-01

### Fixed

- Release workflow: the "sync package version with tag" step failed with
  "npm error Version not changed" when the tag version already matched
  `package.json`. It now bumps only when the versions differ.

## [1.0.2] - 2026-09-01

### Added

- Release workflow now builds Linux (AppImage + deb) in addition to Windows
  (NSIS installer + portable exe) for every `v*` tag.

### Fixed

- Bitwarden sync failed with "Invalid symmetric key length: 111" on accounts
  whose user key is stored as raw bytes (the current Bitwarden client format):
  the account key was decoded as UTF-8 text. Both the raw-bytes and the legacy
  base64-text formats are now accepted, with a clear error for anything else.

## [1.0.1] - 2026-09-01

### Added

- Bitwarden / Vaultwarden sync: mirror SSH keys to the SSH key item type (cipher 5) of the
  user's own vault, configured in Settings (server URL, account email, vault master
  password, folder name defaulting to `SSHSpan`, manual or automatic two-way sync with a
  configurable interval). Newest side wins per item; deletions are never propagated; all
  item fields are encrypted client-side with the Bitwarden protocol; the configured server
  URL is validated against an SSRF guard (http/https only; localhost, `.local`, private,
  link-local, CGNAT and other reserved IPv4/IPv6 addresses rejected, DNS resolution must be
  public); the stored vault password is sealed with the SSHSpan master password; sync
  actions are recorded in the audit log. (Vaultwarden 1.34+ or Bitwarden clients 2024.12+;
  two-factor accounts are not supported yet.)
- Initial public release of the documentation set: README, ARCHITECTURE, SECURITY, PRIVACY,
  CONTRIBUTING, CODE_OF_CONDUCT, LICENSE, CHANGELOG, and .gitignore.
- Vault-protected key store with scrypt key derivation (N=65536, r=8, p=1) and AES-256-GCM
  private key encryption.
- Key management: generate (RSA 3072-8192, Ed25519, ECDSA nistp256/384/521), import, export
  (OpenSSH new-format, PKCS#8, SPKI public, authorized_keys), copy public, update, and delete.
- OpenSSH new-format private key parser supporting none, aes256-ctr, aes256-gcm, and
  chacha20-poly1305@openssh.com ciphers via bcrypt-pbkdf.
- SSH config deployment: marker-bounded managed Host blocks in ~/.ssh/config; deployed key
  files are written to ~/.sshspan/keys/<id> with 0600 permissions on POSIX and
  current-user-only ACLs (icacls /inheritance:r) on Windows.
  (Correction 2026-10-17: this backend ran `icacls <file> /inheritance:r /grant:r <user>:(F)`,
  which removes inherited permissions only and gives that user full control, so "current-user-only"
  was too strong: where the folder passes no permissions down, SYSTEM and Administrators keep the
  full control Windows gave the new file. The Rust app that replaced this backend does the same
  with the user's SID; see [`docs/SECURITY.md`](docs/SECURITY.md#secret-file-writes).)
- Dark-themed vanilla-JS renderer (no framework) with Keys, Deploy, Settings, and Audit
  views, vault gate (create/unlock/change password), keyboard shortcuts (Ctrl+1..4, Ctrl+N,
  Ctrl+L, Ctrl+,), and a 10-second auto-lock status poll.
- Audit log recording key, vault, and settings events.
- Settings view with theme, auto-lock timeout, SSH config path, confirm prompts, editor
  font, and fingerprint display options.
- Tray-on-close behaviour on Windows and Linux, single-instance lock, 1100x720 window with
  880x560 minimum.
- NSIS installer shows the MIT license and project URL during setup; GitHub Actions release
  workflow building the Windows installer + portable exe for every `v*` tag with
  changelog-driven release notes.

### Changed

- SQLite persistence via sql.js with atomic tmp+rename saves and a 500 ms debounced flush.

### Fixed

- Bitwarden sync: encrypted vault fields were sent as serialized Promise objects instead of
  ciphertext (un-awaited async encryption), causing HTTP 422 on folder creation and broken
  item push/pull. All encryption call sites are now awaited; the test transport mirrors the
  real async contract.

### Security

- Master password is never stored; only a scrypt verification hash with timing-safe compare.
- Private key material is encrypted at rest; the database file itself is not encrypted.
- Renderer is sandboxed with contextIsolation and a minimal typed preload API.
- No telemetry, no network access, no auto-update.
