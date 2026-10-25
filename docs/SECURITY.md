# SSHSpan security model

**Last updated:** 2026-10-25  
**Status:** describes v1.10.0; checked against committed source at `6c19b1b`, the
release-signing and Windows CI passages at `38e586e`; nothing it describes has changed since. It
also describes the PuTTY session import, which is not released yet (Unreleased in the CHANGELOG)  
**Platforms:** Windows and Linux

This is a description of controls and boundaries in the source, not a guarantee that the program
is secure. The 2026-10-09 audit is an internal, tool-assisted review rather than a third-party
security assessment, and its severities are baseline estimates. What the remediation fixed and what
it did not is recorded finding by finding in the
[audit index](audit/2026-10-09/README.md); the risks that were knowingly accepted are listed in
[Accepted risks and limitations](#accepted-risks-and-limitations).

## Scope and threat model

SSHSpan is designed to reduce risk from:

- offline access to the vault database after the app is closed;
- a malicious or compromised SSH/SFTP server;
- accidental or malicious remote file names and incomplete transfers;
- substituted or tampered published update assets;
- untrusted terminal output, MCP tool definitions, and MCP results;
- some consequences of a compromised renderer by narrowing high-value IPC commands.

It does **not** defend against:

- an attacker with the user's OS privileges, a debugger, kernel access, a memory dump, or control
  of the running process while the vault is unlocked;
- compromise of the repository, release workflow, or Actions signing secret;
- every consequence of arbitrary renderer code execution - the renderer can invoke registered
  commands, several SFTP local-path operations still accept renderer-supplied paths, and an
  approval click is attested by the renderer (see
  [Renderer-attested approvals](#renderer-attested-approvals));
- guaranteed prompt-injection resistance from an AI model;
- weak master passwords or the absence of full-disk encryption.

The database file is not wholly encrypted. Public keys, fingerprints, saved host metadata,
known-host pins, categories, settings, transfer metadata, and audit rows remain readable to an
attacker who can read the file.

## Cryptography

### Master-password verifier

The master password is not persisted. `master.hash` stores an Argon2id PHC verifier using the
`argon2` crate defaults currently documented by the code as approximately 19 MiB memory, two
iterations, and one lane. Unlock uses the crate verifier. Older Rust builds that stored a
plaintext verifier upgrade it to Argon2id after a successful constant-time comparison.

### Unlock throttle

After five consecutive failures, in-process unlock and change-password attempts enter exponential
backoff: 30 seconds, doubling per additional failure, capped at 15 minutes. A whole unlock attempt
holds the throttle's attempt lock, so guesses sent in parallel meet the same counter, and the
password check inside a master-password change shares it. A lock that lands during an unlock wins:
the password is set, then cleared with "Vault was locked while the operation was in progress."
Restarting the app clears this in-memory counter; Argon2id remains the offline control.

### Sealed vault records

Each private key, saved server password, Bitwarden password, provider API key, or MCP static
secret is sealed independently:

1. generate a fresh 32-byte salt;
2. derive a `VaultKey` with Argon2id (`m=64 MiB`, `t=3`, `p=4`, 32-byte output);
3. derive the AES key through HKDF-SHA-256 with the vault-encryption context;
4. generate a fresh 12-byte nonce;
5. encrypt/authenticate with AES-256-GCM.

The Rust format is **not compatible** with the vaults of the Electron app (1.2.0 and earlier), which
used `crypto.scryptSync`; Argon2id and scrypt derive different keys. There is no automatic legacy
Electron vault importer (A7-58): export the keys from the Electron app and import them.

The in-memory master password, derived key buffers, key text and the import passphrase at the
command boundary, and the saved SSH password on every return path use zeroizing wrappers (the export
passphrase reaches `key_export_to_file` as a plain string). This is not proof that every transient
allocation is wiped: the SSH library zeroizes the password it takes, but builds the authentication
packets in a buffer it clears without wiping and frees keyboard-interactive answers unwiped (A6-11,
an accepted limit).

### Master-password rotation

Rotation is asynchronous on a blocking worker and takes exclusive `VaultRotationLock` access.
Commands that seal data or rewrite a key/server/MCP record take shared access and fail fast with
"The vault is being re-encrypted - try again when it finishes." while a change is active or queued,
and an unlock is refused with the same message until the change finishes.

Rotation:

- verifies the current password under the same failure throttle as unlock;
- snapshots and re-seals keys, saved server passwords, the Bitwarden credential, provider API
  key, and MCP static secrets in memory;
- conditionally updates sealed columns and the verifier in one SQLite transaction so concurrent
  row changes abort rather than get overwritten;
- re-checks the vault generation before commit;
- re-binds live MCP sessions to the new seal, installs the new in-memory password and only then
  attempts the audit row;
- logs an audit-write failure instead of returning a false "change failed" after commit.

A lock during the long re-seal aborts before commit. If a lock lands after the final generation
check, the transaction may finish but the vault remains locked and the new password is the one
that unlocks it.

### Export formats

Private-key export is backend-owned and writes directly to the native save-dialog path, which is
first checked against the write deny-list (`~/.ssh` stays allowed for it; see [SFTP local-path
boundary](#sftp-local-path-boundary)). Supported private exports are:

- OpenSSH new format: optional passphrase, AES-256-CTR + bcrypt KDF;
- PuTTY PPK v3: optional passphrase, PuTTY Argon2id/AES-256-CBC format;
- PKCS#8: plain or PBES2 using PBKDF2-HMAC-SHA-256 (100,000 iterations) and AES-256-CBC.

The Export tab offers the passphrase field for all three; without one, OpenSSH and PPK exports
are unprotected and the tab says so, and encrypted PKCS#8 refuses an empty passphrase. Public-key
exports go through the native save dialog as well, and every save dialog opens in the Downloads
folder (the home folder when there is none). Imported key comments cannot inject lines into
exported text: they are sanitised at generate, import and every exporter (A7-45).

## Storage and filesystem controls

### Real locations

`ProjectDirs::from("org", "sshspan", "SSHSpan")` is the source of truth. `system_paths` returns
the paths the UI shows.

| Platform | Vault database | Managed SSH config |
| --- | --- | --- |
| Windows | `%APPDATA%\sshspan\SSHSpan\data\sshspan.db` | `%APPDATA%\sshspan\SSHSpan\config\ssh\config` |
| Linux defaults | `~/.local/share/sshspan/sshspan.db` | `~/.config/sshspan/ssh/config` |

Linux honors XDG overrides. Settings are rows in the database `config` table, not a separate file.
The app manifests do not support macOS. Debug builds also honor an `SSHSPAN_DB` path override for
development; it is compiled out of release builds, because a process that could set it at launch
could otherwise point the whole vault at a database it controls.

On Unix the data directory is set to 0700 (a failure is logged) and the SQLite file to 0600 (a
failure aborts startup). On Windows the database relies on the inherited user-profile ACL;
secret files written elsewhere receive the explicit handling described next.

### Secret-file writes

Private-key deployment, private-key export, backup export, and other uses of
`write_secret_file` remove the old path, create a new file without following a planted symlink,
and apply protection before the first secret byte:

- Unix: create with mode 0600;
- Windows: create the file empty with sharing disabled; run absolute System32 `whoami.exe` to
  obtain the current SID; run one absolute System32 `icacls.exe` invocation with
  `/inheritance:r /grant:r *SID:F` and `CREATE_NO_WINDOW`; then write through the original
  handle. If ACL setup or the write fails, remove the file.

On Windows `/inheritance:r` removes inherited entries only and `/grant:r` replaces only the user's
own entry, so the entries Windows gave the new file at creation stay. Where the folder passes
permissions down, as `~/.ssh` under the user profile normally does, the file got inherited entries
only, and the current user is then the only account with access. Where it passes none down (seen
for an elevated administrator on the CI runner and for a UAC user on Windows 11), the file got the
creating process's default entries, so SYSTEM and Administrators keep the full control Windows gave
it, beside the user; OpenSSH for Windows accepts both on a private key, and both accounts can reach
any file anyway. The call grants no other account anything; with Windows' default settings, Users,
Everyone and Authenticated Users get no access either way.

A FAT/exFAT destination that cannot carry the expected ACL can therefore reject an export rather
than leave a readable private key. That is fail-closed behavior, not a promise that every volume
is supported. This path was verified natively on Windows 11 from a test executable cross-built in
WSL, and the library and integration tests have since run natively there too. The `windows-latest`
CI job, whose tests cover this path, passed on a runner for the first time on 2026-10-17, at
`38e586e`; its first run had failed five tests that assumed Unix paths or a single ACL entry, since
fixed. Its next run, at `fd4765d`, failed one test, because a database read gave up behind a run of
writes on the loaded runner (since fixed). The job stays `continue-on-error`, so its failure does
not fail the workflow, until it passes consistently.

### Backups

Backup export and restore are Rust commands with native dialogs; the sealed document never crosses
IPC into the webview. A backup is one JSON file whose payload is sealed like a vault record with
the master password current at export time, and the inner key/server/MCP blobs stay sealed with
that same password. It is written through the secret-file writer above, to a path that is checked
against the write deny-list before the backup is built (`~/.ssh` stays allowed).

The payload contains keys and their category links, categories, saved servers (passwords still
sealed), known-host pins, the allowlisted stored settings, MCP server records (secrets still
sealed) and SFTP bookmarks. It deliberately does **not** contain Bitwarden sync configuration,
AI-provider configuration or API key, the audit log, or the transfer queue, so a restore can
neither bring a Bitwarden destination nor confirm one.

Restore picks and reads the file in Rust (32 MiB cap). If the backup was sealed under a different
master password and none was supplied, nothing is restored: Rust answers `needsPassword` and issues
a single-use, five-minute grant for that one file. With the old password, readable blobs are
re-sealed under the current password and undecryptable ones are counted and excluded. Restored
known-host pins are marked imported and must be confirmed on a live connection, restored MCP
servers come back inert with tools disabled, and restored settings pass the same key/value
validation as `settings_set` (rejected entries are counted). A restore holds the shared rotation
guard and aborts, restoring nothing, if the vault locks during it. The `.pem` Browse button
returns a path (`system_pick_file_path`) without reading the file, and `system_select_file`, whose
only caller is key import, refuses a file over 4 MiB.

## Vault lock and locked-state policy

`lock_vault_internal` performs the full lock path for a manual command, the tray lock, the idle
watchdog and every exit:

1. increment `VaultGeneration` so pending connect/SFTP/export/sync operations abort at their next
   commit point;
2. kill interactive SSH sessions;
3. stop SFTP edit watches and best-effort delete their staged local copies;
4. stop SFTP keepalives, clear SFTP handles, and pause queued/active transfers;
5. clear backend AI access levels;
6. drain MCP session/status state and end every MCP session at the endpoint it was set up with, one
   background task per session (each unseals its own credential on the blocking pool from one
   zeroizing copy of the password taken before the store clears);
7. clear the zeroizing master-password store;
8. append `vault.lock` best-effort.

After the renderer observes the lock, it closes dialogs, wipes password and import fields,
destroys terminal tabs (discarding terminal scrollback), and clears each tab's assistant
conversation, pending approval and access level. A PuTTY import that is saving stops before its
next save (a save already sent finishes), and what it reports afterwards is counts only, with no
session name, host, user name or key path.

Every exit - the tray's Quit, `app_quit`, the updater handing over to an installer, closing a
tray-less window - passes `RunEvent::ExitRequested`, which runs the same lock path once (while the
vault is unlocked) and then waits for the MCP session DELETEs still running, 2 seconds at most, so
a hung server cannot hold the exit and a server that answers sees its session ended (A6-09,
A7-47). The window close button otherwise hides to the tray and is not a lock or exit boundary.

Locked state protects integrity as well as secret reads, but only where security-relevant:

- key/category mutations, audit clearing, known-host forgetting, MCP server removal/tool state,
  the Bitwarden "Allow syncing..." question, and sealed-data writes refuse while locked;
- both listings that read hosts and accounts from outside the vault - the hosts of the user's own
  ssh config (`ssh_config_list_hosts`) and PuTTY's saved sessions (`putty_list_sessions`) - refuse
  while locked, before the file or the registry is read: each is an inventory of hosts, accounts
  and key paths;
- `autoLockMinutes`, `confirmDelete`, `autoUpdateCheck`, and `confirmMultiLinePaste` cannot change
  while locked;
- harmless display, terminal, and file-browser preferences remain editable while locked. This is
  intentional and should not be documented as "all settings are read-only."

The default auto-lock is 15 minutes; `0` disables it. The deadline is the last real input (a trusted
keyboard, pointer, touch, wheel, or terminal input event) plus the configured minutes; the renderer
heartbeat is sent only after such activity, and remote output and periodic polls do not count. A
warning shows 60 seconds before an idle lock, and a lock or quit started in the window asks first
while sessions or transfers are live (a second real keypress answers yes; a held key never does);
the tray's Lock and Quit and the idle lock do not ask. The backend watchdog provides a second lock
path if the webview timer cannot run. Tauri v2's desktop run loop exposes no OS suspend or lock
event, so an OS suspend does not lock the vault.

## Key import and deployment

### Import boundary

The only imported key formats are OpenSSH private and PuTTY PPK v2/v3. PKCS#1, SEC1, PKCS#8,
SPKI, RFC 4716, and `authorized_keys` inputs are refused (A7-03). Unsupported private PEM
guidance uses:

```text
ssh-keygen -p -o -f <copy-of-the-key-file>
```

Run it on a copy. It asks for a passphrase to keep or set. Guidance deliberately does not include
`-N ""`, which would strip passphrase protection. The import dialog recognises the other formats
locally, so a private PEM that cannot be imported is not sent over IPC just to be refused. An
unencrypted `.ppk` has its MAC verified and a missing or blank Private-MAC is refused.

Private-key import is an explicit renderer exception: `system_select_file` reads at most 4 MiB and
returns text to the webview, or the user pastes text there. The renderer then calls `key_import`.
Key names must be unique, ignoring case, on create, import and rename.

### Managed SSH config

A deploy writes `~/.ssh/sshspan_<sanitized-name>` and `.pub` files plus `Host` stanzas in SSHSpan's
managed config under the platform config directory. It does **not** edit `~/.ssh/config`.

To make OpenSSH read those stanzas, put the backend-generated line near the top of the user's
config (OpenSSH normally uses the first obtained value for an option):

```text
Include "<managed-config-path-returned-by-SSHSpan>"
```

The generated line:

- quotes the path;
- escapes backslashes and double quotes;
- writes Windows separators as `/`;
- doubles `%` to avoid OpenSSH token expansion.

Caveats: `Include` accepts glob patterns. A platform config path containing `*`, `?`, or `[` can
match more than one file because SSHSpan does not escape those metacharacters. OpenSSH versions
also differ around percent expansion; Win32-OpenSSH 9.5p1 was reported to mishandle doubled
`%%`, and OpenSSH older than 8.7 reads a backslash-forced quote differently. If the path contains
`%` or glob characters, inspect the generated line and verify the resolved host with `ssh -G
<alias>` before relying on it. Do not hand-convert the line to an unquoted path.

Deploy planning and apply use the same serializer (`key_deploy_preview` shows exactly what
`key_deploy` writes), reject pattern aliases (`*`, `?`, `!`), sanitize aliases to literal-safe
characters, quote HostName/User/IdentityFile as needed, refuse a leading `=` in HostName or User
and `%` or `${` in User, warn about a `%` in the config path and about the user's own overlapping
`Host` lines, serialise writes to the managed config, and refuse foreign or another key's
files/stanzas. Undeploy ("Remove deployed copy") deletes only direct `sshspan_*` files in the
managed `~/.ssh` directory plus matching stanzas.

## SSH, SFTP, and local paths

### SSH host keys and connections

First-use trust is decided in a native Rust dialog that shows the fingerprint. A backup-imported
pin is marked untrusted and must be confirmed against a live connection; a pin whose `source`
cannot be read falls back to "imported", which asks again, never to a trusting state. Pins are
keyed by `host:port`; a later mismatch is a hard refusal and is audited, and a changed host key
and a declined first-trust prompt are different errors. Fingerprints are shown as `SHA256:` base64
without padding, the form `ssh-keygen -lf` prints. Connecting has a 20-second limit and
authentication a 30-second limit (the time spent in the trust dialog is excluded) and a timed-out
handshake shuts its socket down.

A saved SSH password is unsealed only to use it, and is wiped on every return path. Editing a
server keeps the saved password unless the user replaces or removes it. A saved password stays
with its account: an edit of an existing server that changes the host (trimmed), port, user name
(trimmed) or authentication method - a switch between password and keyboard-interactive included -
and brings no new password is refused with "Enter the password for the new server or account." and
writes nothing, unless the saved password is removed or the server switches to key sign-in.
Connecting as a user name other than the saved one does not use the saved password (a password
typed for that connection still goes where the connection goes). The server row is read, checked
and written in one transaction, so a save that raced another save is refused the same way. The
edit form asks for the password again at once, and key sign-in never asks, but the rule is
enforced in Rust.

A server can also sign in with a key file (a `.pem` path) instead of a vault key. SSHSpan cannot ask
for a passphrase while connecting, so a connect refuses a passphrase-protected file (OpenSSH, PKCS#8,
traditional PEM or PuTTY) with advice on what to do instead of a decoding error, and saving such a
server returns the same advice as a `warning` beside `ok` (A5-26). That save-time check reads at
most 64 KiB of a regular file and never opens a named pipe or another special file, so it cannot
stall a save; it runs after the save has released the guard that keeps a master-password change
out, and a path that starts with two separators (`\\...` or `//...`) is not looked at, because on
Windows a look would open a connection to the share, hand it an NTLM sign-in and could stall. On
Windows SSHSpan reads a key file only from this computer's drives: a path with a drive letter, a
colon and a separator (`C:\...`, `C:/...`, a mapped drive such as `Z:\...`) is read, and so is the
verbatim form `\\?\C:\...` (it takes only a backslash, so `\\?\C:/...` is refused). A share
(`\\server\share\...`, `//server/share/...`, `\\?\UNC\...`), the object namespace (`\??\...`), a
device (`\\.\...`), any other prefix and every relative form (`key`, `\key`, `D:key`) is refused,
and the file is never touched: saving the server (it is saved all the same) warns "SSHSpan reads
key files only from this computer's drives (like C:\...). Copy the key to a local folder, or
import it under Keys.", and Connect and Test connection refuse with the same text before the path
is opened. On Linux and macOS this rule does not apply.

### PuTTY session import

On Windows the Servers view can import the sessions saved in PuTTY: `putty_list_sessions` lists
them and the renderer saves the ones the user ticks. A session is a set of registry values that any
program running as the user can write, so the listing treats every one as untrusted:

- **The registry is only read.** Only the current user's sessions are read
  (`HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions`). That key and each session's key are
  opened for reading only (`KEY_READ`), only the ten values the listing uses are queried, and
  nothing is ever written. The listing is refused while the vault is locked (see [Vault lock and
  locked-state policy](#vault-lock-and-locked-state-policy)).
- **The listing is bounded.** At most 1,000 sessions are listed, and every subkey counts as one, so
  the reader enumerates and opens at most 1,002 subkeys however many there are. A text value (the
  host, protocol, user name, key file path or port forwardings) with more than 8 KiB of data is
  not read, and counts as too long, never as absent. A session whose name is longer than 256
  characters, host longer than 255, user name longer than 256 or key file path longer than 4,095
  is skipped with that reason, and a session whose registry key cannot be opened is skipped with
  the OS error, so one unreadable session does not fail the listing.
- **Key files are never touched while listing.** A session's key file path is passed on as a
  string: the listing never opens, stats or resolves it (a test checks the module's source for
  file-system calls). On Windows a look at a UNC path (`\\server\share\...`) would open an SMB
  connection to that server and hand it an NTLM sign-in.
- **Saving is the ordinary save.** The ticked sessions are saved one at a time with `server_save`,
  with its checks and its rule for key files on Windows: a key file path that is not on this
  computer's drives is saved with a warning and never touched (see [SSH host keys and
  connections](#ssh-host-keys-and-connections)).
- **Hostile values.** A session whose name, or whose host once cleaned up the way PuTTY cleans it,
  has a control character (C0, C1 or DEL) is skipped. Every other character that does not show - a
  text-direction override, a zero-width character, a space other than the plain one - is spelled
  out in the dialog (`<U+202E>`), and each name, host and key file path is set as text only, in a
  text-direction isolate of its own. A session whose name or host has such a character starts
  unticked and its row says so. A user name with one (a control character included) is not put in
  the username field, which holds what is saved; the row shows it spelled out instead. A session
  can still be ticked, and its name and host are then saved as they are, those characters included
  (`server_save` trims only white space at either end, as for every server).

### SFTP remote-side controls

- remote names are sanitized before local use and every local path built from one is confined to
  the folder the user chose;
- transfer files are created without following symlinks, and a fresh `.part` is created
  exclusively;
- downloads use `.part` staging, sync to disk and rename only after success, and a resumed local
  `.part` is continued only when its length is a strict prefix of the remote size; an upload's
  remote `.part` is checked by size and by reading back its last 64 KiB before more bytes are
  appended;
- expected-size short copies fail;
- recursive downloads and chmod skip symlinks, stop at depth 64 and at an entry cap (10,000 per
  picked item for downloads, 200,000 for chmod), and collect warnings; recursive chmod never puts
  setuid, setgid or sticky on files;
- queue jobs persist stable saved-server ids for reconnect/rebind;
- staged edit names always have an inert extension, and `.pub` is not on the inert list (on
  Windows it can open Microsoft Publisher);
- on servers that report no file types, an entry is not assumed to be a file: a delete tries remove
  first, only empties a folder that really is one, and never walks into a link's target.

### SFTP local-path boundary

Local paths provided over IPC must be absolute. Validation compares the literal and the resolved
spelling (a not-yet-existing target is resolved through its deepest existing ancestor). Locations
are resolved once per batch, so a large download does not pay for a path lookup per file. It
refuses:

- for every access, including a path the user approved in a native dialog: the SSHSpan data
  directory (the vault) and system directories;
- for reads (an upload source): also SSHSpan's managed config directory and everything under
  `~/.ssh` except `*.pub`;
- for writes, renames and deletes (download targets, new folders, the local pane): also SSHSpan's
  managed config directory, `~/.ssh`, startup folders and entries (the per-user and all-users
  Windows Startup folders, autostart entries, systemd user units, launch agents), shell startup
  files and folders (bash, zsh, sh, ksh, csh, fish, nushell, PowerShell profiles), folders on the
  user's `PATH` under the home folder, and settings files that run commands (git, PAM, editor
  startup files, Office startup folders, WindowsApps, Windows Terminal settings);
- deleting or moving a folder that holds a protected location (the home folder holds `~/.ssh`).

Recursive uploads apply the protected-source test to descendants and symlink targets. A
single-file `sftp_download` consumes a one-use native save-dialog grant when present, and its
target is checked against the full write deny-list either way. The write deny-list also covers
SSHSpan's own program files and data: the folder it is installed in (for a portable copy run
directly from the home folder, Downloads, the Desktop or Documents, or from a drive root, only the
executable and, on Windows, the DLLs beside it, so ordinary downloads there keep working), the
running AppImage or `.app` bundle, and its local data, cache and webview-profile folders (on
Windows the WebView2 user-data folder), so a download cannot plant a DLL beside the program or
into its profile; moving, replacing or deleting a folder that holds them is refused, and reads
from them stay allowed. A path picked in a save dialog - for "Download as..." and for the text
exports (a public key, the audit log's CSV) - is held to the same write deny-list as a typed path:
a dialog pick exempts nothing from the list. The text exports also need the pick
(`system_write_text_file` writes only to a path chosen in a save dialog this session, once), while
a "Download as..." target without one is accepted under the same list.
`~/.config/user-dirs.dirs` and `user-dirs.locale` are on the deny-list too, for typed and picked
paths alike: a download over `user-dirs.dirs` could point the Downloads folder, where every save
dialog opens, at a folder of the attacker's choosing. The private-key export and the vault backup,
which Rust writes to a path picked in its own save dialog, are checked against the same list too,
in the words of an export, with one exception: `~/.ssh` stays allowed for them, because exporting
a private key to `~/.ssh/id_...` is an ordinary thing to do (the text exports still refuse it).
SSHSpan's data folder and the system folders are refused first, as for every export. The dialog's
suggested file name is reduced to a name with no folder, the private-key export's included: a key
named `/home/me/.ssh/config` suggests `config` (with the format's extension), so its name cannot
open the dialog on that file. Every save dialog opens in the Downloads folder (the home folder
when there is none), so the page cannot steer where the dialog opens. File dialog titles are
cleaned like message dialog texts (no control characters, length capped).

**Residual renderer boundary (A6-02, Partial):** queue `dest_dir`, queue upload sources,
local-pane mkdir/rename/delete and a "Download as..." target (which uses up a save-dialog grant
when there is one but needs none) remain renderer-supplied strings checked by this deny-list, not
bound to a native dialog. A deny-list cannot name every sensitive path (`~/.aws`, crontab
locations, and other credential files are examples). Closing this requires native-dialog-approved
directory and source grants, a larger change that was not made.

### Edit in an external editor

`sftp_open_for_edit` stages a copy of the remote file with an inert extension and watches it. A
save is coalesced, then the server is checked first: its size and modification time (or, on
servers that report neither, a content hash up to 16 MiB) are compared with what was downloaded.
If the file changed or was deleted there, nothing is uploaded; the save is held back as a conflict
(`sftp-edit-sync` with a `conflictId`) and `sftp_edit_resolve` settles it as Overwrite or Reload,
re-checking the server first. An unchanged save is uploaded to a fresh, exclusively created temp
file beside the target, `LSTAT`-checked, and renamed into place, so a file or link planted at a
predictable name is never written through, renamed into place or deleted. A failed save is reported
once, with no retry storm and at most one leftover temp. The renderer asks about one file at a
time and names it; Overwrite and Reload take no click for 750 ms after a question appears or
changes, so a click meant for one file's question cannot settle another's, and Cancel leaves the
file as it is (its next save asks again).

"Stop editing" (`sftp_close_edit`) does not delete the staged copy when the server lacks something
in it. Without `force` it takes the edit's upload turn (waiting up to 10 seconds for an upload or
Reload that is running) and compares the copy's SHA-256 with the last synced hash; a copy that
differs (a save inside the 700 ms debounce, one whose upload failed or was held back as a
conflict, one whose watcher event was lost), an upload still running after 10 seconds, or a copy
that cannot be read or checked closes nothing and deletes nothing, and the answer asks the user
(the page shows it with Cancel focused; only a yes sends `force: true`, which closes at once). While
it waits and decides, the edit is marked as being closed, and an Edit of the same file is refused
with `<name> is being closed - try again when it has stopped.` (the page says it at once and sends
nothing; `sftp_open_for_edit` refuses it too), so the stop cannot delete the copy an editor has just
been handed; an answer that keeps the edit (`unsynced`) clears the mark and the file opens again.
The limits are in [Accepted risks and limitations](#accepted-risks-and-limitations): closing the
tab, disconnecting or losing the session, and locking the vault end every edit at once and delete
the staged copies (best effort) whatever they hold, and a save that lands in the instant between
the check and the delete is lost; so is the copy of an Edit that takes the edit in the instant
before the mark is set, which the stop then deletes.

Edit sync needs write permission on the file's folder and replaces the file, so ownership, ACLs
and hard links are not kept; see the residual windows under
[Accepted risks and limitations](#accepted-risks-and-limitations).

## Renderer controls

### Terminal links and paste

Every link in the terminal, an OSC 8 hyperlink or a plain URL, asks before it opens, in the app's
own dialog with the site (host) on its own first line. The URL is parsed once: only `http` and
`https` open, and a link that carries a user name or password is refused, so a long user name cannot
push the real host out of the question (A6-12). Pasted text is stripped of control characters (a
tab, carriage return and line feed stay) and bracketed-paste markers (`ESC[201~` cannot end the
paste early), and a multi-line paste is reviewed in the app unless the user turned that off.

### Renderer-attested approvals

The approval click for an AI action (the Execute card, an MCP tool card) and the answer to the
updater dialog are renderer events. Rust enforces what it can verify - the tab's access level, the
tool definition hash, a vault that is unlocked - but cannot tell a real click from a claimed one,
so a compromised renderer can claim an approval. Approvals therefore gate ACTIONS only. Where an
approval would send a secret somewhere, the destination is bound in Rust instead: a native
question that the page cannot answer, shown for an MCP credential or environment variable bound
to an address it was not bound to before (a new server, another URL or variable, a record
restored from a backup or refused before), for a stored assistant API key moved to another
provider or address, and for the Bitwarden sync pointed at a server or account other than the
allowed one (see [Bitwarden / Vaultwarden](#bitwarden--vaultwarden)). Its buttons are "Don't allow",
"Allow" and "Cancel"; "Don't allow" is the default button on Windows, where a stray Enter
answers it, and the GTK dialog on Linux sets no default button, so only a deliberate click on
"Allow" can come early; Esc or closing it means no; an "Allow" within a second of the dialog
opening, after the vault locked (even if it was unlocked again), or for settings that changed
meanwhile confirms nothing (an API-key move whose "Allow" came after a lock moves nothing and says
"The vault was locked while you were deciding - unlock it and save the settings again."); only one
such question is open at a time and a second is never queued (an API-key move is refused, an MCP
server saved meanwhile is stored switched off until it is saved again, and the Bitwarden sync
stays off); a later "no" is never undone by an earlier "Allow"; after a "Don't allow" or "Cancel",
no further question of the same kind is asked for 30 seconds, whatever host, address or account it
names, and a save in that window asks nothing: an MCP server is stored switched off, a save that
would move the stored API key is refused and saves nothing, and the Bitwarden sync stays off (an
MCP credential, a key move and a Bitwarden upload wait separately, so a "no" to one holds back
neither of the others, and the refusal names the host that was declined); every value it quotes is
cleaned and capped; and both answers are audited without the value. Besides that: a saved SSH
password that stays with its account, and a Bitwarden approval that applies only the list it was
issued for (the token stops a changed list from being applied under an approval given for another
one; a compromised renderer can still approve the list it was shown).

The renderer's CSP is `script-src 'self'` with no inline or eval script, dynamic text uses
`textContent` or the project's escaping helper, and the approval card shows the arguments with
invisible and text-direction characters spelled out (values up to 1,500 characters as they are; a
longer set is shortened, and "Show all arguments (N characters)" opens the complete text).

### Names a server chooses

A file name in the file browser is whatever the server's owner chose. Wherever the renderer shows
one (the lists, the path bar, questions, toasts and the activity log) it spells out control,
invisible, zero-width and text-direction characters, unusual spaces, the dots that only stand in for
"." and leading, trailing and repeated spaces as `<U+XXXX>` (and a line break as `\n`); a name that
shows nothing (blank, mark or format characters only, U+2800 and U+1D159 included) is spelled out
whole, and a name that is nothing but dots, spaces and look-alikes of dots has those look-alikes and
any combining marks spelled out too (a `..` with a combining mark on its last dot would otherwise
still read as `..`). The listing flags such a name, and the name `~` (it can read as the home
folder), with a "!" and says why on hover; single-character emoji, symbols and punctuation are
visible content and are not flagged (an emoji written with a variation selector or a zero-width
joiner is spelled out and flagged). Inside a sentence a name is kept in its own text-direction
isolate. A file
dropped onto a remote folder with a flagged name, from the OS or from the local pane, asks first,
and a move says which folder it goes into and which folder that is in. So a hostile name cannot pass
for the parent folder, reorder the words of a question or add lines to it. The backend's own texts
in the SFTP edit flow (a refusal to open an edit, a Stop editing answer that is not ok, a failed
save-back, a refused answer to a conflict) are shown spelled out in the same way. This is display
and confirmation hygiene in the renderer: the backend still
treats every remote name as untrusted when it builds a local path (see [SFTP remote-side
controls](#sftp-remote-side-controls)).

## Network clients

### Bitwarden / Vaultwarden

The optional sync client is HTTPS-only. There is no localhost exception. It rejects embedded URL
credentials, localhost/`.localhost`/`.local`, private/reserved/link-local addresses, and any DNS
name with a non-public answer; a guarded resolver repeats address filtering at connect time (not
behind a system proxy, see [Accepted risks and limitations](#accepted-risks-and-limitations)).
Redirects are refused, and server response text in errors is cut to 300 characters.

**The sync uploads only where the user allowed it.** A sync sends every private key (encrypted
with the account key) and every saved server password to the configured server and account, so
that destination is bound in Rust, to what the user allowed in a native question the page cannot
answer:

- The allowed destination, the server URL and the account email (the email compared without regard
  to case or surrounding spaces), is stored with the settings (`confirmed_destination`). A save
  that changes either stores the settings and then asks, in the native dialog "SSHSpan - Sync with
  Bitwarden?", which names the account, the server and the address; going back to the server and
  account that are still the allowed ones asks nothing (only the last destination allowed is kept,
  so returning to an earlier one after allowing another asks again). "Allow syncing..."
  (`bitwarden_allow_sync`) asks again for the stored destination and is refused while the vault is
  locked or no settings are saved.
- `bitwarden_sync` reads the settings only through one check, and while the stored destination is
  not the allowed one it refuses before anything is unsealed or sent, not even a login. Test
  connection uploads nothing and is not held back; it still reuses the stored master password only
  for the server and account it was saved for.
- The question follows the rules of the other credential questions (see
  [Renderer-attested approvals](#renderer-attested-approvals)): "Don't allow" is the default button
  on Windows (the GTK dialog on Linux sets none), Esc or closing means no, an "Allow" counts only
  after a second, and counts for nothing after the vault locked (even if it was unlocked again),
  for settings that changed meanwhile, or while a master-password change re-encrypts the vault;
  only one such question is open at a time and a second is never queued (the save says so and the
  sync stays off); a later "no" is never undone by an earlier "Allow". A save or "Allow syncing..."
  that does not end allowed returns the reason as a warning, which the page shows (for a save,
  instead of "Bitwarden settings saved."), and Settings > Bitwarden then says "Not confirmed".
- A backup does not hold the Bitwarden settings and a restore never writes them, so a restore can
  neither bring a destination nor confirm one. Settings saved before this check existed keep
  syncing: a one-time migration at the first start after the upgrade counts their destination as
  allowed, so the upgrade asks nothing.
- Both answers are audited with the host only (`sync.destination_allowed`,
  `sync.destination_declined`, the latter noting `answered=too-quickly` for an "Allow" within a
  second); an "Allow" that comes after a lock, for settings that changed meanwhile, while the vault
  is being re-encrypted or when the answer cannot be stored writes no row.
- The account must be one email address: at most 254 characters, exactly one "@" with something
  on both sides, no space, control, format or text-direction character and none of
  `( ) < > [ ] " ' , ; : \`, or the save is refused (the account is quoted in the question and in
  the sync's refusal, and free text in it could add words to what the user is asked). The dialog
  shows the account first, on its own line (Account, then Server and Address), and says when the
  account is not the one allowed before, naming that one.
- After "Don't allow" or "Cancel" (Esc and closing the dialog included), no further question about
  uploading is asked for 30 seconds, whatever server or account it names: a save or "Allow
  syncing..." in that window asks nothing, leaves the sync off and names the server that was
  declined. A renderer that asks again and again, about one server or about a made-up one each
  time, gets that answer instead of a dialog. An "Allow" that came within a second was no decision
  and starts no wait. The questions about an MCP server's credentials (the server is saved switched
  off) and about an assistant API key (the move is refused) wait in the same way, each kind on its
  own: a "no" to one does not hold back another. The waits live in memory for the app's run.

Server-supplied KDF values are **clamped**, not rejected, to these bounds:

- PBKDF2: 600,000 to 10,000,000 iterations;
- Argon2id: 2 to 16 iterations, 16 MiB to 1 GiB, 1 to 16 lanes.

The prelogin's `kdfMemory` is in MiB, as Bitwarden and Vaultwarden send it and the official clients
read it; it is converted to KiB before the bounds apply (a number whose KiB do not fit ends at the
ceiling instead of wrapping to the floor). Every prelogin number above 32 bits - iterations,
memory, parallelism - ends at the ceiling instead of being cut to 32 bits, and a KDF type above 32
bits is refused instead of being read as another type. An out-of-range floor can therefore cause
authentication to fail after deriving at the floor; it is not reported as "KDF rejected." Every
master-key derivation - Argon2id at the account's memory setting (up to 1 GiB) and PBKDF2 alike -
runs on the blocking pool, not on an async worker, at most two at once (Test connection and a sync
share the two places); a sign-in that gets none within 30 seconds stops with "Another Bitwarden
sign-in is still running. Try again when it has finished."

Bitwarden item fields are encrypted client-side with the Bitwarden protocol. The configured
master password is itself sealed by the SSHSpan vault and is reused only for the server and account
it was saved for: Test connection compares the URL and email with the saved ones before it unseals
the password, and a save keeps the stored password only when they match, so a compromised
renderer cannot make SSHSpan log in to an endpoint of its choosing with the stored password, and
the settings row is written in one transaction so no reader sees a new URL with an old password.

Sync keeps data: revision and change marks are written back after every push and pull, edits made
during a sync survive (conditional writes), organisation items are reported, a server carries its
local id so a lost link re-links and never onto an item another local server owns, and undecryptable
fields are errors. Remote changes that would overwrite a local server or key, or add a new one, are
only planned: a sync returns them by name as `pendingServers` and `pendingKeys` (at most 500 per
list, real changes first) with an `approvalToken` for the user to confirm. Each pending change
carries a digest of the item exactly as the vault served it, and applying them takes
`allowRemoteOverwrite: true` plus the `approvalToken` of exactly that list: a run whose own fetch
finds another list applies nothing and returns the new list with a new token (`approvalStale`), and
an approval without a token applies nothing. A list too long to show (more than 500 server changes,
or more than 500 key changes) cannot be approved: it comes back with no token and says why, so no
entry is ever applied unseen. An item's fingerprint and public key are derived from its private key,
an item that claims otherwise is refused by name and not imported, and every name a pending entry or
a key refusal quotes, and every item title or id that another sync error text quotes (several items
naming one server, an older copy, an item without a creation date, an unusable key, a failed pull),
is stripped of control, invisible and text-direction characters and capped at 80 characters (server
names pulled from Bitwarden are stored cleaned the same way). The page shows each error's name and
reason spelled out and in a text isolate of its own, and server response text keeps its 300-character
cap. Every text the backend returns for the Bitwarden settings and for the "Allow syncing..."
answer is shown spelled out as well. `sync.run`, `sync.error` and `sync.key_renamed` audit rows
record runs.

A malicious Bitwarden/Vaultwarden server could feed crafted items; they pass through the same key
parsers as imports, and unparseable items are recorded in the sync result, which the UI displays.

### AI provider

Provider requests are made by Rust. HTTPS can reach a configured host; plain HTTP is accepted only
for `localhost` and `*.localhost` names (which rely on the resolver, see the accepted risks),
loopback, RFC1918/private, link-local, or IPv6 local/private addresses. Credentials embedded in the
URL are refused, and a saved URL that today's rules refuse is refused before the key is unsealed.
Redirects are not followed (a 3xx is an error naming the host), so API keys are not forwarded to
another origin. A stored API key never silently follows a different provider or origin: it needs a
new key or a native answer to the question described under [Renderer-attested
approvals](#renderer-attested-approvals) (declining saves nothing and answers "Enter the API key for
the new address."); the page's own `reuseKeyAtNewOrigin` flag is ignored, a base URL with a control,
invisible or text-direction character is refused, and the URL is stored in its parsed form
(lowercase scheme and host, default port dropped).

The provider receives user chat, session metadata, tool definitions/results, and a bounded recent
terminal snapshot (up to 200 lines / 8,192 characters). Terminal and MCP output are wrapped as
untrusted data with a per-turn nonce and system instructions say only user chat is instruction. This
is a probabilistic mitigation; a model may still be manipulated.

Typing and execution from the assistant pass through Rust gates:

- `assistant_type_text` permits Draft or higher, rejects line breaks, C0/DEL/C1 control characters
  other than a tab, text-disguising characters, and more than 4,096 characters, then audits the
  typed text (`assistant.type`); the renderer's `type_command` and Insert go through it, so the
  model cannot press Enter;
- the disguising set (`DISGUISING_CHARS`) is every Unicode format character (Cf), every
  default-ignorable code point, and the line and paragraph separators (Zl, Zp), held as a table of
  sorted ranges;
- `assistant_exec` applies the same set and also refuses TAB, so the command shown on the Approve
  card is the command that runs; it refuses below Execute, and an approval is renderer-attested.

### MCP

MCP supports Streamable HTTP only; legacy HTTP+SSE and stdio are not supported. Traffic originates
in Rust. Redirects are refused. HTTPS is accepted for any host; plain HTTP only for loopback,
parsed as `127.0.0.0/8`, `::1` or the exact name `localhost` (a name that merely starts with
"127." is not loopback, and `*.localhost` is refused). A URL with a `?query` or `#fragment` is
refused, in the backend and in the renderer's pre-check. The name `localhost` relies on the
resolver (see the accepted risks).

Every discovered tool starts disabled. The backend:

- computes a SHA-256 hash of the canonical definition;
- exposes `definition_hash` and derived `definition_changed`;
- clears enabled/auto-approve state on a definition change;
- requires an `expected_hash` compare-and-swap for **every** enable, so a settings row that went
  stale cannot approve a definition the user did not see;
- reads, changes and writes a server record in one transaction, so a revoked approval cannot come
  back and a removed server is not re-created;
- checks confirmed server, enabled state, pinned/current hash, access level, approval/auto-approve,
  and vault generation before a call, and checks again right before every `tools/call` - also
  after an initialize, a refresh or a session renewal; a `tools/list_changed` announced with the
  initialize answer triggers the refresh;
- returns results as raw content (the renderer wraps every result in the turn's untrusted-data
  block) and audits success/error/failure by argument hash rather than raw arguments;
- checks the stored record (the server removed, its URL or auth changed, or not confirmed) right
  before every initialize and again once it is answered, every `tools/list` page and the page
  asked again on a renewed session, and the refreshes after a call, so a server that was switched
  off, edited or removed while a request was out gets nothing more, and a session set up for it
  is ended where it was set up and never registered;
- caps the requests a server may make of the client inside one response at eight, each checked
  against the vault.

Static MCP secrets are sealed and bound to configured origin and auth semantics: a URL, auth type or
header change drops the stored secret and any environment-variable binding that is not sent again.
Environment-variable auth stores only the variable name and resolves its value per request. Restored
MCP servers are inert and tools disabled until the user reviews and re-saves them. A live session
carries the settings it was set up with; a request uses only a session bound to its record's current
settings, and every session is ended at its own endpoint with its own credential when it is
replaced, refused, removed or locked (best effort: on a lock, a quit and a URL or credential edit
the DELETEs run in the background and an exit waits up to two seconds, while removing a server waits
up to five seconds for its DELETE and removes the record either way). Saving a server that binds a
secret or an environment variable to an address it was not bound to before stores it unconfirmed -
it stays off - until a native question that names the host and the variable is allowed (an "Allow"
given after the vault locked confirms nothing, and a later "Don't allow" is never undone by an
earlier "Allow"); the variable name, including one kept from storage, must be 1 to 128 visible ASCII
characters without spaces or `=`, so it cannot rewrite the question. A replaced session is ended
only once the requests still using it have finished, a lock unseals at most four secrets at once,
and at most 16 teardowns are pending at once (the rest are not sent and expire on their servers).

## Updater

The updater enforces:

- initial installer URL under this repository's GitHub release-download path, an exact release
  asset (six path segments, no query or fragment, the file kind taken from the path);
- HTTPS and a host allowlist on the validated redirect hop;
- manifest/signature/installer size caps;
- GitHub-provided SHA-256 asset digest;
- fail-closed minisign verification against an embedded public key, with the global signature
  checked before the trusted comment;
- a trusted comment that must read `SSHSpan release v<x>` for the release bound to the URL tag, so
  a validly signed older build cannot be installed as a newer one (A6-05);
- semver rollback and URL-tag checks;
- random `create_new` temporary destination; partial downloads deleted on every error and stale
  update files (exact generated names only) pruned at start.

On Windows a setup `.exe` starts through one `ShellExecuteExW` call so UAC can elevate, and a
declined prompt reads as cancelled; an `.msi` (used when a release has no setup `.exe`) is started
with `msiexec /i`, where a declined prompt is not reported as cancelled. On Linux a `.deb` or `.rpm`
is handed to the desktop's opener and an `.AppImage` update is downloaded beside the running
AppImage and replaces it in place. The renderer must ask the user before calling
`update_download_and_run`; the backend does not re-verify that.

The minisign signature authenticates the installer bytes as signed by the key holder and detects
asset substitution/tampering and hostile mirrors. It does **not** defend against compromise of the
repository, release workflow, or `MINISIGN_SECRET_KEY`, because that environment can sign a
malicious build. The signing key was provisioned on 2026-09-12, so the updater is fail-closed. In
this repository the release workflow also stops with an error when `MINISIGN_SECRET_KEY` is
missing, before it attaches any installer, instead of publishing an unsigned release (a fork,
which has no such secret, builds unsigned with a warning). Two gaps remain: the installers are
attached, and the release published, in one step and the `.minisig` files in a later one, so a
failed upload in between leaves a public release without signatures; and no step checks a new
signature against the public key the app embeds (`MINISIGN_PUBLIC_KEY` in `updater.rs`), so a
secret key that does not match it signs without an error. Installed copies refuse such a release,
because the updater fails closed, so either gap means an update outage, not an unverified install.

The embedded public key (key id `D67C45BA942239D8`) pairs with the `MINISIGN_SECRET_KEY` Actions
secret and the maintainer's offline backup. To rotate it, replace both in the same release;
releases published before the key was provisioned cannot serve as auto-update sources for builds
that carry it. Back the signing key up offline: losing it means losing the ability to sign
updates. `scripts/gen_minisign_test_vector.py --check` compares the test vectors with the
constants in `updater.rs`.

## Accepted risks and limitations

Each is a known, deliberate state, with the reason it was left.

- **Renderer-attested approvals gate actions only.** A compromised renderer can claim that a
  human clicked Approve for an AI command, an MCP tool call or an update. Rust cannot observe the
  click. Destinations for secrets are therefore bound in Rust where that matters (native
  questions for an MCP credential or environment variable, a stored assistant API key and the
  Bitwarden sync destination; the saved-password account binding; the Bitwarden approval token),
  and the rest is documented here rather than claimed as a control.
- **The local-path boundary is a deny-list, not a grant model (A6-02, Partial).** It covers the
  locations listed under [SFTP local-path boundary](#sftp-local-path-boundary) and anything else
  is reachable from a compromised renderer. A grant model needs dialog-picked destinations and
  upload sources, a larger change that was not made.
- **A network share as a local path can still start a Windows sign-in (part of A6-02).** On
  Windows, a local path that a compromised renderer supplies for an SFTP command, or as the target
  of `system_open_external`, can name a network share (`\\host\...`, `\\?\UNC\...`), and checking
  the path can make Windows sign in to that host with NTLM. Such paths are not refused: refusing
  shares in the local pane would also block users who browse a NAS there by its UNC path, so this
  stays inside the accepted residual of the local-path boundary above. Key files are different:
  since this release they are read only from this computer's drives (see [SSH host keys and
  connections](#ssh-host-keys-and-connections)).
- **Memory.** While the vault is unlocked, the master password and any key material an operation
  needs are in process memory; a debugger, memory dump, or kernel-level attacker can read them.
- **The SSH library keeps a password copy (A6-11, Accepted).** `russh` zeroizes the password
  `String` it takes, but builds the `USERAUTH_REQUEST` and `USERAUTH_INFO_RESPONSE` packets in a
  cleartext buffer it clears without wiping, and frees keyboard-interactive answers unwiped; SSHSpan
  wipes its own copies but cannot fix this without an upstream change.
- **The verified installer is re-opened by path.** After the digest and signature checks the
  installer is started by path from the user's temp folder (an AppImage update, from beside the
  running AppImage), so code running as the same user could swap it in that window; UAC is not a
  boundary against same-user code.
- **`SSHSPAN_DB` exists in debug builds only.** It is compiled out of release builds.
- **MCP tool arguments get no backend disguising-character check.** The model chooses them; the
  approval card's escaping of invisible and text-direction characters is the control.
- **The server list shows names as they are.** A row of the server list shows the server's name and
  `user@host:port` as they are, without spelling out characters that do not show, so a name with a
  text-direction override (U+202E) takes effect there. This is older than the PuTTY import, which
  starts a session whose name or host has such a character unticked, so saving one as a server
  takes a deliberate tick.
- **A revoke that commits while `tools/call` is on the wire cannot stop that call.** The gate is
  checked right before the request is sent, and a request already sent cannot be recalled.
- **`definition_changed` clears if a server reverts** to the approved definition; the tool stays
  disabled until it is enabled again, so this fails closed.
- **MCP notifications after a response are dropped,** and the names `localhost` (MCP and provider)
  and `*.localhost` (provider only) rely on the resolver to stay on the loopback interface.
- **Edit sync.** One round trip separates the server check from the upload, SFTP v3 has no
  conditional write, and the comparison uses size and modification time in whole seconds, so a
  same-size change in the same second is not noticed. It needs write permission on the folder and
  replaces the file, so ownership, ACLs and hard links are not kept.
- **A resumed `.part` keeps a deterministic name** (resuming across restarts needs it). On a
  shared, writable remote folder a file planted there whose size and tail match what was already
  sent passes the resume check, and a hard link cannot be told from a file over SFTP v3. Replacing
  an existing remote file needs a remove and a rename (OpenSSH refuses a rename onto an existing
  file), so a swap in that one round trip is not prevented.
- **Servers that report no file types.** An entry is accepted as "not a link" when `READLINK` says
  it is not one or `REALPATH` resolves it to itself, and a size match (with the bytes just written)
  decides only when the folder probe is inconclusive; fooling that takes a server that answers those
  probes wrongly on purpose.
- **Key files on mapped drives (Windows).** The rule that a key file is read only from this
  computer's drives goes by the drive letter: a network drive mapped to a letter (`Z:\...`) is read
  like a local one, because the user set it up. Every other spelling is refused before the file is
  touched: a path written as a share or a device (`\\server\...`, `\\?\UNC\...`, `\??\...`,
  `\\.\...`), another prefix (`\\?\Volume{...}`, `\\?\C:/...`) or a relative path (`key`, `\key`,
  `D:key`). A key on a share needs a mapped drive letter or a local copy.
- **Bitwarden.** Test connection needs an unlocked vault (it unseals the saved master password),
  deletions are never propagated, and an older copy of a server stays reported on every sync until
  the user deletes it in Bitwarden. A category rename, move or delete, or a change of a key's
  categories, marks the keys and servers under the category for the next sync, which uploads the new
  path only while the remote item is unchanged and lists Bitwarden's change for approval first
  otherwise; the marks are kept on this machine only and are not in backups, so a restore does not
  carry a pending category upload and the next category change marks again. Settings saved before
  the destination question existed keep syncing: a one-time migration at the first start after the
  upgrade counts their destination as allowed, even settings that a compromised page saved before
  the upgrade, and no question is asked for them (the earlier version would have uploaded to them
  anyway).
- **A started Bitwarden key derivation cannot be cancelled.** It runs to the end even if its
  sign-in stopped waiting or the vault was locked meanwhile, and it keeps its slot until then (two
  derivations at the 1 GiB ceiling hold both slots and about 2 GiB of memory).
- **A system proxy bypasses the Bitwarden connect-time address check.** SSHSpan's HTTP clients use
  the system proxy when one is set (the `HTTP_PROXY` and `HTTPS_PROXY` environment variables and, on
  Windows, the proxy in the system settings). A request that goes through an HTTP proxy connects to
  the proxy, which looks up the vault's host name itself, so the guarded resolver that drops private
  and reserved addresses when a connection is made never sees that name. The check made when the
  sync URL is saved or tested still runs, and the client stays HTTPS-only with redirects refused,
  but a host name whose DNS answer changes afterwards can then reach an internal address through the
  proxy, and what the proxy refuses or allows is then its own policy. With a proxy set, rely on the
  proxy's own egress rules and configure only a vault you trust.
- **Webview differences.** The terminal header uses container queries (WebView2/Chromium 105+,
  WebKit 16+), so on an older WebKitGTK it wraps to two rows; a held `Ctrl+L` or `Ctrl+Q` is
  ignored by checking `KeyboardEvent.repeat`, which was tested in Chromium only; the keypad and
  `Ctrl+Shift`+digit chords were tested with a US-layout event; key rows, category rows and session
  tabs are `role=button` elements with interactive children, which an automated accessibility scan
  flags as nested-interactive.
- **Exit teardown timing.** The wait for MCP session DELETEs at exit is covered by unit tests of
  its parts only; a manual check on Windows (quit with a connected MCP server, then see the session
  DELETE arrive) is still wanted.
- **Native credential questions on Linux.** The one-second minimum before an "Allow" counts is
  measured from the moment the dialog is requested on the main thread. On Windows the
  dialog is created at once; on Linux the GTK dialog is created from an idle callback, so a flooded
  main loop can use up part of that second before the dialog is visible. On Windows a
  stray Enter answers "Don't allow" (the default button); the GTK dialog sets no default button, so
  only a deliberate click on "Allow" can come early.
- **A mistaken "no" costs 30 seconds.** A "no" given by mistake (or Esc, or closing the dialog)
  holds back that kind of question for 30 seconds, for any server or account; a lock does not clear
  the wait, and a restart forgets it.
- **Edit sessions end with their tab, session or lock.** Closing the tab, disconnecting or losing
  the session (`sftp_close`, `terminal_disconnect`) and locking the vault end every edit at once:
  the staged copies are deleted (best effort, a plain delete rather than an overwrite) and saves
  that did not reach the server are lost, unlike "Stop editing", which asks first - the session is
  going away, so nothing could be uploaded any more. A save that lands in the instant between the
  "Stop editing" check and the delete is lost as well, the same race as the check-then-upload of a
  save, and an Edit of the same file that takes the edit in the instant before "Stop editing"
  marks it as being closed hands the editor a copy that the stop then deletes.
- **MCP: unconfirmed tools, replies and teardowns.** The tools of a server that is not confirmed
  are still offered to the model; the backend refuses every call, so the cost is an approval card
  that cannot lead anywhere. The stored record is checked right before each request, so a request
  already out is not recalled, and two kinds of traffic are not checked against it: the `-32601`
  answers to a server's own requests inside an open response (at most eight per response, each
  checked against the vault generation and sent to the same endpoint within the same exchange) and
  the session DELETEs, which only end sessions. When more than 16 session teardowns are pending at
  once (a lock with many sessions), the rest are not sent and those sessions expire on their
  servers.
- **A Windows regression does not fail CI yet, and drag and drop is not proven on the real thing.**
  The `windows-latest` CI job passed on a runner for the first time on 2026-10-17, at `38e586e`
  (743 library, 47 integration and 20 MCP integration tests, natively); its first run had failed
  five library tests that assumed Unix paths or a single ACL entry, since fixed. Its next run, at
  `fd4765d`, failed one test, because a database read gave up behind a run of writes on the loaded
  runner (since fixed). The job stays `continue-on-error` (A7-56, Partial) until it passes
  consistently. The release workflow's own Windows `cargo test`, with the same manifest step, runs
  only when a tag is pushed and has not run since that step was added. Drag and drop is emulated in
  the renderer suites - they remove the HTML5 drag events the Windows webview withholds and drive a
  real mouse - and no real WebView2 drag was run (A3-23).
- **Platform limits.** There is no hardware-backed key storage; keys are as strong as the master
  password and the OS random-number generator. A weak master password can be attacked offline
  against the stored Argon2id verifier. Tauri v2 exposes no OS suspend or lock event, so suspend
  does not lock the vault. Deployed key files rely on filesystem permissions. Accounts that
  require two-factor login are a previously documented unsupported case (not re-verified).
- **Dependencies.** Several transitive Rust crates are flagged unmaintained-class by advisory
  tooling without a known exploitable issue in SSHSpan's use; they are monitored, not eliminated.

## Audit log

The audit log is local and retained to the newest 10,000 rows. It records vault create, unlock
(failed attempts too), lock and master-password changes, key create, import, export, rename, delete
and deploy, category create and delete and a key's category assignment (renames, moves and reorders
write no row), server saves, deletes and tests, connections, host-key trust and forgetting, backups
and restores, Bitwarden and assistant settings saves, sync runs, errors and key renames (`sync.run`,
`sync.error`, `sync.key_renamed`), assistant execution and typing, MCP server additions, changes and
removals, tool calls, approvals and definition changes, and the clearing of the log itself
(`audit.cleared`). A credential allowed or declined in the native question
(`mcp.credential_allowed`, `mcp.credential_declined`, the latter noting an answer that came too
quickly), a declined API-key move (`assistant.key_move_declined`) and a Bitwarden destination
allowed or declined (`sync.destination_allowed`, `sync.destination_declined`, holding the host
only) are recorded too, never with the value. It is **selective**, not a complete event ledger. In
particular:

- general preferences changed through `settings_set` are not audited;
- a write that committed whose audit row then failed is reported as a success with a warning
  where the command can carry one (key, category, Bitwarden-settings, assistant and MCP changes);
  elsewhere the failure is only logged. Either way the change happened, so a missing row does not
  prove an action did not occur;
- an audit-write failure after a master-password rotation is logged, not returned.

The log itself is plaintext metadata in the database and can be cleared while unlocked. It is not
transmitted by SSHSpan.

## Dependency and build notes

- Renderer CSP keeps scripts self-hosted; xterm and addons are vendored and hash-checked.
- Release builds omit Tauri's `devtools` feature.
- HTTP uses reqwest with rustls/native roots and no OpenSSL dependency.
- CI runs formatting, clippy correctness, Rust tests, the renderer syntax, globals, vendor-hash,
  MCP-contract and comment-hygiene checks, the seven renderer suites, IPC argument checks,
  `cargo audit` (with a documented ignore for RUSTSEC-2023-0071), and the Rust tests and static
  checks on `windows-latest` (a job that passed on a runner for the first time on 2026-10-17, at
  `38e586e`; its next run, at `fd4765d`, failed one test, because a database read gave up behind a
  run of writes on the loaded runner, since fixed; it stays `continue-on-error`, so its failure does
  not fail the workflow, until it passes consistently).
- RUSTSEC-2023-0071 affects RSA PKCS#1 v1.5 decryption. SSHSpan uses RSA for signatures/auth, not
  attacker-controlled RSA decryption; there is no patched upstream version, so the risk is
  documented and monitored rather than described as eliminated.
- The renderer suites run in headless Chromium against stubbed IPC; they do not exercise WebView2
  or WebKitGTK, native dialogs, the tray, screen readers or real SSH, SFTP, Bitwarden or MCP
  servers.
- Test coverage at `6c19b1b`: renderer 92.9% of lines; Rust production code 72.0%, below the 80%
  target, because Tauri command code (10.8% of production lines) runs in no test. Details:
  [the audit report](audit/2026-10-09/REPORT.md#89-coverage).

## Operational guidance

- Use a unique, high-entropy master passphrase and full-disk encryption.
- Keep the idle timeout short enough for the machine's environment.
- Treat the database, backups, and deployed `sshspan_*` files as secrets.
- Add only the generated, quoted managed-config `Include` line; verify unusual `%`/glob paths with
  `ssh -G`.
- Treat AI providers and MCP servers as recipients of the data described in `PRIVACY.md`.
- Review the audit log, but do not use absence of a row as proof that no sync/settings action
  occurred.
- SSHSpan has not had a third-party security audit; read the accepted risks above before relying on
  it for secrets you cannot rotate.
