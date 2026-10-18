# SSHSpan privacy model

**Last updated:** 2026-10-18  
**Status:** describes v1.10.0; checked against committed source at `6c19b1b`, and
the passages edited since then at `b637fdc`; the code it describes is the same at both  
**Platforms:** Windows and Linux

SSHSpan collects no telemetry, analytics, advertising identifiers, or crash reports, and it has no
SSHSpan-operated cloud service. It is not "offline only": some features contact servers that the
user configures or starts, and two optional features can send substantial terminal and tool data
to third parties. This document describes the implementation, destination by destination, so the
user can decide which features to switch on.

## Outbound network traffic

| Feature | Destination | When | What can be sent |
| --- | --- | --- | --- |
| SSH / SFTP / Send-to | Hosts the user enters or selects | User connects, opens Files, transfers, or tests a server | Credentials selected for the connection, terminal input/output, file names and file contents the user transfers |
| Update check | `api.github.com` repository release metadata | At startup unless disabled in Settings, or manually | Source IP and User-Agent `SSHSpan-Update-Check`; no account identifier |
| Update download | `github.com/AGSQ11/SSHSpan/releases/download/...` and GitHub's validated asset redirect host | After the user starts an update | Ordinary HTTPS request metadata and User-Agent `SSHSpan-Update-Download`; installer and signature are downloaded |
| Bitwarden / Vaultwarden sync | The one HTTPS server configured by the user | Test connection, and Sync now once the user has allowed that server and account in a native question (saving the configuration also resolves the host name through DNS) | Account login, and the user's keys and saved servers as protocol-encrypted vault items (see below), request metadata |
| AI provider | User-configured provider base URL; the defaults are `https://api.openai.com/v1` and `https://api.anthropic.com` | Each assistant turn after the feature is configured and the user sends a message, and when the user presses "Save & test" | Chat history, session metadata, recent terminal text, tool definitions, tool results, API key as an authentication header; a connection test sends an authenticated request (a model-list request, or for Anthropic a one-token `ping` message) |
| MCP server | Each user-configured MCP URL | Test connection, tool discovery, calls, and session teardown (on removal, lock, exit and a URL or credential edit) | JSON-RPC traffic, tool arguments selected by the model/user, session id, configured static authentication |
| Terminal links | The site of a link the user confirms in the terminal | After the user answers the link question | The URL is handed to the operating system's default browser, which then contacts the site |

No other outbound destination is hard-wired in the source, apart from the base-URL presets the AI
settings offer (OpenAI, OpenRouter, Groq, Ollama and LM Studio on `localhost`, Anthropic), which
only fill the field: nothing is contacted until the user saves and tests the settings or sends a
message. The renderer's CSP and architecture route provider, MCP, Bitwarden, and updater requests
through Rust rather than page `fetch`. On Windows a server's key file is read only through a drive
letter (`C:\...`, `C:/...` or the verbatim `\\?\C:\...`). A path written as a share or a device
(`\\server\...`, `\\?\UNC\...`, `\??\...`, `\\.\...`), a path with any other prefix and a relative
path (`key`, `\key`, `D:key`) are never opened, so a key file path cannot make SSHSpan open a
connection to a file server by naming one. A drive letter is read like a local drive: if you
mapped it to a share, that read goes through your mapping to the file server.

## AI assistant data flow

The assistant is optional and off until a provider is configured and a chat turn is sent.
Per turn, the renderer sends the following to the provider through Rust:

- a system prompt with the current access level and rules;
- session metadata: saved server name, host, port, username, tab mode, and connection state;
- all stored chat history for that tab, including prior assistant text, tool calls, and tool
  results;
- a fresh untrusted snapshot of the tab's xterm buffer: up to the last **200 lines**, then capped to
  **8,192 characters**;
- definitions for the built-in tools (names, descriptions and input schemas) and for enabled MCP
  tools: the tool's name, a description made of its title, the server name and the tool name (the
  MCP server's own description is not sent), and its input schema;
- results returned by `get_terminal_output`, command execution, and MCP tool calls;
- the stored provider API key in the HTTP authentication header.

Terminal text can contain hostnames, usernames, command history, environment output, file
contents, tokens, or secrets that appear on screen. If an MCP tool is enabled, a model may also
place terminal-derived text in tool arguments that are sent to that MCP server, and the result is
fed back to the provider. SSHSpan wraps remote and MCP text as untrusted, but that does not
prevent disclosure to the configured provider.

SSHSpan does not persist assistant conversations or terminal snapshots in its database. They live
in renderer memory. Closing a tab, a vault lock and "New chat" clear a tab's conversation, and a
dropped session keeps its transcript on screen (in memory) but ends the running turn. The
provider's own retention, logging, and training policies are outside SSHSpan's control.

Provider requests follow no redirects and refuse credentials in the base URL, so the API key is not
forwarded to another origin; plain `http://` is accepted only for `localhost` and `*.localhost`
names and for loopback, private, link-local and IPv6 local addresses. A stored API key is never
silently reused for a different provider or address: saving the settings with a changed provider or
address and no new key asks a native question first (Esc means no; the default button is "Don't
allow" on Windows, and the GTK dialog on Linux sets none; an "Allow" within a second of
the dialog opening, or after the vault locked, is not taken; and only one such question is open at
a time; after a "Don't allow" or "Cancel", no further key move is asked about for 30 seconds,
whatever address it names), and a declined key move saves nothing and is audited as
`assistant.key_move_declined`.

The audit log can contain the first 200 characters of AI-executed commands (`assistant.exec`) and
AI-typed text (`assistant.type`). Treat the audit log as potentially sensitive.

### MCP

MCP traffic originates in Rust. A configured server can receive its auth header or environment-
variable-derived token, the negotiated session id, discovery requests, and calls the user approves
or enables for automatic approval/YOLO. HTTPS may reach any host; plain HTTP is accepted only for
loopback (`127.0.0.0/8`, `::1`, `localhost`). A URL with a `?query` or `#fragment` is refused.
Redirects are refused so an auth header is not carried to another origin. Locking the vault,
quitting the app, removing a server, or changing its URL or credential ends the live sessions with
authenticated `DELETE` requests to the endpoint each session was set up with; on a lock, a quit and
a URL or credential edit they are sent in the background (an exit waits up to two seconds for them),
while removing a server waits up to five seconds for its own `DELETE` and removes the record either
way.

A secret or environment variable is bound to an MCP address only after a native question that names
the host (and the variable) has been allowed (Esc means no; the default button is "Don't allow" on
Windows, and the GTK dialog on Linux sets none; an "Allow" within a second of the dialog
opening is not taken; and only one such question is open at a time; after a "Don't allow" or
"Cancel", no further MCP credential question is asked for 30 seconds, whatever server it names):
until then the server stays off and nothing is sent to it. SSHSpan records the answer as
`mcp.credential_allowed` or `mcp.credential_declined`, never with the value. An environment
variable's value is read at request time and sent as an authentication header to the confirmed
address only. The stored record is checked right before every request to a server except two kinds
(the `-32601` answers to the server's own requests inside an open response, and the session
`DELETE`s; see [SECURITY.md](SECURITY.md)), so a server that was switched off, edited or removed
while a request was out gets nothing more.

Tool descriptions and results are untrusted. A malicious or compromised MCP server can attempt
prompt injection and observe any arguments the assistant sends it. The backend does not check a tool
call's arguments for characters that disguise text; the approval card shows the arguments with
invisible characters spelled out (up to 1,500 characters as they are, a longer set shortened with
"Show all arguments (N characters)" to open the rest).

## Optional Bitwarden / Vaultwarden sync

When configured, SSHSpan contacts exactly the server URL entered by the user. HTTPS is required.
Plain HTTP, localhost, `.local`, private, loopback, link-local, and other reserved destinations
are refused, including after DNS resolution (not when the request goes through a system proxy,
which resolves the name itself; see [SECURITY.md](SECURITY.md#accepted-risks-and-limitations));
there is no localhost exception. Redirects are not followed.

Sensitive Bitwarden item fields are encrypted client-side before upload. Account authentication
and protocol metadata remain visible to the server. What a sync uploads, encrypted with the
Bitwarden protocol: for each key an SSH-key item (name, private and public key, fingerprint,
comment, and the key's category ids and paths in its notes), and for each saved server a Login
item (name, user name, the saved password if there is one, `ssh://host:port`, and notes holding the
local server id, the authentication method, the bound key's fingerprint and the server category id
and path). A sync also creates two folders in the vault, one for keys and one for servers (named
`SSHSpan_Keys` and `SSHSpan_Servers` unless the settings say otherwise), with encrypted names. The
stored Bitwarden master password is sealed with the SSHSpan vault password and is used only for the
server and account it was saved for. The Bitwarden configuration (the destination you allowed
included) and its sealed credential are **not** included in SSHSpan backups.

The sync uploads only to a server and account the user allowed. Saving a server URL or an account
email other than the allowed one stores the settings and then asks, in a native dialog ("SSHSpan -
Sync with Bitwarden?"), whether SSHSpan may upload the SSH private keys and saved server passwords
there; the question names the account, the server and the address (Esc means no; the default
button is "Don't allow" on Windows, and the GTK dialog on Linux sets none; an "Allow"
within a second of the dialog opening, or after the vault locked, is not taken; and only one such
question is open at a time). Before you allow the destination, nothing is uploaded and no sync
runs. Test connection, which you start yourself, still signs in to the server you typed and lists
what its vault holds, to check the settings, and uploads nothing. A restore cannot bring or confirm
a destination, because a backup carries no Bitwarden settings, and settings saved before this
question existed keep syncing: a one-time migration at the first start counts their destination as
allowed. SSHSpan audits each answer with the host, never the account, a password or a sealed
value. An "Allow" that is taken writes `sync.destination_allowed` with `host=<host>`. "Don't
allow", "Cancel", Esc or closing the dialog writes `sync.destination_declined` with
`host=<host>`. An "Allow" within a second counts as a refusal (the sync stays off) and writes
`sync.destination_declined` with `host=<host> answered=too-quickly`. No row is written for an
"Allow" that is not taken for another reason: after a lock, for settings that changed meanwhile,
during a master-password change, or when it cannot be stored. The account must be one email
address, and after "Don't allow" or "Cancel" no further question about uploading is asked for 30
seconds, whatever server or account it names; an "Allow" within a second starts no such wait.

A sync can pull changes too. Items that would overwrite a local server or key, or add a new one,
are listed by name and applied only after the user confirms; the names come from the remote items
and are shown locally. Each run writes `sync.run`, `sync.error` and `sync.key_renamed` audit rows
to the local audit log; they record counts, names and error text (cut to a fixed length), not
secrets.

## Data stored locally

`ProjectDirs::from("org", "sshspan", "SSHSpan")` is the path source of truth. The UI shows the
exact vault path in Settings > General.

| Data | Windows | Linux |
| --- | --- | --- |
| Vault database | `%APPDATA%\sshspan\SSHSpan\data\sshspan.db` | `~/.local/share/sshspan/sshspan.db` |
| Managed SSH config | `%APPDATA%\sshspan\SSHSpan\config\ssh\config` | `~/.config/sshspan/ssh/config` |
| Deployed key pairs | `%USERPROFILE%\.ssh\sshspan_<name>` and `.pub` | `~/.ssh/sshspan_<name>` and `.pub` |
| Edit-in-editor staging | `%TEMP%\sshspan-edit` | `<temp>/sshspan-edit`; mode 0700 |
| Updater downloads | `%TEMP%` as `sshspan-<version>-update-*` | `<temp>` as `sshspan-<version>-update-*`; an AppImage update is downloaded beside the running AppImage |

Linux honors XDG directory overrides. Settings are rows in the SQLite `config` table, not a
separate settings file. The project manifests support Windows and Linux only.

### What is protected in the database

- Private keys, saved server passwords, the Bitwarden master password, the AI provider API key,
  and MCP static auth secrets are sealed with the vault password.
- The master password is not stored; only an Argon2id verifier is persisted.
- Public keys, fingerprints, key names/comments, categories, server names/hosts/usernames,
  known-host pins, settings, SFTP bookmarks, transfer queue metadata and local/remote paths,
  Bitwarden non-secret configuration (including the allowed sync destination: the server URL and
  account email you allowed), the AI provider, base URL and model, MCP server URLs/tool
  definitions with their header and variable names, and audit rows are readable to anyone who can
  read the database file.
- Full-disk encryption is the physical-theft control for those readable fields.

### Backups and exports

Private-key exports and vault backups are chosen/written by native Rust dialogs and are written
with restricted permissions (see [SECURITY.md](SECURITY.md#secret-file-writes)); public-key exports
use the native save dialog too, so a cancelled dialog exports nothing. Every save dialog opens in
the Downloads folder (the home folder when there is none).
Private-key exports and backups are refused in system folders, in the places whose contents run at
login or when a program starts, in the folder settings (`user-dirs.dirs`, `user-dirs.locale`) and
in SSHSpan's own folders (`~/.ssh` stays allowed for them; see
[SECURITY.md](SECURITY.md)). A backup contains sealed keys, saved-server records, MCP server
records, known-host pins, categories, links, stored settings, and SFTP bookmarks. It excludes
Bitwarden sync configuration, the AI-provider configuration/API key, the audit log, and the
transfer queue.
Restored MCP servers are inert until reconfirmed. Exported/backup files are as sensitive as the
secrets inside them.

## Memory, clipboard, and lock behavior

While unlocked, the master password and decrypted material needed by active operations exist in
process memory. Locking clears the password store, kills SSH/SFTP sessions, pauses transfers,
stops edit watches and deletes their staged local copies on a best-effort basis, clears backend AI
levels, and ends MCP sessions. The renderer then removes terminal tabs, assistant conversations
and secret-field contents. Every exit - the tray's Quit, the Quit command, `Ctrl+Q`, an update
handing over to its installer - runs the same teardown.

The default idle lock is 15 minutes (`0` disables it) and is driven by real input, not remote
output. A warning shows 60 seconds before it, and a lock or quit started in the window asks first
while sessions or transfers are live (the tray's Lock and Quit and the idle lock do not).

SSHSpan copies public keys, configuration text, paths, and URLs to the clipboard when the user asks,
and copies a terminal selection when text is selected (PuTTY-style). It does not intentionally place
private key material on the clipboard. The assistant can read terminal text already in the xterm
buffer. Pasted text is stripped of control characters other than tab, carriage return and line feed
before it reaches the terminal.

## Audit log and local history

The audit log is stored locally, never transmitted by SSHSpan, retained to the newest 10,000 rows,
and clearable while unlocked. It records selected vault, key, deployment, server, connection,
host-key, backup, Bitwarden sync, assistant, and MCP actions. It does not record general preferences
changed through `settings_set`, so absence of a row is not proof that an action did not occur; a
change that committed but whose audit row could not be written is reported as a success with a
warning where the command can carry one, and only logged elsewhere.

The renderer keeps terminal scrollback and assistant transcripts only in memory. SFTP queue state is
persisted so interrupted transfers can be restored as paused after restart.

## User controls

- Leave the AI assistant and MCP unconfigured. Remove a stored API key ("Remove stored key") or
  an MCP server in Settings.
- Disable the GitHub update check in Settings (`autoUpdateCheck`). The update-install confirmation
  is a renderer dialog and is not independently re-verified by the backend.
- Use a shorter idle lock timeout.
- Keep Bitwarden sync disabled unless needed.
- Choose export/backup locations deliberately and delete files you no longer need.
- Remove deployed `~/.ssh/sshspan_*` files and managed config stanzas with "Remove deployed copy"
  in the key pane, or manually.
- To erase all local SSHSpan state after closing the app, remove the platform data/config
  directories listed above plus the edit staging folder (`<temp>/sshspan-edit*`), any
  `sshspan-<version>-update-*` installers still in the temp folder, the webview profile
  (`org.sshspan.app`, on Windows the WebView2 user-data folder) and any deployed keys, exports, and
  backups you created.

## Children and sensitive data

SSHSpan is not designed for children and does not profile users. It stores the data the user brings
into it and any metadata generated by actions the user takes.

## Changes

This privacy model describes code, not a promise that can change without a release. Any new
telemetry or outbound destination should update this document in the same change.
