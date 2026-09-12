# SSHSpan privacy model

SSHSpan is a local-first application. This document describes what data the app collects, where
it is stored, who can access it, and what choices the user has. It describes the current
Rust/Tauri implementation (v1.7.x); every claim here is a property of the code, not a policy.

## Data collected

SSHSpan collects **no telemetry and no usage data**. There is no analytics SDK and no crash
reporter. The app does not profile user behaviour and cannot be contacted by any server.

There are exactly **two kinds of outbound network requests** the app can make, nothing else:

1. **Update check (on by default, can be turned off).** When the app starts it asks GitHub's
   releases API (`api.github.com/repos/AGSQ11/SSHSpan/releases/latest`) whether a newer
   version exists. The request carries a generic User-Agent (`SSHSpan-Update-Check`) and no
   account identifiers; GitHub sees the request's source IP and that header. Nothing beyond
   that is sent. If — and only if — a new version exists **and the user explicitly approves
   the update in the app's dialog**, the installer is downloaded from
   `github.com/AGSQ11/SSHSpan/releases/download/…` (pinned to this repository), verified
   against a SHA-256 digest and a minisign release signature, and the OS installer is
   launched. The setting is `autoUpdateCheck` in Settings.
2. **Bitwarden/Vaultwarden sync (off until configured).** Described below. The user must
   explicitly configure a server URL, account email, and password before any connection is
   made.

The only data the app processes is data the user explicitly brings into it:

- SSH key pairs the user generates, imports, or exports;
- the master password the user chooses to protect the vault;
- SSH host aliases, saved servers, and known-host pins the user creates;
- settings the user changes in the Settings view;
- an audit log of actions taken inside the app.

## Where data is stored

Everything is stored on the local machine, in the user's profile:

| Path | Contents | Protected by |
| --- | --- | --- |
| Windows `%APPDATA%\SSHSpan\sshspan.db` / Linux `~/.local/share/SSHSpan/sshspan.db` / macOS `~/Library/Application Support/SSHSpan/sshspan.db` | SQLite database: keys, saved servers, known-host pins, settings, audit log | User-profile ACLs; private-key column and saved server passwords encrypted with the master password |
| `~/.ssh/sshspan_<key-name>` (+ `.pub`) | Deployed SSH private/public keys | 0600 permissions from creation (POSIX) / current-user-only ACL via `icacls` (Windows) |
| App config dir `ssh/config` (e.g. `%APPDATA%\SSHSpan\ssh\config`) | SSHSpan's managed SSH config (Host aliases for deployed keys) | User-profile ACLs |

No data is stored in the cloud and no third party receives any of it, unless the user
enables the optional sync below.

## Optional Bitwarden / Vaultwarden sync

If (and only if) the user enables it in Settings, SSHSpan mirrors SSH key items to the
user's own Bitwarden-compatible vault:

- **Destination.** Exactly one destination: the server URL the user configured
  (e.g. their own Vaultwarden instance or Bitwarden cloud). Plain `http://` is refused
  except for loopback targets (self-hosted testing); everything else must be HTTPS. The app
  refuses to connect to localhost, LAN, or otherwise private/reserved addresses (IPv4 and
  IPv6, including IPv4-mapped forms), and re-filters DNS answers at connection time to
  defeat DNS rebinding — so the destination is a user-controlled public server.
- **What is sent.** SSH key vault items whose sensitive fields (private key, public key,
  fingerprint, name) are encrypted client-side with the Bitwarden protocol before they
  leave the machine; the server only ever receives ciphertext. No telemetry, identifiers,
  or metadata beyond the protocol's own account authentication are transmitted. Redirects
  are never followed.
- **What is stored locally in addition.** The sync configuration (server URL, account
  email, folder name) and the Bitwarden master password — the latter only in a form
  AES-256-GCM-encrypted with the SSHSpan vault master password, so it is unreadable on
  disk and only usable while the vault is unlocked.
- **What is never done.** No automatic deletion on either side, no sharing to
  organizations, no third-party endpoints, no analytics about sync usage. Remote
  overwrites and new imports are confirmed with the user before they happen.

The feature is off unless configured, and every sync action is recorded in the local audit
log.

## Who can access the data

Access is governed entirely by the local operating system and by the vault master password:

- **The user** knows the master password and can unlock the vault to view and manage keys.
- **Anyone with the master password** can unlock the vault and access every private key in it.
- **Anyone with local filesystem access to the machine** can read the database file and the
  deployed key files, subject to file permissions and, if the vault is locked, the
  AES-256-GCM encryption of the private-key column.
- **GitHub** sees the update-check request described above (source IP, generic User-Agent)
  and receives no user data.
- **The configured Bitwarden server** (only when sync is enabled) receives vault ciphertext
  and account authentication, never plaintext key material.

## User choices

The user controls the following privacy-relevant behaviour:

- **Master password.** The user chooses it; it is never transmitted or stored in recoverable
  form (only an Argon2id verification hash is persisted).
- **Update check.** On by default; turn it off in Settings (`autoUpdateCheck`). Even when
  on, no installer is downloaded or run without an explicit user approval in the dialog.
- **Auto-lock timeout.** Configurable in Settings; locking removes the master password from
  memory and kills live SSH/SFTP sessions.
- **Which keys to deploy.** Deploy writes a private key to `~/.ssh/sshspan_<name>` and a
  Host alias into SSHSpan's managed SSH config. This is a local file operation; SSHSpan
  contacts a remote host only when the user explicitly connects (terminal/SFTP/Connect) or
  tests a server.
- **Whether to export private keys at all.** Exports require an unlocked vault and are
  logged to the audit log. Exported files can be encrypted with an independent passphrase
  (OpenSSH, PKCS#8/PBES2, or PuTTY PPK formats).
- **Clipboard.** The app's key views copy public key material. Private key material is
  never placed on the clipboard by SSHSpan (a user-selected region in the terminal is, of
  course, whatever the user selected).
- **SSH/SFTP connections.** The embedded SSH client connects only to hosts the user
  explicitly connects to. Host keys are pinned per `host:port` on first connection and any
  later mismatch is a hard failure, recorded in the audit log.

## Audit log

Every security-relevant action is recorded in the `audit` table and viewable from the Audit
log view: key creation, update, deletion, import, export, deployment, vault creation, unlock
(failed and successful), lock, password change, backup create/restore, known-host trust
changes, sync actions, and settings changes. Each entry records the timestamp and a detail
string. The audit log is stored locally in the database file and is never transmitted.

## Children and sensitive data

SSHSpan is not designed for and does not collect data from children. The app stores only the
data the adult user explicitly provides. There is no profile of user behaviour, no
advertising, and no marketing.

## Changes to this policy

SSHSpan stores everything locally and the two network exceptions above are visible in
Settings. This privacy model is a property of the code, not a policy that can change without
a new release. Any change that introduces data collection, additional network access, or
telemetry would require an explicit, visible change to the app and a revision of this
document.
