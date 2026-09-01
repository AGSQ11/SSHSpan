# SSHSpan privacy model

SSHSpan is a local-only application. This document describes what data the app collects, where
it is stored, who can access it, and what choices the user has.

## Data collected

SSHSpan collects **no telemetry and no usage data**. There is no analytics SDK, no crash
reporter, no update checker, and no network code of any kind. The app does not phone home,
does not contact any server, and cannot be contacted by any server.

The only data the app processes is data the user explicitly brings into it:

- SSH key pairs the user generates, imports, or exports;
- the master password the user chooses to protect the vault;
- SSH configuration the user writes or that the app deploys to `~/.ssh/config`;
- settings the user changes in the Settings view;
- an audit log of actions taken inside the app.

## Where data is stored

Everything is stored on the local machine, in the user's home directory:

| Path | Contents | Protected by |
| --- | --- | --- |
| `~/.sshspan/sshspan.db` | SQLite database: keys, settings, audit log | 0600 file permissions; private-key column encrypted with the master password |
| `~/.sshspan/keys/<key-id>` | Deployed SSH private keys | 0600 permissions (POSIX) / current-user-only ACL via `icacls` (Windows) |
| `~/.ssh/config` | SSH client config, with managed Host blocks | User's home directory ACLs |
| `~/.ssh/authorized_keys` (if used) | Public keys the user chooses to install | User's home directory ACLs |

No data is stored in the cloud. No data is transmitted off the machine. No third party receives
any of it.

## Who can access the data

Access is governed entirely by the local operating system and by the vault master password:

- **The user** knows the master password and can unlock the vault to view and manage keys.
- **Anyone with the master password** can unlock the vault and access every private key in it.
- **Anyone with local filesystem access to the machine** can read the database file and the
  deployed key files, subject to 0600 permissions and, if the vault is locked, the
  AES-256-GCM encryption of the private-key column.
- **No remote party** can access the data, because the app makes no network connections.

## User choices

The user controls the following privacy-relevant behaviour:

- **Master password.** The user chooses it; it is never transmitted or stored in recoverable
  form (only a scrypt verification hash and salt are persisted).
- **Auto-lock timeout.** Configurable in Settings; the vault locks after a period of idle
  time (default 15 minutes), removing the master password from memory.
- **Which keys to deploy.** `keys:deploy` writes a private key to `~/.sshspan/keys/<key-id>`
  and updates the managed block in `~/.ssh/config`. The user chooses the target host, user,
  and port for each Host block. SSHSpan never contacts remote hosts; installing the public
  half into a remote `authorized_keys` is left to the user.
- **Whether to export private keys at all.** Exports require an unlocked vault and are
  logged to the audit log. Exported files can be encrypted with an independent passphrase.
- **What is written to the clipboard.** The app only exposes `clipboard:write-public`, which
  writes the public key. Private key material is never copied to the clipboard.
- **SSH config path.** The app writes to `~/.ssh/config` by default; the path is configurable
  in Settings, so the user can redirect managed Host blocks elsewhere.

## Audit log

Every security-relevant action is recorded in the `audit` table and viewable from the Audit
log view: key creation, update, deletion, import, export, deployment, vault creation, unlock,
lock, password change, and settings changes. Each entry records the timestamp and a JSON
detail object. The audit log is stored locally in the database file and is never transmitted.

## Children and sensitive data

SSHSpan is not designed for and does not collect data from children. The app stores only the
data the adult user explicitly provides. There is no profile of user behaviour, no
advertising, and no marketing.

## Changes to this policy

Because the app is fully offline and stores everything locally, this privacy model is a
property of the code, not a policy that can change without a new release. Any change that
introduces data collection, network access, or telemetry would require an explicit, visible
change to the app and a revision of this document.
