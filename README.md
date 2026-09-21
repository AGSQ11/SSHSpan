<p align="center">
  <img src="assets/sshspan-readme-hero.svg" alt="SSHSpan - encrypted SSH key management" width="100%">
</p>

# SSHSpan

Cross-platform SSH key manager, SSH client, and SFTP file transfer tool for the desktop -
built on **Rust + Tauri v2**.

SSHSpan gives you a single, encrypted home for every SSH key you own, a PuTTY-grade terminal
to use them, and a FileZilla-style file browser over the same live connection. Generate new
keys, import existing ones, organize keys and servers into separate category trees, deploy
keys into `~/.ssh/config`, connect to your servers, and move files - all from one
keyboard-friendly app. Private keys are encrypted at rest with AES-256-GCM behind a master
password; the master password itself lives only in memory and auto-locks after 15 minutes of
inactivity (locking also disconnects every live SSH session and stops every transfer).

All sensitive logic - crypto, vault, database, SSH, SFTP - runs in a compiled **Rust** core.
The UI is vanilla HTML/CSS/JS in your OS webview: no Electron, no bundled Chromium, no Node
runtime. The Windows installer is ~9 MB. Everything runs locally: no cloud, no telemetry.
The only network traffic is the update check against GitHub (on by default, disableable in
Settings) and, if you enable it, Bitwarden sync - which talks only to the server you
configure. Auto-updates are minisign-signature-verified and fail closed.

## What's new

- **v1.9.0** - Audit remediation and the AI assistant backend. Two critical defects
  fixed: Bitwarden sync aborted every healthy run with a bogus "vault was locked"
  error (an inverted flag in the lock gate), and restoring a backup silently dropped
  each server's Bitwarden linkage - the next sync then pushed duplicates of every
  server into the vault (a SQL INSERT that bound 17 values against 14 placeholders,
  which sqlx swallows without erroring). Also: a vault lock racing an in-flight SFTP
  open no longer leaves a live channel behind, right-click at the prompt no longer
  pastes unconfirmed multi-line clipboard contents (and no longer double-pastes via
  the context menu), "Restart session" on a live tab no longer doubles every
  keystroke and loses close-detection, window resizes no longer steal focus from
  dialogs, the wheel no longer prints `^[[A^[[A` garbage inside `screen`/`tmux`,
  Split mode no longer half-disables the file browser, "Confirm before deleting a
  key" and the update-check opt-out actually take effect now, and the keyboard
  compatibility settings (rxvt Home/End, application cursor keys, keypad) are
  finally enforced. The AI assistant's Rust backend lands in this release (provider
  proxy for [OI]- and Anthropic-compatible servers, vault-sealed API key, per-tab
  access levels with a server-side execution gate and audit logging); its panel
  ships separately.
- **v1.8.0** - UX pass over the whole renderer. The navigation is two objects (Keys,
  Servers) plus Settings: Deploy is now an action on the keys you have selected rather
  than a destination you visit afterwards, and the audit log is a Settings section. A Ctrl+K
  command palette searches keys, servers and categories and runs actions. The key list
  leads with each key's comment instead of its fingerprint, export moves to its own tab
  with a per-format Secret/Sealed/Public marker and a passphrase field that appears only
  when the format uses one, sessions gain a Shell/Files/Split surface control, the remote
  path is a clickable breadcrumb, and Settings is sectioned with one toggle component
  throughout. Two bugs fixed along the way: the search box did nothing in the default
  grouped key view, and the deploy preview joined its lines on a literal `\n`.
  Also in this release: the Send-to folder scan is bounded by progress rather
  than a flat 120s cap, and rustls is bumped to 0.23.45 for RUSTSEC-2026-0285.
- **v1.7.3** - Security release resolving a full source audit: the renderer-to-native
  executable-staging chain is closed, a vault lock now revokes in-progress connects/exports/
  syncs (not just live sessions), master-password rotation is atomic and covers the
  Bitwarden credential, download resume can no longer follow a planted `.part` symlink,
  recursive uploads re-check every descendant, backups no longer import local deletion
  paths, the updater resolves the signature from the right URL and binds the version to the
  asset, and Bitwarden Argon2id now matches the official client. Plus the SFTP queue's
  pause/resume, auto-retry, throttle, persistence, and integrity verification, richer remote
  listings, and a round of renderer/UI fixes.
- **v1.7.2** - Signed auto-updates (minisign-verified installers, fail-closed), consent-based
  host-key trust with strict refusals, private-key export straight to a file (never through
  the UI process), brute-force backoff, hardened staging and paths, plus the SFTP
  FileZilla-parity set: resumable transfers, conflict dialogs, directory comparison with
  synchronized browsing, drag & drop, and timestamp preservation.
- **v1.7.1** - Security patch: real PBES2 PKCS#8 export, SSRF and data-loss fixes, a verified
  auto-update path, and an XSS fix.
- **v1.7.0** - PuTTY-style terminal utilities: right-click terminal/tab context menu, copy
  all, paste confirmation, duplicate/restart sessions, configurable scrollback, bell
  behavior, keyboard compatibility settings, SSH keepalive, and normal remote Tab
  completion through an explicit `TERM=xterm-256color` + UTF-8 PTY setup.
- **v1.6.0** - Separate key and host categories: the Keys view and the Hosts/Connect view
  each get their own category tree with independent recursive filters and uncategorized
  counts. Scope is enforced everywhere (assignments, parents, backup/restore) and syncs to
  Bitwarden under a separate `Hosts-` namespace. Plus a compact, keyboard-accessible
  category picker.
- **v1.5.0** - SFTP reaches FileZilla parity: background transfer queue, dual-pane browsing,
  chmod dialog, recursive search, per-server bookmarks, multi-select, sorting, remote disk
  usage, and SFTP keep-alive.
- Full history in the [changelog](CHANGELOG.md).

## Screenshots

A quick tour of the desktop UI. These predate the UX pass described under *What's new* -
Deploy is now a sheet over the key list and the audit log is a Settings section, so those
two shots no longer match a view you can navigate to.

<table>
  <tr>
    <td width="50%"><img src="screenshots/keys-view.png" alt="SSHSpan key management view"></td>
    <td width="50%"><img src="screenshots/ssh-view.png" alt="SSHSpan embedded SSH terminal"></td>
  </tr>
  <tr>
    <td align="center"><strong>Keys and categories</strong><br>Manage encrypted keys in scoped category trees.</td>
    <td align="center"><strong>Embedded SSH client</strong><br>Connect with a saved server and use the integrated terminal.</td>
  </tr>
  <tr>
    <td width="50%"><img src="screenshots/sftp-view.png" alt="SSHSpan SFTP dual-pane file browser"></td>
    <td width="50%"><img src="screenshots/deploy-view.png" alt="SSHSpan SSH deployment view"></td>
  </tr>
  <tr>
    <td align="center"><strong>SFTP file browser</strong><br>Browse remote files, use the dual-pane view, and queue transfers.</td>
    <td align="center"><strong>SSH deployment</strong><br>Preview and manage generated SSH config entries.</td>
  </tr>
  <tr>
    <td width="50%"><img src="screenshots/audit-view.png" alt="SSHSpan audit log view"></td>
    <td width="50%"><img src="screenshots/settings-view.png" alt="SSHSpan settings view"></td>
  </tr>
  <tr>
    <td align="center"><strong>Audit log</strong><br>Review an append-only record of sensitive vault and connection actions.</td>
    <td align="center"><strong>Settings</strong><br>Configure transfer concurrency and other desktop preferences.</td>
  </tr>
</table>

## Features

### Keys
- **Generate** - RSA (3072-8192 bits), Ed25519, ECDSA (nistp256/384/521), via the audited
  `ssh-key` Rust crate.
- **Import** - browse or paste: OpenSSH private (incl. passphrase-protected), PKCS#8 PEM,
  PEM public, `authorized_keys` lines, and PuTTY `.ppk` **v3 and legacy v2**
  (passphrase-protected too).
- **Export** - OpenSSH new-format private, PuTTY `.ppk` v3, PKCS#8 PEM (plain or encrypted),
  SPKI PEM public, `authorized_keys` lines. Legacy v2 `.ppk` imports are written back as v3.
- **Encrypted vault** - AES-256-GCM envelopes; the master password is never stored.

### Categories
- Two independent trees: **key categories** for keys, **host categories** for saved servers -
  any depth, many-to-many, drag-and-drop in the sidebar, breadcrumbs, grouped lists, and a
  shared multi-select picker with search and full keyboard navigation.
- The Keys view and Hosts view each filter through their own tree, with explicit
  "uncategorized" entries and live counts.
- Both trees **sync with Bitwarden**: key categories are encoded into cipher `notes`, host
  categories travel under a separate `Hosts-` namespace, so two SSHSpan installs (or a
  reinstall) converge on the same structure.

### Servers - embedded SSH client
- **Saved servers** with per-server username + SSH-key binding; optional password storage
  (sealed with your vault master, unsealed only in-process at connect time).
- **Interactive terminal** (xterm.js + the `russh` Rust SSH library): full ANSI colors,
  configurable scrollback, resizable grid, explicit UTF-8 PTY, and `TERM=xterm-256color`.
- **PuTTY behaviors**: select text to copy instantly, right-click terminal/tab menu,
  Copy All, paste with optional multi-line confirmation, Ctrl+Shift+C/V, duplicate and
  restart sessions, clear/reset terminal, visual or sound bell, keyboard compatibility
  settings, and optional SSH keepalive.
- **Host-key pinning** - the first connection to a host asks for explicit confirmation;
  the backend refuses unpinned hosts without it (a `StrictHostKeyChecking=yes` equivalent).
- **Shell, Files or Split** - a session shows the terminal, the file browser, or both side
  by side; the control is labelled with the surface you are on, not the one you would
  switch to.
  Any later fingerprint change is refused and recorded in the audit log.
- **Right-click any key -> "Use this key to connect..."** - pick a saved server (its username
  + your clicked key) or create a new server pre-filled with that key.
- **Vault-gated**: locking the vault immediately disconnects every live session.
- Test button per server (open -> authenticate -> close, with latency).

### AI assistant (optional, off by default)
An [OI]-compatible or Anthropic-compatible chat panel docked beside the terminal
(`Ctrl+Shift+A`), configured under Settings -> AI assistant with your own provider and API
key (works with [OI], OpenRouter, Groq, Anthropic, and local servers like Ollama or LM
Studio). It can read the live terminal and help with server administration; what it is
allowed to do is a per-tab choice, shown on a color-coded control at the top of the panel:
- **Read** - advise only: sees the terminal, answers, and proposes commands as cards you
  can insert or run yourself. It cannot touch the session.
- **Draft** - may also type into your prompt line, but never presses Enter.
- **Execute** - may run commands, each one behind an Approve/Deny card.
- **YOLO** - runs commands without asking, behind a deliberately scary opt-in dialog and a
  persistent red badge. Full autonomous control of the session - use with care.

The API key is sealed with your vault master password like every other secret, all
provider traffic goes through the Rust backend (nothing is fetched from the page), every
AI-executed command is written to the audit log, and the backend independently re-checks
the access level before anything reaches the SSH channel.

### SFTP - embedded file transfer
Runs over the same live SSH connection as the terminal - no second login, no extra port:
- **Background transfer queue** - uploads and downloads run on dedicated SFTP channels, so
  browsing stays responsive while transfers stream progress, speed, cancel/retry, and
  Queued/Failed/Done tabs. Directories expand recursively in both directions; four transfers
  run in parallel by default (1-4 configurable).
- **Dual-pane mode** - optional local pane with a draggable splitter; drag or double-click a
  local file to upload, double-click folders to navigate, drop files from your OS onto the
  remote pane, and manage the local side directly (new folder, rename, delete, open in your
  file manager).
- **Resumable transfers** - interrupted uploads and downloads continue from verified partials
  (atomic `.part` staging, so a crash never leaves a corrupt "complete" file); per-transfer
  conflict handling with Ask/Overwrite/Skip/Rename/Resume and persistable defaults.
- **Compare & synchronized browsing** - diff the local and remote panes and keep them in step;
  file timestamps can be preserved across transfers.
- **File permissions** - chmod dialog with an owner/group/other read/write/execute grid,
  live octal sync, recursion, and files/directories/all targeting.
- **Recursive remote search** - case-insensitive search across the current directory tree
  with live-streaming results; click a result to jump to its folder.
- **Per-server bookmarks** - save remote (and local) directories via the toolbar star and
  return in one click.
- **File-manager ergonomics** - multi-select (Ctrl-click, Shift-click, Ctrl+A), sortable
  Name/Size/Modified columns, hidden-dotfile toggle, context menu (download, delete, chmod,
  new file, copy path, copy `sftp://` URL), double-click to open or enqueue.
- **Remote disk usage** - free/total space via `statvfs@openssh.com` beside the path bar,
  hidden automatically when the server lacks support.
- **Keep-alive** - a 30-second round-trip keeps idle sessions alive through NATs and
  firewalls; stopped on close, disconnect, or vault lock.
- **Per-tab activity log** - timestamped connect/transfer/chmod/search/delete events.

### Sync & deploy
- **Bitwarden / Vaultwarden sync (optional)** - mirror keys to SSH-key items in your own
  vault, two-way, deletions never propagated; works with getbitwarden.com and self-hosted
  Vaultwarden (SSRF-hardened server URL validation).
- **Deploy to SSH** - select keys in the Keys view and a selection bar offers Deploy; the
  sheet opens over the list with those keys already in it and a preview that updates as you
  type. Writes to `~/.ssh/sshspan_<name>` (owner-only permissions from the moment of
  creation) and manages reversible `Host` blocks in SSHSpan's managed SSH config.
- **Backup and restore** - full vault backups (keys, servers, both category trees) to a
  single encrypted file, restorable only with the master password current at backup time.

### Trust & ops
- **Audit log** - local record of every sensitive action (key lifecycle, vault
  lock/unlock, connects, server changes, backups), exportable as CSV and clearable from
  Settings. Retains the newest 10,000 entries. Lives under Settings.
- **Signed auto-updates** - installers are downloaded only from this repository over HTTPS,
  verified against a SHA-256 digest *and* a minisign signature whose public key is embedded
  in the app; a missing or invalid signature refuses the update.
- **Small & fast** - ~9 MB Windows installer, ~16 MB Linux packages; no Chromium, no Node
  runtime. DevTools are compiled out of release builds.

## Installation

### From a release (recommended)
Grab the latest installer from [Releases](https://github.com/AGSQ11/SSHSpan/releases) -
current release is **v1.7.3**:

| Platform | Files |
| --- | --- |
| Windows | `SSHSpan_1.7.3_x64-setup.exe` (NSIS, per-user) · `SSHSpan_1.7.3_x64_en-US.msi` (system-wide) |
| Linux | `SSHSpan_1.7.3_amd64.deb` · `SSHSpan-1.7.3-1.x86_64.rpm` |

### Build from source
Prerequisites: [Rust](https://rustup.rs) (stable), Node.js >= 18 (for the Tauri CLI), and on
Linux the Tauri system dependencies (`libwebkit2gtk-4.1-dev`, `libgtk-3-dev`,
`libayatana-appindicator3-dev`, ...).

```bash
npm install
npm run tauri dev      # run in development
npm run tauri build    # produce installers in src-tauri/target/release/bundle/
```

Windows builds: `npm run dist:win` · Linux builds: `npm run dist:linux`.
Rust tests: `cargo test --manifest-path src-tauri/Cargo.toml`.

## Architecture (in one paragraph)

A **Tauri v2** app: a Rust binary (`src-tauri/`) owns the SQLite vault (sqlx), all
cryptography (`ssh-key`, `argon2`, `aes-gcm`, `minisign-verify`, the `russh` SSH + SFTP
engines), the Bitwarden client, and the updater; the webview UI (`src/renderer/`) is plain
HTML/CSS/JS that talks to Rust through typed IPC commands. Decrypted private key material
stays inside Rust processes - even exports are written to disk by the backend - and never
crosses the IPC boundary into the UI. The full Node.js -> Rust migration story,
per-version changelog, and engineering notes live in
[`docs/REWRITE-ROADMAP.md`](docs/REWRITE-ROADMAP.md); the process/module layout
is in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Security

Private keys are encrypted at rest (AES-256-GCM, Argon2id key derivation) and only ever
decrypted in-process. The master password is never persisted - only a verification hash.
Host keys are pinned on first use after an explicit trust prompt. See
[docs/SECURITY.md](docs/SECURITY.md) and [docs/PRIVACY.md](docs/PRIVACY.md).

## License

MIT - see [LICENSE](LICENSE).

## Disclaimer

SSHSpan is a personal project. It was built for my own use, and published under MIT
in case it is useful to someone else.

**It has not had a third-party security audit.** It handles private keys,
passphrases and server credentials, so understand what that means before you
point it at anything you care about.

If you intend to rely on it, read the source first or build from it. If you
find something wrong, open an issue - that is more useful to everyone than a
disclaimer is.

## Project statistics

<p align="center">
  <a href="https://github.com/AGSQ11/SSHSpan/releases">
    <img src="https://img.shields.io/github/downloads/AGSQ11/SSHSpan/total?style=flat-square&label=Release%20downloads" alt="Total release downloads">
  </a>
  <a href="https://github.com/AGSQ11/SSHSpan/releases/latest">
    <img src="https://img.shields.io/github/downloads/AGSQ11/SSHSpan/latest/total?style=flat-square&label=Latest%20release" alt="Latest release downloads">
  </a>
  <a href="https://github.com/AGSQ11/SSHSpan/stargazers">
    <img src="https://img.shields.io/github/stars/AGSQ11/SSHSpan?style=flat-square&label=Stars" alt="GitHub stars">
  </a>
  <a href="https://github.com/AGSQ11/SSHSpan/forks">
    <img src="https://img.shields.io/github/forks/AGSQ11/SSHSpan?style=flat-square&label=Forks" alt="GitHub forks">
  </a>
  <img src="https://hits.sh/github.com/AGSQ11/SSHSpan.svg?style=flat-square&label=README%20views" alt="README views">
</p>
