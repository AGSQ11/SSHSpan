# Changelog

All notable changes to SSHSpan are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.5.0] - 2026-09-07

Feature release bringing the SFTP client to FileZilla parity: a background
transfer queue, dual-pane browsing, remote file permissions, recursive search,
per-server bookmarks, multi-select, and more.

### Added

- **Background transfer queue** — uploads and downloads run on dedicated SFTP
  channels over the live SSH connection, so browsing stays responsive during
  transfers. Queued/Failed/Done tabs with per-job progress bars, transfer
  speed, cancel and retry, aggregate status, and clear-finished. Two transfers
  run in parallel by default; configurable 1–4 in Settings. Double-clicking a
  remote file enqueues a download to the last-used directory; "Download as…"
  keeps the save dialog. Directory transfers expand recursively in both
  directions.
- **File permissions (chmod)** — dialog with an owner/group/other read/write/
  execute grid, live two-way octal sync, recursion, and files/directories/all
  targeting. Prefilled from the server's current mode.
- **Recursive remote search** — inline search bar over the current directory
  tree (case-insensitive, 500-result cap, depth-limited); results stream in
  live and clicking one navigates to its folder.
- **Per-server bookmarks** — save the current remote (and local) directory as
  a named bookmark via the toolbar star; one click navigates; right-click
  removes.
- **Dual-pane mode** — optional local pane alongside the remote listing with
  a draggable splitter. Drag a local file onto the remote pane (or
  double-click it) to enqueue an upload; double-click local folders to
  navigate. OS drag-and-drop onto the remote pane continues to upload.
- **Multi-select** — Ctrl-click, Shift-click ranges, Ctrl+A, and empty-area
  click to clear. Context-menu actions (download, delete, chmod) apply to the
  whole selection with batch-aware labels and a single confirmation.
- **Sortable columns** — Name/Size/Modified headers with ascending/descending
  indicators; directories always group first.
- **New file** — create an empty remote file from the context menu (refuses
  to overwrite an existing path).
- **Remote disk usage** — free/total space via `statvfs@openssh.com` shown
  beside the path bar; hidden automatically when the server lacks support.
- **Per-tab activity log** — timestamped connect/transfer/chmod/search/delete
  events, 200-line cap, failures mirrored into it.
- **SFTP keep-alive** — a 30-second round-trip keeps idle sessions alive
  through NATs and firewalls; stopped automatically on close, disconnect, or
  vault lock.
- **Settings** — parallel transfer count (1–4), show-hidden-files default,
  and the dual-pane preference persists across sessions.
- Context menu: Copy path, Copy `sftp://` URL, Select all, Download as….

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

- **Connect — embedded SSH client** (russh 0.63 + xterm.js 5.5, both vendored/offline):
  - Saved servers with per-server username + SSH-key binding, auth methods
    (publickey / password / keyboard-interactive), optional password sealed with the vault
    master, latency test, last-connected tracking.
  - Interactive PTY terminal: full ANSI colors, 5000-line scrollback, live resize
    (incl. maximize-to-app with a floating `<>` toggle and `Esc` restore).
  - PuTTY behaviors: select-to-copy, right-click paste, Ctrl+Shift+C/V, blinking block cursor,
    solid accent selection highlight.
  - TOFU host-key pinning (`known_hosts` table); mismatch refuses the connection.
  - Right-click any key → **"Use this key to connect…"** (server's username + clicked key).
  - Vault-gated: locking the vault disconnects every live session.
  - Audit events: `connect.start/stop`, `server.save/delete`, `server.test_ok/fail`,
    `known_hosts.forget`.

### Changed

- **Backend rewritten from Node.js to Rust** (Tauri v2): crypto (`ssh-key`, AES-256-GCM +
  bcrypt-pbkdf2 vault sealing), SQLite via sqlx (same vault file, in-place migration),
  Bitwarden/Vaultwarden client (expand-only HKDF, Vaultwarden client-version gate,
  SSRF-safe URL validation), SSH deploy, and `~/.ssh/config` management.
- Renderer unchanged in spirit (plain HTML/CSS/JS, strict CSP, vendored xterm.js, generated
  Lucide icon sprite); DevTools enabled in release (the UI holds no secrets).
- Installers shrink from ~150 MB (Electron) to ~9 MB (NSIS).
- Removed the legacy Node/Electron backend (`src/main/`, Node test harnesses); Rust unit tests
  live in `src-tauri` (`cargo test`).

## [1.2.0] - 2026-09-02

### Added

- Import legacy PuTTY **version 2** `.ppk` files (PuTTY 0.52–0.74), encrypted or
  not, for all supported key types. v2 uses a SHA-1 based KDF and HMAC-SHA-1,
  which is weak but mandated by that format; it is accepted for **import only**,
  and exporting a v2 key writes the current **v3** format, so importing one
  quietly upgrades it.

## [1.1.1] - 2026-09-02

### Added

- Import keys from a file, not only by pasting: the Import tab has a
  "Browse for key file…" button that opens a native file picker
  (`.ppk`, `.pem`, `.key`, `.pub`, `.txt` and all files). The main process
  reads the chosen file and feeds it through the same import path as pasted
  material, so both routes behave identically; the name field pre-fills from
  the file name. Files larger than 512 KB are refused.

## [1.1.0] - 2026-09-02

### Added

- PuTTY key support (`.ppk`, version 3 — the format current PuTTYgen writes):
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
  release/*.deb' does not match any files" — space-separated globs are read as
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
