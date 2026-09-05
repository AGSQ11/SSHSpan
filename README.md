<p align="center">
  <img src="assets/sshspan-readme-hero.svg" alt="SSHSpan — encrypted SSH key management" width="100%">
</p>

# SSHSpan

🔐 Cross-platform SSH key manager **and SSH client** for the desktop — built on **Rust + Tauri v2**.

SSHSpan gives you a single, encrypted home for every SSH key you own, and now an embedded
PuTTY-grade terminal to use them. Generate new keys, import existing ones, organize them into
categories, deploy them into `~/.ssh/config`, and connect straight to your servers — all from
one keyboard-friendly app. Private keys are encrypted at rest with AES-256-GCM behind a master
password; the master password itself lives only in memory and auto-locks after 15 minutes of
inactivity (locking also disconnects any live SSH session).

All sensitive logic — crypto, vault, database, SSH — runs in a compiled **Rust** core. The UI is
vanilla HTML/CSS/JS in your OS webview: no Electron, no bundled Chromium, no Node runtime.
Installers are ~9 MB. Everything runs locally: no cloud, no telemetry, and no network access
unless you enable Bitwarden sync, which talks only to the server you configure.

## Features

### Keys
- **Generate** — RSA (3072–8192 bits), Ed25519, ECDSA (nistp256/384/521), via the audited `ssh-key` Rust crate.
- **Import** — browse or paste: OpenSSH private (incl. passphrase-protected), PKCS#8 PEM, PEM public, `authorized_keys` lines, and PuTTY `.ppk` **v3 and legacy v2** (passphrase-protected too).
- **Export** — OpenSSH new-format private, PuTTY `.ppk` v3, PKCS#8 PEM (plain or encrypted), SPKI PEM public, `authorized_keys` lines. Legacy v2 `.ppk` imports are written back as v3.
- **Encrypted vault** — AES-256-GCM envelopes; the master password is never stored.

### Categories
- Organize keys in a **tree of any depth**, many-to-many key↔category, drag-and-drop in the
  sidebar, breadcrumbs, grouped lists, and a shared multi-select picker.
- The tree **syncs with Bitwarden**: it is encoded into each cipher's `notes` field, so two
  SSHSpan installs (or a reinstall) converge on the same structure.

### Connect — embedded SSH client
- **Saved servers** with per-server username + SSH-key binding; optional password storage
  (sealed with your vault master, unsealed only in-process at connect time).
- **Interactive terminal** (xterm.js + the `russh` Rust SSH library): full ANSI colors, 5000-line
  scrollback, resizable grid.
- **PuTTY behaviors**: select text to copy instantly, right-click to paste, Ctrl+Shift+C/V,
  blinking block cursor.
- **Host-key pinning (TOFU)** — first connection stores the server's fingerprint; any change is
  refused with a clear warning. (Management UI: see roadmap.)
- **Right-click any key → "Use this key to connect…"** — pick a saved server (its username +
  your clicked key) or create a new server pre-filled with that key.
- **Vault-gated**: locking the vault immediately disconnects every live session.
- Test button per server (open → authenticate → close, with latency).

### Sync & deploy
- **Bitwarden / Vaultwarden sync (optional)** — mirror keys to SSH-key items in your own vault,
  two-way, deletions never propagated; works with getbitwarden.com and self-hosted Vaultwarden
  (SSRF-hardened server URL validation).
- **Deploy to SSH** — writes selected keys to `~/.sshspan/keys/<id>` (owner-only permissions) and
  manages reversible `Host` blocks between marker comments in `~/.ssh/config`.

### Trust & ops
- **Audit log** — append-only local record of every sensitive action (key lifecycle, vault
  lock/unlock, connects, server changes).
- **DevTools available in release builds** (F12) — the UI layer holds no secrets by design.
- **Small & fast** — ~9 MB installers; no Chromium, no Node runtime.

## Installation

### From a release (recommended)
Grab the latest installer from [Releases](https://github.com/AGSQ11/SSHSpan/releases):

| Platform | Files |
| --- | --- |
| Windows | `SSHSpan_x.y.z_x64-setup.exe` (NSIS, per-user) · `SSHSpan_x.y.z_x64_en-US.msi` (system-wide) |
| Linux | `SSHSpan_x.y.z_amd64.AppImage` · `sshspan_x.y.z_amd64.deb` |

### Build from source
Prerequisites: [Rust](https://rustup.rs) (stable), Node.js ≥ 18 (for the Tauri CLI), and on Linux
the Tauri system dependencies (`libwebkit2gtk-4.1-dev`, `libgtk-3-dev`, `libayatana-appindicator3-dev`, …).

```bash
npm install
npm run tauri dev      # run in development
npm run tauri build    # produce installers in src-tauri/target/release/bundle/
```

Windows builds: `npm run dist:win` · Linux builds: `npm run dist:linux`.
Rust tests: `cargo test --manifest-path src-tauri/Cargo.toml`.

## Architecture (in one paragraph)

A **Tauri v2** app: a Rust binary (`src-tauri/`) owns the SQLite vault (sqlx), all cryptography
(`ssh-key`, `aes-gcm`, `bcrypt-pbkdf`, `chacha20poly1305`, `ring`), the Bitwarden client, the SSH
deploy service, and the russh session engine; the webview UI (`src/renderer/`) is plain
HTML/CSS/JS that talks to Rust through typed IPC commands. Private key material is decrypted only
inside Rust processes and never crosses the IPC boundary. The full Node.js → Rust migration
story, per-version changelog, and engineering notes live in
[`docs/REWRITE-ROADMAP.md`](docs/REWRITE-ROADMAP.md); the process/module layout is in
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Security

Private keys are encrypted at rest (AES-256-GCM, bcrypt-pbkdf2 KDF) and only ever decrypted
in-process. The master password is never persisted — only a verification hash. Host keys are
pinned trust-on-first-use. See [docs/SECURITY.md](docs/SECURITY.md) and
[docs/PRIVACY.md](docs/PRIVACY.md).

## License

MIT — see [LICENSE](LICENSE).
