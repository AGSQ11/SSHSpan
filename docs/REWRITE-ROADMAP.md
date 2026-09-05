# SSHSpan — Rewrite to Rust + Improvements

**Full roadmap: from the Node.js/Electron v1.2.0 baseline to the Tauri v2 / Rust application (v1.3.6).**

This document records everything that changed since `main` (the Node.js version, `v1.2.0`),
why each step was taken, what shipped, and the engineering lessons paid for along the way.
Branch: `rewrite-to-rust-improvements` (work branch: `migrate-to-tauri`). Delta vs `main`:
**+15,833 / −742 lines across 19 files**, every line of backend logic re-implemented in Rust.

---

## 1. Where we left: SSHSpan v1.2.0 (Node.js / Electron)

`main` at `70e7c9d` was a fully functional Electron app:

| Area | What existed |
| --- | --- |
| **Vault** | Master-password gate; private keys sealed with bcrypt-pbkdf2 + AES-256-GCM; in-memory password only |
| **Keys** | Generate Ed25519 / RSA / ECDSA-P256/384/521; import OpenSSH (incl. encrypted), PKCS#8, SPKI, `authorized_keys` lines, PuTTY `.ppk` v3 **and legacy v2**; export to all of those formats; SHA-256/MD5 fingerprints |
| **Categories** | User-defined tree (any depth), many-to-many key↔category, sidebar tree with drag-and-drop, breadcrumbs, grouped key list, multi-select picker; Bitwarden two-way sync encodes the tree into cipher `notes` as `{v:1, sshspan:{categories:[{id,path}]}}` with deterministic IDs for convergence |
| **Bitwarden/Vaultwarden** | Direct Bitwarden API client (no `bw serve`): login, HKDF stretch, user-key unwrap, cipher CRUD restricted to a single SSHSpan folder, two-way sync (newest wins, deletions never propagated), SSRF-hardened server URL |
| **Deploy** | Writes selected keys to `~/.sshspan/keys/<id>` (owner-only perms) + manages `# >>> SSHSpan managed >>>` blocks in `~/.ssh/config` |
| **Ops** | Local SQLite (sql.js) audit log, settings, system tray, single-instance, win+linux CI |

**Architecture:** Node.js main process (`src/main/services/*`: database, cryptoService,
keyService, puttyParser, bitwardenCrypto, bitwardenClient, bitwardenSyncService,
sshConfigService, sessionService) + plain-JS renderer. Everything that touches key material
lives behind IPC.

**Why rewrite?**

1. **Runtime weight & packaging.** Shipping a Node runtime + sql.js WASM + Electron Chromium
   for a utility app meant ~150 MB installers and a large CVE surface for code we don't control.
2. **One implementation of crypto.** The Node side carried hand-rolled Bitwarden crypto and
   format parsers in JavaScript; we wanted key material handled in one compiled, memory-safe
   language with audited crates.
3. **The roadmap demanded an SSH client.** A PuTTY-grade embedded terminal is a poor fit for
   Electron-child-process hacks; it wants an async Rust SSH stack (russh) in the same trust
   boundary as the vault.
4. **Smaller trust surface.** Tauri runs the UI in the OS webview (WebView2/WebKitGTK) instead
   of shipping Chromium, and the strict CSP actually holds because there is no bundler or
   remote code path.

---

## 2. The rewrite: Tauri v2 + Rust (branch `migrate-to-tauri`)

The entire backend was re-implemented in Rust (`src-tauri/`); the renderer stayed
framework-free (plain DOM + `window.__TAURI__.core.invoke`) so the CSP can remain
`script-src 'self'` with zero build tooling.

### 2.1 Rust module map

| Module | Responsibility |
| --- | --- |
| `src-tauri/src/crypto/keys.rs` | Key generation/import/export via the `ssh-key` crate: Ed25519, RSA (3072–8192), ECDSA P-256/384/521; OpenSSH/PKCS#8/SPKI/`authorized_keys` formats; SHA-256 + MD5 fingerprints; private halves held as raw OpenSSH blobs, converted to a target format only at export |
| `src-tauri/src/crypto/vault.rs` | `seal()`/`unseal()` — bcrypt-pbkdf2 KDF + AES-256-GCM envelope; same scheme as v1.2.0, so **existing vaults migrate without re-entry** |
| `src-tauri/src/crypto/putty.rs` | PuTTY `.ppk` v3 **and legacy v2** import (v3 export only, per the legacy-format policy: read anything, write modern) |
| `src-tauri/src/db/mod.rs` | sqlx + SQLite. Phased migrations: core (`keys`, `audit`, `config`) → categories (`categories`, `key_categories`) → Connect (`servers`, `known_hosts`). All DB access via a `block()` helper that is runtime-aware (works from sync commands and inside async commands without nesting a tokio runtime) |
| `src-tauri/src/bitwarden/` | Direct Bitwarden/Vaultwarden client: login (PBKDF2/Argon2id KDF info), **expand-only HKDF** (matches Bitwarden's stretch semantics), EncString parse/encrypt, user-key unwrap (incl. the 80-byte PKCS7 pad-strip fix), two-way cipher sync with folder gating, Vaultwarden `Bitwarden-Client-Version` header, SSRF-safe URL resolution |
| `src-tauri/src/ssh/` | Deploy feature: writes staged keys with owner-only perms, manages the SSHSpan-managed block in `~/.ssh/config` |
| `src-tauri/src/config/` | `~/.ssh/config` parser/writer |
| `src-tauri/src/ssh_client/` | **New in v1.3** — russh 0.63 (ring backend) embedded SSH client: `SessionRegistry` (Arc-managed), interactive PTY sessions, publickey/password/keyboard-interactive auth, TOFU host-key pinning, in-memory key unseal |
| `src-tauri/src/commands/` | 40+ IPC commands (see §2.3). Vault password held in `VaultPasswordStore` (memory-only), cleared on lock; every sensitive action lands in the audit log |

### 2.2 Security model (unchanged guarantees, tighter enforcement)

- **Private keys never reach the webview.** The renderer only ever sees names, types,
  fingerprints, and public keys. Decryption, signing, and SSH auth happen in Rust.
- **Vault master password lives in memory only** (`VaultPasswordStore`), cleared on lock.
  Locking the vault also terminates every live SSH session (`SessionRegistry::kill_all`).
- **Saved server passwords are sealed** with the vault master (same AES-256-GCM envelope) and
  only unsealed in-process at connect time.
- **Host keys are pinned TOFU-style** in the `known_hosts` table; a fingerprint mismatch
  refuses the connection with an actionable message.
- **CSP:** `script-src 'self'`; styles additionally allow `'unsafe-inline'` because xterm.js
  injects its color table/layout sheets at runtime (see §4, lesson L2).
- **DevTools enabled in release builds** (F12) for transparency — the renderer cannot hold
  secrets, so inspecting it reveals nothing sensitive.

### 2.3 IPC surface (invoke commands)

| Group | Commands |
| --- | --- |
| Vault | `vault_create`, `vault_unlock`, `vault_lock`, `vault_change_password`, `vault_status`, `vault_export`, `vault_import` |
| Keys | `key_generate`, `key_import`, `key_export`, `key_delete`, `key_list`, `key_get`, `key_fingerprint`, `key_deploy`, `key_remove_deployed` |
| Categories | `category_list`, `category_create`, `category_rename`, `category_reparent`, `category_delete`, `key_set_categories`, `key_create_with_categories` |
| SSH config | `ssh_config_read`, `ssh_config_write`, `ssh_config_list_hosts` |
| **Servers (new)** | `server_list`, `server_save`, `server_delete`, `server_test` |
| **Terminal (new)** | `terminal_connect`, `terminal_send`, `terminal_resize`, `terminal_disconnect`, `terminal_list`, `known_hosts_list`, `known_hosts_forget` |
| Bitwarden | `bitwarden_get_config`, `bitwarden_save_config`, `bitwarden_test_connection`, `bitwarden_sync` |
| Ops | `settings_get`, `settings_set`, `audit_list`, `system_open_external`, `system_show_item_in_folder`, `system_select_file` |

### 2.4 Renderer

- `app.js` (framework-free controller), `icons.js` (generated Lucide SVG sprite — zero font/CDN
  requests), `styles.css` (dark "precision instrument" theme, all tokens in `:root`).
- `vendor/xterm.js` + `addon-fit.js` + `addon-web-links.js` + `xterm.css` — committed to the
  repo; loads under the strict CSP with no bundler and no npm at runtime.
- `terminal.js` — xterm wrapper: builds the terminal lazily (the Connect view starts hidden;
  xterm must only measure a visible host), streams session output over a
  `tauri::ipc::Channel`, forwards keystrokes as UTF-8 bytes, refits on resize.
- Connect UX: server list (search, dblclick connect, context menu), server editor (auth-method
  segmented control, vault key dropdown, on-disk `.pem` fallback, save-password checkbox),
  custom password modal (native `prompt()` silently fails in WebView2), in-terminal connect
  trace, status strip, per-stage error surfacing.
- Key right-click → **"Use this key to connect…"** → pick a saved server (server's username,
  clicked key overrides the saved binding) or create a new server pre-filled with the key.
- Boot diagnostics: dynamic script loading with per-file `onerror` toasts, global error →
  toast, and a build marker in the sidebar (`KEY MANAGER · <build>`) so the exact shipped
  frontend is always identifiable.

---

## 3. Version-by-version changelog (this branch)

### v1.3.0 — Embedded SSH client ("Connect")

- `servers` + `known_hosts` tables; server CRUD with key/user binding, optional sealed
  password, last-connected tracking; `server_test` (open → auth → close, latency reported).
- russh client: TCP + KEX, publickey (in-vault key unsealed in-process, or on-disk `.pem`),
  password, keyboard-interactive; PTY + login shell; `window-change` resize.
- `terminal_connect` streams output over `tauri::ipc::Channel<String>`; keystrokes stream in
  via `terminal_send` (UTF-8 encoded); `SessionRegistry` tracks live sessions;
  **vault lock kills all sessions**.
- TOFU host-key pinning with mismatch → hard failure + hint to forget the host.
- Connect nav item (vault-gated), Connect view, server modal, key right-click flow.
- Audit events: `connect.start`, `connect.stop`, `server.save`, `server.delete`,
  `server.test_ok`, `server.test_fail`, `known_hosts.forget`.

**Fix rounds that followed (same milestone):** local `ico` shadows that clobbered the icon
helper; custom password modal; Tauri camelCase Channel args (`on_data` → `onData`); lazy xterm
build (hidden host ⇒ zero-size ⇒ NaN fit); Connect CSS pointed at the real design tokens;
`inactivity_timeout: None` (`Some(0)` fires immediately); PTY modes `ECHO/ICANON/ISIG/OPOST/
ONLCR` (an empty mode list makes many sshd silently skip shell spawn); loud Channel-send
errors; close detection by registry contents; boot-time script-load checks; skip password
prompt when one is sealed; in-terminal stage trace.

### v1.3.1 — Stale-asset discovery

Frontend files are **embedded into the exe at Rust compile time**; cargo skips the crate when
no Rust code changes, so frontend-only fixes shipped stale binaries. Protocol adopted: bump
the version in all three manifests before every release build and require `Compiling sshspan`
in the build log; build marker added so the running frontend is identifiable at a glance.

### v1.3.2 — Root cause of the "blank terminal"

The renderer's classic scripts share one global lexical scope: `terminal.js` re-declared
`const invoke` (already declared in `app.js`), a **SyntaxError that silently killed the whole
file in every previous build**. Fixed by namespacing (`tcore.invoke`); scripts now load
dynamically with per-file 404 reporting (a failed `<script src>` fires no `window.onerror`);
global errors surface as toasts; DevTools enabled in release builds.

### v1.3.3 — PuTTY-grade terminal UX

Solid accent-blue selection highlight (alpha variants render invisibly), PuTTY-style blinking
block cursor (green, `cursorAccent` themed), select-to-copy, right-click paste, and
Ctrl+Shift+C/V; status strip keeps the friendly "Connected — streaming" state; Disconnect
button follows the real session lifecycle (hidden while connecting, shown once live).

### v1.3.5 — CSP vs xterm's injected styles (colors, cursor, selection restored)

xterm.js injects its **color table (`.xterm-fg-N` classes), span layout, and cursor rules** as
runtime `<style>` elements — the CSP `style-src 'self'` blocked all of them, leaving a
colorless, cursorless, unselectable terminal. Fixed with `style-src 'self' 'unsafe-inline'` in
**both** CSP declarations (tauri.conf.json *and* the `index.html` meta — both apply, the
stricter wins). Also: `@xterm/xterm@5.5.0` ships an incomplete `css/xterm.css` — the missing
core rules (`.xterm-rows` grid with `white-space: pre`, `.xterm-selection` positioning,
`.xterm-bold`/`.xterm-italic`) are now patched in `styles.css`; a window-resize refit keeps
the grid in sync with maximize.

### v1.3.6 — Publickey auth

Vault keys are stored as **raw binary OpenSSH blobs**, not PEM text. The Connect path now
loads keys through the same `load_private_key_data` → `export_private_key(OpenSsh)` pipeline
used by export/deploy, so every key type (Ed25519, RSA, ECDSA, .ppk-imported) works for SSH
auth, and the right-click "use this key to connect" flow works against any vault key. Failures
surface with the key's name.

---

## 4. Engineering lessons (the expensive ones)

1. **Classic scripts share one global lexical scope.** Two top-level `const` declarations of
   the same name across files = SyntaxError that deletes an entire script silently.
   Namespace cross-file dependencies; never guard them with silent `typeof` checks.
2. **CSP applies to JS-injected styles.** xterm.js (and anything else injecting `<style>` at
   runtime) needs `style-src … 'unsafe-inline'`. Both the `tauri.conf.json` CSP *and* any
   `<meta http-equiv="Content-Security-Policy">` in the HTML apply — they intersect, and the
   stricter one wins. Fix one, and the other still bites.
3. **Frontend assets are frozen at Rust compile time.** `tauri build` re-embeds `frontendDist`
   only when cargo actually recompiles the crate. Frontend-only changes + unchanged version =
   stale exe. Bump the version, confirm `Compiling sshspan` in the log, and ship a build
   marker in the UI.
4. **A `<script src>` that 404s fires no `window.onerror`.** Load anything critical
   dynamically with explicit `onerror` reporting.
5. **russh config gotchas:** `inactivity_timeout: Some(Duration::ZERO)` fires *immediately* —
   use `None` for interactive sessions; `request_pty` with an empty terminal-modes list makes
   many sshd silently skip spawning a shell — pass at least ECHO/ICANON/ISIG/OPOST/ONLCR.
6. **Tauri IPC argument names are camelCase on the JS side** (Rust `on_data` ⇄ JS `onData`)
   unless the command opts into `rename_all = "snake_case"`.
7. **Never `let _ =` a Channel send.** A broken renderer channel then looks exactly like a
   connected-but-dead session. Propagate the error.
8. **Debug the packaged app, not vibes.** WebView2 accepts
   `WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS="--remote-debugging-port=9223"`; from there CDP
   (Node's built-in WebSocket ≥22) can read computed styles, run live tests, and screenshot
   the real UI. Every claim in §3's fix list was verified this way.
9. **Native `prompt()`/`confirm()` dialogs silently fail in WebView2.** Use in-app modals.
10. **Never `let _ =` a russh PTY echo either:** terminal modes exist for a reason (see 5).

---

## 5. Where we are vs. where we left — scorecard

| Capability | v1.2.0 (Node) | v1.3.6 (Rust) |
| --- | --- | --- |
| Key lifecycle (gen/import/export) | ✔ | ✔ (same formats, Rust `ssh-key`) |
| PuTTY .ppk v3 export / v2+v3 import | ✔ | ✔ |
| Categories tree + DnD + Bitwarden notes sync | ✔ | ✔ (re-implemented) |
| Bitwarden/Vaultwarden two-way sync | ✔ | ✔ (+ Vaultwarden client-version gate) |
| Deploy to `~/.ssh` + managed config block | ✔ | ✔ |
| Audit log, settings, tray, single-instance | ✔ | ✔ |
| **Embedded SSH terminal** | ✖ | ✔ russh + xterm.js, TOFU, vault-gated |
| **Saved servers with key/user binding** | ✖ | ✔ sealed passwords, latency test |
| **Key right-click → connect** | ✖ | ✔ any vault key type |
| PuTTY-style clipboard + cursor + maximize | ✖ | ✔ |
| Installer size (Windows) | ~150 MB (Electron) | ~9 MB (NSIS) |
| Backend language | JavaScript (Node) | Rust |

---

## 6. Roadmap from here (unchanged direction)

1. **Known-hosts management UI** — the IPC (`known_hosts_list` / `known_hosts_forget`)
   already exists; a settings-page panel completes the TOFU story.
2. **Minimize-to-tray on window close** — today the X button exits; tray-aware close would
   match the tray's promise.
3. **ssh-agent story** — feed Pageant/OpenSSH agent instead of shipping our own (per the
   standing roadmap decision), with auto-remove on vault lock.
4. **Session tabs** — multiple simultaneous terminals in the Connect view.
5. **PuTTY session import/export (`.reg`)**, jump hosts, port forwarding — in that order.
6. **Health panel** — key age, cipher strength, deployed-file drift.

---

*Maintained on branch `rewrite-to-rust-improvements`. Every claim above is reproducible from
the commit history (`git log main..HEAD`) and the CDP-verified test trail.*
