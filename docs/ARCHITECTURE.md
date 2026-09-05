# SSHSpan Architecture

SSHSpan is a **Tauri v2** desktop application: a compiled **Rust core** owns every sensitive
resource (the SQLite vault, the master-password session, key material, the Bitwarden client,
and the SSH session engine), and a **vanilla HTML/CSS/JS webview** renders the UI and talks to
Rust only through typed IPC commands. There is no Node runtime, no bundled browser, and no
bundler — the renderer is served as static files from the executable, and all vendor JavaScript
(xterm.js) is committed under `src/renderer/vendor/` so the CSP can stay strict.

```
┌──────────────────────────────────────────────────────────────────┐
│  WebView (OS webview: WebView2 / WebKitGTK)                      │
│  src/renderer/                                                   │
│    app.js        — UI controller (plain DOM, no framework)       │
│    terminal.js   — xterm.js wrapper for the Connect view         │
│    icons.js      — generated Lucide SVG sprite (no fonts/CDN)    │
│    vendor/       — xterm.js + fit + web-links (UMD, committed)   │
│        │  invoke('command', args)  /  ipc::Channel streams       │
└────────────────┬─────────────────────────────────────────────────┘
                 │ typed IPC (camelCase args, JSON results)
┌────────────────┴─────────────────────────────────────────────────┐
│  Rust core (src-tauri/)                                          │
│   commands/   — 40+ #[tauri::command] handlers                   │
│   crypto/     — keys (ssh-key crate), vault seal/unseal, PPK v2/v3│
│   db/         — sqlx + SQLite (keys, categories, servers, audit…)│
│   bitwarden/  — direct Bitwarden/Vaultwarden client + sync       │
│   ssh/        — deploy: ~/.sshspan/keys + managed ~/.ssh/config  │
│   config/     — ~/.ssh/config parser/writer                      │
│   ssh_client/ — russh session engine + SessionRegistry + TOFU    │
└──────────────────────────────────────────────────────────────────┘
```

## Process model

A single Rust process hosts:

- the **webview** (UI), sandboxed by CSP (`script-src 'self'`); it holds **no secrets** —
  private key material never crosses the IPC boundary, so DevTools in release builds are safe;
- the **tokio runtime** that drives russh SSH sessions and Bitwarden HTTP;
- **managed state**: `AppState` (sqlx DB pool), `VaultPasswordStore` (master password,
  memory-only, cleared on lock), `Arc<SessionRegistry>` (live SSH sessions; cleared on lock).

The system tray (Show / Lock Vault / Quit) and the single-instance plugin live in `lib.rs`.
The master password is never persisted — only a verification hash — and locking the vault both
clears it and disconnects all SSH sessions.

## IPC contract

All commands are `#[tauri::command]` functions under `src-tauri/src/commands/`, registered in
`lib.rs` (`generate_handler!`). Argument names are camelCase on the JS side (Tauri default).
Every handler returns `Result<T, CmdError>` where `CmdError` stringifies into the JS rejection.
Long-running output (terminal bytes) uses `tauri::ipc::Channel<String>` rather than events, for
ordered, high-throughput delivery.

| Group | Commands |
| --- | --- |
| Vault | `vault_create`, `vault_unlock`, `vault_lock`, `vault_change_password`, `vault_status`, `vault_export`, `vault_import` |
| Keys | `key_generate`, `key_import`, `key_export`, `key_delete`, `key_list`, `key_get`, `key_fingerprint`, `key_deploy`, `key_remove_deployed` |
| Categories | `category_list`, `category_create`, `category_rename`, `category_reparent`, `category_delete`, `key_set_categories`, `key_create_with_categories` |
| SSH config | `ssh_config_read`, `ssh_config_write`, `ssh_config_list_hosts` |
| Servers | `server_list`, `server_save`, `server_delete`, `server_test` |
| Terminal | `terminal_connect`, `terminal_send`, `terminal_resize`, `terminal_disconnect`, `terminal_list`, `known_hosts_list`, `known_hosts_forget` |
| Bitwarden | `bitwarden_get_config`, `bitwarden_save_config`, `bitwarden_test_connection`, `bitwarden_sync` |
| Ops | `settings_get`, `settings_set`, `audit_list`, `system_open_external`, `system_show_item_in_folder`, `system_select_file` |

## Module walkthrough (src-tauri/src)

- **crypto/keys.rs** — generation, import, export, fingerprints via the `ssh-key` crate.
  Private halves are stored as **raw OpenSSH binary blobs**; PEM/PPK/PKCS#8/`authorized_keys`
  renderings are produced on demand by `export_private_key`/`export_public_key`.
- **crypto/vault.rs** — `seal()` / `unseal()`: bcrypt-pbkdf2 KDF → AES-256-GCM envelope.
  Same scheme as the 1.x Node app, so existing vaults migrate without re-entry.
- **crypto/putty.rs** — PuTTY `.ppk` v3 and legacy v2 import; v3-only export.
- **db/mod.rs** — sqlx + SQLite at `~/.sshspan/sshspan.db`. Tables: `keys`, `audit`, `config`,
  `categories`, `key_categories`, `servers`, `known_hosts`. All access funnels through a
  runtime-aware `block()` helper so sync commands and async commands can share the pool
  without nesting tokio runtimes.
- **bitwarden/** — direct client: login (PBKDF2/Argon2id), expand-only HKDF stretch, EncString
  encryption, user-key unwrap, folder-gated two-way cipher sync (deletions never propagate),
  SSRF-safe URL resolution, Vaultwarden compatibility headers. The category tree rides in each
  cipher's `notes` field as `{v:1,sshspan:{categories:[{id,path}]}}` with deterministic IDs.
- **ssh/** — deploy: writes staged keys with owner-only permissions and manages the
  `# >>> SSHSpan managed >>>` block in `~/.ssh/config`.
- **config/** — `~/.ssh/config` parse/serialize.
- **ssh_client/mod.rs** — the Connect engine: russh client (ring backend), `TerminalHandler`
  implementing TOFU host-key verification against `known_hosts`, authentication
  (publickey from unsealed vault keys or on-disk `.pem`, password, keyboard-interactive),
  PTY + shell with terminal modes, window-change resize, and a spawned per-session task that
  multiplexes channel data / stdin / resize over tokio channels.

## Data flows

**Unlock** — `vault_unlock` verifies the master password against the stored hash, stores it in
`VaultPasswordStore`, and the renderer loads key metadata (public parts only).

**Connect (publickey)** — `terminal_connect(serverId, onData, …)` → resolve server row →
unseal key → export OpenSSH PEM → russh connect (TOFU check) → authenticate → PTY + shell →
register session → spawn streaming task → return `sessionId`. Keystrokes: renderer →
`terminal_send` → session stdin. Output: channel → `onData.send(text)` → `term.write()`.
`terminal_disconnect` drops the session's stdin sender; the task closes the channel and
removes itself from the registry (the renderer also polls `terminal_list` as a backstop).

**Sync** — `bitwarden_sync` pulls ciphers, matches by fingerprint, newest-wins two-way merge,
never propagates deletions, then pushes category metadata into `notes`.

## SQLite schema (essentials)

```
keys(id, name, key_type, public_key, private_key_encrypted, fingerprint_sha256,
     fingerprint_md5, comment, created_at, updated_at, deployed, deploy_path,
     bitwarden_id, bitwarden_sync, bitwarden_revision_ts, bitwarden_updated_at)
categories(id, name, parent_id, color, sort_index, created_at, updated_at)
key_categories(key_id, category_id)
servers(id, name, host, port, username, auth_method, key_id, pem_path,
        saved_password /* sealed */, category_id, color, last_connected_at,
        created_at, updated_at)
known_hosts(host PRIMARY KEY, host_key, fingerprint_sha256, first_seen)
audit(id, action, key_id, details, timestamp)
config(key PRIMARY KEY, value)
```

Migrations are phased `CREATE TABLE IF NOT EXISTS` blocks executed at startup, so 1.x vaults
upgrade in place.

## Persistence & trust boundaries

- Private keys: sealed at rest (AES-256-GCM), unsealed only in Rust, never sent to the UI.
- Saved server passwords: sealed with the vault master; unsealed only at connect time.
- Master password: memory-only (`VaultPasswordStore`), cleared on lock/quit; lock also kills
  every live SSH session before clearing.
- Host keys: TOFU-pinned in `known_hosts`; mismatches refuse the connection.

## Reasoning log (highlights)

- **Tauri over Electron**: ~9 MB installers, the OS webview, and one compiled language for all
  trust-boundary code. Full rationale in `docs/REWRITE-ROADMAP.md`.
- **russh over libssh2/ssh2**: pure-Rust, Tokio-native, Apache-2.0 (no LGPL static-link
  constraints on Windows), supports in-memory key decode and OpenSSH certificates.
- **xterm.js over a custom emulator**: the same engine VS Code uses; committed UMD builds keep
  the CSP strict and builds fully offline.
- **Framework-free renderer**: no build step, no supply chain, and the CSP actually holds.
  The five views (Keys, Connect, Deploy, Settings, Audit) are small enough that hand-written
  components give finer control over focus, keyboard navigation, and theming than a component
  library.
- **sqlx over rusqlite**: async-friendly, compile-time-checked queries, and a shared pool for
  sync + async command contexts via the `block()` helper (avoiding nested-runtime panics).
- **Vanilla renderer + vendored xterm.js**: deterministic behavior across webview versions, no
  lazy-loaded chunks (offline guarantee), and a minimal DOM surface that is easy to audit.
