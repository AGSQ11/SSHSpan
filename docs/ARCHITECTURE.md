# SSHSpan Architecture

SSHSpan is a three-process Electron desktop application. The **main process** owns all sensitive state (the database, the master-password session, and key material); the **renderer process** is a vanilla HTML/CSS/JS UI that can only talk to main through a hardened context bridge; the **preload script** is the only bridge between them.

## Process model

```
┌─────────────────────────────────────────────────────────────┐
│                     Electron main process                    │
│  ┌─────────────┐  ┌──────────────────┐  ┌────────────────┐  │
│  │ index.js    │  │ services/        │  │ Node built-ins │  │
│  │ window, tray,│  │ sshspan.js,      │  │ crypto, fs, os │  │
│  │ single-lock │  │ database.js,     │  │ path, child    │  │
│  │ bootstrap   │  │ cryptoService.js,│  │ process        │  │
│  │             │  │ sessionService.js,│  │ (sql.js WASM)  │  │
│  │             │  │ keyService.js,   │  │                │  │
│  │             │  │ opensshParser.js,│  │                │  │
│  │             │  │ sshConfigService,│  │                │  │
│  │             │  │ settingsService, │  │                │  │
│  │             │  │ ipcHandlers.js   │  │                │  │
│  │  └──────┬──────┘  └────────┬─────────┘  └───────┬────────┘  │
│         │                  │                    │           │
│         │     IPC (ipcMain.handle) + contextBridge     │           │
│         │                  │                    │           │
│  ┌──────┴──────────────────┴────────────────────┴───────┐   │
│  │                preload.js (contextBridge)              │   │
│  │         exposes window.sshspan → ipcRenderer.invoke    │   │
│  └────────────────────────────┬─────────────────────────┘   │
└───────────────────────────────┼─────────────────────────────┘
                                │
                     ┌──────────┴──────────┐
                     │   renderer process  │
                     │  index.html         │
                     │  styles.css         │
                     │  app.js (vanilla)   │
                     │  NO nodeIntegration │
                     │  contextIsolation   │
                     └─────────────────────┘
```

On-disk:
  ~/.sshspan/sshspan.db       vault DB (private-key blobs encrypted; atomic tmp+rename)
  ~/.sshspan/keys/<id>        deployed private key files (0600 / Windows ACL-restricted)
  ~/.ssh/config               managed Host block between markers

## Window and security sandbox

- BrowserWindow: 1100 x 720, minimum 880 x 560.
- `webPreferences`: `contextIsolation: true`, `nodeIntegration: false`, `sandbox: false`, `webSecurity: true`.
- The renderer loads `index.html` only; no remote URLs, no external fonts or CDNs at runtime.
- The preload exposes exactly one global: `window.sshspan`, a fixed set of methods that proxy to `ipcRenderer.invoke`.
- Single-instance lock: a second launch focuses the existing window instead of opening another.
- On Windows/Linux, closing the window minimizes to the system tray (on macOS the app stays in the Dock).

## IPC contract

Every channel is invoked through `window.sshspan.<method>(args)` and returns a Promise that resolves to `{ ok: true, data }` or `{ ok: false, error }` — handlers never reject across the bridge; errors are carried in the envelope. `keys:get` **never** returns private key material.

| Channel | Method | Payload | Response data |
|---|---|---|---|
| `vault:status` | `vaultStatus()` | — | `{ hasVault, unlocked }` |
| `vault:create` | `vaultCreate({ password })` | — | `{ ok: true }` |
| `vault:unlock` | `vaultUnlock({ password })` | — | `{ ok: true }` |
| `vault:lock` | `vaultLock()` | — | `{ ok: true }` |
| `vault:change-password` | `vaultChangePassword({ password })` | — | `{ ok: true }` |
| `keys:list` | `keysList()` | — | key record array |
| `keys:get` | `keysGet({ id })` | — | record without `privateKeyPem`/`passphrase`, plus `hasPrivate` |
| `keys:create` | `keysCreate(payload)` | name/type/bits/curve/comment | `{ id }` |
| `keys:import` | `keysImport({ pem, ...opts })` | PEM + name/passphrase | `{ id }` |
| `keys:update` | `keysUpdate({ id, patch })` | name/comment/tags/sshConfig only | updated record |
| `keys:delete` | `keysDelete({ id })` | — | `{ ok }` |
| `keys:export` | `keysExport({ id, format, ...opts })` | format + optional passphrase/comment | `{ data: string }` |
| `keys:copy-public` | `keysCopyPublic({ id })` | — | `{ ok }` (writes authorized_keys line to clipboard) |
| `keys:deploy` | `keysDeploy({ ids, ...opts })` | ids + host/user/port/strictHostKey/keyPassphrase/writeSshConfig | `{ files, keys, keysDir, configPath, configBytes }` |
| `keys:render-config` | `keysRenderConfig({ ids, ...opts })` | ids + config options | rendered config text |
| `settings:get` | `settingsGet()` | — | settings object |
| `settings:set` | `settingsSet({ key, value })` | — | `{ ok: true }` (rejects `bwSync.*` keys) |
| `sync:get-config` | `syncGetConfig()` | — | sanitized sync config (no secrets) |
| `sync:save-config` | `syncSaveConfig(patch)` | serverUrl/email/folderName/autoSync/autoSyncMinutes/masterPassword | saved config |
| `sync:test` | `syncTest()` | — | `{ ok, server, account, kdf, sshItemCount, folders }` |
| `sync:now` | `syncNow({ reason })` | — | sync summary (pushed/pulled/updated/conflicts/errors) |
| `audit:list` | `auditList({ limit })` | — | audit row array |
| `clipboard:write-public` | `clipboardWritePublic({ id })` | — | `{ ok }` |


## Module walkthrough

### src/main/index.js
index.js is the process bootstrap. It sets up the single-instance lock, creates the BrowserWindow with the sandbox settings, registers the system tray icon (Windows/Linux), and loads the preload. It also wires the app lifecycle events: it creates the vault directory on first run, starts the session service, and on quit it locks the vault and wipes the master password from memory.

### src/main/preload.js
preload.js is the ONLY code the renderer can execute. It imports `contextBridge` and `ipcRenderer` from Electron and exposes a single `window.sshspan` object. Every method is a thin wrapper around `ipcRenderer.invoke(channel, args)`. The preload does not import any Node modules and does not touch the filesystem directly, so the renderer can never reach the main process APIs outside the declared contract.

### src/main/services/sshspan.js
sshspan.js is the high-level orchestrator. It owns the vault lifecycle (create/unlock/lock/change-password), the key lifecycle (create/import/update/delete/export/copy-public/deploy/render-config), settings, and audit logging. It is the only module the ipc handlers call; it delegates to the specialized services and never touches sql.js directly.

### src/main/services/database.js
database.js wraps sql.js. It loads the WASM, opens the database at `~/.sshspan/sshspan.db`, runs migrations, and exposes `run(sql, params)` and `all(sql, params)`. Persistence is debounced 500 ms: after any write it schedules `db.export()`, serializes to a temp file, and atomically renames over the real path. No WAL or busy pragmas are used; on next open the file is read directly.

### src/main/services/cryptoService.js
cryptoService.js implements the vault crypto. `deriveKey(password, salt)` runs scrypt with N=65536, r=8, p=1 and returns a 32-byte key. `encrypt(key, plaintext)` generates a 16-byte salt and a 12-byte IV, runs AES-256-GCM with AAD `sshspan-aad`, and returns `base64url(salt || iv || tag || ciphertext)`. `decrypt(key, blob)` reverses it and verifies the GCM tag. `hashForVerify(password, salt)` derives a scrypt hash used for the timing-safe master-password check. The master password itself is never persisted.

### src/main/services/sessionService.js
sessionService.js holds the unlocked master password in memory only. `lock()` wipes it. An auto-lock idle timer (configurable via the `autoLockMinutes` setting, default 15) calls `lock()` after inactivity; the timer is `unref()`'d so it never holds a process open. Private key material is never stored unencrypted: storing a private key requires an unlocked vault and the blob is AES-256-GCM encrypted before insert. Only public-only records (imported public halves) can exist while locked.

### src/main/services/keyService.js
keyService.js owns key generation, parsing, and export. Generation uses Node `crypto.generateKeyPairSync`: rsa (3072-8192 bits; the 2048-bit floor was raised to 3072 in v1.0.1), ed25519, ecdsa (nistp256/384/521). Fingerprints are `SHA256:<base64 without padding>` of the SSH public wire blob. Exports produce OpenSSH new-format private keys, PKCS#8 PEM (plain or AES-256-CBC encrypted), SPKI PEM public keys, and authorized_keys lines. `keysGet` strips `privateKeyPem` and `passphrase` before returning.

### src/main/services/opensshParser.js
opensshParser.js parses `openssh-key-v1` private key files. It supports the ciphers none, aes256-ctr, aes256-gcm, and chacha20-poly1305@openssh.com, with bcrypt KDF via `bcrypt-pbkdf`. It can also parse legacy PEM private keys and public keys for import.

### src/main/services/ppkCipher.js
ppkCipher.js holds the AES-256-CBC helpers used by the PPK container. The mode is mandated by the PPK format; it runs through WebCrypto SubtleCrypto and length-checks key, IV and data before use. Decryption failures are reported generically so the parser's constant-time MAC check remains the authority on integrity.

### src/main/services/puttyParser.js
puttyParser.js parses and writes PuTTY private key files (`.ppk`, version 3) for RSA, Ed25519 and ECDSA. It derives key material with Argon2 (Node's built-in `argon2Sync`), splits the 80-byte tag into AES key / CBC IV / MAC key, and verifies the HMAC-SHA-256 integrity check timing-safely over the DECRYPTED private blob before returning any key material, so a wrong passphrase or tampered file never yields a usable key. Version 2 files are rejected with guidance to re-save them in a current PuTTYgen, because that format uses SHA-1 for both its KDF and its MAC. Argon2 parameters read from a file are validated, and implausible memory requests are refused.

### src/main/services/sshConfigService.js
sshConfigService.js manages the Host block in `~/.ssh/config` between the markers `# >>> SSHSpan managed >>>` and `# <<< SSHSpan managed <<<`. Deployed IdentityFile values point to `~/.sshspan/keys/<key-id>` and deployed files are written with mode 0600.

### src/main/services/settingsService.js
settingsService.js reads and writes the `config` table. Known keys and defaults: `theme` (dark), `accent` (#6ea8ff), `sidebarWidth` (260), `showFingerprint` (true), `autoLockMinutes` (15), `sshConfigPath` (null → `~/.ssh/config`), `sshKeysDir` (null → `~/.sshspan/keys`), `editorFont` (Consolas), `editorFontSize` (13), `copyOnImport` (true), `confirmDelete` (true), `confirmDeploy` (true).

### src/main/services/ipcHandlers.js
ipcHandlers.js registers every `ipcMain.handle` channel listed in the IPC contract table. Each handler validates its payload, calls the appropriate service method, and returns the canonical `{ ok: true, data }` / `{ ok: false, error }` envelope.

### src/main/services/bitwardenCrypto.js
bitwardenCrypto.js implements the subset of the Bitwarden client-side crypto stack needed to write SSH key (cipher type 5) items: master key derivation (PBKDF2-SHA256 or Argon2id via `hash-wasm`), the PBKDF2 login password hash, master-key stretching via HKDF-Expand (SHA-256, infos `enc`/`mac`), and the `2.<iv>|<ct>|<mac>` EncString format (AES-256-CBC + HMAC-SHA256 through WebCrypto SubtleCrypto, MAC verified timing-safely before decryption). Only type-2 EncStrings are accepted; the server only ever receives ciphertext.

### src/main/services/bitwardenClient.js
bitwardenClient.js is the Bitwarden/Vaultwarden HTTP client: prelogin, password-grant and refresh-grant token requests, `/api/sync`, folder create, cipher create/update. Every request runs against a base URL that passed `resolveSafeServerUrl` — the SSRF guard that enforces http/https only, rejects localhost/`.local` hostnames, literal loopback/private/reserved IPv4+IPv6 addresses (including IPv4-mapped and 6to4 forms), and refuses hostnames whose DNS resolution yields a private or reserved address. Self-hosted vaults must therefore be reachable via a public hostname.

### src/main/services/bitwardenSyncService.js
bitwardenSyncService.js is the two-way sync engine. It maps local key records to remote cipher type-5 items, linking rows by stored `bitwardenId` or, on first contact, by fingerprint. Per row, newest side wins: local `updatedAt` vs the per-row `bitwardenUpdatedAt` baseline decides the local side, remote `revisionDate` vs the stored `bitwardenRevision` decides the remote side; simultaneous changes favour the local copy and are reported as conflicts. Remote deletions are reported but never propagated. It manages the target vault folder (created on demand, default name `SSHSpan`), runs an optional auto-sync timer while the vault is unlocked, and stores its configuration under `bwSync.*` config keys — the Bitwarden master password is sealed with the vault master password (AES-256-GCM) and only decryptable while the vault is unlocked.

## Data flows

### Generate a key
renderer → keysCreate → sshspan → keyService.generate → crypto.generateKeyPairSync → JWK interchange → fingerprint of wire blob → database insert (encrypted if vault unlocked) → audit row → `{ id }`.

### Import a key
renderer → keysImport → opensshParser.parse → keyService.normalize → store (encrypted if vault unlocked) → audit row → `{ id }`.

### Export a key
renderer → keysExport → keyService.export → serialize to requested format (OpenSSH/PKCS#8/SPKI/authorized_keys) → optionally AES-256-CBC encrypt with passphrase → `{ data }`.

### Deploy keys
renderer → keysDeploy → write `~/.sshspan/keys/<id>` files (0600 POSIX / icacls-restricted on Windows) + `.pub` siblings → sshConfigService.writeConfig updates the managed `~/.ssh/config` Host block → `{ files, keys, keysDir, configPath, configBytes }`.

### Create vault
renderer → vaultCreate → enforce minimum length → cryptoService.createVerification (scrypt) → store `master.hash`/`master.salt` in config → session unlocked. No private keys can pre-date the vault, so there is nothing to re-encrypt at creation time.

### Unlock vault
renderer → vaultUnlock → load stored hash+salt → scrypt verify (timing-safe) → sessionService holds master key → mark unlocked.

### Change password
renderer → vaultChangePassword (new password only; the current one is held by the session in main) → verify current password against `master.hash` → for every stored private key: decrypt with the current password, re-encrypt with the new password, write back → THEN update `master.hash`/`master.salt`. Rekey-before-hash guarantees a failure can never strand keys under a hash that no longer matches their encryption.

### Lock vault
renderer → vaultLock → sessionService.lock() wipes master password → mark locked → audit row.

### Bitwarden sync
renderer → sync:save-config → SSRF URL validation (incl. DNS) → settings + master password sealed with the vault key → `sync:now` (manual or auto timer) → BitwardenClient: prelogin → password-grant token → `/api/sync` → decrypt user key → ensure target folder → per-row push/pull as described in the module walkthrough → read-back of `bitwardenId`/`bitwardenRevision` → audit rows (`sync.push`, `sync.pull`, `sync.run`, `sync.error`).

## SQLite schema
The database has four tables, created by database.js migrations on first open.

```sql
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS keys (
  id TEXT PRIMARY KEY,               -- crypto.randomUUID()
  name TEXT NOT NULL,
  type TEXT NOT NULL CHECK (type IN ('rsa','ed25519','ecdsa')),
  bits INTEGER NOT NULL,             -- RSA bits, or 256/384/521 for ECDSA; ed25519 = 256
  comment TEXT NOT NULL DEFAULT '',
  fingerprint TEXT NOT NULL,         -- SHA256:<base64 no padding>
  privateKeyPem TEXT NOT NULL,       -- AES-256-GCM blob; '' for public-only records
  publicKeyPem TEXT NOT NULL,        -- SPKI PEM
  publicAuthorizedKey TEXT NOT NULL, -- authorized_keys line
  encrypted INTEGER NOT NULL DEFAULT 0,
  passphrase TEXT,                   -- always NULL in practice (material never stored)
  createdAt INTEGER NOT NULL,
  updatedAt INTEGER NOT NULL,
  tags TEXT NOT NULL DEFAULT '[]',   -- JSON array
  sshConfig TEXT NOT NULL DEFAULT '[]', -- JSON array
  bitwardenId TEXT,                  -- remote cipher id when the row is linked to Bitwarden
  bitwardenRevision TEXT,            -- last-seen remote revisionDate (ISO)
  bitwardenUpdatedAt INTEGER         -- local epoch millis of the last successful per-row sync
);
-- ECDSA curve is derived from bits at read time (256→nistp256, 384→nistp384, 521→nistp521).

CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT NOT NULL);
-- holds master.hash, master.salt (scrypt verification), and JSON-encoded settings.

CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,               -- epoch millis
  event TEXT NOT NULL,               -- vault.* / keys.* / settings.*
  detail TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_keys_type ON keys(type);
CREATE INDEX IF NOT EXISTS idx_keys_fp ON keys(fingerprint);
CREATE INDEX IF NOT EXISTS idx_keys_name ON keys(name);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit(ts);
```

## Persistence strategy

The SQLite database is a single file at `~/.sshspan/sshspan.db`, created by sql.js on first
open and recreated from scratch on every load (the in-memory WASM database is the source of
truth; the file is only a durable snapshot). Writes are never issued directly to the database
file:

1. **Atomic save.** sql.js `db.export()` produces a complete byte array. The app writes it to a
   temporary file next to the destination (`sshspan.db.tmp`) and, only after the write and fsync
   complete, renames it over the real path. A crash or power loss during the write therefore
   leaves either the previous intact database or an empty/partial `.tmp` file; the real path
   is never a truncated half-write. The directory `~/.sshspan/` is created with `fs.mkdirSync`
   (recursive) before the first save.
2. **Debounced flush.** Individual mutations (key create, update, delete, import, deploy,
   settings change) each trigger a pending save. A 500 ms timer coalesces bursts of rapid
   mutations into a single export+write, so a vault unlock followed by several key operations
   persists once instead of once per operation. The timer is reset on each pending change and
   cancelled on app quit; a final synchronous export runs in the `before-quit` handler so the
   last mutation is not lost if the user closes the window immediately.
3. **No WAL.** The pragmatic journal mode, rollback journal, and WAL pragmas are not used.
   sql.js operates on an in-memory B-tree and the on-disk format is a single self-contained
   file written wholesale; there is no incremental journal to replay or checkpoint, so the
   `no WAL` property is a consequence of the export-and-replace model rather than a disabled
   feature. The trade-off is a full-file rewrite per flush, which is acceptable because the
   database is small (a few kilobytes per key record) and the 500 ms debounce bounds write
   frequency.
4. **File permissions.** The database file and the `~/.sshspan/` directory are created with
   mode 0600 (owner read/write only) on Unix; on Windows the equivalent protection comes from
   the default restrictive ACLs of the user profile directory. Deployed key files under
   `~/.sshspan/keys/<key-id>` are also written 0600.
5. **No encryption at the file level.** The database file itself is not encrypted. Private key
   material is stored only in the encrypted `privateKeyPem` column (AES-256-GCM blob) and the
   master password is stored only as a scrypt verification hash; see SECURITY.md. Anyone with
   filesystem read access to `~/.sshspan/sshspan.db` can read the file, but cannot recover
   private keys without the master password.
## Reasoning log

This section records the design decisions that were deliberately chosen and the alternatives
that were considered and rejected, so that future maintainers can evaluate the reasoning
behind the codebase.

### sql.js vs better-sqlite3 vs sqlite3

- **sql.js (chosen).** sql.js compiles SQLite to WebAssembly and ships as a single npm
  package with no native build step. It runs identically on Windows, macOS, and Linux without
  a compiler, native-gyp build, or platform-specific binary, which matters for a cross-platform
  Electron app distributed as source. The database is held entirely in memory and exported to
  disk on demand, which gives the atomic save model described above. The cost is that every
  flush re-serialises the whole database, but at the scale SSHSpan manages (hundreds of key
  records, a few kilobytes each) that cost is negligible next to the 500 ms debounce.
- **better-sqlite3 (rejected).** better-sqlite3 binds the native SQLite library and offers
  synchronous APIs, WAL support, and far better performance on large databases. It was rejected
  because it requires a native compilation step (node-gyp) that fails on machines without a
  Python/C++ toolchain, produces platform-specific binaries that must be rebuilt per release,
  and complicates packaging for a project whose stated goal is zero-build portability.
- **sqlite3 (rejected).** Same native-build objection as better-sqlite3, with a callback-heavy
  API and no WASM fallback.

### Node crypto vs node-forge

- **Node `crypto` (chosen).** Every cryptographic operation key generation, fingerprinting,
  AES-256-GCM, and scrypt uses Node's built-in `crypto` module. It is backed by the
  platform's OpenSSL/LibreSSL implementation, is FIPS-validated where the platform build enables it, and
  requires no dependency. The API surface used is small: `crypto.generateKeyPairSync`,
  `crypto.createCipheriv`/`createDecipheriv` with the `gcm` mode, `crypto.scryptSync`, and
  `crypto.createHash` for SHA-256 fingerprints.
- **node-forge (rejected).** node-forge is a pure-JavaScript TLS and PKI library. It was
  considered for key generation and AES because it avoids native code, but it is slower, its
  AES-GCM implementation is not constant-time, its scrypt parameters are less well-tested, and
  adding a ~2 MB dependency for a handful of cipher calls is a poor trade for an app whose
  security surface is the native crypto stack.
### bcrypt-pbkdf for OpenSSH private keys

OpenSSH new-format private keys embed a bcrypt-derived KDF. The app uses the standalone
`bcrypt-pbkdf` package rather than `bcrypt` directly because OpenSSH's key derivation is
bcrypt-PBKDF (a variant of the bcrypt password-hashing function with a configurable iteration
count and salt), not the bcrypt password-storage format. `bcrypt-pbkdf` is a small,
suspension-free WASM/JS implementation whose output matches OpenSSH's `ssh-keygen`
interoperability tests, which is the whole reason for using it: keys the app writes must be
loadable by OpenSSH and vice versa.

### JWK interchange for key export

Node's `generateKeyPairSync` returns KeyObject handles that can be exported to JWK via
`key.export({ format: 'jwk' })`. JWK is the only format that round-trips RSA, Ed25519, and
ECDSA key material through a single, versioned, JSON-serialisable structure, so the app
imports and exports private keys as JWK internally and then translates to the on-disk formats
the user actually wants (OpenSSH new-format private, PKCS#8 PEM, SPKI PEM public,
authorized_keys). The translation is lossless for the supported curves and key sizes; the
only information discarded is metadata such as the original passphrase, which the app
re-encrypts at export time if the user requested an encrypted output.

### Vanilla HTML/CSS/JS renderer

The renderer is plain HTML, CSS, and JavaScript with no framework, no virtual DOM, no build
step, and no external network resources. The reasons are deliberate:

- **Determinism.** With no transpiler, bundler, or runtime framework, the renderer's behaviour
  on any supported Electron version is identical to what was tested; there is no framework
  upgrade that silently changes rendering or introduces a dependency with a CVE.
- **Offline operation.** The app is fully offline by design. A framework that lazily loads
  chunks over HTTP would violate that guarantee; shipping the framework bundle at build time
  would add megabytes of code for a UI with four views.
- **Small attack surface.** The renderer holds no private key material (see IPC contract:
`keys:get` never returns private key bytes), so the renderer is untrusted input to the main
  process. A minimal DOM-manipulation codebase is easier to audit for XSS and easier to lock
  down via the preload's exposed, typed API than a framework's re-entrant event system.
- **Accessibility and control.** The four views (Keys, SSH Config, Settings, Audit log) are
  small enough that hand-written components give finer control over focus management, keyboard
  navigation, and dark/light theming than any generic component library would.

