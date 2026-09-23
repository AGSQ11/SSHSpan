# SSHSpan security model

SSHSpan is a local-first SSH key manager. It stores no data on any server and ships no
telemetry. Its network traffic is (1) an update check against GitHub, on by default and
disableable in Settings, (2) the optional **Bitwarden/Vaultwarden sync**, which talks
only to the server the user explicitly configures, (3) the **SSH/SFTP connections and
transfers the user initiates** via Connect/SFTP - by design these carry vault secrets to the
target hosts the user chose, and (4) when the AI assistant is configured and used, its
**model-provider and MCP-server traffic**, both to user-entered URLs (below). This document describes the cryptographic
controls, the storage layout, and the threat model the app is designed to defend against, as
well as the things it deliberately does not defend against. It describes the current
Rust/Tauri implementation.

## Cryptographic primitives

Cryptography is implemented in Rust with audited RustCrypto crates (`aes-gcm`, `argon2`,
`sha2`, `hkdf`, `pbkdf2`), the `ssh-key` crate for OpenSSH key parsing/serialization, and
`russh` for the SSH transport. PuTTY PPK v2/v3 import/export is hand-written against the
PuTTY spec, with MAC verification in constant time.

### Master password and vault

The master password is never stored. When a vault is created, an **Argon2id** verification
hash (PHC string, crate-default parameters: 19 MiB memory, 2 iterations, 1 lane) is stored
in the `config` table under the key `master.hash`; on unlock the supplied password is
verified against it with the `argon2` crate's constant-time verifier. Vaults created by
older builds that stored a legacy plaintext verifier are transparently upgraded to Argon2id
on the first successful unlock.

While the vault is unlocked, the master password exists only in memory inside a
`Zeroizing<String>` store; per-command copies are also zeroized on drop. When the vault is
locked the store is cleared and every live SSH/SFTP session is killed. There is no
persistent copy of the password anywhere on disk.

Password verification attempts are rate-limited: after 5 consecutive failures, further
attempts are delayed with an exponential backoff (30 s doubling per failure, capped at
15 minutes). This slows IPC-driven guessing; the primary offline defense remains the
at-rest Argon2id hash, which does not depend on this in-process counter.

### Private key encryption

Each private key is sealed independently as an `EncryptedVault` envelope
(`{salt, nonce, ciphertext, auth_tag}`, base64, JSON):

- a fresh 32-byte random **salt** is generated per seal, and the AES-256 key is derived with
  **Argon2id** (64 MiB memory, 3 iterations, 4 lanes) from the master password - deliberately
  expensive, so this runs per single-key operation, never in a list loop;
- a fresh 12-byte random **nonce** (OsRng) is used per encryption;
- **AES-256-GCM** produces the ciphertext and the 16-byte authentication tag.

Saved server passwords are sealed with the same scheme. Changing the master password
re-derives and re-seals every key, every saved server password, **and the stored Bitwarden
sync credential** in memory first; if any record fails to unseal, the whole change is
aborted and nothing is persisted. The re-sealed records and the master verifier are then
committed in a **single SQLite transaction**, so a crash or I/O error part-way rolls back to
the complete old state - the vault never ends up split across two passwords.

Vault backups are sealed (same envelope) with the vault password; restoring a backup taken
under a different password re-seals every readable blob with the current password, and
blobs that cannot be decrypted under either password are **excluded** (and counted in the
result/audit log) rather than imported in a stranded state.

## Storage

The database is a single SQLite file at the platform app-data directory
(`%APPDATA%\SSHSpan\sshspan.db` on Windows, `~/.local/share/SSHSpan/sshspan.db` on Linux).
The relevant columns are:

- `keys.private_key_encrypted` - the sealed envelope described above;
- `servers.saved_password` - sealed with the same scheme;
- `known_hosts` - one row per trusted host, keyed by `host:port`, storing the exact
  wire-format host-key blob and its SHA-256 fingerprint;
- `config` table row `master.hash` - the Argon2id verification material;
- everything else - public key material, fingerprints, tags, settings, and the audit log -
  is stored in the clear.

The database file itself is **not encrypted**. It inherits the restrictive ACLs of the user
profile directory (Windows) / user-owned permissions (Unix).

## The seven security properties

1. **Private keys are encrypted at rest.** No private key material appears in the database
   in plaintext. Every seal uses a fresh Argon2id salt and a fresh nonce, so compromising
   one ciphertext reveals nothing about another.
2. **The master password is never stored.** Only an Argon2id verification hash is
   persisted, and it is useless without the password.
3. **Verification is timing-safe.** Password verification goes through the `argon2` crate's
   verifier; PuTTY PPK MAC verification uses a constant-time comparison.
4. **Each key is independently encrypted.** Compromising one key's ciphertext does not
   reveal another's.
5. **The vault can be locked.** Locking wipes the in-memory password (zeroized) and kills
   every live SSH terminal and SFTP session, because sessions run on unsealed key material.
   On app exit the same teardown runs (`RunEvent::ExitRequested`). An auto-lock timer
   (configurable in Settings) locks the vault after idle time.
6. **Exports are under user control.** Exports require an unlocked vault and can be
   passphrase-protected: OpenSSH format (aes256-ctr + bcrypt KDF), PKCS#8 PBES2
   (PBKDF2-HMAC-SHA256, 100 000 iterations, AES-256-CBC), or PuTTY PPK v3. The export
   passphrase is independent of the vault password and is not stored. Private-key exports
   are serialized by the backend directly into a user-chosen file - the decrypted key never
   crosses the IPC boundary into the renderer process - and every export is audited.
7. **The network surface is small, explicit, and user-controlled.** Two management
   destinations exist: the GitHub update check (default on, disableable; downloads pinned to
   `github.com/AGSQ11/SSHSpan/releases/`, HTTPS, redirect-validated, size-capped, verified
   against GitHub's asset digest and a minisign release signature) and the opt-in Bitwarden
   sync (below). The SSH/SFTP sessions and transfers the user initiates (Connect, SFTP,
   Send-to) are the third, by-design network flow - they carry the vault secrets the user
   chose to use to the target hosts the user chose to reach. The fourth and fifth belong to
   the AI assistant and exist only while it is configured and used: the model provider
   endpoint (user-configured base URL; defaults `api.openai.com` / `api.anthropic.com`) and
   the user-added **MCP servers** (below). No other endpoint is contacted.

## SSH client, SFTP, and host keys

- **Host keys are pinned, and first trust is a user decision.** Before connecting to a
  `host:port` with no stored pin, the app asks the user to confirm; the backend REFUSES an
  unpinned host unless that consent was given (the `StrictHostKeyChecking=yes` equivalent),
  and records a refused attempt in the audit log. When the user accepts, the presented key
  is stored (TOFU), the fingerprint is shown in the terminal, and the trust is recorded in
  the audit log. Every later connection must present the exact same key; a mismatch is a
  hard failure and is recorded in the audit log. Pins are scoped to `host:port` so the same
  hostname on different ports cannot share pins.
- **A malicious SSH/SFTP server is an in-scope attacker.** Remote file names are sanitized
  before they can become local paths: separators, `..` segments, drive letters, UNC paths,
  Windows reserved device names, and control characters are rejected or neutralized, and
  every queued download is verified to stay under the canonical destination directory the
  user chose. Staged copies (edit-in-place, Send-to) live in a 0700 staging directory with
  unpredictable file names; executable extensions are never preserved on staged copies (they
  are forced to `.txt`), and stale staged files are pruned.
- **Authentication secrets are zeroized.** Decrypted private keys and passwords are wrapped
  in `Zeroizing` on the auth path and never logged. Keyboard-interactive authentication
  answers one round of prompts with the saved password and refuses further rounds, so a
  hostile server cannot harvest it via repeated prompts.
- **Deployed keys are protected by filesystem permissions only**: the file is
  created at 0600 *before* any content is written (a previous version opened an
  existing file with `mode(0o600)`, which applies at creation only, so a
  re-deploy wrote the key under the old mode and chmod'd afterwards), and on
  Windows a failure to apply the current-user-only ACL deletes the file and
  fails the operation.
  Unix; on Windows NTFS inheritance is stripped and only the current user is granted access
  (`icacls /inheritance:r /grant:r <SID>:F`, verified as a deploy failure if it cannot be
  applied).

## Bitwarden / Vaultwarden sync

The optional sync feature stores SSH key items in the user's own Bitwarden-compatible vault.
Its security properties:

- **Opt-in and scoped.** The feature is idle until the user configures a server URL, account
  email, and master password in Settings. It talks to *that* server only, and never to
  anything else.
- **HTTPS-only.** Plain `http://` is refused except for loopback targets (self-hosted
  Vaultwarden testing). Redirects are never followed, and every response status is checked.
- **SSRF guard, including at connect time.** The configured URL is validated before any
  request: http/https schemes only, no embedded credentials, and localhost/`.local`
  hostnames, literal loopback, private, link-local, CGNAT, multicast, documentation and
  other reserved addresses (IPv4 and IPv6, including IPv4-mapped, NAT64 and 6to4 forms) are
  rejected. The hostname is DNS-resolved and *every* resolved address must be public. In
  addition, the HTTP client installs a DNS resolver that re-applies the same filtering to
  every connect-time resolution, so DNS rebinding between check time and connect time
  cannot bypass the guard. A self-hosted vault must therefore be reachable via a public
  hostname (e.g. behind a reverse proxy with a real domain).
- **KDF floors are enforced.** Server-announced KDF parameters below PBKDF2 600 000
  iterations or Argon2id 16 MiB / 2 iterations are rejected rather than used.
- **End-to-end encryption is preserved.** Item fields are encrypted client-side with the
  Bitwarden protocol (master key via PBKDF2/Argon2id, HKDF-Expand stretching, AES-256-CBC +
  HMAC-SHA256 EncStrings), exactly as official clients do; the server only ever receives
  ciphertext. SSHSpan accepts only HMAC-verified type-2 EncStrings and verifies the MAC
  (timing-safe) before decrypting.
- **Sync is confirm-first.** Remote overwrites and new remote imports require explicit user
  confirmation; skipped items are counted and reported.
- **The stored vault master password is sealed with the SSHSpan vault password.** It is
  AES-256-GCM-encrypted before it touches disk and is only decryptable while the SSHSpan
  vault is unlocked; locking the vault makes sync impossible until it is unlocked again.
  Changing the master password re-seals it.
- **Deletions are never propagated.** A sync creates and updates items both ways but never
  deletes; a remote deletion is only reported in the summary and audit log.
- **Every sync action is audited** (`sync.config`, `sync.push`, `sync.pull`, `sync.run`,
  `sync.error`).

Known limitations of the sync feature:

- Accounts with **two-factor authentication** are not supported yet (the password grant
  cannot answer a 2FA challenge); use a dedicated account without 2FA. Bitwarden cloud's
  new-device login verification may also require approving the device once by email.
- `bw serve`-style localhost integrations are intentionally not used, for the same SSRF
  reasons that private addresses are rejected.

## Updater

The update check runs at startup unless disabled (`autoUpdateCheck`). It reads GitHub's
latest-release metadata for `AGSQ11/SSHSpan` and, if a strictly newer semver exists, offers
the OS-matching installer. Downloading only happens after explicit user approval, and the
download path is hardened:

- **Repo-pinned URL**: the initial URL must be
  `https://github.com/AGSQ11/SSHSpan/releases/download/...` (not merely any github.com host),
  so a compromised renderer cannot retarget the updater at another repository's asset.
- **HTTPS + host allowlist on every redirect hop**, followed manually and re-validated.
- **Size caps** on the manifest, the signature, and the installer.
- **SHA-256 verification** against GitHub's computed asset digest before execution.
- **minisign release signature** verified against a public key embedded in the binary -
  which binds the installer to the source tree even if the GitHub repo/token is compromised.
  The key was provisioned on 2026-09-12 (key id `D67C45BA942239D8`; the secret lives in the
  `MINISIGN_SECRET_KEY` Actions secret and the maintainer's offline backup, never in the
  repository). Verification is fail-closed: a missing or invalid signature refuses the
  update, so releases published before provisioning cannot serve as auto-update sources
  for provisioned builds.

## MCP servers

The AI assistant can attach remote **MCP (Model Context Protocol) servers** (Streamable
HTTP only) to extend the assistant with external tools. MCP widens the assistant's reach
from the one host in the terminal to every service the user connects - and every one of
those services is an untrusted peer, so the controls below are the whole point of the
feature. Stdio and the legacy HTTP+SSE (2024-11-05) transports are deliberately
unsupported and are refused with a clear error.

- **All MCP traffic goes through the Rust backend.** The renderer never fetches an MCP
  URL, and the page's CSP `connect-src` is unchanged. In Phase 1 the only MCP destination
  is the *configured* origin: one plain reqwest client, deliberately without the SSRF
  resolver, because a self-hosted/LAN server is legitimate. No URL is ever *discovered*
  from a server response, so there is nothing to guard beyond the configured origin - the
  guarded resolver (`bitwarden::ssrf`) is wired to a reserved `guarded_client()` seam for
  Phase 2 (e.g. OAuth endpoints learned via WWW-Authenticate) so discovered-URL handling
  cannot silently dial unguarded. Redirects are
  never followed: a 3xx is a hard error, so an auth header can never be carried to a
  different origin.
- **Tool descriptions, schemas, and results are untrusted.** Anything an MCP server
  returns is text written by a potentially hostile peer and lands in the model's context.
  It is treated exactly like terminal output: every MCP result is wrapped in the
  assistant's per-turn nonce-boundary untrusted block before it enters the conversation,
  and the system prompt tells the model that only the user's own chat messages are
  instructions. This is a defense that *raises the cost* of an injection; injection
  resistance is probabilistic and is not a proof.
- **Per-tool approval and pinning.** No MCP tool is enabled until the user approves it
  individually (default: all disabled). At approval, the tool's definition is pinned as
  SHA-256 over canonical JSON of `{name, title, description, inputSchema, annotations}`.
  If a tool's definition ever changes (a "rug pull"), the pin mismatches, the tool is
  disabled and audit-logged, and the user must re-approve. Server-provided annotations
  (`readOnlyHint`, `destructiveHint`) are shown to the user as hints from an untrusted
  source but are never used to bypass approval.
- **Execution is gated like `assistant_exec`.** The access levels are unchanged
  (read/draft/execute/yolo). At read/draft/execute, every MCP call requires the user's
  approval (unless that tool is explicitly flagged auto-approve); at yolo, calls run
  without a card. The Rust `mcp_call_tool` command independently enforces the level, the
  tool's enabled state, the pin match, and the auto-approve flag. **The human approval
  itself is attested by the renderer** - the backend enforces everything it can verify
  itself, but the click that says "this user approved this call" comes from the renderer,
  so a compromised renderer can attest approval it did not actually receive (same
  boundary as every other approval in the app; see the threat model). An optional
  hardening under consideration is to raise the MCP approval as a native Rust dialog,
  which a compromised renderer cannot click.
- **Credential origin-binding.** Static-auth secrets are sealed with the vault master
  password (never returned over IPC, rotated in the same transaction as the other
  secrets, zeroized after use). The environment-variable source stores only the variable
  *name* and resolves the value from the process environment at request time, never
  persisting it. An auth header is only ever sent to the origin of the server it was
  configured for - never to a redirected URL (3xx is refused outright), and, once Phase 2
  adds discovered URLs, never to those either.
- **Backup/restore entries are inert.** An MCP server entry restored from a backup,
  sync, or import is stored with `confirmed = false` and the backend refuses to connect
  it - no initialize is ever sent - until the user re-confirms its URL and auth source
  by re-saving it in the UI, so a malicious backup cannot point a stored secret or env
  var at an attacker's URL on first connect. The inert flag is only cleared by that
  re-save: a vault lock/unlock does not inert a configured entry (it only drops live
  sessions), and unlocking the vault makes the next call re-initialize a fresh session
  transparently. Vault backups carry server configuration and static secrets.
  Tested: `backup_restored_entries_come_back_inert` (unit).
- **Vault lock tears down sessions.** Locking the vault sends an HTTP `DELETE` with the
  `Mcp-Session-Id` for each live session (a 405 is valid and ignored; the DELETE is
  fire-and-forget so the lock path never blocks on network I/O), drops the in-memory
  session/status state, and uses the same vault-generation capture/re-check pattern as
  the SFTP and terminal paths around every await that registers state; the decrypted
  secrets only ever live in command frames, which end at the lock. Tested: the
  generation pattern and session storage are unit/integration covered; the DELETE
  side-effect is verified in the manual smoke checklist (docs/MCP-SMOKE-TEST.md step
  21), as the teardown call needs a live Tauri AppHandle.

## Threat model

SSHSpan is designed to defend against a specific, realistic class of attacker:

- **an attacker with filesystem access to the machine after the app has closed**, including
  a stolen or borrowed laptop. The database file is readable, but private keys are
  AES-256-GCM-encrypted with a key derived from the master password, which is not on disk.
- **an attacker who obtains a snapshot of the app's memory while the vault is unlocked.**
  They can read the master password and the decrypted private keys, because the app holds
  them in memory by design. This is an accepted limitation, see below.
- **a malicious or compromised SSH/SFTP server.** Host-key pinning, filename sanitization,
  and destination-root containment (above) bound what such a server can do: it controls its
  own filesystem view, not the user's.
- **a malicious or compromised renderer.** The renderer runs under a CSP of
  `script-src 'self'` (no inline/eval scripts), loads no remote content, and renders
  server-controlled text through escaping/`textContent`. That said, the renderer exposes
  the application's IPC surface (`window.__TAURI__`): a full renderer compromise can invoke
  backend commands (e.g. export a key once the vault is unlocked, read files the user picks
  in dialogs, connect to hosts). The high-value commands are narrowed accordingly - writes
  require a user-approved dialog path, `system_open_external` only opens SSHSpan-staged
  files whose extension is on an inert editor/viewer allowlist, and the updater is
  repo-pinned and signature-checked - but renderer compromise
  remains the highest-impact single failure, which is why the XSS defenses above are the
  app's most important attack surface.

  One boundary is worth stating plainly: **exporting** a private key is backend-owned (the
  decrypted key is written to a user-chosen file without crossing IPC), but **importing** a
  private key from a file reads the file in the renderer (`system_select_file`) and passes
  the text to `key_import` over IPC, so the plaintext transits renderer memory during an
  import. This is why a compromised renderer is in the threat model at all.

## Limitations

These are deliberate, documented trade-offs, not bugs:

- **Known third-party dependency advisories.** The `rsa` crate (transitive via the russh
  SSH stack, versions 0.9.x and 0.10.0-rc) carries RUSTSEC-2023-0071 ("Marvin", a timing
  side channel against RSA *decryption*). There is no patched upstream release. Exposure in
  SSHSpan is limited: the app never RSA-decrypts attacker-controlled ciphertext (the
  attack's requirement) - RSA appears only in signature verification (host keys) and
  client-authentication signing, and RSA auth signatures are pinned to `rsa-sha2-256`
  rather than legacy SHA-1. The risk is accepted and the dependency is monitored for an
  upstream fix. Several other transitive crates (`instant`, `proc-macro-error`, `unic-*`,
  `glib` on Linux) are flagged unmaintained-class with no known exploitable issue.

- **The database file is not encrypted.** Only the private-key column, saved server
  passwords, and the verifier are protected. Public key material, fingerprints, tags,
  known-host pins, and the audit log are plaintext in the database file. An attacker with
  filesystem read access can enumerate every key the app knows, including which hosts each
  key is deployed to.
- **The master password is in memory while unlocked.** Any code running with the same user
  and OS-level access (a debugger, a malicious driver, a compromised hypervisor, or a memory
  dump) can read it. SSHSpan cannot defend against an attacker with kernel or hardware
  access to the running process.
- **No OS-suspend hook.** Tauri v2's desktop run loop exposes no suspend/lock event, so an
  OS suspend while the vault is unlocked does not clear the in-memory password; the
  auto-lock timer and the exit teardown are the applicable controls.
- **No hardware-backed key storage.** SSHSpan uses software cryptography. It does not use a
  TPM, HSM, or platform secure enclave. Keys are as strong as the master password and the
  OS's PRNG.
- **Passphrase protection is only as strong as the user's password.** Argon2id (64 MiB, 3
  iterations for key sealing; 19 MiB, 2 iterations for the verifier) provides meaningful but
  not indefinite protection against offline guessing. A weak master password can be
  brute-forced from the stored hash.
- **Full disk encryption is recommended.** Because the database file is not encrypted at the
  file level, SSHSpan relies on the operating system for physical-theft protection. The
  recommended companion control is full disk encryption (BitLocker, FileVault, LUKS) with a
  separate unlock password.
- **Deployed key files are protected by filesystem permissions only** (see above). This is
  standard for SSH private keys but is not hardware-backed.
- **Sync widens the blast radius of a server compromise to key availability, not
  confidentiality.** If the configured Bitwarden/Vaultwarden server or the account password
  is compromised, an attacker obtains ciphertext that requires the account's master password
  to decrypt - the same trust model as any Bitwarden client. A malicious server, however,
  could feed SSHSpan crafted items; they are parsed with the same hardened key parsers used
  for user imports, and unparseable items are reported per-item rather than aborting.

## Operational guidance

- Choose a master password that is not reused anywhere else and is not a single dictionary
  word. Consider a passphrase generated by a password manager or Diceware.
- Keep the auto-lock timeout as short as is practical.
- Enable full disk encryption on the machine.
- Treat the app-data directory and `~/.ssh/sshspan_*` as sensitive: back them up encrypted,
  and do not share them.
- Review the audit log periodically for unexpected key creation, deletion, export, deploy,
  or host-key trust events.
- Keep the minisign signing key backed up offline (losing it means losing the ability to
  sign updates); if it is ever compromised, rotate it by replacing both the
  `MINISIGN_SECRET_KEY` secret and the embedded public key in the same release.
