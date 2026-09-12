# SSHSpan security model

SSHSpan is a local-first SSH key manager. It stores no data on any server and ships no
telemetry. Its only network traffic is (1) an update check against GitHub, on by default and
disableable in Settings, and (2) the optional **Bitwarden/Vaultwarden sync**, which talks
only to the server the user explicitly configures. This document describes the cryptographic
controls, the storage layout, and the threat model the app is designed to defend against, as
well as the things it deliberately does not defend against. It describes the current
Rust/Tauri implementation (v1.7.x).

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
  **Argon2id** (64 MiB memory, 3 iterations, 4 lanes) from the master password — deliberately
  expensive, so this runs per single-key operation, never in a list loop;
- a fresh 12-byte random **nonce** (OsRng) is used per encryption;
- **AES-256-GCM** produces the ciphertext and the 16-byte authentication tag.

Saved server passwords are sealed with the same scheme. Changing the master password
re-derives and re-seals every key and saved server password **in memory first**; if any
record fails to unseal, the whole change is aborted and nothing is persisted, so a failure
can never leave a key stranded in an unrecoverable state.

Vault backups are sealed (same envelope) with the vault password; restoring a backup taken
under a different password re-seals every readable blob with the current password, and
blobs that cannot be decrypted under either password are **excluded** (and counted in the
result/audit log) rather than imported in a stranded state.

## Storage

The database is a single SQLite file at the platform app-data directory
(`%APPDATA%\SSHSpan\sshspan.db` on Windows, `~/.local/share/SSHSpan/sshspan.db` on Linux).
The relevant columns are:

- `keys.private_key_encrypted` — the sealed envelope described above;
- `servers.saved_password` — sealed with the same scheme;
- `known_hosts` — one row per trusted host, keyed by `host:port`, storing the exact
  wire-format host-key blob and its SHA-256 fingerprint;
- `config` table row `master.hash` — the Argon2id verification material;
- everything else — public key material, fingerprints, tags, settings, and the audit log —
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
   are serialized by the backend directly into a user-chosen file — the decrypted key never
   crosses the IPC boundary into the renderer process — and every export is audited.
7. **The network surface is small, explicit, and user-controlled.** Exactly two destinations
   exist: the GitHub update check (default on, disableable; downloads pinned to
   `github.com/AGSQ11/SSHSpan/releases/`, HTTPS, redirect-validated, size-capped, verified
   against GitHub's asset digest and a minisign release signature) and the opt-in Bitwarden
   sync (below). No other endpoint is contacted.

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
- **Deployed keys are protected by filesystem permissions only**: 0600 from creation on
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
  `https://github.com/AGSQ11/SSHSpan/releases/download/…` (not merely any github.com host),
  so a compromised renderer cannot retarget the updater at another repository's asset.
- **HTTPS + host allowlist on every redirect hop**, followed manually and re-validated.
- **Size caps** on the manifest, the signature, and the installer.
- **SHA-256 verification** against GitHub's computed asset digest before execution.
- **minisign release signature** verified against a public key embedded in the binary —
  which binds the installer to the source tree even if the GitHub repo/token is compromised.
  Until the maintainer provisions the signing key (`MINISIGN_SECRET_KEY` secret + embedded
  public key, see CHANGELOG "Unreleased"), releases ship unsigned and the digest check
  alone applies; the updater logs this state at startup.

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
  in dialogs, connect to hosts). The high-value commands are narrowed accordingly — writes
  require a user-approved dialog path, `system_open_external` only opens SSHSpan-staged
  files, and the updater is repo-pinned and signature-checked — but renderer compromise
  remains the highest-impact single failure, which is why the XSS defenses above are the
  app's most important attack surface.

## Limitations

These are deliberate, documented trade-offs, not bugs:

- **Known third-party dependency advisories.** The `rsa` crate (transitive via the russh
  SSH stack, versions 0.9.x and 0.10.0-rc) carries RUSTSEC-2023-0071 ("Marvin", a timing
  side channel against RSA *decryption*). There is no patched upstream release. Exposure in
  SSHSpan is limited: the app never RSA-decrypts attacker-controlled ciphertext (the
  attack's requirement) — RSA appears only in signature verification (host keys) and
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
  to decrypt — the same trust model as any Bitwarden client. A malicious server, however,
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
- Provision the minisign release key (CHANGELOG "Unreleased" checklist) so auto-updates are
  signature-verified end to end.
