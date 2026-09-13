# Crypto and secrets

What this app is protecting: SSH private keys at rest, the master password,
saved server passwords, Bitwarden credentials and derived keys, and host-key
pins (integrity rather than confidentiality, but a trust anchor).

## Contents

- [Vault encryption](#vault-encryption)
- [Key derivation parameters](#key-derivation-parameters)
- [Server-supplied KDF parameters](#server-supplied-kdf-parameters)
- [Randomness](#randomness)
- [Comparisons](#comparisons)
- [Secrets in memory](#secrets-in-memory)
- [Secrets on disk](#secrets-on-disk)
- [Secrets in transit](#secrets-in-transit)
- [Key lifecycle](#key-lifecycle)

## Vault encryption

- AEAD, not raw encryption — confirm the ciphertext is authenticated and that
  the tag is actually verified (a decrypt path that ignores a tag error and
  returns plaintext-shaped garbage is worse than no encryption).
- **Nonce/IV uniqueness.** A repeated nonce under the same key breaks the
  scheme. Check how nonces are generated and whether re-encrypting the same
  record (e.g. a password change re-sealing every key) can reuse one.
- **Salt per record or per vault**, stored alongside, never hard-coded.
- **Associated data**: if record ids or types are not bound into the AEAD, a
  ciphertext can be moved between records. Check whether swapping two rows in
  the DB is detected.
- **Version/algorithm field** in the stored format, so a future migration
  cannot be tricked into downgrading. If the format carries an algorithm
  identifier read *from the ciphertext*, confirm an attacker cannot select a
  weaker algorithm by editing it.

## Key derivation parameters

- Which KDF, and are the parameters at or above current guidance? For PBKDF2
  count the iterations; for scrypt and Argon2 check memory, time and
  parallelism together — a high iteration count with tiny memory is not strong.
- Parameters must be **stored with the record** so they can be raised later
  without locking users out, and the code must handle records written under
  older parameters.
- Deriving a key must not be skippable — check the path where a cached key is
  reused and whether it can be reached without the password.

## Server-supplied KDF parameters

Specific to Bitwarden/Vaultwarden sync, and easy to miss: the *server* tells
the client which KDF to use and with what cost.

- **Floors alone are not enough.** `value.max(MINIMUM)` protects against a
  server weakening the KDF but does nothing about a server *strengthening* it
  absurdly. `kdfIterations: 2_000_000_000` or `kdfMemory: 16 GiB` turns a sync
  into an unkillable CPU/RAM burn. Clamp both ends.
- **HTTP timeouts do not cover derivation.** The request completes; the damage
  happens afterwards, locally. A 30s network timeout gives no protection.
- **Argon2 vs PBKDF2 parameter confusion.** The same field name means very
  different things per algorithm; a floor intended for PBKDF2 iterations
  (hundreds of thousands) applied to Argon2's time cost is catastrophic. Check
  the clamp is selected by KDF type.
- Same reasoning applies to any other server-supplied size or count that
  drives allocation.

## Randomness

- `getrandom` / `OsRng` / `rand::rngs::OsRng` for anything security-relevant.
- Never `rand::thread_rng()` seeded deterministically, never a PRNG for salts,
  nonces, tokens, or temp-file names.
- Temp file and staging names that must be unpredictable (to resist a local
  attacker pre-creating them) need CSPRNG-derived randomness, not a counter or
  timestamp.
- UUID v4 from a CSPRNG is acceptable for unguessability; UUID v1 is not.

## Comparisons

- Secret comparisons (password hashes, MACs, tokens, fingerprints) must be
  constant-time. Grep for `==` on anything secret.
- Host-key comparison is integrity-critical; a short-circuiting compare leaks
  little here but a *wrong* compare (prefix match, case-insensitive, trimmed)
  is a real bypass.

## Secrets in memory

- `Zeroizing<T>` / `zeroize()` on master passwords, derived keys, decrypted
  private keys, tokens. Check the whole path, not just the struct that holds
  the value at rest:
  - IPC command parameters arrive as plain `String` and are copies.
  - Intermediate `String`/`Vec<u8>` from parsing, base64, or format conversion.
  - Values captured in closures or moved into async tasks.
- A `Drop` impl that zeroizes is defeated by `mem::forget`, by panics that skip
  drops in some configurations, and by the value having already been cloned.
- Process-level exposure worth noting as low/informational, since it bounds how
  much zeroization buys:
  - **Core dumps** — `MADV_DONTDUMP` / disabling dumps for the process.
  - **Swap and hibernation** — `mlock`/`VirtualLock` keeps pages out of swap,
    but a hibernation image contains all of RAM regardless; encrypted swap is
    the real mitigation and is the user's responsibility.
  - **ptrace / debuggers** — any process with the same uid can read memory.
  - Recommend these as documentation rather than pretending they are solved.
- Secrets must not survive a lock: check that locking the vault actually clears
  the in-memory password and derived keys, and that live sessions are torn
  down.

## Secrets on disk

- The vault DB's file permissions, and whether the path can be redirected by an
  env var or argument in a release build.
- Exported private keys: created with restrictive mode *before* content is
  written (see `rust-backend.md`), and on Windows the ACL restriction must fail
  closed rather than warn.
- Backups: encrypted, and the encryption keyed by something the attacker who
  stole the backup does not have.
- Staged/temp copies of secret material: unpredictable names, 0700 parent, 0600
  files, removed on every exit path including error and cancel.
- Logs and audit records must record *that* something happened, never the
  secret itself.
- Deleted keys: is the DB row overwritten, and does SQLite leave the plaintext
  in a freelist page or WAL? Worth an informational note.

## Secrets in transit

- TLS verification never disabled, no custom verifier that accepts everything,
  no `danger_accept_invalid_certs`.
- Redirects re-validated — a redirect can move an authenticated request to
  another host, taking the credential with it.
- Credentials in URLs or query strings end up in logs.
- Response size bounds, so a hostile server cannot make the client buffer
  unboundedly.

## Key lifecycle

- Generation: correct key sizes, and the entropy source.
- Import: a malformed or hostile key file must not panic or execute anything;
  passphrase-protected keys must not be silently stored unencrypted.
- Export: explicit user action, correct file permissions, and the format
  actually matching what the UI promised (an "encrypted" export that is not).
- Deployment to a server: what is written to `authorized_keys`, and whether any
  field is attacker-influenced (see the SSH config injection notes in
  `ssh-sftp.md`).
- Rotation and deletion: does removing a key remove every copy, including
  deployed ones, backups, and sync state?
</content>
