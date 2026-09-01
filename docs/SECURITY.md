# SSHSpan security model

SSHSpan is a local-only SSH key manager. It stores no data on any server, makes no network
requests, and ships no telemetry. This document describes the cryptographic controls, the
storage layout, and the threat model the app is designed to defend against, as well as the
things it deliberately does not defend against.

## Cryptographic primitives

All cryptography is implemented with Node's built-in `crypto` module; no third-party
cryptographic library is used.

### Master password and vault

The master password is never stored. When a vault is created, the app derives two values:

- a **scrypt** key derivation: N = 65536, r = 8, p = 1, over a 16-byte random salt;
- the derived key is used as an AES-256 key to encrypt every private key in the vault.

Separately, a **verification hash** is stored in the `config` table so the app can tell whether
a supplied password is correct without decrypting key material:

- the master password is hashed with scrypt (same parameters, independent 16-byte salt);
- the result is stored in the `config` table as `master.hash` and `master.salt` (base64url);
- on unlock, the supplied password is hashed with the stored salt and compared with the
  stored hash using a **timing-safe** comparison.

The master password exists only in the session service's memory while the vault is unlocked.
When the vault is locked, the in-memory copy is wiped. There is no persistent copy of the
password anywhere on disk.

### Private key encryption

Each private key is encrypted independently with **AES-256-GCM**:

- a fresh 12-byte random **IV** is generated per key per encryption (the standard nonce size for GCM);
- a 16-byte **authentication tag** is produced by GCM;
- **AAD** (additional authenticated data) is the fixed string `sshspan-aad`;
- the encrypted blob is `base64url(salt || iv || tag || ciphertext)`, where `salt` is a
  fresh 16-byte random scrypt salt generated for that specific encryption.

A key is re-encrypted with the current master key whenever the password changes; the
re-encryption happens **before** the verification hash is updated, so a failure mid-way
(strongly unlikely, since the operation is in-memory) can never leave a key stranded in an
unrecoverable state.

## Storage

The database is a single SQLite file at `~/.sshspan/sshspan.db` (see ARCHITECTURE.md for the
persistence strategy). The relevant columns are:

- `keys.privateKeyPem` — the AES-256-GCM blob described above, or NULL before a vault exists;
- `config.masterHash` and `config.masterSalt` — the scrypt verification material;
- everything else — public key material, fingerprints, tags, settings, and the audit log —
  is stored in the clear.

The database file itself is **not encrypted**. File permissions are 0600 on Unix and the
restrictive default ACLs of the user profile directory on Windows.

## The seven security properties

1. **Private keys are encrypted at rest.** No private key material appears in the database in
   plaintext. The only plaintext private-key column is NULL until a vault is created.
2. **The master password is never stored.** Only a scrypt verification hash and its salt are
   persisted, and they are useless without the password.
3. **Verification is timing-safe.** The stored hash is compared with constant-time logic, so
   an attacker cannot learn how close a guess came to matching.
4. **Each key is independently encrypted.** Compromising one key's ciphertext does not reveal
   another's, because every encryption uses a fresh IV and the keys share only the master key.
5. **The vault can be locked.** `vault:lock` wipes the in-memory password and requires the
   master password to reopen; an auto-lock timer (configurable, default 15 minutes of idle
   time) locks the vault automatically.
6. **Exports are under user control.** `keys:export` and `keys:copy-public` require an
   unlocked vault and never write private key material to the clipboard; only
   `clipboard:write-public` exists, and it writes the public key only.
7. **The app is fully offline.** There is no telemetry, no network access, no auto-update
   mechanism, and no phone-home of any kind. Every operation runs locally.

## Threat model

SSHSpan is designed to defend against a specific, realistic class of attacker:

- **an attacker with filesystem access to the machine after the app has closed**, including a
  stolen or borrowed laptop. The database file is readable, but private keys are
  AES-256-GCM-encrypted with a key derived from the master password, which is not on disk.
- **an attacker who obtains a snapshot of the app's memory while the vault is unlocked.**
  They can read the master password and the decrypted private keys, because the session
  service holds them in memory by design. This is an accepted limitation, see below.
- **a malicious or compromised renderer.** The renderer is sandboxed (contextIsolation on,
  nodeIntegration off) and the preload exposes only a typed, minimal API. `keys:get` never
  returns private key material, so even a fully compromised renderer cannot read private keys
  directly; it can only request actions the main process performs with the vault key.

## Limitations

These are deliberate, documented trade-offs, not bugs:

- **The database file is not encrypted.** Only the private-key column and the master hash are
  protected. Public key material, fingerprints, tags, SSH config, and the audit log are
  plaintext in the database file. An attacker with filesystem read access can enumerate every
  key the app knows, including which hosts each key is deployed to.
- **The master password is in memory while unlocked.** Any code running with the same user
  and OS-level access (a debugger, a malicious driver, a compromised hypervisor, or a memory
  dump) can read it. SSHSpan cannot defend against an attacker with kernel or hardware access
  to the running process.
- **No hardware-backed key storage.** SSHSpan uses software cryptography via Node's OpenSSL
  binding. It does not use a TPM, HSM, or platform secure enclave. Keys are as strong as the
  master password and the OS's PRNG.
- **Passphrase protection is only as strong as the user's password.** Scrypt with N=65536,
  r=8, p=1 provides meaningful but not indefinite protection against offline guessing. A
  weak master password can be brute-forced from the stored hash and salt.
- **Full disk encryption is recommended.** Because the database file is not encrypted at the
  file level, SSHSpan relies on the operating system for physical-theft protection. The
  recommended companion control is full disk encryption (BitLocker, FileVault, LUKS) with a
  separate unlock password.
- **Deployed key files are protected by filesystem permissions only.** Files written to
  `~/.sshspan/keys/<key-id>` are restricted to the current user: mode 0600 on Linux/macOS,
  and on Windows the NTFS inheritance is stripped and only the current user is granted
  access (`icacls <file> /inheritance:r /grant:r <user>:(F)`), which is what OpenSSH for
  Windows requires before it will accept a private key. This is standard for SSH private
  keys but is not hardware-backed.
- **Passphrase-protected exports are recommended for portability.** When exporting a private
  key to OpenSSH or PKCS#8 format, the app can encrypt the output with a user-supplied
  passphrase. This passphrase is independent of the vault master password and is not stored.

## Operational guidance

- Choose a master password that is not reused anywhere else and is not a single dictionary
  word. Consider a passphrase generated by a password manager or Diceware.
- Keep the auto-lock timeout as short as is practical (the default is 15 minutes).
- Enable full disk encryption on the machine.
- Treat `~/.sshspan/` as sensitive: back it up encrypted, and do not share the directory.
- Review the audit log (`audit:list`) periodically for unexpected key creation, deletion,
  export, or deploy events.
