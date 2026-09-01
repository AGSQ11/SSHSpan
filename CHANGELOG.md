# Changelog

All notable changes to SSHSpan are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Initial public release of the documentation set: README, ARCHITECTURE, SECURITY, PRIVACY,
  CONTRIBUTING, CODE_OF_CONDUCT, LICENSE, CHANGELOG, and .gitignore.
- Vault-protected key store with scrypt key derivation (N=16384, r=8, p=1) and AES-256-GCM
  private key encryption.
- Key management: generate (RSA 2048-8192, Ed25519, ECDSA nistp256/384/521), import, export
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

### Changed

- SQLite persistence via sql.js with atomic tmp+rename saves and a 500 ms debounced flush.

### Security

- Master password is never stored; only a scrypt verification hash with timing-safe compare.
- Private key material is encrypted at rest; the database file itself is not encrypted.
- Renderer is sandboxed with contextIsolation and a minimal typed preload API.
- No telemetry, no network access, no auto-update.
