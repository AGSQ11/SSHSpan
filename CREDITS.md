# Credits

Security issues reported by **itzsenu** and **forest** (LowEndTalk), fixed in v1.7.1–v1.7.2:

- Updater ran installers without signature or hash verification, host allowlist bypassable, HTTPS not enforced, redirects unvalidated — #31, #39
- DevTools enabled in release builds — #37
- Master password retained in renderer memory — #37
- SSH config injection via unescaped values — #37, #38
- SFTP path traversal from hostile remote filenames — #36
- Remote filename reaching Windows ShellExecute — #37
- `system_open_external` accepted arbitrary URLs and paths — #37
- HTML injection in the SSH config import menu — #28
- Bitwarden SSRF DNS-rebinding TOCTOU — #30
- Bitwarden HTTP layer: unvalidated redirects, unbounded bodies — #26
- Bitwarden sync substituted wrong key material on seal/unseal failure — #29
- SFTP edit staging used a predictable, world-readable temp dir — #32
- Silent trust-on-first-use host key acceptance — #38
- Backup restore silently replaced host key pins — #38

Additional issues found in the September 2026 code audit, fixed in v1.7.2 (#41):

- Updater accepted installer URLs from any public GitHub repository, and a renderer-controlled value could steer the installer temp-file path
- `system_write_text_file` could write arbitrary text to any user-writable location (e.g. the Startup folder)
- `system_open_external` would ShellExecute any existing local file
- Keyboard-interactive SSH authentication answered unlimited server prompts with the saved password
- Private key material passed through the WebView during export
- No backoff on repeated master-password unlock attempts
- Backup restore silently imported key blobs that could no longer be decrypted under any known password
- Deployed private keys were briefly world-readable on Unix; Windows ACL-restriction failures were silently ignored
- The SFTP staging temp directory could be symlink-hijacked on multi-user Linux hosts
- `SSHSPAN_DB` let any local process redirect the vault database in release builds
- CI third-party actions were pinned to mutable tags instead of commit SHAs
- PRIVACY.md and SECURITY.md claimed "no network / scrypt" while the updater (on by default) and Argon2id shipped

Remaining items tracked under the `security` label.

Rust + Tauri migration suggested by **Herdie** (LowEndTalk Discord Server).
