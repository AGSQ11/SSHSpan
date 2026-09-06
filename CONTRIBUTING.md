# Contributing to SSHSpan

Thank you for improving SSHSpan. SSHSpan is a Rust/Tauri v2 desktop application with a vanilla HTML/CSS/JavaScript renderer.

## Development setup

Install Node.js 24+, Rust stable, and the Tauri v2 system prerequisites for your platform. From the repository root:

```sh
npm ci
npm run dev
```

The Tauri backend lives in `src-tauri/src/`; the renderer lives in `src/renderer/`. The local vault is created in the platform app-data directory. Use a throwaway test database or a separate development profile when working on vault behavior.

## Useful commands

```sh
# Development app
npm run dev

# Rust tests (requires cargo on PATH)
npm test

# Direct Rust checks
cargo fmt --check --manifest-path src-tauri/Cargo.toml
cargo test --manifest-path src-tauri/Cargo.toml
cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets -- -D warnings

# Production bundles
npm run dist:win
npm run dist:linux -- --bundles deb,rpm
```

The SFTP e2e fixtures are opt-in examples and are not release binaries:

```sh
cargo run --manifest-path src-tauri/Cargo.toml --example dev-sshd
cargo run --manifest-path src-tauri/Cargo.toml --example sftp-smoke
```

## Conventions

- Match the surrounding Rust formatting with `cargo fmt`; use the existing vanilla JS style in renderer files.
- Use “vault” for the master-password-protected store and “key” for an SSH key pair record.
- Tauri commands return `Result<T, String>` through the IPC bridge. Keep command arguments in camelCase on the renderer wire; Rust parameters use the project’s Tauri command naming convention.
- Never log the master password, private key material, saved SSH passwords, or encrypted blob contents.
- Private key material must remain in the Rust process unless the user explicitly requests an export or deployment operation.
- Add or update tests for changes to crypto, database migrations, IPC contracts, and SSH/SFTP behavior.

## Pull requests

1. Create a branch from `main`.
2. Keep commits focused and explain user-visible behavior in the PR.
3. Run JavaScript syntax checks and `cargo test --all-targets` locally.
4. Run `cargo fmt --check`; run clippy when changing Rust APIs or security-sensitive code.
5. For release-affecting changes, verify the native bundle on the platform you can test.
6. Never create a tag or GitHub release automatically; releases are maintainer actions.

## Reporting security issues

Do not open a public issue for security vulnerabilities. Contact the maintainers privately with the affected component, severity, reproduction steps, and suggested mitigation.

## Licensing

By contributing, you agree that your contributions are licensed under the project license (see `LICENSE`).
