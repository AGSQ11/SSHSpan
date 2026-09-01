# Contributing to SSHSpan

Thank you for your interest in improving SSHSpan. This document describes how to set up a
development environment, the conventions the project follows, and how to submit changes.

## Development setup

SSHSpan is an Electron app. From the repository root:

```sh
npm install
npm run dev
```

- `npm run dev` starts the Electron app with logging enabled. There is no hot reload; restart
  after changes (`npm start` works identically).
- The source is in `src/main/` (process, services, IPC handlers) and `src/renderer/` (vanilla
  HTML/CSS/JS views).
- The database is created on first run at `~/.sshspan/sshspan.db`. Use a throwaway home
  directory or a test vault when developing, because the app will prompt to create a vault.

## Conventions

- **Code style.** The existing code uses 2-space indentation, single quotes, semicolons, and
  `'use strict'` module headers. Match the surrounding code in each file.
- **Terminology.** Use "vault" for the master-password-protected store and "key" for an SSH
  key pair record. Do not use "wallet", "account", or "credential" for these concepts.
- **IPC contract.** Every channel returns `{ ok: true, data }` or `{ ok: false, error }`.
  Never return raw private key material from `keys:get`; only public key material, metadata,
  and renderable config.
- **Security.** Never log the master password, private key material, or the contents of the
  encrypted blob. The audit log records events, not secrets.
- **Dependencies.** The app is deliberately dependency-light. Before adding a new dependency,
  consider whether a Node built-in can do the job, whether the dependency is maintained, and
  whether it introduces native code that breaks the zero-build portability goal.

## Testing

```sh
npm test
```

Tests live under `tests/` and are run by the plain-Node harness `tests/run-tests.js` (no test
framework dependency): crypto/format unit checks (`smoke-core.js`), database persistence
(`smoke-db.js`), the full vault+key lifecycle through the aggregator (`smoke-app.js`), and an
interop cross-check against the system `ssh-keygen` when available (`crosscheck-keygen.js`).
Each suite uses a temporary directory, never the real `~/.sshspan/`.

## Pull requests

1. Fork the repository and create a branch from `main`.
2. Make your change with focused commits.
3. Ensure `npm test` passes (all four suites green).
4. Open a pull request describing the change, the reasoning, and any user-visible behaviour.
5. For security-sensitive changes, include a short note in the PR about the threat model
   impact and whether the change is a hardening or a new capability.

## Reporting security issues

Do not open a public issue for security vulnerabilities. Instead, describe the issue and the
steps to reproduce it privately to the maintainers. Include the affected component, the
severity, and any suggested mitigation.

## Licensing

By contributing, you agree that your contributions are licensed under the terms of the
project license (see `LICENSE`).
