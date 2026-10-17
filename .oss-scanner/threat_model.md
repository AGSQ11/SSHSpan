# Threat model

SSHSpan is a desktop application (Rust core, Tauri v2, plain HTML/CSS/JS webview) that stores SSH private keys in an
encrypted local vault, connects to servers over SSH/SFTP with an embedded terminal, optionally syncs keys with a
Bitwarden/Vaultwarden server, and has an optional AI assistant that can attach remote MCP servers. The project's own
statement of its security model is `docs/SECURITY.md`; `docs/ARCHITECTURE.md` describes the components. Read both first.
This file adds what the scanner needs: where untrusted input enters, what is in scope, how to run things, and how
severity is rated.

## What this project does and where untrusted input enters

The Rust core owns every secret: the SQLite vault, the master password (in memory only, zeroized on lock), decrypted
key material, the Bitwarden client and the SSH session engine. The webview holds no secrets and talks to Rust only
through `#[tauri::command]` IPC handlers (`src-tauri/src/commands/`, registered in `src-tauri/src/lib.rs`).

Treat all of the following as attacker-controlled:

- **A remote SSH/SFTP server the user connects to.** Terminal output, remote file names and metadata, SFTP directory
  listings and file contents, server banners, keyboard-interactive prompts, and the host key it presents. A malicious
  or compromised server is explicitly in scope.
- **Key and vault files the user imports.** OpenSSH, PEM/PKCS#8 (encrypted and unencrypted), PuTTY `.ppk` v2/v3,
  `authorized_keys` lines, SSHSpan vault backups, and `~/.ssh/config`. These go through hand-written or wrapped
  parsers (`crypto/keys.rs`, `crypto/pkcs8.rs`, `crypto/putty.rs`, `config/mod.rs`, `db/mod.rs`).
- **A Bitwarden/Vaultwarden server (or anything that can answer as one).** Login responses, announced KDF parameters,
  cipher items and EncStrings, redirects, and DNS answers for the configured URL (`bitwarden/`, `crypto/bitwarden.rs`).
- **MCP servers and the AI model provider.** Tool names, descriptions, schemas and results from MCP servers
  (`assistant/mcp.rs`) and model output (`assistant/mod.rs`, `src/renderer/assistant.js`). These land in the
  assistant's context and can try to drive tool calls and terminal commands (prompt injection).
- **The update channel.** GitHub release metadata, redirects, asset bytes and signatures (`commands/updater.rs`).
- **The renderer, if it is compromised.** The page runs under a CSP of `script-src 'self'`, but a script that runs
  there can call every IPC command. Anything that lets server-controlled text become executable script in the webview
  (XSS in `src/renderer/*.js`) is the highest-impact path into the rest of the app.

Not attacker-controlled: the local user, the contents of their own OS account while the app runs as that user, and the
command line / environment of the app process.

## Components that matter most / least

Most important:

- `src-tauri/src/crypto/` (vault seal/unseal, key parsing and serialization, PPK, PKCS#8, Bitwarden EncStrings).
  Parsers here take untrusted bytes and must never panic, over-allocate, or accept a bad MAC or tag.
- `src-tauri/src/ssh_client/mod.rs`: host-key pinning (TOFU) and authentication.
- `src-tauri/src/sftp/` and `src-tauri/src/commands/sftp.rs`: remote file names to local paths, destination-root
  containment, the 0700 staging directory, "open with editor" sync-back, queued transfers.
- `src-tauri/src/bitwarden/` (SSRF guard in `ssrf.rs`, no-redirect client, KDF floors, confirm-first sync).
- `src-tauri/src/commands/updater.rs`: repo-pinned URL, redirect validation, size caps, SHA-256 digest check and
  minisign verification before anything is executed.
- `src-tauri/src/assistant/` and `src/renderer/assistant.js`, `mcp.js`: access levels (read, draft, execute, yolo),
  per-tool approval, tool-definition pinning, credential origin-binding, inert restored entries.
- `src/renderer/*.js` (except `vendor/`): output escaping, CSP compliance, handling of server-controlled strings.
- `src-tauri/src/db/mod.rs` and `src-tauri/src/ssh/mod.rs`: SQL construction, and deploy of keys to `~/.sshspan/keys`
  and the managed block in `~/.ssh/config` (file modes and ACLs set before content is written).

Less important: `src-tauri/src/config/mod.rs` beyond its parser, settings and tray code in `lib.rs`, the audit log
(except for log injection that forges or hides entries).

## How to exercise it

Everything is built into the image at `/src` and cargo is already offline, so do not run `cargo update` or add
dependencies. There is no display, so the GUI cannot be launched. Work through the Rust core and the renderer's
JavaScript instead.

```sh
cd /src
cargo test --manifest-path src-tauri/Cargo.toml          # about 270 tests, a few minutes
cargo test --manifest-path src-tauri/Cargo.toml <name>   # one test
cargo build --manifest-path src-tauri/Cargo.toml --all-targets
```

- Unit tests sit next to the code (`#[cfg(test)]`). Integration tests are `src-tauri/tests/integration.rs` and
  `src-tauri/tests/mcp_integration.rs`. New reproducers are easiest as extra `#[test]`s in those files, or as
  `cargo run --example`-style programs.
- `src-tauri/examples/dev-sshd.rs` is a local SSH server with an SFTP subsystem on `127.0.0.1:2222` (any user, password
  `testpass`). `src-tauri/examples/sftp-smoke.rs` drives SSHSpan's SFTP client against it. Edit `dev-sshd` to act as a
  hostile server, for example to return crafted file names, attributes or banners.
- `scripts/mcp-smoke-server.py [PORT]` is a dependency-free mock MCP server over Streamable HTTP that can send
  redirects, list-changed events and session-expiry responses.
- The renderer has no build step. `scripts/check-renderer-globals.js`, `scripts/check-ipc-args.js` and
  `scripts/check-vendor.js` run under the image's `node`. `scripts/check-renderer-ui.js` needs Playwright and a browser
  that are not installed here.
- `ssh-keygen` (OpenSSH) is installed, for producing reference key files and checking SSHSpan's output against it.
- Dependency advisories: `cargo audit` is not installed and the audit has no network access, so judge dependency issues
  by reading `src-tauri/Cargo.lock` and the code that calls into the crate.

## How you rate severity

SSHSpan guards SSH private keys, so confidentiality and integrity of key material outrank availability.

- **Critical:** remote code execution in the app process or on the user's machine from attacker-controlled input with no
  user action beyond normal use (connecting to a hostile server, opening a malicious file or sync item); a way for
  untrusted content to run script in the webview (and so reach the IPC surface); a bypass of minisign or digest
  verification that lets the updater run an attacker's installer; disclosure of decrypted private keys or the master
  password to a remote party.
- **High:** a file write or read outside the directory the user chose, triggered by a remote file name or SFTP response;
  bypass of host-key pinning or of the "refuse unpinned host" check; bypass of the SSRF guard (including DNS rebinding)
  or following a redirect with credentials; MCP or AI-assistant execution without the approval its access level
  requires, or a tool-pin check that fails open; an authentication secret sent to an origin other than the configured
  one; a private key written to disk with permissive modes, even briefly; a weakness in the vault or export crypto that
  makes ciphertext cheaper to attack than documented (nonce or salt reuse, a KDF parameter below the documented floor,
  accepting a bad MAC or tag).
- **Medium:** panics or unbounded memory or CPU in a parser reachable from untrusted input (denial of service of the
  app, not of anything else); log or audit-trail injection; secrets that stay in memory or temp files longer than
  documented, without a remote trigger; incomplete cleanup of staged files; a missing audit-log entry for an action the
  documentation says is audited.
- **Low:** hardening gaps with no demonstrated path from attacker-controlled input, and defects in documentation or
  error messages that would mislead a user about security.

Memory-safety bugs in `unsafe` code, in a vendored or dependency crate reached through SSHSpan's code, count as High
at minimum if reachable from untrusted input, and Critical if they give control of execution. SSHSpan has no
telemetry and no server component, so there is no server-side impact class.

Please give each report: the file and line, the trust boundary crossed, a reproducer (a failing `cargo test` is best),
and a patch where you can write one. A short, accurate report is better than a long speculative one.

## Anything to leave alone

These are documented, accepted trade-offs (see "Limitations" in `docs/SECURITY.md`). Do not report them as
vulnerabilities, but do report a way to make them worse than documented:

- RUSTSEC-2023-0071 (Marvin timing side channel in the `rsa` crate, no upstream fix). SSHSpan only uses RSA for
  signing and signature verification, never for decrypting attacker-supplied ciphertext. Report it only if you can show
  a decryption path an attacker controls.
- The SQLite database is not encrypted as a whole. Only private keys, saved server passwords, Bitwarden credentials,
  MCP static secrets and the master verifier are sealed. Public keys, fingerprints, tags, host pins and the audit log
  are plaintext by design.
- The master password and decrypted keys are in process memory while the vault is unlocked, and there is no OS
  suspend/lock hook, no TPM or secure-enclave storage, and a weak master password can be guessed offline.
- An attacker who already runs code as the same OS user, or who can dump the process's memory, is out of scope.
- A fully compromised renderer can call IPC commands. Report the XSS or injection that gets there. Do not report the
  IPC surface itself, or that the human approval for an assistant or MCP action is attested by the renderer. That
  boundary is documented. Do report a command that an unapproved renderer can use in a way the docs say it cannot (for
  example, a decrypted private key crossing IPC on export).
- Assistant "yolo" level runs commands without asking, and the user chooses a model-provider and MCP base URL, so the
  app contacts those hosts. Both are by design. Prompt-injection resistance is documented as probabilistic.
- SSH and SFTP sessions carry the credentials the user selected to the hosts the user chose. That is the feature.
- The Bitwarden sync does not support accounts with two-factor authentication, and the SSRF guard deliberately rejects
  private-range server addresses, so a self-hosted vault needs a public hostname. Both are documented.

Out of scope as code:

- `src/renderer/vendor/` is third-party xterm.js and its addons, pinned and hashed in `VENDOR.md`. Report only how
  SSHSpan uses it, not bugs inside it.
- `src-tauri/examples/dev-sshd.rs`: a dev-only server that accepts any user, not shipped. It is a test harness. Do not
  report its lack of authentication.
- `scripts/` (dev and CI tooling), `src-tauri/tests/`, `src-tauri/gen/`, `src-tauri/icons/` and `docs/`, except that
  `docs/` is the reference for the intended behavior.
- Windows-only code paths (`icacls` ACL handling, NSIS/MSI packaging) cannot be run in this Linux image. They may be
  reported from reading the source if the reasoning is concrete.
