# Prior findings

Every issue below was a real bug in this repository, found by an external
reporter or an audit. Read this before sweeping: the fastest way to find the
next bug is to check whether a past one has a sibling that was missed.

Use it three ways:

1. **Regression check** — confirm each fix is still in place.
2. **Sibling hunt** — for each pattern, find the other call sites.
3. **Rot map** — the areas listed under *Where bugs cluster* are where to look
   first when time is short.

## Where bugs cluster

Ranked by how often this codebase has actually gone wrong there:

1. **A validator exists but one call path skips it.** By far the most common
   shape. Whenever you find a guard, enumerate every function that should call
   it. The asymmetry is the bug.
2. **`canonicalize()` on paths that may not exist**, so guards silently pass.
3. **Ignored `Result` on a permission or cleanup operation** — `let _ =`,
   `.ok()`, or warn-and-continue where the security property then does not hold.
4. **Security decisions made in the renderer** and trusted by the backend.
5. **Remote-derived strings reaching a sink** — HTML, the terminal, a path.
6. **Import and restore paths** treated as trusted because "the user chose the
   file".
7. **Bounds applied on one side only** — floors without ceilings, minimums
   without maximums.

## Confirmed and fixed

Check these have not regressed.

**Updater**
- Ran installers with no signature or hash verification; host allowlist
  bypassable; HTTPS not enforced; redirects unvalidated.
- Accepted asset URLs from any public GitHub repository.
- A renderer-controlled value could steer the installer temp-file path.
- Shipped a placeholder minisign key, so verification could not succeed.
- Legacy (non-prehashed) signatures were accepted.

**Renderer / webview**
- DevTools enabled in release builds.
- Master password retained in renderer memory.
- HTML injection in the SSH config import menu.
- A second `<meta>` CSP in `index.html` intersecting with the config CSP and
  drifting out of sync.
- Category picker opened *behind* the host modal (equal z-index, DOM order
  decided) making it unreachable — a UI failure that blocked a whole feature.

**SSH / SFTP**
- SSH config injection via unescaped values; key names now go through
  `validate_key_name`, which every create/import/rename path must use.
- Path traversal from hostile remote filenames.
- A remote filename reaching Windows `ShellExecute`.
- Silent trust-on-first-use host-key acceptance.
- Backup restore silently replaced existing host-key pins.
- Keyboard-interactive answered unlimited server prompts with the saved
  password.
- Cancel during a server-to-server copy fell through to a fallback channel and
  kept transferring; the cancel sentinel was also wrapped into a longer string
  so the job finished as `Failed` with a garbled message instead of `Cancelled`.

**Filesystem and permissions**
- `system_write_text_file` could write arbitrary text anywhere user-writable
  (Startup folder, shell rc files) — now gated on `DialogPathStore`.
- `system_open_external` accepted arbitrary URLs and paths, and would
  ShellExecute any existing local file.
- SFTP edit staging used a predictable, world-readable temp directory, and was
  symlink-hijackable on multi-user Linux.
- Deployed private keys were briefly world-readable on Unix; Windows ACL
  failures were silently ignored on the deploy path.
- `SSHSPAN_DB` let any local process redirect the vault database in release
  builds (now debug-only).

**Crypto / vault**
- Private key material passed through the WebView during export.
- No backoff on repeated master-password unlock attempts.
- Backup restore imported key blobs undecryptable under any known password.
- Bitwarden: SSRF DNS-rebinding TOCTOU; unvalidated redirects; unbounded
  response bodies; wrong key material substituted on seal/unseal failure.
- Legacy plaintext master-password comparison was not constant-time.

**Build / docs**
- CI third-party actions pinned to mutable tags instead of commit SHAs.
- PRIVACY.md and SECURITY.md claimed "no network / scrypt" while the updater
  (on by default) and Argon2id shipped. **Stale security claims in docs are
  findings** — they are what users base decisions on.

## Reported and open at time of writing

Verify current state before reporting these again; several may be fixed.

**Critical / high**
- **Queued SFTP downloads bypass `validate_sftp_local_path`.** The validator is
  called only from `sftp_download` and `sftp_upload`; `sftp_queue_add` takes a
  renderer-supplied `dest_dir` straight to `create_dir_all` + `canonicalize`.
  Because the validator is also what blocks the app-data directory, a
  compromised renderer plus a hostile server can overwrite the vault DB.
  *(An earlier review wrongly cleared this by characterising the validator as
  a system-directory denylist and missing the app-data guard. Read the whole
  function before dismissing a finding.)*
- **TOFU consent enforced only in the renderer** — `allow_tofu` is a raw IPC
  boolean; the backend cannot prove the dialog was shown.
- **Crafted backups can plant host-key pins** for hosts never contacted: a
  differing pin is skipped, an absent one is inserted unconditionally.

**Medium**
- **`is_system_path` returns false for non-existent paths** because the Unix
  branch is wrapped in `if let Ok(canonical) = p.canonicalize()`. New paths
  under `/etc`, `/usr/lib` and friends are unchecked.
- **The Windows branch of `is_system_path` never matches**: it lowercases the
  path and compares against mixed-case literals (`"C:\\windows"`), so the
  prefix test is always false. Only the `WINDIR` fallback does anything, and it
  inherits the canonicalize hole.
- **Staging directory hijack**: another local user can pre-create
  `/tmp/sshspan-edit`; the symlink check passes for a real directory they own,
  the `0700` chmod then fails and is only logged, and staged files inherit
  umask (0644).
- **`DialogPathStore` never forgets.** Insert-only `HashSet`, no single-use
  nonce, no purpose binding — a path approved once is writable for the rest of
  the session, and the same allowlist serves SFTP downloads and backup exports.
- **Key export writes before fixing permissions.** `OpenOptions::mode()`
  applies at creation only, so a pre-existing file is written under its old
  mode and chmod'd afterwards. Windows ACL failure only warns.
- **Bitwarden KDF parameters have floors but no ceilings** — a hostile vault
  server can specify absurd iterations/memory and burn CPU and RAM locally. The
  HTTP timeout does not cover derivation.

**Low / informational**
- `terminal_keepalive` writes `\x00` into the PTY, which interactive programs
  receive as Ctrl-@. Should be an SSH-level keepalive.
- Bitwarden master password is `Zeroizing` inside the client struct, but the
  IPC command parameter and the hashing helper take plain `String`.
- SSH config is written under `ProjectDirs/ssh/config`, not `~/.ssh/config`,
  despite what the UI implies.
- `terminal_connect` interpolates host and username into the xterm stream —
  small ANSI spoofing surface.
- Trailing data in a `.minisig` is ignored by the parser. Not exploitable (the
  signature is still verified over the installer bytes) but worth tightening.
- `examples/dev-sshd.rs` accepts any user with a fixed password on
  `127.0.0.1:2222`. Dev-only and not shipped, but confirm that stays true.
- Registered-but-unused Tauri plugins (`sql`, `notification`, `os`, `process`,
  and `opener` beyond one command) — dead surface.

## Reports that were wrong, and why

Worth reading: two of these were features that existed but were invisible,
which is a real usability finding and not a security one. Do not "fix" them by
reimplementing.

- *"SFTP has no multi-select"* — it did (ctrl/shift-click, Ctrl+A); there was
  no affordance telling anyone.
- *"No way to show all keys across categories"* — there was; the filter button
  shipped with the `disabled` attribute and only enabled once JS ran, so it
  looked inert.
- *"Bitwarden passwords are plain Strings"* — the client struct uses
  `Zeroizing`; only the IPC parameter is plain.

The lesson for the audit: when a report says a control or feature is missing,
check whether it exists and is merely unreachable or undiscoverable. The fix is
different, and claiming a phantom vulnerability costs credibility.
</content>
