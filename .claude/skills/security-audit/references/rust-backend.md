# Rust backend

Rust removes memory-corruption bugs from safe code. It removes nothing else.
The vulnerability frontier in a Rust app is logic at boundaries: path handling,
permissions, ignored errors, deserialisation, and concurrency. Audit for those,
not for buffer overflows.

## Contents

- [Path handling](#path-handling)
- [Permissions and file creation](#permissions-and-file-creation)
- [TOCTOU and symlinks](#toctou-and-symlinks)
- [Error discarding](#error-discarding)
- [Panics](#panics)
- [Integers and allocation](#integers-and-allocation)
- [Deserialisation](#deserialisation)
- [Concurrency](#concurrency)
- [SQL and the database](#sql-and-the-database)
- [Process and command execution](#process-and-command-execution)
- [Logging](#logging)
- [Dependencies](#dependencies)

## Path handling

The recurring bug in this codebase. Patterns to hunt:

- **`canonicalize()` on a path that may not exist.** It returns `Err`, and the
  usual shapes are both wrong:
  - `if let Ok(c) = p.canonicalize() { ...check... }` — a non-existent path
    skips the check entirely and is treated as safe.
  - `p.canonicalize().unwrap_or_else(|_| p.to_path_buf())` — falls back to the
    unresolved path, so a later check runs against something different from
    what will actually be written.
  Both mean *new* paths under a protected directory are not protected. Test
  every path guard with a path whose final components do not exist yet.
- **String prefix comparison on paths.** `starts_with` on a `&str` is not
  path-aware (`/etc-backup` starts with `/etc`), and case handling is easy to
  get wrong — a lowercased haystack compared against a mixed-case literal never
  matches. Prefer `Path::starts_with` on canonicalised paths, and unit-test
  the comparison.
- **Denylists of system directories.** They are inherently incomplete. Note
  what a denylist misses that matters here: `~/.ssh`, `~/.bashrc`,
  `~/.config/autostart`, the Windows Startup folder, the app's own data
  directory. An allowlist anchored at a user-chosen root is stronger.
- **Joining remote-supplied names.** Must go through sanitisation *and* a
  containment re-check after the join (`joined.starts_with(root)`), because
  sanitisation alone misses `..` reintroduced by encoding or by an intermediate
  `create_dir_all`.
- **UTF-8 vs bytes.** Paths are not UTF-8 on Unix. `to_string_lossy()` in a
  security check can collapse distinct paths to the same string.

## Permissions and file creation

- **`OpenOptions::mode()` only applies at creation.** If the file already
  exists, the mode is whatever it was, and content is written under the old
  permissions. For anything secret, the order must be: create with restrictive
  mode, or set permissions *before* writing content — never write then chmod.
- **`let _ = fs::set_permissions(...)`** silently accepts failure. On a secret,
  that is the security property not holding. Same for `.ok()`.
- **Windows ACLs.** A `log::warn!` and continue on an ACL-restriction failure
  means the file ships with inherited (broad) permissions while the operation
  reports success. Decide per call site whether that should fail closed — for
  private key material it should.
- **Umask.** Files created without an explicit mode inherit umask, typically
  0644. A 0700 parent directory is not sufficient if the directory can be
  hijacked (below).
- Check the *whole* set: the vault DB, exported keys, staged files, temp files,
  backups, logs.

## TOCTOU and symlinks

- Any `exists()` / `metadata()` followed by an open or write is a race.
- Use `symlink_metadata()` (lstat) when the question is "what is this entry",
  and never follow a symlink when walking a directory supplied by a remote.
- Directory-walk cycles: `ln -s .. up` recurses forever. Require an explicit
  cycle guard *and* treating symlinks as leaves.
- **Pre-created directories in shared temp.** If another local user creates
  `/tmp/<predictable-name>` first, an `AlreadyExists` branch that accepts a
  real directory hands them the staging area. The symlink check is necessary
  but not sufficient — also verify ownership, and treat a failed `chmod 0700`
  as fatal (fall back to a fresh unpredictable directory) rather than logging
  and continuing.

## Error discarding

Grep for these and judge each on whether the discarded error carried a security
property:

```bash
grep -rn "let _ = \|\.ok();\|unwrap_or(false)\|unwrap_or_default()" src-tauri/src/
```

The dangerous shapes are: a discarded permission change, a discarded write of
an audit record, a validation returning `Result` whose value is never checked,
and `unwrap_or(false)` on a *deny* decision (fails open).

## Panics

Panics are availability bugs and, in a process holding decrypted secrets, can
also mean a crash dump containing key material.

- `unwrap()` / `expect()` on anything derived from remote or renderer input.
- Slicing and indexing on attacker-controlled lengths.
- Integer division, `as` casts that truncate.
- Parsers over untrusted bytes — signature formats, config files, key formats.

## Integers and allocation

- Server-supplied lengths or counts used for `Vec::with_capacity` or a read
  buffer: bound them before allocating.
- Release builds wrap on overflow rather than panicking. Any arithmetic on
  attacker-controlled numbers (offsets, sizes, iteration counts) needs
  `checked_*` / `saturating_*`.
- Server-supplied *work factors* — KDF iterations, memory, parallelism — are
  allocation and CPU control. See `crypto-secrets.md`.

## Deserialisation

- `#[serde(default)]` on a security-relevant field: absent means default, and
  if the default is permissive the attacker just omits the field.
- Unknown fields silently ignored (`deny_unknown_fields` absent) is usually
  fine but worth noting where a typo'd field would silently disable a control.
- Untrusted JSON reaching a struct with `Option<bool>` gates — `None` handling
  must be explicit and safe.
- Restored backups and imported configs are deserialisation of attacker-
  supplied structure. Everything in them is untrusted, including ids, paths,
  and any embedded trust material (see `ssh-sftp.md` on planted host keys).

## Concurrency

- A `std::sync::Mutex` guard held across `.await` — deadlock, and in Tauri it
  can wedge the UI.
- Lock ordering between the several registries this app manages.
- Shared mutable state that gates a security decision (throttles, allowlists)
  must be checked and updated atomically, or the check races.

## SQL and the database

- All queries should be parameterised (`sqlx::query(...).bind(...)`). Grep for
  `format!` near SQL.
- `LIKE` patterns built from user input need `%` and `_` escaped with an
  explicit `ESCAPE` clause, or a caller controls the match set.
- Migrations that re-run on every open must be idempotent, and a data migration
  that re-keys rows must be checked for what it *misses* — an orphaned row can
  silently drop a security control (a lost host-key pin becomes a fresh
  trust-on-first-use prompt).
- The DB file's own permissions, and whether an env var can redirect its path
  in release builds.

## Process and command execution

- Anything reaching `Command`, `opener`, `ShellExecute` or a URL handler:
  scheme allowlist, absolute path, no shell interpolation, and no
  remote-derived component.
- Argument vectors rather than shell strings.

## Logging

- Secrets, key material, passwords and tokens must never reach logs. URLs are
  usually fine; query strings may not be.
- Error strings from a remote server land in logs and sometimes in the UI —
  see the ANSI notes in `renderer-web.md`.

## Dependencies

```bash
cargo audit          # RustSec advisories
cargo tree --duplicates
```

Note unmaintained crates, duplicated versions of crypto libraries, and any
dependency doing its own networking or path handling on our behalf.
</content>
