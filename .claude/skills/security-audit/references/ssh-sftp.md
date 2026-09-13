# SSH, SFTP and the terminal

The remote server is the primary attacker in this app's threat model. The user
chose to connect to it, but that is not the same as trusting it: a server can
be compromised, impersonated, or hostile from the start. Everything it sends is
input.

## Contents

- [Host-key trust](#host-key-trust)
- [Planted trust](#planted-trust)
- [Authentication](#authentication)
- [Remote filenames and paths](#remote-filenames-and-paths)
- [Transfers](#transfers)
- [Remote attributes and sizes](#remote-attributes-and-sizes)
- [The terminal stream](#the-terminal-stream)
- [SSH config generation](#ssh-config-generation)
- [Agent and forwarding](#agent-and-forwarding)
- [Test and example servers](#test-and-example-servers)

## Host-key trust

Host-key verification is the only thing standing between the user and a
machine-in-the-middle. Audit it as the security control it is.

- **Where is the decision made?** If the backend accepts a boolean from the
  renderer (`allow_tofu` or similar) then consent is unverifiable: injected
  renderer code sets it to `true` and the connection proceeds silently. The
  backend cannot prove a dialog was shown. Rank on the fact that it removes
  MITM protection, and prefer a design where the backend owns the prompt or
  issues a one-time challenge the renderer must echo back.
- **First contact vs mismatch must be distinguishable.** "Never seen this host"
  is routine; "the stored key changed" is an attack signal. Presenting them the
  same way trains users to click through the dangerous one. Check the backend
  returns distinct states and the UI renders them differently.
- **Fingerprint before the decision.** Showing it only after accepting is
  theatre.
- **Key lookup keying.** If pins are keyed by `host:port`, check what happens
  for IPv6 literals (already contain colons), for default vs explicit ports,
  and for a hostname reached via different aliases. A lookup that *misses*
  silently degrades a hard mismatch failure into a first-trust prompt — the
  same downgrade an attacker wants.
- **Migrations that re-key the pin store.** Orphaned rows equal lost pins equal
  a fresh TOFU prompt. Check the migration's predicate against every row shape
  that actually exists, and whether it is idempotent in a way that prevents a
  second attempt.
- **Algorithm pinning.** If a host was pinned under one key type, accepting a
  different type without comment lets a server downgrade to whatever it likes.
- **Forget/replace paths** must be explicit user actions and audited.

## Planted trust

Any import path that can *add* a host-key pin is a way to pre-seed trust for a
host the user has never contacted. Then the attacker MITMs the first real
connection and it matches silently.

Check backup restore, vault import, and sync:

- A differing pin for a known host should be refused or surfaced loudly.
- An **absent** pin being inserted unconditionally is the subtle case — there
  is no conflict to detect, so it passes quietly. Decide whether import should
  add pins at all, and if so, mark them as imported and prompt on first use.
- The same reasoning applies to imported server records with saved passwords,
  and to `~/.ssh/config` imports that can define `ProxyCommand` or
  `StrictHostKeyChecking no`.

## Authentication

- **Keyboard-interactive** must not answer an unbounded number of prompts with
  the saved password — a hostile server can simply keep asking and harvest it,
  or use the response count as an oracle. Bound the rounds.
- Password auth: is the password ever sent before host-key verification
  completes? Order matters.
- Public-key auth: confirm the private key is not read into the renderer, and
  that agent use (if any) is scoped.
- Failed-attempt backoff on the *local* master password, so a local attacker
  cannot brute-force the vault.

## Remote filenames and paths

Every name in a directory listing is attacker-chosen. The full hostile set:

- `../` and `..\` sequences, and encoded variants
- Absolute paths (`/etc/cron.d/x`) and drive letters (`C:\`)
- `.` and `..` themselves
- Empty names, names that are only dots or spaces
- Very long names (filesystem component limits, 255 UTF-16 units on NTFS)
- Windows reserved device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1`…, `LPT1`…),
  including with extensions
- Trailing dots and spaces (Windows strips them, which can re-expose a blocked
  extension)
- Characters invalid on the target platform, and NUL bytes
- Unicode tricks: right-to-left override to disguise an extension, homoglyphs,
  normalisation differences that defeat an allowlist
- Names differing only by case on a case-insensitive filesystem

Required handling: sanitise to a single path component, join under a
canonicalised root, then **re-check containment after the join** and again
after any `create_dir_all`, because directory creation can follow a symlink
planted between the check and the write.

## Transfers

- The destination root must be validated once, at the boundary, and every
  expanded job anchored to it. A queue or batch path that skips the validator
  the single-file path uses is the classic asymmetry — and if the validator is
  what protects the app-data directory, that gap reaches the vault DB.
- Recursive walks: `symlink_metadata` only, symlinks treated as leaves, an
  explicit cycle guard, an entry cap and a timeout, and unreadable branches
  skipped rather than fatal.
- Staged `.part` files and their cleanup on every exit path, including cancel,
  pause and panic.
- Overwrite decisions: does the user actually get to choose, and can a remote
  name collide with something outside the intended set?
- Server-to-server copies stage locally — that staging area has the same temp
  directory concerns as editing.

## Remote attributes and sizes

- File sizes drive buffer and progress logic. A server claiming a huge or
  negative-ish size must not cause an allocation or an overflow.
- Permission bits, uid/gid and timestamps from the server are display data;
  never make a local trust decision from them.
- `READDIR` attributes are lstat-derived, so a symlink to a directory reports
  as a non-directory — code that assumes otherwise misclassifies entries.
- A listing with an enormous number of entries is a DoS vector for the
  renderer as much as the backend.

## The terminal stream

Covered in depth in `renderer-web.md` under ANSI. The backend-side questions:

- Does the app compose any of its own status text into the PTY stream with
  interpolated hostnames, usernames or server messages? Strip control
  characters from the interpolated parts.
- Keepalive implementation: sending a byte into the PTY (for example a NUL) is
  visible to the remote program — interactive applications receive it as a
  keystroke. Keepalives belong at the SSH protocol layer (a global request or
  channel-level keepalive), not in the data channel.
- Anything echoing terminal content back into a command, a filename, or the
  clipboard.

## SSH config generation

If the app writes an SSH config, every value it interpolates is a potential
directive injection: a newline in a name introduces a new line in the config,
and a following `ProxyCommand` or `IdentityFile` changes where the user's
traffic and keys go.

- Validate at the point the name is *set*, not only when the config is written
  — every creation, import and rename path needs the same gate.
- Reject whitespace, control characters, newlines, and over-long values.
- Check the file's actual location matches what the UI claims. Writing to an
  app-private path while the UI says `~/.ssh/config` is a correctness and trust
  bug: the user believes their system SSH is configured when it is not.
- Permissions on the written file and its directory.

## Agent and forwarding

- Agent forwarding gives the remote host use of the user's keys for the life of
  the session; it should be off by default and clearly labelled.
- Agent socket exposure and lifetime.
- Upstream classes worth checking against if agent code exists: operations
  intended to be local-only being reachable through a forwarded socket.

## Test and example servers

- `examples/` binaries that accept weak or fixed credentials are fine as long
  as they cannot ship. Confirm Cargo only builds them under `--example`, they
  are not in the bundle's resource list, and they bind to loopback.
- Any test fixture containing a real key or credential is a finding regardless
  of where it lives.
</content>
