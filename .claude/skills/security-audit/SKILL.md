---
name: security-audit
description: Exhaustive security audit of SSHSpan — hunt for anything that could put a user's keys, credentials, vault, or machine at risk, at every severity from critical to cosmetic. Use this whenever the user asks for a security review, audit, threat assessment, pentest, hardening pass, or "is this safe", when triaging an externally reported security issue, before cutting a release, or after changing anything that touches IPC commands, the vault, crypto, SSH/SFTP, the updater, file paths, permissions, packaging, or the renderer. Also use it proactively when reviewing a diff that crosses one of those areas, even if the user only asked for a normal code review. Unlike a PR review, this skill deliberately reports low-severity and hygiene findings too — its job is coverage, not brevity.
---

# SSHSpan security audit

This app holds users' SSH private keys, master password, saved server passwords
and Bitwarden credentials, and it talks to servers the user does not control.
A miss here costs someone their infrastructure. Audit accordingly.

Two things make this different from the PR-review skill:

- **Report everything, ranked.** A normal review suppresses low-value findings
  to protect signal. Here, an unreported low finding is a defect in the audit.
  Rank by severity and let the reader triage.
- **Verify before you claim.** Every finding needs a real source→sink path read
  out of the current code, not a pattern match. A confident false positive
  costs more trust than a missed nit. See *Verification discipline* below.

## Start by mapping the trust boundaries

Vulnerabilities live where data crosses a boundary. Enumerate them before
sweeping for bug classes, because a checklist applied without a boundary map
finds only what it already knows to look for.

SSHSpan's boundaries, and who the attacker is at each:

| Boundary | Attacker-controlled input |
|---|---|
| **Remote SSH/SFTP server** | filenames, directory listings, file contents, symlink targets, banners, terminal output, host keys, error strings, `SSH_FXP_*` attributes |
| **Renderer → Rust (IPC)** | every `#[tauri::command]` argument. Treat a compromised renderer as in-scope: XSS or a malicious page means the renderer lies |
| **Update channel** | release JSON, asset URLs, redirect chains, installer bytes, `.minisig` contents |
| **Bitwarden / Vaultwarden server** | KDF parameters, cipher blobs, folder/item names, redirects, response sizes |
| **Imported files** | `~/.ssh/config`, `.pem`/private keys, vault backups, restored DBs |
| **Other local users** | `/tmp` staging dirs, world-readable exports, the SQLite file, swap/core dumps |
| **Build & release** | CI actions, dependency graph, bundled libraries, signing keys |

A finding is only real if you can name the boundary it crosses and the
concrete input that crosses it.

## How to sweep

Work the reference files in `references/`. Each is a checklist for one area
with the specific failure patterns to grep for and the reasoning behind them.
Read the ones relevant to the change under audit; read all of them for a full
audit.

| Reference | Covers |
|---|---|
| `references/tauri-desktop.md` | IPC commands, capabilities, CSP, plugins, updater, packaging, window/webview config |
| `references/rust-backend.md` | Path handling, TOCTOU, permissions, panics, error discarding, integers, concurrency, SQL |
| `references/renderer-web.md` | XSS sinks, DOM injection, IPC argument trust, clipboard, terminal/ANSI output |
| `references/crypto-secrets.md` | Vault crypto, KDF parameters, key handling, secrets in memory and on disk, randomness |
| `references/ssh-sftp.md` | Host-key trust, path traversal, symlinks, transfers, agent, terminal stream |
| `references/prior-findings.md` | Every real bug already found in this repo — regression seeds, and a map of which areas historically rot |
| `references/coverage-checklist.md` | Breadth backstop: lifecycle phases, OWASP TCASVS chapters, and the areas that habitually get skipped |

The first five are depth. `coverage-checklist.md` is breadth — work it last, to
answer "did I skip an area?" before calling the audit done. It is also where
the easy-to-forget categories live (binary hardening, audit-log integrity,
privacy, deep links, DoS, unicode, uninstall residue).

Read `prior-findings.md` early. Bugs cluster: the same mistake tends to recur
in a sibling function that was written by copy-paste and never revisited. A
past finding is the best predictor of the next one.

### Sweep order

1. **Enumerate the IPC surface.** `grep -n "#\[tauri::command\]" -A3` across
   `src-tauri/src/`. Every command is an entry point a compromised renderer can
   call with arbitrary arguments. Cross-check against the `generate_handler!`
   list in `lib.rs` — a command that exists but is unregistered is dead surface;
   one registered but undocumented is unreviewed surface.
2. **Trace each argument to its sink.** File path, SQL, shell, SSH channel,
   HTTP URL, HTML. Note which validator (if any) stands between them.
3. **Look for the sibling.** When a validator exists, find every call site and
   every function that *should* call it and doesn't. Asymmetry is the bug.
4. **Sweep remote-derived data into local sinks** — filenames into paths,
   server strings into HTML or the terminal, server numbers into allocations.
5. **Check the boundaries nobody owns**: packaging, CI, generated files,
   examples, dead plugins.

## Severity

Rank by what an attacker gains and what they need to start. State both.

- **Critical** — remote or renderer-reachable compromise of key material, the
  vault, or code execution. No user interaction beyond normal use.
- **High** — same impact but needs a precondition the attacker can usually
  arrange (a specific setting, a connection to a hostile server), or silent
  loss of a security control (a check that stops firing).
- **Medium** — needs meaningful user interaction or an unusual configuration,
  or degrades a defence without removing it. Local-attacker file exposure.
- **Low** — hardening gaps, defence-in-depth, missing zeroization, ignored
  errors on a security-relevant path, misleading security UI.
- **Informational** — dead code and unused permissions that widen the audit
  surface, stale security claims in docs, inconsistencies that will become
  bugs.

Two rules that matter more than the labels:

- **Security UI that lies is a real finding.** A dialog that says a check
  happened when it didn't, or a consent prompt the backend cannot verify, is
  worse than no dialog — users make decisions on it.
- **A control enforced only in the renderer is not enforced.** The renderer is
  attacker-reachable. If the backend cannot prove the user consented, say so
  and rank it on what the missing check protects.

## Verification discipline

The tooling in this repo lets you confirm most findings rather than assert
them. Use it — a verified finding survives review, a plausible one starts an
argument.

```bash
cd src-tauri && cargo check          # compile
cd src-tauri && cargo test           # 180+ unit + integration tests
cargo +1.98.0 fmt --manifest-path src-tauri/Cargo.toml -- --check   # CI pins 1.98.0
node --check src/renderer/<file>.js  # renderer syntax
```

For anything in the renderer — XSS sinks, DOM behaviour, focus, stacking —
drive the real page in headless Chromium rather than reasoning about it.
Playwright is available; see `references/renderer-web.md` for the harness,
including the `window.__TAURI__` stub you need before navigation (without it
`app.js` throws at module scope and every later top-level `const` is stuck in
the temporal dead zone, so tests silently measure a half-initialised page).

Before writing up a finding, confirm:

- The vulnerable line exists in the **current** code, not a stale memory of it.
- The sink is **reachable** — the command is registered, the branch runs.
- You can name the **input** and the **boundary** it crosses.
- No guard elsewhere already stops it. Read the whole function, not the hunk.

When you cannot verify something in this environment — anything needing a real
Wayland session, a Windows ACL, a packaged AppImage, a live SSH server — say
so explicitly in the finding rather than implying you tested it.

## Reporting

Order findings by severity, highest first. For each:

```
### [SEVERITY] Short title — `file.rs:line`

**What.** The flaw in one or two sentences.

**Why it matters.** The boundary crossed and what the attacker gains.

**Path.** Concrete source → sink, step by step, with the real inputs.

**Evidence.** The quoted code, and how you confirmed it (test run, grep,
browser check). Say if it is reasoned rather than executed.

**Fix.** The specific change. Prefer moving the check to the trust boundary
over adding another caller-side validator.
```

Close the report with:

- **Checked and clean** — the areas you swept that were sound. This is what
  makes the audit auditable; without it nobody can tell coverage from silence.
- **Could not verify** — what needs hardware, a real server, or another OS.
- **Systemic observations** — where the same class recurs, which suggests a
  missing abstraction rather than N separate fixes.

## When fixing rather than reporting

If asked to fix, prefer the change that makes the whole class impossible:

- Move validation into the boundary function every caller must pass through,
  so a new caller cannot forget it. Most findings in this repo are "the
  validator exists but this path skipped it".
- Fail closed. An ignored `Result` on a permission tightening, a `let _ =` on
  a chmod, or a warn-and-continue on an ACL failure means the security property
  silently does not hold.
- Make consent verifiable in the backend rather than trusting a renderer flag.
- Keep the diff minimal and never weaken an existing check to make a test pass.
- Add a regression test where the logic is pure — this repo's `#[cfg(test)]`
  blocks already cover path sanitisation and name validation.
