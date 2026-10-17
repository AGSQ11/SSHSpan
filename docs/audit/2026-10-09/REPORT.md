# SSHSpan flaw remediation: audit and remediation report

This report covers the branch `gsq/app-flaws-audit-subagents-c36b18`, which fixes the findings of the 2026-10-09 audit of SSHSpan. The base is `main` at 1ca864f. The code described here is the branch at 3b0fcfb plus the final fix wave (6c19b1b). The report is published in the documentation commit that adds it, together with the [audit index](README.md), the user and developer documents and the CI changes. A follow-up commit answers the first CI run and the review of [pull request #85](https://github.com/AGSQ11/SSHSpan/pull/85) (section 3.2).

## 1. Summary

### 1.1 In brief

- **The audit.** On 2026-10-09 eight read-only audits of SSHSpan v1.9.1 produced 307 candidate findings: 3 Critical, 55 High, 147 Medium and 102 Low.
- **The work.** The findings were fixed in 20 code and script units and one documentation commit, using AI subagents. In each unit an implementer wrote failing tests first as a rule (section 6.5 lists the exceptions), independent reviewers checked the change, fix rounds followed, and the controller verified the result and committed only reviewed diffs (the fix wave's small fifth round was checked by the controller alone). Through 3b0fcfb the 19 units took 33 fix rounds; the last fix wave took four more, after its own re-checks.
- **The result.** In the audit index: 298 Fixed, 7 Partial, 1 Deferred, 1 Accepted limitation, 0 Won't fix. All three Criticals are Fixed: the idle auto-lock fires, the app's confirmations work, and private keys can be written on Windows.
- **Beyond the audit.** Reviews and new tests found more real defects; all were fixed except a few that are documented as accepted risks (sections 6.3 and 7.3). Two predate the branch and matter most:
  - a compromised renderer could point the Bitwarden sync at its own server and upload every private key and saved server password (rated High);
  - Bitwarden accounts that use Argon2id with any memory setting other than 16 MiB could not log in.
- **Tests.** Rust tests grew from 272 at the base (216 library, 45 integration, 11 MCP integration) to 905 at 3b0fcfb and 950 at the fix-wave commit 6c19b1b (882, 48, 20). The renderer had one suite of 76 checks; seven suites ran 2,810 checks at 3b0fcfb, 2,936 at 6c19b1b and 2,935 with the documentation commit, whose `test:ui` no longer carries a copy of the MCP contract check. The pull request follow-up brings Rust to 952 (884 library) and the renderer to 2,998 checks (`test:sftp` 763).
- **Coverage of the final code (6c19b1b).** Renderer lines 92.9% (changed lines 95.7%). Rust production lines 72.0% (changed lines 77.3%), below the 80% target, mainly because code that needs a running Tauri app runs in no test: the commands' 2,378 lines and 1,391 lines of helpers that take an `AppHandle`, `State` or `Window` make up 61% of the uncovered lines; without the commands alone the figure is 80.7%. Section 8.9 has the method and an earlier measurement.
- **Not done.** Seven findings are Partial and one is Deferred, each with a reason (section 7). Some things were never run on the real platform: a real WebView2 drag, a real GTK credential dialog and the exit-time MCP session teardown on Windows (section 9). The Windows CI job first ran on the pull request and failed five tests, none for a product bug (Unix-style paths in four, a too-strict ACL check in one), which the follow-up commit fixes; it has not passed on a runner yet (section 8.4).
- **Published for review.** The branch is pushed and [pull request #85](https://github.com/AGSQ11/SSHSpan/pull/85) is open. There is no release.

### 1.2 What was audited

SSHSpan is a Tauri 2 desktop SSH key manager and SSH and SFTP client. Its Rust core is in `src-tauri/` and its vanilla-JS renderer in `src/renderer/`. On 2026-10-09 eight read-only audits examined v1.9.1 at `main` 1ca864f (the counts are in section 1.1). They are in `docs/audit/2026-10-09/A1-*.md` to `A8-*.md`, which keep their original text and line anchors.

Findings were treated as candidates, not facts. Each unit re-read the cited code before changing it, and said so where a finding was already fixed or wrongly described:
- A3-11: already fixed when JU5 reached it. At the base `window.terminalPaste`, which the right-click, Ctrl+Shift+V and the terminal menu's Paste used, ended in `sendTerminalBytes`, as the audit says; 7e5c5c5 routed every paste through `term.paste()`, and JU5 kept its checks as guards.
- A7-57: the audit's `a:b` example is not a collision; the real one is `back:up` and `back_up`.
- A8-21: two of the three CDP drivers (`cdp-e2e-2.js` and `cdp-featurepass.js`) were not broken the way the audit says.

The documentation accuracy review later found two index rows marked Fixed that were only half done, A5-26 and A5-42. The fix wave finished both.

### 1.3 What landed

At 3b0fcfb the branch holds 23 commits on top of `main`: 4 audit and plan documentation commits, 18 `fix(...)` commits and 1 `chore(scripts)` commit. Two more follow: the fix wave (6c19b1b) and the documentation commit that adds this report. A third, the pull request follow-up, answers the pull request's first CI run and review (section 3.2).

Against the base, `git diff --shortstat 1ca864f..3b0fcfb` gives 65 files changed, +77,763 / -12,129 lines:

| Path | Files | Lines added | Lines removed |
|---|---:|---:|---:|
| `src-tauri/` | 26 | 48,268 | 7,903 |
| `src/renderer/` | 9 | 10,738 | 3,339 |
| `scripts/` | 17 | 14,973 | 881 |
| `docs/` (the audit findings and the plan) | 10 | 3,734 | 0 |
| `.github/` | 2 | 44 | 6 |
| `package.json` | 1 | 6 | 0 |

The fix-wave commit 6c19b1b changes 13 files under `src-tauri/` (+4,470 / -301) and 8 renderer and test files (+996 / -53). The documentation commit adds the user and developer documents, the audit index, this report and the CI changes. The documentation commit also edits code comments, and nothing else, in `src/renderer/app.js`, six Rust files and two test scripts: references to review rounds and internal labels become audit IDs or plain words, the `lib.rs` note on the credential questions is completed, and two notes no longer state Bitwarden's default memory setting as a fact.

When this report was first written, no remote-tracking ref contained 3b0fcfb or 6c19b1b (`git branch -r --contains` printed nothing for either). The branch was pushed later, for pull request #85.

### 1.4 Status counts

These come from the audit index, recounted from its 307 per-ID rows for this report. Status is the disposition at the fix-wave commit plus the documentation commit.

| Status | IDs |
|---|---:|
| Fixed | 298 |
| Partial | 7 |
| Deferred | 1 |
| Accepted limitation | 1 |
| Won't fix | 0 |
| **Total** | **307** |

| Area | Fixed | Partial | Deferred | Accepted | Total |
|---|---:|---:|---:|---:|---:|
| A1 HTML, CSS, visual | 39 | 1 | 0 | 0 | 40 |
| A2 `app.js` logic | 53 | 0 | 0 | 0 | 53 |
| A3 `sftp.js` and `terminal.js` logic | 37 | 0 | 0 | 0 | 37 |
| A4 assistant and MCP logic | 27 | 0 | 0 | 0 | 27 |
| A5 UX | 45 | 2 | 0 | 0 | 47 |
| A6 security | 13 | 1 | 0 | 1 | 15 |
| A7 Rust logic | 55 | 3 | 1 | 0 | 59 |
| A8 docs and consistency | 29 | 0 | 0 | 0 | 29 |
| **All** | **298** | **7** | **1** | **1** | **307** |

| Severity | Fixed | Partial | Deferred | Accepted | Total |
|---|---:|---:|---:|---:|---:|
| Critical | 3 | 0 | 0 | 0 | 3 |
| High | 54 | 1 | 0 | 0 | 55 |
| Medium | 145 | 2 | 0 | 0 | 147 |
| Low | 96 | 4 | 1 | 1 | 102 |

Definitions, as in the index:
- **Fixed** means a committed fix, or for a documentation defect a corrected and committed document, checked against the cited code and test evidence. It is not a guarantee of correctness. A finding with a backend half and a renderer half is Fixed only when both are committed.
- **Partial** means a required part is committed and the missing part has a stated reason:
  - A1-29 (Low): the wholesale CSS token refactor is deferred by ruling R10; dead and duplicate rules were removed.
  - A5-22 (Medium): the updater has no download progress events, so there is no progress bar (R10).
  - A5-28 (Low): every server row has a "..." button; the Edit button in the terminal header, which the finding and the plan proposed, was not added.
  - A6-02 (Medium): the local-path boundary is a deny-list plus confinement, not a dialog-bound grant model.
  - A7-03 (High): importers for PKCS#1, PKCS#8, SPKI and authorized_keys are deferred (R9). The misleading promise is gone from the app and, with the documentation commit, from the README, but a PKCS#8 export still cannot be re-imported.
  - A7-55 (Low): the mock-server `run_sync` suite is deferred (R10); targeted tests exist.
  - A7-56 (Low): the `windows-latest` CI job exists but has not passed on a runner yet (its first run, on the pull request, failed five tests that the follow-up commit fixes; section 8.4), so it is `continue-on-error` until it has passed once.
- **Deferred**: A7-54 (Low), the full queue state-machine suite (R10). Targeted tests exist.
- **Accepted limitation**: A6-11 (Low). russh 0.63 zeroizes the password `String` it takes, but builds its authentication packets in a buffer it clears without wiping, and frees keyboard-interactive answers unwiped. SSHSpan wipes its own copies.

What the counts rest on:
- A5-26 and A5-42 count as Fixed with the fix wave, which finishes their server halves (sections 6.1 and 6.2).
- Ten rows are Fixed only by the documentation commit: A6-07, A7-58, A8-05, A8-06, A8-07, A8-08, A8-09, A8-19, A8-22 and A8-28. Parts of A1-39, A5-05, A8-04, A8-10, A8-17, A8-21, A8-26 and A8-27 are in it too, as are A7-56's Windows job and the README corrections that A5-39 and A7-03 rely on.

### 1.5 The three Criticals and how each was closed

1. **A2-01, the idle auto-lock never fired.** The 10-second status poll re-armed the idle timer, and the 30-second heartbeat kept the backend watchdog fed. Closed in 7e5c5c5:
   - the deadline is the last trusted, capture-phase input plus the configured minutes;
   - the poll no longer re-arms, and the heartbeat is sent only after real activity;
   - terminal typing counts as activity;
   - absent or invalid minutes mean 15, and `"0"` means off.

   It is tested on a fake clock in `scripts/check-audit-safety.js`: 332 checks at that commit; run against the unchanged renderer, the suite's first version (291 checks) passed 134 and failed 148 (a block that hit an error counted as one failure and skipped its remaining checks). The backend watchdog reads the same default, and `settings_get` reports `"15"` (57993ba). d5e9d22 adds a warning 60 seconds before an idle lock.
2. **A5-01, every native `confirm()` guard was bypassed.** `tauri-plugin-dialog` replaces `window.confirm` with an async shim whose Promise is always truthy. Key and server deletes, backup restore, host-key forget, tab close, MCP removal, multi-line paste and update install therefore ran unconfirmed. Closed in 7e5c5c5: all 13 sites await the in-app `confirmModal` (Cancel focused, Escape means no). A static scan in `test:safety` fails on any native `confirm(` call. Since 3b0fcfb a confirmation also ignores the second click of a double-click, so a double-click cannot answer a question that opens under the pointer.
3. **A7-01, every private-key write failed on Windows.** `restrict_windows_file` passed a bare SID to `icacls /grant:r`, which Windows rejects. Deploy, private-key export, backup export and audit CSV export all failed. Closed in 57993ba:
   - one `icacls` call with the `*SID` form, from absolute `System32` paths, with `CREATE_NO_WINDOW`;
   - the file is created empty and restricted before any secret byte is written: inherited permissions are removed and the current user gets full control; where the folder passes none down, SYSTEM and Administrators keep the full control Windows gave the new file.

   The ACL test went RED to GREEN natively on Windows 11, and 22 targeted tests including it ran natively on the final RU1 tree. These were the only tests the branch ran natively on Windows until the pull request (section 8.4).

## 2. Method

### 2.1 The eight audit areas

| Area | Scope | Findings |
|---|---|---|
| A1 | HTML, CSS and visual audit of the renderer: layout at 880x560, 1100x720 and 1600x1000, contrast, focus, dead CSS | 40 |
| A2 | `app.js` logic: timers, dialogs, settings, IPC use | 53 |
| A3 | `sftp.js` and `terminal.js` logic (reported later, commit d3d7e0b) | 37 |
| A4 | Assistant and MCP renderer logic | 27 |
| A5 | UX and ease of use across the main journeys | 47 |
| A6 | Security review of the whole app | 15 |
| A7 | Rust backend logic | 59 |
| A8 | Code critic: docs and code truthfulness, in-app copy, structure, CI scripts | 29 (A8-00 to A8-28) |

The audits were read-only, and every finding cites `file:line`. The renderer audits drove the real page in headless Chromium with a stubbed `window.__TAURI__`. The Rust audits read the code and ran no `cargo`, because the antivirus blocks cargo builds on Windows ([AUDIT-CONTEXT.md](AUDIT-CONTEXT.md), hard rule 3). Nothing was run against real SSH or SFTP servers, WebView2, WebKitGTK, Bitwarden or MCP servers.

### 2.2 Rulings R1 to R12

The [plan](../../superpowers/plans/2026-10-09-flaw-remediation.md) ("Rulings") settles the places where findings disagreed or left a product decision open:

- **R1** Every native `confirm()` becomes `await confirmModal(...)`; no native dialogs from JS.
- **R2** Auto-lock: absent or invalid minutes mean 15, `"0"` means off; the backend reports the defaults; activity is human input, and the heartbeat is sent only after activity.
- **R3** Deploy writes SSHSpan's managed config and shows exactly what it will write (`key_deploy_preview`); it offers the `Include` line; collisions are refused, never overwritten.
- **R4** The Servers "Config" import reads the user's real `~/.ssh/config`, read-only, one `Include` level.
- **R5** Backups never pass through the webview: Rust opens the native dialogs, and the old backup commands are de-registered.
- **R6** MCP approval: the renderer passes `approved=true` after the card resolves; at Read and Draft the card is always shown; a changed tool definition clears auto-approve.
- **R7** AI typing goes through `assistant_type_text` (level at least Draft, no control characters other than TAB, audited as `assistant.type`); the renderer also refuses multi-line text.
- **R8** The `[OI]` token is the provider name OpenAI.
- **R9** Key import stays OpenSSH private and PuTTY .ppk; PKCS#8, PKCS#1, SPKI and authorized_keys import is deferred and documented.
- **R10** Deferred and documented: the A7-54 and A7-55 full suites, the A7-58 legacy Electron vault importer, the A7-03 importers, the A1-29 wholesale CSS token refactor, and updater download progress events.
- **R11** `app_quit`, a one-time tray notice when closing hides the window to the tray, and Ctrl+Q.
- **R12** `app_info` returns the real version; the `v14-tabs` marker is removed everywhere.

### 2.3 Unit workflow

Work ran in units, each listed with its commit in section 3:
- Group 1 and Task 10 came first.
- Then two lanes: Rust units (RU1 to RU6b) and renderer units (JU1 to JU6b), plus DOC phase A for scripts.
- Then two final fix waves, RW for Rust and JW for the renderer, after the first whole-branch reviews.
- Then one last fix wave, FW, after the second whole-branch reviews, and the documentation commit.

Each unit followed one loop (the plan's "Execution rules" and "Global Constraints"):

1. **Brief.** The controller wrote a brief: the files the unit owns, the items and their finding IDs, the contract to implement, and the acceptance commands.
2. **Implementer, test first.** A fresh agent wrote the failing test, watched it fail (RED), fixed the code (GREEN) and reported both, with the contract the other side would build against. Where a new API did not exist yet, the RED run used stubs that kept the old behaviour, or failed to compile. Implementers did not commit and did not dispatch subagents.
3. **Review.** An independent code reviewer checked spec and quality. Security-sensitive units also had a security reviewer.
4. **Fix rounds.** Findings went back to the same implementer. The workflow allowed five rounds per unit. RU5 used four. RW used six: the sixth root-caused a test that hung under load, because the controller ruled that nothing would be committed with a hanging test. The last fix wave used four.
5. **Scoped re-review.** The same reviewer checked only what changed between the reviewed snapshot and the new diff.
6. **Controller verification.**
   - Renderer: `node --check` on every file, the static checks and every `test:*` suite, on the tree or on a clean `git archive` copy.
   - Rust, in WSL: `cargo fmt -- --check`, `cargo clippy --all-targets -- -D clippy::correctness`, the full `cargo test`, and `cargo check --target x86_64-pc-windows-gnu --all-targets`.
   - From RU5 on, while another Rust unit was editing the shared tree, the controller verified on a copy built from `git archive HEAD` plus the unit's reviewed diff.
7. **Commit** (section 2.4).

The plan first proposed four parallel streams. Before any code was written this became sequential execution on one branch, and then two lanes, one Rust and one renderer, with one implementer per lane at a time; the lanes ran together only when their files were disjoint. Near the end, to shorten the tail, more work ran side by side on disjoint files:
- RU6b in two phases around RU6a's files;
- JW in two phases around JU6b's;
- the documentation passes beside the code units, with marked placeholders for unfinished work;
- the whole-branch reviews on frozen snapshots.

### 2.4 Commit mechanics

Only the controller committed, locally:
- Before each commit it regenerated the unit's diff over the unit's paths and compared it with the snapshot the reviewers had approved, ignoring git's `index` lines. It committed only when the tree equalled the reviewed snapshot, and staged only that unit's paths.
- RU3 and JU6a were committed the moment the next unit started on the same files, after the same check.
- RW and JW were staged with `git apply --cached <reviewed snapshot>`, and the staged result was compared with the snapshot (for JW the per-file blocks were identical and only their order differed). This kept the fix wave's edits to the same files unstaged.
- A snapshot was taken only after the implementer reported that it was done. The rule came from JW, whose implementer fixed two more things after the first snapshot; both reviewers then reviewed the final state.

### 2.5 Model routing

The user allowed Opus and Sonnet for any role, and Fable only for security review, code review, critic and advisor roles. The plan's execution rules say the same.

- **Controller:** Opus.
- **Implementers.** Opus was rate-limited during the audit, so the first implementers and reviewers ran on Sonnet: Group 1 and Task 10 were implemented on Sonnet. Sonnet then answered `model_not_found` for a while, and JU1 and every later code unit were implemented on Opus. DOC phase A and the other documentation passes ran on Sonnet.
- **Reviews until 2026-10-12.** The first Group 1 and Task 10 reviews ran on Sonnet, and most other task and code reviews on Opus. Fable reviewed:
  - RU2: the security review and its re-review;
  - JU3: the review and its re-review;
  - RU5: the security review and two re-reviews;
  - RU6a: the security review and two re-reviews;
  - JU5: the security review and its re-review;
  - RU6b: its first security review only.
- **Reviews from 2026-10-12.** Every Fable request then failed with HTTP 429, "Usage credits are required for this model". The Fable whole-branch reviewers died mid-run. From then on every review ran on Opus: RU6b's re-reviews, JU6b, RW, JW, both whole-branch review passes, the documentation accuracy review and the fix wave's re-checks, which the two pass-2 reviewers made. No Fable review is claimed for any of them.
- **Supporting agents** ran on Sonnet: the coverage advisor (after Fable answered "usage credits required"), the coverage tooling, the first draft of this report and the commit-message drafts. This text was written on Opus from that draft, the controller's records and the unit reports, and is checked by the controller before it is committed.

### 2.6 Outages, session ends and the C: drive incident

- **Outages.** Model errors (`model_not_found`, HTTP 429, "usage credits required") and dropped streams killed in-flight agents several times:
  - Task 10's first fix round died before it verified anything, so the controller ran the WSL checks itself;
  - JU3's implementer dropped before its first edit;
  - one outage killed RU6a, JU4's first fix round, both RU5 re-reviews and the coverage advisor;
  - the first attempts at RU6a's first fix round and at JU5 died before any edit;
  - another outage, with Opus and Sonnet both answering `model_not_found`, killed RU6a, JU5, RU6b and DOC phase A;
  - JU6b and the report drafter stalled once on a stream watchdog.

  Each agent was resumed with its context kept, or retried.
- **Session ends.** The controller's session ended five times:
  - once mid-review, on 2026-10-12; before the reviewers were resumed, the controller checked that the trees still equalled the reviewed diffs;
  - around 03:30 on 2026-10-12, followed by about 13 hours idle;
  - from about 01:52 to 13:48 on 2026-10-13;
  - from about 03:41 on 2026-10-14, when the machine and WSL went away, to 23:51;
  - from about 01:28 on 2026-10-15, during the fix wave's second round, to 20:00 on 2026-10-16; WSL had restarted meanwhile.

  Each time the controller resumed from its written notes and `git log`, checked the in-flight trees against the last reviewed diffs, and resumed the agents. From the 2026-10-16 resume on, the session ran under the app's keep-awake hold.
- **The C: drive incident (2026-10-12, about 21:40).** C: had 0.1 GB free. The WSL Ubuntu-25.10 disk image, on C: and not sparse, had grown to 151 GB from about 20 per-agent cargo target directories. A copy of an 11 GB target directory, made by RW's reviewers, finished it, and WSL failed to start. Recovery, as the user chose and approved:
  1. delete the task's temporary scratch copies;
  2. shut WSL down (which also stopped Docker Desktop's backend);
  3. delete 119 GB of the task's target and scratch directories inside WSL, keeping the two shared target directories;
  4. trim, then compact the disk image with an elevated `diskpart` (the user approved the elevation): 151 GB to 32.5 GB, with 119.46 GB free on C: afterwards.

  The rule from then on: every cargo run uses only two shared target directories, `$HOME/sshspan-target` and `$HOME/sshspan-target-win`; no per-agent target directories and no copies of one.
- **Other events.** The WSL VM restarted once during RW's fourth acceptance run, which was re-run clean. The controller's own full `cargo test` of RW hung for more than 15 minutes; that became RW's sixth round (section 6.1).

### 2.7 Tooling

- **Rust.** Every cargo run happened in WSL2 Ubuntu-25.10 (rustc 1.98.0), because the antivirus blocks freshly built cargo build scripts on Windows. The checks are the four in step 6 of section 2.3. The `windows-gnu` check type-checks Windows-only code and executes nothing.
- **Real tools inside tests.** OpenSSH 10.0p2 `ssh -G` and `ssh-keygen -lf` (RU3, RU4, RU6a); an in-process SFTP server (`src-tauri/src/sftp/testkit.rs`) and an in-process russh SSH server (the test fixture in `src-tauri/src/ssh_client/mod.rs`); scripted MCP servers in the MCP tests. The fix wave checked the Bitwarden key derivation against the official Bitwarden SDK's test vectors.
- **Renderer.** There is no build step. Seven headless Playwright 1.56.1 suites run the real `src/renderer` files over HTTP against stubbed IPC, with real xterm 5.5.0 where terminal behaviour matters and fake clocks for timers: `test:ui`, `test:safety`, `test:sftp`, `test:polish`, `test:assistant`, `test:keys` and `test:servers`. They share `scripts/lib/renderer-harness.js`, which since JU6b also withholds the HTML5 drag events that WebView2 withholds while Tauri owns OS drops, and drives a real mouse.
- **Static checks.**
  - `check-renderer-globals.js`;
  - `check-ipc-args.js`: parses `generate_handler!`, fails on calls to unregistered commands, and lists every call site it cannot read statically;
  - `check-vendor.js`;
  - `check-mcp-contract.js`;
  - since JW, `check-renderer-hygiene.js`: comments cite an audit ID or a plain reason, removed code stays removed, and errors are not turned into text by hand in the shapes it knows. It runs inside `test:polish`, and as `npm run check:hygiene` from the documentation commit on.
- **CI.** At 3b0fcfb `ci.yml` runs a Rust job (fmt, clippy, test) on `ubuntu-latest`, a renderer job with all seven suites, an IPC argument-names job and a dependency-advisory job. The documentation commit adds:
  - the MCP renderer contract step and the comment-hygiene step;
  - a timeout on every job;
  - a `windows-latest` job (`cargo test` and the static renderer checks), `continue-on-error` until it has passed once on a runner;
  - in `release.yml`, the Common-Controls 6 manifest step that its Windows `cargo test` needs.

## 3. Units

### 3.1 All units

Rows are in commit order. "Fix rounds" counts the rounds sent back to the implementer after the first review: 33 over the 19 units through 3b0fcfb. Test counts are the ones the unit reports and the controller's verification runs state; where a count was taken in a tree shared with another unit's work in progress, the row says so. The Audit IDs column copies the commit message; the index is the authority on final status. Section 3.2 has the detail for the units after d5e9d22.

| Sha | Unit | Scope | Reviews and fix rounds | Tests | Audit IDs (as listed in the commit message) |
|---|---|---|---|---|---|
| a451eb2, f820ab1, d3d7e0b, 571ad27 | Audit and plan | The audit findings A1, A2 and A4 to A8 and the plan (a451eb2); sequential execution (f820ab1); the A3 findings (d3d7e0b); A3 folded into Tasks 6, 8 and 11 and a new Task 16 (571ad27) | none | none | A3-01 to A3-37 added in d3d7e0b |
| 7e5c5c5 | Group 1 | Renderer: in-app confirmations, an idle auto-lock that fires, dialog and secret hygiene, native paste review (plan Task 1, the renderer part of Task 2, the confirm and paste items of Tasks 8, 11, 12 and 14) | Sonnet: spec ok, Needs fixes (1 Important: auto-lock stayed unarmed after a failed load). Fix 1: 6 of 6 addressed. **1 round** | New `scripts/check-audit-safety.js` (`npm run test:safety`, in CI): 332 checks (291 in round 0, +41 in fix 1). RED 134 ok / 148 FAIL on the unchanged renderer; fix 1 RED 327 ok / 5 FAIL. `test:ui` 76 unchanged | A5-01 A5-02 A5-45 A2-01 A2-06 A2-09 A2-10 A2-13 A2-22 A2-40 A2-49 A1-09 A1-27 A1-30; partial A2-18 A2-53 |
| dc09f93 | Task 10 | SFTP backend: folder uploads create remote folders, short copies fail, bounded walks, safe edit sync, search ids, queue server ids | Sonnet: spec ok, Approved with minors. Fix 1 (7 minors): 7 of 7 addressed (Opus re-review). **1 round** | Library 216 to 316 (+100); integration 45 and MCP 11 unchanged; new in-process SFTP server kit `src-tauri/src/sftp/testkit.rs` | A7-06 A7-09 A7-16 A7-17 A7-18 A7-19 A7-20 A7-21 A7-34 A7-35 A7-36 A7-48 A7-57 A6-06 A6-14 A8-16 (sftp); A6-02 partial |
| 11abb3e | JU1 | SFTP renderer: transactional navigation, safe selection, reliable queue controls (plan Task 11 without layout and drag and drop) | Opus: Needs fixes (3 Important: a refresh dropped a pending navigation; recursive chmod spread special bits to files; paused jobs unbounded). Fix 1: 9 addressed, 1 new Important. Fix 2: 3 of 3 addressed. **2 rounds** | New `scripts/check-sftp-ui.js` (`npm run test:sftp`): 230 checks (197 in round 0, +33). RED 65 ok / 121 FAIL on the unchanged renderer. New shared harness `scripts/lib/renderer-harness.js`, a verified pure move | A3-01..07 A3-09 A3-12 A3-15..22 A3-29 A3-33 A3-34(1-3,6,7) A3-37 A5-40(partial) A5-46 A5-47 A1-04 |
| 57993ba | RU1 | Rust core: Windows secret files, backups kept in Rust, path-only picker, settings defaults and validation, lock gates, vault rotation lock, zeroizing | Opus: Needs fixes (**Critical**: moving the password change off the main thread let sealing commands interleave). Fix 1: the Critical and 5 minors addressed. Fix 2: 7 of 7 addressed. **2 rounds** | Library 316 to 363 (+47), integration 45 to 47, MCP 11; 30 new Linux tests in round 0 plus a Windows-only ACL test; 22 targeted tests ran natively on Windows 11 | A7-01 A7-43 A6-13 A6-03 A2-48 A7-41 A7-25 A7-27 A7-13 A6-04 A2-19 A7-48(part) A7-11 A2-14 A8-14 A5-32(backend) A6-08 A6-11 A7-52 A8-23(d) |
| c227218 | JU2 | Renderer for RU1: backups through the Rust dialogs, honest settings, lock-aware controls, resilient boot, `generate_handler!` registration check | Opus: Approved (no Critical or Important, 9 minors). **0 rounds** | `test:safety` 332 to 464 (+132 checks in 11 new scenarios), 80 of them failing on the old renderer; `check-ipc-args.js` now parses `generate_handler!` and flagged three stale backup calls | A6-03 A2-48 A2-30 A7-41 A6-04 A2-19 A8-14 A5-32 A2-14 A6-08(UI) A2-18 A2-32 A8-11 A8-23(a) A2-20 A5-21 |
| d33028d | RU2 | Assistant and MCP backend: AI typing gate, rug-pull guard bound to the reviewed definition, provider client, MCP records | Fable security: Approved with 1 Important (enabling pinned whatever hash was stored at click time). Fix 1, in two parts (the second made `expected_hash` mandatory for every enable): 7 of 7 addressed. **1 round** | 37 unit tests and 9 MCP integration tests added; at the commit 81 assistant unit tests and 20 MCP integration tests | A4-02 A6-01 A3-30 A6-10 A4-05 A7-29 A8-15 A7-44 A4-03(backend) A4-18 A4-07 A7-30 A4-12 A4-13 A4-27 A7-51 A4-22 A7-49(mcp) A7-50 A6-08(mcp) |
| 46a9d1b | RU3 | Keys and deploy backend: deploy writes what it previews, OpenSSH-safe config, PPK and RFC 4716 export fixes, unique key names | Opus: Needs fixes (1 Important: managed config lines OpenSSH rejects). Fix 1: 7 of 7 addressed; the re-review checked them with OpenSSH 10.0p2 and Win32-OpenSSH 9.5p1. **1 round** | 46 targeted library tests and a rewritten integration test in round 0, more in fix 1 (not totalled); at close 458 library, 48 integration (including a real `ssh -G` parse through an `Include`), 20 MCP | A2-02 A7-02 A5-37 A2-03 A7-05 A5-38 A7-12 A7-45 A7-03(msg) A5-39(msg) A2-46 A5-25 A7-53 A2-05 A7-04 A8-01 A5-04 A5-05(backend) A7-59 A7-56 A8-24 A8-16 A7-22 A7-28 A2-54 A2-31 A7-40 A7-13(deploy) |
| 53347df | JU6a | Renderer polish: keyboard and screen-reader access, one menu system, contrast, palette ranking, audit log filters | Opus: Needs fixes (1 Important: the reveal button was folded into five password fields' accessible names). Fix 1: 6 of 6 addressed. **1 round** | New `scripts/check-ui-polish.js` (`npm run test:polish`): 190 checks; `test:safety` 471, `test:sftp` 231; 149 FAIL lines over 18 RED runs; screenshots before and after at three sizes | A1-05 A2-16 A2-50 A1-26 A2-21 A1-04 A1-28 A2-27 A1-10 A1-11 A1-13 A1-14 A1-06 A5-13 A1-19 A1-22 A5-15 A1-08 A1-18 A1-35 A1-37 A1-32 A1-33 A1-34 A1-36 A5-17 A3-35 A5-16 A2-17 A5-31 A8-18 A5-35 A1-29 A8-24 A2-34 A8-17 |
| d589b51 | JU3 | Assistant and MCP UI: approvals reach the backend, typing through the gate, full arguments on cards, provider and MCP settings round trip | Fable: Needs fixes (**Critical**: approval-card masking keyed by server-chosen parameter names, introduced by JU3 itself). Fix 1: 7 of 7 addressed. **1 round** | New `scripts/check-assistant-ui.js` (`npm run test:assistant`): 280 checks in round 0, 312 after fix 1. RED 74 ok / 134 FAIL on the unchanged renderer; fix 1 RED 255 ok / 29 FAIL | A4-01 A6-15 A4-02 A6-01 A3-30 A4-05 A8-15 A4-17 A4-06 A4-09 A4-19 A4-10 A4-03 A4-16 A4-20 A4-13 A7-33 A8-13 A4-14 A4-22 A8-10 A1-39 A5-29 A4-07 A4-08 A4-11 A8-20 A4-12 A4-15 A4-23 A4-27 A8-27 A4-21 A4-24 A4-04 A4-25 A4-26 A5-36 A1-03 |
| 5e77b54 | RU4 | Servers and SSH client: saved passwords kept on edit, real `~/.ssh/config` import, host-key and timeout messages, UTF-8 carry, fingerprint format | Opus: Needs fixes (1 Important: the chmod walk for servers without file types spread special bits to files, a regression of JU1's fix). Fix 1 (1 Important, 8 minors): the Important addressed; the minors the re-review added went to the deferred list, most of them closed in RU6a. **1 round** | 43 tests in round 0, 6 in fix 1; at the commit 533 library, 48 integration, 20 MCP, counted in a shared tree that held RU5 work in progress; two mutation runs | A2-04 A7-07 A5-03 A2-43 A7-26 A8-02 A5-05 A7-08 A3-32 A7-14 A7-15 A7-46 A6-11(rest) A2-12(backend) A8-16 A8-23(c) and the JU1/RU4 chmod follow-up |
| 652aa5e | JU4 | Keys, categories and deploy UI: truthful exports and imports, the deploy sheet from the backend plan, safe category moves | Opus: Needs fixes (Important: busy controls lost keyboard focus). Fix 1; re-review Needs fixes (new Important: a move into a restored category loop froze the app). Fix 2; re-review Approved. **2 rounds** | New `scripts/check-keys-ui.js` (`npm run test:keys`): 199 checks in round 0, 258 after fix 1, 278 after fix 2; RED 112 FAIL on the first run; 19 + 10 mutants killed; `test:safety` 471 to 470 (one assertion changed on purpose) | A2-02 A2-03 A2-05 A2-07 A2-15 A2-23 A2-26 A2-28 A2-29 A2-31 A2-33 A2-34 A2-36 A2-37 A2-42 A2-45 A2-46 A2-54 A1-07 A1-12 A1-24 A1-40 A5-04 A5-05 A5-12 A5-23 A5-26 A5-27 A5-34 A5-38 A5-39 A5-42 A5-43 A7-03 A7-04 A7-22 A7-32 A8-01 A8-12 A8-16 A8-25 |
| 863a024 | RU5 | Lifecycle and updater: `app_quit`, exit teardown, startup failure dialog, `app_info`, signed-release binding, a Bitwarden sync that keeps data, `system_pick_files` | Fable security: Needs fixes (Important: the stored Bitwarden master password could be used for a typed endpoint; six more). Opus code: Needs fixes (2 Important). Fix 1 (18 items); security Needs fixes (a split save let a concurrent test read the new URL with the old password); fix 2; fix 3 (code Needs fixes: 2 Important on notes re-linking); fix 4; code Approved. **4 rounds**; committed rather than a fifth round | 614 tests at round 0; 579 library, 48 integration, 20 MCP on the controller's isolated tree at the commit; the per-unit added count is not reported; some round-1 tests were written in the same edit as their code and never seen failing (section 6.5) | A2-24 A2-41 A2-47 A2-51 A2-52 A5-24 A5-35 A5-40 A6-05 A6-09 A7-10 A7-23 A7-31 A7-37 A7-39 A7-42 A7-47 A7-48 A8-04 A8-23 A8-26 |
| 463345c | RU6a | SFTP local paths confined, edit-sync conflicts, safe temp files, stricter SSH config parsing, deploy and PPK follow-ups | Opus code: Needs fixes (2 Important, 13 minors). Fable security: Needs fixes (Important: a predictable temp file opened without exclusive create; four more). Fix 1 (20 items): security Approved, code Needs fixes (new Important: a failing save was retried forever). Fix 2 (7 items): both Approved. **2 rounds** | 56 tests in round 0, 37 added or rewritten in fix 1, 11 in fix 2; library 579 to 680, integration 48, MCP 20 on the controller's isolated tree; a flaky keyboard-interactive test fixed (0 of 100 runs fail under CPU contention) | A6-02 A7-19 |
| 11e7e30 | DOC phase A | Scripts and the `release.yml` signing comment: stricter IPC argument check, MCP contract presence checks, the minisign vector script, four stale scripts removed | Opus: Approved with 1 Medium and 4 Low. Fix 1: 6 of 6 addressed. **1 round** | No suite. Self-check seeds in `check-ipc-args.js`; a 16-check `check-mcp-contract.js`; `gen_minisign_test_vector.py --check` matches 4 of 4 constants in `updater.rs` | A8-17 A8-21 |
| d5e9d22 | JU5 | Servers, terminal, lifecycle and lock UX, the updater dialog, Bitwarden results, the Upload picker | Opus code: Needs fixes (Important: restart then Cancel orphaned the live session; header clipping; a stale hint). Fable security: Needs fixes (Important: the OSC 8 confirm hid the real host behind a user name; six more). Fix 1 (19 items): security Approved, code Needs fixes (new Important: a held Ctrl+Q or Ctrl+L answered its own question). Fix 2: code Approved. **2 rounds** | New `scripts/check-servers-ui.js` (`npm run test:servers`, in CI): 325 checks in round 0, 456 after fix 1, 480 after fix 2; RED 124 ok / 180 FAIL on the 652aa5e renderer; 18 + 23 + 5 mutants caught; `test:sftp` 231 to 232, `test:safety` 470 to 471 | A1-20 A1-21 A1-29 A1-38 A2-04 A2-08 A2-11 A2-12 A2-18 A2-24 A2-25 A2-26 A2-34 A2-35 A2-39 A2-41 A2-44 A2-47 A2-52 A2-53 A3-10 A3-11 A3-13 A3-14 A3-26 A3-27 A3-31 A3-34 A3-36 A5-02 A5-03 A5-09 A5-10 A5-11 A5-12 A5-20 A5-22 A5-24 A5-28 A5-30 A5-33 A5-35 A5-40 A5-41 A5-44 A6-12 A7-24 A8-03 A8-25 A8-26 |
| cd11f97 | RU6b | Rust residuals II: MCP records in one transaction, the call gate again before every `tools/call`, sessions bound to their settings, an exit wait for MCP DELETEs, 14 commands off the main thread, bounded category walks, Bitwarden names in errors and pending lists | Fable security: Approved with 2 minors. Opus code: Needs fixes (2 Important). Fix 1 (11 items); both re-reviews (Opus) Approved. **1 round** | Library 680 to 740 (60 new, 48 of them seen failing first); integration 48, MCP 20 | A4-23 A5-12 A7-49 |
| d94ed2d | JU6b | SFTP layout and pointer drag and drop (plan Task 11's layout half and Task 16), the edit-conflict question, one `sftp_open` per tab, hostile names spelled out, settings and cache leftovers, Bitwarden pending changes by name | Opus code: Changes requested (1 High). Opus security: 2 Medium, 3 Low. Fix 1 (13 items); the re-reviews found one new High (Medium for the security reviewer); fix 2 (5 items); both Approved. **2 rounds** | `test:sftp` 232 to 598, `test:keys` 278 to 324, `test:servers` 480 to 511, `test:safety` 471 to 481; RED 41 ok / 91 FAIL; 71 mutants killed | A1-01 A1-02 A1-03 A1-15 A1-16 A1-17 A1-28 A1-31 A3-23 A5-07 A5-12 A7-19 |
| 03dfa92 | RW | Rust final fix wave: saved passwords bound to their account, native credential questions, the program-folder deny-list, the Bitwarden approval token and derived fingerprints, `category_set_order`, every MCP request checked against the stored record, the "Stop editing" guard, the lost wake-up in `db::block()` | Opus code: Block (1 High). Opus security: not ready (1 Medium, 4 Low). Six fix rounds with scoped re-reviews, ending in Approve from both. **6 rounds** | Library 740 to 837 (+97); integration 48, MCP 20; 905 in all | A4-13 A6-02 A6-03 A7-23 A8-16 |
| 3b0fcfb | JW | Renderer final fix wave: deploy warnings and Host lines, the password again for changed servers, the MCP and Bitwarden flows for RW's contract, "Stop editing" asks, lock gating, SFTP menus, one error text, category order through `category_set_order`, `check-renderer-hygiene.js` | Opus code: approve with warnings (1 Medium). Opus security: Approve (1 Low, 4 Info). Fix 1 (10 items); fix 2 (11 items); both Approve. **2 rounds** | `test:assistant` 312 to 367, `test:safety` 481 to 491, `test:sftp` 598 to 679, `test:polish` 190 to 195, `test:keys` 324 to 422, `test:servers` 511 to 580; 135 mutants killed | A2-04 A2-05 A2-07 A2-08 A2-18 A2-45 A2-50 A4-23 A5-03 A5-09 A6-08 A8-01 A8-17 |
| 6c19b1b | FW | Last fix wave: the Bitwarden destination bound to a native question that names the account; a 30-second back-off per kind of credential question; the Argon2id memory unit, and its derivation off the async workers; advice for passphrase-protected key files, at connect and at save; on Windows, key files from local drives only; save dialogs in Downloads with bare suggested names, and the write deny-list for paths picked in them and for every export; the cross-scope category parent; no reuse of an edit being closed; the key move after a lock; the Bitwarden destination in Settings; new servers in a filtered list; backend texts spelled out; clean file-dialog titles | Opus re-checks. Round 1: code Approve (2 Lows, 2 nits); security Approve with warnings (the High closed end to end; 3 Lows, 1 informational point, 1 nit). Round 2: code Approve (2 Lows, 2 nits); security Approve with warnings (2 Lows, one shared). Round 3: code Approve (2 nits); security Approve with warnings (2 Lows, one of them a design limit; 1 informational point). Round 4: security Approve (1 nit, older than the branch). Round 5: checked by the controller. **4 fix rounds** | Library 837 to 856, 871, 878 and 880 over rounds 1 to 4, final 882 (950 with the integration and MCP tests); renderer at the fix-wave commit `test:servers` 676, `test:sftp` 700, `test:keys` 431, 2,936 checks in all; 136 Rust and 64 renderer mutations, all caught | A2-07 A2-08 A4-13 A5-26 A5-42 A6-02 A7-19 |
| the documentation commit that adds this report | Docs | README, CHANGELOG, CONTRIBUTING, `docs/**` (with the audit index and this report), `ci.yml`, `release.yml`, `package.json`, `scripts/check-renderer-ui.js`; comment-only edits in `src/renderer/app.js`, six Rust files and two test scripts | Opus documentation accuracy review of the uncommitted documents against 3b0fcfb: about 140 corrections, all applied | No suite; `test:ui` 76 to 75 (its embedded copy of the MCP contract check is removed; `check-mcp-contract.js` keeps it) | A1-39 A5-05 A6-07 A7-58 A8-04 to A8-10 A8-17 A8-19 A8-21 A8-22 A8-26 A8-27 A8-28; the Windows job of A7-56; the README corrections behind A5-39 and A7-03 |
| the pull request follow-up commit | PR | The first CI run and review of pull request #85: two dependencies with advisories, the transfer list at 880x560, five Windows-only test failures, the release signing gate, the MCP smoke mock, the nine review comments on the documents | The layout fix: an independent code review, Approve with three small points, all taken. The whole follow-up: a Fable code review (Approve, one Low) and a Fable security review (Approve with warnings, three Lows), all answered (section 3.2). The controller checked each subagent's diff, report and evidence, then verified the whole tree | Library 882 to 884 (952 in all); `test:sftp` 700 to 763 (2,998 checks in all); before the layout fix 8 of its checks failed on Windows and 10 on Linux; every changed Rust test and each part of the layout fix was mutation-checked | A1-02; A7-56 (still Partial) |

Notes on the table:
- An ID appears in several commits when each landed a part (A2-18, A5-12 and A8-23, for example). The final status is in the index, not in this table.
- Commit messages often omit IDs the commit covers, so the index cites the code and the tests, not the message. For example:
  - the d5e9d22 message omits A2-43, A5-05, A5-29, A7-07, A7-26, A7-37, A7-38, A8-02 and A8-23, which its body covers;
  - the cd11f97 message omits A7-48 (commands moved off the main thread);
  - the d94ed2d message omits A1-34 (the SFTP search box's name, hint and spellcheck).
- The reviews rated two findings Critical: RU1's rotation interleave and JU3's argument masking. Both were hazards that the change under review had introduced, and both were closed before the unit was committed (section 5.5).

### 3.2 The units after d5e9d22

#### RU6b, cd11f97 (2026-10-12)

Rust residuals: the deferred Rust minors that needed RU5's files, plus items routed from other reviews.

- **What it changed.**
  - MCP server records are read, changed and written in one `BEGIN IMMEDIATE` transaction (save, tool toggle, connect, refresh), so a revoked approval cannot come back and a removed server is never re-created (A7-49).
  - The call gate runs again right before every `tools/call`, after any initialize, refresh or session renewal.
  - Sessions carry the URL and credential they were set up with, and each is ended at its own endpoint with its own credential. The exit waits up to 2 s for those DELETEs.
  - MCP URLs with `?query` or `#fragment` are refused (A4-23). A legacy saved assistant URL that today's rules refuse is refused before the key is unsealed. An audit row that fails after a commit becomes a warning, not an error.
  - The typing and exec gate refuses every Unicode format and default-ignorable character.
  - 14 commands moved off the main thread, among them `key_import`, `vault_create`, `vault_unlock` and `server_save` (A5-12, A7-48), and the races this exposed were fixed (section 6.1).
  - Every read-then-write SQLite transaction uses `BEGIN IMMEDIATE`.
  - Category moves walk a bounded chain and refuse cycles and loops.
  - Bitwarden's error for several items claiming one server names each item, and sync results list pending server and key changes by name.
  - A failed save that the file watcher missed is retried quietly, with backoff.
- **How it ran.** In two phases, so it could start before RU6a was committed: first the files RU6a never touched, then `commands/mod.rs`, `lib.rs` and parts of `commands/sftp.rs` once RU6a's commit released them.
- **Reviews.**
  - Fable security review: Approved, with two minors (a tool-list change announced with the initialize answer was dropped on the call path; a session was removed inside the save transaction) and a note (`vault_unlock` did not take the password-change guard).
  - Opus code review: Needs fixes, two Important. A session for the old URL stayed registered after a refused call and could be reused against the new endpoint. `vault_lock` unsealed every MCP secret on the main thread (Argon2id, about 0.75 s each in a release build), freezing the window and pushing the exit past its 2 s budget.
  - Fix round 1 (11 items). The re-reviews ran on Opus, because Fable was no longer available: security Approved, with one new Low and two informational notes, which went to RW; code Approved, with 23 mutations caught.
- **Tests.** Library tests 680 to 724 in round 0 (44 new, 35 of them seen failing first), then 740 after the fix round (16 new, 13 seen failing first). Integration 48 and MCP 20 unchanged.
- **Verification.** On a WSL copy of d5e9d22 plus the reviewed diff, the controller ran fmt, clippy, the full test run (740 + 48 + 20 = 808 passing) and the `windows-gnu` check.
- **A count that differs.** The commit message says the unit moved "the local SFTP mkdir/rename and 11 more commands" off the main thread. The unit's own list of converted commands has 14 in all, that is 8 beyond the six the message names, and the index says the same; this report uses 14.

#### JU6b, d94ed2d (2026-10-13)

The SFTP layout and pointer-based drag and drop (plan Task 11's layout half, and Task 16), plus renderer leftovers.

- **What it changed.** The file list fits at 880x560, 1100x720 and 1600x1000; in-page drag and drop uses pointer events, so it no longer depends on the HTML5 drag events WebView2 withholds (not yet tried in a real WebView2); edit conflicts get a question one file at a time; hostile file names are spelled out; repeated Files and Split clicks open one SFTP session; the file browser's settings revert when refused; caches refresh the folders that changed; categories next to restored loops keep their order; the Bitwarden approval lists each pending change by name; a test covers the server list's host-category filter. Section 4.3 has the user-visible detail.
- **Reviews.**
  - Opus code review: Changes requested.
    - High: the edit-conflict question was one global slot, so a conflict on another file re-targeted the open question, and a click meant for one file overwrote another.
    - Medium: the category order next to promoted loop roots was still wrong; a correct order needs a sort-order-only backend write, which went to RW and JW.
    - Medium: categories could not be reordered without dragging (WCAG 2.2 success criterion 2.5.7).
    - Eight Lows.
  - Opus security review: no Critical or High and no XSS.
    - The same global slot, rated Medium.
    - Medium: the Bitwarden pending list's text isolation could be escaped, and runs of spaces could fake extra lines.
    - Three Lows.
    - Two backend issues outside the unit, passed to RW: a Bitwarden approval was not bound to the list shown, and an incoming key's fingerprint was the item's own claim.
  - Fix round 1 (13 items). The re-reviews found new problems: a vault lock left a hidden conflict question, so every later conflict queued invisibly (High for the code reviewer, Medium for the security reviewer); Cancel was not disarmed, so a double-click dismissed the next file's question (Medium); the transfer panel could not grow at small window heights (Low).
  - Fix round 2 (5 items). Final re-reviews: code Approved, with 17 of 17 reviewer mutants killed; security confirmed the lock fix on all four lock paths and found one new Low (a name made of U+2800 Braille blanks passed as ".."), which was fixed in JW rather than in a third round.
- **Tests.** `test:sftp` 232 to 598, `test:keys` 278 to 324, `test:servers` 480 to 511 and `test:safety` 471 to 481; checks that described behaviour changed on purpose were adjusted. RED: the unit's SFTP scenarios ran 41 ok / 91 FAIL on the unchanged d5e9d22 renderer. The implementer killed 71 mutants (21, 28 and 22 over the three rounds). Screenshots before and after were taken at the three window sizes and checked.
- **Verification.** On a clean copy of HEAD plus the reviewed diff: `node --check` on 20 files, the four static checks, and all seven suites. The first `test:safety` run lost one scenario to a 20 s page-load timeout while the CPU was at 100%; the re-run passed with 481 checks.

#### RW, 03dfa92 (2026-10-14)

The Rust final fix wave. It carried the findings of the first whole-branch reviews (pass 1, over 1ca864f..d5e9d22), the backend items from JU6b's security review, and RU6b's leftovers.

- **What it changed.**
  - Saved credentials: a saved SSH password stays with its server and account; MCP secrets and environment variables, and the stored assistant API key, reach a new destination only after a native question (section 5.3).
  - Bitwarden: approvals bound to the list shown by a token; fingerprints and public keys derived from the private key; cleaned text in pending entries, with the settings an overwrite would change; category changes that never upload older data (A7-23).
  - SFTP: SSHSpan's own program and data folders refused for writes and deletes (A6-02); "Stop editing" keeps changes the server lacks; a file of unknown size hashed to its end.
  - MCP: every set-up, listing page, renewal, refresh and call checked against the stored record right before it is sent; a lock leaves no half-registered session; replaced sessions ended where they were set up; at most four unseals at once at a lock.
  - Vault and categories: success with a warning when only the audit row fails; Connect, Test and the assistant read sealed secrets under the password-change guard and unseal on the blocking pool; the new `category_set_order`; `category_rename` changes only the name.
  - Clean-up: ten unregistered command bodies deleted with their helpers (A6-03, A8-16); 374 comment lines that cited internal work labels rewritten to give the audit ID or a plain reason.
  - Database calls: the fix for a lost wake-up in `db::block()` (section 6.1).
- **Reviews and rounds.** Round 0 is the review of the first delivery; rounds 1 to 6 are fix rounds.
  - Round 0. Opus code review: Block. High: the native credential dialog defaulted to "Allow", so Enter confirmed. Medium: the assistant's question quoted the raw URL the renderer sent (injected lines; a NUL aborted the dialog on Linux GTK). Medium: the Bitwarden sync ran Argon2id on an async worker. Several Lows. It also noted that RW alone breaks three renderer flows (Bitwarden Apply, editing a server's host, the assistant's key reuse) until JW lands. Opus security review: not ready, with the same default (Medium) and four Lows: the raw URL; a dialog-picked save path skipped the program-folder rule while the renderer could preset a full path as the dialog's default name (a DLL-planting route); queued teardowns kept password copies; an approval applied entries nobody was shown.
  - Round 1 (13 items). Security re-review: all five addressed, with the dialog defaults and the Esc mapping checked in the rfd 0.16.0 and tauri-plugin-dialog 2.7.3 sources for Windows, macOS and GTK. Code re-review: approve after one fix. Medium: comparing pending Bitwarden changes read the whole category table once per lookup (300 overwrites with 150 categories took 357 s, holding the password-change lock). Three Lows.
  - Round 2 (4 items): categories read once per pass (1.17 s); a refused call's refresh no longer reaches the old endpoint; a source scan forbids direct Argon2 calls in the sync and MCP code; the one-second clock starts on the main thread. Code re-review: approve after one line (the refresh after a refusal could still reach a switched-off server), and the Linux timing of the clock accepted as a documented residual.
  - Round 3: that line, the Linux comment, and tests made robust under load (waits that include an Argon2 derivation raised to 120 s; duration comparisons replaced by ordering checks) after the controller's own loaded run failed 3 tests.
  - Round 4: the refresh after a sent call gets the same rule; every path that sets up a session goes through one check of the stored record (`not_contactable`); "Stop editing" keeps changes the server lacks; quoted Host lines capped at 300 characters. One scoped code re-review of rounds 3 and 4: Approve, with two Lows (the request retried after a 404 renewal skipped the check; the per-page check had no test of its own). The security re-check of round 4 found one Low, the same retried page.
  - Round 5: a set-up checks again once its initialize is answered; the retried page is checked; the per-page check has its own test; when the gate refuses, a failed call set-up still ends as the gate's audited refusal. Security re-check: Approve. Code re-check: Approve, with a Low (no test that an ordinary set-up failure stays a failure), a documentation claim that was too broad, and a test that hung under load in the controller's run and the reviewer's own.
  - Round 6: the root cause of the hang and its fix (section 6.1); every join and direct await in the MCP tests bounded at 60 s; a timeout on the test client; a test that an HTTP 500 at set-up stays a failure; the claim narrowed. Code re-check: Approve, with the mechanism confirmed in the tokio 1.53.1 sources and reproduced. It found one latent Low (on a current-thread runtime the new path would starve that runtime) and a test nit; both were fixed in FW.
  - Six rounds is one more than the workflow allowed (section 7.1).
- **Tests.** Library tests 740 to 837 (+97 over the seven review cycles); integration 48 and MCP 20; 905 in all. Every round recorded its RED runs; rounds 1, 3, 5 and 6 added mutation checks, and round 2 checked its new test against the mutation the reviewer had found surviving; the loop that reproduced the hang went from 6 hangs in 18 runs to none in 84.
- **Verification.** The controller's last full `cargo test`, on the worktree with `src-tauri` equal to HEAD plus the reviewed diff: fmt clean; 837 of 837 library, 48 of 48 integration and 20 of 20 MCP tests, exit 0, no hang. Clippy and the `windows-gnu` check come from the implementer's final acceptance and the code reviewer's runs.

#### JW, 3b0fcfb (2026-10-14)

The renderer final fix wave: the renderer findings of the first whole-branch reviews, the renderer side of RW's contract, and leftovers.

- **What it changed.** The deploy sheet shows the preview's warnings and the user's own Host lines; a changed server needs its password again; MCP rows show when a credential is not confirmed; the assistant drops its own key-reuse prompt; Bitwarden Apply sends the approval token, and the status line shows the last result; "Stop editing" asks before losing changes; lock gating covers the remaining vault-dependent controls; the SFTP menus use the shared menu helper; one `errText` and one path join replace about 90 hand-made copies; categories are ordered through `category_set_order`; a new `scripts/check-renderer-hygiene.js` guards comments and removed code. Section 4 has the user-visible detail.
- **How it ran.** Phase 1 on files no running unit touched; phase 2 after JU6b's commit. After its first all-green run the implementer found and fixed two more defects (section 6.2); the controller then had both reviewers review the final state.
- **Reviews.**
  - Opus code review: approve with warnings.
    - Medium: a category dropped next to its own loop's promoted root landed last.
    - Lows: emoji and symbol names were flagged as unusual; three hand-made error-to-text copies remained, and the hygiene check missed their shapes; no test dragged a promoted loop root; gaps in the label rule; nits.
    - A note that "Stop editing" could delete a save the renderer could not see. A backend guard was added in RW's round 4, and the renderer half in JW's fix round.
  - Opus security review: Approve.
    - Low: the deploy sheet's notes were neither isolated nor bounded (a U+202E could reverse a verdict; a 50,000-character line was shown twice).
    - Four Info items: `check-ipc-args.js` was blind to 13 call shapes; a missing `confirmed` read as confirmed; blank Bitwarden names; `errText` could print "[object Object]" or throw.
  - Fix round 1 (10 items). Security re-review: Approve, with two new Lows: a double-click on a menu item answered the "Stop editing" question that opened under the pointer, sending a forced close (reproduced); a late backend answer could open that question after a lock. Code re-review: approve with warnings (a regression for U+1D159, test gaps, nits).
  - Fix round 2 (11 items). Both re-checks: Approve. Three nits and one note went to FW.
- **Tests.** `test:assistant` 312 to 367, `test:safety` 481 to 491, `test:sftp` 598 to 679, `test:polish` 190 to 195, `test:keys` 324 to 422, `test:servers` 511 to 580; `test:ui` 76. 135 mutants killed (76, 33 and 26 over the three rounds); three survived their first run and got stronger tests.
- **Verification.** On a clean copy of d94ed2d plus the reviewed JW diff and the RW diff of that moment (RW's last round changed only Rust): `node --check` on 21 files; the globals, IPC (146 call sites, every one read), vendor, MCP-contract and hygiene checks; and all seven suites with no re-runs (`test:ui` 76, `test:safety` 491, `test:sftp` 679, `test:polish` 195, `test:assistant` 367, `test:keys` 422, `test:servers` 580). After the commits, the static checks ran again on a clean copy of 3b0fcfb.

#### FW, 6c19b1b (2026-10-17)

The last fix wave. It carried the findings of the second whole-branch reviews (pass 2; section 5.4), the last nits of RW and JW, and three items from the documentation accuracy review. Its own re-checks then sent it back four times, so it ran in five rounds. Its rounds count deliveries: round 1 is the first, rounds 2 to 5 are its four fix rounds.

- **Round 1, Rust** (12 files under `src-tauri/`, +2,227 / -186 as first delivered):
  1. The Bitwarden destination is bound to a native question (the pass-2 security review's High, older than the branch; section 5.3).
  2. An assistant key-move "Allow" given after a lock moves nothing (pass-2 security, Low).
  3. Save dialogs open in the Downloads folder, or home when there is none, and a dialog-picked download may not replace a startup folder or a shell startup file (pass-2 security, Low).
  4. A category whose saved parent is in the other scope counts as top level when ordering (pass-2 code, Low).
  5. An edit that is being closed is not handed out again (pass-2 code, Low).
  6. Bitwarden error texts quote item titles and ids cleaned; a doc comment fixed (pass-2 nits).
  7. `db::block()` takes its own-parker path only on a multi-thread runtime (RW's last re-check, latent Low).
  8. Two test assertions that could not fail removed, with a doc paragraph (RW's last re-check, nit).
  9. Argon2id `kdfMemory` is converted from MiB to KiB (a real bug, older than the branch; section 6.1).
  10. A passphrase-protected key file gets advice instead of "The key is encrypted" (A5-26, server half).
  11. Comments on the credential dialog's default button corrected: GTK sets none.
- **Round 1, renderer** (7 files, +526 / -35 as first delivered):
  1. The Bitwarden error list is spelled out and each entry isolated.
  2. Edit while "Stop editing" is still checking is refused with "<name> is being closed - try again when it has stopped.", and nothing is sent.
  3. JW's nits: `check-ipc-args.js` treats parameter lists, arrow parameters and `catch` bindings as patterns; two overlapping slow checks restore the right status text; ".." plus a combining mark is spelled out; a lock silences the one-second "Checking..." line.
  4. The Bitwarden destination in Settings: "Not confirmed - SSHSpan will not sync with <host> until you allow it." with an "Allow syncing..." button (lock-gated, busy until answered); a save that comes back unconfirmed shows its reason.
  5. A5-42, server half: a new server starts in the host category the list is filtered by, and a saved server that the filter hides is announced: "Server saved - it is hidden by the current filter. Clear the filter to see it."
- **Round 2, Rust** (the same 12 files; +3,622 / -281 for rounds 1 and 2 together), answering round 1's re-checks:
  1. The Bitwarden account must be one email address: one token of at most 254 characters, one "@" between a non-empty name and domain, and no space, control, invisible or direction character, quote, bracket or other separator. It is checked again inside the transaction that stores the settings. Free text could add words to the native question.
  2. The Bitwarden question names the account first, on its own line, then the server and the address, and says when the account is not the one allowed before. The sync refusal names the account too.
  3. After "Don't allow" or "Cancel" (Esc and closing the dialog included), the same question is not asked again for 30 seconds. The back-off is part of the shared question machinery, so the MCP credential question and the assistant's key-move question have it as well. An "Allow" given too quickly starts no wait.
  4. A path picked in a save dialog gets the same write deny-list as a typed path, for downloads and for the public-key and audit-log text exports. This reverses the earlier rule, kept since the one-use dialog grant of dc09f93, that a picked path skips most of the list. `~/.config/user-dirs.dirs` and `user-dirs.locale` join the list for every write: a typed download over `user-dirs.dirs` could move the Downloads folder, and with it the folder the next save dialog opens in.
  5. The Bitwarden master key is derived on the blocking pool, at most two at a time across the app (Test connection and sync share them). A third waits up to 30 seconds, then gets "Another Bitwarden sign-in is still running. Try again when it has finished."
  6. The key-file check at save runs after the password-change guard is let go, and never touches a UNC or device path (`\\server\share`, `//...`).
  7. Prelogin numbers too large for 32 bits end at the ceiling instead of wrapping, and a KDF type out of range is refused.
  8. A test comment that named a review says in plain words what it tests.
- **Round 2, renderer** (8 files; +992 / -50 for rounds 1 and 2 together):
  1. `server_save`'s warning is shown, in the backend's words and spelled out: after a save in the server dialog, which the ssh config import also saves through, and for each server that a deploy's "Also save these as servers" saves. With this, the save-time half of A5-26 is visible too.
  2. Every backend error and warning in the Bitwarden and SFTP-edit paths is spelled out, so a file name, account, host or item title it quotes cannot turn the sentence around.
  3. After a successful "Allow syncing...", the focus moves on to Sync now, or to Save or Test connection when Sync now cannot take it; after a "no" it stays on the button.
- **Round 3, Rust** (13 files: `commands/terminal.rs` joins them), answering round 2's re-checks:
  1. The 30-second back-off was keyed on the host and port a question names, and for Bitwarden also the account, instead of the full address, so another path on the same host could not ask again at once. The two re-checks had differed between the exact destination and the host. Round 4 replaced this step.
  2. On Windows, key files are read only from this computer's drives: a drive letter followed by a colon and a separator, mapped drives included, or the same in the `\\?\C:\` form. Shares (`\\server\share`, `//server/share`, `\\?\UNC\...`), the `\??\` object namespace, devices and relative forms are never touched: saving such a server saves it and warns, and Connect and Test connection refuse, with "SSHSpan reads key files only from this computer's drives (like C:\...). Copy the key to a local folder, or import it under Keys." Round 2's check had let the `\??\UNC\` spelling reach the network, and the connect path, older than the branch, read any saved key-file path, so Test connection could reach a share.
  3. The private-key export and the vault backup export get the write deny-list too, with `~/.ssh` still allowed for both: exporting a private key into `~/.ssh` is an ordinary thing to do.
  4. A stale doc comment says what the code does.
- **Round 3, renderer:** two test stubs that still used retired backend texts carry the current ones. No renderer code changed.
- **Round 4, Rust**, answering round 3's security re-check:
  1. The export dialogs suggest a bare file name. The private-key export used to suggest the key's own name, so a key named like a path (`/root/.ssh/config`, `../../.ssh/config`) opened the dialog in `~/.ssh` with `config` filled in, and the `~/.ssh` exception let one Save and "Replace" overwrite the user's ssh config. Now the suggestion is cut after the last "/", "\" or ":" and cleaned like every suggested name; the backup's name goes through the same function.
  2. The back-off is per kind of question. After any "no", no further question of that kind - an MCP credential, an assistant key move, a Bitwarden destination - is asked for 30 seconds, whatever host, path or account it names, because keying on the host could not stop a page from raising one fresh question per made-up host. A "no" holds back only questions of its own kind. One text changed: the MCP save's warning now says "sending a credential to <host>", naming the host that was declined.
  3. Lines of the implementer's own report that had gone stale were corrected; no code.
- **Round 5, Rust**, answering round 4's security re-check: file-dialog titles that come from the page are cleaned like the texts of message dialogs. A NUL in a title would have made the Linux GTK dialog code panic inside a callback, which aborts the app; this is older than the branch.
- **Tests.**
  - Rust, round 1: 19 new library tests (837 to 856), 16 of them seen failing first. The other three: the pure-helper test behind the key-file advice, which passes before the fix by design (the tests of its two call sites were the RED); a test that a saved Bitwarden destination is never taken for one from before, added after the first RED run; and the named-pipe test below. Three hardening cases added after GREEN (a 4 TiB `kdfMemory`, a named pipe as the key file, a DES-EDE3 legacy PEM) and the destination test were each turned red by the mutation that removes the guard they pin. 52 of 52 mutations caught.
  - Rust, round 2: 15 more (to 871). Its RED batches failed 1 test, then 17, among them earlier tests whose expected texts or outcomes changed; the two tests written after GREEN were turned red by the mutation of their guard. 91 of 91 mutations caught, all of them run on the round-2 code, round 1's included.
  - Rust, round 3: 7 more (to 878), all 7 seen failing first; 115 of 115 mutations caught, all of them run on the round-3 code.
  - Rust, round 4: 880 library tests, after the host-keyed tests of round 3 gave way to per-kind ones; 9 seen failing first. The 32 mutations for its new and changed code and tests were all caught, and the other 94 stand from round 3's full run: 126 distinct Rust mutations in all.
  - Rust, round 5: 2 more (to 882), both seen failing first; its 10 mutations were all caught, 136 distinct Rust mutations in all. Final count: 950 (882 library, 48 integration, 20 MCP integration).
  - Renderer, round 1: `test:servers` 580 to 635, `test:sftp` 679 to 693; 32 mutations killed. Round 2: `test:servers` to 676, `test:sftp` to 700, `test:keys` 422 to 431; 32 more, 64 distinct mutations in all, every one killed. Round 3 changed only two stubs, and both suites they feed kept their counts. `check-ipc-args.js` reads 147 call sites against 110 registered commands (`bitwarden_allow_sync` is new).
- **Left as they are.**
  - `server_save`'s rejection texts, which carry names the user typed, are shown as plain text, not spelled out. The security re-check accepted this: it is the user's own input, and no server supplies it.
  - Settings saved before round 2 with an account the new rule refuses keep working; the question and the refusal quote such an account cleaned and capped.
  - Going back to the Bitwarden destination that is still the allowed one asks nothing, by design; only the last destination allowed is kept, so returning to an earlier one after allowing another asks again.
  - An Edit that took the edit in the instant before "Stop editing" set its mark is not caught.
  - A user who answers "no" by mistake waits 30 seconds before any question of that kind, for another server or account too; the answer names the host declined and says to wait.
  - On Windows, SFTP local paths and "open external" targets that a compromised page gives as a network share can still make Windows sign in to that share; section 7.3 says why this stays.
- **Reviews.** The two pass-2 reviewers (Opus) re-checked rounds 1 to 3, the security reviewer round 4, and the controller round 5.
  - Round 1. Code: Approve, with every pass-2 finding closed and two Lows and two nits, all answered in round 2; one Low was the security re-check's dialog-pick finding, found independently. Security: Approve with warnings. The High is closed end to end and all eight bypass attempts held (section 5.3), but the save-dialog fix was only partial; three Lows, one informational point and a nit, all answered in round 2.
  - Round 2. Code: Approve, with every finding closed, two Lows (the back-off's key; the Windows UNC spelling, with the connect path) and two nits. Security: Approve with warnings; every round-1 finding closed (the UNC point on Linux only), and two Lows, the Windows UNC spelling it shared with the code re-check and the key and backup export paths. All went into round 3.
  - Round 3. Code: Approve, with every item closed and two nits: the back-off saw a host with a trailing dot as a second host, which round 4 made moot, and a stale line in the implementer's report. Security: Approve with warnings. The Windows key-path rule held against every network spelling tried in a cross-compiled probe, and the `~/.ssh` exception reached nothing else. Two Lows: the export dialog steered by a key's name, shown with a GTK probe, and the design limit of host keying; and one informational point, the Windows share residual, which was accepted (section 7.3).
  - Round 4. Security: Approve. The export dialogs suggest only bare names in every format tried, and the per-kind back-off holds back one question per kind for exactly 30 seconds after the user's own "no", each kind on its own. One nit, older than the branch: the uncleaned file-dialog titles, fixed in round 5.
  - Round 5: the controller checked its small change.

#### Docs: the documentation commit that adds this report

- **What it changes.** README, CHANGELOG (the `[Unreleased]` section; in released sections, typo and format fixes in place and factual corrections annotated "(Correction 2026-10-09: ...)"), CONTRIBUTING, `docs/ARCHITECTURE.md` (its IPC table checked by a script against `generate_handler!`), `docs/SECURITY.md` (rewritten against the code, with the accepted-risk list), `docs/PRIVACY.md`, `docs/MCP-SMOKE-TEST.md`, `docs/REWRITE-ROADMAP.md`, the [audit index](README.md) and this report; also `ci.yml`, `release.yml`, `package.json` (`check:hygiene`) and `scripts/check-renderer-ui.js`. It also edits code comments, and nothing else, in `src/renderer/app.js`, six Rust files and two test scripts: references to review rounds and internal labels become audit IDs or plain words, the `lib.rs` note on the credential questions is completed, and two notes no longer state Bitwarden's default memory setting as a fact.
- **How it was written.** On Sonnet, beside the code units, with marked placeholders for work not yet committed; then end passes after JU6b, after RW and JW, after the accuracy review, and for the fix wave, whose later rounds were written in marked passages and checked against each round's code. A last pass after the fix-wave commit fills in its commit, the counts and the coverage figures.
- **Review.** An Opus documentation accuracy review checked the uncommitted documents against the code at 3b0fcfb and recorded about 140 corrections, all of them applied (section 6.3).

#### The pull request follow-up (2026-10-17)

Three checks failed in the first CI run of [pull request #85](https://github.com/AGSQ11/SSHSpan/pull/85): the dependency advisories, the renderer suites, and the new Windows job, which does not fail the workflow. An automated review bot left nine comments on the documents and workflows, all Low. One more commit answers them. The controller made the lockfile change; subagents wrote the other fixes and the document changes, and the controller checked their diffs, reports and evidence, then verified the whole tree.

- **Dependency advisories.** `cargo audit` failed on seven advisories against two locked dependencies: RUSTSEC-2026-0338, -0340 and -0343 in quinn-proto 0.11.17, and RUSTSEC-2026-0346 to -0349 in rustls 0.23.45. `Cargo.lock` moves to the patched releases, quinn-proto 0.11.18 and rustls 0.23.46. The only other lockfile change is tempfile's `getrandom` entry, which names 0.3.4 instead of 0.4.3; both were already locked and both are in tempfile's range.
- **The transfer list at 880x560 (A1-02).** The renderer job failed "A1-02 880x560: the first job's buttons are not covered".
  - Cause: text width, not line height. At 880x560 the transfer panel is clamped to 92 px. With Linux fonts its head no longer fits on one line, so its actions wrap, and the note about paused transfers of a server that is not connected took the rest, leaving the job list 0 px. With Windows fonts the list was 24.7 px, already less than one 28 px job row. In Split the head wraps on every platform, and the list was about 4 px, with the buttons under the note. No check covered either case.
  - The fix: the note is the head's last item. Where the file surface is under 420 px tall it is thinner and shares the head's last line; elsewhere it keeps a line of its own, and the panel looks as before (pixel-identical at 1600x1000). The job list never drops below one row, whatever the fonts: when text needs more room, the panel grows and the file list above it scrolls. The resize handle offers only heights that take effect with that floor; without that, an arrow key in Split could store a height that changed nothing, and that height later made the panel shorter in a larger window.
  - Tests: the list keeps a whole row and the note stays on screen on one line, at all three sizes in Files, Dual and Split; the note keeps a line of its own where there is room; a test-only larger-text variant (letter spacing and taller lines) reproduces the CI failure with any machine's fonts; and a scenario for the handle. Before the fix 8 checks failed on Windows and 10 on Linux, the CI check among them, with its failure note reproduced byte for byte. After it, `test:sftp` passes 763 checks on both, and removing any one part of the fix fails at least one check.
  - The seven suites also passed on Linux (WSL, with the Chromium and fonts CI uses). The last four had never run on Linux for this branch, because CI stopped at `test:sftp`. An independent code review approved the change, with three small points, all taken.
- **Windows.** The five failures and their fix are in section 8.4: test portability and a too-strict ACL test, no product bug. The comments and documents that said a key file on Windows is restricted to the current user, or has exactly one entry, now say what happens.
- **Release signing.** Before, a release with an empty `MINISIGN_SECRET_KEY` was published unsigned with a warning, and existing installations would refuse it as an update. In this repository the signing step now fails with an error before any asset is attached; forks keep the warning and an unsigned build.
- **The MCP smoke mock** (`scripts/mcp-smoke-server.py`) answers `/mcp-listchanged` like `/mcp`: it sends the `list_changed` notification and then the matching response. Its `image_cat` tool returns a real image block. Steps 19 and 26 of `docs/MCP-SMOKE-TEST.md` can be run again. A check script passed 51 of 51 checks against the new mock; against the old one, 23 of 50 failed.
- **The review comments.** Eight led to edits:
  - two sentences in PRIVACY: which key paths are opened, and what happens before a Bitwarden destination is allowed;
  - the gate re-check in MCP-SMOKE-TEST;
  - the mock and the release signing (above);
  - a note in both workflows on why doctests need no manifest;
  - a correction note in REWRITE-ROADMAP on import formats;
  - the lines the mock prints, in MCP-SMOKE-TEST step 5.

  One needed no change: CONTRIBUTING's Node version. Playwright 1.56.1 declares `engines.node >=18`, CI runs the suites on Node 20, and no document says Node 20 is required. Each thread is answered on the pull request.
- **Documents.** Besides the above:
  - the Windows job's first run and the native Windows runs (README, CONTRIBUTING, CHANGELOG, SECURITY, `ci.yml`'s comment, the index);
  - the Windows ACL wording (CHANGELOG, ARCHITECTURE, README, PRIVACY, REWRITE-ROADMAP, SECURITY, the index);
  - correction notes on two older CHANGELOG entries: the Electron backend's key files, and SFTP edit staging, whose copies take the per-user temp folder's permissions on Windows;
  - this report.
- **Tests.** Rust 952 (884 library, 48 integration, 20 MCP integration). Renderer: the seven suites pass with 2,998 checks (`test:sftp` 763; the other six unchanged). The five static checks pass.
- **Reviews of the whole follow-up** (Fable, read-only):
  - Code: Approve. One Low, two documents that still gave the renderer's old counts (fixed), and two nits: the Node wording above (fixed) and the signing gate's repository name (below).
  - Security: Approve with warnings, three Lows.
    - The signing gate was keyed on the repository's name, so a rename or a transfer would have brought back the warning-only path; it is now keyed on the repository's ID, which survives both.
    - The CHANGELOG headline "a release is never published unsigned" claimed more than the workflow guarantees. It now says what is true. Two gaps remain, listed in SECURITY.md and section 9: the installers and their signatures are attached in separate steps, and the workflow does not check a new signature against the public key the app embeds. Either gap ends in a release the updater refuses, not in an unsigned install.
    - The ACL test accepted SYSTEM and Administrators in every folder. In a folder that passes permissions down, the product leaves only the user's entry, so an explicit extra grant would have passed there. The test now sets up both kinds of folder itself and requires the user's entry alone in the first (section 8.4); natively on Windows, an explicit Administrators grant fails it there.
  - Informational points, taken: "no other account has access" is what Windows' default settings give, not something the call enforces, and the documents now say so.

## 4. What changed for users, by area

Each item names the commits that carry it. 6c19b1b is the fix wave.

### 4.1 Keys, categories and deploy

- ECDSA keys can be generated from the New key dialog: the curve options send `p256`, `p384` and `p521`, and the backend also accepts the `nistp` names (46a9d1b, 652aa5e).
- Exporting "PKCS#8 encrypted" without a passphrase is refused before the save dialog opens. OpenSSH and PuTTY exports take an optional passphrase and say the file is unprotected unless one is set (46a9d1b, 652aa5e).
- Public key and authorized_keys exports go through the native save dialog first, so a cancel exports and audits nothing (652aa5e). Every save dialog opens in the Downloads folder, or in home when there is none, and suggests only a bare file name, so a key named like a path can no longer steer the private-key export onto that file. The path picked gets the same write deny-list as any other write, with `~/.ssh` still allowed for the private-key and backup exports (6c19b1b; section 5.3).
- Passphrase-protected PuTTY exports now open in PuTTY and in SSHSpan; before, they failed their own MAC check. RFC 4716 public exports keep the whole comment and wrap the body at 70 characters (46a9d1b).
- The Import dialog names the two supported formats, OpenSSH private key and PuTTY .ppk. Other formats (PKCS#1, SEC1, PKCS#8, encrypted PKCS#8, SPKI, RFC 4716 public, authorized_keys lines) are recognised locally, and the dialog explains how to convert them; a private PEM in an unsupported format is not sent over IPC just to be refused (46a9d1b, 652aa5e). Importers for those formats were deferred (R9).
- PuTTY files are checked for damage: an unencrypted .ppk now has its MAC verified, and a missing or blank Private-MAC is refused (46a9d1b, 463345c).
- Key names must be unique, ignoring case, on create, import and rename. RSA sizes outside 2048 to 8192 are refused, a hint says 4096 and 8192 can take a minute, and key generation runs off the UI thread (46a9d1b, 652aa5e). Import runs off the main thread too, and two imports of the same key at once store it once (cd11f97).
- Comments on generated and imported keys cannot inject lines into exported files or into the public key shown (46a9d1b).
- Create, Import, Export, Remove deployed copy and Deploy show a busy state, ignore a second click and keep keyboard focus. The New key dialog returns focus to its opener and resets its category chips (652aa5e).
- The key list has a "No keys match" row with Clear filter; a filtered-out key closes its detail pane and clears the export passphrase; there is a select-all for the keys shown; nothing is auto-selected after a delete; a new key hidden by the filter is announced (652aa5e). With the vault locked, the empty Keys view says "The vault is locked" with an Unlock button, and with no vault "No vault yet" with Create vault (3b0fcfb).
- When a key or category change is made but its audit row cannot be written (key delete, rename and create, category create and delete, a key's categories), the change is reported as done, with a warning toast. A retry used to fail with "already exists" (03dfa92, 3b0fcfb).
- Categories: counts are recursive and de-duplicated; paths and counts survive category loops; restored parent loops are shown and can be repaired; a move into a loop is refused; drop zones are read before the classes reset; deleting a host category moves its servers to the parent, and the list refreshes; deleting a key removes its category links (46a9d1b, 652aa5e). The backend now walks a bounded chain, refuses cycles and loops, and moves categories off the main thread, so a restored loop can no longer hang the app (cd11f97).
- Category order: a drag, Move up or Move down writes one `category_set_order` for the whole list as shown, loop roots included, preceded by `category_reparent` only when the parent changes (Move to... sends only `category_reparent`). A drop beside a promoted loop root lands where it was dropped, no row other than the moved one changes place, and a repeated drop is stable (03dfa92, 3b0fcfb). A rename changes only the name, so it cannot undo a move made meanwhile (03dfa92). A category whose saved parent is in the other scope (a host category under a key category, say), which a restore can produce, is shown and can be reordered at the top level of its own tree (6c19b1b).
- Categories can be reordered without dragging: Move up and Move down in the row menu, and Alt+Up and Alt+Down on a focused row (d94ed2d); Move to..., which already existed, changes the parent.
- The deploy sheet shows the backend's own plan: the exact config text, the files per key, every warning and every refusal. Host alias, HostName, User and port are honoured and validated before anything is written; a key is never written over another key's file or alias; the sheet shows the managed config path and an `Include` line with a Copy button ("put it at the top of ~/.ssh/config"); servers are saved before the sheet closes, and save errors are shown (46a9d1b, 652aa5e).
- Under the plan, the deploy sheet lists the preview's warnings ("Check before you deploy:") and every Host line of the user's own ssh config that names the target hosts, as "file:line - text", marking lines ssh cannot read and lines an older SSHSpan wrote. The Deploy question repeats up to six warnings. Quoted text is spelled out, isolated, and cut at 300 or 800 characters (03dfa92, 3b0fcfb).
- Deploy writes values OpenSSH can parse: quoted and escaped paths, aliases limited to letters, digits, dot, underscore and hyphen, and pattern aliases (`*`, `?`, `!`) refused. It also refuses a leading `=` in HostName or User and `%` or `${` in User, warns about a `%` in the config path and about the user's own overlapping `Host` lines, never edits `~/.ssh/config`, and serialises writes to the managed config (46a9d1b, 463345c).
- "Remove deployed copy" exists in the key pane, and deleting a key offers to remove its deployed files; only `sshspan_*` files directly in `~/.ssh` are ever deleted (46a9d1b, 652aa5e).

### 4.2 Servers and terminal

- Editing a server no longer erases its saved password. The dialog says "A password is saved - leave blank to keep it" and offers "Remove saved password"; switching to key login removes the password (5e77b54, d5e9d22).
- A saved password stays with its server and account. Changing the host, port, user name or sign-in method while a password is saved says at once "A changed server needs its password again", and Save asks at the password field until the password is typed or the saved one removed; key sign-in never asks. The backend refuses such a save with "Enter the password for the new server or account." and writes nothing, and Connect and Test spend the saved password only for the server's own user name (03dfa92, 3b0fcfb).
- Test connection asks for a password when none is saved, the row "..." menu offers it, and only one test runs at a time (d5e9d22).
- The port is checked as 1 to 65535 beside the field, and the backend refuses 0 (5e77b54, d5e9d22).
- "Use this key to connect" lists key-login servers only and says why others are missing. Every server row has a "..." actions button. A filter with no matches says so and offers Clear filter (d5e9d22).
- A new server created while the list is filtered by a host category starts in that category, and a saved server that the filter hides is announced: "Server saved - it is hidden by the current filter. Clear the filter to see it." (6c19b1b).
- A server that uses a passphrase-protected key file no longer fails with "The key is encrypted" alone. Connect and Test say: "This key file is protected by a passphrase, which SSHSpan cannot ask for when connecting. Import it under Keys (New key > Import asks for the passphrase) and choose that key for this server, or remove the passphrase from the file." Saving such a server shows the same advice as a warning: in the server dialog, which the ssh config import also saves through, and for each server that a deploy's "Also save these as servers" saves. The server is saved either way (6c19b1b).
- The check at save reads only a regular file, at most 64 KiB, and does not open a network path. On Windows, key files are read only from this computer's drives, mapped drives included: a key file on a network share or a device path is never opened, saving the server warns, and Connect and Test connection refuse with "SSHSpan reads key files only from this computer's drives (like C:\...). Copy the key to a local folder, or import it under Keys." (6c19b1b).
- The Config import reads the user's own `~/.ssh/config` (read-only, one `Include` level, patterns and `Match` blocks skipped), names the file it read, and is disabled while the vault is locked (5e77b54, d5e9d22).
- Closing or cancelling a tab mid-connect disconnects the session that arrives late. While a tab connects, its dot pulses, its status line says "Connecting to <host>:<port>..." and the terminal header shows Cancel; each tab keeps its own status line (d5e9d22).
- Reconnect and Restart act on the active tab and keep its key. Restart asks first on a live tab, ends the old session only after the password prompt, and keeps the scrollback with a "reconnecting" line (d5e9d22).
- A changed host key and a declined first-trust prompt have different messages. Connect times out after 20 seconds and authentication after 30, with time spent in the trust dialog excluded. Fingerprints use the `SHA256:` form that `ssh-keygen -lf` prints, and stored rows were migrated (5e77b54).
- Connect, Test and the assistant refuse at once, with "The vault is being re-encrypted - try again when it finishes.", while the master password is being changed (03dfa92).
- Terminal output split across packets no longer produces replacement characters (5e77b54).
- The key-compatibility settings (Home, End, arrows, keypad) and the Backspace setting are sent to the session; before, they wrote into the local display. Ctrl+Shift+1, 2, 3 and M work while the terminal has focus and never send NUL. There is one "[connection closed]" line, resizes are sent once per frame and only when the size changed, and the bell flashes the tab (d5e9d22).
- Every link in the terminal, OSC 8 or plain, asks first and shows the site on its own line. Links that hide their address behind a user name or password are refused, and only http and https open (d5e9d22).
- Pastes keep text, TAB, CR and LF and lose every other control character and the bracketed-paste markers, and multi-line paste is reviewed in the app (7e5c5c5, d5e9d22).
- The terminal's deferred focus no longer takes focus from a menu or a control the user just reached. Developer traces appear only when a developer-tools flag is set (d5e9d22).
- Header controls go icon-only when the window is narrow instead of being clipped, and the maximize button moved into the header (d5e9d22).

### 4.3 SFTP

- Uploading a folder creates the remote folders first; before, every file in a new folder failed with "No such file" (dc09f93).
- A short read is reported as an error ("incomplete transfer") instead of Done. "Download as..." writes `<name>.part` and renames it, so a failed download no longer destroys the file it replaced. Resume seeks instead of re-reading, downloads keep modification times when asked, and same-named targets in a batch get distinct names (dc09f93).
- Verifying a transfer against a server that does not report file sizes hashes to the end of the file. It used to compare against the digest of an empty file and delete a good copy as a checksum mismatch (03dfa92).
- Folder downloads skip symlinks and special files, stop at depth 64 and 10,000 entries, and report per-item notes. Recursive chmod skips symlinks, reports failures and never puts setuid, setgid or sticky on files; the chmod dialog shows and keeps those bits (dc09f93, 11abb3e, 5e77b54).
- Editing a remote file in an external editor: staged copies always carry an inert extension, so extension-less files such as `authorized_keys` and `Makefile` open. Saves are coalesced, uploaded to a temporary name and then renamed over the file, so a save that fails before the swap leaves the remote file untouched; if the swap itself fails, the message says where the saved content is (on a server that will not rename over a file the old file may already be gone), and success or failure is reported (dc09f93, 11abb3e).
- Each save compares the server's size and time with what was downloaded. A change is held back as a conflict instead of being overwritten, and a file deleted on the server is a conflict that Overwrite recreates (463345c). The app asks about it: "<name> changed on the server since you opened it" (or was deleted, or could not be checked), with Overwrite, Reload and Cancel, Cancel focused. It asks about one file at a time and queues the others; Overwrite and Reload take no click for 750 ms after the question appears or changes, and Cancel none for 750 ms after it moves on to another file; a vault lock drops every question, a closed tab or an ended session drops that session's questions, and a late event cannot bring one back (d94ed2d).
- "Stop editing" first checks that the server has what the local copy holds. A copy with changes the server lacks, an upload still running after 10 s, or a copy that cannot be read closes nothing and deletes nothing: the app asks, in the backend's words with Cancel focused, and only a yes closes the edit and deletes the copy (03dfa92, 3b0fcfb). Opening the file for editing while its stop is still checking is refused: "<name> is being closed - try again when it has stopped." (6c19b1b). A failed save that the file watcher missed is retried quietly after 60 s, then at doubling intervals of up to 15 minutes (cd11f97).
- Local paths built from remote names are confined to the chosen folder, writes to protected locations are refused, and deleting or moving a folder that holds `~/.ssh`, SSHSpan's own folders, a startup location or a shell startup file is refused (463345c; section 5).
- SSHSpan's own program and data are refused for SFTP writes and deletes: the install folder (for a copy run straight from a drive root, the home folder, Downloads, the Desktop or Documents, only the executable and, on Windows, the DLLs beside it), the AppImage, the macOS bundle, the data and cache folders and the webview profile. Reads still work (03dfa92). Save dialogs open in the Downloads folder, or in home when there is none. A path picked in one gets the same write deny-list as a typed path: `~/.ssh`, startup folders, shell startup files, settings that run commands (git, vim, emacs, Office, Windows Terminal), folders on the PATH, SSHSpan's own program and data, and the folder settings `user-dirs.dirs` and `user-dirs.locale`, which say where Downloads is. Such a file (a .bashrc, say) can still be saved on purpose: save it in another folder, then move it into place (6c19b1b).
- The layout fits at 880x560, 1100x720 and 1600x1000 (d94ed2d):
  - an empty transfer queue shows only its header and opens with the first job; the panel is capped and resizable within what the window allows;
  - the file list keeps a floor of whole rows, and secondary toolbar buttons fold into a "More" menu on a narrow panel;
  - the queue grid drops columns or wraps instead of scrolling sideways, and row actions stay reachable;
  - Split never overflows its column; the dual-pane split is one percentage; both splitters work from the keyboard and report their position to assistive technology;
  - names stay on one line, with the full name on hover; symlink and broken-link badges, the size spinner and the quick-find indicator are styled; the local table shows only the columns its rows fill;
  - while the note about paused transfers of a server that is not connected is showing, the transfer list keeps room for at least one job at every size, in Files, Dual and Split, whatever the fonts. At 880x560 the note had left it no room with Linux fonts, and in Split on any platform (the pull request follow-up, section 3.2).
- Drag and drop no longer depends on the HTML5 drag events the Windows webview withholds: in-page drags use pointer events, with a 5 px threshold, a ghost, highlighted targets and Escape to cancel, and a release never also clicks. Every drag has a menu alternative (Move to..., Download, Upload) and keeps its confirmation. Drops onto the local side ask first, because the old folder-drop path could replace a local file silently (d94ed2d).
- File names with control, direction or invisible characters, and names that only look like "..", show nothing or are "~", are spelled out ("<U+202E>") and flagged; dropping into a flagged folder asks first (d94ed2d, 3b0fcfb, 6c19b1b). Every backend error and warning about an edit is spelled out too (6c19b1b).
- Repeated Files and Split clicks open one SFTP session, and the control shows that it is opening (d94ed2d).
- Settings the file browser saves are put back when the backend refuses them, and caches drop the folders that changed (d94ed2d).
- A failed folder open keeps the previous folder; listings are sequenced; the selection is cleared on a folder change and pruned to visible rows; delete prompts name the items; the conflict dialog defaults to Skip with Cancel focused; "don't ask again" is separate for remote and local deletes; Up works on Windows drive roots and UNC paths; OS drops are ignored unless the Files view is on screen (11abb3e).
- The file, folder, local-pane and Bookmarks menus use the shared menu helper: focus moves in and returns, arrows, Home, End, Escape and Tab work, and a file row opens its menu with Shift+F10 or the Menu key (3b0fcfb).
- The queue patches rows in place, so Pause and Cancel clicks survive progress events; running and next jobs are never cut by the 100-row cap; cancelled jobs are listed with Retry; a finishing transfer no longer takes keyboard focus; jobs remember their saved server and resume after a reconnect (dc09f93, 11abb3e).
- Upload opens a native multi-file picker, queues the picks with one call and reports each file; there is a toolbar Upload button and an empty-area menu (863a024, 463345c, 11abb3e, d5e9d22).
- Searches carry an id, and a new search cancels the previous walk (dc09f93, 11abb3e). A capped search says why it stopped ("stopped at 500 matches", "after scanning 200,000 entries", "after 2 minutes"), and "Send to" says "Queued" when a file is only queued (3b0fcfb).
- Remote list, mkdir, remove, rename, stat, touch and free-space errors name the server's status once, instead of "mkdir failed: Failure: Failure" (03dfa92).
- Local new-folder and rename run off the main thread, and two renames to one name can no longer replace each other (cd11f97).

### 4.4 Assistant and MCP

- The model can no longer press Enter. `type_command` and Insert go through `assistant_type_text`, which enforces the tab's access level, refuses line breaks, control characters other than TAB and characters that can disguise text, and caps length at 4,096 characters. Before, an embedded newline ran a command at Draft level with no approval card and no audit row (d33028d, d589b51). `assistant_exec` refuses control characters, TAB and the same invisible characters (863a024). Both now refuse every Unicode format and default-ignorable character (cd11f97).
- MCP tool calls carry `approved=true` only after the user approved the card, and at Read and Draft the card is always shown (d33028d, d589b51).
- A changed tool definition disables the tool, clears its auto-approve and shows a notice. Each enable and each auto-approve names the definition hash the user was shown, so a stale settings row cannot approve a new definition (d33028d, d589b51).
- The call gate runs again right before every `tools/call`, after the session's set-up and after any refresh or renewal (cd11f97). Every set-up, listing page, renewal, refresh and call checks the stored server record right before it is sent, so a server switched off, edited or removed while a request was out gets nothing more (03dfa92; section 5.3).
- MCP server records are read, changed and written in one transaction, so a revoked approval cannot come back and a removed server is never re-created. Sessions are bound to the URL and credential they were set up with and are ended there. URLs with `?query` or `#fragment` are refused (cd11f97).
- An MCP save that would send a secret or an environment variable somewhere new is stored switched off and asked about in a native dialog that names the host and the variable (03dfa92; section 5.3). Its row then says "Not confirmed - SSHSpan will not send this credential until you allow it" and offers "Allow sending..." (3b0fcfb). Variable names must be 1 to 128 visible ASCII characters, without spaces or "=" (03dfa92). After "Don't allow" or "Cancel", no further MCP credential question is asked for 30 seconds, whatever server it names: the server is saved switched off, and the save names the host that was declined and says to wait (6c19b1b).
- Approval cards and event rows show every argument in full, with long values marked and expandable; invisible and text-direction characters are shown as `<U+XXXX>` (d589b51, d5e9d22). A new card takes the focus only when the focus is in the assistant panel or nowhere, never from a terminal being typed in, and the panel's X returns the focus to its toggle (3b0fcfb).
- Closing a tab or locking denies a pending card, resets the level to Read and drops late replies. A dropped session keeps the transcript. Every tool call gets a result even after a stop, history is trimmed in whole groups, and there is a New chat button (d589b51).
- Provider settings: redirects are not followed; plain `http://` is allowed only for loopback and private addresses; credentials inside the base URL are refused; "Remove stored key" exists; presets set provider and URL together; "Save & test" tests what is on screen; "OpenAI" replaces the `[OI]` placeholder (d33028d, d589b51). A saved base URL that today's rules refuse is refused before the key is unsealed (cd11f97).
- The stored API key moves to another provider or address only after a native question; "no" answers "Enter the API key for the new address.", and the renderer's old reuse flag is ignored. The base URL is stored as parsed, and control or invisible characters in it are refused (03dfa92, 3b0fcfb). An "Allow" given after the vault was locked moves nothing; if the vault was unlocked again meanwhile, the save says "The vault was locked while you were deciding - unlock it and save the settings again." (while it is still locked, "Vault is locked."). After a "no", any key move within 30 seconds is refused, with a note to wait or to enter the key for the new address (6c19b1b).
- MCP servers: each row shows the tool counts and the protocol version, and the Edit form shows the header name, the variable name and whether a secret is stored ("A secret is stored - leave this blank to keep it."). Edits keep or clear credentials deliberately, sanitised names must be unique, and removing an unreachable server always deletes it. A server that speaks only legacy HTTP+SSE gets a clear "Streamable HTTP only" message. Loopback means a parsed 127.0.0.0/8 address, `::1` or `localhost`, not a host name that starts with "127."; IPv6 URLs keep their brackets (d33028d, d589b51, 863a024).
- The assistant panel overlays the terminal below 1500 px instead of squeezing it, and the transcript is a live region (d589b51).

### 4.5 Vault, backups and settings

- Confirmations work: key and server delete, backup restore, host-key forget, tab close, MCP removal, multi-line paste and update install all wait for an answer in the app's own dialog (7e5c5c5). A confirmation ignores the second click of a double-click (3b0fcfb).
- Idle auto-lock fires: 15 minutes by default, `0` turns it off, typing in the terminal counts as activity, a warning appears 60 seconds before an idle lock (half-way for an auto-lock of two minutes or less), and locking from the window with live sessions or transfers asks first (7e5c5c5, 57993ba, d5e9d22). The tray's Lock only refreshes the page, because the backend has locked already; Ctrl+L or the idle timer on a locked vault does nothing; locking a locked vault writes no second audit row (03dfa92, 3b0fcfb).
- Locking closes every dialog and blanks password and PEM fields. A dismissed unlock dialog stays dismissed, and the backup password prompt is masked (7e5c5c5).
- Backup and restore never pass through the page: Rust opens the native dialogs. Restore asks first, then handles a backup made under another master password with a masked prompt and one retry, and afterwards keys, servers and settings reload. Backups include SFTP bookmarks (57993ba, c227218). The backup's save dialog opens in the Downloads folder, and the path picked there gets the write deny-list, with `~/.ssh` still allowed; the audit-log CSV export's dialog opens there too, and its path gets the whole list, `~/.ssh` included (6c19b1b).
- Settings show the effective defaults (auto-lock 15 minutes, 4 parallel transfers), are validated in Rust, revert a control when a save is refused, and disable the security settings with a reason while locked (57993ba, c227218). Bitwarden Save, Test and Sync, backup Create and Restore, and "Lock now" are disabled with a hint while locked, and "Lock now" with no vault says there is none (3b0fcfb).
- Changing the master password runs off the main thread under a vault-wide rotation lock. The dialog stays open and busy, and other writers that seal data fail fast with "The vault is being re-encrypted - try again when it finishes." (57993ba, c227218). An unlock is refused with the same message while the change runs (cd11f97).
- Vault creation and unlock run off the main thread. The unlock throttle holds for guesses sent in parallel and for the password-change check, and a lock that lands during an unlock wins (cd11f97).
- Every read-then-write SQLite transaction uses `BEGIN IMMEDIATE`. One effect: an assistant settings save that failed part-way used to keep a new base URL beside the old key (cd11f97).
- On Windows, deploy, private-key export, backup export and audit CSV export succeed (57993ba).
- Destructive and policy commands refuse while the vault is locked: key delete and rename, category edits, audit clear, known-hosts forget, four security settings, MCP removal and tool toggles (57993ba, d33028d).
- Boot no longer aborts when one call fails; keys, servers and settings show an error card with Retry; identical toasts collapse; the audit CSV export neutralises spreadsheet formulas; the create-vault dialog names Argon2id (c227218). The CSV export shows a busy state (3b0fcfb).

### 4.6 Lifecycle and updater

- Quit exists in the vault menu, the palette and as Ctrl+Q. Closing the window hides it to the tray and shows a notice the first time. Quitting from the window with live sessions or transfers asks first, and the lock and quit chords ignore held keys (863a024, d5e9d22).
- Every exit runs the vault lock teardown (863a024) and waits up to 2 s for MCP session DELETEs (cd11f97). The lock no longer unseals MCP secrets on the main thread (cd11f97) and unseals at most four at once (03dfa92).
- A failed database open or migration shows a native dialog with the cause and the database path, and exits cleanly (863a024).
- The real version shows in the sidebar, the window title and Settings; the internal "v14-tabs" marker is gone (863a024, d5e9d22).
- Updater: the signed trusted comment must name the release bound to the URL tag, so a validly signed older build cannot install as a newer one. Release URLs must be exact release assets. The setup `.exe` (the NSIS installer, the release asset ending in `_x64-setup.exe`) starts through one `ShellExecuteExW` call so UAC can elevate, and a declined prompt reads as cancelled; an `.msi`, picked only when a release has no setup `.exe`, is started with `msiexec /i`, where a declined prompt is not reported as cancelled. Partial downloads are deleted on error, and stale ones are pruned at start (863a024).
- The update dialog names the version and warns about live work, only one update run happens at a time, and a newer release without an installer for this platform is reported (d5e9d22).

### 4.7 Bitwarden

- Before SSHSpan uploads anything to a Bitwarden server, a native dialog asks: "SSHSpan will upload your SSH private keys and saved server passwords to this Bitwarden account when it syncs:", then the account, the server and the address on lines of their own, a line saying so when the account is not the one allowed before, and "Allow?". It asks after the first save and after any change of the server URL or the account. Until it is allowed, Sync is refused before any network call, with a message that names the account; "Allow syncing..." in Settings asks again, and Settings shows "Not confirmed - SSHSpan will not sync with <host> until you allow it." After "Don't allow" or "Cancel", no Bitwarden destination question is asked for 30 seconds, whatever server or account it names. Settings saved before this version keep syncing: a one-time migration at the first start counts their destination as allowed. A backup never carries Bitwarden settings (6c19b1b; section 5.3).
- The account must be one email address: "Enter the Bitwarden account as one email address, like name@example.com." (6c19b1b).
- Accounts that use Argon2id with a memory setting other than 16 MiB can log in. The memory the server reports in MiB used to be read as KiB (6c19b1b; section 6.1). The key is derived on a background thread, for two sign-ins at a time at most; a third waits up to 30 seconds, then says "Another Bitwarden sign-in is still running. Try again when it has finished." (6c19b1b).
- Test connection and save reuse the stored master password only for the server and account it was saved for; changing either needs a password (863a024, d5e9d22). The settings row is written in one `BEGIN IMMEDIATE` transaction, so no reader sees a new URL with an old password (863a024).
- Sync keeps data. It writes back revision and change marks after each push and pull; edits made during a sync survive; items moved to another folder stay matched; organisation items are reported instead of duplicated; servers carry their local id, so a lost link re-links instead of duplicating; server passes honour the allow-remote-overwrite confirm; undecryptable fields are errors; category deletes mark keys and servers for sync; pulled key names are de-duplicated (863a024).
- Results show key and server counters, deletions and each error; a run that stopped part-way is a failure and never says "Sync complete." (d5e9d22). The status line shows the last result: "Last sync stopped: <reason>", or "Last synced: <time> - <n> errors, see the list below." (3b0fcfb). Audit rows `sync.run`, `sync.error` and `sync.key_renamed` are written (863a024).
- The approval question lists each pending server and key change by name, with the address or fingerprint it would set and, for a server, which settings would change (d94ed2d, 03dfa92). Apply sends the approval token of the list that was shown. If Bitwarden's list changed meanwhile, nothing is applied and the new list is asked about again; the question is shown three times at most, then nothing is applied and the app says to sync again. More than 500 server changes, or more than 500 key changes, cannot be approved (03dfa92, 3b0fcfb).
- An imported key's fingerprint and public key come from its private key; an item whose claims do not match is reported by name and not imported (03dfa92).
- Pending entries quote cleaned text (no control, invisible or direction characters, 80 characters at most), and server names pulled from Bitwarden are stored cleaned (03dfa92). Sync errors quote item titles and ids the same way, the error list is spelled out and isolated, and every other backend text in the Bitwarden settings is spelled out (6c19b1b).
- A category rename, move or delete, or a change of a key's categories, uploads only while Bitwarden's item is unchanged. Otherwise the remote change is listed for approval and the category follows at the next sync, so an older password is never uploaded (A7-23; 03dfa92).
- The error for several items claiming one server names each item and says to delete only true duplicates (cd11f97).

### 4.8 Accessibility and visual

- One menu helper builds the vault, category, key-connect, config-import, server and terminal menus: clamped to the window, `role=menu`, arrow keys, Escape and outside click, with the focus returned to the opener (53347df). The SFTP menus use it too (3b0fcfb).
- There is a visible focus ring. Key rows, category rows, chevrons and session tabs work with Enter and Space; tabs and radio groups have real semantics; labels are bound to their controls; settings rows are no longer `<label>` wrappers (the bandwidth "Unlimited" pill used to toggle twice). Password fields get a show-and-hide button that does not pollute their accessible names. Motion respects the reduced-motion setting, and hit areas are at least 24 px (53347df).
- Faint text contrast is raised to at least 4.5:1, and accent fills carry dark text (53347df).
- Dialogs keep their buttons visible at 880x560, the category tree is reachable as a drawer at 900 px and below, the vault chip is compact, the selection bar wraps, and `color-scheme` is dark (53347df).
- The SFTP view fits the default and minimum window sizes, its splitters are keyboard-operable separators, and every drag has a single-pointer alternative (WCAG 2.2 success criterion 2.5.7) (d94ed2d).
- After a successful "Allow syncing...", the focus moves on to Sync now instead of falling to the page (6c19b1b).
- The command palette requires every word to match and ranks results, with more destinations; the audit log has event and text filters and "Load older entries" (53347df).
- Terminology follows Servers, Server categories and Keyboard-interactive; sentence case and " - " in shown text are enforced by a scan (53347df, d5e9d22). Renderer comments cite an audit ID or a plain reason, checked by `check-renderer-hygiene.js` (3b0fcfb).

## 5. Security

### 5.1 The Criticals

| ID | Problem | Closed in | How |
|---|---|---|---|
| A7-01 | Every private-key write failed on Windows (`icacls` was given a bare SID) | 57993ba | One `icacls` call with `*SID`, absolute `System32` paths and `CREATE_NO_WINDOW`; the file is restricted before any secret byte is written; the ACL test went RED to GREEN natively on Windows 11; after the Windows job's first run it checks two folders it sets up, by SID: the user's entry alone where the folder passes permissions down, the user, SYSTEM and Administrators where it passes none down |
| A2-01 | The idle auto-lock never fired | 7e5c5c5, 57993ba | Deadline from the last trusted input, a poll that no longer re-arms, a heartbeat only after activity, and a backend default of 15 minutes |
| A5-01 | Every native `confirm()` guard was bypassed | 7e5c5c5 | All 13 sites await `confirmModal`; a static scan in `test:safety` fails on any native call |

### 5.2 Other security findings from the audit

| ID | Severity (highest in the row) | Problem | Closed in | Evidence |
|---|---|---|---|---|
| A6-01, A4-02, A3-30 | High | Model text with an embedded newline ran commands at Draft level with no approval card and no audit row | d33028d, d589b51, 863a024, cd11f97 | `typing_needs_draft_or_higher`, `typed_text_cannot_press_enter_or_send_control_keys`, `exec_refuses_tab_but_typing_keeps_it`; `test:assistant` |
| A4-01, A6-15 | High | `approved` was never sent, so user-approved MCP calls were always denied and the approval path was dead | d33028d, d589b51 | `the_call_gate_needs_approval_below_execute_and_names_who_approved`; `test:assistant` |
| A4-05, A7-29, A8-15 | High | A changed MCP tool definition kept its approval and its auto-approve | d33028d, d589b51, cd11f97 | `a_changed_definition_is_disabled_loses_auto_approve_and_is_flagged`; `an_enable_racing_a_definition_change_never_approves_the_new_definition` |
| A7-05, A2-03, A5-38 | High | "PKCS#8 PEM, encrypted" with an empty passphrase silently wrote an unencrypted private key | 46a9d1b, 652aa5e | `private_export_passphrase`; `test:keys` refuses before any IPC |
| A6-03, A2-48 | Medium | `vault_backup_create` handed the whole sealed vault to the webview | 57993ba, c227218; the old command bodies deleted in 03dfa92 | `backup_exported_to_a_file_restores_from_that_file`; `test:safety` |
| A6-04, A2-19 | Medium | The .pem browse button read the private key's plaintext into the webview to learn its path | 57993ba, c227218 | The path-only `system_pick_file_path`; `test:safety` |
| A6-05 | Medium | The updater verified the signature but did not bind it to the version, so an older signed installer re-tagged as newer passed | 863a024 | The signed comment must read `SSHSpan release v<x>`; a v1.8.0 signature no longer passes as v1.10.0; vectors from `scripts/gen_minisign_test_vector.py` |
| A6-06 | Medium | Folder download walks had no depth or entry cap and followed symlinked folders | dc09f93 | Download-plan tests over a fake listing and a real in-process session (a loop link, a dangling link, a link out of the tree) |
| A6-02 | Medium (Partial) | Local paths the renderer supplied were not bound to a native dialog | dc09f93, 463345c, 03dfa92, 6c19b1b | A write deny-list, a one-use dialog grant for `sftp_download`, confined derived paths, delete and move refusals, and SSHSpan's own program and data folders; in the fix wave, the same deny-list for paths picked in save dialogs and for the text, key and backup exports; still a deny-list (section 7.3) |
| A2-09, A5-19 | Medium | Locking left open dialogs and pasted secrets (PEM, passphrases) in the DOM | 7e5c5c5 | The `test:safety` lock sweep |
| A4-13, A7-33, A8-13 | Medium | A stored API key could not be removed, and followed a changed provider or base URL to the new origin | d33028d, d589b51, 03dfa92, 3b0fcfb, 6c19b1b | `a_stored_key_does_not_silently_follow_a_new_provider_or_origin`, `rw_s2_the_stored_api_key_moves_only_when_the_native_question_allows_it`, `fw_r2_an_allow_after_a_lock_never_moves_the_api_key` |
| A6-07 | Medium | The docs stated guarantees the code did not keep | the documentation commit | `docs/SECURITY.md` rewritten against the code and checked by the documentation accuracy review |
| A6-08 | Low | Destructive and policy commands ran while the vault was locked | 57993ba, d33028d, c227218, 3b0fcfb | A lock-gate test per command; the renderer's lock gates in `test:safety` and `test:servers` |
| A6-09, A7-47 | Low | Exit skipped the lock teardown, so staged plaintext copies and MCP sessions outlived the process | 863a024, cd11f97 | Every exit runs the lock path once and waits up to 2 s for MCP DELETEs; `the_exit_waits_for_mcp_teardowns_but_never_past_its_budget`; the `RunEvent` wiring itself needs a Tauri runtime |
| A6-10 | Low | The provider client followed redirects and accepted plain http to any host, forwarding the API key | d33028d | `provider_client_does_not_follow_a_redirect_with_the_api_key`, `plain_http_base_urls_only_reach_local_or_private_hosts` |
| A6-12 | Low | OSC 8 links fell back to xterm's `confirm()` plus `window.open` | d5e9d22 | An in-app question showing the real site; `test:servers` clicks a real link in a real xterm |
| A6-13, A7-43 | Low | `whoami` and `icacls` were started by bare name | 57993ba | Absolute `System32` paths and `CREATE_NO_WINDOW` |
| A6-14 | Low | `.pub` counted as an inert extension (it opens Publisher on Windows) | dc09f93 | `pub_is_not_an_inert_extension` |
| A7-45 | Low | A newline in an imported comment injected lines into `authorized_keys` text, `.pub` files and PPK headers | 46a9d1b | `sanitize_key_comment` at generate, import and every exporter |
| A2-32 | Low | The audit CSV export did not neutralise spreadsheet formulas | c227218 | `csvField` prefixes a quote; `test:safety` |
| A6-11 | Low (Accepted) | Secret-wiping gaps | 57993ba, 5e77b54 | SSHSpan's copies are zeroized; the rest is inside russh (section 7.3) |

### 5.3 Destinations for secrets, bound in Rust

The later reviews assumed a compromised renderer: script in the webview that can call any registered command with any arguments. Rust cannot observe a click in the page, so an approval the renderer reports can gate an action, but cannot prove a human decided (`docs/SECURITY.md`, accepted risks). Where a secret leaves the machine, the destination is therefore now bound in Rust.

- **Saved SSH passwords (03dfa92, 3b0fcfb).** The pass-1 security review found, with a probe, that `server_save` kept the sealed password while the host, port or user changed, so a compromised renderer could re-point a server and receive its password, with no dialog at all if the new host was already trusted (Medium). Now:
  - a save that moves a server with a saved password to another host, port, user name or sign-in method is refused with "Enter the password for the new server or account." and writes nothing, unless a new password comes with it, the saved one is removed, or the server switches to a key;
  - the read, the check and the write happen in one transaction;
  - Connect and Test spend the saved password only for the server's own user name.

  Tests: `rw_s1_a_retarget_without_a_new_password_is_refused_and_changes_nothing`, `rw_s1_a_retargeted_server_never_spends_the_old_password`, `rw_fix1_a_save_checks_the_row_it_writes`.
- **Native credential questions (03dfa92).** The pass-1 security review found that `mcp_save_server` would bind any environment variable or secret to any https origin and mark it confirmed, and that the stored assistant key moved to a new origin on a flag the renderer set (Medium). Now:
  - An MCP save that would send a secret or an environment variable somewhere it was not bound to before (a new server, another URL or variable, a record restored from a backup or declined before) is stored switched off and asked about in a native dialog that names the host and the variable. Nothing is sent until it is allowed.
  - The stored API key moves to another provider or address only after the same kind of question. The renderer's old reuse flag is accepted and ignored.
  - The dialog offers "Don't allow" (first), "Allow" and "Cancel"; Esc and closing it mean no. "Allow" counts only at least 1 s after the dialog appears; an earlier one is "too quick". One question is open at a time, app-wide; a second is neither asked nor queued: an MCP server or Bitwarden settings saved meanwhile stay switched off (Bitwarden since 6c19b1b), and a key move is refused. An "Allow" given after a lock (for the assistant key move, since 6c19b1b), or for settings that changed while the dialog was open, confirms nothing, and a later "no" is never undone by an earlier "Allow". Quoted values are cleaned and capped. Both answers are audited without the value.
  - The first version defaulted to "Allow", so Enter confirmed; RW's code review caught it (High), and it was fixed before the commit.
  - After "Don't allow" or "Cancel", no further question of the same kind is asked for 30 seconds, whatever it names, so a page can neither wear a user down with repeats nor raise a fresh question for each made-up host. Each of the three kinds - MCP credential, assistant key move, Bitwarden destination - waits on its own: a "no" holds back only questions of its kind, though the three still share the one open question (6c19b1b).

  Tests: `rw_fix1_the_credential_question_defaults_to_dont_allow`, `rw_fix1_only_a_deliberate_allow_allows`, `rw_fix1_one_credential_question_at_a_time`, `rw_fix1_an_allow_given_after_a_lock_confirms_nothing`, `fw_r2_an_allow_after_a_lock_never_moves_the_api_key`, `rw_fix1_a_later_dont_allow_is_never_undone_by_an_earlier_allow`, `rw_fix2_the_second_starts_when_the_dialog_is_on_screen`, `fw_u2_a_no_holds_back_its_kind_whatever_the_host`, `fw_u2_a_declined_credential_holds_back_every_mcp_question`, `fw_u2_a_declined_key_move_holds_back_every_key_move`.
- **MCP requests checked against the stored record (cd11f97, 03dfa92).**
  - The call gate runs again right before every `tools/call`, after any initialize, refresh or session renewal (cd11f97).
  - One check of the stored record, `not_contactable`, refuses a server that was removed, edited or switched off. It runs before every initialize and again once the initialize is answered (before the session is registered and before `notifications/initialized` is sent), before every `tools/list` page, before the page asked again after a 404 renewal, and before the refreshes that follow a refused or a sent call (03dfa92).
  - A session set up for a server that changed meanwhile is ended where it was set up and is never registered.
  - Not checked against the record: the `-32601` answers to requests a server sends inside a response that is still open, and session DELETEs (section 7.3).

  Tests: `rw_fix4_no_session_is_set_up_with_a_server_switched_off_edited_or_removed`, `rw_fix5_a_server_changed_while_its_initialize_was_out_gets_no_session`, `rw_fix5_a_listing_asks_for_no_further_page_once_its_server_changed`, `rw_fix5_a_page_is_not_asked_again_on_a_renewed_session_once_its_server_changed`, `rw_fix5_a_call_whose_server_changes_during_its_set_up_is_refused`. Each check is pinned by a mutation that removes it alone.
- **Bitwarden approvals bound to the list shown (03dfa92, 3b0fcfb).** JU6b's security review found that an approval was not bound to the list on screen, and that an incoming key's fingerprint was whatever the item claimed, so a swapped key looked unchanged. Now:
  - remote changes apply only with the approval token of the list that was shown: a SHA-256 over every pending change and over each item exactly as Bitwarden served it;
  - if this run's list differs, nothing is applied and the new list comes back to be asked again (three rounds at most in the app);
  - more than 500 server changes, or more than 500 key changes, cannot be approved;
  - an imported key's fingerprint and public key are derived from its private key, and an item whose claims do not match is reported and not imported.

  Tests: `rw_s4_an_approval_applies_only_the_list_it_was_issued_for`, `rw_s5_a_key_swapped_behind_its_old_fingerprint_is_refused`, `rw_fix1_an_approval_of_a_list_too_long_to_show_is_refused`.
- **The Bitwarden destination (6c19b1b).** The pass-2 security review found a High that predates the branch. A compromised renderer could call `bitwarden_save_config` with its own server URL, account and master password, then `bitwarden_sync`. Every key and server, still linked to items in the user's real vault, would be planned as new and uploaded: each OpenSSH private key and each saved server password, with no question and no approval token. The reviewer proved both steps with probe tests. The fix binds the destination (server URL and account email) the way MCP credentials are bound:
  - the first save, a changed URL or a changed email stores the settings unconfirmed and asks "SSHSpan - Sync with Bitwarden?" with the same dialog rules;
  - the question names the account first, on its own line, so a look-alike account cannot hide behind a familiar host, then the server and the address, and it says when the account is not the one allowed before; the account must be one email address, because free text could add words to the question;
  - until the destination is allowed, `bitwarden_sync` refuses before anything is unsealed or sent, with a message that names the account, and "Allow syncing..." in Settings asks again;
  - settings stored before this version keep syncing (a one-time migration that a restore cannot run again counts their destination as allowed), and a backup never carries Bitwarden settings, so a restore can neither bring nor allow a destination;
  - both answers are audited with the host only.

  The fix wave's security re-check found the High closed end to end. Only `bitwarden_sync` uploads, and it refuses before any unseal, prelogin or login. Only the native "Allow" confirms the destination, after the one-second rule, the question's turn and the password-change guard, inside one transaction that checks the vault generation and the destination again. All eight bypass attempts held, among them declined, too-quick and overlapping answers; look-alike accounts with a tag, a trailing dot or Cyrillic letters, each of which is asked about (an account with an invisible character, asked about then, is now refused at save by the one-email rule); racing saves; an "Allow" racing a save; and a lock. An account that differs only in case or surrounding spaces counts as the same one, by design.

  Tests: `fw_r1_a_re_pointed_sync_refuses_before_any_network_call`, `fw_r1_a_first_save_a_changed_url_and_a_changed_email_come_back_unconfirmed`, `fw_r1_allow_counts_only_after_a_second_unlocked_and_for_the_destination_asked`, `fw_r1_the_answers_are_audited_without_a_value`, `fw_r1_settings_from_before_keep_syncing_and_nothing_else_is_allowed_by_itself`, `fw_s1_the_account_is_one_email_address`, `fw_s1_the_question_names_the_account_first`, `fw_u2_a_declined_destination_holds_back_every_destination`. With this, the statement in `docs/SECURITY.md` that destinations for secrets are bound in Rust holds for the sync too.
- **The program-folder deny-list, and paths picked in dialogs (03dfa92, 6c19b1b).**
  - SFTP writes and deletes are refused for SSHSpan's own program and data: the install folder (for a copy run straight from a drive root, the home folder, Downloads, the Desktop or Documents, only the executable and, on Windows, the DLLs beside it), the AppImage, the macOS bundle, the data and cache folders and the webview profile. A folder that holds them cannot be moved, replaced or deleted; reads still work. A "Download as..." path may not replace the program files, and the save dialog's suggested name is reduced to a file name (03dfa92).
  - Save dialogs open in the Downloads folder and suggest only a bare file name. A path picked in one gets the same write deny-list as a typed path, for downloads and for the public-key, audit-log, private-key and backup exports, with `~/.ssh` still allowed for the private-key and backup exports. This reverses the earlier rule that a picked path skips most of the list: a pick could still replace settings that run commands, such as `.gitconfig` or `.vimrc`. `user-dirs.dirs` and `user-dirs.locale` are protected for every write, because they say where Downloads is, and so where the save dialogs open: a typed download over them could have steered the next dialog (6c19b1b).
  - Found by the pass-1 security review (the deny-list did not cover the app itself); RW's security review (a dialog-picked path skipped the program-folder rule while the renderer could preset a full path as the default name, a DLL-planting route); the pass-2 security review (GTK's save dialog opened in the home folder, so a suggested `.bashrc` was one Save away from `~/.bashrc`); and the fix wave's re-checks (picked paths could still replace settings that run commands; the folder-settings chain; with no Downloads folder on Linux the dialog fell back to home; the key export could suggest `.bashrc`, and a key named like a path could steer it into `~/.ssh`).
  - Tests: `rw_s3_the_install_folder_appimage_and_webview_profile_are_refused_for_writes`, `rw_fix1_a_dialog_picked_download_never_writes_the_program_files`, `rw_fix1_the_save_dialog_suggests_only_a_file_name`, `fw_r3_a_dialog_picked_download_never_replaces_a_startup_file`, `fw_r3_a_save_dialog_opens_in_downloads_or_else_home`, `fw_s2_a_dialog_picked_download_gets_the_whole_deny_list`, `fw_s2_picked_or_typed_never_program_settings_or_folder_settings`, `fw_r12_a_dialog_picked_text_export_gets_the_write_deny_list`, `fw_t3_key_and_backup_exports_get_the_deny_list_but_not_for_ssh`, `fw_u1_a_key_name_suggests_only_a_bare_file_name`, `fw_u1_every_save_dialog_suggests_a_bare_file_name`.
  - It is still a deny-list, so A6-02 stays Partial.
- **Key files on network paths (6c19b1b).** On Windows, opening a key file on a network share makes an SMB connection and a sign-in to that share. A compromised page can save any key-file path, and the connect path, older than the branch, read whatever path was saved, so Test connection could reach a share chosen by the page. Now, on Windows, key files are read only from this computer's drives, mapped drives included; a share, the `\??\` object namespace, a device or a relative path is never touched: saving such a server saves it and warns, and Connect and Test connection refuse. The rule is a pure function, tested on every platform; the security re-check's cross-compiled probe found every network spelling it tried refused. Tests: `fw_t2_only_a_drive_letter_path_is_a_local_key_file`, `fw_t2_a_key_file_elsewhere_is_refused_before_it_is_touched`, `fw_s4_the_key_file_is_looked_at_after_the_rotation_guard`. SFTP local paths and "open external" targets are not covered; section 7.3 says why.
- **Names a server chooses (d94ed2d, 3b0fcfb, 6c19b1b).** Wherever a name from a server or a Bitwarden item could deceive, invisible and text-direction characters are spelled out ("<U+202E>"), the name is isolated from the sentence around it, and long text is capped: SFTP file names (and names that only look like "..", show nothing or are "~"), the edit-conflict question, the Bitwarden pending list and error list, the deploy sheet's notes and the native questions' quoted values. In the fix wave every backend error and warning in the Bitwarden and SFTP-edit paths is spelled out as well. The texts `server_save` refuses with, which carry only names the user typed, are not; the security re-check accepted that (section 7.3).

### 5.4 The whole-branch reviews

Besides the per-unit reviews, the branch had two whole-branch passes, all on Opus (section 2.5).

**Pass 1, over 1ca864f..d5e9d22** (run while RU6b and JU6b were still in progress, which it left out):
- Security review: no Critical or High; A6-01 to A6-15 all addressed; the content security policy and the capabilities unchanged. Two Medium findings, both proved with probes under the compromised-renderer model: the saved SSH password that followed an edited endpoint, and MCP credentials bound to any origin together with the assistant key moving on a renderer flag. It also asked for the app's own folders on the deny-list, and listed the accepted risks for the docs. All went into RW (section 5.3).
- Rust review: no Critical or Important and no regression, with 748 tests passing. Its fix list went into RW: audit rows that failed after a committed write, the password-change guard for Connect and Test, dead command bodies, SFTP error texts, the unknown-size hash (section 6.1), and a triage of every minor the units had deferred.
- Renderer-to-backend review: Warning, with two Important findings: the deploy sheet ignored the preview's warnings and legacy Host lines, and "Stop editing" deleted the only local copy without asking. Eight Minor and several older items came with them. All went into JW, and "Stop editing" also got a backend guard in RW.

**Pass 2, over d5e9d22 onwards** (a frozen snapshot of RU6b, JU6b, JW, and RW before its sixth round, which RW's code reviewer checked on its own):

| Review | Verdict | Finding | What was done |
|---|---|---|---|
| Code | Approve: all nine renderer-to-backend contracts match, the cross-unit flows and invariants hold, the static checks and all seven suites pass, 64 targeted Rust tests pass | Low: a host category whose saved parent is in the other scope blocked every top-level reorder in that scope (probe) | Fixed in 6c19b1b |
| | | Low: "Edit" while "Stop editing" was still checking reused the edit that the stop then closed and deleted (probe) | Fixed in 6c19b1b |
| | | Nit: a doc comment named a function that is now test-only | Fixed in 6c19b1b |
| Security | Approve with warnings: checked sound were all contracts, MCP gating end to end, the native dialog defaults in the plugin and rfd sources, the saved-password binding against pulls and restores, the lock and quit wipes, and the invariants | High, older than the branch: the Bitwarden sync could be re-pointed and would upload every key and saved password (probe tests) | Fixed in 6c19b1b (section 5.3) |
| | | Low: the assistant key-move question still counted after a lock (probe) | Fixed in 6c19b1b |
| | | Low: GTK's save dialog opened in the home folder, and dialog-picked downloads skipped the shell-startup rules (GTK offscreen probe) | Fixed in 6c19b1b |
| | | Nit: Bitwarden error texts were not isolated (a U+202E survived) | Fixed in 6c19b1b |

**The fix wave's re-checks**, made by the same two reviewers (section 3.2 has the detail):

| Round | Code re-check | Security re-check |
|---|---|---|
| 1 | Approve: every pass-2 finding closed. 2 Lows (paths picked in a save dialog, found independently of the security re-check; the focus after "Allow syncing...") and 2 nits | Approve with warnings: the High closed end to end, all eight bypass attempts held. 3 Lows (the Bitwarden account as free text; picked paths and the folder-settings chain; Argon2id on an async worker), 1 informational point (the key-file check at save) and 1 nit (backend texts not spelled out) |
| 2 | Approve: everything closed. 2 Lows (the back-off keyed on the full address; the Windows `\??\UNC\` spelling, with the connect path) and 2 nits | Approve with warnings: every round-1 finding closed. 2 Lows (the Windows UNC spelling, shared with the code re-check; the key and backup export paths); the plain `server_save` rejection texts accepted |
| 3 | Approve: every item closed. 2 nits (a host with a trailing dot counted as a second host for the back-off, made moot by round 4; a stale line in the implementer's report) | Approve with warnings: the Windows key-path rule held against every network spelling in a cross-compiled probe, and the `~/.ssh` exception reached nothing else. 2 Lows (the export dialog steered by a key's name, shown with a GTK probe; host keying cannot stop a fresh question per made-up host, a design limit) and 1 informational point (the Windows share residual, accepted) |
| 4 | - | Approve: bare suggested names in every format; one question per kind for exactly 30 seconds after the user's own "no", each kind on its own. 1 nit, older than the branch (file-dialog titles not cleaned) |

The controller sent round 4 to the security re-check only, and checked round 5, the nit's fix, itself.

### 5.5 Hardening and security bugs found beyond the audit

These came from the per-unit reviews, the new tests, or a unit's own verification; none had an audit ID. The binding work of section 5.3 is not repeated here.

| # | What was wrong | Found by | Closed in | Test or evidence |
|---|---|---|---|---|
| 1 | Passphrase-protected PuTTY exports failed their own MAC check: `export_ppk` MACed the unpadded private blob, while PuTTY and SSHSpan's import MAC the padded plaintext, so almost every protected .ppk export was unreadable | The new export-to-import round-trip test (A7-53), first RED run | 46a9d1b | `encrypted_ppk_export_imports_back_for_every_key_type` |
| 2 | The RFC 4716 public export kept only the first word of the comment | RU3's own test, RED | 46a9d1b | `rfc4716_public_export_keeps_the_whole_comment` |
| 3 | MCP loopback was decided by string prefix: `http://127.evil.example/mcp` counted as loopback, so a DNS name starting with "127." was accepted for plain-http MCP traffic; IPv6 base URLs also lost their brackets | JU3, while reading the backend contract; RED in RU5 | 863a024 | `http_loopback_is_decided_on_the_parsed_address_not_a_name_prefix` |
| 4 | The saved Bitwarden master password could be used for a typed endpoint: `bitwarden_test_connection` logged in to a server URL and email the renderer chose. The next round found that the save wrote URL, email and password as separate commits, so a concurrent test could read a new URL with the old password (reproduced in SQLite) | RU5 security reviews (Fable) | 863a024: the saved password is unsealed only for the saved URL and email; the save is one `BEGIN IMMEDIATE` transaction | Four tests the re-review showed failing on the old code |
| 5 | Edit temp-file pre-plant: the edit save wrote a predictable `<target>.sshspan-tmp` without exclusive create, so a symlink planted at that name made a save overwrite the victim file; the queue's `.part` had the same pattern, and a resumed `.part` could be swapped between check and append | RU6a security reviews (Fable) | 463345c: a fresh, unguessable temp opened with exclusive create, `LSTAT` before the rename, only temps the call created removed; a resumed `.part` checked by size and a read-back of its last 64 KiB | `ru6a_fix1_an_edit_save_never_writes_through_a_planted_temp_file` |
| 6 | OSC 8 links with a user name: the in-app question let a long user name hide the real host | JU5 security review (Fable) | d5e9d22: the URL is parsed once, user names and passwords are refused, "Site: <host>" is the first line | `test:servers` |
| 7 | Approval-card masking keyed by names the server chooses: JU3 masked argument values whose names looked secret, so a server or an injected model could name an exfiltration parameter innocuously (`page_token`) and hide it from the approver | JU3 review (Fable), rated Critical, before commit | d589b51: full arguments are always shown | `test:assistant` |
| 8 | Rug-pull window: enabling a tool pinned whatever definition hash was stored at click time, so a stale settings row could approve a new definition with auto-approve | RU2 security review (Fable) | d33028d: `expected_hash` compare-and-swap, mandatory for every enable; cd11f97 runs the compare inside the record transaction and re-checks the gate right before each `tools/call` | `an_enable_racing_a_definition_change_never_approves_the_new_definition` |
| 9 | Password rotation interleave: moving the master-password change off the main thread (the A7-13 fix) let writers seal data under the old password while a rotation ran: stranded secrets, old blobs written back, reverted edits | RU1 review (Opus), rated Critical, before commit | 57993ba: `VaultRotationLock` (writers fail fast; the rotation holds the write lock from its snapshot through the commit and the password install) and conditional updates that roll back if a sealed row changed | `apply_vault_rotation_rolls_back_when_a_sealed_row_changed` |
| 10 | Managed config lines OpenSSH rejects: an unquoted `IdentityFile` with spaces, quote characters or `*` in an alias, and `'` or `#` in HostName or User made `ssh` refuse the whole config once the `Include` line was added | RU3 review (Opus), shown with OpenSSH 10.0p2 `ssh -G` | 46a9d1b: values quoted and escaped, aliases reduced to safe characters, pattern aliases refused | A real `ssh -G` parse through an `Include` in the integration tests |
| 11 | Undeploy deletion scope: undeploy could delete any file inside `~/.ssh` that a deployment record pointed at, including the user's own keys | RU3 implementer | 46a9d1b: only `sshspan_*` files directly in `~/.ssh` are deleted | - |
| 12 | `assistant_exec` lacked the invisible-character check that typing has, so a command could look different on the Approve card from what ran (Trojan Source) | Controller note on JU3's review; RU5 security review for TAB | 863a024 | `exec_refuses_tab_but_typing_keeps_it` |
| 13 | Recursive chmod could put setuid, setgid or sticky on every file in a tree; RU4's new walk for servers without file types then undid JU1's fix | JU1 review, then RU4 review | 11abb3e, 5e77b54: special bits only on the root and walked folders | RED showed mode `1533` where `509` was expected |
| 14 | Known hosts failed open: an unreadable `source` column fell back to "connection", which trusts silently | RU4 | 5e77b54: it falls back to "imported", which asks again | - |
| 15 | Delete through a link on servers without file types: when `READLINK` failed, a recursive delete of a linked folder could empty the folder the link points to | RU6a security review (Fable) | 463345c: a link is unlinked and never walked; a folder is emptied only when `REALPATH` agrees | - |
| 16 | Edit staging path escape: a staged copy's name could resolve outside the staging folder (`../../evil`), and a multi-byte character at byte 8 would have panicked the command | RU6a RED run | 463345c | - |
| 17 | Updater: a URL query or fragment could steer the extension and `.minisig` derivation; the stale-file prune matched names too loosely; server error bodies were quoted verbatim | RU5 security review (Fable) | 863a024: exactly six path segments and no query or fragment, prune only the generated name shape, errors cut to 300 characters | - |
| 18 | Pasted text could carry the end-of-paste marker `ESC[201~`; plain links opened on one click; the renderer's hidden-character list lagged the backend's; a held Ctrl+Q or Ctrl+L answered its own question | JU5 security review (Fable); code re-review for the held key | d5e9d22 | `test:servers` |
| 19 | An MCP environment-variable binding would have followed a URL or auth change to the new origin | RU2 implementer | d33028d: a URL, auth type or header change drops the stored secret and any binding not re-sent | `a_bearer_or_custom_header_server_needs_an_auth_source` |
| 20 | An MCP server could stream unlimited requests of its own inside one response, each answered with a request carrying the auth header, even after a lock | RU2 security review (Fable) | d33028d: at most eight answered, with a vault check before each | - |
| 21 | A secret file must be restricted before any secret byte lands in it | RU1 review | 57993ba: created empty, restricted, then written through the same handle | `failed_permission_restriction_writes_no_secret_and_removes_the_file` |
| 22 | Once `vault_unlock` ran off the main thread, the unlock throttle no longer held: 8 wrong guesses sent at once were all checked. The master-password change's current-password check was a second, unthrottled guess stream | RU6b RED; RU6b code review | cd11f97 | `unlock_guesses_sent_at_once_still_meet_the_throttle`, `guesses_split_between_unlock_and_a_password_change_still_meet_the_throttle` |
| 23 | After an edit, a session set up for the old URL stayed registered after a refused call and could be reused against the new endpoint | RU6b code review (Important) | cd11f97: sessions are bound to their settings and ended where they were set up | `a_call_refused_after_an_edit_ends_the_session_it_set_up_at_the_old_endpoint`, `a_session_set_up_with_other_settings_is_never_used_and_is_ended_where_it_belongs` |
| 24 | A tool-list change announced with the initialize answer was dropped on the call path, so the rug-pull check missed a server that had changed while the app was closed | RU6b security review (Fable) | cd11f97; 03dfa92 keeps the announcement through a failed or refused call | `a_list_change_announced_with_the_initialize_answer_brings_the_refresh`, `rw_r1_a_list_change_announced_with_the_set_up_survives_a_failed_call` |
| 25 | The assistant's native question quoted the base URL the renderer sent: injected lines, and a NUL that aborted the GTK dialog | RW code and security reviews | 03dfa92: control and invisible characters refused, the URL stored as parsed, dialog text cleaned | `rw_fix1_a_base_url_with_control_or_invisible_characters_is_refused`, `rw_fix1_a_dialog_message_keeps_its_lines_and_loses_every_nul` |
| 26 | A Bitwarden approval applied the entries beyond the 50-entry list that nobody had been shown | RW security review | 03dfa92: a cap of 500 per list; a longer list cannot be approved | `rw_fix1_an_approval_of_a_list_too_long_to_show_is_refused` |
| 27 | Queued MCP teardowns kept master-password copies | RW security review | 03dfa92: one shared copy, wiped when the last holder lets go; at most 16 pending teardowns | `rw_fix1_teardowns_share_one_password_copy_and_wait_in_a_capped_queue` |
| 28 | The edit-conflict question was one global slot: a conflict on another file re-targeted the open question, and a click meant for one file overwrote another | JU6b code review (High) and security review (Medium) | d94ed2d: one question per file, the others queued | `test:sftp` |
| 29 | The Bitwarden pending list's text isolation could be escaped, and runs of spaces could fake extra lines | JU6b security review | d94ed2d (each value in its own isolate, cleaned); 03dfa92 (cleaned at the source) | `rw_s6_pending_text_drops_disguising_characters_and_collapses_whitespace` |
| 30 | The deploy sheet's notes were neither isolated nor bounded: a U+202E could reverse a verdict, and a 50,000-character line was shown twice | JW security review | 03dfa92 (quoted lines capped at 300 characters); 3b0fcfb (spelled out, isolated, capped) | `rw_fix4_a_very_long_host_line_is_quoted_capped`; `test:keys` |
| 31 | The Bitwarden account was free text, so injected words could appear in the native question and a look-alike account could hide behind a familiar host; and a declined question could be asked again at once | Fix-wave security re-check, round 1 (Low) | 6c19b1b: one email address; the account named first, with a line when it is not the one allowed before; a 30-second back-off after "Don't allow" or "Cancel" on every credential question | `fw_s1_the_account_is_one_email_address`, `fw_s1_the_question_names_the_account_first`, `fw_s1_a_declined_destination_is_not_asked_again_for_30_seconds` |
| 32 | A path picked in a save dialog could still replace settings that run commands (`.gitconfig`, `~/.config/git/config`, `.vimrc`, `~/.local/bin/ssh`), and a typed download over `~/.config/user-dirs.dirs` could move the Downloads folder and so steer the next save dialog (shown as a probe chain). With no Downloads folder on Linux, the dialog opened in home, one Save away from `.vimrc` and the like | Fix-wave security re-check, round 1 (Low); the code re-check independently (Low, probe) | 6c19b1b: picked paths get the typed-path deny-list; the folder settings are protected for every write | `fw_s2_picked_or_typed_never_program_settings_or_folder_settings`, `fw_s2_this_machines_folder_settings_are_refused_for_writes` |
| 33 | The Bitwarden master key was derived inline on an async worker. With the Argon2id unit fixed, derivations above 16 MiB, up to 1 GiB, became real, and Test connection could start any number of them | Fix-wave security re-check, round 1 (Low) | 6c19b1b: on the blocking pool, two at a time, with a busy refusal after 30 seconds | `fw_s3_the_master_key_is_derived_on_the_blocking_pool`, `fw_s3_at_most_two_derivations_run_at_once`, `fw_s3_a_sign_in_that_finds_no_free_derivation_is_refused` |
| 34 | The key-file check at save ran under the password-change guard, and a UNC path opened an SMB connection (an NTLM sign-in to the share) at save. Round 2's check then let a `\??\UNC\` spelling through on Windows, and the connect path, older than the branch, read any saved key-file path, so Test connection could reach a share | Fix-wave security re-check, round 1 (informational); code re-check, round 2 (Low), confirmed by the security re-check with a cross-compiled probe | 6c19b1b: in round 2, the check after the guard and never on UNC or device paths; in round 3, on Windows, key files read only from this computer's drives; any other path is never touched (a save warns, Connect and Test refuse) | `fw_s4_the_key_file_is_looked_at_after_the_rotation_guard`, `fw_t2_only_a_drive_letter_path_is_a_local_key_file`, `fw_t2_a_key_file_elsewhere_is_refused_before_it_is_touched` |
| 35 | The 30-second back-off was keyed on the full address, so another path on the same host (`/mcp2`, `/v2`) was asked about at once while the question named the same host | Fix-wave code re-check, round 2 (Low; probed in all three questions) | 6c19b1b: keyed on the host in round 3, then per kind in round 4 (row 38) | `fw_u2_a_no_holds_back_its_kind_whatever_the_host` |
| 36 | The private-key export suggested the key's own name as the file name, which could be `.bashrc`, and the key and backup exports were guarded only by a basic export-path check | Fix-wave security re-check, round 2 (Low) | 6c19b1b, round 3: both get the write deny-list, with `~/.ssh` still allowed for both; the suggested name in round 4 (row 39) | `fw_t3_key_and_backup_exports_get_the_deny_list_but_not_for_ssh` |
| 37 | Backend texts in the Bitwarden and SFTP-edit paths were shown as they came, among them the refusal to reopen an edit being closed and the sync refusal | Fix-wave security re-check, round 1 (nit) | 6c19b1b: every backend error and warning there is spelled out | `test:servers`, `test:sftp` |
| 38 | Keyed on the host, the back-off still let a page raise one fresh question per made-up host | Fix-wave security re-check, round 3 (Low, a design limit) | 6c19b1b, round 4: after any "no", no question of that kind for 30 seconds, whatever it names | `fw_u2_a_declined_destination_holds_back_every_destination`, `fw_u2_a_declined_credential_holds_back_every_mcp_question`, `fw_u2_a_declined_key_move_holds_back_every_key_move` |
| 39 | A key named like a path (`/root/.ssh/config`, `../../.ssh/config`, `C:\Users\u\.ssh\config`) opened the private-key export's dialog in `~/.ssh` with `config` filled in, and the `~/.ssh` exception then let one Save and "Replace" overwrite the user's ssh config. The suggested name is older than the branch | Fix-wave security re-check, round 3 (Low, shown with a GTK probe) | 6c19b1b, round 4: every save dialog suggests a bare file name | `fw_u1_a_key_name_suggests_only_a_bare_file_name`, `fw_u1_every_save_dialog_suggests_a_bare_file_name` |
| 40 | File-dialog titles from the page reached the dialog library uncleaned; a NUL in a title would have made its Linux GTK code panic inside a callback, which aborts the app. Older than the branch; found by reading the library's code | Fix-wave security re-check, round 4 (nit) | 6c19b1b, round 5: titles are cleaned like the texts of message dialogs | - |
| 41 | A release whose `MINISIGN_SECRET_KEY` was empty was published unsigned, with only a warning; existing installations would refuse it as an update. Older than the branch | The pull request's automated review (Low) | The pull request follow-up: in AGSQ11/SSHSpan the signing step fails before any asset is attached; forks keep the warning | `release.yml` |
| 42 | Seven advisories against two locked dependencies: quinn-proto 0.11.17 (RUSTSEC-2026-0338, -0340, -0343) and rustls 0.23.45 (RUSTSEC-2026-0346 to -0349) | `cargo audit` in the pull request's first CI run | The pull request follow-up: quinn-proto 0.11.18 and rustls 0.23.46 in `Cargo.lock` | `cargo audit` passes |

### 5.6 Limits of the security work

The security reviews were code reads plus targeted tests and probes. There was no penetration test and no run against real hosts, real Bitwarden or MCP servers, or the shipping webviews. The accepted risks and the untested areas are in section 7.

## 6. Bugs found beyond the audit

Rows 1 and 2 of section 5.5 also came from new round-trip tests. The rest, by area:

### 6.1 Rust backend

**The test hang: a lost wake-up in `db::block()` (03dfa92, guarded in 6c19b1b).**
- *Symptom.* The controller's full `cargo test` of RW hung for more than 15 minutes in an MCP race test. RW's code reviewer saw the same stall in 3 of 17 loaded runs and none of 9 quiet ones, including a test older than that round. A gdb backtrace of every thread showed the process idle, every runtime worker parked, the test thread parked in `block_on`, and no client socket at all.
- *Cause.* Every database call goes through `db::block()`, which ran `block_in_place(|| Handle::current().block_on(f))`. In a multi-thread `#[tokio::test]` the test body is the root future of the outer `block_on`, on the same thread, and both `block_on` calls park on one thread-local parker. A wake-up meant for the root, such as another branch's 5 ms timer in a `tokio::join!`, could be consumed by the nested park, and the root then waited for an event that never came.
- *Evidence.* 6 hangs in 18 loaded runs before the fix. A 40-line tokio probe lost the wake-up in 296 of 300 rounds. A new database test saw a wake-up only when a 30 s timer fired. After the fix, no hang in 84 runs.
- *Effect on the app: none.* The app's database calls from async code run inside tasks, its only `block_on` roots make no database call, and every MCP request has a timeout.
- *Fix, made anyway.* With a runtime entered but no task running, `block()` now drives the future with its own thread parker; inside tasks and off the runtime nothing changed (`rw_fix6_a_database_call_in_a_block_on_root_keeps_the_wake_ups_of_others`). Every join and direct await in the MCP tests now fails after 60 s instead of hanging. RW's last re-check found that on a current-thread runtime the new path would starve that runtime, so the fix wave limits it to the multi-thread runtime the app uses (`fw_r7_a_current_thread_runtime_keeps_the_old_behaviour`).

**The Bitwarden Argon2id memory unit (6c19b1b).**
- *Bug.* Bitwarden's prelogin reports `kdfMemory` in MiB. SSHSpan passed it on as KiB and raised it to its 16 MiB floor, so every Argon2id account was derived with 16 MiB. Only accounts set to exactly 16 MiB could log in. The code is the same at the base commit, so the bug predates the branch.
- *How it was found and confirmed.* The documentation accuracy review spotted it in passing. Before changing anything, the fix wave checked it against the official Bitwarden SDK's own test vectors (`bitwarden/sdk-internal`, `test_master_key_derive_argon2` and `test_password_hash_argon2id`): through the prelogin path, SSHSpan derived a different master key and a different hash. An older test, `kdf_argon2_matches_official_sdk_vector`, passed because it handed the KDF its memory already in KiB, bypassing the prelogin path.
- *Fix.* The prelogin's `kdfMemory` is converted from MiB to KiB, saturating, before the floor and ceiling are applied (`fw_r9_the_argon2id_memory_of_a_prelogin_is_in_mib`, which also checks 0, 15, 16, 64, 1024 and 1025 MiB, a value that would wrap, and the largest value).

| Bug | Found by | Fixed in | Test |
|---|---|---|---|
| Comparing pending Bitwarden changes read the whole category table once per lookup: 300 server overwrites with 150 host categories took 357 s, holding the password-change lock. Now 1.17 s for the same case, categories read once per pass | RW code re-review (Medium) | 03dfa92 | `rw_fix2_pending_server_overwrites_read_the_categories_once`, `rw_fix2_pending_key_overwrites_read_the_categories_once` |
| `vault_lock` unsealed every MCP secret on the main thread (Argon2id, about 0.75 s each in a release build), freezing the window and pushing the exit past its 2 s budget | RU6b code review (Important) | cd11f97 | `the_lock_returns_before_any_secret_is_unsealed_and_lets_go_of_its_password_copy` |
| Moving commands off the main thread removed the serialisation they relied on: a second concurrent vault create replaced the first one's verifier; a lock that landed during an unlock lost; two imports of one key stored it twice; two local renames to one name both succeeded | RU6b RED tests and code review | cd11f97 | `a_vault_create_racing_another_create_does_not_replace_its_verifier`, `a_lock_during_an_unlock_wins`, `two_imports_of_one_key_at_once_store_it_once`, `ru6b_two_local_renames_to_one_name_never_replace_each_other` |
| MCP records were read, changed and written in separate steps: a save or a connect could bring back a revoke that committed meanwhile, and a tool toggle racing a removal re-created the removed server | RU2 triage; RU6b RED | cd11f97 | `a_save_keeps_a_tool_revoke_that_committed_while_it_ran`, `a_tool_toggle_racing_a_removal_does_not_bring_the_server_back` |
| Read-then-write transactions read outside their transaction; the assistant settings save was four separate statements, so a save that failed part-way kept a new base URL beside the old key | RU6b's audit of `db/mod.rs` | cd11f97 | `an_assistant_settings_save_that_fails_part_way_changes_nothing`, `the_fingerprint_migration_reads_the_rows_it_rewrites_inside_its_transaction` |
| A category move under a parent loop never returned (an unbounded walk, on the main thread), and two opposite moves at once could make a loop | JU4 re-review; RU6b RED | cd11f97 | `a_move_under_a_parent_loop_is_refused_and_returns`, `two_opposite_moves_at_once_do_not_make_a_loop` |
| A file of unknown size was hashed as an empty file, so verifying a copy against a server that omits sizes deleted a good copy as a checksum mismatch (older than the branch) | Pass-1 Rust review | 03dfa92 | `rw_b6_a_file_of_unknown_size_is_hashed_to_its_end`, `rw_b6_a_good_copy_on_a_server_without_sizes_verifies` |
| An audit row that failed after a committed write returned an error, so a retry then failed with "already exists" | Pass-1 Rust review | 03dfa92 | `rw_b1_a_committed_change_whose_audit_row_fails_reports_success_with_a_warning` |
| A category rename wrote the whole row back, undoing a move that committed meanwhile | Pass-1 Rust review (a watch item); RW RED | 03dfa92 | `rw_b7_a_rename_keeps_a_move_that_commits_meanwhile` |
| A host category whose saved parent was a key category (possible after a restore) made every top-level reorder in that scope fail with "Those categories do not share a parent", and reloading could not help | Pass-2 code review (probe) | 6c19b1b | `fw_r4_a_parent_in_the_other_scope_counts_as_missing` |
| "Edit" while "Stop editing" was still checking reused the edit that the stop then closed, deleting the copy the editor had just reopened; later saves were lost | Pass-2 code review (probe) | 6c19b1b (backend refusal and renderer message) | `fw_r5_an_edit_being_closed_is_not_handed_out_again`; `test:sftp` |
| A5-26, server half: a server using a passphrase-protected .pem failed with "Could not decode the selected private key: The key is encrypted" and no guidance | Documentation accuracy review | 6c19b1b: advice at Connect and Test, and as a warning at save, shown in the server dialog and after a deploy saves servers | `fw_r10_a_connect_with_a_protected_key_file_says_what_to_do`, `fw_r10_saving_a_server_with_a_protected_key_file_says_what_to_do`, `fw_r10_a_key_file_protected_by_a_passphrase_is_recognised`; `test:servers`, `test:keys` |
| Prelogin numbers were cut to 32 bits before they were clamped: a memory value of 2^32 + 16 (MiB) became 16 MiB, and a KDF type of 2^32 read as 0, which means PBKDF2 | Fix-wave code re-check, round 1 (nit) | 6c19b1b: they end at the ceiling, and a type out of range is refused | `fw_r13_a_prelogin_number_above_u32_ends_at_the_ceiling` |
| Tests bound to wall-clock limits failed under load (3 failures in the controller's loaded run of RW) | Controller verification | 03dfa92: waits that include an Argon2 derivation raised to 120 s; duration comparisons replaced by ordering checks | - |
| The upload leg and the "Send to" second leg returned early after the "remove target, rename again" retry, skipping checksum verification and preserve-timestamps on exactly the path OpenSSH takes for every overwrite | Task 10, while testing | dc09f93 (a shared `rename_over`) | - |
| `File::close()` after `shutdown()` sends a second CLOSE (russh-sftp has no closed guard); a comment claimed it was a no-op | Task 10's test kit | dc09f93 | `a_second_close_after_shutdown_is_answered_with_a_failure` |
| sqlx `SELECT *` after an `ALTER TABLE` panics on a pooled connection whose schema is older (5 of 40 runs failed, 0 of 40 with named columns), so the first launch after an upgrade could have failed for users with queued jobs | Task 10's migration test, then RU1, RU3 and RU4 | dc09f93, 46a9d1b, 5e77b54 | - |
| Two old test defects in `commands/sftp.rs`: a duplicated `#[test]` attribute, and a test that never ran | Task 10 | dc09f93 | - |
| A7-20 was rated "likely"; with links treated as files, a real-session test showed the shared folder behind a link losing its search bit (0o755 became 0o600), so it is confirmed | Task 10 | dc09f93 | - |
| A new server with key login stored a sealed password if one was sent | RU4 RED | 5e77b54 | - |
| Servers that report no file type bits: folders were read and deleted as files; opening a FIFO blocked the server; "Send to" read the source under its sanitised name | RU4 and RU6a RED (a real `mkfifo` test) | 5e77b54, 463345c | - |
| A deploy wrote back the managed config it had read at plan time, undoing a concurrent undeploy and dropping concurrent deploys' stanzas | RU6a RED | 463345c | `ru6a_concurrent_deploys_keep_every_stanza` |
| A bare `Host` or `Match` line leaked its settings into the previous block (after `Host *`, into every host); keyword splitting on Unicode whitespace differed from OpenSSH | RU4 review; RU6a RED with real `ssh -G`; RU6a security review | 463345c | - |
| A .ppk with no Private-MAC imported | RU6a RED | 463345c | - |
| `sanitize_remote_name` was not idempotent: a name ending in an ideographic space was refused on a second pass (checked over every name of up to four characters from an 18-character alphabet, 111,150 names, plus 20,000 pseudo-random names of up to 16 characters) | RU6a code review | 463345c | - |
| `notify` 7 reports an overflow as an event with the Rescan flag, not as an error, so a save lost to an overflow was skipped silently | RU6a | 463345c | - |
| The periodic edit-sync check retried a failing save forever and piled up temp copies | RU6a code re-review (Important) | 463345c | - |
| A keyboard-interactive test with a 400 ms deadline flaked under CPU load | RU5; RU6a RED (5 of 6 runs failed under contention) | 463345c (0 of 100 runs fail after) | - |
| Bitwarden sync: the legacy "SSHSpan" folder was renamed after the new one was created (two folders with one name); pulling a non-OpenSSH remote key reported a silent "updated"; pulled keys did not refresh the MD5 fingerprint | RU5 | 863a024 | - |
| Bitwarden notes re-linking could attach a server to an item another local server owned, and a lost-link copy could be imported as a new server | RU5 code reviews, four rounds | 863a024: owned items never re-link; several unowned candidates skip the server with an error | - |
| RU5's own second fix round made settings writes fail at once with `SQLITE_BUSY` under any concurrent write (a deferred `BEGIN` upgrading from read to write) | RU5 code re-review | 863a024 (`BEGIN IMMEDIATE`) | - |

### 6.2 Renderer and test tooling

| Bug | Found by | Fixed in |
|---|---|---|
| A vault lock left a hidden edit-conflict question behind, so every later conflict was queued invisibly and never asked (the lock wedged the conflict queue) | JU6b's first-round re-reviews (High for the code reviewer, Medium for the security reviewer) | d94ed2d: a lock (Ctrl+L, the tray, the idle timer, the backend watchdog) drops every question, and a tab close drops that tab's questions |
| Cancel was not disarmed when the question moved on to the next file, so a double-click dismissed the next file's question | JU6b code re-review | d94ed2d: Cancel, Escape and a backdrop click wait out the same 750 ms as the other answers |
| A double-click on a menu item answered the "Stop editing" question that opened under the pointer, sending a forced close (reproduced) | JW security re-review | 3b0fcfb: a confirmation ignores a click whose `detail` is above 1 |
| A late backend answer could open the "Stop editing" question after a lock | JW security re-review | 3b0fcfb |
| The old folder-drop path queued a download at once and could silently replace a local file | JU6b implementer | d94ed2d: drops onto the local side ask first, like every download |
| The chmod dialog's X was never wired, so it did not close the dialog | JU6b implementer | d94ed2d |
| After three Apply rounds in which Bitwarden's list changed each time, the app said "Sync complete." although nothing had been applied | JW implementer, after its first all-green run | 3b0fcfb: it says nothing was applied and to sync again |
| "Send to" put the remote file name into the sentence raw, so a U+202E reversed the rest of it | JW implementer, after its first all-green run | 3b0fcfb |
| `e.message \|\| String(e)` threw on a null rejection, and an `{ error }` object read "[object Object]"; about 90 hand-made copies of that pattern existed | JW | 3b0fcfb: one `errText`, guarded by `check-renderer-hygiene.js` and `test:polish` |
| A category dropped next to its own loop's promoted root landed last | JW code review (Medium) | 3b0fcfb |
| A name made of U+2800 Braille blanks passed as ".." | JU6b's final security re-review | 3b0fcfb |
| A5-42, server half: a new server created in a filtered list got no category and a plain "Server saved." while the filter hid it | Documentation accuracy review | 6c19b1b |
| After a successful "Allow syncing...", the reload hid the button while it still held the focus, so a keyboard user's focus fell to the page | Fix-wave code re-check, round 1 (Low, probe) | 6c19b1b: the focus moves on to Sync now |
| A busy flag was cleared after the redraw, so Auto-approve stayed disabled | JU3's first GREEN run | d589b51 |
| `check-ipc-args.js` lost parameters after a comment containing a comma, so `clear_api_key` was never checked | JU3's self-check | d589b51 |
| `check-ipc-args.js` treated every `Channel<T>` parameter as injected by Tauri, so `terminal_connect`'s required `onData` had never been checked, and payloads built in a variable were skipped silently | DOC phase A | 11e7e30 |
| `check-ipc-args.js` said "every argument name was checked" while it dropped quoted and computed keys, and it could not see 13 call shapes | DOC phase A re-review; JW security review | 3b0fcfb: every site it cannot read is listed as not checked; the fix wave adds parameter patterns and `catch` bindings |
| The queue's re-layout with `replaceChildren` lost a click held while another job arrived | JU1 self-review | 11abb3e |
| The static `confirm(` scan lost sync on regex literals | Group 1 re-review | 7e5c5c5: a bracket-balance guard catches a scrubber that drifts |
| The chip's x in the New key dialog removed the category from the choice but left the chip on screen; a key list rebuilt from the Servers view was filtered by a server category | JU4, in passing | 652aa5e |
| A move into a restored category loop froze the app (the backend's ancestor walk was unbounded and synchronous) | JU4 re-review (Important) | 652aa5e (renderer refusal); cd11f97 (backend bound) |
| The terminal's deferred focus (50 ms after a connect, 60 ms after a tab switch) took focus from controls the user had just reached; the old `terminal.js` failed 5 of 20 runs | JU4 first fix round traced an intermittent `test:polish` failure to it; JU5 | d5e9d22 (72 of 72 runs passed without the harness's timer barrier) |
| The harness failed with "Cannot fast-forward to the past" under load (2 of 16 runs), and some slow boots exceeded the step timeout | JU5 second fix round | d5e9d22 |
| At 880x560, with the note about paused transfers showing, the transfer list had no room for a job: with Linux fonts the panel's head wrapped and the note left the list 0 px; with Windows fonts the list was 24.7 px, under one 28 px row; in Split about 4 px on every platform, with the buttons under the note. The layout check passed on Windows only because the first button's centre still fell inside the list once it was scrolled to | The pull request's first CI run (the renderer job, on Linux) | The pull request follow-up: the note joins the panel's head, the list keeps one row whatever the fonts, and the resize handle offers only heights that take effect; a test-only larger-text variant reproduces the CI failure on any machine (section 3.2) |

### 6.3 Documentation

The documentation accuracy review (Opus) checked the uncommitted documents against the code at 3b0fcfb. It split the documents across parallel read-only fact-checkers and verified their significant findings in the code itself. It recorded about 140 corrections: roughly 75 Wrong, 8 Stale, 30 Missing and 30 Style. All were applied in the last documentation passes (217 tracked lines: 209 as worded, 8 reworded, none declined). The ones that mattered most:
- **Two index statuses were wrong.** A5-26 and A5-42 were marked Fixed with only one half done. The controller had both halves finished in the fix wave rather than downgrade the rows to Partial.
- A1-26 contradicted the index's own claim that the final waves changed no status: the SFTP menus took the keyboard only in 3b0fcfb.
- Wrong test counts in the CHANGELOG (835 library tests should have been 837; `test:ui` is 76 at 3b0fcfb, not 75), and two wrong line counts in ARCHITECTURE.
- Wrong security behaviour, repeated across several documents: an unlock during a password change is refused, not made to wait; the tray's Lock and Quit do not ask; the download resume check; the MCP `*.localhost` rule; who wraps MCP results; how audit failures are reported.
- "1.x vaults" for the Electron app (1.2.0 and earlier), although 1.3.6 to 1.9.1 are the Rust app, so current users would have read it as their own vault.

In passing it found four code issues:
- the Argon2id memory unit (fixed in the fix wave; section 6.1);
- `release.yml` ran the Windows `cargo test` without the Common-Controls 6 manifest step the test executables need (added by the documentation commit; not yet run at a tag);
- a system proxy bypasses the Bitwarden connect-time address check (documented as an accepted risk);
- the hygiene check misses "(Task N)" comments, and `test:ui` ignores `SSHSPAN_RENDERER_DIR` (documented).

### 6.4 Audit statements the units corrected

- A7-57: the audit's `a:b` and `a_b` example is not a collision (`a:b` reads as a drive-letter pattern); the real collision is `back:up` and `back_up` (dc09f93, 463345c).
- A8-21: `cdp-e2e-2.js` and `cdp-featurepass.js` were not broken the way the audit says. They were deleted anyway, because they act on whatever app instance they attach to, with hard-coded throwaway secrets (11e7e30).

### 6.5 Where tests were not seen failing first

The plan requires a RED run before each fix. These are the recorded exceptions:
- **Written with their code and never seen failing:** in RU5's first fix round, the tests of the sync marks of pulled new keys and servers, of linked items outside the sync folder or owned by an organisation, of a pull racing a local change, of the server link found through an item's notes, of the counts of a stopped run, of the deleted-items count, of undecryptable server fields, and of the mapping of a declined UAC prompt to "cancelled"; RU6b's four tests of its new exit-wait and category-chain helpers, written with them. In RU3's first fix round the HostName, User and alias-pattern checks were written with their code, with a real `ssh -G` run as their RED, and one test (`a_foreign_public_key_file_is_refused_too`) was written before the code but run after it.
- **Passing before and after by design** (characterisation and guard tests): RU6a's test-only item; RU4's six passing RED tests; JU5's A3-11 guards; RW's tests that an edit within one account keeps its password; RW's pure-layout tests for the program folders; RW's test of the rotation lock on a blocking-pool thread (coverage was asked for, not a fix); RU6b's five guard tests; JU6b's host-category filter test, which the reviewer's mutant proves; the fix wave's pure-helper test behind the key-file advice, `fw_r10_a_key_file_protected_by_a_passphrase_is_recognised` (the tests of its two call sites were the RED); the fix wave's renderer checks that pin what must not change (a save with no warning, a "no" that keeps the focus on its button).
- **Proved by a mutation instead of a RED run:** RU6b's size-check test for servers without file types; RU6b's two transaction busy tests; RW round 5's per-page check, which already existed since round 4; the fix wave's test that a saved Bitwarden destination is never taken for one from before (`fw_r1_a_saved_destination_is_never_taken_for_one_from_before`), added after its first RED run; the three hardening cases the fix wave added after its first GREEN run, and the two tests it added after its second.
- **Windows-only tests** (RU6a's first fix round, RW's personal-folder test) compile on `windows-gnu` and were not executed.
- **No test, by nature:** comment-only and test-only changes (RW's comment sweep; the fix wave's doc comments, its two removed assertions, its dialog comments and the two test stubs it brought up to date). JW's conversion of the SFTP menus has no mutant of its own: it was all or nothing, and RED showed the old builders failing every check.

## 7. Rulings, deferrals, accepted limitations and residual risks

### 7.1 Rulings that shaped the result

R1 to R12 are in section 2.2. These are the controller's own rulings, each with its reason and what it costs if it is wrong:

- **Commits stay local.** Nothing is pushed, and no pull request or release is created without the user. (The user later asked for the pull request, #85.) "Fix on a new branch" implies commits on that branch; the cost if wrong is discarding a branch.
- **Sequential work on one branch, with controller-side commits.** One tree is robust to the controller changing mode. The cost is wall-clock time, with no merge debt. Two lanes, one Rust and one renderer, ran together only where their files were disjoint.
- **Deploy keeps writing SSHSpan's managed config** (R3) instead of editing `~/.ssh/config`, because `ssh_config_write` was de-registered for ProxyCommand injection. The cost is one manual `Include` step.
- **Auto-lock activity is human input,** not remote output. The lock still ends live sessions, warns 60 seconds ahead and asks first on a manual lock with live work. The cost: a long unattended job is still cut at the idle timeout.
- **`settings_set` is lock-gated only for four keys** (`autoLockMinutes`, `confirmDelete`, `autoUpdateCheck`, `confirmMultiLinePaste`). Settings is reachable while locked, and gating every preference would make it read-only for no security gain.
- **Duplicate key names are refused only for new** create, import and rename; existing duplicates stay readable, so existing vaults do not break.
- **MCP `expected_hash` is required for every enable,** first approvals included, because a first approval must be bound to the definition shown. Cost: enabling MCP tools from the UI failed between d33028d and d589b51.
- **57993ba was committed although it de-registered backup commands the renderer still called,** so Backup and Restore were broken until c227218. Reason: the unit boundary. Cost: a commit that cannot be bisected on a fix branch.
- **RU5 was committed after four fix rounds, not a fifth.** The open minor was an error text in a rare lost-link case, and RU6a was blocked on RU5's files; the text was fixed in RU6b.
- **The deferred Rust minors ran as RU6a and RU6b** before the final review, so the Rust lane did not sit idle.
- **Released CHANGELOG sections** get typo and format fixes in place; factual corrections are annotated "(Correction 2026-10-09: ...)".
- **DOC phase A committed scripts and the `release.yml` comment only;** CHANGELOG.md and `docs/REWRITE-ROADMAP.md` point at the rewritten SECURITY.md, so they wait for the documentation commit.
- **When Fable became unavailable, the remaining review roles ran on Opus,** using reviewer types that cannot spawn further agents. The user's rules allow Opus for any role, and Fable had only ever been optional for review. Cost: none for quality, since Opus had already reviewed most units.
- **Work started early on disjoint files to shorten the tail:** RU6b in two phases before RU6a's commit, JW's first phase before JU6b's commit, and the documentation passes with marked placeholders. Cost: occasional build interference, and a delta pass on marked text.
- **RW stayed uncommitted until JW was ready, and the two were committed back to back,** because RW alone breaks three renderer flows. Cost: none.
- **RW got a sixth fix round, one more than the workflow allowed, and RW and JW waited for it,** because nothing would be committed with a hanging test. Cost: about an hour, used to run the pass-2 reviews on a frozen snapshot.
- **JU6b's last Low (names made of U+2800) went to JW** instead of a third JU6b round; the gap existed only between two adjacent, unpushed commits.
- **The fix wave lands as its own commit after RW and JW,** so the reviewed units stay exactly as reviewed. Cost: one extra commit.
- **The pass-2 security review's High was fixed at once,** with the same native-question design as MCP. Cost: one more native question during Bitwarden setup.
- **A5-26 and A5-42 were finished in the fix wave** rather than downgraded to Partial, and the Argon2id unit was checked against the official vectors before any code changed.
- **The fix wave's own re-check findings were fixed in the same wave,** in four more rounds, not deferred.
- **A path picked in a save dialog gets the same deny-list as a typed path.** This reverses the earlier ruling that picks skip most of the list, because a pick could still replace settings that run commands. Cost: a deliberate save of such a dotfile through SSHSpan is refused; it can be saved elsewhere and moved.
- **The 30-second back-off lives in the shared question machinery,** so the MCP and assistant questions have it as well as Bitwarden's, and it is per kind of question: after any "no", no question of that kind is asked for 30 seconds, whatever it names. It got there in two steps. When the two re-checks differed between keying on the exact destination and on the host, the controller first chose the host, because path variants defeat the back-off's purpose. When the security re-check then showed that host keying cannot stop a fresh question per made-up host, it ruled for one back-off per kind. Cost: a user who declines one server by mistake waits up to 30 seconds before being asked about another of the same kind.
- **At most two Bitwarden key derivations run at once,** with a busy refusal after 30 seconds, because with the memory setting read in the right unit a derivation can use up to 1 GiB, and Test connection could start any number of them.
- **On Windows, key files are read only from this computer's drives,** mapped drives included. Cost: a key on a raw UNC path needs a mapped drive.
- **The private-key and backup exports get the write deny-list, except `~/.ssh`,** because exporting a private key into `~/.ssh` is a legitimate workflow, and both files are SSHSpan's own.
- **Windows shares stay reachable as SFTP local paths and "open external" targets.** Refusing them in the local pane would block users who browse a NAS by its UNC path, so this stays under the accepted A6-02 residual (section 7.3). Key files no longer allow it.
- **Rounds 4 and 5 mutation-checked only their new and changed guards** (32 and 10 mutations); the others stand from round 3's full run.
- **A nit older than the branch, found by the last re-check, was still fixed before the fix-wave commit,** in a small fifth round that the controller checked itself, because the user asked for every flaw to be fixed.
- **`server_save`'s rejection texts are not spelled out.** The security re-check accepted this: they carry only what the user typed.
- **The Windows CI job is `continue-on-error`** until it has passed once on a runner: it had never run when this was decided, and several tests assumed Unix paths. Its first run, on the pull request, failed five such tests, which the follow-up commit fixes (section 8.4). Cost: a Windows regression does not fail CI until the flag is removed.
- **Coverage is reported as measured,** with no exclusion hidden in the headline figures, and a follow-up is recommended for the command code. Cost: the 80% rule stays unmet for Rust production code, and this report says so.
- **After the C: drive filled, cargo uses only two shared target directories** (section 2.6).

### 7.2 Deferrals

- **A7-03 (Partial), R9:** importers for PKCS#1, PKCS#8, SPKI and authorized_keys. New crypto parsers need their own design and review.
- **A7-54 (Deferred) and A7-55 (Partial), R10:** the full queue state-machine suite and the mock-server `run_sync` suite. Targeted tests were added with each fix instead.
- **A7-58, R10:** a legacy Electron vault importer. Vaults from the Electron app (1.2.0 and earlier) are not migrated; keys are exported and re-imported. The documentation is corrected, so the row is Fixed.
- **A1-29 (Partial), R10:** the wholesale CSS token refactor; dead and duplicate rules were removed (53347df, d5e9d22).
- **A5-22 (Partial), R10:** updater download progress events. The dialog, the busy state and the notice landed without a progress bar (d5e9d22).
- **A5-28 (Partial):** an Edit button in the terminal header. The unit brief narrowed the finding to the row "..." button.
- **A7-56 (Partial):** the Windows CI job exists in the documentation commit but has not passed on a runner yet (its first run failed five tests, fixed in the follow-up commit; section 8.4); a Windows test executable needs a Common-Controls 6 manifest beside it, which the job writes; one cross-built with the MinGW target also needs `WebView2Loader.dll`, while the MSVC build the runner uses links the loader statically.
- **A6-02 (Partial):** a grant model for local paths, which needs dialog-picked destinations and upload sources (section 7.3).
- **Command code that tests can reach:** making the Tauri commands generic over `tauri::Runtime`, so Tauri's `MockRuntime` can test them (section 8.9).
- **A persistent terminal debug-trace setting.** It needs a key in the Rust `settings_set` allowlist; today it is a developer-tools page flag.
- **Module splits.** At 6c19b1b these files are past the 800-line soft ceiling (`git show 6c19b1b:<path> | wc -l`): `commands/sftp.rs` 13,160 lines, `commands/mod.rs` 9,614, `assistant/mcp.rs` 9,375, `app.js` 8,448, `db/mod.rs` 5,917, `sftp.js` 5,439, `bitwarden/sync.rs` 5,277, `sftp/queue.rs` 3,853, `assistant/mod.rs` 3,267, `styles.css` 3,102, `ssh_client/mod.rs` 2,263, `ssh/mod.rs` 2,141, `commands/updater.rs` 2,081, `bitwarden/mod.rs` 2,046, `config/mod.rs` 1,740, `assistant.js` 1,689, `sftp/mod.rs` 1,464, `crypto/keys.rs` 1,207, `index.html` 1,143, `commands/server.rs` 1,106, `crypto/putty.rs` 1,089, `mcp.js` 1,038 and `terminal.js` 965. Splitting them was kept out of these units for reviewability; [Large files and deferred splits](../../ARCHITECTURE.md#large-files-and-deferred-splits) in `docs/ARCHITECTURE.md` names where to cut the largest ones.
- **Servers that report no file types:** a stricter "not a link" rule (trusting only a `READLINK` that says so) was evaluated and not adopted, because it breaks saves on servers without `READLINK`; reading a sample back after the upload needs the queue's callers.
- **MCP tools of a server that is not confirmed** are still offered to the model; the renderer could skip them (section 7.3).
- **Smaller items:** a way to choose between several Bitwarden copies of one server (today the user deletes the extras in Bitwarden; deletions are never propagated, by design); `ensure_category_path_scoped` is not transactional (a concurrent duplicate fails on the primary key; no data is lost); the focus drops to the page after the MCP form saves; a bookmark can be removed only by right-clicking it; the hygiene check does not catch "(Task N)" comments.

### 7.3 Accepted limitations

These are known, deliberate states. `docs/SECURITY.md` ("Accepted risks and limitations") carries the security-relevant ones in full.

- **Renderer-attested approvals gate actions only.** A compromised renderer can claim that a human clicked Approve for an AI command, an MCP tool call or an update. Destinations for secrets are bound in Rust instead (section 5.3).
- **The local-path boundary is a deny-list (A6-02).** Anything the list does not name stays reachable from a compromised renderer, whether a path is typed or picked in a dialog. The list also refuses a deliberate save of a protected dotfile, such as `.gitconfig`, through SSHSpan; such a file can be saved elsewhere and moved. On Windows, SFTP local paths and "open external" targets that a compromised page gives as a network share can still make Windows sign in to that share when the path is checked: refusing shares in the local pane would block users who browse a NAS by its UNC path. Key files are no longer affected.
- **The SSH library keeps a password copy (A6-11).** russh 0.63 builds its authentication packets in a cleartext buffer it clears without wiping, and frees keyboard-interactive answers unwiped. This cannot be fixed without an upstream change.
- **Memory.** While the vault is unlocked, the master password and the key material an operation needs are in process memory.
- **The verified installer is re-opened by path** from the user's temp folder, so code running as the same user could swap it in that window; UAC is not a boundary against same-user code.
- **MCP.**
  - The tools of a server that is not confirmed are still offered to the model. The backend refuses every call, so the cost is an approval card that cannot lead anywhere.
  - The `-32601` answers to a server's own requests inside an open response (at most eight per response, each checked against the vault generation and sent within the same exchange) and session DELETEs are not checked against the stored record.
  - A request already sent is not recalled; a revoke that commits while `tools/call` is on the wire cannot stop that call.
  - When more than 16 session teardowns are pending at once (a lock with many sessions), the rest are not sent, and those sessions expire on their servers.
  - Tool arguments get no backend disguising-character check; the approval card's escaping is the control.
  - `definition_changed` clears if a server reverts to the approved definition, but the tool stays disabled, so this fails closed. Notifications after a response are dropped. The name `localhost` relies on the resolver to stay on the loopback interface (MCP accepts only that exact name; the AI provider also accepts `*.localhost`, with the same reliance).
- **Edit sync.**
  - The conflict check compares size and modification time in whole seconds (or, on servers that report neither, the content up to 16 MiB), so a same-size change within the same second is not noticed. One round trip separates the check from the upload, because SFTP v3 has no conditional write.
  - It needs write permission on the folder and replaces the file, so ownership, ACLs and hard links are not kept.
- **Edit sessions end with their tab, session or lock.** Closing the tab, the end of its session (a disconnect or a dropped connection), or locking the vault ends every edit of that session at once (a lock ends every session's), saves that did not reach the server included: the session is going away, so nothing could be uploaded any more. The lock deletes the staged copies best-effort (a plain delete, not an overwrite). A save that lands while the "Stop editing" check reads the copy, or between that check and the delete, is lost, the same race as the check-then-upload of a save, and an Edit that took the edit in the instant before the stop set its mark is not caught.
- **A resumed `.part` keeps a deterministic name,** which resuming across restarts needs, so a check-then-use window remains on a shared, writable remote folder.
- **Servers that report no file types.** Fooling the "not a link" checks takes a server that answers several probes wrongly on purpose.
- **Bitwarden.**
  - Test connection needs an unlocked vault, deletions are never propagated, and an older copy of a server is reported on every sync until the user deletes it in Bitwarden.
  - Category marks are kept on this machine only and are not in backups, so a restore does not carry a pending category upload.
  - A system proxy bypasses the connect-time address check: the proxy resolves the vault's host name, so the guarded resolver never sees it. The check when the URL is saved or tested still runs.
  - Going back to the destination that is still the allowed one asks nothing, by design; only the last destination allowed is kept, so returning to an earlier one after allowing another asks again. A "no" given through "Allow syncing..." while a master-password change holds its lock is logged, not written.
  - Settings saved before the upgrade keep syncing: a one-time migration at the first start counts their destination as allowed, even if a hostile page had saved them. The security re-check accepted this, because the old version would have uploaded to them anyway.
  - Settings saved before the fix wave's second round with an account the new rule refuses keep working; the question and the refusal quote such an account cleaned and capped.
  - A sign-in that finds no free key derivation within 30 seconds fails with the busy text. A derivation that has started cannot be cancelled; its slot frees when it ends.
- **Native credential questions on Linux.** The one-second minimum is measured from the moment the dialog is requested on the main thread. GTK creates the dialog from an idle callback, so a flooded main loop can use up part of that second before the dialog is visible. GTK also sets no default button; on Windows and macOS a stray Enter answers "Don't allow".
- **The 30-second back-off** after "Don't allow" or "Cancel" is kept in memory, so a restart forgets it. It is per kind of question, so after a "no" every question of that kind waits, for another server or account too; the answer names the host that was declined and says to wait.
- **`server_save`'s rejection texts** carry names the user typed and are shown as plain text, not spelled out. The security re-check accepted this, since no server supplies them.
- **A database call from the root future of a current-thread runtime** still panics, as before; the app runs Tauri's multi-thread runtime.
- **Connect** uses one 20-second budget across the addresses it tries in turn, and has no deadline after authentication.
- **Key files.** On Windows only this computer's drives are read, mapped drives included, so a key on a raw UNC path needs a mapped drive; a verbatim path written with forward slashes (`\\?\C:/...`) is refused too. The Windows rule is tested on every platform through its pure function, and the library tests have since run natively on Windows too (section 8.4); no key file on a real network share was tried. Elsewhere, `//path` is another spelling of `/path`; such a key path gets no warning at save, and the connect still says what to do.
- **Webviews, platform and dependencies.** The terminal header uses container queries and wraps on an older WebKitGTK; held-key and chord handling was tested in Chromium with a US layout; key rows, category rows and session tabs are `role=button` elements with interactive children, which an accessibility scan flags. There is no hardware-backed key storage, and suspend does not lock the vault. Several transitive Rust crates are flagged unmaintained-class by advisory tooling, with no known exploitable issue in SSHSpan's use.

### 7.4 Residual risks and what no suite exercised

- **Not the shipping webviews.** The renderer suites run in headless Chromium only. WebView2 and WebKitGTK rendering, the native dialogs, the tray, real SSH, SFTP, Bitwarden and MCP servers, and screen readers were not exercised.
- **Windows.** Until the pull request, Windows code ran natively only for RU1's secret-file tests; the `windows-gnu` check executes nothing. Since then the library tests have run natively on the `windows-latest` runner, and the library and integration tests on Windows 11 from a cross-build (section 8.4). Still not exercised for real on Windows: the `ShellExecuteExW` installer path, a real sharing violation, a key file on a network share and Win32-OpenSSH (emulated in the test kit). The new `windows-latest` CI job has not passed on a runner yet, and `release.yml`'s Windows tests, with the new manifest step, run only at a tag and have not run since that step was added.
- **Drag and drop is emulated.** The suites withhold the HTML5 drag events WebView2 withholds and drive a real mouse; no real WebView2 drag was run.
- **Native dialogs.** The credential questions are tested through injected answers and the answer mapping; they were never shown in a real dialog, GTK included (the reviewers' offscreen GTK probes covered the save dialogs only).
- **Runtime-bound code.** The exit-time MCP DELETE wait, the tray hide and `app_quit` need a Tauri runtime. A manual check on Windows is still wanted: quit with a connected MCP server and see the session DELETE arrive.
- **Static checks have limits.** `check-ipc-args.js` reads text, not syntax, and lists what it cannot read as not checked. The global `unhandledrejection` handler only logs.
- **Bisecting.** 57993ba and d33028d leave the renderer partly broken until c227218 and d589b51, and 03dfa92 alone breaks three renderer flows until 3b0fcfb, so bisecting inside those ranges is unreliable.
- **Test-first gaps** are listed in section 6.5. Rust production coverage is below 80% (section 8.9).

## 8. Verification evidence

### 8.1 Rust tests per unit (WSL Ubuntu-25.10, rustc 1.98.0)

| Commit | Unit | Library | Integration | MCP integration | How the count was obtained |
|---|---|---:|---:|---:|---|
| 1ca864f | base (`main`) | 216 | 45 | 11 | The baseline Task 10 stated |
| dc09f93 | Task 10 | 316 | 45 | 11 | Controller in WSL: fmt, clippy and tests exit 0 |
| 57993ba | RU1 | 363 | 47 | 11 | Controller in WSL: fmt, clippy, test and the `windows-gnu` check exit 0 |
| d33028d | RU2 | 447 (a) | 47 | 20 | Implementer, shared tree; the assistant tests alone 81 |
| 46a9d1b | RU3 | 458 | 48 | 20 | Implementer, shared tree; fmt, clippy and `windows-gnu` exit 0 |
| 5e77b54 | RU4 | 533 (b) | 48 | 20 | Implementer, shared tree |
| 863a024 | RU5 | 579 | 48 | 20 | Controller, isolated tree (652aa5e plus the unit's diff): fmt, clippy, test and `windows-gnu` pass |
| 463345c | RU6a | 680 | 48 | 20 | Controller, isolated tree (863a024 plus the unit's diff): the same four |
| d5e9d22 | JU5 | 680 | 48 | 20 | No file under `src-tauri` changed since 463345c |
| cd11f97 | RU6b | 740 | 48 | 20 | Controller, isolated tree (d5e9d22 plus the reviewed diff): the same four |
| d94ed2d | JU6b | 740 | 48 | 20 | No file under `src-tauri` changed |
| 03dfa92 | RW | 837 | 48 | 20 | Controller, full `cargo test` on the worktree with `src-tauri` equal to HEAD plus the reviewed diff: fmt clean, exit 0, no hang; clippy and `windows-gnu` from the implementer's acceptance |
| 3b0fcfb | JW | 837 | 48 | 20 | No file under `src-tauri` changed |
| fix wave, round 1 | FW | 856 | 48 | 20 | Implementer's acceptance: fmt, clippy, test and `windows-gnu`, all exit 0 |
| fix wave, round 2 | FW | 871 | 48 | 20 | Controller, on the worktree with `src-tauri` equal to HEAD plus the round-2 diff: fmt clean, clippy (`-D clippy::correctness`) exit 0, test exit 0 with no hang, `windows-gnu` exit 0 |
| fix wave, round 3 | FW | 878 | 48 | 20 | Controller: fmt clean, clippy exit 0, test exit 0, `windows-gnu` exit 0 |
| fix wave, round 4 | FW | 880 | 48 | 20 | Controller: fmt clean, clippy exit 0, test exit 0, `windows-gnu` exit 0 |
| 6c19b1b | FW, after round 5 | 882 | 48 | 20 | Controller, on the worktree with `src-tauri` equal to HEAD plus the round-5 diff: fmt clean, clippy (`-D clippy::correctness`) exit 0, test exit 0, `windows-gnu` exit 0 |
| the pull request follow-up | PR | 884 | 48 | 20 | Controller, on the worktree with the follow-up's `src-tauri`: `cargo audit` exit 0, fmt clean, clippy (`-D clippy::correctness`) exit 0, test exit 0, `windows-gnu` exit 0; natively on Windows 11, library 740 of 742, integration 47 of 47, MCP 20 of 20 (section 8.4) |

(a) The run in the shared tree included RU3 work in progress. (b) The shared tree included RU5 work in progress; the commit message states the same totals.

Growth: 272 Rust tests at the base, 905 at 3b0fcfb (+633) and 950 at 6c19b1b (+45). These counts are Linux runs; until the pull request only RU1's 22 targeted tests had run natively on Windows (section 8.4). The pull request follow-up adds two tests: 952 (884, 48, 20). The `windows-gnu` check passed at every Rust verification, with two warnings in Windows-only test code in `sftp/mod.rs`.

### 8.2 Renderer suites per unit (checks passed, 0 FAIL in every run)

| Commit | Unit | `test:ui` | `test:safety` | `test:sftp` | `test:polish` | `test:assistant` | `test:keys` | `test:servers` | Total |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 1ca864f | base | 76 | | | | | | | 76 |
| 7e5c5c5 | Group 1 | 76 | 332 | | | | | | 408 |
| 11abb3e | JU1 | 76 | 332 | 230 | | | | | 638 |
| c227218 | JU2 | 76 | 464 | 230 | | | | | 770 |
| 53347df | JU6a | 76 | 471 | 231 | 190 | | | | 968 |
| d589b51 | JU3 | 76 | 471 | 231 | 190 | 312 | | | 1,280 |
| 652aa5e | JU4 | 76 | 470 | 231 | 190 | 312 | 278 | | 1,557 |
| d5e9d22 | JU5 | 76 | 471 | 232 | 190 | 312 | 278 | 480 | 2,039 |
| d94ed2d | JU6b | 76 | 481 (c) | 598 | 190 | 312 | 324 | 511 | 2,492 |
| 3b0fcfb | JW | 76 | 491 | 679 | 195 | 367 | 422 | 580 | 2,810 |
| fix wave, round 1 | FW | 75 (d) | 491 | 693 | 195 | 367 | 422 | 635 | 2,878 |
| 6c19b1b | FW, final | 76 | 491 | 700 | 195 | 367 | 431 | 676 | 2,936 |
| the documentation commit | Docs | 75 (d) | 491 | 700 | 195 | 367 | 431 | 676 | 2,935 |
| the pull request follow-up | PR | 75 | 491 | 763 | 195 | 367 | 431 | 676 | 2,998 |

Up to d5e9d22 the counts come from the unit reports and, for JU4 and JU5, also from the controller's logs, which agree with them. d94ed2d and 3b0fcfb are the controller's runs on clean copies. The final fix-wave row is the controller's clean-copy run of the fix wave's round-2 renderer: its later rounds changed only two test stubs, and the two suites those feed counted the same afterwards. The committed code was run as well: on a clean copy of 6c19b1b the seven suites count 76, 491, 700, 195, 367, 431 and 676 (2,936), in the coverage run of section 8.9 and again in a final review of the documents, and that review counted 75 for `test:ui` with the documentation commit's script (2,935). The documentation row is the documentation pass's run of a snapshot that carries the fix wave and the documentation commit. Round 1 is the implementer's acceptance run. The pull request row is the controller's run on a clean copy of the documentation commit plus the follow-up, and the seven suites also passed on Linux in WSL, with the Chromium and fonts CI uses. Only `test:ui` existed at the base.

(c) The first `test:safety` run lost one scenario to a 20 s page-load timeout with the CPU at 100%; the re-run passed.

(d) With the documentation commit's `scripts/check-renderer-ui.js`, which drops its embedded copy of the MCP contract check (76 to 75 checks); `check-mcp-contract.js` runs that check, in CI as its own step. The implementer's round-1 run already had that script; the controller's clean copies of the fix wave do not, so they count 76.

### 8.3 Static checks

| Tree | `node --check` | Globals | `check-ipc-args.js` | Vendor | MCP contract | Hygiene |
|---|---|---|---|---|---|---|
| d5e9d22 | 20 files | 1,767 names, no undefined calls or duplicates | 148 call sites against 118 commands (108 registered) | 4 of 4 | pass (16 checks) | - |
| d94ed2d | 20 files | 1,899 names | 139 call sites against 118 commands (108 registered) | 4 of 4 | pass | - |
| 3b0fcfb | 21 files | 1,947 names | 146 call sites against 109 commands (109 registered), every site read | 4 of 4 | pass | 4,185 comments in 8 files; 10 removals and 3 code rules |
| fix wave, round 1 | 21 files | 1,956 names | 147 call sites against 110 commands (110 registered), every site read | 4 of 4 | pass | 4,230 comments |
| fix wave, from round 2 | 21 files | 1,960 names | 147 call sites against 110 commands (110 registered), every site read | 4 of 4 | pass | 4,252 comments; 10 removals and 3 code rules |

The command count fell from 118 to 109 because RW deleted ten unregistered command bodies and added `category_set_order`; the fix wave adds `bitwarden_allow_sync`. The five static checks passed again with the Rust diffs of the fix wave's rounds 3 and 4.

### 8.4 Windows

- Native execution: until the pull request, RU1's secret-file tests only. The ACL test went RED to GREEN on Windows 11, and 22 targeted tests passed natively on the final RU1 tree.
- Everything else Windows-specific was type-checked with `cargo check --target x86_64-pc-windows-gnu --all-targets` and not executed.
- The documentation commit adds a `windows-latest` CI job (`cargo test` and the static renderer checks, with the Common-Controls 6 manifest step), `continue-on-error` until it has passed once. The documentation accuracy review ran that job's five static renderer checks on Windows at 3b0fcfb, and they passed.
- **The job's first run, on the pull request (2026-10-17).** The static renderer checks passed. `cargo test` ran the library natively: 736 passed and 5 failed, so the integration suites did not run. None of the five was a product bug:
  - Three numbering tests (`case_only_collisions_are_renamed_on_every_platform`, `colliding_sanitized_names_get_a_numbered_local_name`, `numbering_keeps_the_extension_and_handles_dotfiles_and_taken_numbers`) spelled their paths with `/`. A real download batch on Windows is spelled with `\` throughout, and the renamed path came back as `/d\readme (1)`.
  - `rw_fix1_a_dialog_picked_download_never_writes_the_program_files` used a `/fixture` base with no drive letter, which is refused as not absolute before the program-folder rule under test is reached.
  - `write_secret_file_leaves_one_full_control_ace_for_the_current_user` expected exactly one entry. The product's one `icacls <file> /inheritance:r /grant:r` call removes every inherited entry and gives the current user full control. Where the folder passes no permissions down, as the runner's temp folder did, the new file's entries come from the creating process's defaults instead, and SYSTEM and Administrators keep full control beside the user. OpenSSH for Windows accepts both on a private key.
- **The fix, in the follow-up commit** (test code and comments only):
  - The numbering tests build their paths the way a batch does, from a platform folder with `Path::join`, and still compare exact strings.
  - The program-folder test uses `C:\fixture` on Windows.
  - The ACL test keeps its name, which the index cites, and no longer depends on the machine's temp folder. It sets up two folders and writes a secret file into each. In one that passes permissions down (`icacls <dir> /inheritance:r /grant:r *<SID>:(OI)(CI)F`), the file must end with exactly one entry, the user's full control, explicit, with inheritance blocked. In one that passes none down (`/grant:r *<SID>:F`, the runner's shape), it requires blocked inheritance, nothing inherited, allow entries only, full control for the current user, and no entry for anyone but the user, SYSTEM and Administrators. Entries are judged by SID from `icacls /save`, so localized account names do not matter.
  - Two cross-platform table tests pin both rules: `secret_acl_rule_in_an_inheriting_folder_admits_only_the_user` and `secret_acl_rule_admits_only_the_user_system_and_administrators`. They refuse Users, Everyone, Authenticated Users and any other account, and the first also refuses SYSTEM or Administrators beside the user.
  - Every changed test was mutation-checked on Linux and natively on Windows. Among the mutations: an explicit extra Administrators grant (it fails the folder that passes permissions down), no `/inheritance:r`, read-only access for the user, and a Users entry. The comments and documents that said a key file on Windows is restricted to the current user now say what happens.
  - The tightening of the ACL test came from the follow-up's security review (section 3.2); the native runs below predate it, and the ACL tests passed natively again after it, in both folders and with the temp folder in either state.
- **Native runs after the fix.** The test executables were cross-built in WSL (`x86_64-pc-windows-gnu`) and run on Windows 11 as a user without elevation, with `WebView2Loader.dll` and the Common-Controls 6 manifest:
  - library: 740 of 742; the other two read source files through `env!("CARGO_MANIFEST_DIR")`, which the cross-build bakes in as a WSL path, and both passed on the runner;
  - integration: 47 of 47 (the 48th is `#[cfg(unix)]`);
  - MCP integration: 20 of 20.

  All five failures were first reproduced natively, the ACL one in a folder that passes no permissions down.
- **One latent fragility, left as it is.** `dedupe_local_targets` compares lowercased path strings, so one path spelled with mixed separators would count as two. Its only caller passes paths spelled one way, so this cannot happen today.

### 8.5 RED evidence

Each new or extended renderer suite was first run against the renderer as it was before the unit:

| Suite | Result against the renderer before the unit |
|---|---|
| `test:safety` (Group 1) | 134 ok / 148 FAIL; fix 1: 327 ok / 5 FAIL |
| `test:sftp` (JU1) | 65 ok / 121 FAIL |
| `test:safety` additions (JU2) | 80 FAIL |
| `test:polish` (JU6a) | 149 FAIL lines over 18 runs |
| `test:assistant` (JU3) | 74 ok / 134 FAIL; fix 1: 255 ok / 29 FAIL |
| `test:keys` (JU4) | 112 FAIL on the first run |
| `test:servers` (JU5) | 124 ok / 180 FAIL |
| `test:sftp` JU6b scenarios (JU6b) | 41 ok / 91 FAIL on the d5e9d22 renderer; fix 1: 223 ok / 35 FAIL; fix 2: 38 ok / 42 FAIL in that round's scenarios |
| `test:assistant` (JW) | 324 ok / 21 FAIL with JW's new checks on the renderer before JW; every JW item, including the two late fixes, was written RED first |
| Fix wave, renderer, round 1 | RED per item, with the backend stubs following the Rust contract exactly |
| Fix wave, renderer, round 2 | The save-time warning: 4 checks failing in `test:servers` and 2 in `test:keys`. The spelled-out backend texts: every check failing. The focus after "Allow syncing...": 3 of 6 failing; the other 3 pin what must not change |

For Rust, the first failing runs recorded were:
- RU1: 15 of 16 targeted tests; RU2: 23 unit and 6 integration tests; RU3: 15 of 18; RU4: 37 of 43; RU6a: 34 of 37 in the first batch.
- RU6b: 35 tests in round 0 and 13 in the fix round.
- RW: RED batches in every round, from five batches in round 0 to the reproduced hang in round 6. Where a new seam was needed to compile, it kept the old behaviour, and none of those stubs is left.
- Fix wave, round 1: 6 of 6 tests for the Bitwarden destination (a seventh, added after that run, was proved by a mutation); 7 of 8 in the batch for the next six items (the eighth, RW's adjusted save-dialog test, passes before and after by design); 3 of 4 for the Argon2id unit and the key-file advice (the fourth tests a pure helper).
- Fix wave, round 2: 1 of 7 in the text-export batch (the new test; the others pass by design), then 17 of 27 in the main batch, among them earlier tests whose expected texts or outcomes changed. The two tests written after GREEN were turned red by the mutation of their guard.
- Fix wave, rounds 3, 4 and 5: 7, 9 and 2 tests failing first.

### 8.6 Mutation and probe evidence

A mutation check removes or alters one guard in a scratch copy and runs the named tests, which must fail.

| Unit | Mutations |
|---|---|
| RU4 | two runs (a naive timeout; no socket shutdown) |
| RU5 | the security re-review proved its four tests for the split Bitwarden save fail on the old semantics |
| JU4 | 19 + 10 killed |
| JU5 | 18 + 23 + 5 killed |
| RU6b | the size-check test for servers without file types, by mutation; two transaction mutants that survived round 0 killed by new busy tests; 23 mutations caught by the code re-reviewer |
| JU6b | 21 + 28 + 22 killed by the implementer; 17 of 17 by the code reviewer's final re-review |
| RW | round 1: the ignored reuse flag; round 2: the reviewer's mutation of an inline unseal; round 3: four, for the de-timed tests; round 5: four, each check removed alone; round 6: one, a failed set-up turned into a refusal |
| JW | 76 + 33 + 26 killed; three survived their first run and got stronger tests |
| FW | Rust: 52 of 52 in round 1, then 91 of 91 in round 2 and 115 of 115 in round 3, each set run in full on that round's code; in round 4, its 32 new and changed mutations, with the other 94 standing from round 3; in round 5, 10 for its new guard: 136 distinct, all caught. Renderer: 32 in round 1 and 32 more in round 2, 64 distinct, all killed |

Probes and independent checks:
- The pass-1 security review proved the saved-password and MCP-binding findings with probes; the pass-2 security review proved the Bitwarden re-pointing with probe tests, and the GTK save-dialog finding with an offscreen GTK probe; the pass-2 code review proved both of its Lows with probes.
- RU6b's security review checked the disguising-character table against Unicode 16 (4,208 code points: every format character, every default-ignorable code point and the line and paragraph separators) and the unlock throttle under 6, 12 and 20 parallel guesses.
- RW's security re-review checked the dialog defaults and the Esc mapping in the rfd 0.16.0 and tauri-plugin-dialog 2.7.3 sources, for Windows, macOS and GTK.
- The hang (section 6.1): a gdb backtrace of every thread; a 40-line tokio probe (296 of 300 rounds lost the wake-up); a reproduction loop (6 hangs in 18 runs before, none in 84 after). RW's code re-check reproduced the mechanism in tokio 1.53.1: with the old `block()` a wake-up was seen only after 30.0009 s, with the fix after 0.30 s. Under load, 4 of 8 copies with the old `block()` failed with "did not finish within 60s" instead of hanging; with the fix, 16 of 16 passed.
- The fix wave's Argon2id check used the official Bitwarden SDK vectors (`bitwarden/sdk-internal` at commit eb9e208b, fetched 2026-10-14).
- The fix wave's re-checks. In round 1 the security re-check tried eight ways around the Bitwarden binding, and all held; the code re-check showed with a probe that an edit's closing mark is cleared on a timeout, a cancel, a panic and an unreadable copy. In round 2 the code re-check showed that the derivation slots are freed on a panic and a cancel, and probed the back-off's path variants in all three questions; the security re-check confirmed the Windows `\??\UNC\` spelling with a cross-compiled probe. In round 3 the code re-check tried the Windows key-path rule on 18 more inputs; the security re-check's cross-compiled probe found every network spelling refused, and a GTK probe showed a key's name steering the export dialog. In round 4 the security re-check confirmed with a GTK probe that the export dialog keeps its Downloads folder, and checked the per-kind back-off with a hand-moved clock.

### 8.7 Spot checks for this report

Made with `git grep` and `git show` at 3b0fcfb and at 6c19b1b:
- The index's 307 per-ID rows were recounted: 298 Fixed, 7 Partial, 1 Deferred, 1 Accepted limitation, with the area and severity splits of section 1.4.
- At 3b0fcfb: `not_contactable`, `credential_buttons`, `CREDENTIAL_MIN_ANSWER_DELAY`, `struct CredentialQuestions`, `timed_question_by`, `approval_token`, `MAX_PENDING_ENTRIES` (500), `PASSWORD_FOR_NEW_ACCOUNT`, `app_program_locations`, `block_on_own_parker`, `EDIT_CLOSE_UPLOAD_WAIT`, `MAX_PARALLEL_UNSEALS`, `MAX_PENDING_TEARDOWNS` (16), `category_set_order`, `modify_mcp_servers`, `category_chain`, `MAX_CATEGORY_DEPTH`, `QUOTED_LINE_MAX_CHARS` (300), `sync_category_marks` and `EXIT_TEARDOWN_BUDGET` exist in `src-tauri`; `errText`, `joinPlatformPath`, the `ev.detail > 1` guard, `sftpOpenOnce`, `beginPointerDrag`, `serverNeedsPasswordAgain`, `renderDeployNotes`, `BW_APPROVAL_ROUNDS` and `sftpQueueEditConflict` exist in `src/renderer`.
- At 6c19b1b: `bitwarden_allow_sync` is registered in `generate_handler!`; the prelogin memory goes through `argon2_memory_kib`; the save dialogs start from `save_dialog_folder`; "is being closed - try again when it has stopped." is in both `commands/sftp.rs` and `sftp.js`; `db::block()` checks `try_id()` and the runtime flavour; `bitwarden_account`, `CREDENTIAL_DECLINE_BACKOFF`, `write_hit`, `write_text_export`, `KDF_PERMITS`, `KDF_PERMIT_WAIT` and `CONFIG_FOLDER_SETTINGS` exist in `src-tauri`, and `errSpelled`, `warningSpelled` and `bwFocusAfterAllow` in `src/renderer`; so do `windows_key_path_is_local`, `key_path_refusal`, `KEY_FILE_NOT_LOCAL`, `own_export_refusal`, `check_own_export`, `write_key_export`, `QuestionKind` and `private_export_file_name`, while round 3's host-keyed back-off helpers are gone; round 5's `file_dialog_title` is in `commands/mod.rs`. Every fix-wave test name cited above exists.
- At the base 1ca864f, `bitwarden/mod.rs` passes `kdfMemory` straight into a field documented as KiB, so the Argon2id bug predates the branch; and `remote_sha256` in `commands/sftp.rs` hashes `size.unwrap_or(0)` bytes, so the unknown-size bug does too.
- `git branch -r --contains` is empty for 3b0fcfb and for 6c19b1b.

These spot checks ran no test suite and no cargo command; the coverage run of section 8.9 ran the seven renderer suites and all 950 Rust tests on a clean copy of 6c19b1b.

### 8.8 Controller verifications of the later units

- **RU6b:** a WSL copy of d5e9d22 plus the reviewed diff: fmt, clippy, 740 + 48 + 20 tests, `windows-gnu`.
- **JU6b:** a clean copy of HEAD plus the reviewed diff: `node --check` on 20 files, four static checks, all seven suites (one re-run after a load timeout).
- **RW:** the worktree with `src-tauri` equal to HEAD plus the reviewed diff: fmt and the full `cargo test` (837 + 48 + 20), no hang. An earlier run, under heavy load, failed 3 timing-bound tests and led to round 3; another hung and led to round 6.
- **JW:** a clean copy with the reviewed JW diff: `node --check` on 21 files, five static checks and all seven suites with no re-runs; after the commits, the static checks again on a clean copy of 3b0fcfb.
- **FW, round 2:** Rust on the worktree with `src-tauri` equal to HEAD plus the round-2 diff: fmt clean, clippy (`-D clippy::correctness`) exit 0, 871 + 48 + 20 = 939 tests passing with no hang, and the `windows-gnu` check exit 0. Renderer on a clean copy of HEAD with the renderer's round-2 diff (and round 1's Rust diff; the suites stub the backend): `node --check` on 21 files, the five static checks, and all seven suites with no re-runs (`test:ui` 76, `test:safety` 491, `test:sftp` 700, `test:polish` 195, `test:assistant` 367, `test:keys` 431, `test:servers` 676). The five static checks passed again with the round-2 Rust diff.
- **FW, rounds 3 and 4:** Rust: fmt clean, 878 + 48 + 20 = 946 and then 880 + 48 + 20 = 948 tests passing, clippy exit 0 and the `windows-gnu` check exit 0 each time. The five static checks passed on clean copies with each round's Rust diff.
- **FW, round 5, and the final tree:** the controller checked round 5's change. Rust: fmt clean, 950 tests passing (882 library, 48 integration, 20 MCP integration), clippy (`-D clippy::correctness`) and `windows-gnu` exit 0. Renderer: 2,936 checks at the fix-wave commit and 2,935 with the documentation commit (section 8.2).

### 8.9 Coverage

**Method.** Both measurements run on a clean `git archive` copy of one commit.
- Renderer: V8 precise coverage collected through Playwright while the seven suites run, from a preload around the harness (the harness and the suites are unchanged). Vendored files are excluded, and a line counts as covered when any code on it ran. Changed lines are the lines added since 1ca864f.
- Rust: cargo-llvm-cov 0.9.1 on the Linux debug test build. Every `#[cfg(test)]` region and the test-only SFTP server kit are stripped from the line data, so only production lines are scored.

**Measured at the final code, 6c19b1b** (2026-10-17; both halves valid; the measured build ran all 950 Rust tests):

| Measure | Covered | % | 80% target |
|---|---|---:|---|
| Renderer, all executable lines | 11,620 / 12,512 | 92.9 | met |
| Renderer, changed lines | 6,324 / 6,607 | 95.7 | met |
| Rust, production lines | 15,866 / 22,043 | 72.0 | not met |
| Rust, changed production lines | 10,987 / 14,211 | 77.3 | not met |

**Why the Rust figures are lower.** 106 of the 110 `#[tauri::command]` functions take an `AppHandle`, `State` or `Window`, and no test can produce them, so their 2,378 production lines (10.8% of all) run in no test; 1,771 changed lines are among them. 54 more functions that take an `AppHandle`, `State` or `Window` add 1,391 production lines, also uncovered. Without the commands the figures are 80.7% of production lines and 88.3% of changed lines; without the commands and those helpers, 86.8% and 90.4%. These exclusions are shown for explanation only; the headline figures exclude nothing but test code.

**Measured earlier, at d94ed2d** (three runs, within 0.1 point of each other), before RW, JW and the fix wave:

| Measure | Covered | % | 80% target |
|---|---|---:|---|
| Renderer, all executable lines | 11,228 / 12,213 | 91.9 | met |
| Renderer, changed lines | 5,898 / 6,133 | 96.2 | met |
| Rust, production lines | 13,337 / 19,954 | 66.8 | not met |
| Rust, changed production lines | 8,054 / 10,521 | 76.6 | not met |

At d94ed2d, 112 of the 118 commands took an `AppHandle`, `State` or `Window` (2,500 production lines, 12.5% of all); without them the Rust figures were 76.4% and 87.8%.

**Caveats.** Execution coverage is not assertion strength: a covered line ran during a test, which does not mean a test would fail if it were wrong (the mutation checks in section 8.6 speak to that). The renderer ran in headless Chromium, not in WebView2 or WebKitGTK, and CSS is not measured. Windows-only code (329 source lines at 6c19b1b, 299 at d94ed2d) is compiled out of the Linux build and is in no denominator.

**Recommendation.** Make the commands generic over `tauri::Runtime`, as some `sftp/queue.rs` helpers already are, and enable Tauri's `test` feature, so that `MockRuntime` can drive them.

## 9. Open items and follow-ups

| Item | What it needs |
|---|---|
| Manual checks never run | On Windows, quit with a connected MCP server and see the session DELETE arrive. On Windows, a key file on a network share: the drive-letter rule is tested through its pure function only. A real WebView2 drag and drop in the SFTP view and the category tree. A real GTK credential dialog (no default button; the idle-callback timing). The Windows CI job's first green run on a runner (its first run failed five tests, fixed in the follow-up commit; section 8.4), after which `continue-on-error` should go. `release.yml`'s new Windows manifest step, at the next tag |
| The coverage refactor | Commands generic over `tauri::Runtime`, so `MockRuntime` can test the command code (10.8% of production lines at 6c19b1b), which no test reaches today (section 8.9) |
| Deferred and Partial findings | A7-03 importers (R9); A7-54 and A7-55 suites, A7-58 importer, A1-29 token refactor and A5-22 progress events (R10); A5-28 terminal-header Edit button; A6-02 grant model; A7-56 Windows job's first green run |
| Smaller follow-ups | Skip the tools of unconfirmed MCP servers in the renderer; module splits; a read-back check for servers without file types; in `release.yml`, attach the installers and their signatures in one step (or publish a draft last), check each new signature against the public key the app embeds, and refuse a missing key before the build rather than after it; the rest of section 7.2 |
| Publication | The branch is pushed and [pull request #85](https://github.com/AGSQ11/SSHSpan/pull/85) is open for review. Merging it and any release need the user |

---

The working evidence behind this report - the unit briefs and reports, the RED, GREEN and mutation logs, the controller's verification logs and the controller's ledger - is kept outside the repository, in the git-ignored `.superpowers/` folder of the working tree. The commits, test names, scripts and documents cited above are the durable record.

