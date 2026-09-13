# Renderer

The renderer is plain JavaScript with no framework, loaded from `index.html`
plus scripts injected by `app.js`. There is no framework auto-escaping to fall
back on, so every sink is manual and every one needs checking.

Two audiences for a finding here:

- **Injected content executing** — an XSS in a Tauri webview with
  `withGlobalTauri` is not a web XSS, it is a foothold that can call every
  granted IPC command with the vault unlocked.
- **The renderer lying to the backend** — see `tauri-desktop.md`. Anything the
  UI "enforces" is advisory.

## Contents

- [XSS sinks](#xss-sinks)
- [What is remote-derived](#what-is-remote-derived)
- [Escaping helpers](#escaping-helpers)
- [Terminal and ANSI output](#terminal-and-ansi-output)
- [Clipboard](#clipboard)
- [Security-relevant UI](#security-relevant-ui)
- [Storage](#storage)
- [Headless verification harness](#headless-verification-harness)

## XSS sinks

```bash
grep -rn "innerHTML\|outerHTML\|insertAdjacentHTML\|document.write\|srcdoc\|eval(\|new Function\|createContextualFragment\|setAttribute('on" src/renderer/
```

For each hit, decide whether any part of the string is remote- or user-derived.
Static literals and icon lookups are fine; note them as checked so the next
audit does not redo the work.

Also check:

- `javascript:` or `data:` reaching `href`/`src`.
- Event-handler attributes built by string concatenation.
- `element.style` fed untrusted values (CSS injection can exfiltrate via
  `background-image: url(...)` where CSP allows it).
- Template strings assembling HTML — the risk is the same as `innerHTML`.

Prefer `createTextNode` / `textContent`. When HTML is genuinely needed, the
escaping must cover the context: attribute values need quote escaping, and an
escaper that omits `'` is only safe if every attribute in the codebase uses
double quotes — which is a property that silently breaks later.

## What is remote-derived

Anything on this list arrives from a machine the user does not control and must
be treated as hostile in the renderer:

- SFTP filenames, directory listings, symlink targets, permissions strings
- Server error messages and status text (these reach toasts and logs)
- Saved-server names and hostnames (user-entered, but also import-derived from
  `~/.ssh/config`, which may itself be attacker-supplied)
- Bitwarden item, folder and collection names
- Updater release notes, tag names and asset names
- Host-key fingerprints and comments
- Terminal output, in full

## Escaping helpers

Find the codebase's escape helper and check every HTML sink uses it:

```bash
grep -rn "function escapeHtml\|escapeHtml(" src/renderer/ | head
```

Look for the asymmetric case: a family of similar render functions where all
but one escape. That one is the bug, and it is the most common shape of XSS in
a codebase that mostly gets it right.

## Terminal and ANSI output

The terminal is a rich sink, and remote output goes into it by design. Beyond
XSS, escape sequences are their own attack class ("weaponised ANSI"):

- **OSC 52** — clipboard write (and on some terminals read). A remote server
  can silently replace the user's clipboard, which for an SSH tool means
  swapping a command or a key.
- **OSC 0/2 title set, then query** — terminals that echo the title back inject
  attacker bytes into the *input* stream. Historically this reached command
  execution.
- **DECRQSS and other query/report sequences** — echo-back primitives with the
  same effect.
- **OSC 8 hyperlinks** — improperly terminated sequences let following text
  escape into control context.
- **OSC 7** — working-directory reporting has caused DNS lookups (data
  exfiltration channel) on some terminals.
- **Character-repeat sequences** — cheap DoS, can render the UI unusable.
- **C1 controls in UTF-8** — a second encoding of the same controls that naive
  filters miss.

Audit points for this app:

- Any string the *app itself* composes into the terminal stream (connection
  banners, status lines, error text) that interpolates a hostname, username,
  file path or server message. That is app-originated content carrying
  attacker-controlled substrings into a control-interpreting sink — strip or
  escape `ESC` (0x1b) and other C0/C1 controls before writing.
- Whether xterm.js has any risky addon or option enabled.
- Anything that copies terminal content to the clipboard without filtering.

The pragmatic defence is to escape ESC in untrusted text and let everything
else through, rather than trying to enumerate every dangerous sequence.

## Clipboard

- Reading the clipboard is a capability worth justifying.
- Writing secrets to the clipboard (private keys, passwords) is sometimes the
  feature, but note whether it is cleared, and that other apps can read it.
- A copy path that reports success or failure incorrectly is a usability *and*
  trust bug — users retry, or believe a secret was copied when it was not.

## Security-relevant UI

These are findings even though they are "just UI":

- A consent dialog whose answer the backend cannot verify.
- A dialog that claims a check was performed that was not.
- A prompt that cannot distinguish "never seen this host" from "the stored key
  changed" — the second is an attack signal and must not be presented as
  routine.
- A fingerprint shown *after* the decision instead of before it.
- A destructive confirmation that focuses the destructive button, or that
  cannot be dismissed with Escape, or where a "don't ask again" checkbox arms
  on the cancel path.
- Error text that silently truncates or overwrites a previous error, hiding a
  security-relevant message.

## Storage

- `localStorage` / `sessionStorage` / IndexedDB are readable by any script in
  the page and persist on disk unencrypted. Nothing secret belongs there.
- Watch for a renderer-side cache of a value that also lives in the backend —
  two sources of truth for a security setting will diverge.

## Headless verification harness

Claims about DOM behaviour should be executed, not reasoned about. Chromium is
available; `playwright-core` can be installed without downloading a browser.

```js
const { chromium } = require('<scratchpad>/node_modules/playwright-core');
const b = await chromium.launch({
  executablePath: '/opt/pw-browsers/chromium-1194/chrome-linux/chrome',
  args: ['--no-sandbox'],
});
const p = await b.newPage({ viewport: { width: 1280, height: 900 } });

// REQUIRED. app.js destructures window.__TAURI__ at module scope, so without a
// stub it throws there and every later top-level `const` stays in the temporal
// dead zone — functions appear defined (hoisted) but their dependencies are
// not, and tests silently measure a half-initialised page.
await p.addInitScript(() => {
  window.__TAURI__ = {
    core: { invoke: async () => ({}) },
    event: { listen: async () => () => {} },
  };
});
await p.goto('file:///home/user/SSHSpan/src/renderer/index.html');
await p.waitForTimeout(300);
```

Useful checks this enables:

- **XSS proof**: call the render path with a payload and assert the DOM has
  zero injected element nodes and no execution, rather than asserting the code
  "uses textContent".
- **Stacking and reachability**: `document.elementFromPoint` to prove a control
  is actually clickable, which catches z-index and overlay bugs.
- **Focus**: whether a dialog traps Tab, and where focus lands on open.
- **Computed styles**: whether a themed rule actually applies.

Collect `p.on('pageerror')` and report anything thrown — a boot error can leave
half the UI's guards unwired.
</content>
