# Tauri v2 and desktop packaging

Tauri's own model: the WebView and the Rust core are two trust groups, and IPC
is the bridge between them. Everything the WebView can reach is whatever the
capability set and the command list allow. So the audit question is always
*what can a lying renderer do*, not *what does our UI do*.

## Contents

- [IPC command surface](#ipc-command-surface)
- [Capabilities and permissions](#capabilities-and-permissions)
- [CSP and content containment](#csp-and-content-containment)
- [Plugins](#plugins)
- [Window and webview config](#window-and-webview-config)
- [Updater](#updater)
- [Build, CI and distribution](#build-ci-and-distribution)
- [Linux packaging](#linux-packaging)

## IPC command surface

Enumerate first, then trace:

```bash
grep -rn "#\[tauri::command\]" -A4 src-tauri/src/ | grep "fn "
grep -n "generate_handler!" -A120 src-tauri/src/lib.rs
```

Check each command for:

- **Argument trust.** Every argument is attacker-controlled under a compromised
  renderer. Paths, ids, indices, booleans, size hints — all of it.
- **Consent booleans.** A parameter like `allow_tofu`, `force`, `confirmed` or
  `skip_check` that gates a security decision is not consent, it is a request.
  The backend cannot tell a dialog happened. Flag these and rank on what the
  gate protects.
- **Registration drift.** A command defined but missing from `generate_handler!`
  is unreachable (dead surface, informational). One registered but never called
  from the renderer is unreviewed reachable surface — worse.
- **Sync vs async and the main thread.** Tauri runs a synchronous
  `#[tauri::command] fn` on the main thread. Blocking there — notably the
  dialog plugin's `blocking_*` helpers — deadlocks the whole UI. Not a
  vulnerability by itself, but a hang on a security dialog is a real
  availability and usability failure, and users work around hangs in unsafe
  ways.
- **Argument naming.** Tauri v2 expects camelCase from JS. A snake_case
  argument is silently dropped and the parameter takes its default — a
  security flag that defaults to `false` fails safe, one defaulting to `true`
  or `None`-means-skip does not. Grep both sides and compare.

## Capabilities and permissions

`src-tauri/capabilities/*.json` plus the generated `gen/schemas/*.json`.

- Diff the **generated** schema too when capabilities change — it is the
  effective grant and it is committed. A capability edit that produces an
  unexpected extra permission in the generated file is the finding.
- Look for wildcards and `:default` sets that pull in more than the app uses.
  `core:default` is broad; the plugin `:default` sets often include more
  commands than the one being used.
- Any permission granting filesystem, shell, or opener reach deserves a
  specific justification. `shell:allow-execute` and `opener:allow-open-url` are
  the two that turn a renderer XSS into code execution.
- Removing a permission is a *security improvement* — confirm the removal is
  real (in both the capability file and the generated schema) rather than
  shadowed by another grant.
- Known upstream class: **CVE-2025-31477**, `tauri-plugin-shell`'s `open`
  endpoint failed to validate protocols, so `file://`, `smb://` and `nfs://`
  reached the OS handler and gave RCE. If any code passes a URL or path to an
  opener/shell API, verify the scheme allowlist is enforced in *our* code and
  not assumed from the plugin.

## CSP and content containment

- CSP belongs in `tauri.conf.json` (`app.security.csp`). A second `<meta>` CSP
  in `index.html` *intersects* with it and drifts — check there is exactly one
  source of truth.
- `script-src 'self'` with no `unsafe-inline`/`unsafe-eval` is the property
  that keeps an injected string from becoming code. Any relaxation is a finding.
- `connect-src` is the exfiltration boundary. Every host listed should be one
  the app genuinely needs. `http:` entries on a desktop app deserve scrutiny.
- `csp: null` disables it entirely.
- Asset protocol scope: if `assetProtocol` is enabled, its scope is a path
  allowlist and has historically been traversal-prone (CVE-2022-39215 —
  missing canonicalisation in recursive read). If it is disabled, note that as
  a positive.
- `withGlobalTauri: true` exposes `window.__TAURI__` to any script in the page.
  It is a convenience that widens what an injected script can call; worth an
  informational note with the capability set as the real control.

## Plugins

For each `.plugin(tauri_plugin_*)` in `lib.rs`, establish whether it is
actually used:

```bash
for p in dialog process os sql notification opener clipboard-manager updater; do
  printf "%-20s rust:%s renderer:%s\n" "$p" \
    "$(grep -ro "tauri_plugin_${p//-/_}" src-tauri/src/ | wc -l)" \
    "$(grep -ro "__TAURI__\.${p//-/}" src/renderer/ | wc -l)"
done
```

A registered-but-unused plugin is attack surface with no benefit: its commands
exist, its permissions may be granted, and it ships in the binary. Report as
informational with the recommendation to drop it.

## Window and webview config

- `devtools` must not be enabled in release builds — it hands an attacker with
  local access a full inspector over a process holding decrypted keys.
- Check `dangerousDisableAssetCspModification`, `dangerousRemoteDomainIpcAccess`
  and any `dangerous*` key. Their presence is the finding.
- `withGlobalTauri`, `incognito`, `additionalBrowserArgs` — note anything that
  changes the webview's isolation.

## Updater

The updater is the highest-value target in the app: it downloads and executes
code. Audit against what The Update Framework assumes will go wrong.

- **Signature verification must fail closed.** A parse failure, a 404 on the
  signature, an unexpected key — all must abort *and delete the downloaded
  artifact*, never fall through to execution.
- **Placeholder keys.** A build shipping a dummy or empty public key means
  verification silently cannot succeed (or worse, is skipped). Check the
  embedded key parses.
- **Legacy signature modes.** minisign's non-prehashed mode should be refused
  if the release process signs prehashed; accepting both widens what a forger
  can present.
- **URL pinning.** Host *and* path prefix, applied after `Url::parse`
  normalisation so `..` cannot walk out of the pinned prefix. Re-validate every
  redirect hop, not just the initial URL.
- **Rollback / downgrade.** Does the client refuse an offered version older
  than the installed one? Without a version check, an attacker who can serve
  release metadata can pin users to a known-vulnerable build. Also consider
  **freeze** (serving a stale "no update" forever) and **fast-forward**
  (an absurd version number that makes every real future update look like a
  rollback).
- **Filename handling.** Version strings and asset names reach a temp path;
  strip separators or a crafted name walks out of the download directory.
- **Hash vs signature.** A digest from the same server that served the file is
  not integrity — only the signature over the bytes, with a key not fetched at
  runtime, is.

## Build, CI and distribution

- **Actions pinned to commit SHAs**, not tags. A tag is mutable and a
  compromised upstream action runs inside the release job with the signing key.
- **Signing key handling** in CI: written to a temp file, `chmod 600`, removed
  on exit via `trap`. Confirm it cannot leak into logs.
- **Order of operations**: any post-processing of an artifact must happen
  *before* signing, or the signature covers a file that is not what ships.
- **Artifact globs** must actually match what was built; a signing loop that
  finds zero files and does not fail is a silent no-op.
- **Reproducibility and provenance** — worth noting if absent, since an
  unreproducible build cannot be checked against source.
- Generated files committed to the repo (`gen/schemas/`, lockfiles) should be
  regenerated by tooling, never hand-edited, and reviewed in the diff.

## Linux packaging

- **Bundled libraries that must come from the host.** `libwayland-client.so.0`
  is on the official AppImage excludelist because it has to match the running
  compositor; bundling it breaks startup entirely on Wayland. The same logic
  applies to graphics and GPU libraries.
- **Media framework**: WebKitGTK expects a GStreamer stack; missing it produces
  runtime errors that block file dialogs and other features.
- **File permissions inside the package**, and whether the AppImage's own
  extraction directory is predictable.
- **Deb/RPM dependency lists** should match what the binary actually dlopens.
</content>
