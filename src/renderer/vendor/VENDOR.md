# Vendored front-end libraries

These files are committed rather than installed, so nothing else in the repo
records what they are. Without that record nobody can answer "are we exposed to
CVE-X?" without downloading upstream and diffing by hand, and `npm audit` /
Dependabot see nothing at all.

Each row below was verified by fetching the upstream release and comparing
byte-for-byte — all four are unmodified. `scripts/check-vendor.js` re-checks the
hashes and runs in CI, so a file that changes without this table changing fails
the build.

| File | Package | Version | SHA-256 |
|---|---|---|---|
| `xterm.js` | [xterm](https://www.npmjs.com/package/xterm) | 5.5.0 | `1f991ac3b4b283ebf96e60ae23a00a52765dd3a2e46fa6fdda9f1aab032f7495` |
| `xterm.css` | [xterm](https://www.npmjs.com/package/xterm) | 5.5.0 | `ba8e6985669488981ccf40c0cefe3aba80722cb6c92de7ad628b0bd717faf2b6` |
| `addon-fit.js` | [@xterm/addon-fit](https://www.npmjs.com/package/@xterm/addon-fit) | 0.10.0 | `bdaefa370b1bfc42ee88d46fe6072400902a4d4b2d45cd93438dda9b23c97089` |
| `addon-web-links.js` | [@xterm/addon-web-links](https://www.npmjs.com/package/@xterm/addon-web-links) | 0.11.0 | `f230a6c8211ce4614dda5441f27b603c7c1ca95151a655bc0efac6377ee643f0` |

## Upgrading one of these

1. Download the exact file from the CDN, e.g.

   ```
   curl -fsSL -o src/renderer/vendor/xterm.js \
     https://cdnjs.cloudflare.com/ajax/libs/xterm/<version>/xterm.js
   curl -fsSL -o src/renderer/vendor/addon-fit.js \
     https://cdn.jsdelivr.net/npm/@xterm/addon-fit@<version>/lib/addon-fit.js
   ```

2. `sha256sum` it and update the row above — version **and** hash.
3. `npm run check:vendor` to confirm, then `npm run test:ui` for the terminal paths.

## A note on the terminal's link handling

Two kinds of link reach a click in the terminal:

- plain `http(s)` URLs in the output, which `addon-web-links` linkifies;
- OSC 8 hyperlinks, which xterm parses and hands to the terminal's
  `linkHandler` option. `terminal.js` sets it, so xterm never falls back to a
  native `confirm()` and `window.open()`. Here the visible text and the target
  are independent - a hostile server can display one URL and point at another.

Both go through `terminalOpenLink` in `terminal.js`, which parses the target
once and refuses, with a reason and without asking, a link whose scheme is not
`http`/`https` or that carries a user name or password in front of the host
(`https://accounts.google.com:signin@evil.tld/` opens `evil.tld`). Any other
link is shown in the app's own dialog - `Site: <host>` on a line of its own
first, then the address, cut at 300 characters - and opens only on OK,
through the backend's `system_open_url`, which accepts only `http`/`https`.
