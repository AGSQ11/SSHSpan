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

`addon-web-links` linkifies `http(s)` matches in terminal output, and clicks are
routed through the backend's `system_open_url`, which accepts only `http`/`https`.

xterm also parses OSC 8 hyperlinks, where the visible text and the target are
independent — a hostile server could display one URL and open another. That is
**not** currently reachable: xterm surfaces OSC 8 links only when the terminal's
`linkHandler` option is set, and `terminal.js` does not set it (verified against
the real page — the OSC 8 sequence produces no anchor). If `linkHandler` is ever
added, show the real target before opening it.
