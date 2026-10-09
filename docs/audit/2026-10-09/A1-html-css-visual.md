# A1 - HTML / CSS / visual audit of the SSHSpan renderer

1. **Counts:** Critical 0 | High 6 | Medium 20 | Low 14 (total 40).
2. **Covered (static):** src/renderer/index.html (all 974 lines), styles.css (all 2578 lines: tokens, theme support, dead/duplicate rules, focus handling, z-index, font sizes, contrast computed from the palette), and every DOM template in app.js, sftp.js, terminal.js, assistant.js, mcp.js; scripted cross-checks for undefined custom properties, dead selectors (strict string-literal scan), classes with no CSS, modifier classes with no effect, icon names absent from ICONS, duplicate/overridden declarations, HTML tag balance and duplicate ids (index.html is balanced, 266 unique static ids, no forms, no aria references to missing ids).
3. **Covered (dynamic):** headless Chromium 1.56.1 (Playwright) against the real page with a stubbed __TAURI__ (including Channel and a fed xterm session) at 880x560, 1100x720 and 1600x1000, plus 733x480/550x360 (Interface scale 150%/200%) and width sweeps 899-1000: Keys (list, detail, export tab, selection bar, 30-key list), Servers (list, live terminal, assistant panel, Files, dual pane, Split, transfer queue, context menus), all 7 Settings sections incl. the MCP form, and all 17 modal variants (key generate/import, server key/password, vault create/unlock/change, connect-password, deploy, palette, picker, prompt, confirm, YOLO, SFTP delete/chmod/conflict). Behaviour probes: Tab-order and computed focus styles, Escape per dialog, dialog stacking, label activation, splitter drags, context-menu clamping, vault re-prompt timing. About 150 screenshots in .superpowers/audit/scratch/A1/. Zero page errors and zero console errors/warnings were emitted in any run.
4. **NOT covered / limits:** WebView2/WebKitGTK rendering (Chromium is a stand-in: native select popups, scrollbars - headless Chromium hides them - and font fallback differ); Windows high-contrast/forced-colors mode; real xterm output beyond a synthetic stream; real SFTP/transfer data (all stubbed); hover-only states were verified by computed style rather than pixel; no visual-regression baseline exists, so 'inconsistent' findings are judged against the app's own palette and tokens; vendor/ and Rust were not audited.
5. **Method:** read-only; every finding cites file:line plus computed evidence from the live page and/or a screenshot name with its viewport; contrast ratios are WCAG 2.x relative-luminance values computed from the :root palette (scratch/A1/contrast.js); harness and scripts live in .superpowers/audit/scratch/A1/ (git-ignored); finding blocks are assembled from scratch/A1/parts/*.md by scratch/A1/assemble.js.

---

## A1-01: SFTP file listing shows no rows at the default and minimum window sizes
- **Severity:** High
- **Category:** ui
- **Location:** `src/renderer/styles.css:1660-1666` (`.sftp-queuepanel { flex: none; height: 220px; min-height: 120px }`), `styles.css:1525-1527` (`.sftp-toolbar` wraps to 3 rows), `sftp.js:202-207` and `sftp.js:2982-3101` (the queue panel is mounted with every Files/Split activation, jobs or not)
- **Evidence:** Playwright, Files mode, EMPTY queue, 4 stub directory entries: 880x560 -> `.sftp-tablewrap` height 0px, 0 of 4 rows visible; 1100x720 (default window) -> tablewrap 37px (28px of it is the `<thead>`), 0 rows fully visible; 1600x1000 -> 355px, 4/4 visible. The wrapped toolbar is 108px tall at 880 and 1100. Screenshots `1100x720-sftp-empty-queue.png`, `880x560-sftp-empty-queue.png`, `880x560-connect-sftp.png`.
- **Why it is a flaw:** the headline file-browser feature shows only column headers on first open at the default window size; a 220px transfer panel is reserved even when nothing is queued, and the wrapped toolbar takes another ~108px of the 460px surface (300px at the minimum window).
- **Proposed fix:** collapse the queue panel to its header row while `queueJobs.size === 0` (and cap it at ~35% of the surface otherwise), give `.sftp-pane` a `min-height` (about 160px) and let `.sftp-body` scroll vertically, and fold the secondary toolbar buttons (Columns, Dual, Log, Compare, Sync browse) into an overflow menu below ~600px.
- **Confidence:** confirmed
- **Effort:** M

## A1-02: Transfer queue needs 742px; Pause/Cancel/Retry are off-screen and the whole SFTP body scrolls sideways
- **Severity:** High
- **Category:** ui
- **Location:** `src/renderer/styles.css:1699-1703` (`grid-template-columns: 26px minmax(120px,2fr) minmax(110px,1.4fr) minmax(150px,1.6fr) 76px 64px minmax(80px,1fr) 60px; gap: 8px` = 742px minimum), `styles.css:1514` (`.sftp-body { overflow: auto }`), `styles.css:1676` (`.sftp-queuehead` has no `flex-wrap`), `sftp.js:3040-3068` (head actions), `sftp.js:3300-3347` (row actions)
- **Evidence:** with queued jobs, `#sftpQueueList` (overflow auto) has scrollWidth 742 vs clientWidth 436 (880x560) and 494 (1100x720); the first row's `.q-act` cell (Pause/Cancel/Retry buttons) has its right edge at x=1139 in an 880px window and x=1301 in a 1100px window (it only fits at 1600: right=1553); scrolling the list 400px sideways brings it to x=1053. The column header `.sftp-queuecols` sits outside that scroller and overflows the panel instead, so `#sftpBody` (overflow auto) gets scrollWidth 686 vs clientWidth 518 at 1100x720 and scrolling it 120px shifts the whole toolbar 120px left (headless Chromium hides scrollbars; WebView2 would draw the 10px custom ones from `styles.css:822-830`). `.sftp-queuehead` is scrollWidth 508 > clientWidth 494 at 1100x720: "Clear finished" is clipped at the pane edge and `.sftp-queuesummary` wraps to 5 lines ("1 active / . 200.0 / KB/s . 1 / queued . 1 / paused", head height 96px vs 26px at 1600). Screenshots `1100x720-connect-sftp.png`, `880x560-connect-sftp.png`.
- **Why it is a flaw:** the only controls that cancel or pause a transfer are off-screen at the default window size and need a sideways scroll of the queue list, whose header row does not scroll with it, while the same grid makes the whole file browser horizontally scrollable.
- **Proposed fix:** make the column template responsive (hide Route/Speed/ETA below ~700px, or render each job as two lines using a container query), add `flex-wrap: wrap` to `.sftp-queuehead`, set `white-space: nowrap; flex: none` on `.sftp-queuesummary`, and keep `.q-act` visible with `position: sticky; right: 0`.
- **Confidence:** confirmed
- **Effort:** M

## A1-03: Docked AI assistant (flex: 0 0 380px) squeezes the terminal to 9-17 columns; Split mode overflows its column
- **Severity:** High
- **Category:** ui
- **Location:** `src/renderer/styles.css:2338-2343` (`.assistant-panel { flex: 0 0 380px }`), `styles.css:2335-2336` (`.assistant-open .terminal-body { flex: 1; min-width: 0 }`), `styles.css:2262-2264` (`.session-surface.split .terminal-body { min-width: 240px }`, `.sftp-body { min-width: 280px }`)
- **Evidence:** Playwright with a stub session and a fitted xterm. Assistant open: `#terminalBody` is 80px wide / 9 columns (880x560), 138px / 17 columns (1100x720), 638px / 87 columns (1600x1000); terminal output wraps every ~17 characters (screenshot `1100x720-connect-assistant.png`). Split mode: terminal-body 280 + splitter 6 + sftp-body 280 = 566px inside a 518px surface at 1100x720 (surface scrollWidth 566; the SFTP pane's right edge is x=1113 vs terminal-column edge 1066, so 47px are clipped: toolbar "Folder"/"Log" buttons and the queue banner text are cut - screenshot `1100x720-connect-split.png`); 534px in a 460px surface at 880x560 (73px clipped). Split + assistant: the panel spans x=786-1166 in a 1100px window and still x=1383-1763 at 1600x1000 where the terminal column ends at x=1566, so about 200px (half) of the assistant is clipped: only the Read and Draft access levels are visible, Execute/YOLO and the Send button are cut off (screenshot `1600x1000-two-tabs-split-assistant.png`).
- **Why it is a flaw:** at the default window size opening the assistant leaves a 17-column terminal, and Split clips the right-hand file pane; with Split plus the assistant even a 1600px window clips the access-level control and the Send button, so Execute/YOLO and sending cannot be reached. The rigid widths ignore that the 280px server column and 228px sidebar leave only 518px at the default size.
- **Proposed fix:** make the assistant shrinkable (`flex: 0 1 380px; min-width: 260px`) and give the terminal a floor (`min-width: 320px`) with `overflow-x: auto` on the surface; or overlay the assistant on the terminal below ~1300px; auto-collapse the server column (or sidebar) while Split or the assistant is active.
- **Confidence:** confirmed
- **Effort:** M

## A1-04: Context menus are positioned at raw pointer coordinates and can open entirely outside the viewport
- **Severity:** High
- **Category:** ui
- **Location:** `src/renderer/app.js:1263-1306` (`openTerminalContextMenu`: raw `left=x`, `top=y`), `app.js:3794-3825` (server context menu: same), `sftp.js:1661-1791` and `sftp.js:2235-2315` (remote/local SFTP menus: same), despite a viewport-clamping helper already existing at `app.js:3975-3982`
- **Evidence:** right-clicking the live terminal at (1000,520) in a 1100x720 window produced menu rect `{left:1000, top:520, right:1200, bottom:829}`: every item is cut off on the right (the menu spans x=1000-1200 in a 1100px window, e.g. "Copy all to", "Clear scrollbac") and the last items (Restart session, Switch to SFTP, most of Duplicate session) lie entirely below the 720px window. Screenshot `1100x720-termmenu-offscreen.png` shows only a clipped strip in the lower-right. The host picker does not have this flaw because it calls `positionCtxMenuAt()` at `app.js:4116-4117`.
- **Why it is a flaw:** right-clicks near the bottom or right edge (the prompt line sits at the bottom of the terminal) produce a menu with truncated labels and unreachable items; the user must dismiss it and right-click somewhere higher.
- **Proposed fix:** call the existing `positionCtxMenuAt(menu, x, y)` after appending every `.ctx-menu` instead of directly assigning `left/top`; do the same for async bookmark/import menus anchored near an edge.
- **Confidence:** confirmed
- **Effort:** S

## A1-05: Controls are nested inside `<label>` wrappers, so label clicks fire hidden controls: the bandwidth "Unlimited" pill double-toggles, and a click on blank space resets the server auth method
- **Severity:** High
- **Category:** html
- **Location:** `src/renderer/app.js:2475-2504` (`mkRow` wraps every Settings control in one `<label class="settings-row">`), `app.js:2637-2694` (hidden checkbox + clickable `.settings-combo-tag` which also toggles and dispatches `change`), `src/renderer/styles.css:593` (checkbox is invisible), `index.html:792-798` (`<label class="span-2 auth-method-row">` wraps three `<button>`s), `app.js:3498-3504` and `app.js:3880-3889`
- **Evidence:** (1) From stored Unlimited (`checked=true`), one real mouse click on the visible "Unlimited" pill made 4 calls: `settings_set 524288` + `sftp_queue_set_rate_limit 524288`, then `settings_set 0` + `sftp_queue_set_rate_limit 0`, ending visually unchanged at Unlimited; after a prior title click had disabled Unlimited, one pill click made the reverse pair and ended disabled. Toasts claimed both "Bandwidth limit removed" and "Bandwidth limit set to 512 KB/s". The span's explicit handler toggles the checkbox, then the label's implicit activation toggles it again. (2) A click on the row *title text* of "Bandwidth limit" silently changed the setting to 512 KB/s (calls `settings_set sftpMaxBps=524288` + `sftp_queue_set_rate_limit`); a click on the title text of "Check for an update now" activated its nested button and called `update_check`, because a `<button>` is nested in the label. The two inner controls of the bandwidth row (number + unit select) have no accessible name (the label binds to the first labelable descendant, the hidden checkbox). (3) In the server editor, Password was selected (`state.connectAuthMethod==='password'`), then a click on blank space inside the full-width Auth-method label (not on a segment) changed it to `publickey`, because label activation forwards to the first labelable descendant (the Key button).
- **Why it is a flaw:** the visible bandwidth control cannot change the setting while a caption click silently throttles every transfer; unrelated row text triggers update checks; whitespace clicks mutate the server's authentication method.
- **Proposed fix:** make `.settings-row` a `<div>` and bind only real captions with `for`/`htmlFor`; make the Unlimited pill a `<label for=...>` with no manual toggle (or a real button with `aria-pressed` and one state path); replace the auth-method `<label>` with `<fieldset><legend>` / `role=radiogroup aria-labelledby`.
- **Confidence:** confirmed
- **Effort:** S

## A1-06: At <=900px the category tree is hidden and nothing replaces it, so categories cannot be filtered or managed (min window, or default window at Interface scale >=125%)
- **Severity:** High
- **Category:** ux
- **Location:** `src/renderer/styles.css:836-855` (esp. `848-854`: comment + `.cat-panel { display: none !important }`), `src/renderer/index.html:35-41` (the tree and `#catAddRootBtn` live only in the sidebar), `index.html:77-95` (toolbar has no category control), `index.html:88-91` (comment: the toolbar filter was removed; "The tree is now the only place you filter"), `src/renderer/app.js:867-868` (picker empty state: "Create one in the sidebar"), `styles.css:992-994` (the `.cat-filter-btn` the CSS comment relies on is dead), `app.js:2526-2545` (Interface scale offers 90-200%)
- **Evidence:** Playwright: at 1100x720 `#catPanel` computes `display:flex` and `#catAddRootBtn` is visible; at 899x700 and 880x560 `#catPanel` computes `display:none`, `#catAddRootBtn` has zero width, and the Keys toolbar contains only the search field, `#typeFilter`, `#keyCount` and `#newKeyBtn`. The media-query comment claims "The Keys page keeps its own 'All categories' filter button", but no such element exists in `index.html` or any JS template. Browser zoom/Interface scale shrinks the CSS viewport: a 1100px window at 125% scale is 880 CSS px, so this layout is also the default window at common 1080p scale settings. The only remaining category route is the Ctrl+K palette ("Categories -> Filter"); creating, renaming, moving or deleting a category is impossible.
- **Why it is a flaw:** a documented, supported window size (and a common scale setting) silently removes the whole category feature while the picker tells users to use the hidden sidebar; the CSS comment's justification is false in the code.
- **Proposed fix:** below 900px show the tree as a drawer/popover opened from a toolbar "Categories" button (reusing `openCategoryPicker` plus create/rename actions), or keep the tree in the narrow rail; remove the false comment and the dead `.cat-filter-btn` rules.
- **Confidence:** confirmed
- **Effort:** M

## A1-07: Key list rows wrap names mid-word at the default size (ellipsis rule matches nothing; invisible Connect button reserves 88px)
- **Severity:** Medium
- **Category:** visual
- **Location:** `src/renderer/styles.css:437` (`.key-row-name > :first-child { overflow: hidden; text-overflow: ellipsis; white-space: nowrap }`), `app.js:1478-1480` (`name.textContent = ...` makes the name a bare text node), `styles.css:1996-1999` (`.key-row .row-btn { opacity: 0 }` still occupies layout), `app.js:1525-1536`
- **Evidence:** `:first-child` only matches elements, so for rows without a badge the rule matches nothing (`firstElementChild === null`, computed `white-space: normal`). At 1100x720 `.key-row-main` is 29px wide for "prod-deploy" (wraps to "prod-" / "deploy", row height 82px) and 136px for a long name (4 lines, row 121px); `.row-btn` is 88px wide at `opacity: 0` on every private-key row, and `.key-row-sub` shrinks to "pro..." / "laptop@ho...". Screenshot `1100x720-keys-detail.png`.
- **Why it is a flaw:** the primary list wraps names mid-word, produces rows of unequal height and truncates the comment line far short of the free space, on first launch at the default size.
- **Proposed fix:** wrap the name in a `<span class="key-row-title">` (so the existing rule applies) or move the rule onto `.key-row-name` itself, and take `.row-btn` out of flow (`position: absolute` or `display: none` until hover/focus) so it stops reserving width.
- **Confidence:** confirmed
- **Effort:** S

## A1-08: Settings is clamped to 780px; Known hosts "Forget" button and "First seen" column are outside the window
- **Severity:** Medium
- **Category:** css
- **Location:** `src/renderer/styles.css:580` (`.settings-view { max-width: 780px }`, left over from the pre-rail layout) vs `styles.css:2205` (`.settings-view { display: flex; gap: 22px }`) and `styles.css:2225` (`.settings-panel { max-width: 880px }`); `index.html:307-312`
- **Evidence:** at 1100x720 and 1600x1000 `.settings-view` is 780px and `.settings-panel` 572px; the Known hosts `.table-wrap` has clientWidth 530 / scrollWidth 725 and the first "Forget" button sits at x=1110-1194 inside a 1100px window (screenshots `1100x720-settings-hosts.png`, `1600x1000-settings-hosts.png`: ~570px of empty space to the right, a table showing only Host + Fingerprint). Host cells wrap mid-word ("db-replica-1.eu-west-" / "1.internal.example.com:22").
- **Why it is a flaw:** the table's only action is hidden behind a horizontal scroll with no visible affordance at every window size; the intended 880px panel width is never reached.
- **Proposed fix:** delete the `max-width: 780px` rule at line 580 (and the dead `.settings-view > h2` rule beside it) so `.settings-panel` can use its 880px, and let long fingerprints wrap (`word-break: break-all`) or truncate with a copy button.
- **Confidence:** confirmed
- **Effort:** S

## A1-09: Application dialogs all share z-index 50, so a newly opened dialog can render behind an older one and take focus invisibly
- **Severity:** Medium
- **Category:** ui
- **Location:** `src/renderer/styles.css:681-687` (all `.modal-backdrop` use `z-index: 50`), `styles.css:691-698` (only `#pickerModal` is raised), `app.js:1881-1890` (`openPalette`), `app.js:3400-3447` (Ctrl+K remains global), `app.js:4545-4548` (vault-status poll), `app.js:1021-1060` (`showVaultModal`)
- **Evidence:** Playwright opened an existing server dialog, then Ctrl+K. `#paletteModal.hidden === false`, focus moved to hidden-behind `#paletteInput`, but `elementFromPoint()` over the palette returned `#serverModal` as the painted backdrop (screenshot `1100x720-ctrlk-under-server-modal.png`: only New Server is visible). Repeating with `showVaultModal('unlock')` while each dialog was open put the vault below `#serverModal`, `#deployModal`, `#paletteModal`, `#promptModal`, and `#confirmModal`; only the earlier-in-DOM key dialog happened to paint below it (screenshot `zorder-vault-under-server-modal.png`). All backdrops have equal stacking order, so DOM order—not open order—wins, while `modalStack` at `app.js:105-179` assumes the last-opened dialog is topmost.
- **Why it is a flaw:** keyboard focus can be trapped in a dialog the user cannot see. More seriously, if the vault status changes while a server/deploy/prompt dialog is open, the unlock UI and gate can be hidden behind it even though the vault is locked.
- **Proposed fix:** assign stacking order on open (`node.style.zIndex = 50 + modalStack.length`) and remove it on close, or centralize dialogs under one portal and append the active backdrop last. Suppress Ctrl+K and other dialog openers while a modal is active unless deliberate stacking is supported.
- **Confidence:** confirmed
- **Effort:** M

## A1-10: The global focus rule removes the browser outline from every control, while most buttons provide no focus-visible replacement
- **Severity:** Medium
- **Category:** a11y
- **Location:** `src/renderer/styles.css:92-94` (`button:focus-visible, input:focus-visible, select:focus-visible, textarea:focus-visible { outline: none }`), `styles.css:195-249` (primary/ghost/danger/icon buttons have hover but no focus-visible rule), `styles.css:271-275` (inputs get a custom ring), isolated replacements only at `styles.css:569`, `styles.css:2287`, `styles.css:2171`, `styles.css:2250`
- **Evidence:** after establishing keyboard modality, Playwright focused `.nav-item`, `#paletteBtn`, `#detailRenameBtn`, `#detailConnectBtn`, `#detailDeleteBtn`, both `.detail-tab`s, `#vaultStatus`, `#catAddRootBtn`, `.cat-chip.add-chip`, `#newKeyBtn`, and a group-collapse button (after waiting out the 120ms transitions). Every element matched `:focus-visible`, but computed outline stayed `none 0px` and none of outline, box-shadow, border colour, background, colour, filter or transform differed between the unfocused and focused states; screenshot `focus-detail-rename.png`. A 44-stop Tab pass found 30 stops showing neither outline nor shadow; the remaining 14 were text inputs/textarea/checkboxes (covered by `input:focus`) and two primary buttons whose static drop-shadow does not change on focus.
- **Why it is a flaw:** keyboard users cannot tell where focus is across the app's navigation and action controls, including destructive Delete/Disconnect buttons and modal tabs.
- **Proposed fix:** replace the global suppression with a shared rule such as `:where(button, a[href], [role=button], [tabindex]):focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }` (or `box-shadow: var(--ring)`), retaining specialized checkbox/row rules.
- **Confidence:** confirmed
- **Effort:** S

## A1-11: The clickable key rows, category rows/chevrons, and terminal tabs are not keyboard-operable
- **Severity:** Medium
- **Category:** a11y
- **Location:** `src/renderer/app.js:1457-1545` (key row is a clickable `<div>` with no role/tabindex/keydown), `app.js:460-504` (category row and chevron are clickable `<div>/<span>` with no role/tabindex/keydown), `app.js:4332-4361` (terminal tab + close are clickable `<div>/<span>`), `index.html:221-223` (`#termTabAdd` is a clickable `<div>`), `sftp.js:1941-1951` (SFTP search results are clickable `<div>`s too)
- **Evidence:** live DOM at 1100x720: `.key-row` `{tabIndex:-1, role:null}`, `.cat-node` `{tabIndex:-1, role:null}`, `.cat-chevron:not(.leaf)` `{tabIndex:-1, role:null}`, and `#termTabAdd` `{tag:'DIV', tabIndex:-1, role:null, ariaLabel:null}`. Only child controls (deploy checkbox/Connect) are reachable; users cannot open a public-only key (which has no Connect button), select a category, expand a category, activate/close a session tab, or use the advertised New-session “+” without a mouse. The category action button itself can be tab-focused but remains `opacity: 0` because CSS exposes it only on `.cat-node:hover`/`.active` (`styles.css:936-945`), so its focus is invisible even before the global focus-ring defect.
- **Why it is a flaw:** primary navigation inside each view is pointer-only, a WCAG 2.1.1 keyboard blocker.
- **Proposed fix:** use native `<button>`s (or add `role="button"`, `tabindex="0"`, and Enter/Space handlers); use `role=tab` + roving tabindex for terminal tabs; make `.cat-node:focus-within .cat-actions-btn { opacity:1 }`.
- **Confidence:** confirmed
- **Effort:** M

## A1-12: Group "Collapse" controls change their icon/title but do not hide any key rows
- **Severity:** Medium
- **Category:** ui
- **Location:** `src/renderer/app.js:1421-1453` (adds/toggles `.collapsed`), `src/renderer/styles.css:1066-1079` (group rules; no `.key-group.collapsed` rule)
- **Evidence:** Playwright at 1100x720: before click the first group had 2 visible rows; after clicking its "Collapse group" button, class became `key-group collapsed`, button title changed to "Expand group", but it still had 2 visible rows. Static CSS contains `.sftp-queuegroup.collapsed` at line 1733 but no rule for `.key-group.collapsed`. This collapse path is not among the behaviours asserted by `npm run test:ui`.
- **Why it is a flaw:** the visible control lies about its state and cannot compact a long grouped key list.
- **Proposed fix:** wrap group rows in a child container and hide that container when collapsed, or add `.key-group.collapsed > .key-row { display:none; }` while leaving the header visible.
- **Confidence:** confirmed
- **Effort:** S

## A1-13: Low-contrast text token fails WCAG AA throughout the UI, often at only 10-11.5px
- **Severity:** Medium
- **Category:** a11y
- **Location:** `src/renderer/styles.css:27` (`--text-faint: #667085`), used in 64 `color: var(--text-faint)` declarations including `styles.css:269` (all placeholders), `styles.css:301` (`.hint`, 11.5px), `styles.css:131` (`.brand-sub`, 10px), `styles.css:440` (key-row subtext, 11px), `styles.css:508-510` (detail labels, 10.5px), `styles.css:881` (category heading, 10px), `styles.css:927-932` (category counts, 10px), `styles.css:1945-1948` (palette headings, 10px), `styles.css:2239` (settings descriptions, 11.5px)
- **Evidence:** WCAG relative-luminance calculations from the declared palette (`scratch/A1/contrast.js`): `#667085` is 3.88:1 on `--bg #0b0e14`, 3.77:1 on `--bg-elev`, 3.64:1 on `--panel`, 3.43:1 on `--panel-2`, 3.16:1 on `--panel-3`, and 2.96:1 on `--hover`; all are below the 4.5:1 normal-text threshold. Playwright computed 10px `#667085` on `.brand-sub`, `.cat-panel-title`, `.cat-count`; 10.5px on `.vault-sub` and `.detail-label`. Screenshots `1100x720-settings-general.png`, `1100x720-keys-detail.png`, `1100x720-modal-palette.png` show low-contrast secondary/help text.
- **Why it is a flaw:** secondary information (placeholders, setting consequences, category counts, timestamps/hints) is materially hard to read, especially at the app's own sub-11px sizes; this is not a preference but a contrast failure.
- **Proposed fix:** raise `--text-faint` to at least about `#7f899d` for the darkest surfaces and audit text on `--panel-3`/hover separately; use `--text-dim` for 10-11.5px explanatory text. Re-run the supplied contrast script against every text/background pair.
- **Confidence:** confirmed
- **Effort:** M

## A1-14: White text on light fills: the selected server-auth segment (2.41:1) and the assistant's YOLO badge (2.80:1)
- **Severity:** Medium
- **Category:** a11y
- **Location:** `src/renderer/styles.css:1381-1392` (`.seg-btn.active { background: var(--accent); color: white }`); the dark-text correction exists only for terminal mode at `styles.css:2276-2278` and AI levels at `styles.css:2366-2376` (whose comment at `2366-2371` describes exactly this bug); `styles.css:2355-2359` (`.ai-yolo-badge { color:#fff; background: var(--danger) }`, 10px)
- **Evidence:** computed server-modal active Key segment: foreground `rgb(255,255,255)` on `rgb(110,168,255)`, WCAG contrast 2.41:1; `#fff` on `--danger #f4717d` is 2.80:1 for the 10px bold YOLO badge. The same fills with the app's already-used dark text `#0a1120` are 7.82:1 and 6.74:1 (`scratch/A1/contrast.js`). Screenshot `1100x720-server-modal-keyselected.png`.
- **Why it is a flaw:** the selected authentication method (12px) and the badge that warns the assistant is in YOLO mode fail even the 3:1 large-text threshold, making selection and warning state hard to read.
- **Proposed fix:** set the base `.seg-btn.active` text to `#0a1120` (matching `.mode-seg` and `.ai-level-seg`) and use `#0a1120` on the YOLO badge, or darken the fills until white reaches 4.5:1.
- **Confidence:** confirmed
- **Effort:** S

## A1-15: Dual-pane splitter changes only `--local-pct`; the remote pane stays 50%, causing overlap/blank space and no usable resize
- **Severity:** Medium
- **Category:** ui
- **Location:** `src/renderer/styles.css:1584-1585` (`remote: var(--remote-pct,50%)`, `local: var(--local-pct,50%)`), `src/renderer/sftp.js:498-515` (drag sets only `--local-pct`; `--remote-pct` is never written anywhere), `src/renderer/styles.css:2263-2274` and `sftp.js:159-180` (`.surface-splitter`/`--split-pct`: the splitter is only shown/hidden, no drag handler exists)
- **Evidence:** Playwright at 1600x1000. Initial panes: local 497px + remote 497px + 6px splitter inside a 994px pane region (already 6px too wide). Dragging splitter 220px right set local to 696px but remote remained 497px: sum 1199px, scrollWidth 1199, remote right overflow 205px; screenshot `1600x1000-dual-splitter-dragged-right.png` shows the remote pane pushed 205px past the pane region with its Modified/Permissions/Owner columns cut off. Dragging 500px left set local 199px while remote remained 497px: only 702px of 994px used, leaving ~292px blank; screenshot `1600x1000-dual-splitter-dragged-left.png`. The independent `.surface-splitter` has no JS drag listener at all: dragging it 150px left kept terminal width 550px and left `--split-pct` empty.
- **Why it is a flaw:** both visible resize affordances are broken: one creates overflow or blank space rather than redistributing width, and the other does nothing.
- **Proposed fix:** use one percentage: `local: 0 0 var(--local-pct)` and `remote: 1 1 0` (or set `--remote-pct: calc(100% - var(--local-pct) - 6px)`); subtract splitter width; wire `#surfaceSplitter` to set `--split-pct` with the same clamped drag pattern; add keyboard/ARIA separator semantics.
- **Confidence:** confirmed
- **Effort:** M

## A1-16: SFTP name cells are flex `<td>` elements and have no ellipsis/nowrap, causing 53-109px table rows and broken alignment
- **Severity:** Medium
- **Category:** visual
- **Location:** `src/renderer/styles.css:1587-1610` (`.sftp-table`, `.sftp-table td`, `.sftp-tdname { display:flex; overflow:hidden; text-overflow:ellipsis }` but no `white-space:nowrap`), `sftp.js:1073-1095` and `sftp.js:2104-2118`
- **Evidence:** at 1600x1000, `.sftp-tdname` computes `display:flex` while sibling cells are `table-cell`; a long file row is 53px and even `notes.txt` is 53px because Size/Modified wrap. At 1100x720, directory rows are 53px and the long file row is 109px (about six lines); the screenshot `1600x1000-sftp-symlink-quickfind.png` shows names, sizes and dates wrapping and baselines no longer aligned. `text-overflow: ellipsis` cannot work without `white-space: nowrap` and the flexified `<td>` opts out of normal table-cell behaviour.
- **Why it is a flaw:** a file table ceases to scan as rows/columns; four entries can consume hundreds of pixels and the virtualizer's nominal 31px height (`sftp.js:1108-1110`) must repeatedly remeasure variable-height rows.
- **Proposed fix:** keep `<td>` as `display: table-cell`; put icon+name inside a nested `.sftp-namewrap { display:flex; min-width:0 }`, and apply `overflow:hidden; text-overflow:ellipsis; white-space:nowrap` to a child name span. Add nowrap to Size/Modified/Permissions/Owner cells (with title/tooltips).
- **Confidence:** confirmed
- **Effort:** S

## A1-17: Three SFTP states are rendered but have no stylesheet at all (spinner, symlink badge, quick-find indicator)
- **Severity:** Medium
- **Category:** css
- **Location:** `src/renderer/sftp.js:604-613` (adds `.is-link`, comment promises a CSS `::after` badge), `sftp.js:1027-1033` (adds `.sftp-spinner`), `sftp.js:1438-1442` (toggles `.broken`), `sftp.js:411-418` and `sftp.js:973-981` (adds/shows `.sftp-quickfind`); no matching selectors exist in `styles.css` (reverse class scan; the same scan also shows `.empty-state.small` at `index.html:192` has no variant rule, so that empty state renders at full 44px padding)
- **Evidence:** Playwright at 1600x1000: pending-directory `.sftp-spinner` computed `display:inline`, width 0, height 0, animation `none` and empty text; symlink icon `.sftp-eicon.is-link` had `::after { content:none }` and exactly the same colour as an ordinary directory (screenshot `1600x1000-sftp-symlink-quickfind.png`: `current` is indistinguishable from a directory); quick-find rendered as a plain 19px-high line inside the pane (`position:static`, transparent background, no padding) that takes layout space under the table, despite the code comment at `sftp.js:411-413` saying it is positioned over the pane.
- **Why it is a flaw:** directory-size calculation appears to erase the Size value with no progress feedback; symlink/broken-link state is invisible; type-to-filter feedback lands as unstyled table-adjacent text rather than the intended indicator.
- **Proposed fix:** add scoped styles for `.sftp-spinner` (sized border spinner + animation), `.sftp-eicon.is-link::after` / `.broken::after`, and `.sftp-quickfind` (`position:absolute; top/right; z-index; opaque panel background`); make `.sftp-pane { position:relative }`.
- **Confidence:** confirmed
- **Effort:** S

## A1-18: Selection bar overflows its narrow key column; Deploy and Clear end up painted under the detail pane
- **Severity:** Medium
- **Category:** ui
- **Location:** `src/renderer/styles.css:2013-2022` (`.selection-bar` is a non-wrapping flex row), `index.html:108-115` (four actions), `styles.css:370-377` (key column shares width with detail pane)
- **Evidence:** at 1100x720 the key-column selection bar is 383px wide (clientWidth 381) but its content is scrollWidth 492px; the bar ends at x=635 and the detail pane starts at x=653, but the Deploy button spans x=615-719 and the Clear button x=729-745, so everything right of x=653 (most of Deploy and all of Clear) sits under the detail pane, which paints over it. Screenshot `1100x720-selection-bar.png` shows the primary action truncated to "Dep" and Clear not visible. At 1600x1000 it fits; at 880x560 the detail pane stacks below the list and the bar fits the full 756px.
- **Why it is a flaw:** at the default window size the bulk-action bar's primary action ("Deploy...") and its dismiss control are partially or completely hidden behind another panel.
- **Proposed fix:** add `flex-wrap: wrap` or switch the bar to a compact two-row/grid layout below a key-column container width of ~520px; allow text labels to collapse to icons with accessible labels; keep `overflow: hidden` on the bar only after it is responsive.
- **Confidence:** confirmed
- **Effort:** S

## A1-19: Compact (<=900px) layout artefacts: the vault control's countdown wraps to three lines in the 66px rail, and "New key" shows two plus signs
- **Severity:** Medium
- **Category:** visual
- **Location:** `src/renderer/styles.css:836-854` (at <=900px hides `.vault-label` but not `.vault-sub`, `.vault-text` or `.vault-caret`), `styles.css:1885-1888` (vault text/caret layout), `app.js:3581-3593` (countdown text)
- **Evidence:** at 880x560 (and at any viewport narrower than 900 CSS px, which includes the 880px minimum window and the default window at an Interface scale of 125% or more) the vault button is 49px wide while `#vaultSub` is squeezed to a 1px-wide flex item (x=32-33, 39px tall); its "locks in 15:00" text overflows that box, wraps to three lines and runs into the caret. Screenshots `880x560-clip-vault.png` and `880x560-keys.png` show the jammed "locks / in v / 15:00".
- **Why it is a flaw:** the persistent control that shows the vault state looks corrupted on every screen in the compact layout; the text is neither readable nor intentionally hidden. In the same layout the primary "New key" button renders a doubled plus: `index.html:94` already contains a plus SVG, and `styles.css:844-845` sets `#newKeyBtn { font-size:0 }` and adds a second `::before { content:'+' }` (computed 27px-wide button with one SVG plus the generated `"+"`, no `title`/`aria-label`; screenshot `880x560-clip-newkey-vault.png` shows "++").
- **Proposed fix:** within the <=900px media query hide `.vault-text` and `.vault-caret` entirely (keep `title`/`aria-label` updated with state + countdown); remove the `::before` plus, hide only a label span, and add `title="New key" aria-label="New key"`.
- **Confidence:** confirmed
- **Effort:** S

## A1-20: Server rows reserve invisible Connect buttons, truncate names without a tooltip, and misalign short names
- **Severity:** Medium
- **Category:** visual
- **Location:** `src/renderer/styles.css:1198-1210` (`justify-content: space-between`; `.server-name` ellipses), `styles.css:2288-2296` (`.server-go { opacity:0; flex:none }` stays in layout), `app.js:3717-3769` (dot + name + button in one head; no title on the name)
- **Evidence:** live rows are 266px wide; hidden Connect/Open is 65-78px wide on every row. A long name is limited to 147px and is truncated with no `title`; short names are pushed toward the centre because `justify-content: space-between` distributes the gap (`web-1` begins 69px after the status dot, `pw-box` 57px, while long names begin 6px after it). Screenshot `1100x720-connect-ssh.png`/`1600x1000-sftp-symlink-quickfind.png` shows visibly wandering baselines and truncated names.
- **Why it is a flaw:** the server list's primary identifier moves horizontally by name length and important names are truncated with no way to reveal the full value.
- **Proposed fix:** set `.server-name { flex:1; min-width:0 }`, make the head use a fixed `gap` (not space-between), position/display the action only on hover/focus, and set `name.title = s.name` for truncation disclosure.
- **Confidence:** confirmed
- **Effort:** S

## A1-21: Server modal squeezes the `.pem` path field to ~70px because the row accidentally uses the key-list `.key-row` class
- **Severity:** Medium
- **Category:** css
- **Location:** `src/renderer/index.html:799-809` (`#srvKeyRow` contains label/select then `.pem-row`), `src/renderer/styles.css:383-391` (`.key-row` global flex styling unintentionally applies because the server row reuses the same generic class), `styles.css:1351-1369` (server-grid styling), `styles.css:1393-1398` (`.pem-row`)
- **Evidence:** at both 1100x720 and 880x560 the server form's `#srvKeyRow` is 522px wide: vault key select 321px, path input only 70px, Browse 88px. Screenshot `1100x720-server-modal-keyselected.png` shows the path placeholder reduced to `...or pick`, while a selected long key name consumes most of the row. The container computes the unrelated key-list card background/border/cursor because its class is `span-2 key-row`.
- **Why it is a flaw:** users cannot read or verify a selected PEM path; an accidental global class collision styles a form row as a clickable key list card.
- **Proposed fix:** rename it to `.server-key-row`, lay it out as a two-column grid (`minmax(0,1fr) minmax(0,1fr)`) or stack the alternatives, and give both select/path `min-width:0` with title/ellipsis.
- **Confidence:** confirmed
- **Effort:** S

## A1-22: Key/import/server modal actions fall below the visible modal at minimum height; the modal footer is not sticky
- **Severity:** Medium
- **Category:** ux
- **Location:** `src/renderer/styles.css:700-708` (`.modal { max-height: calc(100vh - 60px); overflow:auto }`), `styles.css:732-737` (`.modal-footer` is ordinary flow), `index.html:543-610` (key modal), `index.html:776-829` (server modal)
- **Evidence:** Playwright at 880x560: key-generate modal client height 498 / scrollHeight 520, footer bottom y=551 > modal bottom y=530; key-import scrollHeight 721, footer bottom 752; server-key scrollHeight 649, footer bottom 680; server-password scrollHeight 660, footer bottom 691. Screenshots `880x560-modal-key-import.png` and `880x560-modal-server-key.png` show the form cut off with no Cancel/Import or Cancel/Save buttons visible until the user discovers that the whole modal scrolls. At 1100x720, key-import and server-password still scroll with footer below the fold.
- **Why it is a flaw:** a modal can appear to have no completion action at the app's supported minimum height; the scrollbar is low-contrast and outside the user's reading flow.
- **Proposed fix:** make `.modal` a flex column with `overflow:hidden`; put `overflow:auto; min-height:0` on `.modal-body`; keep header/footer `flex:none` (as the deploy sheet already does). Ensure initial focus/scroll puts the first field, not a hidden footer, in view.
- **Confidence:** confirmed
- **Effort:** S

## A1-23: Vault Cancel is temporary: the 10-second status poll reopens the unlock dialog and steals focus
- **Severity:** Medium
- **Category:** ux
- **Location:** `src/renderer/app.js:1065-1094` (`refreshVaultStatus` always calls `showVaultModal('unlock')` while locked), `app.js:3164-3167` (Cancel hides it and promises "unlock it any time"), `app.js:4545-4548` (poll every 10 seconds), `app.js:1056-1060` (reopening focuses password)
- **Evidence:** with `vault_status={hasVault:true, unlocked:false}`, Playwright saw the dialog initially, clicked Cancel (dialog hidden), then it automatically reappeared 8.5s later (remainder of the 10s interval) and focus moved into `#vaultPassword`. Screenshot `1100x720-locked-vault.png`.
- **Why it is a flaw:** users cannot dismiss the lock gate to inspect Settings/help or deliberately postpone unlock; the recurring modal interrupts typing and steals focus every poll.
- **Proposed fix:** record a session-only `vaultPromptDismissed` flag when Cancel is pressed; polls should update state/nav but not reopen until the user clicks the vault control or a gated action. Clear the flag when lock state changes.
- **Confidence:** confirmed
- **Effort:** S

## A1-24: Selecting a key in a long list (or in the compact layout) leaves its detail pane off-screen: the pane is neither sticky nor independently scrollable
- **Severity:** Medium
- **Category:** ux
- **Location:** `src/renderer/styles.css:370-377` (`.keys-layout { display:flex; flex-wrap:wrap; align-items:flex-start }`), `styles.css:481-490` (`.detail-pane` has no `position: sticky`, `max-height` or own scroll), `styles.css:324` (the whole `.view` scrolls), `styles.css:846-847` (`@media (max-width: 900px) { .keys-layout { flex-direction: column } }`), `src/renderer/app.js:1617-1625` (`selectKey` fills the pane but never scrolls it into view)
- **Evidence:** Playwright with 30 stub keys: selecting the 22nd key at 1100x720 leaves `.view` scrolled 1243px and the pane at y=-1111..-526 (computed `position: static`), the whole right half of the window blank (screenshot `1100x720-keys-long-list-selected.png`); at 1600x1000 the pane is at y=-971..-386. In the compact layout (880x560, 4 keys) the pane stacks below the list and starts at y=503 of 560, so only its header strip is visible after selecting a key; any longer list pushes it entirely below the fold. The stacking is not limited to the <=900px media query: measured at 901px and 950px viewports the pane's top is y=519 (below the list); it only sits beside the list from about 975px up, because `flex-wrap` needs 688px of content width.
- **Why it is a flaw:** the master/detail view stops working for realistic vault sizes: choosing a key gives no visible result, and the Connect / Export / Rename / Delete actions live in the invisible pane.
- **Proposed fix:** make `.detail-pane { position: sticky; top: 0; max-height: calc(100vh - var(--topbar-h) - 44px); overflow: auto; }` in the side-by-side layout, and in the stacked layout scroll the pane into view in `selectKey` (or open it as a drawer/modal).
- **Confidence:** confirmed
- **Effort:** S

## A1-25: The "Preserve timestamps" toolbar toggle is never rendered, so the transfer option has no UI
- **Severity:** Medium
- **Category:** ui
- **Location:** `src/renderer/sftp.js:561` (`ensureSftpPreserveTsToggle(tabId)` is called at the end of `buildSftpPanel`, before the caller appends the panel), `sftp.js:570-585` (the function begins with `document.getElementById('sftpPanel-' + tabId)` and returns when it is null), `sftp.js:192-197` (`showSftpForTab` appends the panel only after `buildSftpPanel` returns), `sftp.js:588-600` (the only handler for the setting), `sftp.js:2520-2525` and `2579-2584` (transfers read `tab.sftpPreserveTs`); the Compare/Sync buttons avoid the problem because `sftpCmpEnsureButtons` runs later from `refreshSftpPanel` (`sftp.js:934`)
- **Evidence:** Playwright in Files mode lists exactly 12 toolbar buttons (Up, Refresh, Folder, File, Bookmarks, Search, Hidden, Columns, Dual, Log, Compare, Sync browse) and `document.getElementById('sftpPreserveTsBtn-<tab>')` is `null`; there is no other caller and the Settings page (`app.js:2506-2853`) has no row for `sftpPreserveTs`.
- **Why it is a flaw:** a transfer option that the code, comments and persisted setting all assume exists cannot be toggled by the user; the setting is silently stuck at whatever was stored.
- **Proposed fix:** call `ensureSftpPreserveTsToggle(tabId)` from `showSftpForTab` after `sbody.appendChild(panel)` (or pass the panel element as an argument); give the button a text label like its siblings (it would otherwise be an icon-only button reusing the `history` icon of "Log"), plus a Settings row.
- **Confidence:** confirmed
- **Effort:** S

## A1-26: Popup menus never receive keyboard focus, and re-rendering lists drops focus to `<body>`
- **Severity:** Medium
- **Category:** a11y
- **Location:** `src/renderer/app.js:1122-1165` (`openVaultMenu` appends the menu at the end of `<body>`, no focus, no role; the trigger at `index.html:47` advertises `aria-haspopup="menu"`), `app.js:1550-1581` (`openKeyConnectMenu`), `app.js:1263-1307` (terminal menu), `app.js:3794-3826` (server menu), `sftp.js:1661-1792` and `sftp.js:2235-2316` (SFTP menus): none move focus into the menu, set `role=menu/menuitem`, or handle arrow keys/Escape; `app.js:1617-1619` (`selectKey` rebuilds the whole list via `renderKeyList`), `app.js:1811` (a format-row click re-renders the list), `app.js:3788-3792` (`selectServer` re-renders the server list)
- **Evidence:** Playwright with keyboard only: Enter on `#vaultStatus` opened the vault menu (`aria-expanded="true"`) but `document.activeElement` stayed on the button; the menu is `document.body.lastElementChild` with no `role`, and it took 24 Tab presses to reach its first item. Enter on a key row's Connect button left `document.activeElement === BODY` (the list was rebuilt by `selectKey`) with the connect menu open and unfocused. Space on an export-format row also left `activeElement === BODY` because `renderExportFormats` recreated every row.
- **Why it is a flaw:** keyboard users cannot use the vault, key-connect, server, file or terminal menus except by Tabbing through the whole page, and after selecting a key, server or export format they lose their place and restart from the top of the document.
- **Proposed fix:** a shared `openMenu()` helper that focuses the first item, sets `role="menu"`/`"menuitem"`, supports ArrowUp/ArrowDown/Home/End/Escape and returns focus to the opener on close; render lists incrementally (toggle `.selected` in place) or restore focus to the element with the same `data-id` after re-rendering.
- **Confidence:** confirmed
- **Effort:** M

## A1-27: Custom modal Escape support is incomplete and depends on which control has focus
- **Severity:** Low
- **Category:** a11y
- **Location:** `src/renderer/app.js:3400-3417` (global Escape handles only palette, picker, deploy, key, server, term-max, and vault/change), `app.js:3392-3395` (prompt Escape only on `#promptInput`), `app.js:3541-3544` (connect-password Escape only on its input), `assistant.js:167-180` (YOLO has no key handler), `app.js:3164-3167` (vault unlock/create only close via Cancel)
- **Evidence:** Playwright opened each dialog, moved focus to its Cancel button, then pressed Escape. `#promptModal`, `#connectPwModal`, and `#yoloModal` all remained open. `showVaultModal('unlock')` also remained open after Escape (create behaves the same); only change mode is handled by the global branch. Conversely the generic confirm/delete/chmod/conflict dialogs each install their own capture-phase Escape listener. Initial focus for the tested dialogs was valid (e.g. YOLO Cancel), so this is not a focus-trap artifact.
- **Why it is a flaw:** Escape works or fails based on modal type and focused child, violating the expected dialog contract and trapping keyboard users in some common prompts.
- **Proposed fix:** put Escape handling in the central modal manager (`initModalFocusManagement`): close the topmost dialog through a registered close callback. Remove per-input/per-modal duplicates once every dialog opts into that contract; if vault create/unlock must not close, document and expose that explicitly rather than allowing Cancel but not Escape.
- **Confidence:** confirmed
- **Effort:** M

## A1-28: Icons fail to render in three menus/dialogs (category menu, terminal menu, conflict dialog), and the terminal menu's `<hr>` separators show the browser's inset border
- **Severity:** Low
- **Category:** visual
- **Location:** (a) `src/renderer/app.js:645-649` (`openCatMenu` writes `<span data-ico="...">` markup after boot, but `injectIcons()` at `app.js:289-300` runs only once from `main()` at `app.js:4484`), (b) `app.js:1284-1289` (`ico('clipboard')`, `ico('eraser')`, `ico('rotate-ccw')`) with `src/renderer/icons.js:3` (ICONS has none of the three names), (c) `src/renderer/index.html:948` (`<button class="icon-btn" id="conflictCloseBtn" title="Close"></button>` has no `data-ico-x` and no `aria-label`, unlike lines 551/669/759/784/901), plus `app.js:1287-1290` (`<hr class="ctx-sep">`), `styles.css:1436` and duplicate `styles.css:1891` (`.ctx-sep` has no `border:0`), other menus use `<div class="ctx-sep">` (e.g. `app.js:1143-1145`)
- **Evidence:** (a) opening a category's "..." menu in Playwright: all four items (Rename, New subcategory, Move to..., Delete) have `hasSvg:false` and an empty `[data-ico]` span; screenshot `1100x720-cat-menu.png` shows text with an empty icon gap. (b) static evaluation: `clipboard=false`, `eraser=false`, `rotate-ccw=false` while `copy/plus/refresh-cw/folder-tree=true`; the Paste, Clear scrollback and Reset terminal rows have `hasSvg:false`, so their text starts 22px left of icon rows (x=915 vs x=937 at 1100x720). (c) every modal audit at all three viewports reported `button#conflictCloseBtn.icon-btn` as an empty icon button; screenshot `1100x720-modal-conflict.png` shows no X in the header. Computed `<hr.ctx-sep>`: 2px high with 1px `inset rgb(128,128,128)` top and bottom borders versus `<div.ctx-sep>` 1px with no border; screenshot `1100x720-connect-termmenu.png` shows two bright double-line separators.
- **Why it is a flaw:** the category management menu and terminal menu look like failed icon loads with ragged text columns, the conflict dialog lacks its visible close control (an invisible but focusable button named only by `title`), and one shared separator renders two ways depending on tag.
- **Proposed fix:** build menu icons with `ico()` (or call `injectIcons(root)` after creating dynamic markup); add the three Lucide SVGs to `ICONS` (or use existing names) and make `ico()` emit a fixed-width empty slot for unknown names; add `data-ico-x aria-label="Close"` to the conflict button; add `border:0` to `.ctx-sep` and delete the duplicate rule at line 1891 (or use `<div role="separator">` consistently).
- **Confidence:** confirmed
- **Effort:** S

## A1-29: Stylesheet hygiene: 15 dead selectors, overridden duplicate declarations, unused tokens, raw values that bypass the palette, and a monospace stack that bypasses `--mono`
- **Severity:** Low
- **Category:** css
- **Location:** dead rules `src/renderer/styles.css:302` (`.sep`), `454` (`.badge.ghost`), `522-525` (`.export-row`), `531-538` (`.config-view`, `.deploy-options`), `574` (`.config-actions`), `611-624` (`.setting-row/.setting-name/.setting-desc`), `656` (`.audit-view`), `581-585` (`.settings-view > h2`; no such child), `992-994` (`.cat-filter-btn`, `#catFilterLabel`), `1130-1150` (`.partial`, `.dimmed`), `1824` (`.sftp-upload-row`); overridden duplicates `142` vs `873` (`.nav { flex }` 1 then none), `69-70` (`html` height twice), `1436` vs `1891` (`.ctx-sep`), `173` vs `1879` (`.vault-status` gap), `1179` vs `2327` (`.server-list-head .search-wrap` flex); unused tokens `32` (`--accent-strong`), `56` (`--shadow-glow`); monospace stacks `1215` and `1537` (`'JetBrains Mono','Menlo',monospace`) vs `--mono` at line 59 and xterm's own stack at `terminal.js:301`; eight per-component `[hidden]{display:none !important}` rules (`2000, 2048, 2226, 2269, 2311, 2344, 2360, 2384, 2444`) already covered by the global rule at line 90; `!important` used to win ordering/specificity fights: `542`, `2156`, `2231` (`flex-direction: row !important` only to beat the global `label { flex-direction: column }` at line 296 and `.server-grid label` at 1357), `854` (`.cat-panel { display:none !important }` because the media block at 836 is declared before the base rule at 874) and `1824`
- **Evidence:** the strict scanner `scratch/A1/dead-css2.js` counts a class/id as used only if it appears in an HTML attribute or a JS string literal (dynamic prefixes such as `q-state-`, `ai-h`, `level-` expanded) and found no reference for the 15 selectors across `index.html`, `app.js`, `sftp.js`, `terminal.js`, `assistant.js`, `mcp.js` (the looser scan produced false positives where a word merely appears as a JS identifier). The duplicate scanner (`scratch/A1/dup-css.js`) found the conflicting declarations above; `.setting-row` (dead) sits next to the live `.settings-row` at line 2230. `JetBrains Mono` and `Menlo` are not Windows fonts, so `.server-row-sub` and `.sftp-path` fall back to the generic monospace while all other mono text uses Cascadia/Consolas via `--mono`. About 55 lines (2%) of the file are unreachable. Raw values that duplicate or bypass tokens (`scratch/A1/hardcoded-colors.js`): `#39445a` x4 (lines 270, 552, 603, 2164; a hover border with no token), `#0a1120` x4 (198, 2278, 2372, 2483; dark-on-accent text), `rgba(245,181,68,...)` at 188 and 454 instead of `--warn-rgb`, the `#5f9cf5`/`#4c8cf2` primary-button gradient (197) instead of `--accent`/`--accent-strong`, and the terminal background `#0f1115` at `styles.css:1258` and `terminal.js:304`; 63 raw `border-radius` declarations versus 38 `var(--r-*)` uses with 15 distinct values (panels use 11, 12, 14 and 15px), and 14 distinct font sizes from 10px to 18px in half-pixel steps. No visible defect today (single theme), but a token change would not reach these values.
- **Why it is a flaw:** dead and shadowed rules make cascade changes unsafe (singular/plural Settings systems coexist) and one font family differs between sibling UI strings.
- **Proposed fix:** delete the dead blocks after a screenshot regression pass, remove the shadowed first copies, use `var(--mono)` everywhere, drop the redundant per-component `[hidden]` rules, and add a selector-token check to `scripts/` with an allowlist for vendor/dynamic classes.
- **Confidence:** confirmed
- **Effort:** S

## A1-30: Generic confirmation modal initially focuses the destructive action rather than Cancel
- **Severity:** Low
- **Category:** a11y
- **Location:** `src/renderer/app.js:923-950`, specifically `app.js:949` (`setTimeout(() => el('confirmOkBtn').focus(), 0)`), while SFTP delete correctly focuses Cancel at `sftp.js:1604-1606`
- **Evidence:** opening `confirmModal('Clear audit log', ...)` set `document.activeElement` to `#confirmOkBtn.danger-btn`. The SFTP delete dialog's documented safe pattern intentionally focuses Cancel; the generic modal does the opposite.
- **Why it is a flaw:** a reflex Enter/Space confirms irreversible actions (currently audit-log clearing) instead of taking the safe default; this is inconsistent across dialogs.
- **Proposed fix:** focus `#confirmCancelBtn` initially; leave destructive confirmation reachable by Tab or an explicit accelerator.
- **Confidence:** confirmed
- **Effort:** S

## A1-31: SFTP Local pane header shows Permissions and Owner columns that its rows never fill
- **Severity:** Low
- **Category:** visual
- **Location:** `src/renderer/sftp.js:465` (local `<thead>` has five `<th>`, two `.col-extra`), `sftp.js:2104-2118` (each local row appends three cells), `styles.css:1601-1602` (`.col-extra` is shown whenever `.show-owner-cols` is on), `sftp.js:91` (default on)
- **Evidence:** the Local table has five header cells and three body cells per row; with Columns enabled by default two empty "PERMISSIONS"/"OWNER" columns reserve width beside the Local rows. Screenshot `1600x1000-dual-splitter-dragged-right.png`: headings over blank columns on the Local site.
- **Why it is a flaw:** columns that can never contain data waste scarce horizontal space in a pane that already becomes narrow in dual mode.
- **Proposed fix:** drop the two `.col-extra` `<th>` elements from the Local table (or fill them from `sftp_local_list` if the backend can return mode/owner).
- **Confidence:** confirmed
- **Effort:** S

## A1-32: The assistant textarea's focus style uses `border-color: var(--ring)`, where `--ring` is a box-shadow value
- **Severity:** Low
- **Category:** css
- **Location:** `src/renderer/styles.css:2463` (`.ai-foot textarea:focus { outline:none; border-color: var(--ring); }`), `styles.css:57` (`--ring: 0 0 0 2px rgba(var(--accent-rgb), 0.55)`)
- **Evidence:** `--ring` resolves to `0 0 0 2px rgba(110, 168, 255, 0.55)`. Used as a colour it is invalid at computed-value time, so the focused textarea's border computes to `rgb(232, 236, 243)` (`currentcolor`, `--text`) rather than the accent used by every other field. Screenshot `1100x720-ai-input-focus.png` shows a near-white border inside the blue shadow ring.
- **Why it is a flaw:** the assistant input is the only focus treatment that does not follow the palette; the line was clearly meant to be `var(--accent)`.
- **Proposed fix:** use `border-color: var(--accent)` (and drop `outline:none`, which the global rule already provides).
- **Confidence:** confirmed
- **Effort:** S

## A1-33: The SFTP delete dialog's "Don't prompt" option is a native checkbox stacked above its caption (inline style loses to the global `label` column rule)
- **Severity:** Low
- **Category:** css
- **Location:** `src/renderer/index.html:881-884` (inline `display:flex; align-items:center; gap:8px; ...` with a plain `<input type=checkbox>`), `src/renderer/styles.css:296` (`label { display:flex; flex-direction: column; ... }`)
- **Evidence:** computed on the dialog's label: `flex-direction: column; align-items: center`; the native 13px checkbox (`appearance:auto; accent-color:auto`) is at (544,364) centred above the caption at (433,385). Screenshot `1100x720-modal-delete.png`. Every other checkbox option uses the `.toggle-chip`/`.toggle-box` pattern.
- **Why it is a flaw:** the intended inline row never forms, the white native box clashes with the dark UI, and the control is the only unstyled toggle left in the dialogs.
- **Proposed fix:** replace the inline style with `<label class="toggle-chip"><input ...><span class="toggle-box"></span>Don't prompt me for this session anymore.</label>`.
- **Confidence:** confirmed
- **Effort:** S

## A1-34: Inputs holding hostnames, paths and secrets are missing `autocomplete`/`spellcheck` hints, inconsistently with the app's own vault and AI fields
- **Severity:** Low
- **Category:** html
- **Location:** `src/renderer/index.html:172` (`#detailExportPass`), `559`/`581`/`589` (`#genName`, `#genComment`, `#importName`), `597` (`#importPass`), `675-676` (`#cfgHost`, `#cfgUser`), `694` (`#keyPassphraseInput`), `788-791` and `806` (`#srvName`, `#srvHost`, `#srvPort`, `#srvUser`, `#srvPemPath`), `842` (`#promptInput`), `923` (`#chmodOctal`), `src/renderer/app.js:2336-2340` (Bitwarden `server_url`, `email`, `master_password`, folder fields), `src/renderer/sftp.js:318-321` (search input)
- **Evidence:** a live DOM scan shows `autocomplete` and `spellcheck` both unset on all of the above, including four password-type fields (`importPass`, `detailExportPass`, `keyPassphraseInput`, `bw_master_password`). In contrast `vaultPassword*`, `connectPwInput`, `srvPassword`, `aiApiKey`, `mcpAuthSecret` set `autocomplete="off"`, and `paletteInput`, SFTP path boxes, AI/MCP URL fields set `spellcheck=false`.
- **Why it is a flaw:** hostnames, usernames and file paths pick up spellcheck underlines in WebView2, and passphrase/master-password fields can be offered to general autofill.
- **Proposed fix:** add `spellcheck="false" autocomplete="off"` to the host/user/path/name fields, and `autocomplete="new-password"` (or `off`) to every password field; do it in the JS-built Bitwarden fields too.
- **Confidence:** confirmed
- **Effort:** S

## A1-35: Truncated values (key fingerprint, server names, key comments, palette subtext) have ellipsis but no tooltip or other way to read the rest
- **Severity:** Low
- **Category:** ux
- **Location:** `src/renderer/styles.css:2057-2061` (`.copy-row code`), `app.js:1682` (`#detailFingerprint` set via `textContent`, no `title`), `styles.css:439-444` / `app.js:1505-1508` (`.key-row-sub`), `styles.css:1204-1210` / `app.js:3728-3731` (`.server-name`), `styles.css:1971-1976` (`.palette-sub`)
- **Evidence:** the in-page audit found `text-overflow: ellipsis` with `scrollWidth > clientWidth` and no `title` on the element or any ancestor for: `code#detailFingerprint` (a 50-character `SHA256:` fingerprint cut by about five characters at 1100x720), two `.key-row-sub`, two `.server-name`, one `.palette-sub`. Screenshot `1100x720-keys-detail.png` shows the fingerprint ending in an ellipsis. The detail-pane copy in `app.js:1501-1504` says the fingerprint is the thing you compare there.
- **Why it is a flaw:** the user cannot read or visually verify the tail of a fingerprint, and long server names cannot be told apart, without copying to another app.
- **Proposed fix:** set `title` to the full text for every ellipsised element (cheap helper), and let the fingerprint wrap (`overflow-wrap:anywhere; white-space:normal`) instead of truncating.
- **Confidence:** confirmed
- **Effort:** S

## A1-36: Assorted a11y gaps: incomplete ARIA tab/combobox patterns, five `<label>`s that label nothing, no `prefers-reduced-motion`, and 12-19px pointer targets
- **Severity:** Low
- **Category:** a11y
- **Location:** `src/renderer/index.html:128-131` (`.detail-tabs` `role=tablist`), `210-214` (`#termModeSeg`), `237-242` (assistant level segmented control), `554-557` (key-modal `.tabs`: no roles at all), `734` and `764` (`aria-expanded="true"` hard-coded on two comboboxes), `135,137,142,159,171` (`<label class="detail-label">` elements with no control; `#detailExportPass` at line 172 is named only by its placeholder), `src/renderer/app.js:1980-1983` (palette rows are `role=option` buttons but `aria-activedescendant` is never set; only the picker sets it at `app.js:893`), `styles.css:647-649`, `687`, `708`, `794`, `2448` (infinite and entry animations; no `prefers-reduced-motion` rule exists), small targets `styles.css:1492-1498` (`.term-tab-close`), `936-942` (`.cat-actions-btn`), `908-914` (`.cat-chevron`), `1123-1127` (`.picker-chip-remove`), `805-809` (`.toast-dismiss`)
- **Evidence:** grep over `src/renderer` finds no `role="tabpanel"`, `aria-controls` on any tab, `aria-current`, or `prefers-reduced-motion`; the three `role=tab` groups are plain buttons that are all Tab stops with no arrow-key handling; the assistant's access levels are mutually exclusive choices announced as tabs. Playwright confirmed the five detail labels have no `control` and `#detailExportPass` has no name besides its placeholder. Measured hit boxes at 1100x720: session-tab close `12x17`, category "..." button `16x16`, category chevron `14x14` (CSS), picker chip remove `15x15`, toast dismiss `19x20`, against the 24x24 CSS px minimum of WCAG 2.2 SC 2.5.8.
- **Why it is a flaw:** assistive technology receives tab/combobox semantics without the supporting relationships, users who ask for reduced motion still get pulsing/animated UI, and the smallest controls (closing a session tab, expanding a category) are easy to miss with a pointer.
- **Proposed fix:** either implement the full tab pattern (tabpanel, aria-controls, roving tabindex, arrow keys) or use radio-group/`aria-pressed` semantics; set `aria-expanded` from real state and `aria-activedescendant` in the palette; replace the unbound labels with `<span>`/`<h3>` or bind them; add `@media (prefers-reduced-motion: reduce)` disabling the keyframe animations; give the small controls a 24px hit area (padding or a `::before` hit target).
- **Confidence:** confirmed
- **Effort:** M

## A1-37: No `color-scheme: dark`, so native widgets (number spinners, form-validation bubbles, some select popups) render in the light theme
- **Severity:** Low
- **Category:** css
- **Location:** `src/renderer/styles.css:11-64` (`:root` declares tokens but no `color-scheme`), `styles.css:256-285` (inputs/selects restyled individually)
- **Evidence:** `getComputedStyle(document.documentElement).colorScheme` is `normal` and so is the Settings number input's. Screenshot `1100x720-number-spinner.png` shows the native up/down spinner of "Parallel file transfers" drawn as a light-grey control on the dark field. The repo has no `data-theme`/`prefers-color-scheme` handling; the UI is a single dark theme (all 41 `:root` custom properties are defined; only the JS-set `--local-pct`, `--q-depth`, `--remote-pct`, `--split-pct` are read without a CSS definition, and the last two are never set, see A1-15).
- **Why it is a flaw:** the app is dark-only but tells the engine it is light, so any control it does not restyle (spinners, native validation/autofill UI, WebKitGTK popups) clashes.
- **Proposed fix:** add `color-scheme: dark;` to `:root`.
- **Confidence:** confirmed
- **Effort:** S

## A1-38: The terminal host's 4px padding contradicts its own comment, so FitAddon over-counts rows; the faint maximize button overlaps the last column
- **Severity:** Low
- **Category:** css
- **Location:** `src/renderer/styles.css:1256-1263` (comment says "No padding: xterm measures the host box exactly; padding skews FitAddon", declaration is `padding: 4px`), `src/renderer/terminal.js:331-335` and `371-383` (`FitAddon.fit()`), `styles.css:1268-1291` (`.term-max-btn { opacity: .35 }` positioned `right: 8px; bottom: 34px`)
- **Evidence:** at 880x560 the `.terminal-host` border box is 300px tall with 4px padding (292px content). The vendored FitAddon's `proposeDimensions` (`src/renderer/vendor/addon-fit.js`) reads the parent element's computed `height` (a border-box value here) and subtracts only the xterm element's own padding, so it chose 20 rows x 15px = 300px; `.xterm-screen`'s bottom is therefore y=484 while the host ends at y=481, clipping the last row by about 3px (up to 8px at other heights). At 1100x720 the 30-row grid fits only by rounding luck (450px in 452px). The maximize button (26x26 at x=1031-1057, y=611-637) overlaps the xterm viewport (right edge x=1061) and intercepts clicks there (`elementFromPoint` returns it); at opacity .35 its icon has a computed contrast of about 1.97:1 against the panel (`scratch/A1/contrast.js`).
- **Why it is a flaw:** the comment's claim is false in the code (so a previous fix was undone), the prompt row can be clipped at some window heights, and a control that is both nearly invisible and in the way of terminal selection is the worst combination for discoverability.
- **Proposed fix:** remove the host padding (pad an inner wrapper instead) as the comment prescribes; place the maximize control in `.terminal-head`/`.terminal-strip` rather than floating over the screen, and give it at least 3:1 contrast.
- **Confidence:** confirmed
- **Effort:** S

## A1-39: Settings shows a literal `[OI]` placeholder where the provider name should be
- **Severity:** Low
- **Category:** ui
- **Location:** `src/renderer/index.html:370` (`<option value="openai" selected>[OI]-compatible (chat/completions)</option>`), `index.html:379` (preset option text `[OI]` for `https://api.openai.com/v1`), `index.html:400` (status strip "Works with [OI], OpenRouter, Groq, Anthropic, ...")
- **Evidence:** the rendered Settings -> AI assistant section (screenshot `1100x720-settings-assistant-top.png`) displays "[OI]-compatible (chat/completions)" in the Provider select and "Works with [OI], OpenRouter, ..." beneath the buttons; the same token also appears in `README.md:55,180,182` and `CHANGELOG.md:213,260,261`, which suggests a global find/replace artifact rather than a product name.
- **Why it is a flaw:** the default provider option reads as an unresolved template token; users cannot tell which provider the preset or the compatibility claim refers to.
- **Proposed fix:** replace `[OI]` with the real provider name (or "OpenAI-compatible") in the three UI strings and the docs.
- **Confidence:** likely
- **Effort:** S

## A1-40: The server list's "KEY MISSING" badge is rendered in the success green because `.badge.warn` has no rule
- **Severity:** Low
- **Category:** css
- **Location:** `src/renderer/app.js:3732-3736` (`m.className = 'badge warn'`), `src/renderer/styles.css:446-455` (`.badge` defaults to the green ed25519 tint; only `.badge.pub, .badge.ghost` use `--warn`)
- **Evidence:** a modifier-vs-selector scan (`scratch/A1/modifier-check.js`) finds that `warn` on `badge warn` is the only class in the renderer that never combines with its base in any rule; computed style of the live badge is `color: rgb(52,211,153)` on `rgba(52,211,153,0.13)` (the ok/ed25519 green). Screenshot `1100x720-connect-assistant.png` shows "KEY MISSING" in a green chip beside the server name.
- **Why it is a flaw:** an actionable error (the server cannot connect without its key) is drawn in the colour the app uses for healthy/Ed25519 items, so the badge communicates the opposite of its text.
- **Proposed fix:** extend the rule to `.badge.pub, .badge.ghost, .badge.warn { background: rgba(var(--warn-rgb), .13); color: var(--warn) }` (drop the unused `.ghost`).
- **Confidence:** confirmed
- **Effort:** S

