# redesign: the approved MTI look, built into the web app

## Why

The owner approved a redesign of the web app (`apps/web`), shown as a clickable mock-up on the design board.
Their complaints with the current app, in their words: it feels like a documentation page; the left sidebar is
old-school; there is no dark/light toggle at the top; there are too many lines; link underlines look like
borders; checkboxes and dropdowns are native OS controls; every click feels jittery; the home page looks empty.
Keep the palette and fonts in `apps/web/app/styles/tokens.css` (Geist, Geist Mono, ink on canvas, tangerine
accent, the dark set). Change the layout, surfaces, controls and motion.

## What to build

1. **Shell: no sidebar.** Replace the left sidebar with a floating top bar, sticky 12px from the top, centred,
   max width 1240px, fully rounded, a translucent `--glass` background with `backdrop-filter: blur(18px)` and
   a soft shadow, no border. In order:
   - Brand: a 12px accent dot with a 4px `--accent-soft` ring, "MTI", and "by Motiontic" in muted text.
   - Main links as pills: Discover (`/`), Exploited (exploited-in-the-wild list), Vulnerabilities, Breaches,
     AI incidents. The current page's pill has the `--surface-2` fill.
   - A "More" disclosure menu (a real `<button aria-expanded>` and a list) holding Index A–Z, Malicious
     packages, Techniques, Terms, Cyber operations and Sources. It opens with the drop animation, closes on
     Escape, outside click and navigation.
   - Search: a pill input "Search or ask anything" that submits to `/search?q=`. Add a quick-search palette
     opened by ⌘K / Ctrl+K and by a "⌘K" key button in the input: a dialog with an input, up to 8 matches
     from the existing search API (debounced), arrow keys to move, Enter to open, Escape to close, focus
     trapped and returned. Without JavaScript the input still submits.
   - Theme toggle: a two-button segmented control (moon, sun) with a sliding thumb. It sets `data-theme` on
     `<html>`, stores the choice in a cookie (so the server renders the right theme, no flash) and falls back
     to `prefers-color-scheme` when no choice is stored. If any script is needed before paint, it must carry
     the request's CSP nonce.
   - Account: Log in (ghost pill) and Sign up free (solid pill) when signed out; the user button when signed
     in.
   - Below 900px the bar wraps: brand, theme, account and a menu button on the first row, search on the
     second, and the links (including the More items, expanded) in a panel that the menu button opens.
   The footer becomes one quiet line of muted text and links, no top border.
2. **Surfaces and lines.** Add tokens for both themes and use them everywhere: `--surface`, `--surface-2`,
   `--hover`, `--glass`, `--lift` (shadow), `--accent-ink`, `--e-out: cubic-bezier(.16,1,.3,1)`,
   `--e-io: cubic-bezier(.65,0,.35,1)` (values in the appendix). Remove borders and divider lines from cards,
   panels, list rows, tables, filters, tabs, the header and footer. Separate things with surface colour,
   spacing and radius (cards 20-24px, rows 12-14px, pills 999px). Table rows separate by hover tint, not
   rules.
3. **Links.** No resting underline anywhere. Inline text links get an underline that draws in from the left
   on hover (`background-size` or a scaled pseudo-element, 0.25-0.28s `--e-out`). Navigation, cards and rows
   are not underlined at all; they answer with a background tint.
4. **Controls drawn by MTI.** No native-looking control remains:
   - Checkboxes and radios: `appearance: none`, 20px, 7px radius (circle for radio), `--surface-2` fill,
     accent fill with a dark tick when checked; the tick animates in; press scales to 0.9; visible focus ring.
   - Every `<select>` (search filters and sort in `routes/search.tsx`, the account settings in
     `routes/account.tsx`) becomes a themed dropdown: a button showing the value with a chevron that rotates,
     and a listbox (role="listbox", options role="option", aria-selected, a tick on the chosen one) with
     arrow, Enter, Escape and Tab handling. It must still work without JavaScript: render the native select
     on the server and swap in the themed one after hydration, keeping the same form field name and value.
   - Sort becomes a segmented control where it has two or three choices.
   - Entry page tabs become a pill segmented control with a sliding indicator.
   - Switches (alerts settings): 44x26 track, sliding knob.
5. **Home page.** Keep the home-latest data and panels, arranged as on the mock-up: a status pill ("Updated
   every 3 hours from N public sources"), the big headline "Every vulnerability, exploit and breach, *as it
   happens.*" with the accent on the last words, the lede, a large ask/search box (sparkle icon, accent
   Search button), suggestion pills, count tiles as plain surface cards (the exploited one in accent), then
   a "Latest" heading and a 12-column bento grid: exploited in the wild (7 columns), what changed (5), new
   vulnerabilities, public exploits and breaches (4 each), AI incidents and malicious packages (6 each).
   Empty panels keep the honest empty state from home-latest, styled as a soft surface.
6. **Motion.** Durations: press and hover 120-150ms; toggles, menus, tabs 200-240ms; overlays and page
   content 240-300ms; theme change 280ms (`--e-io`). Only `transform` and `opacity` animate (plus colour and
   background for hover and theme). Buttons scale to 0.97 on press. On navigation the top bar stays still and
   only the page content fades up 6px; never blank the whole page. Show a thin accent progress bar at the top
   while a navigation is pending (React Router's navigation state) so a click answers at once. Hover styles
   only under `@media (hover: hover)`. Everything respects `prefers-reduced-motion`.
7. **Every page.** Apply the new look to every route: home, search, entry, breach, incident, technique and
   their lists, index A-Z, sources, account, ops, sign-in/sign-up wrappers (Clerk's forms keep their current
   appearance config), not found and error pages.
8. **Tests and QA.**
   - Update tests that assert the old markup. Add tests: theme cookie read on the server and set by the
     toggle; the themed dropdown keeps the form value and handles keys; the More menu and the palette open,
     close on Escape and return focus; the active nav pill follows the route.
   - QA in the browser, in both themes and at 1440px and 375px: home, search with a filter and a sort
     change, an entry page with tab switches, the palette, the More menu, the mobile menu, sign-in. Save
     screenshots in the proof.

## Constraints

- The CSP allows no inline `style` attributes on server HTML (the smoke check fails on `style="`), and scripts
  need the nonce. Put all styles in CSS files. Do not loosen `apps/web/app/lib/security.server.ts`.
- Do not change `apps/web/scripts/smoke.mjs` except to add checks.
- No new dependencies and no change to `pnpm-lock.yaml`; build the dropdown, palette and menus yourself.
- Keep accessibility: real buttons and links, labels, focus rings, 44px touch targets, 4.5:1 text contrast in
  both themes.

## Files this loop owns

`apps/web/app/**` (components, routes, styles, lib, root), `apps/web/test/**`, `apps/web/public/**`.
Not the API, collector, packages or migrations.

## Acceptance criteria

1. `pnpm build` and `pnpm test:workers` pass.
2. No `<select>`, checkbox or radio renders with the browser's own look after hydration (checked in QA).
3. No border or divider line on cards, rows, panels, tables, tabs, header or footer (checked in QA and by a
   grep of the CSS for `border` declarations, each remaining one justified in the proof).
4. The QA screenshots in the proof cover the pages and states listed in 8.

## Appendix: the board mock-up's style layer (reference values)

The approved mock-up is a vanilla HTML page; its redesign is this CSS layer on top of the old styles. Use it
for values (tokens, radii, durations, curves, sizes); translate class names to the app's own components.

```css

/* ===== MTI redesign layer (24 Nov 2026). Same palette; no sidebar, fewer lines, smooth motion. ===== */
:root{
  --e-out:cubic-bezier(.16,1,.3,1); --e-io:cubic-bezier(.65,0,.35,1);
  --surface:#FFFFFF; --surface-2:#EFEEE9; --hover:rgba(18,18,18,.045); --glass:rgba(255,255,255,.76);
  --canvas:#F6F5F1; --paper:#FFFFFF; --ink-3:#66655F; --na:rgba(18,18,18,.05);
  --lift:0 1px 2px rgba(18,18,18,.04),0 10px 28px rgba(18,18,18,.06); --accent-ink:#B4501C;
}
@media (prefers-color-scheme: dark){
  :root:not([data-theme="light"]){
    --canvas:#0F0F0E; --paper:#181816; --surface:#181816; --surface-2:#22221F; --hover:rgba(242,241,236,.06);
    --glass:rgba(24,24,22,.72); --ink-3:#97958C; --na:rgba(242,241,236,.06); --accent-soft:rgba(242,144,94,.14);
    --lift:0 1px 0 rgba(255,255,255,.04) inset,0 10px 30px rgba(0,0,0,.35); --accent-ink:#F5A77E; --tile:rgba(201,204,247,.1);
  }
}
:root[data-theme="dark"]{
  --canvas:#0F0F0E; --paper:#181816; --surface:#181816; --surface-2:#22221F; --hover:rgba(242,241,236,.06);
  --glass:rgba(24,24,22,.72); --ink-3:#97958C; --na:rgba(242,241,236,.06); --accent-soft:rgba(242,144,94,.14);
  --lift:0 1px 0 rgba(255,255,255,.04) inset,0 10px 30px rgba(0,0,0,.35); --accent-ink:#F5A77E; --tile:rgba(201,204,247,.1);
}
body{font-size:15px;transition:background-color .28s var(--e-io),color .28s var(--e-io)}
a{text-decoration:none}
:focus-visible{border-radius:10px}
kbd,.kb{border:0;background:var(--hover);border-radius:7px;padding:2px 7px;font-family:"Geist Mono",monospace;font-size:11px;color:var(--ink-3)}
/* links inside text: no resting underline, one draws in on hover */
.prose a,.dl dd a,.credit a,.note a,.gate a,.crumbs a,.sitefoot a,.rs a,.muted a,.card2 a:not(.ibtn),.feed a{color:var(--ink);background-image:linear-gradient(var(--accent),var(--accent));background-size:0 1px;background-repeat:no-repeat;background-position:0 100%;transition:background-size .28s var(--e-out),color .15s var(--e-out)}
.prose a:hover,.dl dd a:hover,.credit a:hover,.note a:hover,.gate a:hover,.crumbs a:hover,.sitefoot a:hover,.rs a:hover,.muted a:hover,.card2 a:not(.ibtn):hover,.feed a:hover{background-size:100% 1px}
.prose a{color:var(--accent-ink)}
/* banner */
.banner{background:var(--hover);color:var(--ink-2);margin:10px auto 0;max-width:1240px;border-radius:999px;padding:6px 44px 6px 16px}
.banner a{color:var(--ink)}
/* shell: floating top bar, no sidebar */
.app{display:block;min-height:100vh}
.rail{display:none}
.bar{position:sticky;top:12px;z-index:30;display:flex;align-items:center;gap:6px;max-width:1240px;margin:12px auto 0;padding:6px;border-radius:999px;background:var(--glass);-webkit-backdrop-filter:saturate(1.4) blur(18px);backdrop-filter:saturate(1.4) blur(18px);box-shadow:var(--lift)}
.bar .brand{display:flex;align-items:center;gap:9px;height:40px;padding:0 12px 0 10px;flex:none}
.bar .brand .dot{margin:0;width:12px;height:12px;box-shadow:0 0 0 4px var(--accent-soft)}
.bar .brand b{display:inline;font-weight:600}
.bar .brand small{display:inline;font-size:12.5px;color:var(--ink-3)}
.nav{flex-direction:row;align-items:center;gap:2px;flex:none}
.nav > a,.nav summary{height:40px;display:inline-flex;align-items:center;gap:6px;padding:0 13px;border-radius:999px;color:var(--ink-2);font-size:14px;cursor:pointer;list-style:none;transition:background-color .15s var(--e-out),color .15s var(--e-out)}
.nav summary::-webkit-details-marker{display:none}
.nav > a:hover,.nav summary:hover{background:var(--hover);color:var(--ink)}
.nav > a.on,.nav details.on > summary{background:var(--surface-2);color:var(--ink)}
.nav summary svg{transition:transform .25s var(--e-out)}
.nav details[open] summary svg{transform:rotate(180deg)}
.nav details{position:relative}
.nav .drop{position:absolute;top:48px;left:0;min-width:240px;padding:6px;background:var(--surface);border-radius:16px;box-shadow:0 18px 50px rgba(0,0,0,.28),0 0 0 1px var(--hover);display:flex;flex-direction:column;transform-origin:top left;animation:drop .2s var(--e-out)}
.nav .drop a{display:flex;justify-content:space-between;align-items:center;gap:10px;min-height:40px;padding:0 12px;border-radius:10px;color:var(--ink-2);font-size:14px;transition:background-color .12s var(--e-out),color .12s}
.nav .drop a:hover,.nav .drop a.on{background:var(--hover);color:var(--ink)}
.nav .drop a .c{font-family:"Geist Mono",monospace;font-size:11px;color:var(--ink-3)}
#topForm{position:relative;flex:1 1 200px;max-width:340px;margin-left:auto}
#topForm .ico{position:absolute;left:14px;top:50%;transform:translateY(-50%);color:var(--ink-3)}
#topForm input{width:100%;height:40px;border:0;border-radius:999px;background:var(--hover);padding:0 54px 0 38px;font-size:14px;transition:background-color .15s var(--e-out),box-shadow .15s var(--e-out)}
#topForm input:hover{background:var(--surface-2)}
#topForm input:focus{outline:none;background:var(--surface-2);box-shadow:0 0 0 2px var(--accent-soft)}
#topForm .kb{position:absolute;right:8px;top:50%;transform:translateY(-50%);cursor:pointer;background:var(--surface)}
.theme{position:relative;display:inline-flex;flex:none;padding:3px;border-radius:999px;background:var(--hover)}
.theme button{position:relative;z-index:1;width:34px;height:34px;border:0;background:transparent;color:var(--ink-3);border-radius:999px;display:grid;place-items:center;cursor:pointer;transition:color .2s var(--e-out)}
.theme button[aria-pressed="true"]{color:var(--ink)}
.theme .thumb{position:absolute;top:3px;left:3px;width:34px;height:34px;border-radius:999px;background:var(--surface);box-shadow:var(--lift);transition:transform .3s var(--e-out)}
.theme.is-light .thumb{transform:translateX(34px)}
.authwrap{margin-left:0;flex:none}
.menu{display:none}
#view{max-width:1240px;margin:0 auto;padding:40px 24px 40px}
#view.rise{animation:rise .3s var(--e-out)}
@keyframes rise{from{opacity:0;transform:translateY(6px)}}
@keyframes drop{from{opacity:0;transform:translateY(-4px) scale(.98)}}
@keyframes pop{from{opacity:0;transform:translateY(10px) scale(.98)}}
.sitefoot{max-width:1240px;margin:0 auto;padding:24px 24px 48px;display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;font-size:13px;color:var(--ink-3)}
.sitefoot span:last-child{display:flex;gap:18px}
.sitefoot a{color:var(--ink-3)}
/* buttons */
.ibtn{border:0;background:var(--hover);color:var(--ink);border-radius:999px;height:40px;padding:0 16px;font-size:14px;transition:background-color .15s var(--e-out),transform .12s var(--e-out),opacity .15s}
.ibtn:hover{background:var(--surface-2);color:var(--ink)}
.ibtn:active,.bigs button:active,.primary:active,.pill:active,.tile:active{transform:scale(.97)}
.ibtn.pri{background:var(--ink);color:var(--canvas)}
.ibtn.pri:hover{opacity:.88;background:var(--ink)}
.ibtn.on{background:var(--accent-soft);color:var(--ink)}
.avatar{border:0;width:40px;height:40px;background:var(--accent-soft);color:var(--accent-ink)}
/* chips and type badges stay; quieter */
.ch.ghost{border:0;background:var(--hover)}
/* home */
.hero{max-width:none;padding:48px 0 8px;display:flex;flex-direction:column;gap:18px}
.hero .live{display:inline-flex;align-items:center;gap:8px;width:max-content;height:30px;padding:0 12px;border-radius:999px;background:var(--hover);font-size:13px;color:var(--ink-2)}
.hero .live i{width:7px;height:7px;border-radius:50%;background:#3CCF91;animation:pulse 2.4s var(--e-out) infinite}
@keyframes pulse{0%{box-shadow:0 0 0 0 rgba(60,207,145,.45)}70%{box-shadow:0 0 0 8px rgba(60,207,145,0)}100%{box-shadow:0 0 0 0 rgba(60,207,145,0)}}
.hero h1{font-size:clamp(38px,5.2vw,70px);line-height:1;letter-spacing:-.045em;margin:0;max-width:15ch;text-wrap:balance}
.lede{margin:0;max-width:64ch;font-size:18px;text-wrap:pretty}
.bigs{max-width:860px;align-items:center;gap:0;background:var(--surface);border-radius:22px;box-shadow:var(--lift);padding:8px 8px 8px 0;transition:box-shadow .2s var(--e-out)}
.bigs:focus-within{box-shadow:0 0 0 2px var(--accent-soft),var(--lift)}
.bigs .ico{position:static;transform:none;margin:0 6px 0 18px;color:var(--ink-3);flex:none}
.bigs input{border:0;box-shadow:none;background:transparent;padding:12px 8px;font-size:17px}
.bigs input:focus{outline:none}
.bigs button{height:48px;border-radius:16px;background:var(--accent);color:#141413;transition:transform .12s var(--e-out),opacity .15s}
.bigs button:hover{opacity:.9}
.sugg{margin:0}
.pill{border:0;background:var(--hover);height:34px;display:inline-flex;align-items:center;padding:0 14px;font-size:13.5px;transition:background-color .15s var(--e-out),color .15s var(--e-out)}
.pill:hover{background:var(--surface-2);color:var(--ink)}
.tiles{gap:14px;margin:28px 0 8px}
.tile{background:var(--surface);border-radius:22px;padding:18px 20px;transition:transform .2s var(--e-out)}
.tile:hover{transform:translateY(-2px)}
.tile .n{font-size:30px;color:var(--ink);letter-spacing:-.035em}
.tile .l{color:var(--ink-3);font-size:13px}
.tile.hot{background:var(--surface)}.tile.hot .n{color:var(--accent)}
.sec2{display:flex;align-items:baseline;justify-content:space-between;gap:16px;margin:48px 0 14px}
.sec2 h2{margin:0;font-size:26px;letter-spacing:-.03em;font-weight:600}
.bento{display:grid;grid-template-columns:repeat(12,minmax(0,1fr));gap:16px}
.bento .s7{grid-column:span 7}.bento .s5{grid-column:span 5}.bento .s4{grid-column:span 4}.bento .s6{grid-column:span 6}
.panel{border:0;box-shadow:none;background:var(--surface);border-radius:24px;padding:16px 10px 10px;min-width:0}
.panel + .panel{margin-top:0}
.ph{padding:2px 12px 10px;align-items:center}
.ph h3{font-size:15px;display:flex;align-items:center;gap:8px}
.ph h3 i{width:8px;height:8px;border-radius:50%;background:var(--accent)}
.ph a.see{position:relative;color:var(--ink-3);font-size:13px;transition:color .15s var(--e-out)}
.ph a.see::after{content:"";position:absolute;left:0;right:0;bottom:-2px;height:1px;background:currentColor;transform:scaleX(0);transform-origin:right;transition:transform .25s var(--e-out)}
.ph a.see:hover{color:var(--ink)}.ph a.see:hover::after{transform:scaleX(1);transform-origin:left}
.row{border-top:0;padding:9px 12px;border-radius:14px;min-height:44px;transition:background-color .15s var(--e-out)}
.row:hover{background:var(--hover)}
.row:hover .rt2{text-decoration:none}
.rt2{font-weight:400}
.feed{display:flex;flex-direction:column;gap:2px}
.feed li{border-top:0;padding:9px 12px;border-radius:14px;grid-template-columns:52px 1fr;transition:background-color .15s var(--e-out)}
.feed li:hover{background:var(--hover)}
.browse{padding:0 2px 4px}
.browse a{border:0;background:var(--hover);border-radius:14px;min-height:44px;transition:background-color .15s var(--e-out)}
.browse a:hover{background:var(--surface-2)}
.empty{border:0;background:var(--hover);border-radius:18px;color:var(--ink-2)}
.panel .empty{margin:6px 2px 2px}
/* search */
.sh h2{font-size:34px;letter-spacing:-.04em}
.sgrid{grid-template-columns:260px minmax(0,1fr);gap:24px;align-items:start}
.filters{position:sticky;top:84px;background:var(--surface);border-radius:24px;padding:18px}
.fg label{min-height:40px;padding:6px 8px;margin:0 -8px;border-radius:12px;gap:12px;font-size:14px;transition:background-color .15s var(--e-out)}
.fg label:hover{background:var(--hover)}
.clear{text-decoration:none;position:relative}
.clear::after{content:"";position:absolute;left:0;right:0;bottom:-1px;height:1px;background:currentColor;transform:scaleX(0);transform-origin:right;transition:transform .25s var(--e-out)}
.clear:hover{color:var(--ink)}.clear:hover::after{transform:scaleX(1);transform-origin:left}
.res{border:0;box-shadow:none;background:var(--surface);border-radius:20px;padding:18px 20px;transition:transform .2s var(--e-out),box-shadow .2s var(--e-out)}
.res:hover{border:0;transform:translateY(-2px);box-shadow:var(--lift)}
.rt{font-size:17px}
/* custom checkboxes and radios */
input[type="checkbox"],input[type="radio"]{-webkit-appearance:none;appearance:none;flex:none;width:20px;height:20px;margin:0;border-radius:7px;background:var(--surface-2);display:inline-grid;place-items:center;cursor:pointer;transition:background-color .18s var(--e-out),transform .12s var(--e-out)}
input[type="radio"]{border-radius:50%}
input[type="checkbox"]::after{content:"";width:9px;height:5px;margin-top:-2px;border-left:2px solid #141413;border-bottom:2px solid #141413;transform:rotate(-45deg) scale(0);transition:transform .2s var(--e-out)}
input[type="radio"]::after{content:"";width:8px;height:8px;border-radius:50%;background:#141413;transform:scale(0);transition:transform .2s var(--e-out)}
input[type="checkbox"]:checked,input[type="radio"]:checked{background:var(--accent)}
input[type="checkbox"]:checked::after{transform:rotate(-45deg) scale(1)}
input[type="radio"]:checked::after{transform:scale(1)}
input[type="checkbox"]:active,input[type="radio"]:active{transform:scale(.9)}
/* themed dropdowns (built from each <select> by enhanceSelects) */
.xsel{position:relative;display:inline-block;min-width:150px}
.fg .xsel{display:block}
.xsel select{position:absolute;opacity:0;pointer-events:none;width:1px;height:1px}
.xsel-b{width:100%;height:40px;display:flex;align-items:center;gap:8px;padding:0 12px 0 14px;border:0;border-radius:12px;background:var(--hover);font-size:14px;cursor:pointer;text-align:left;transition:background-color .15s var(--e-out)}
.xsel-b:hover{background:var(--surface-2)}
.xsel-b span{flex:1}
.xsel-b svg{color:var(--ink-3);transition:transform .25s var(--e-out)}
.xsel-b[aria-expanded="true"] svg{transform:rotate(180deg)}
.xsel-m{position:absolute;z-index:40;left:0;right:0;top:46px;min-width:180px;max-height:300px;overflow:auto;margin:0;padding:6px;list-style:none;background:var(--surface);border-radius:14px;box-shadow:0 18px 50px rgba(0,0,0,.28),0 0 0 1px var(--hover);animation:drop .2s var(--e-out)}
.xsel-m[hidden]{display:none}
.xsel-m button{width:100%;display:flex;align-items:center;gap:8px;min-height:38px;padding:0 10px;border:0;border-radius:10px;background:transparent;font-size:14px;cursor:pointer;text-align:left;transition:background-color .12s var(--e-out)}
.xsel-m button:hover,.xsel-m button:focus{background:var(--hover);outline:none}
.xsel-m .tick{width:14px;color:var(--accent);opacity:0}
.xsel-m button[aria-selected="true"] .tick{opacity:1}
.sh .sort .xsel{min-width:170px}
/* entry */
.crumbs a{color:var(--ink-3)}
.eh h1{font-size:clamp(28px,3.6vw,44px);letter-spacing:-.035em;line-height:1.08}
.tabs{display:inline-flex;max-width:100%;gap:2px;padding:4px;border-bottom:0;border-radius:999px;background:var(--hover)}
.tabs a{border-bottom:0;margin:0;border-radius:999px;padding:8px 14px;color:var(--ink-3);transition:background-color .2s var(--e-out),color .2s var(--e-out)}
.tabs a:hover{color:var(--ink)}
.tabs a.on{background:var(--surface);color:var(--ink);box-shadow:var(--lift)}
.todo{border-left:0;background:var(--surface);border-radius:18px}
.gate{border:0;background:var(--accent-soft);border-radius:16px}
.tbl{border:0;background:var(--surface);border-radius:18px;border-collapse:separate;border-spacing:0}
.tbl th{border-bottom:0;background:transparent;padding:12px 14px 6px}
.tbl td{border-bottom:0;padding:10px 14px}
.tbl tbody tr{transition:background-color .15s var(--e-out)}
.tbl tbody tr:hover{background:var(--hover)}
.tl li::before{background:var(--hover)}
.glance{border:0;background:var(--surface);border-radius:24px;padding:10px 20px;top:84px}
.gi{border-bottom:0;padding:12px 0}
.checker{border:0;background:var(--surface);border-radius:18px}
.checker input{border:0;background:var(--hover);border-radius:10px;height:38px}
.credit{border-top:0;padding-top:0}
/* index */
.letters a,.letters span{border:0;border-radius:10px;width:34px;height:34px;transition:background-color .15s var(--e-out)}
.letters a{background:var(--hover)}
.letters a:hover{background:var(--surface-2)}
.letters a.on{background:var(--ink);color:var(--canvas)}
.ltr{border-bottom:0;padding-bottom:0}
.gl a{border-bottom:0;padding:10px 12px;margin:0 -12px;border-radius:12px;transition:background-color .15s var(--e-out)}
.gl a:hover{background:var(--hover)}
.gl a:hover b{text-decoration:none}
.typebar a{border:0;background:var(--hover);height:34px;display:inline-flex;align-items:center;padding:0 14px;transition:background-color .15s var(--e-out)}
.typebar a:hover{background:var(--surface-2)}
.typebar a.on{background:var(--ink);color:var(--canvas)}
/* overlays */
.ov{background:rgba(10,10,9,.42);-webkit-backdrop-filter:blur(6px);backdrop-filter:blur(6px);animation:fadein .2s var(--e-out)}
@keyframes fadein{from{opacity:0}}
.pal,.mod,.amod{border:0;border-radius:22px;background:var(--surface);box-shadow:0 30px 90px rgba(0,0,0,.45);animation:pop .24s var(--e-out)}
.pal .pin{border-bottom:0}
.pal li a{border-radius:12px;min-height:44px;transition:background-color .12s var(--e-out)}
.pal li.sel a{background:var(--hover)}
.pal .ft{border-top:0;background:var(--hover)}
.mod .mh{border-bottom:0}
.umenu{border:0;border-radius:16px;background:var(--surface);box-shadow:0 18px 50px rgba(0,0,0,.28),0 0 0 1px var(--hover);animation:drop .2s var(--e-out)}
.umenu .who{border-bottom:0;background:var(--hover);border-radius:12px;margin-bottom:6px}
.umenu a,.umenu button{border-radius:10px;transition:background-color .12s var(--e-out)}
.sso button{border:0;background:var(--hover);border-radius:12px;min-height:44px;transition:background-color .15s var(--e-out)}
.sso button:hover{background:var(--surface-2)}
.or::before,.or::after{display:none}
.inp{border:0;background:var(--hover);border-radius:12px;min-height:44px;transition:background-color .15s var(--e-out),box-shadow .15s var(--e-out)}
.inp:focus{outline:none;background:var(--surface-2);box-shadow:0 0 0 2px var(--accent-soft)}
.primary{border-radius:999px;min-height:44px;transition:transform .12s var(--e-out),background-color .15s var(--e-out),color .15s}
.afoot button{text-decoration:none;color:var(--accent-ink)}
.anote{border-top:0}
.lock .gatecard > div{border:0;border-radius:22px;background:var(--surface);box-shadow:0 24px 70px rgba(0,0,0,.3)}
/* account */
.acct nav a{border-radius:999px;transition:background-color .15s var(--e-out)}
.acct nav a:hover{background:var(--hover)}
.card2{border:0;border-radius:22px;background:var(--surface)}
.wl{border-top:0;padding:10px 12px;margin:0 -12px;border-radius:12px;transition:background-color .15s var(--e-out)}
.wl:hover{background:var(--hover)}
.switch{width:44px;height:26px;background:var(--surface-2);transition:background-color .2s var(--e-out)}
.switch::after{top:3px;left:3px;width:20px;height:20px;background:var(--ink);transition:left .28s var(--e-out),background-color .2s}
.switch[aria-checked="true"]::after{left:21px;background:#141413}
.toast{border-radius:999px;padding:10px 16px;transform:translateX(-50%) translateY(8px);transition:opacity .2s var(--e-out),transform .25s var(--e-out)}
.toast.show{transform:translateX(-50%)}
/* responsive */
@media (max-width:1100px){.bento > *{grid-column:span 12 !important}.nav > a:nth-child(n+4){display:none}}
@media (max-width:900px){
  .bar{flex-wrap:wrap;border-radius:24px}
  .nav{display:none;order:9;flex-basis:100%;flex-direction:column;align-items:stretch;padding:6px 0 2px}
  .bar.open .nav{display:flex}
  .nav > a{display:flex !important;border-radius:12px}
  .nav details{display:block}
  .nav summary{display:flex;width:100%;border-radius:12px}
  .nav .drop{position:static;display:flex;box-shadow:none;background:transparent;padding:0 0 0 10px;animation:none}
  .bigs input{min-width:0}
  .bigs button{flex:none;padding:0 16px}
  #topForm{order:3;max-width:none;margin-left:0;flex:1 1 100%}
  .menu{display:inline-flex;margin-left:auto}
  .sgrid{grid-template-columns:1fr}.filters{position:static}
  #view{padding:28px 16px 40px}
  .bar .brand small{display:none}
}
@media (prefers-reduced-motion:reduce){*,*::before,*::after{animation-duration:.01ms !important;animation-iteration-count:1 !important;transition-duration:.01ms !important}}

```
