# Warp Drive site design guide

Plain HTML, one stylesheet (warp.css), ES modules in this folder, served by
GitHub Pages from docs/. No framework. No build step for the site itself.
The only third-party origin is Google Fonts CSS. No third-party scripts.

## Add a page

Copy the skeleton from any page: head with meta and the theme and motion
bootstrap, SVG sprite, skip link, header, rail nav, footer. Fix the relative
prefix for depth. Set body data-page and data-home-dimension (0 Drift,
1 Slipstream, 2 Lattice, 3 Ledger). Mark the current page with
aria-current="page" in both navs. Run python3 scripts/check_site.py.

## Sections and figures

Sections use section.sec with data-index and data-num, a .wrap, a .sec-head
with a numbered label and a source chip, an h2 and a lede. The rail builds
from data-index. Figure law: title, how-to-read line, source line with a
truth label, a real table twin with caption and scope, keyboard path, both
themes, no horizontal scroll at 320px, rendered text at least 11px.

## Motion law

One shared 30fps loop in warp.js, paused when hidden, idle 60s, or motion
off. ?motion=off and ?theme=dark are the test switches. The Motion toggle
keeps one fixed name plus aria-pressed. The warp canvas is decoration
(aria-hidden). Data figures use role="img" with a conclusion sentence plus
a table twin. Nothing loops on its own. Scroll sets velocity with thrust
0.6 per viewport height, clamp 0.25 per event, cruise 0.06, half-life 900ms
(see warp-velocity.js). One channel, one quantity: bar length and trail
length mean velocity, hue means dimension, Lattice brightness means pointer
distance.

## Tokens and type

Widths: wrap 1320px, read 760px, wide 1040px. Type: Space Grotesk for
headings, Source Serif 4 for prose, IBM Plex Mono for labels and data.
Label floor 11px. Colours live in custom properties only. The style pad
(vendor Eido modules, see vendor/NOTICE) writes --warp-round,
--warp-density, --warp-hue-offset and --warp-contrast. Body ink is a theme
token and is never pad-driven, so pad corners keep body text contrast by
construction. Measured pairs still to record before launch: ink on bg,
ink-2 on bg, ink-3 on bg in both themes (6 ratios). Font fallback metrics
in warp.css are first-pass values. Re-measure before launch.

## Truth labels

Exact means recomputed with a named command at the commit the label names
(main 47de9f2 or this branch head). Documented
means stated in repo docs, not re-run. Planned means PLAN milestones 3
and 4. Never upgrade a label. Test counts always name the runner. The
demo leakage line (110 of 112) sits next to any task count.

## Data

scripts/build_expeditions.py writes docs/data/expeditions.json from
studies/ and the demo manifest. The Expeditions page bakes a static copy
between prerender markers and re-renders from JSON, keeping the bake on
fetch failure. Refresh the bake by hand when JSON changes. CI runs the
builder in --check mode. OG cards come from scripts/make_assets.py and
carry no counts.
