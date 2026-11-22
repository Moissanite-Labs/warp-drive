#!/usr/bin/env python3
"""Six site checks adapted from f0. Stdlib only.
1 expeditions JSON shape  2 links and anchors resolve  3 meta and OG rules
4 no third-party scripts  5 cross-page number consistency  6 forbidden strings."""
import json, re, sys
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
SITE = "https://moissanite-labs.github.io/warp-drive/"
errors = []
def fail(msg): errors.append(msg)

# 1. Expeditions data shape (hand check of the draft-07 schema fields).
data = json.loads((DOCS / "data/expeditions.json").read_text())
slugs = [r["slug"] for r in data["records"]]
if slugs != sorted(set(slugs), key=slugs.index) or len(slugs) != len(set(slugs)):
    fail("expeditions slugs not unique")
for r in data["records"]:
    for k in ("slug", "name", "kind", "summary", "verdicts", "has_certificate", "git_last_touch", "repo_path"):
        if k not in r: fail(f"record {r.get('slug')} missing {k}")
    if r.get("kind") not in ("study", "demo"): fail(f"bad kind {r.get('slug')}")

class Page(HTMLParser):
    def __init__(self):
        super().__init__(); self.links = []; self.ids = set(); self.meta = {}
        self.scripts = []; self.title = ""; self.lang = ""; self._t = False
    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if a.get("id"): self.ids.add(a["id"])
        if tag == "html": self.lang = a.get("lang", "")
        if tag in ("a", "link") and a.get("href"): self.links.append(a["href"])
        if tag in ("script", "img") and a.get("src"):
            self.links.append(a["src"])
            if tag == "script": self.scripts.append(a["src"])
        if tag == "meta":
            k = a.get("property") or a.get("name")
            if k: self.meta[k] = a.get("content", "")
        if tag == "title": self._t = True
    def handle_endtag(self, tag):
        if tag == "title": self._t = False
    def handle_data(self, d):
        if self._t: self.title += d

pages = sorted(DOCS.rglob("*.html"))
parsed = {}
for p in pages:
    text = p.read_text()
    pg = Page(); pg.feed(text); parsed[p] = pg
    rel = p.relative_to(DOCS)
    own = SITE if str(rel) == "index.html" else SITE + str(rel.parent) + "/" if p.name == "index.html" else SITE
    # 3. Meta rules (404 og:url points home).
    for k in ("description", "og:title", "og:description", "og:image", "twitter:card"):
        if not pg.meta.get(k): fail(f"{rel} missing meta {k}")
    if not pg.title.strip(): fail(f"{rel} missing title")
    if not pg.lang: fail(f"{rel} missing lang")
    if not pg.meta.get("viewport"): fail(f"{rel} missing viewport")
    og_url = pg.meta.get("og:url", "")
    want = SITE if p.name == "404.html" else own
    if og_url != want: fail(f"{rel} og:url {og_url} != {want}")
    og_img = pg.meta.get("og:image", "")
    if og_img.startswith(SITE):
        if not (DOCS / og_img[len(SITE):]).exists(): fail(f"{rel} og:image file missing")
    elif og_img: fail(f"{rel} og:image not under SITE")
    # 2. Links and anchors. 404 uses a base bootstrap, check loosely.
    for href in pg.links:
        if href.startswith(("http://", "https://", "mailto:", "#")):
            if href.startswith("#") and len(href) > 1 and href[1:] not in pg.ids and p.name != "404.html":
                fail(f"{rel} anchor {href} has no id")
            continue
        target = href.split("#")[0]
        if not target: continue
        resolved = (p.parent / target).resolve()
        try: resolved.relative_to(DOCS.resolve())
        except ValueError: fail(f"{rel} link escapes docs: {href}"); continue
        if not resolved.exists() and not (resolved / "index.html").exists():
            fail(f"{rel} broken link {href}")
    # 4. No third-party scripts.
    for s in pg.scripts:
        if s.startswith("http"): fail(f"{rel} third-party script {s}")
# 5 and 6. Consistency and forbidden strings across copy.
all_text = "\n".join(p.read_text() for p in pages)
if "53-test" in all_text or "53 passing" in all_text: fail("stale 53-test claim present")
if "—" in all_text: fail("em dash present in HTML copy")
for needle in ("218 passed", "pytest"):
    if needle not in all_text: fail(f"missing site-safe count text: {needle}")
if "110 of 112" not in all_text: fail("missing demo leakage line")

if errors:
    print("site gate: FAIL")
    for e in errors: print(" -", e)
    sys.exit(1)
print("site gate: all checks pass (" + str(len(pages)) + " pages)")
