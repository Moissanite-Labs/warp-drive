#!/usr/bin/env python3
"""Six site checks. Stdlib only.
1 expeditions JSON shape, matching studies/ on the tree
2 links and anchors resolve  3 meta and OG rules
4 no third-party scripts  5 static counts match the tree (modules, lines,
test files, studies, canaries, blueprints, baked expedition cards) and agree
across pages  6 forbidden strings."""
import json, re, sys
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
SITE = "https://moissanite-labs.github.io/warp-drive/"
errors = []
def fail(msg): errors.append(msg)

# Tree-derived counts: the static site copy must match these exactly.
MODS = {p.name: p.read_bytes().count(b"\n") for p in sorted((ROOT / "src" / "warp_modeld").glob("*.py"))}
TEST_FILES = sorted((ROOT / "tests").glob("test_*"))
STUDIES = sorted(d.name for d in (ROOT / "studies").iterdir() if d.is_dir())
_canaries = json.loads((ROOT / "schemas" / "verifier-canaries.json").read_text())
N_CANARIES = len(_canaries["canaries"] if isinstance(_canaries, dict) else _canaries)
BLUEPRINTS = {str(p.relative_to(ROOT)): p.stat().st_size
              for p in sorted((ROOT / "blueprints").rglob("*")) if p.is_file()}

# 1. Expeditions data shape (hand check of the draft-07 schema fields).
data = json.loads((DOCS / "data/expeditions.json").read_text())
slugs = [r["slug"] for r in data["records"]]
if slugs != sorted(set(slugs), key=slugs.index) or len(slugs) != len(set(slugs)):
    fail("expeditions slugs not unique")
for r in data["records"]:
    for k in ("slug", "name", "kind", "summary", "verdicts", "has_certificate", "pinned_commit", "git_last_touch", "repo_path"):
        if k not in r: fail(f"record {r.get('slug')} missing {k}")
    if r.get("kind") not in ("study", "demo"): fail(f"bad kind {r.get('slug')}")
    pc = r.get("pinned_commit")
    if pc is not None and (not isinstance(pc, list) or not all(isinstance(x, str) and x for x in pc)):
        fail(f"record {r.get('slug')} pinned_commit must be null or a list of strings")
    if not (ROOT / r["repo_path"]).exists(): fail(f"record {r.get('slug')} repo_path not on tree: {r['repo_path']}")
study_slugs = sorted(r["slug"] for r in data["records"] if r["kind"] == "study")
if study_slugs != STUDIES:
    fail(f"expeditions.json studies {study_slugs} != studies/ dirs {STUDIES}")

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
# 5. Static counts must match the tree and agree across pages.
all_text = "\n".join(p.read_text() for p in pages)
home = (DOCS / "index.html").read_text()
arch = (DOCS / "architecture" / "index.html").read_text()
ver = (DOCS / "verifier" / "index.html").read_text()
exp = (DOCS / "expeditions" / "index.html").read_text()
bp = (DOCS / "blueprints" / "index.html").read_text()
mmap = (DOCS / "assets" / "module-map.js").read_text()

n_mod, total_lines = len(MODS), sum(MODS.values())
rows = {k: int(v) for k, v in re.findall(r'<th scope="row"><code>([^<]+)</code></th><td>(\d+)</td>', arch)}
if rows != MODS: fail("architecture module table drifted from src/warp_modeld")
if f"Total: {total_lines} lines" not in arch: fail(f"architecture total line drifted (want {total_lines})")
if f"Exact: {n_mod} modules, {total_lines} lines" not in arch: fail("architecture chip drifted from tree")
if f"All {n_mod} modules in src/warp_modeld." not in arch: fail("architecture heading drifted from tree")
if f"all {n_mod} modules" not in arch: fail("architecture meta description drifted from tree")
js_mods = {k: int(v) for k, v in re.findall(r'\["([^"]+)", (\d+),', mmap)}
if js_mods != MODS: fail("module-map.js MODULES drifted from src/warp_modeld")
big = max(MODS, key=MODS.get)
if f"Map of the {n_mod} modules" not in mmap or f"{big} at {MODS[big]} lines" not in mmap:
    fail("module-map.js aria-label drifted from tree")

# Home meta splits by commit: main-true counts carry the main label, runner
# totals carry the branch-head label and name the command that produced them.
pt_pass = pt_skip = None
m_main = re.search(r"counted at main ([0-9a-f]+): (\d+) modules · (\d+) canaries", home)
if not m_main:
    fail("home main-count line missing or malformed")
elif (int(m_main.group(2)), int(m_main.group(3))) != (n_mod, N_CANARIES):
    fail("home main-count line drifted from tree")
m_br = re.search(r"counted on this branch head \(main ([0-9a-f]+) plus PR 42's test file\): (\d+) test files\b.*?pytest (\d+) passed, (\d+) skipped", home)
if not m_br:
    fail("home branch-count line missing or malformed")
else:
    if int(m_br.group(2)) != len(TEST_FILES):
        fail("home branch test-file count drifted from tree")
    pt_pass, pt_skip = m_br.group(3), m_br.group(4)
if m_main and m_br and m_main.group(1) != m_br.group(1):
    fail("home branch label names a different main sha than the main-count line")
for cmd in ("PYTHONPATH=src python3 -B -m pytest -q tests/",
            "PYTHONPATH=src python3 -B -m unittest discover -s tests",
            "ls tests/test_*.py | wc -l"):
    if cmd not in home: fail(f"home branch counts do not name the command: {cmd}")
if pt_pass is not None:
    if f"pytest {pt_pass} passed and {pt_skip} skipped" not in ver:
        fail("verifier pytest line disagrees with home")
    if "counted on this branch head" not in ver:
        fail("verifier runner totals not labelled as counted on this branch head")
for cmd in ("PYTHONPATH=src python3 -B -m pytest -q tests/",
            "PYTHONPATH=src python3 -B -m unittest discover -s tests"):
    if cmd not in ver: fail(f"verifier counts do not name the command: {cmd}")
mu = re.search(r"unittest (\d+) ran and (\d+) skipped", ver)
if not mu: fail("verifier unittest line missing")
elif f"unittest alone runs {mu.group(1)} and skips {mu.group(2)}" not in home:
    fail("home unittest line disagrees with verifier")
if pt_pass is not None and f"inside the {pt_pass} passed count" not in bp:
    fail("blueprints pytest reference disagrees with home")
if "counted on this branch head" not in bp:
    fail("blueprints runner reference not labelled as counted on this branch head")
mc = re.search(r"pytest (\d+) passed, (\d+) skipped, (\d+) collected", home)
if not mc: fail("home tests card missing the pytest collected figure")
elif pt_pass is not None and (mc.group(1), mc.group(2)) != (pt_pass, pt_skip):
    fail("home tests card pytest figures disagree with the home meta line")
elif int(mc.group(3)) != int(mc.group(1)) + int(mc.group(2)):
    fail("home collected figure != passed + skipped")
mm_home = re.search(r"At main ([0-9a-f]+) itself: pytest (\d+) passed, (\d+) skipped; unittest (\d+) ran, (\d+) skipped", home)
mm_ver = re.search(r"At main ([0-9a-f]+) itself: pytest (\d+) passed, (\d+) skipped; unittest (\d+) ran, (\d+) skipped", ver)
if not mm_home: fail("home missing the 'At main itself' figures")
if not mm_ver: fail("verifier missing the 'At main itself' figures")
if mm_home and mm_ver and mm_home.groups() != mm_ver.groups():
    fail("home and verifier 'At main itself' figures disagree")
if f"{N_CANARIES} canaries" not in ver or f"{N_CANARIES} canaries" not in home: fail("canary count drifted from schema")
cb = len(re.findall(r"def test_", (ROOT / "tests" / "test_cerebras_client.py").read_text()))
if f"{cb} tests in tests/test_cerebras_client.py" not in ver: fail("cerebras test count drifted from tree")
nb = len(re.findall(r"def test_", (ROOT / "tests" / "test_blueprints.py").read_text()))
if f"{nb} passing tests" not in bp or f"{nb} blueprint tests" not in bp: fail("blueprint test count drifted from tree")
if (f"the {len(BLUEPRINTS)} blueprint files" not in bp or f"The {len(BLUEPRINTS)} blueprint files." not in bp
        or f"Exact: {len(BLUEPRINTS)} files" not in bp or f"The {len(BLUEPRINTS)} blueprint files" not in bp):
    fail("blueprints page file count drifted from tree")
lis = re.findall(r"<li>(.*?)</li>", bp, re.S)
for path, size in BLUEPRINTS.items():
    li = next((x for x in lis if path in x), None)
    if li is None or f"{size} bytes" not in li: fail(f"blueprints page entry drifted for {path} ({size} bytes)")
if f"{len(STUDIES)} dated studies" not in exp: fail("expeditions meta description count drifted from tree")
cnt = re.search(r'<span data-expeditions-count>([^<]+)</span>', exp)
if not cnt or cnt.group(1) != f"{len(STUDIES)} studies and 1 demo lane":
    fail("expeditions count fallback drifted from tree")
for r in data["records"]:
    pins = r.get("pinned_commit")
    want = "Pinned commits: " + (", ".join(pins) if pins else "not declared")
    card = re.search(r'<article class="card" data-slug="' + re.escape(r["slug"]) + r'">(.*?)</article>', exp, re.S)
    if not card: fail(f"baked card missing for {r['slug']}")
    elif want not in card.group(1): fail(f"baked card pinned-commits line drifted for {r['slug']}")
if f"{len(STUDIES)} studies checked parts of the checker" not in home: fail("home expeditions count drifted from tree")
shas = set(re.findall(r"This site cites main at ([0-9a-f]+)", all_text))
if len(shas) != 1: fail(f"footer main sha inconsistent across pages: {sorted(shas)}")
for m in (m_main, m_br, mm_home, mm_ver):
    if m and shas and m.group(1) not in shas:
        fail("a labelled main sha differs from the footer sha")

# 6. Forbidden strings across copy.
if "53-test" in all_text or "53 passing" in all_text: fail("stale 53-test claim present")
if "—" in all_text: fail("em dash present in HTML copy")
if "pytest" not in all_text: fail("missing runner-named pytest line")
if "110 of 112" not in all_text: fail("missing demo leakage line")
for line in all_text.splitlines():
    if "counted at main" in line and re.search(r"pytest|unittest|test files", line):
        fail("a test-runner total is labelled 'counted at main'")

if errors:
    print("site gate: FAIL")
    for e in errors: print(" -", e)
    sys.exit(1)
print("site gate: all checks pass (" + str(len(pages)) + " pages)")
