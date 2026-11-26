// Architecture module map. Cell area encodes source lines only.
// Recomputed on resize only, never per frame. The table twin in the HTML
// carries the same numbers for keyboard and screen reader use.
import { layoutCells, layerThreads, hitTest } from "./vendor/cell-layout.js";
const MODULES = [
  ["__init__.py", 196, "Package marker and re-exports"],
  ["fingerprint.py", 864, "Stage 1 checkpoint fingerprints"],
  ["certificate.py", 583, "Stage 2 exact integer certificates"],
  ["canary.py", 1019, "Stage 3 shadow-load canaries"],
  ["llama_client.py", 345, "llama-server HTTP client"],
  ["state_banks.py", 131, "Three state bank model"],
  ["ledger.py", 483, "Stage 4 signed hash-chained ledger"],
  ["verifier.py", 852, "Stage 1 to 4 orchestrator"],
  ["server.py", 379, "Unix socket JSON-RPC server"],
  ["cli.py", 192, "Command line entry points"],
  ["errors.py", 119, "Typed fail-closed errors"],
  ["experiment.py", 1679, "Bounded demo controller"],
  ["cerebras_client.py", 756, "Cerebras client, mocked tests only"],
  ["cerebras_prompts.py", 130, "Fixed Cerebras prompt fixtures"],
];
const host = document.querySelector("[data-module-map]");
if (host) {
  const NS = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(NS, "svg");
  svg.setAttribute("role", "img");
  svg.setAttribute("aria-label", "Map of the 14 modules in src/warp_modeld. Cell area is proportional to source lines. The largest cell is experiment.py at 1679 lines. The full list is in the table below.");
  host.append(svg);
  const stageOf = (n) => n === "fingerprint.py" ? "s1" : n === "certificate.py" ? "s2"
    : n === "canary.py" || n === "llama_client.py" ? "s3" : "other";
  function render() {
    const w = host.clientWidth || 720, h = Math.max(320, Math.round(w * 0.55));
    svg.setAttribute("viewBox", "0 0 " + w + " " + h);
    svg.replaceChildren();
    const items = MODULES.map(([name, lines]) => ({ weight: lines, labelLength: name.length }));
    const layout = layoutCells(items, { width: w, height: h }, { charWidth: 7.2, labelHeight: 11 });
    const groups = MODULES.map(([name]) => stageOf(name));
    const byIndex = new Map(layout.cells.map((c) => [c.index, c]));
    for (const t of layerThreads(layout.cells, groups)) {
      const a = byIndex.get(t.a), b = byIndex.get(t.b); if (!a || !b) continue;
      const line = document.createElementNS(NS, "line");
      line.setAttribute("x1", a.x); line.setAttribute("y1", a.y);
      line.setAttribute("x2", b.x); line.setAttribute("y2", b.y);
      line.setAttribute("class", "map-thread"); svg.append(line);
    }
    layout.cells.forEach((c) => { const i = c.index;
      const r = document.createElementNS(NS, "rect");
      r.setAttribute("x", c.x - c.half); r.setAttribute("y", c.y - c.half);
      r.setAttribute("width", c.side); r.setAttribute("height", c.side);
      r.setAttribute("class", "map-cell"); svg.append(r);
      const t = document.createElementNS(NS, "text");
      t.setAttribute("x", c.x); t.setAttribute("y", c.y + c.half + 13);
      t.setAttribute("class", "map-label"); t.setAttribute("text-anchor", "middle");
      t.textContent = MODULES[i][0]; svg.append(t);
    });
    svg.onpointermove = (e) => {
      const box = svg.getBoundingClientRect();
      const i = hitTest(layout, (e.clientX - box.left) * (w / box.width), (e.clientY - box.top) * (h / box.height));
      host.title = i >= 0 ? MODULES[i][0] + ": " + MODULES[i][1] + " lines. " + MODULES[i][2] : "";
    };
  }
  new ResizeObserver(render).observe(host);
  render();
}
