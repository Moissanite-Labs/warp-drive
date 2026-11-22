// Warp runtime: theme and motion toggles, shared 30fps loop, warp field
// canvas, section rail, HUD. The canvas is decoration only (aria-hidden).
// Every HUD number is real HTML text. Nothing moves when motion is off.
import { WARP, DIMENSIONS, decayVelocity, applyThrust, speedWord, dimensionAt, hueAt } from "./warp-velocity.js";
import { mountStylePad, vectorFor, applyVector } from "./style-pad.js";
import { encodeFontTable, glyphBit, packLabel, GLYPH_COLS, GLYPH_ROWS, GLYPH_ADVANCE } from "./vendor/glyph-font.js";
const FONT = encodeFontTable();
// Field ink: dark enough to read on cream, bright enough on the dark field.
const isDark = () => (document.documentElement.dataset.theme || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light")) === "dark";
const fieldInk = (hue) => "hsl(" + Math.round(hue * 360) + (isDark() ? " 70% 68% / 0.8)" : " 60% 32% / 0.7)");
// Decoration only: mirror the HUD dimension word in canvas glyphs. The HTML
// HUD text is the source of truth. Uppercase set, 16 char cap, per vendor API.
function drawGlyphWord(word, hue) {
  if (!ctx) return;
  const label = packLabel(word.toUpperCase(), 16);
  const pxSize = 3, x0 = W - label.length * GLYPH_ADVANCE * pxSize - 16, y0 = 76;
  ctx.fillStyle = fieldInk(hue);
  for (let i = 0; i < label.length; i++) {
    const code = (label.words[i >> 2] >> ((i & 3) * 8)) & 255;
    const words = [FONT[code * 2] || 0, FONT[code * 2 + 1] || 0];
    for (let r = 0; r < GLYPH_ROWS; r++) for (let c = 0; c < GLYPH_COLS; c++)
      if (glyphBit(words, c, r)) ctx.fillRect(x0 + (i * GLYPH_ADVANCE + c) * pxSize, y0 + r * pxSize, pxSize - 1, pxSize - 1);
  }
}

const root = document.documentElement;
const motionOn = () => root.dataset.motion !== "off";
function wireToggle(id, key, apply) {
  const btn = document.getElementById(id);
  if (!btn) return;
  const sync = () => btn.setAttribute("aria-pressed", String(apply.current()));
  btn.addEventListener("click", () => {
    const next = apply.toggle();
    try { localStorage.setItem(key, next); } catch { /* private mode */ }
    sync();
  });
  sync();
}
wireToggle("motion-toggle", "warp-motion", {
  current: motionOn,
  toggle: () => { const v = motionOn() ? "off" : "on"; root.dataset.motion = v; root.dataset.motionPref = v; paintStatic(); return v; },
});
wireToggle("theme-toggle", "warp-theme", {
  current: () => (root.dataset.theme || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light")) === "dark",
  toggle: () => {
    const cur = root.dataset.theme || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
    const v = cur === "dark" ? "light" : "dark"; root.dataset.theme = v; readTokens(); paintStatic(); return v;
  },
});
// Restore style pad early so CSS variables match the head bootstrap.
try {
  const raw = localStorage.getItem("warp-style");
  if (raw) applyVector(vectorFor(JSON.parse(raw)));
} catch { /* defaults in CSS apply */ }
const padMount = document.querySelector("[data-style-pad]");
if (padMount) mountStylePad(padMount, document.querySelector("[data-style-readout]"), document.querySelectorAll("[data-pole]"));

// Section rail from section[data-index], after the f0 pattern.
const secs = [...document.querySelectorAll("section[data-index]")];
const rail = document.querySelector("[data-hud]");
if (rail && secs.length) {
  const ul = document.createElement("ul");
  for (const s of secs) {
    const li = document.createElement("li");
    const a = document.createElement("a");
    a.href = "#" + s.id;
    a.textContent = (s.dataset.num || "") + " " + (s.querySelector("h2")?.textContent || s.id);
    li.append(a); ul.append(li);
  }
  rail.append(ul);
}
// Dimension sections: home maps by section, inner pages by data-dimension.
function dimSections() {
  const marked = [...document.querySelectorAll("[data-dimension]")];
  if (marked.length) return marked.map((el) => ({ top: el.offsetTop, dim: Number(el.dataset.dimension) }));
  const home = document.body.dataset.page === "home";
  const byId = { hero: 0, problem: 0, stages: 1, layer: 2, proof: 3, try: 3, limits: 3 };
  return secs.filter((s) => s.id in byId).map((s) => ({ top: s.offsetTop, dim: byId[s.id] }))
    .concat(home ? [] : [{ top: 0, dim: Number(document.body.dataset.homeDimension || 0) }])
    .sort((a, b) => a.top - b.top);
}
let sections = dimSections();
addEventListener("resize", () => { sections = dimSections(); sizeCanvas(); });

// Canvas field. One channel, one quantity: trail and link brightness encode
// velocity only, cell brightness encodes pointer distance only, hue encodes
// dimension only.
const canvas = document.getElementById("warp-field");
const ctx = canvas?.getContext("2d");
let W = 0, H = 0, tokens = {};
function readTokens() {
  const cs = getComputedStyle(root);
  tokens = { ink: cs.getPropertyValue("--ink").trim() || "#888", line: cs.getPropertyValue("--line").trim() || "#ccc" };
}
function sizeCanvas() {
  if (!canvas) return;
  const dpr = Math.min(devicePixelRatio || 1, 2);
  W = innerWidth; H = innerHeight;
  canvas.width = W * dpr; canvas.height = H * dpr;
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
}
readTokens(); sizeCanvas();
const N = innerWidth < 640 ? 45 : 90;
const stars = Array.from({ length: N }, (_, i) => ({
  x: ((i * 2654435761) % 1000) / 1000, y: ((i * 40503) % 1000) / 1000, z: 0.3 + ((i * 97) % 70) / 100,
}));
let velocity = WARP.cruise, px = 0, py = 0, epx = 0, epy = 0, lastY = scrollY;
addEventListener("scroll", () => { velocity = applyThrust(velocity, scrollY - lastY, innerHeight); lastY = scrollY; }, { passive: true });
addEventListener("pointermove", (e) => {
  if (document.querySelector(":focus-visible")) return;
  px = (e.clientX / innerWidth) * 2 - 1; py = (e.clientY / innerHeight) * 2 - 1;
}, { passive: true });
function drawField(v, hue, dim) {
  if (!ctx) return;
  ctx.clearRect(0, 0, W, H);
  const off = Number(getComputedStyle(root).getPropertyValue("--warp-hue-offset")) || 0;
  const h = ((hue + off) % 1 + 1) % 1;
  ctx.fillStyle = fieldInk(h);
  ctx.strokeStyle = ctx.fillStyle;
  const ox = epx * 28, oy = epy * 28;
  if (dim === 2) { // Lattice cells brighten near the pointer only.
    const gap = 72;
    for (let gx = gap / 2; gx < W; gx += gap) for (let gy = gap / 2; gy < H; gy += gap) {
      const d = Math.hypot(gx - (px * 0.5 + 0.5) * W, gy - (py * 0.5 + 0.5) * H);
      ctx.globalAlpha = Math.max(0.08, 1 - d / 320);
      ctx.strokeRect(gx - 10 + ox * 0.3, gy - 10 + oy * 0.3, 20, 20);
    }
    ctx.globalAlpha = 1; return;
  }
  for (const s of stars) {
    const x = s.x * W + ox * s.z, y = (s.y * H + scrollY * 0.02 * s.z) % H + oy * s.z;
    if (dim === 0) { ctx.beginPath(); ctx.arc(x, y, 1.4 * s.z + 0.4, 0, 7); ctx.fill(); }
    else if (dim === 1) { const len = 6 + v * 90 * s.z; ctx.beginPath(); ctx.moveTo(x, y); ctx.lineTo(x, y + len); ctx.stroke(); }
    else { // Ledger links: chained blocks, brightness follows velocity.
      ctx.globalAlpha = 0.25 + v * 0.75;
      ctx.strokeRect(x, y, 7, 7);
      ctx.beginPath(); ctx.moveTo(x + 3, y + 7); ctx.lineTo(x + 3, y + 7 + 8 + v * 22); ctx.stroke();
      ctx.globalAlpha = 1;
    }
  }
}
// HUD text at most 4 times per second. Dimension changes announce once,
// politely. Speed numbers are never announced live.
const hudSpeed = document.querySelector("[data-hud-speed]");
const hudDim = document.querySelector("[data-hud-dimension]");
const hudBar = document.querySelector("[data-hud-bar]");
const hudLive = document.querySelector("[data-hud-live]");
let lastDimName = "", lastHud = 0;
function updateHud(v, now) {
  const { dim } = dimensionAt(scrollY, sections);
  const name = DIMENSIONS[dim].name;
  if (now - lastHud >= 250) {
    lastHud = now;
    if (hudSpeed) hudSpeed.textContent = speedWord(v) + " · " + Math.round(v * 100) + "%";
    if (hudDim) hudDim.textContent = name;
    if (hudBar) hudBar.style.transform = "scaleX(" + v.toFixed(3) + ")";
  }
  if (name !== lastDimName) {
    if (lastDimName && hudLive) hudLive.textContent = "Dimension: " + name;
    lastDimName = name;
  }
  return dim;
}
function paintStatic() {
  if (!ctx) return;
  const { dim } = dimensionAt(scrollY, sections);
  drawField(WARP.cruise, DIMENSIONS[dim].hue, dim);
}
// Shared loop capped at 30fps, paused when hidden, motion off, or idle 60s.
let lastFrame = 0, lastInput = performance.now(), lastDecay = performance.now();
for (const ev of ["pointermove", "pointerdown", "keydown", "scroll", "touchstart"])
  addEventListener(ev, () => { lastInput = performance.now(); }, { passive: true });
function loop(now) {
  requestAnimationFrame(loop);
  if (!motionOn() || document.hidden || now - lastInput > 60000) return;
  if (now - lastFrame < 1000 / 30) return;
  const dt = now - lastDecay; lastDecay = now; lastFrame = now;
  velocity = decayVelocity(velocity, dt);
  epx += (px - epx) * 0.08; epy += (py - epy) * 0.08;
  const dim = updateHud(velocity, now);
  const hue = hueAt(scrollY, sections);
  drawField(velocity, hue, dim);
  drawGlyphWord(DIMENSIONS[dim].name, hue);
}
paintStatic();
if (motionOn()) requestAnimationFrame(loop); else updateHud(velocity, performance.now());
matchMedia("(prefers-color-scheme: dark)").addEventListener?.("change", () => { readTokens(); paintStatic(); });
// Details menus close on Escape and outside click.
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") document.querySelectorAll("details[open]").forEach((d) => d.removeAttribute("open"));
});
document.addEventListener("click", (e) => {
  document.querySelectorAll("details.menu[open]").forEach((d) => { if (!d.contains(e.target)) d.removeAttribute("open"); });
});
