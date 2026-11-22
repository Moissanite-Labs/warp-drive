// Warp velocity and dimension math. Pure functions first, DOM mount second.
// Reinvents the reading-weave score idea for warp: sustained scroll is thrust,
// not a fault. No blur, no link drift, no word splitting. Nothing autostarts.
export const WARP = Object.freeze({
  thrustGain: 0.6,      // velocity added per viewport-height of scroll
  perEventClamp: 0.25,  // one scroll event can add at most this much
  cruise: 0.06,         // resting speed the field settles to
  halfLifeMs: 900,      // decay half-life while no scroll arrives
  maxVelocity: 1,
});
export const DIMENSIONS = [
  { name: "Drift", hue: 0.58 },
  { name: "Slipstream", hue: 0.48 },
  { name: "Lattice", hue: 0.36 },
  { name: "Ledger", hue: 0.11 },
];
export function clamp01(x) { return Math.min(1, Math.max(0, x)); }
export function thrustFromScroll(deltaPx, viewportH) {
  if (!(viewportH > 0)) return 0;
  const raw = (Math.abs(deltaPx) / viewportH) * WARP.thrustGain;
  return Math.min(raw, WARP.perEventClamp);
}
export function applyThrust(v, deltaPx, viewportH) {
  return clamp01(v + thrustFromScroll(deltaPx, viewportH));
}
export function decayVelocity(v, dtMs) {
  const k = Math.pow(0.5, Math.max(0, dtMs) / WARP.halfLifeMs);
  return WARP.cruise + (v - WARP.cruise) * k;
}
export function speedWord(v) {
  if (v < 0.12) return "Cruise";
  if (v < 0.45) return "Cruise plus";
  return "Warp";
}
// Circular mean hue blend. Mirrors the vendored mixer rule: 0.95 and 0.05
// blend to red (0), never through grey or cyan.
export function blendHue(h1, h2, t) {
  const a1 = h1 * Math.PI * 2, a2 = h2 * Math.PI * 2;
  const x = (1 - t) * Math.cos(a1) + t * Math.cos(a2);
  const y = (1 - t) * Math.sin(a1) + t * Math.sin(a2);
  let h = Math.atan2(y, x) / (Math.PI * 2);
  return h < 0 ? h + 1 : h;
}
// sections: [{top, dim}] sorted by top. Returns {dim, blend} at scrollY.
export function dimensionAt(scrollY, sections, blendPx = 400) {
  if (!sections.length) return { dim: 0, blend: 0 };
  let cur = sections[0];
  for (const s of sections) if (scrollY >= s.top) cur = s;
  const i = sections.indexOf(cur);
  const next = sections[i + 1];
  if (!next) return { dim: cur.dim, blend: 0 };
  const start = next.top - blendPx;
  if (scrollY < start) return { dim: cur.dim, blend: 0 };
  return { dim: cur.dim, blend: clamp01((scrollY - start) / blendPx) };
}
export function hueAt(scrollY, sections, blendPx = 400) {
  const { dim, blend } = dimensionAt(scrollY, sections, blendPx);
  const a = DIMENSIONS[dim].hue;
  const b = DIMENSIONS[Math.min(dim + 1, DIMENSIONS.length - 1)].hue;
  return blend > 0 ? blendHue(a, b, blend) : a;
}
// DOM mount. Returns a handle with destroy(). Caller gates on motion.
export function mountVelocity(onChange) {
  let v = WARP.cruise, lastY = window.scrollY, lastT = performance.now();
  let raf = 0, dead = false;
  const onScroll = () => {
    const y = window.scrollY;
    v = applyThrust(v, y - lastY, window.innerHeight);
    lastY = y;
  };
  const tick = (t) => {
    if (dead) return;
    v = decayVelocity(v, t - lastT); lastT = t;
    onChange(v);
    raf = requestAnimationFrame(tick);
  };
  window.addEventListener("scroll", onScroll, { passive: true });
  raf = requestAnimationFrame(tick);
  return {
    get velocity() { return v; },
    destroy() {
      dead = true; cancelAnimationFrame(raf);
      window.removeEventListener("scroll", onScroll);
    },
  };
}
