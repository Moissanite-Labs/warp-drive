// Style pad: Eido simplex pad + aesthetic mixer steer CSS variables only.
// Geometry and velocity belong to the dimension system. The pad never moves
// text, never changes text size, and never drops body text below AA: body ink
// is a theme token and is not pad-driven. Only lines, radius, density scale
// and a canvas hue offset respond to the pad.
import { mountSimplexPad } from "./vendor/simplex-pad.js";
import { mixAestheticPresets } from "./vendor/aesthetic-mixer.js";

export const POLES = ["Chartroom", "Engine room", "Deep field"];
export const PRESETS = {
  chartroom: { rounding: 0.08, density: 0.35, hue: 0.0, contrast: 0.55 },
  engine: { rounding: 0.02, density: 0.85, hue: 0.04, contrast: 0.75 },
  deep: { rounding: 0.45, density: 0.5, hue: 0.95, contrast: 0.35 },
};
const KEYS = ["chartroom", "engine", "deep"];
export function vectorFor(weights) {
  const byKey = {};
  KEYS.forEach((k, i) => { byKey[k] = weights[i] || 0; });
  return mixAestheticPresets(PRESETS, byKey);
}
export function applyVector(vec, root = document.documentElement) {
  root.style.setProperty("--warp-round", (vec.rounding * 14).toFixed(1) + "px");
  root.style.setProperty("--warp-density", (0.85 + vec.density * 0.3).toFixed(3));
  root.style.setProperty("--warp-hue-offset", vec.hue.toFixed(4));
  root.style.setProperty("--warp-contrast", vec.contrast.toFixed(3));
}
function storedWeights() {
  try {
    const q = new URLSearchParams(location.search).get("style");
    if (q === "chartroom") return [1, 0, 0];
    if (q === "engine") return [0, 1, 0];
    if (q === "deep") return [0, 0, 1];
    const raw = localStorage.getItem("warp-style");
    if (raw) { const w = JSON.parse(raw); if (Array.isArray(w) && w.length === 3) return w; }
  } catch { /* fall through to default */ }
  return [1, 0, 0];
}
export function mountStylePad(mount, readout, buttons) {
  const weights = storedWeights();
  const show = (w) => {
    if (readout) readout.textContent = POLES.map((p, i) => p + " " + Math.round(w[i] * 100) + "%").join(", ");
    applyVector(vectorFor(w));
  };
  const pad = mountSimplexPad(mount, {
    labels: POLES, weights,
    onChange: (w) => {
      show(w);
      try { localStorage.setItem("warp-style", JSON.stringify(w)); } catch { /* private mode */ }
    },
  });
  show(weights);
  buttons?.forEach((btn) => btn.addEventListener("click", () => {
    const i = Number(btn.dataset.pole);
    const w = [0, 0, 0]; w[i] = 1; pad.set(w);
  }));
  return pad;
}
