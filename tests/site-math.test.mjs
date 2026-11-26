import { test } from "node:test";
import assert from "node:assert/strict";
import { decayVelocity, applyThrust, blendHue, WARP } from "../docs/assets/warp-velocity.js";
import { mixAestheticPresets } from "../docs/assets/vendor/aesthetic-mixer.js";
import { layoutCells } from "../docs/assets/vendor/cell-layout.js";

test("velocity decays toward cruise and stays bounded", () => {
  const v = decayVelocity(1, 900);
  assert.ok(Math.abs(v - (WARP.cruise + (1 - WARP.cruise) * 0.5)) < 1e-9);
  assert.ok(applyThrust(0.99, 100000, 800) <= 1);
  assert.ok(applyThrust(0, 100000, 800) <= WARP.perEventClamp + 1e-9);
});
test("hue blends on the circle: 0.95 and 0.05 give red", () => {
  const h = blendHue(0.95, 0.05, 0.5);
  assert.ok(h < 0.02 || h > 0.98, "hue " + h);
  const m = mixAestheticPresets(
    { a: { rounding: 0, density: 0, hue: 0.95, contrast: 0 }, b: { rounding: 0, density: 0, hue: 0.05, contrast: 0 } },
    { a: 0.5, b: 0.5 });
  assert.ok(m.hue < 0.02 || m.hue > 0.98, "mixer hue " + m.hue);
});
test("cell area ratio equals weight ratio", () => {
  const layout = layoutCells(
    [{ weight: 100, labelLength: 3 }, { weight: 25, labelLength: 3 }],
    { width: 800, height: 500 }, {});
  const byIndex = new Map(layout.cells.map((c) => [c.index, c]));
  const ratio = (byIndex.get(0).side / byIndex.get(1).side) ** 2;
  assert.ok(Math.abs(ratio - 4) < 1e-6, "ratio " + ratio);
});
