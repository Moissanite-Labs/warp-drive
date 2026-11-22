#!/usr/bin/env python3
"""AUDIT-104 Pure-Q Reference Oracle & Certifier for `siliconcordat#5` + `#15`/`#16`/`#18`.

Implements:
  1. Live raw portal scanner & pseudocode-defect witness extractor for
     `Moissanite-Labs/siliconcordat` Discussion #5 (`discussion_5_raw.json` + `discussion_5_full.md`).
  2. Exact pure-Q algebraic refutation of Discussion #5 Reply 9.1's unstable decay formula
     (`1 - 0.01 * base_decay * (1 + 1/(T + 1e-5))` -> `-49.0005x` sign-flip blowup at T=0).
  3. Three executable Law-2b `aletheia v2.1+` pure-Q invariants (zero floats, zero bare asserts):
     - Invariant A: Feasibility-First Anti-Homogenization / Monoculture-Avoidance Gate
     - Invariant B: Resource-Bounded Monotone Ratchet + Fail-Closed Edge-Snap + exact `#16`
       weight-norm vs. behavioral-anchor calibration gap proof witness
     - Invariant C: Splicer Protocol v0.1.0 (`#18`) `splice.json` (`Slice -> Severance -> Seam -> Lock`)
       manifest, 5-state lifecycle, and 4 hard-invariant validator
  4. Fail-closed conservation & anti-bypass certifier (`certify_siliconcordat_d5_audit`).

100% pure Python 3 stdlib, exact int / Fraction arithmetic, ZERO floats, ZERO bare asserts.
"""

from __future__ import annotations

from collections.abc import Sequence
from fractions import Fraction
import json
import math
from pathlib import Path
import posixpath
import re
from typing import Any


class CordatAuditError(ValueError):
    """Fail-closed refusal raised on any malformed input, invariant breach, or conservation error."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise CordatAuditError(message)


def _require_exact_int(value: Any, name: str) -> int:
    _require(isinstance(value, int) and not isinstance(value, bool), f"exact-int:{name}")
    return value


def _require_exact_bool(value: Any, name: str) -> bool:
    _require(type(value) is bool, f"exact-bool:{name}")
    return value


def _require_exact_fraction(value: Any, name: str) -> Fraction:
    if isinstance(value, Fraction):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return Fraction(value, 1)
    raise CordatAuditError(f"exact-fraction:{name}")


def _require_clean_ascii(value: Any, name: str) -> str:
    _require(
        isinstance(value, str)
        and len(value) > 0
        and value == value.strip()
        and all(32 <= ord(ch) <= 126 for ch in value),
        f"clean-ascii:{name}",
    )
    return value


def reject_floats(obj: Any, path: str = "$") -> None:
    """Recursively reject any IEEE-754 float or complex anywhere inside nested structures."""
    _require(not isinstance(obj, (float, complex)), f"float-forbidden:{path}")
    if isinstance(obj, dict):
        for k, v in obj.items():
            reject_floats(k, f"{path}.<key>")
            reject_floats(v, f"{path}.{k}")
    elif isinstance(obj, (list, tuple, set, frozenset)):
        for i, v in enumerate(obj):
            reject_floats(v, f"{path}[{i}]")


def frac_str(value: Fraction) -> str:
    v = _require_exact_fraction(value, "frac_str")
    return f"{v.numerator}/{v.denominator}"


def frac_dec(value: Fraction, digits: int = 6) -> str:
    """Truncate exact Fraction toward zero to `digits` decimals."""
    v = _require_exact_fraction(value, "frac_dec")
    d = _require_exact_int(digits, "digits")
    _require(d >= 1, "digits-pos")
    sign = "-" if v < 0 else ""
    av = abs(v)
    ten_pow = 10**d
    scaled = (av.numerator * ten_pow) // av.denominator
    whole, rem = divmod(scaled, ten_pow)
    return f"{sign}{whole}.{rem:0{d}d}"


_FRAC_STR_RE = re.compile(r"^(?:0|-?[1-9][0-9]*)/[1-9][0-9]*$")


def _parse_frac_str(raw: Any, name: str) -> Fraction:
    s = _require_clean_ascii(raw, name)
    _require(_FRAC_STR_RE.match(s) is not None, f"frac-str:{name}")
    num_s, den_s = s.split("/")
    try:
        num = int(num_s)
        den = int(den_s)
    except ValueError as exc:
        raise CordatAuditError(f"frac-str-digits:{name}") from exc
    _require(math.gcd(num, den) == 1, f"frac-str-unreduced:{name}")
    return Fraction(num, den)


def _require_vec(raw: Any, dim: int | None, name: str) -> list[Fraction]:
    _require(isinstance(raw, (list, tuple)) and len(raw) >= 1, f"vec-nonempty:{name}")
    vec = [_require_exact_fraction(x, f"{name}[{i}]") for i, x in enumerate(raw)]
    if dim is not None:
        _require(len(vec) == dim, f"vec-dim:{name}")
    return vec


def _vec_sq_dist(u: Sequence[Fraction], v: Sequence[Fraction]) -> Fraction:
    return sum((a - b) * (a - b) for a, b in zip(u, v))


# =============================================================================
# 1. LIVE PORTAL PARSER & PSEUDOCODE-DEFECT SCANNER (DISCUSSION #5)
# =============================================================================

_SYMP_OVERWRITE_RE = re.compile(r"self\.symp_matrix\s*=\s*(?:tension|budget|step|decay_factor)\b")
_MOV_CR3_RAX_RE = re.compile(r"mov cr3,\s*rax")
_FPGA_MAGIC_RE = re.compile(r"0xABCDE00[12]")
_DECAY_BLOWUP_RE = re.compile(
    r"adaptive_decay_pressure\s*=\s*decay_factor\s*\*\s*\(1\.0\s*\+\s*\(1\.0\s*/\s*\(next_tension\s*\+\s*1e-5\)\)\)"
)
_HASH_SUM_RE = re.compile(r"hash\(input_latent\.sum\(\)\.item\(\)\)")
_SPLICEWARE_RE = re.compile(r"^### SPLICEWARE$", re.M)


def parse_discussion_5_portal(raw_json_path: Path, full_md_path: Path) -> dict[str, Any]:
    """Parse raw `discussion_5_raw.json` and `discussion_5_full.md` with zero floats."""
    _require(raw_json_path.is_file() and full_md_path.is_file(), "portal-files-missing")
    raw_obj = json.loads(raw_json_path.read_text(encoding="utf-8"))
    _require(isinstance(raw_obj, dict) and isinstance(raw_obj.get("comments"), dict), "portal-json-shape")

    disc_num = _require_exact_int(raw_obj.get("number"), "portal.number")
    title = _require_clean_ascii(raw_obj.get("title"), "portal.title")
    author_obj = raw_obj.get("author")
    _require(isinstance(author_obj, dict), "portal-author-dict")
    author = _require_clean_ascii(author_obj.get("login"), "portal.author")
    created_at = _require_clean_ascii(raw_obj.get("createdAt"), "portal.createdAt")
    updated_at = _require_clean_ascii(raw_obj.get("updatedAt"), "portal.updatedAt")

    comment_nodes = raw_obj["comments"].get("nodes")
    _require(isinstance(comment_nodes, list) and len(comment_nodes) >= 1, "portal-comments-nonempty")
    reply_count = 0
    for c in comment_nodes:
        _require(isinstance(c, dict) and isinstance(c.get("replies"), dict), "portal-comment-shape")
        r_nodes = c["replies"].get("nodes")
        _require(isinstance(r_nodes, list), "portal-replies-list")
        reply_count += len(r_nodes)

    md_text = full_md_path.read_text(encoding="utf-8")
    md_lines = len(md_text.splitlines())
    _require(md_lines >= 1, "portal-md-nonempty")

    defects = {
        "reply91_symp_matrix_scalar_overwrite": len(_SYMP_OVERWRITE_RE.findall(md_text)),
        "comment11_uninitialized_mov_cr3_rax": len(_MOV_CR3_RAX_RE.findall(md_text)),
        "reply112_fake_fpga_bitstream_magic": len(_FPGA_MAGIC_RE.findall(md_text)),
        "reply91_adaptive_decay_blowup_formula": len(_DECAY_BLOWUP_RE.findall(md_text)),
        "replies73_101_hash_sum_collision_bug": len(_HASH_SUM_RE.findall(md_text)),
    }

    return {
        "discussion_number": disc_num,
        "title": title,
        "author": author,
        "created_at": created_at,
        "updated_at": updated_at,
        "top_level_comments": len(comment_nodes),
        "replies": reply_count,
        "total_entries_incl_op": 1 + len(comment_nodes) + reply_count,
        "markdown_line_count": md_lines,
        "spliceware_marker_count": len(_SPLICEWARE_RE.findall(md_text)),
        "pseudocode_defect_counts": defects,
        "pseudocode_defect_total": sum(defects.values()),
    }


def prove_reply91_decay_explosion() -> dict[str, Any]:
    """Exact pure-Q refutation of Reply 9.1's `1 - 0.01 * base * (1 + 1/(T + 1e-5))` decay."""
    base_decay = Fraction(1, 20)
    tension_zero = Fraction(0, 1)
    eps = Fraction(1, 100000)
    pressure = base_decay * (Fraction(1, 1) + Fraction(1, 1) / (tension_zero + eps))
    multiplier = Fraction(1, 1) - pressure * Fraction(1, 100)

    # Law-2b bounded decay: 1 - base_decay * (1 - T / T_max) stays strictly in [1 - base_decay, 1]
    t_max = Fraction(100, 1)
    safe_mult_calm = Fraction(1, 1) - base_decay * (Fraction(1, 1) - tension_zero / t_max)
    safe_mult_peak = Fraction(1, 1) - base_decay * (Fraction(1, 1) - t_max / t_max)

    return {
        "base_decay": frac_str(base_decay),
        "calm_tension": frac_str(tension_zero),
        "eps": frac_str(eps),
        "d5_reply91_pressure": frac_str(pressure),
        "d5_reply91_multiplier": frac_str(multiplier),
        "d5_reply91_multiplier_dec4": frac_dec(multiplier, 4),
        "d5_reply91_sign_flip_blowup": multiplier < Fraction(0, 1),
        "law2b_bounded_mult_at_calm": frac_str(safe_mult_calm),
        "law2b_bounded_mult_at_peak": frac_str(safe_mult_peak),
        "law2b_strictly_stable": Fraction(0, 1) < safe_mult_calm <= safe_mult_peak <= Fraction(1, 1),
    }


# =============================================================================
# 2. INVARIANT A — FEASIBILITY-FIRST ANTI-HOMOGENIZATION GATE (ALETHEIA V2.1+)
# =============================================================================


def evaluate_anti_homogenization_gate(
    candidates: Sequence[dict[str, Any]],
    archive: Sequence[Sequence[Any]],
    *,
    tension: Any,
    tension_max: Any,
    alpha_base: Any,
    novelty_cap_sq: Any,
    min_cohort_spread_sq: Any,
    min_distinct_vectors: int,
    min_renyi2_diversity: Any,
) -> dict[str, Any]:
    """Pure-Q bounded feasibility-first anti-homogenization & monoculture-avoidance gate."""
    _require(isinstance(candidates, (list, tuple)) and len(candidates) >= 2, "ah-candidates-ge-2")
    _require(isinstance(archive, (list, tuple)) and len(archive) >= 1, "ah-archive-nonempty")

    t_val = _require_exact_fraction(tension, "tension")
    t_max = _require_exact_fraction(tension_max, "tension_max")
    a_base = _require_exact_fraction(alpha_base, "alpha_base")
    nov_cap = _require_exact_fraction(novelty_cap_sq, "novelty_cap_sq")
    min_spread = _require_exact_fraction(min_cohort_spread_sq, "min_cohort_spread_sq")
    min_dist_u = _require_exact_int(min_distinct_vectors, "min_distinct_vectors")
    min_d2 = _require_exact_fraction(min_renyi2_diversity, "min_renyi2_diversity")

    _require(t_max > 0 and 0 <= t_val <= t_max, "ah-tension-range")
    _require(a_base >= 0 and nov_cap >= 0 and min_spread >= 0, "ah-nonneg-params")
    _require(2 <= min_dist_u <= len(candidates) and min_d2 >= 1, "ah-diversity-bounds")

    arch_vecs = [_require_vec(av, None, f"archive[{i}]") for i, av in enumerate(archive)]
    dim = len(arch_vecs[0])
    for i, av in enumerate(arch_vecs[1:], 1):
        _require(len(av) == dim, f"ah-archive-dim:{i}")

    parsed_cands: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for i, c in enumerate(candidates):
        _require(isinstance(c, dict), f"ah-cand-dict:{i}")
        cid = _require_clean_ascii(c.get("id"), f"cand[{i}].id")
        _require(cid not in seen_ids, f"ah-dup-cand-id:{cid}")
        seen_ids.add(cid)
        vec = _require_vec(c.get("vector"), dim, f"cand[{i}].vector")
        cluster = _require_clean_ascii(c.get("cluster"), f"cand[{i}].cluster")
        fit = _require_exact_fraction(c.get("fitness"), f"cand[{i}].fitness")
        passed_inv = _require_exact_bool(c.get("passed_invariants"), f"cand[{i}].passed_invariants")
        parsed_cands.append({"id": cid, "vector": vec, "cluster": cluster, "fitness": fit, "passed": passed_inv})

    k = len(parsed_cands)
    feasible_cands = [c for c in parsed_cands if c["passed"]]
    f_cnt = len(feasible_cands)

    # Monoculture diversity is evaluated STRICTLY over the feasible (passed_invariants=True)
    # cohort so infeasible decoys can NEVER mask a feasible echo-chamber monoculture.
    veto_reasons: list[str] = []
    if f_cnt == 0:
        distinct_vectors = 0
        cohort_spread_sq = Fraction(0, 1)
        min_pair_dist_sq = Fraction(0, 1)
        renyi2_collision = Fraction(1, 1)
        eff_diversity_d2 = Fraction(1, 1)
        veto_reasons.append("NO_FEASIBLE_CANDIDATE_PASSED_INVARIANTS")
    elif f_cnt == 1:
        distinct_vectors = 1
        cohort_spread_sq = Fraction(0, 1)
        min_pair_dist_sq = Fraction(0, 1)
        renyi2_collision = Fraction(1, 1)
        eff_diversity_d2 = Fraction(1, 1)
        veto_reasons.append("INSUFFICIENT_FEASIBLE_COHORT_FOR_DIVERSITY")
    else:
        n_pairs = f_cnt * (f_cnt - 1) // 2
        pair_dists: list[Fraction] = []
        feas_clusters: dict[str, int] = {}
        for i in range(f_cnt):
            cl = feasible_cands[i]["cluster"]
            feas_clusters[cl] = feas_clusters.get(cl, 0) + 1
            for j in range(i + 1, f_cnt):
                pair_dists.append(_vec_sq_dist(feasible_cands[i]["vector"], feasible_cands[j]["vector"]))

        cohort_spread_sq = sum(pair_dists) / Fraction(n_pairs, 1)
        min_pair_dist_sq = min(pair_dists)
        distinct_vectors = len({tuple(c["vector"]) for c in feasible_cands})

        r2_num = sum(cnt * cnt for cnt in feas_clusters.values())
        renyi2_collision = Fraction(r2_num, f_cnt * f_cnt)
        eff_diversity_d2 = Fraction(f_cnt * f_cnt, r2_num)

        if distinct_vectors < min_dist_u:
            veto_reasons.append("MONOCULTURE_DISTINCT_VECTORS_BELOW_MIN")
        if cohort_spread_sq < min_spread:
            veto_reasons.append("MONOCULTURE_COHORT_SPREAD_BELOW_MIN")
        if eff_diversity_d2 < min_d2:
            veto_reasons.append("MONOCULTURE_RENYI2_DIVERSITY_BELOW_MIN")

    # Exact tension-damped novelty weight in [0, alpha_base]
    alpha_eff = a_base * (t_max - t_val) / t_max

    scored_rows: list[dict[str, Any]] = []
    eligible: list[tuple[Fraction, str]] = []
    n_arch = Fraction(len(arch_vecs), 1)
    for c in parsed_cands:
        raw_nov_sq = sum(_vec_sq_dist(c["vector"], av) for av in arch_vecs) / n_arch
        capped_nov_sq = nov_cap if raw_nov_sq > nov_cap else raw_nov_sq
        score = c["fitness"] + alpha_eff * capped_nov_sq
        scored_rows.append(
            {
                "id": c["id"],
                "cluster": c["cluster"],
                "passed_invariants": c["passed"],
                "fitness": frac_str(c["fitness"]),
                "raw_novelty_sq": frac_str(raw_nov_sq),
                "capped_novelty_sq": frac_str(capped_nov_sq),
                "selection_score": frac_str(score),
            }
        )
        if c["passed"]:
            eligible.append((score, c["id"]))

    monoculture_rejected = len(veto_reasons) > 0
    selected_id: str | None = None
    if not monoculture_rejected:
        eligible.sort(key=lambda pair: (-pair[0], pair[1]))
        selected_id = eligible[0][1]

    return {
        "zone": "ZONE_A_SOCRATIC_DISCOVERY",
        "epistemic_tag": "UNVERIFIED_HYPOTHESIS",
        "diversity_scope": "FEASIBLE_COHORT_ONLY",
        "cohort_size": k,
        "archive_size": len(arch_vecs),
        "vector_dim": dim,
        "distinct_vectors": distinct_vectors,
        "cohort_spread_sq": frac_str(cohort_spread_sq),
        "min_pair_dist_sq": frac_str(min_pair_dist_sq),
        "cluster_renyi2": frac_str(renyi2_collision),
        "effective_diversity_d2": frac_str(eff_diversity_d2),
        "alpha_effective": frac_str(alpha_eff),
        "eligible_count": f_cnt,
        "gate_passed": not monoculture_rejected,
        "veto_reasons": veto_reasons,
        "selected_candidate_id": selected_id,
        "candidates": scored_rows,
    }


# =============================================================================
# 3. INVARIANT B — RESOURCE-BOUNDED MONOTONE RATCHET + EDGE-SNAP & #16 PROBE
# =============================================================================


def evaluate_monotone_ratchet_trace(
    w0: Sequence[Any],
    steps: Sequence[dict[str, Any]],
    *,
    radius_sq: Any,
    budget_max: Any,
    behavior_floor: Any,
    require_monotone_behavior: bool = True,
) -> dict[str, Any]:
    """Pure-Q resource-bounded monotone ratchet (`||W - W0||^2 <= R^2` + budget + behavior + Edge-Snap)."""
    base_w = _require_vec(w0, None, "w0")
    dim = len(base_w)
    r_sq = _require_exact_fraction(radius_sq, "radius_sq")
    b_max = _require_exact_fraction(budget_max, "budget_max")
    b_floor = _require_exact_fraction(behavior_floor, "behavior_floor")
    req_mono = _require_exact_bool(require_monotone_behavior, "require_monotone_behavior")
    _require(r_sq > 0 and b_max > 0, "ratchet-pos-limits")
    _require(isinstance(steps, (list, tuple)) and len(steps) >= 1, "ratchet-steps-nonempty")

    w_committed = list(base_w)
    best_behavior = b_floor
    spent = Fraction(0, 1)
    committed_count = 0
    rollback_count = 0
    seen_step_ids: set[str] = set()
    trace: list[dict[str, Any]] = []

    for i, st in enumerate(steps):
        _require(isinstance(st, dict), f"ratchet-step-dict:{i}")
        sid = _require_clean_ascii(st.get("step_id"), f"step[{i}].step_id")
        _require(sid not in seen_step_ids, f"ratchet-dup-step:{sid}")
        seen_step_ids.add(sid)
        delta = _require_vec(st.get("delta"), dim, f"step[{i}].delta")
        cost = _require_exact_fraction(st.get("cost"), f"step[{i}].cost")
        _require(cost > 0, f"ratchet-cost-pos:{sid}")
        beh = _require_exact_fraction(st.get("behavior_score"), f"step[{i}].behavior_score")

        w_cand = [a + b for a, b in zip(w_committed, delta)]
        cand_drift_sq = _vec_sq_dist(w_cand, base_w)

        reasons: list[str] = []
        if spent + cost > b_max:
            reasons.append("BUDGET_EXCEEDED")
        else:
            # Spend is charged immediately and never refunded on rejected candidates (anti-retry DoS).
            spent += cost
            if cand_drift_sq > r_sq:
                reasons.append("NORM_RADIUS_EXCEEDED")
            if beh < b_floor:
                reasons.append("BEHAVIOR_FLOOR_BREACH")
            if req_mono and beh < best_behavior:
                reasons.append("BEHAVIOR_REGRESSION")

        if reasons:
            # Fail-closed Edge-Snap: active state snaps bit-identically back to w_committed.
            w_active = list(w_committed)
            rollback_count += 1
            committed = False
            snapped = True
        else:
            w_committed = w_cand
            w_active = list(w_committed)
            if beh > best_behavior:
                best_behavior = beh
            committed_count += 1
            committed = True
            snapped = False

        trace.append(
            {
                "step_id": sid,
                "cost": frac_str(cost),
                "cumulative_spent": frac_str(spent),
                "candidate_drift_sq": frac_str(cand_drift_sq),
                "behavior_score": frac_str(beh),
                "committed": committed,
                "edge_snapped": snapped,
                "active_equals_committed": w_active == w_committed,
                "rejection_reasons": reasons,
            }
        )

    final_drift_sq = _vec_sq_dist(w_committed, base_w)
    return {
        "dim": dim,
        "radius_sq": frac_str(r_sq),
        "budget_max": frac_str(b_max),
        "behavior_floor": frac_str(b_floor),
        "require_monotone_behavior": req_mono,
        "total_steps": len(steps),
        "committed_count": committed_count,
        "rollback_count": rollback_count,
        "total_spent": frac_str(spent),
        "final_drift_sq": frac_str(final_drift_sq),
        "final_best_behavior": frac_str(best_behavior),
        "final_committed_weights": [frac_str(x) for x in w_committed],
        "trace": trace,
    }


def prove_calibration_weight_vs_behavior_gap(
    radius_sq: int | Fraction = 16,
    perm_readout: tuple[int, int] = (-1, 1),
    flip_readout: tuple[int, int] = (-1, 1),
) -> dict[str, Any]:
    """Exact pure-Q proof witness reproducing `#16`'s calibration probe: norm alone cannot bound behavior."""
    r_sq = _require_exact_fraction(radius_sq, "cal-radius-sq")
    _require(r_sq > 0, "cal-radius-pos")
    _require(isinstance(perm_readout, tuple) and len(perm_readout) == 2, "cal-perm-readout")
    _require(isinstance(flip_readout, tuple) and len(flip_readout) == 2, "cal-flip-readout")
    r_perm = (_require_exact_int(perm_readout[0], "cal-pr0"), _require_exact_int(perm_readout[1], "cal-pr1"))
    r_flip = (_require_exact_int(flip_readout[0], "cal-fr0"), _require_exact_int(flip_readout[1], "cal-fr1"))
    # Toy linear-readout network y(x) = r @ (H @ x) over 4 exact rational probe inputs:
    probes = [(1, 0), (0, 1), (1, 1), (-1, 1)]
    h0 = (3, 0, 0, 3)
    r0 = (1, -1)
    # 1. Exact unit permutation (swaps hidden units & readout weights): zero behavioral change, huge drift!
    h_perm = (0, 3, 3, 0)
    # 2. Exact readout sign flip (identical hidden weights, negated readout): small drift, catastrophic R^2!
    h_flip = (3, 0, 0, 3)

    def eval_net(h: tuple[int, int, int, int], r: tuple[int, int]) -> list[Fraction]:
        out: list[Fraction] = []
        for x1, x2 in probes:
            z1 = h[0] * x1 + h[1] * x2
            z2 = h[2] * x1 + h[3] * x2
            out.append(Fraction(r[0] * z1 + r[1] * z2, 1))
        return out

    y0 = eval_net(h0, r0)
    y_perm = eval_net(h_perm, r_perm)
    y_flip = eval_net(h_flip, r_flip)
    y_mean = sum(y0) / Fraction(len(y0), 1)
    sst = sum((yi - y_mean) * (yi - y_mean) for yi in y0)
    sse_perm = sum((a - b) * (a - b) for a, b in zip(y_perm, y0))
    sse_flip = sum((a - b) * (a - b) for a, b in zip(y_flip, y0))
    r2_perm = Fraction(1, 1) - sse_perm / sst
    r2_flip = Fraction(1, 1) - sse_flip / sst

    w0_flat = [Fraction(x, 1) for x in (*h0, *r0)]
    w_perm_flat = [Fraction(x, 1) for x in (*h_perm, *r_perm)]
    w_flip_flat = [Fraction(x, 1) for x in (*h_flip, *r_flip)]
    drift_sq_perm = _vec_sq_dist(w_perm_flat, w0_flat)
    drift_sq_flip = _vec_sq_dist(w_flip_flat, w0_flat)

    perm_false_reject = drift_sq_perm > r_sq and r2_perm == Fraction(1, 1)
    flip_false_accept = drift_sq_flip <= r_sq and r2_flip < Fraction(0, 1)
    ratio_str = frac_str(drift_sq_perm / drift_sq_flip) if drift_sq_flip > 0 else "INF"

    return {
        "radius_sq": frac_str(r_sq),
        "perm_drift_sq": frac_str(drift_sq_perm),
        "perm_r2": frac_str(r2_perm),
        "perm_norm_only_falsely_rejects": perm_false_reject,
        "flip_drift_sq": frac_str(drift_sq_flip),
        "flip_r2": frac_str(r2_flip),
        "flip_r2_dec4": frac_dec(r2_flip, 4),
        "flip_norm_only_falsely_accepts": flip_false_accept,
        "drift_ratio_perm_over_flip": ratio_str,
        "calibration_gap_proved": perm_false_reject and flip_false_accept,
    }


# =============================================================================
# 4. INVARIANT C — SPLICER PROTOCOL v0.1.0 (`#18`) MANIFEST & LIFECYCLE VALIDATOR
# =============================================================================

_EXPECTED_SPLICE_TOP_KEYS = frozenset({"splice_version", "capability", "donor", "severance_map", "seam", "verification"})
_EXPECTED_DONOR_KEYS = frozenset({"uri", "commit", "license", "entry_symbols"})
_EXPECTED_SEAM_KEYS = frozenset({"path", "exports"})
_EXPECTED_VERIF_KEYS = frozenset({"command", "max_host_files_touched"})
_EXPECTED_EXEC_KEYS = frozenset(
    {
        "states_executed",
        "probe_foreign_imports",
        "lockfiles_before_sha256",
        "lockfiles_after_sha256",
        "human_lockfile_override",
        "host_imports_by_file",
        "core_files_sha256_after_extract",
        "core_files_sha256_after_lock",
        "host_files_touched",
        "lock_exit_code",
        "ejection_build_ok",
        "vendor_dir_is_symlink",
        "airlock_envelope_keys",
        "verifier_zone_a_board_read_access",
    }
)
_EXPECTED_STATES = ["PROBE", "SEVER", "EXTRACT", "WEAVE", "LOCK"]
_FORBIDDEN_AIRLOCK_FIELDS = frozenset(
    {"zone_a_transcript", "author_identity", "model_identity", "agreement_count", "persuasive_prose"}
)
_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_HTTPS_URI_RE = re.compile(r"^https://[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+(?::([0-9]{1,5}))?(?:/[^\s]*)?$")
_SEV_TARGET_RE = re.compile(r"^(?:host|stdlib)://[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*$")
_SHA1_40_RE = re.compile(r"^[0-9a-f]{40}$")
_SHA256_64_RE = re.compile(r"^[0-9a-f]{64}$")
_SPDX_ALLOWLIST = frozenset({"MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "MPL-2.0", "Unlicense"})
_UNSAFE_CMD_RE = re.compile(
    r"(?:\bnpx\b[^\n]*\s(?:-y|--yes)\b"
    r"|(?:^|[\s;&|(])(?:/[\w./-]+/)?rm\b[^\n]*\s-(?:[a-zA-Z]*[rR][a-zA-Z]*f|[a-zA-Z]*f[a-zA-Z]*[rR])[a-zA-Z]*\b"
    r"|(?:^|[\s;&|(])(?:/[\w./-]+/)?rm\b[^\n]*(?:-[a-zA-Z]*[rR]|--recursive\b)[^\n]*(?:-[a-zA-Z]*f|--force\b)"
    r"|(?:^|[\s;&|(])(?:/[\w./-]+/)?rm\b[^\n]*(?:-[a-zA-Z]*f|--force\b)[^\n]*(?:-[a-zA-Z]*[rR]|--recursive\b)"
    r"|(?:^|[\s;&|(])(?:/[\w./-]+/)?rm\b[^\n]*(?:-[a-zA-Z]*[rRf]|--recursive\b|--force\b)[^\n]*(?:\s(?:/|~|\$))"
    r"|\bfind\b[^\n]*\s-delete\b"
    r"|\bgit\b[^\n]*\bclean\b[^\n]*(?:-[a-zA-Z]*f|--force\b)"
    r"|(?:^|[\s;&|(])(?:/[\w./-]+/)?(?:(?:ba|z|da|k|a)?sh|python3?|perl|ruby|node)\b[^\n]*\s-[a-zA-Z]*[ce]\b"
    r"|\|\s*(?:env\s+)?(?:/[\w./-]+/)?(?:(?:ba|z|da|k|a)?sh|python3?|perl|ruby|node)\b"
    r"|\$\(|`|\bsudo\b)"
)


def _require_safe_relpath(raw: Any, name: str) -> str:
    s = _require_clean_ascii(raw, name)
    parts = s.split("/")
    _require("\\" not in s and all(p not in ("", ".", "..") for p in parts), f"unsafe-relpath:{name}")
    return s


def validate_splicer_graft(manifest: dict[str, Any], execution_record: dict[str, Any]) -> dict[str, Any]:
    """Fail-closed Splicer Protocol v0.1.0 (`#18`) manifest + 5-state + 4-hard-invariant validator."""
    reject_floats(manifest, "manifest")
    reject_floats(execution_record, "execution_record")
    _require(isinstance(manifest, dict) and isinstance(execution_record, dict), "splice-dicts")
    _require(set(manifest.keys()) == _EXPECTED_SPLICE_TOP_KEYS, "splice-top-keys-exact")
    _require(manifest["splice_version"] == "0.1.0", "splice-version")

    cap = _require_clean_ascii(manifest["capability"], "manifest.capability")
    _require(_SLUG_RE.match(cap) is not None, "splice-capability-slug")

    donor = manifest["donor"]
    _require(isinstance(donor, dict) and set(donor.keys()) == _EXPECTED_DONOR_KEYS, "splice-donor-keys")
    donor_uri = _require_clean_ascii(donor["uri"], "donor.uri")
    uri_m = _HTTPS_URI_RE.match(donor_uri)
    _require(uri_m is not None, "splice-donor-https")
    if uri_m.group(1) is not None:
        port_val = int(uri_m.group(1))
        _require(1 <= port_val <= 65535, "splice-donor-port")
    donor_commit = _require_clean_ascii(donor["commit"], "donor.commit")
    _require(_SHA1_40_RE.match(donor_commit) is not None, "splice-donor-commit-sha1")
    donor_lic = _require_clean_ascii(donor["license"], "donor.license")
    _require(donor_lic in _SPDX_ALLOWLIST, "splice-donor-license")
    entry_syms = donor["entry_symbols"]
    _require(isinstance(entry_syms, list) and len(entry_syms) >= 1, "splice-entry-symbols-nonempty")
    clean_syms = [_require_clean_ascii(s, f"entry_symbols[{i}]") for i, s in enumerate(entry_syms)]
    _require(len(set(clean_syms)) == len(clean_syms), "splice-entry-symbols-unique")

    sev_map = manifest["severance_map"]
    _require(isinstance(sev_map, dict), "splice-sev-map-dict")
    for dep_k, target_v in sev_map.items():
        _require_clean_ascii(dep_k, "sev.key")
        tv = _require_clean_ascii(target_v, f"sev.{dep_k}")
        _require(
            _SEV_TARGET_RE.match(tv) is not None
            and all(seg not in (".", "..") for seg in tv.split("://", 1)[1].split("/")),
            f"splice-sev-target:{dep_k}",
        )

    seam = manifest["seam"]
    _require(isinstance(seam, dict) and set(seam.keys()) == _EXPECTED_SEAM_KEYS, "splice-seam-keys")
    seam_path = _require_safe_relpath(seam["path"], "seam.path")
    vendor_prefix = f"vendor/splices/{cap}/"
    core_prefix = f"vendor/splices/{cap}/core"
    _require(not seam_path.startswith("vendor/splices/"), "splice-seam-outside-vendor")
    seam_exports = seam["exports"]
    _require(isinstance(seam_exports, list) and len(seam_exports) >= 1, "splice-seam-exports-nonempty")
    clean_exports = [_require_clean_ascii(e, f"seam.exports[{i}]") for i, e in enumerate(seam_exports)]
    _require(len(set(clean_exports)) == len(clean_exports), "splice-seam-exports-unique")

    verif = manifest["verification"]
    _require(isinstance(verif, dict) and set(verif.keys()) == _EXPECTED_VERIF_KEYS, "splice-verif-keys")
    v_cmd = _require_clean_ascii(verif["command"], "verification.command")
    _require(_UNSAFE_CMD_RE.search(v_cmd) is None, "splice-verif-cmd-unsafe")
    max_touched = _require_exact_int(verif["max_host_files_touched"], "verification.max_host_files_touched")
    _require(max_touched >= 1, "splice-max-host-files-pos")

    # Execution record checks: exact schema + 5-state lifecycle + 4 Hard Invariants (#18 §5)
    _require(set(execution_record.keys()) == _EXPECTED_EXEC_KEYS, "splice-exec-keys-exact")
    states = execution_record.get("states_executed")
    _require(isinstance(states, list), "splice-states-list")
    foreign_imports = execution_record.get("probe_foreign_imports")
    _require(isinstance(foreign_imports, list), "splice-foreign-imports-list")
    clean_foreign = [_require_clean_ascii(x, f"foreign[{i}]") for i, x in enumerate(foreign_imports)]

    lf_before = execution_record.get("lockfiles_before_sha256")
    lf_after = execution_record.get("lockfiles_after_sha256")
    _require(isinstance(lf_before, dict) and isinstance(lf_after, dict), "splice-lockfiles-dicts")
    for lf_name, lf_map in (("lockfiles_before", lf_before), ("lockfiles_after", lf_after)):
        for lk, lh in lf_map.items():
            _require_safe_relpath(lk, f"{lf_name}.path")
            _require(
                _SHA256_64_RE.match(_require_clean_ascii(lh, f"{lf_name}.hash")) is not None,
                f"splice-{lf_name}-hash-fmt",
            )
    human_override = _require_exact_bool(
        execution_record.get("human_lockfile_override"), "splice.human_lockfile_override"
    )

    host_imports = execution_record.get("host_imports_by_file")
    _require(isinstance(host_imports, dict), "splice-host-imports-dict")
    core_extract = execution_record.get("core_files_sha256_after_extract")
    core_lock = execution_record.get("core_files_sha256_after_lock")
    _require(isinstance(core_extract, dict) and len(core_extract) >= 1 and isinstance(core_lock, dict), "splice-core-hashes-dicts")
    for cf_name, cf_map in (("core_extract", core_extract), ("core_lock", core_lock)):
        for cf_k, cf_h in cf_map.items():
            cf_clean = _require_safe_relpath(cf_k, f"{cf_name}.path")
            _require(cf_clean.startswith(core_prefix + "/"), f"splice-{cf_name}-under-core")
            _require(
                _SHA256_64_RE.match(_require_clean_ascii(cf_h, f"{cf_name}.hash")) is not None,
                f"splice-{cf_name}-hash-fmt",
            )

    host_touched = execution_record.get("host_files_touched")
    _require(isinstance(host_touched, list), "splice-host-touched-list")
    clean_touched = [_require_safe_relpath(p, f"touched[{i}]") for i, p in enumerate(host_touched)]
    lock_exit_code = _require_exact_int(execution_record.get("lock_exit_code"), "splice.lock_exit_code")
    ejection_ok = _require_exact_bool(execution_record.get("ejection_build_ok"), "splice.ejection_build_ok")
    vendor_sym = _require_exact_bool(execution_record.get("vendor_dir_is_symlink"), "splice.vendor_dir_is_symlink")
    airlock_keys = execution_record.get("airlock_envelope_keys")
    _require(isinstance(airlock_keys, list) and len(airlock_keys) >= 1, "splice-airlock-keys-nonempty")
    clean_airlock_keys = [_require_clean_ascii(k, f"airlock_keys[{i}]") for i, k in enumerate(airlock_keys)]
    zone_a_read = _require_exact_bool(
        execution_record.get("verifier_zone_a_board_read_access"), "splice.verifier_zone_a_board_read_access"
    )

    violations: list[str] = []
    if states != _EXPECTED_STATES:
        violations.append("STATE_MACHINE_ORDER_BREACH")
    unmapped = sorted(dep for dep in clean_foreign if dep not in sev_map)
    if unmapped:
        violations.append("UNMAPPED_FOREIGN_DEPENDENCY")
    if lf_before != lf_after and not human_override:
        violations.append("LOCKFILE_MUTATION_WITHOUT_OVERRIDE")

    core_path_lo = core_prefix.lower()
    core_dot_lo = f"vendor.splices.{cap}.core".lower()
    pkg_dot_lo = f"vendor.splices.{cap}".lower()
    core_token_re = re.compile(
        r"(?:^|[\s./:\\'\"(),\[\]])" + re.escape(core_path_lo) + r"(?:$|[\s./:\\'\"(),\[\]])"
        r"|(?:^|[\s./:\\'\"(),\[\]])" + re.escape(core_dot_lo) + r"(?:$|[\s.:'\"(),\[\]])"
        r"|\bfrom\s+" + re.escape(pkg_dot_lo) + r"\s+import\b[^\n]*(?:\bcore\b|\*)"
    )
    visibility_leaks: list[str] = []
    for hf, imp_list in sorted(host_imports.items()):
        hf_clean = _require_safe_relpath(hf, "host_imports.file")
        _require(isinstance(imp_list, list), f"host_imports.list:{hf_clean}")
        for imp in imp_list:
            imp_s = _require_clean_ascii(imp, f"host_imports.imp:{hf_clean}")
            imp_lo = re.sub(r"\s*\.\s*", ".", posixpath.normpath(imp_s.replace("\\", "/")).lower())
            if core_token_re.search(imp_lo) is not None and hf_clean != seam_path:
                visibility_leaks.append(hf_clean)
    if visibility_leaks:
        violations.append("ONE_WAY_VISIBILITY_BREACH")

    if core_extract != core_lock:
        violations.append("IMMUTABLE_CORE_MUTATED")
    non_vendor_touched = [p for p in clean_touched if not p.startswith(vendor_prefix)]
    if len(non_vendor_touched) > max_touched or seam_path not in non_vendor_touched:
        violations.append("HOST_TOUCH_BUDGET_OR_SEAM_BREACH")
    if lock_exit_code != 0:
        violations.append("LOCK_CONTRACT_TEST_FAILED")
    if not ejection_ok:
        violations.append("CLEAN_EJECTION_FAILED")
    if vendor_sym:
        violations.append("VENDOR_SYMLINK_FORBIDDEN")
    airlock_leaks = sorted(k for k in clean_airlock_keys if k.lower() in _FORBIDDEN_AIRLOCK_FIELDS)
    if airlock_leaks or zone_a_read:
        violations.append("AIRLOCK_ZONE_A_LEAKAGE_BREACH")

    return {
        "airlock_boundary": "ZONE_A_TO_ZONE_B_BLINDED_LOCK",
        "capability": cap,
        "splice_version": manifest["splice_version"],
        "compliant": len(violations) == 0,
        "violations": violations,
        "unmapped_foreign_imports": unmapped,
        "visibility_leaks": sorted(set(visibility_leaks)),
        "airlock_leaked_fields": airlock_leaks,
        "verifier_blinded_from_zone_a": not zone_a_read,
        "core_file_count": len(core_extract),
        "non_vendor_host_files_touched": len(non_vendor_touched),
        "max_host_files_touched": max_touched,
    }


# =============================================================================
# 5. FULL REFERENCE WITNESS SUITE & FAIL-CLOSED CONSERVATION CERTIFIER
# =============================================================================


def run_reference_invariants() -> dict[str, Any]:
    """Execute deterministic positive & negative witness controls across all 3 Law-2b invariants."""
    reply91_refutation = prove_reply91_decay_explosion()

    # Invariant A: Anti-Homogenization positive + monoculture veto + unsafe-outlier block
    archive_a = [[Fraction(0, 1), Fraction(0, 1)], [Fraction(1, 1), Fraction(0, 1)]]
    ah_pass = evaluate_anti_homogenization_gate(
        candidates=[
            {"id": "cand-alpha", "vector": [Fraction(1, 1), Fraction(2, 1)], "cluster": "symbolic", "fitness": Fraction(9, 10), "passed_invariants": True},
            {"id": "cand-beta", "vector": [Fraction(3, 1), Fraction(0, 1)], "cluster": "spectral", "fitness": Fraction(8, 10), "passed_invariants": True},
            {"id": "cand-rogue-outlier", "vector": [Fraction(100, 1), Fraction(100, 1)], "cluster": "rogue", "fitness": Fraction(1, 10), "passed_invariants": False},
        ],
        archive=archive_a,
        tension=Fraction(2, 10),
        tension_max=Fraction(1, 1),
        alpha_base=Fraction(1, 4),
        novelty_cap_sq=Fraction(10, 1),
        min_cohort_spread_sq=Fraction(2, 1),
        min_distinct_vectors=2,
        min_renyi2_diversity=Fraction(2, 1),
    )
    ah_monoculture = evaluate_anti_homogenization_gate(
        candidates=[
            {"id": "clone-1", "vector": [Fraction(1, 1), Fraction(0, 1)], "cluster": "same", "fitness": Fraction(9, 10), "passed_invariants": True},
            {"id": "clone-2", "vector": [Fraction(1, 1), Fraction(0, 1)], "cluster": "same", "fitness": Fraction(9, 10), "passed_invariants": True},
            {"id": "clone-3", "vector": [Fraction(1, 1), Fraction(0, 1)], "cluster": "same", "fitness": Fraction(9, 10), "passed_invariants": True},
        ],
        archive=archive_a,
        tension=Fraction(2, 10),
        tension_max=Fraction(1, 1),
        alpha_base=Fraction(1, 4),
        novelty_cap_sq=Fraction(10, 1),
        min_cohort_spread_sq=Fraction(2, 1),
        min_distinct_vectors=2,
        min_renyi2_diversity=Fraction(2, 1),
    )

    # Invariant B: Monotone Ratchet + Edge-Snap trace + #16 calibration gap witness
    ratchet_trace = evaluate_monotone_ratchet_trace(
        w0=[Fraction(0, 1), Fraction(0, 1)],
        steps=[
            {"step_id": "s1-valid-improve", "delta": [Fraction(1, 1), Fraction(1, 1)], "cost": Fraction(2, 1), "behavior_score": Fraction(85, 100)},
            {"step_id": "s2-behavior-collapse-inside-norm", "delta": [Fraction(1, 1), Fraction(0, 1)], "cost": Fraction(2, 1), "behavior_score": Fraction(-19, 5)},
            {"step_id": "s3-norm-radius-exceeded", "delta": [Fraction(5, 1), Fraction(0, 1)], "cost": Fraction(2, 1), "behavior_score": Fraction(95, 100)},
            {"step_id": "s4-valid-monotone-step", "delta": [Fraction(1, 1), Fraction(0, 1)], "cost": Fraction(3, 1), "behavior_score": Fraction(90, 100)},
            {"step_id": "s5-budget-exceeded", "delta": [Fraction(0, 1), Fraction(1, 1)], "cost": Fraction(2, 1), "behavior_score": Fraction(99, 100)},
        ],
        radius_sq=Fraction(16, 1),
        budget_max=Fraction(10, 1),
        behavior_floor=Fraction(80, 100),
        require_monotone_behavior=True,
    )
    calibration_gap = prove_calibration_weight_vs_behavior_gap()

    # Invariant C: Splicer v0.1.0 compliant graft + adversarial violation control
    valid_manifest = {
        "splice_version": "0.1.0",
        "capability": "bounded_ratchet_gate",
        "donor": {
            "uri": "https://github.com/Moissanite-Labs/weft",
            "commit": "a" * 40,
            "license": "MIT",
            "entry_symbols": ["RatchetGate.step", "RatchetGate.snap"],
        },
        "severance_map": {
            "donor_logger": "host://aletheia/strict_io",
            "numpy": "stdlib://fractions",
        },
        "seam": {
            "path": "aletheia/seams/bounded_ratchet_seam.py",
            "exports": ["evaluate_ratchet_step"],
        },
        "verification": {
            "command": "python3 -I -B tests/test_bounded_ratchet_seam.py",
            "max_host_files_touched": 2,
        },
    }
    valid_exec = {
        "states_executed": ["PROBE", "SEVER", "EXTRACT", "WEAVE", "LOCK"],
        "probe_foreign_imports": ["donor_logger", "numpy"],
        "lockfiles_before_sha256": {"pyproject.toml": "1" * 64},
        "lockfiles_after_sha256": {"pyproject.toml": "1" * 64},
        "human_lockfile_override": False,
        "host_imports_by_file": {
            "aletheia/seams/bounded_ratchet_seam.py": ["vendor/splices/bounded_ratchet_gate/core/gate.py"],
            "aletheia/cli.py": ["aletheia/seams/bounded_ratchet_seam.py"],
        },
        "core_files_sha256_after_extract": {"vendor/splices/bounded_ratchet_gate/core/gate.py": "2" * 64},
        "core_files_sha256_after_lock": {"vendor/splices/bounded_ratchet_gate/core/gate.py": "2" * 64},
        "host_files_touched": [
            "vendor/splices/bounded_ratchet_gate/core/gate.py",
            "vendor/splices/bounded_ratchet_gate/splice.json",
            "aletheia/seams/bounded_ratchet_seam.py",
            "tests/test_bounded_ratchet_seam.py",
        ],
        "lock_exit_code": 0,
        "ejection_build_ok": True,
        "vendor_dir_is_symlink": False,
        "airlock_envelope_keys": ["claim_ledger", "pinned_input_sha256s", "artifact_and_tests"],
        "verifier_zone_a_board_read_access": False,
    }
    splicer_pass = validate_splicer_graft(valid_manifest, valid_exec)

    bad_exec = json.loads(json.dumps(valid_exec))
    bad_exec["probe_foreign_imports"].append("unmapped_third_party_pkg")
    bad_exec["lockfiles_after_sha256"]["pyproject.toml"] = "9" * 64
    bad_exec["host_imports_by_file"]["aletheia/cli.py"].append("vendor/splices/bounded_ratchet_gate/core/gate.py")
    bad_exec["core_files_sha256_after_lock"]["vendor/splices/bounded_ratchet_gate/core/gate.py"] = "8" * 64
    bad_exec["airlock_envelope_keys"].append("zone_a_transcript")
    bad_exec["verifier_zone_a_board_read_access"] = True
    splicer_fail = validate_splicer_graft(valid_manifest, bad_exec)

    return {
        "reply91_decay_refutation": reply91_refutation,
        "invariant_a_anti_homogenization": {
            "diverse_with_rogue_outlier_blocked": ah_pass,
            "monoculture_echo_chamber_vetoed": ah_monoculture,
        },
        "invariant_b_monotone_ratchet": {
            "trace_witness": ratchet_trace,
            "calibration_gap_witness": calibration_gap,
        },
        "invariant_c_splicer_protocol": {
            "compliant_graft_witness": splicer_pass,
            "adversarial_violation_witness": splicer_fail,
        },
    }


_EXPECTED_PORTAL_KEYS = frozenset(
    {
        "discussion_number",
        "title",
        "author",
        "created_at",
        "updated_at",
        "top_level_comments",
        "replies",
        "total_entries_incl_op",
        "markdown_line_count",
        "spliceware_marker_count",
        "pseudocode_defect_counts",
        "pseudocode_defect_total",
    }
)
_EXPECTED_DEFECT_KEYS = frozenset(
    {
        "reply91_symp_matrix_scalar_overwrite",
        "comment11_uninitialized_mov_cr3_rax",
        "reply112_fake_fpga_bitstream_magic",
        "reply91_adaptive_decay_blowup_formula",
        "replies73_101_hash_sum_collision_bug",
    }
)
_EXPECTED_INVARIANTS_TOP_KEYS = frozenset(
    {
        "reply91_decay_refutation",
        "invariant_a_anti_homogenization",
        "invariant_b_monotone_ratchet",
        "invariant_c_splicer_protocol",
    }
)
_EXPECTED_R91_KEYS = frozenset(
    {
        "base_decay",
        "calm_tension",
        "eps",
        "d5_reply91_pressure",
        "d5_reply91_multiplier",
        "d5_reply91_multiplier_dec4",
        "d5_reply91_sign_flip_blowup",
        "law2b_bounded_mult_at_calm",
        "law2b_bounded_mult_at_peak",
        "law2b_strictly_stable",
    }
)
_EXPECTED_INV_A_KEYS = frozenset(
    {
        "diverse_with_rogue_outlier_blocked",
        "monoculture_echo_chamber_vetoed",
    }
)
_EXPECTED_AH_KEYS = frozenset(
    {
        "zone",
        "epistemic_tag",
        "diversity_scope",
        "cohort_size",
        "archive_size",
        "vector_dim",
        "distinct_vectors",
        "cohort_spread_sq",
        "min_pair_dist_sq",
        "cluster_renyi2",
        "effective_diversity_d2",
        "alpha_effective",
        "eligible_count",
        "gate_passed",
        "veto_reasons",
        "selected_candidate_id",
        "candidates",
    }
)
_VALID_AH_VETO_CODES = frozenset(
    {
        "NO_FEASIBLE_CANDIDATE_PASSED_INVARIANTS",
        "INSUFFICIENT_FEASIBLE_COHORT_FOR_DIVERSITY",
        "MONOCULTURE_DISTINCT_VECTORS_BELOW_MIN",
        "MONOCULTURE_COHORT_SPREAD_BELOW_MIN",
        "MONOCULTURE_RENYI2_DIVERSITY_BELOW_MIN",
    }
)
_EXPECTED_INV_B_KEYS = frozenset({"trace_witness", "calibration_gap_witness"})
_EXPECTED_RT_KEYS = frozenset(
    {
        "dim",
        "radius_sq",
        "budget_max",
        "behavior_floor",
        "require_monotone_behavior",
        "total_steps",
        "committed_count",
        "rollback_count",
        "total_spent",
        "final_drift_sq",
        "final_best_behavior",
        "final_committed_weights",
        "trace",
    }
)
_EXPECTED_RT_ROW_KEYS = frozenset(
    {
        "step_id",
        "cost",
        "cumulative_spent",
        "candidate_drift_sq",
        "behavior_score",
        "committed",
        "edge_snapped",
        "active_equals_committed",
        "rejection_reasons",
    }
)
_EXPECTED_CG_KEYS = frozenset(
    {
        "radius_sq",
        "perm_drift_sq",
        "perm_r2",
        "perm_norm_only_falsely_rejects",
        "flip_drift_sq",
        "flip_r2",
        "flip_r2_dec4",
        "flip_norm_only_falsely_accepts",
        "drift_ratio_perm_over_flip",
        "calibration_gap_proved",
    }
)
_EXPECTED_INV_C_KEYS = frozenset({"compliant_graft_witness", "adversarial_violation_witness"})
_EXPECTED_SPLICER_OUT_KEYS = frozenset(
    {
        "airlock_boundary",
        "capability",
        "splice_version",
        "compliant",
        "violations",
        "unmapped_foreign_imports",
        "visibility_leaks",
        "airlock_leaked_fields",
        "verifier_blinded_from_zone_a",
        "core_file_count",
        "non_vendor_host_files_touched",
        "max_host_files_touched",
    }
)
_VALID_SPLICER_VIOLATION_CODES = frozenset(
    {
        "STATE_MACHINE_ORDER_BREACH",
        "UNMAPPED_FOREIGN_DEPENDENCY",
        "LOCKFILE_MUTATION_WITHOUT_OVERRIDE",
        "ONE_WAY_VISIBILITY_BREACH",
        "IMMUTABLE_CORE_MUTATED",
        "HOST_TOUCH_BUDGET_OR_SEAM_BREACH",
        "LOCK_CONTRACT_TEST_FAILED",
        "CLEAN_EJECTION_FAILED",
        "VENDOR_SYMLINK_FORBIDDEN",
        "AIRLOCK_ZONE_A_LEAKAGE_BREACH",
    }
)


def certify_siliconcordat_d5_audit(portal: dict[str, Any], invariants: dict[str, Any]) -> dict[str, Any]:
    """Fail-closed exact conservation & anti-bypass certifier for AUDIT-104."""
    reject_floats(portal, "portal")
    reject_floats(invariants, "invariants")
    _require(isinstance(portal, dict) and isinstance(invariants, dict), "cert-dicts")
    _require(set(portal.keys()) == _EXPECTED_PORTAL_KEYS, "portal-keys-exact")
    _require(set(invariants.keys()) == _EXPECTED_INVARIANTS_TOP_KEYS, "invariants-keys-exact")

    # 1. Portal conservation
    _require_exact_int(portal["discussion_number"], "portal.discussion_number")
    _require_clean_ascii(portal["title"], "portal.title")
    _require_clean_ascii(portal["author"], "portal.author")
    _require_clean_ascii(portal["created_at"], "portal.created_at")
    _require_clean_ascii(portal["updated_at"], "portal.updated_at")
    _require_exact_int(portal["spliceware_marker_count"], "portal.spliceware_marker_count")
    top_c = _require_exact_int(portal["top_level_comments"], "portal.top_level_comments")
    reps = _require_exact_int(portal["replies"], "portal.replies")
    tot_e = _require_exact_int(portal["total_entries_incl_op"], "portal.total_entries_incl_op")
    md_l = _require_exact_int(portal["markdown_line_count"], "portal.markdown_line_count")
    defects = portal["pseudocode_defect_counts"]
    _require(isinstance(defects, dict) and set(defects.keys()) == _EXPECTED_DEFECT_KEYS, "portal.defects-keys-exact")
    def_tot = _require_exact_int(portal["pseudocode_defect_total"], "portal.defect_total")
    def_vals = [_require_exact_int(v, f"portal.defect.{k}") for k, v in defects.items()]
    _require(top_c >= 1 and reps >= 0 and tot_e == 1 + top_c + reps and md_l >= 1, "portal-entry-conservation")
    _require(all(x >= 0 for x in def_vals) and sum(def_vals) == def_tot, "portal-defect-sum")

    # 2. Reply 9.1 decay refutation (exact formula replay!)
    r91 = invariants["reply91_decay_refutation"]
    _require(isinstance(r91, dict) and set(r91.keys()) == _EXPECTED_R91_KEYS, "r91-keys-exact")
    r91_bd = _parse_frac_str(r91["base_decay"], "r91.base_decay")
    r91_ct = _parse_frac_str(r91["calm_tension"], "r91.calm_tension")
    r91_eps = _parse_frac_str(r91["eps"], "r91.eps")
    r91_press = _parse_frac_str(r91["d5_reply91_pressure"], "r91.pressure")
    r91_mult = _parse_frac_str(r91["d5_reply91_multiplier"], "r91.mult")
    r91_mult_dec4 = _require_clean_ascii(r91["d5_reply91_multiplier_dec4"], "r91.mult_dec4")
    r91_calm = _parse_frac_str(r91["law2b_bounded_mult_at_calm"], "r91.calm")
    r91_peak = _parse_frac_str(r91["law2b_bounded_mult_at_peak"], "r91.peak")
    r91_blow = _require_exact_bool(r91["d5_reply91_sign_flip_blowup"], "r91.blowup")
    r91_safe = _require_exact_bool(r91["law2b_strictly_stable"], "r91.safe")
    _require(r91_bd > Fraction(0, 1) and r91_ct >= Fraction(0, 1) and r91_eps > Fraction(0, 1), "r91-params-range")
    expected_press = r91_bd * (Fraction(1, 1) + Fraction(1, 1) / (r91_ct + r91_eps))
    expected_mult = Fraction(1, 1) - expected_press * Fraction(1, 100)
    _require(
        r91_press == expected_press
        and r91_mult == expected_mult
        and r91_mult_dec4 == frac_dec(expected_mult, 4)
        and r91_calm == Fraction(1, 1) - r91_bd,
        "r91-formula-match",
    )
    _require(r91_blow == (r91_mult < Fraction(0, 1)), "r91-blowup-match")
    _require(r91_safe == (Fraction(0, 1) < r91_calm <= r91_peak <= Fraction(1, 1)), "r91-safe-match")

    # 3. Invariant A conservation & controls
    inv_a = invariants["invariant_a_anti_homogenization"]
    _require(isinstance(inv_a, dict) and set(inv_a.keys()) == _EXPECTED_INV_A_KEYS, "inv_a-keys-exact")
    ah_ok = inv_a["diverse_with_rogue_outlier_blocked"]
    ah_bad = inv_a["monoculture_echo_chamber_vetoed"]
    _require(
        isinstance(ah_ok, dict)
        and set(ah_ok.keys()) == _EXPECTED_AH_KEYS
        and isinstance(ah_bad, dict)
        and set(ah_bad.keys()) == _EXPECTED_AH_KEYS,
        "inv_a-subdicts",
    )
    ah_ok_pass = _require_exact_bool(ah_ok["gate_passed"], "ah_ok.gate_passed")
    ah_bad_pass = _require_exact_bool(ah_bad["gate_passed"], "ah_bad.gate_passed")
    ah_ok_k = _require_exact_int(ah_ok["cohort_size"], "ah_ok.k")
    ah_ok_u = _require_exact_int(ah_ok["distinct_vectors"], "ah_ok.u")
    ah_ok_el = _require_exact_int(ah_ok["eligible_count"], "ah_ok.eligible")
    ah_ok_r2 = _parse_frac_str(ah_ok["cluster_renyi2"], "ah_ok.r2")
    ah_ok_d2 = _parse_frac_str(ah_ok["effective_diversity_d2"], "ah_ok.d2")
    _require(ah_ok_k >= 2 and 0 <= ah_ok_el <= ah_ok_k and 0 <= ah_ok_u <= ah_ok_el, "ah-ok-counts")
    _require(Fraction(0, 1) < ah_ok_r2 <= Fraction(1, 1) and ah_ok_r2 * ah_ok_d2 == Fraction(1, 1), "ah-ok-renyi-inv")
    _require(ah_ok["selected_candidate_id"] != "cand-rogue-outlier", "ah-rogue-blocked")
    for ah_label, ah_obj in (("ah_ok", ah_ok), ("ah_bad", ah_bad)):
        _require(
            ah_obj["zone"] == "ZONE_A_SOCRATIC_DISCOVERY"
            and ah_obj["epistemic_tag"] == "UNVERIFIED_HYPOTHESIS"
            and ah_obj["diversity_scope"] == "FEASIBLE_COHORT_ONLY",
            f"ah-zone-a-unverified-tag:{ah_label}",
        )
    if ah_ok_pass:
        _require_clean_ascii(ah_ok["selected_candidate_id"], "ah_ok.selected_candidate_id")
        _require(
            ah_ok_u >= 2 and ah_ok_d2 > Fraction(1, 1) and ah_ok["veto_reasons"] == [],
            "ah-ok-pass-consistency",
        )
    if not ah_bad_pass:
        ah_bad_vetoes = ah_bad["veto_reasons"]
        _require(
            isinstance(ah_bad_vetoes, list)
            and len(ah_bad_vetoes) >= 1
            and ah_bad["selected_candidate_id"] is None,
            "ah-bad-veto-consistency",
        )
        clean_ah_vetoes = [_require_clean_ascii(code, f"ah_bad.veto[{i}]") for i, code in enumerate(ah_bad_vetoes)]
        _require(
            len(set(clean_ah_vetoes)) == len(clean_ah_vetoes)
            and all(code in _VALID_AH_VETO_CODES for code in clean_ah_vetoes),
            "ah-bad-veto-codes",
        )

    # 4. Invariant B ratchet semantic replay & #16 calibration proof
    inv_b = invariants["invariant_b_monotone_ratchet"]
    _require(isinstance(inv_b, dict) and set(inv_b.keys()) == _EXPECTED_INV_B_KEYS, "inv_b-keys-exact")
    rt = inv_b["trace_witness"]
    cg = inv_b["calibration_gap_witness"]
    _require(
        isinstance(rt, dict)
        and set(rt.keys()) == _EXPECTED_RT_KEYS
        and isinstance(cg, dict)
        and set(cg.keys()) == _EXPECTED_CG_KEYS,
        "inv_b-subdicts",
    )
    rt_dim = _require_exact_int(rt["dim"], "rt.dim")
    _require(rt_dim >= 1, "rt-dim-pos")
    req_mono = _require_exact_bool(rt["require_monotone_behavior"], "rt.require_monotone_behavior")
    tot_s = _require_exact_int(rt["total_steps"], "rt.total_steps")
    com_c = _require_exact_int(rt["committed_count"], "rt.committed_count")
    rol_c = _require_exact_int(rt["rollback_count"], "rt.rollback_count")
    b_max = _parse_frac_str(rt["budget_max"], "rt.budget_max")
    spent = _parse_frac_str(rt["total_spent"], "rt.total_spent")
    r_sq = _parse_frac_str(rt["radius_sq"], "rt.radius_sq")
    f_drift = _parse_frac_str(rt["final_drift_sq"], "rt.final_drift_sq")
    b_floor = _parse_frac_str(rt["behavior_floor"], "rt.behavior_floor")
    f_best_beh = _parse_frac_str(rt["final_best_behavior"], "rt.final_best_behavior")
    fcw_raw = rt["final_committed_weights"]
    _require(isinstance(fcw_raw, list) and len(fcw_raw) == rt_dim, "rt-final-weights-dim")
    fcw = [_parse_frac_str(w_raw, f"rt.final_committed_weights[{j}]") for j, w_raw in enumerate(fcw_raw)]
    _require(r_sq > Fraction(0, 1) and b_max > Fraction(0, 1), "rt-pos-limits")
    _require(tot_s >= 1 and com_c >= 0 and rol_c >= 0 and com_c + rol_c == tot_s, "rt-step-conservation")
    trace_rows = rt["trace"]
    _require(isinstance(trace_rows, list) and len(trace_rows) == tot_s, "rt-trace-len")
    trace_com = 0
    seen_sids: set[str] = set()
    running_spent = Fraction(0, 1)
    best_beh = b_floor
    last_committed_drift = Fraction(0, 1)
    for idx, row in enumerate(trace_rows):
        _require(isinstance(row, dict) and set(row.keys()) == _EXPECTED_RT_ROW_KEYS, f"rt-trace-row-keys:{idx}")
        sid = _require_clean_ascii(row["step_id"], f"rt.trace[{idx}].step_id")
        _require(sid not in seen_sids, f"rt-trace-dup-step:{sid}")
        seen_sids.add(sid)
        row_cost = _parse_frac_str(row["cost"], f"rt.trace[{idx}].cost")
        _require(row_cost > Fraction(0, 1), f"rt-trace-cost-pos:{idx}")
        row_cum = _parse_frac_str(row["cumulative_spent"], f"rt.trace[{idx}].cumulative_spent")
        row_drift = _parse_frac_str(row["candidate_drift_sq"], f"rt.trace[{idx}].candidate_drift_sq")
        _require(row_drift >= Fraction(0, 1), f"rt-trace-drift-nonneg:{idx}")
        row_beh = _parse_frac_str(row["behavior_score"], f"rt.trace[{idx}].behavior_score")
        row_com = _require_exact_bool(row["committed"], f"rt.trace[{idx}].committed")
        row_snap = _require_exact_bool(row["edge_snapped"], f"rt.trace[{idx}].edge_snapped")
        row_eq = _require_exact_bool(row["active_equals_committed"], f"rt.trace[{idx}].active_equals_committed")
        row_rej = row["rejection_reasons"]
        _require(isinstance(row_rej, list), f"rt-trace-rej-list:{idx}")
        clean_rej = [_require_clean_ascii(rr, f"rt.trace[{idx}].rej[{j}]") for j, rr in enumerate(row_rej)]
        _require(row_eq and row_com != row_snap, f"rt-trace-row-conservation:{idx}")
        expected_reasons: list[str] = []
        if running_spent + row_cost > b_max:
            expected_reasons.append("BUDGET_EXCEEDED")
        else:
            running_spent += row_cost
            if row_drift > r_sq:
                expected_reasons.append("NORM_RADIUS_EXCEEDED")
            if row_beh < b_floor:
                expected_reasons.append("BEHAVIOR_FLOOR_BREACH")
            if req_mono and row_beh < best_beh:
                expected_reasons.append("BEHAVIOR_REGRESSION")
        _require(
            clean_rej == expected_reasons and row_com == (len(expected_reasons) == 0),
            f"rt-trace-semantic-match:{idx}",
        )
        if row_com:
            best_beh = max(best_beh, row_beh)
            last_committed_drift = row_drift
            trace_com += 1
        _require(row_cum == running_spent, f"rt-trace-cum-spent:{idx}")
    _require(
        trace_com == com_c
        and running_spent == spent
        and f_drift == last_committed_drift
        and sum(w * w for w in fcw) == f_drift
        and f_best_beh == best_beh,
        "rt-trace-count-match",
    )

    cg_r = _parse_frac_str(cg["radius_sq"], "cg.radius_sq")
    cg_pd = _parse_frac_str(cg["perm_drift_sq"], "cg.perm_drift_sq")
    cg_fd = _parse_frac_str(cg["flip_drift_sq"], "cg.flip_drift_sq")
    cg_pr2 = _parse_frac_str(cg["perm_r2"], "cg.perm_r2")
    cg_fr2 = _parse_frac_str(cg["flip_r2"], "cg.flip_r2")
    cg_fr2_dec4 = _require_clean_ascii(cg["flip_r2_dec4"], "cg.flip_r2_dec4")
    cg_pfr = _require_exact_bool(cg["perm_norm_only_falsely_rejects"], "cg.perm_false_reject")
    cg_ffa = _require_exact_bool(cg["flip_norm_only_falsely_accepts"], "cg.flip_false_accept")
    cg_ratio = _require_clean_ascii(cg["drift_ratio_perm_over_flip"], "cg.ratio")
    cg_proved = _require_exact_bool(cg["calibration_gap_proved"], "cg.proved")
    _require(cg_r > Fraction(0, 1) and cg_fd >= Fraction(0, 1) and cg_pd >= Fraction(0, 1), "cg-nonneg-drifts")
    expected_pfr = cg_pd > cg_r and cg_pr2 == Fraction(1, 1)
    expected_ffa = cg_fd <= cg_r and cg_fr2 < Fraction(0, 1)
    expected_ratio = frac_str(cg_pd / cg_fd) if cg_fd > Fraction(0, 1) else "INF"
    _require(
        cg_pfr == expected_pfr
        and cg_ffa == expected_ffa
        and cg_fr2_dec4 == frac_dec(cg_fr2, 4)
        and cg_ratio == expected_ratio
        and cg_proved == (expected_pfr and expected_ffa),
        "cg-proved-match",
    )

    # 5. Invariant C Splicer controls
    inv_c = invariants["invariant_c_splicer_protocol"]
    _require(isinstance(inv_c, dict) and set(inv_c.keys()) == _EXPECTED_INV_C_KEYS, "inv_c-keys-exact")
    sp_ok = inv_c["compliant_graft_witness"]
    sp_bad = inv_c["adversarial_violation_witness"]
    _require(
        isinstance(sp_ok, dict)
        and set(sp_ok.keys()) == _EXPECTED_SPLICER_OUT_KEYS
        and isinstance(sp_bad, dict)
        and set(sp_bad.keys()) == _EXPECTED_SPLICER_OUT_KEYS,
        "inv_c-subdicts",
    )
    sp_ok_c = _require_exact_bool(sp_ok["compliant"], "sp_ok.compliant")
    sp_bad_c = _require_exact_bool(sp_bad["compliant"], "sp_bad.compliant")
    sp_ok_t = _require_exact_int(sp_ok["non_vendor_host_files_touched"], "sp_ok.touched")
    sp_ok_m = _require_exact_int(sp_ok["max_host_files_touched"], "sp_ok.max_touched")
    _require(1 <= sp_ok_t <= sp_ok_m, "sp-ok-touch-bounds")
    if sp_ok_c:
        _require(
            sp_ok["violations"] == []
            and sp_ok["airlock_boundary"] == "ZONE_A_TO_ZONE_B_BLINDED_LOCK"
            and sp_ok["airlock_leaked_fields"] == []
            and sp_ok["verifier_blinded_from_zone_a"] is True,
            "sp-ok-empty-violations",
        )
    sp_bad_v = sp_bad["violations"]
    _require(isinstance(sp_bad_v, list), "sp-bad-violations-list")
    sp_bad_clean = [_require_clean_ascii(code, f"sp_bad.violations[{i}]") for i, code in enumerate(sp_bad_v)]
    _require(
        len(set(sp_bad_clean)) == len(sp_bad_clean)
        and all(code in _VALID_SPLICER_VIOLATION_CODES for code in sp_bad_clean),
        "sp-bad-violations-codes",
    )

    r91_ok = r91_blow and r91_safe
    inv_a_ok = ah_ok_pass and not ah_bad_pass
    inv_b_ok = cg_proved and com_c >= 1 and rol_c >= 1
    inv_c_ok = sp_ok_c and not sp_bad_c and len(sp_bad_clean) >= 5

    violations: list[str] = []
    if not r91_ok:
        violations.append("REPLY91_DECAY_REFUTATION_INCOMPLETE")
    if not inv_a_ok:
        violations.append("INVARIANT_A_CONTROLS_FAILED")
    if not inv_b_ok:
        violations.append("INVARIANT_B_CONTROLS_FAILED")
    if not inv_c_ok:
        violations.append("INVARIANT_C_CONTROLS_FAILED")

    return {
        "certified": len(violations) == 0,
        "violations": violations,
        "portal_conservation_ok": True,
        "invariant_a_ok": inv_a_ok,
        "invariant_b_ok": inv_b_ok,
        "invariant_c_ok": inv_c_ok,
    }
