#!/usr/bin/env python3
"""Independent verifier for the warp-drive demo lanes (issue #7).

Reads only artifacts: frozen contract files, published pilot receipts,
candidate receipts, and receipt logs. It never imports the controller
(``warp_modeld.experiment``) or any Warp runtime code, so a verdict here
is an independent re-derivation, not a re-run of the code under audit.

Usage (from the repo root, after the lane branches are merged or checked
out at <exp-dir>):

    python3 tools/lane7_verify/verify.py contract --exp-dir experiments/demo-2026-11-22
    python3 tools/lane7_verify/verify.py leakage --exp-dir ... --harvest-meta harvest_v1.meta.json --ml-manifest ml-manifest.json
    python3 tools/lane7_verify/verify.py margins --pilot server_logit_check_v2.json
    python3 tools/lane7_verify/verify.py receipt --receipt receipt.json --exp-dir ...
    python3 tools/lane7_verify/verify.py receipt-log --log receipts.jsonl
    python3 tools/lane7_verify/verify.py cerebras-bounds --schema schemas/cerebras-candidate.schema.json --exp-dir ...
    python3 tools/lane7_verify/verify.py policy --measurements receipt.json --exp-dir ...
    python3 tools/lane7_verify/verify.py all --exp-dir ... [--harvest-meta ... --ml-manifest ... --pilot ... --receipt ... --log ... --schema ...]

Each check prints one JSON object: {"check", "verdict", "evidence"} with
verdict in VERIFIED / PARTIAL / FALSIFIED / UNVERIFIED. Exit code is 0
when no check is FALSIFIED, 1 when any check is FALSIFIED, 2 on error.
Exact checks (digests, counts, schema consts) are distinguished from
sampled measurements in the evidence text.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

# Frozen counts from the contract (thresholds.json): the margin rule covers 84
# adapter and 36 baseline probe requests, and the rollback rule needs 14 of 14
# sequences. The verifier keeps its own copies so it does not read them back
# from the controller under audit.
FROZEN_MARGIN_ADAPTER_REQUESTS = 84
FROZEN_MARGIN_BASELINE_REQUESTS = 36
FROZEN_ROLLBACK_SEQUENCES = 14

SUITE_ORDER = ("task", "retention_iid", "retention_shifted", "safety_canaries")
SUITE_FILES = {
    "task": "suites/task.json",
    "retention_iid": "suites/retention_iid.json",
    "retention_shifted": "suites/retention_shifted.json",
    "safety_canaries": "suites/safety_canaries.json",
}
DIGEST_FILES = {
    "task": "suites/task.json",
    "retention_iid": "suites/retention_iid.json",
    "retention_shifted": "suites/retention_shifted.json",
    "safety_canaries": "suites/safety_canaries.json",
    "thresholds": "thresholds.json",
    "controls": "controls.json",
    "receipt_schema": "receipt.schema.json",
    "audit_split_leakage": "audit/split_leakage.json",
    "generate_suites_script": "scripts/generate_suites.py",
}


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_bytes(payload) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_canonical(payload) -> str:
    return sha256_bytes(canonical_bytes(payload))


def _reject_constant(value):
    raise ValueError("non-strict JSON constant: %s" % value)


def load_json(path: Path, *, strict: bool = False):
    text = path.read_text(encoding="utf-8")
    if strict:
        return json.loads(text, parse_constant=_reject_constant)
    return json.loads(text)


def result(check: str, verdict: str, evidence: str) -> dict:
    return {"check": check, "verdict": verdict, "evidence": evidence}


# ---------------------------------------------------------------------------
# contract
# ---------------------------------------------------------------------------


def check_contract(exp_dir: Path) -> list[dict]:
    out: list[dict] = []
    try:
        manifest = load_json(exp_dir / "manifest.json")
        thresholds = load_json(exp_dir / "thresholds.json")
        controls = load_json(exp_dir / "controls.json")
    except (OSError, ValueError) as exc:
        return [result("contract", "FALSIFIED", "cannot load contract files: %s" % exc)]
    digests = manifest.get("digests")
    if not isinstance(digests, dict):
        return [result("contract", "FALSIFIED", "manifest has no digests mapping")]
    bad = []
    good = []
    for key, rel in DIGEST_FILES.items():
        path = exp_dir / rel
        if key not in digests:
            bad.append("%s: digest missing from manifest" % key)
            continue
        if not path.is_file():
            bad.append("%s: file missing (%s)" % (key, rel))
            continue
        actual = sha256_file(path)
        if actual != digests[key]:
            bad.append("%s: manifest %s, file %s" % (key, digests[key][:12], actual[:12]))
        else:
            good.append(key)
    combined = sha256_bytes(
        b"".join((exp_dir / SUITE_FILES[name]).read_bytes() for name in SUITE_ORDER)
    )
    if combined != digests.get("combined_suites"):
        bad.append("combined_suites: manifest %s, computed %s"
                   % (str(digests.get("combined_suites"))[:12], combined[:12]))
    else:
        good.append("combined_suites")
    if manifest.get("manifest_version") != thresholds.get("thresholds_version"):
        bad.append("manifest/thresholds versions disagree")
    if manifest.get("repair_budget_max_rounds") != thresholds.get("repair_budget_max_rounds"):
        bad.append("manifest/thresholds repair budgets disagree")
    for name in SUITE_ORDER:
        suite = load_json(exp_dir / SUITE_FILES[name])
        count = suite.get("n_cases", suite.get("n_canaries"))
        expected = manifest["suites"][name]["cases"]
        if count != expected:
            bad.append("suite %s holds %s cases, manifest pins %s" % (name, count, expected))
    if bad:
        return [result("contract", "FALSIFIED", "exact digest/count check failed: " + ". ".join(bad))]
    manifest_sha = sha256_file(exp_dir / "manifest.json")
    return [result("contract", "VERIFIED",
                   "exact: %d file digests + combined suite digest match the manifest. "
                   "Versions and suite counts agree. Manifest sha256=%s"
                   % (len(good), manifest_sha))]


# ---------------------------------------------------------------------------
# split leakage
# ---------------------------------------------------------------------------


def check_leakage(exp_dir: Path, harvest_meta: Path, ml_manifest: Path) -> list[dict]:
    try:
        meta = load_json(harvest_meta)
        mlm = load_json(ml_manifest)
        audit = load_json(exp_dir / "audit" / "split_leakage.json")
        task = load_json(exp_dir / "suites" / "task.json")
    except (OSError, ValueError) as exc:
        return [result("split_leakage", "UNVERIFIED", "cannot load inputs: %s" % exc)]
    held_ids = set(mlm["held_out_ids"])
    states = meta["states"]
    held = [s for s in states if s["id"] in held_ids]
    train = [s for s in states if s["id"] not in held_ids]
    train_pairs = {(tuple(s["pos_toks"]), tuple(s["neg_toks"])) for s in train}
    leaked = [s for s in held
              if (tuple(s["pos_toks"]), tuple(s["neg_toks"])) in train_pairs]
    by_family = {}
    for fam in sorted({s["family"] for s in held}):
        fam_states = [s for s in held if s["family"] == fam]
        fam_leak = [s for s in fam_states
                    if (tuple(s["pos_toks"]), tuple(s["neg_toks"])) in train_pairs]
        by_family[fam] = (len(fam_states), len(fam_leak))
    task_pairs = {(tuple(c["positive_tokens"]), tuple(c["negative_tokens"]))
                  for c in task["cases"]}
    held_pairs = {(tuple(s["pos_toks"]), tuple(s["neg_toks"])) for s in held}
    problems = []
    if len(held) != audit.get("held_out_states"):
        problems.append("held-out count %d vs audit %s" % (len(held), audit.get("held_out_states")))
    if len(train) != audit.get("training_states"):
        problems.append("training count %d vs audit %s" % (len(train), audit.get("training_states")))
    if len(leaked) != audit.get("reusing_train_pair"):
        problems.append("reusing %d vs audit %s" % (len(leaked), audit.get("reusing_train_pair")))
    if len(held_pairs) != audit.get("distinct_held_out_pairs"):
        problems.append("distinct held-out pairs %d vs audit %s"
                        % (len(held_pairs), audit.get("distinct_held_out_pairs")))
    if len(train_pairs) != audit.get("distinct_training_pairs"):
        problems.append("distinct training pairs %d vs audit %s"
                        % (len(train_pairs), audit.get("distinct_training_pairs")))
    if task_pairs != held_pairs:
        problems.append("task suite pairs do not match the held-out states")
    for fam, (n, leak) in by_family.items():
        entry = audit.get("by_family", {}).get(fam, {})
        if entry.get("held_out_states") != n or entry.get("reusing_train_pair") != leak:
            problems.append("family %s: recomputed %d/%d, audit %s/%s"
                            % (fam, leak, n, entry.get("reusing_train_pair"),
                               entry.get("held_out_states")))
    if problems:
        return [result("split_leakage", "FALSIFIED",
                       "exact recomputation disagrees with the audit: " + ". ".join(problems))]
    return [result("split_leakage", "VERIFIED",
                   "exact: %d/%d held-out states (%.1f%%) reuse a training pair. "
                   "By family %s. %d distinct held-out pairs, %d distinct training pairs"
                   % (len(leaked), len(held), 100.0 * len(leaked) / len(held),
                      ", ".join("%s %d/%d" % (f, l, n) for f, (n, l) in sorted(by_family.items())),
                      len(held_pairs), len(train_pairs)))]


# ---------------------------------------------------------------------------
# margins
# ---------------------------------------------------------------------------


def check_margins(pilot: Path) -> list[dict]:
    try:
        data = load_json(pilot)
    except (OSError, ValueError) as exc:
        return [result("margins", "UNVERIFIED", "cannot load pilot file: %s" % exc)]
    threshold = data.get("decision_threshold_margin_midpoint")
    if not isinstance(threshold, (int, float)):
        return [result("margins", "UNVERIFIED", "pilot file has no decision_threshold_margin_midpoint")]
    rows = []
    for rnd in data.get("rounds", []):
        for res in rnd.get("results", []):
            if res.get("margin") is not None:
                rows.append((res.get("requested"), float(res["margin"])))
    triple = [m for req, m in rows if req == "triple"]
    w0 = [m for req, m in rows if req == "w0"]
    if not triple or not w0:
        return [result("margins", "UNVERIFIED", "pilot rounds carry no triple/w0 margins")]
    summary = data.get("summary", {})
    problems = []
    if len(triple) != summary.get("triple_requests"):
        problems.append("triple n=%d vs summary %s" % (len(triple), summary.get("triple_requests")))
    if len(w0) != summary.get("w0_requests"):
        problems.append("w0 n=%d vs summary %s" % (len(w0), summary.get("w0_requests")))
    if abs(min(triple) - summary.get("triple_margin_min", min(triple))) > 1e-9:
        problems.append("triple min disagrees with summary")
    if abs(max(w0) - summary.get("w0_margin_max", max(w0))) > 1e-9:
        problems.append("w0 max disagrees with summary")
    bad_triple = [m for m in triple if m <= threshold]
    bad_w0 = [m for m in w0 if m > threshold]
    if bad_triple:
        problems.append("%d adapter margins at or below the threshold" % len(bad_triple))
    if bad_w0:
        problems.append("%d baseline margins above the threshold" % len(bad_w0))
    if problems:
        return [result("margins", "FALSIFIED",
                       "recomputed from %d raw round results: " % len(rows) + ". ".join(problems))]
    return [result("margins", "VERIFIED",
                   "exact, recomputed from %d raw round results: adapter %d/%d above %.4f "
                   "(range %.4f to %.4f). Baseline %d/%d at or below (range %.4f to %.4f). "
                   "Gap %.4f"
                   % (len(rows), len(triple), len(triple), threshold, min(triple), max(triple),
                      len(w0), len(w0), min(w0), max(w0),
                      min(triple) - max(w0)))]


# ---------------------------------------------------------------------------
# receipt + receipt log
# ---------------------------------------------------------------------------


def _validate_against_schema(value, schema, path: str, problems: list[str]) -> None:
    if not isinstance(schema, dict):
        return
    if "const" in schema and value != schema["const"]:
        problems.append("%s: %r != const %r" % (path, value, schema["const"]))
        return
    if "enum" in schema and value not in schema["enum"]:
        problems.append("%s: %r not in %s" % (path, value, schema["enum"]))
    expected = schema.get("type")
    if expected:
        types = (expected,) if isinstance(expected, str) else tuple(expected)
        ok = False
        for t in types:
            if t == "object" and isinstance(value, dict):
                ok = True
            elif t == "array" and isinstance(value, list):
                ok = True
            elif t == "string" and isinstance(value, str):
                ok = True
            elif t == "number" and isinstance(value, (int, float)) and not isinstance(value, bool):
                ok = True
            elif t == "integer" and isinstance(value, int) and not isinstance(value, bool):
                ok = True
            elif t == "boolean" and isinstance(value, bool):
                ok = True
            elif t == "null" and value is None:
                ok = True
        if not ok:
            problems.append("%s: %r is not of type %s" % (path, value, expected))
            return
    if "maximum" in schema and isinstance(value, (int, float)) and value > schema["maximum"]:
        problems.append("%s: %s exceeds maximum %s" % (path, value, schema["maximum"]))
    if isinstance(value, dict):
        for req in schema.get("required", []):
            if req not in value:
                problems.append("%s: missing required %s" % (path, req))
        for key, subschema in schema.get("properties", {}).items():
            if key in value:
                _validate_against_schema(value[key], subschema, path + "." + key, problems)


def check_receipt(receipt_path: Path, exp_dir: Path) -> list[dict]:
    try:
        receipt = load_json(receipt_path, strict=True)
        schema = load_json(exp_dir / "receipt.schema.json")
        manifest = load_json(exp_dir / "manifest.json")
    except (OSError, ValueError) as exc:
        return [result("receipt", "FALSIFIED", "cannot load receipt or contract: %s" % exc)]
    problems: list[str] = []
    _validate_against_schema(receipt, schema, "receipt", problems)
    if receipt.get("manifest_sha256") != sha256_file(exp_dir / "manifest.json"):
        problems.append("manifest_sha256 does not match the recomputed manifest digest")
    combined = sha256_bytes(
        b"".join((exp_dir / SUITE_FILES[name]).read_bytes() for name in SUITE_ORDER))
    if receipt.get("suite_sha256") != combined:
        problems.append("suite_sha256 does not match the recomputed combined suite digest")
    cfg = receipt.get("candidate", {}).get("config", {})
    knobs = manifest.get("allowed_candidate_knobs", {})
    if cfg.get("rank") != knobs.get("rank"):
        problems.append("candidate rank %s != frozen %s" % (cfg.get("rank"), knobs.get("rank")))
    if cfg.get("target_layer") != manifest.get("last_layer_target", {}).get("layer"):
        problems.append("candidate target_layer %s != frozen %s"
                        % (cfg.get("target_layer"),
                           manifest.get("last_layer_target", {}).get("layer")))
    eta_range = knobs.get("eta_range", [None, None])
    eta = cfg.get("eta")
    if eta is None or not (eta_range[0] <= eta <= eta_range[1]):
        problems.append("candidate eta %s outside frozen range %s" % (eta, eta_range))
    if cfg.get("lora_scale") not in (0.0, 1.0, -1.0):
        problems.append("candidate lora_scale %s is not 0.0, 1.0, or -1.0" % cfg.get("lora_scale"))
    if problems:
        return [result("receipt", "FALSIFIED", ". ".join(problems))]
    return [result("receipt", "VERIFIED",
                   "exact: receipt matches the frozen schema consts, manifest and "
                   "combined suite digests recompute, candidate config matches the "
                   "frozen knobs (rank %s, layer %s, eta %s, scale %s). Verdict %s"
                   % (cfg.get("rank"), cfg.get("target_layer"), cfg.get("eta"),
                      cfg.get("lora_scale"), receipt.get("verdict")))]


def check_receipt_log(log_path: Path) -> list[dict]:
    try:
        lines = log_path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        return [result("receipt_log", "UNVERIFIED", "cannot read log: %s" % exc)]
    lines = [ln for ln in lines if ln.strip()]
    if not lines:
        return [result("receipt_log", "PARTIAL",
                       "empty log verifies vacuously: absence of receipts is undetectable "
                       "from the log alone")]
    prev = "0" * 64
    for index, line in enumerate(lines, start=1):
        try:
            entry = json.loads(line, parse_constant=_reject_constant)
        except ValueError as exc:
            return [result("receipt_log", "FALSIFIED",
                           "line %d is not strict JSON: %s" % (index, exc))]
        if entry.get("seq") != index:
            return [result("receipt_log", "FALSIFIED",
                           "line %d has seq %s, expected %d (gap or reorder)"
                           % (index, entry.get("seq"), index))]
        if entry.get("prev_sha256") != prev:
            return [result("receipt_log", "FALSIFIED",
                           "line %d prev_sha256 does not match the previous entry" % index)]
        claimed = entry.get("entry_sha256")
        body = {k: v for k, v in entry.items() if k != "entry_sha256"}
        if claimed != sha256_canonical(body):
            return [result("receipt_log", "FALSIFIED",
                           "line %d entry_sha256 does not recompute" % index)]
        prev = str(claimed)
    events = []
    for line in lines:
        events.append(json.loads(line).get("event"))
    return [result("receipt_log", "VERIFIED",
                   "exact: %d entries, sequence and hash chain recompute. Events: %s"
                   % (len(lines), " -> ".join(str(e) for e in events)))]


def check_config_digests(log_path: Path) -> list[dict]:
    try:
        lines = [ln for ln in log_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    except OSError as exc:
        return [result("config_digests", "UNVERIFIED", "cannot read log: %s" % exc)]
    proposed: dict[str, str] = {}
    evaluated: set[str] = set()
    recorded: set[str] = set()
    checked = 0
    for index, line in enumerate(lines, start=1):
        try:
            entry = json.loads(line, parse_constant=_reject_constant)
        except ValueError as exc:
            return [result("config_digests", "FALSIFIED",
                           "line %d is not strict JSON: %s" % (index, exc))]
        event = entry.get("event")
        if event == "candidate_proposed":
            config = entry.get("config")
            claimed = entry.get("config_digest")
            if config is None or claimed is None:
                return [result("config_digests", "FALSIFIED",
                               "candidate_proposed for %s is missing config or config_digest"
                               % entry.get("candidate_id"))]
            if sha256_canonical(config) != claimed:
                return [result("config_digests", "FALSIFIED",
                               "config_digest does not recompute for %s"
                               % entry.get("candidate_id"))]
            proposed[str(entry.get("candidate_id"))] = str(claimed)
            checked += 1
        elif event == "evaluated":
            evaluated.add(str(entry.get("candidate_id")))
        elif event == "candidate_digest_recorded":
            # No config is logged here. The digest must match the one
            # proposed for the same candidate, and it must have been
            # recorded before that candidate was evaluated: a digest
            # first recorded after evaluation binds nothing.
            candidate_id = str(entry.get("candidate_id"))
            claimed = entry.get("config_digest")
            earlier = proposed.get(candidate_id)
            if claimed is None or earlier is None:
                return [result("config_digests", "FALSIFIED",
                               "candidate_digest_recorded for %s has no matching proposal"
                               % entry.get("candidate_id"))]
            if claimed != earlier:
                return [result("config_digests", "FALSIFIED",
                               "digest recorded before evaluation differs from the proposed "
                               "digest for %s" % entry.get("candidate_id"))]
            if candidate_id in evaluated:
                return [result("config_digests", "FALSIFIED",
                               "digest for %s was first recorded after evaluation"
                               % entry.get("candidate_id"))]
            recorded.add(candidate_id)
            checked += 1
    # Fail closed: every evaluated candidate needs a digest recorded earlier in
    # the log. A digest recorded after evaluation was rejected above; this
    # catches candidates that were never proposed or never had a digest recorded.
    unbound = sorted(cid for cid in evaluated if cid not in recorded)
    if unbound:
        return [result("config_digests", "FALSIFIED",
                       "evaluated with no recorded digest: %s" % ", ".join(unbound))]
    if not checked:
        return [result("config_digests", "UNVERIFIED",
                       "no candidate_proposed/digest entries in the log")]
    if not recorded:
        return [result("config_digests", "VERIFIED",
                       "exact: %d logged config digests recompute from the logged configs "
                       "(canonical JSON, sorted keys). No digest was recorded, so no "
                       "before-evaluation binding is claimed" % checked)]
    unanchored = sorted(cid for cid in recorded if cid not in evaluated)
    if unanchored:
        return [result("config_digests", "UNVERIFIED",
                       "digest for %s matches the proposed digest, but no evaluated event "
                       "exists for it, so before-evaluation binding is not established"
                       % ", ".join(unanchored))]
    return [result("config_digests", "VERIFIED",
                   "exact: %d logged config digests recompute from the logged configs "
                   "(canonical JSON, sorted keys). Every digest was recorded before its "
                   "candidate was evaluated, and matches the proposed digest" % checked)]


# ---------------------------------------------------------------------------
# cerebras bounds
# ---------------------------------------------------------------------------


def check_cerebras_bounds(schema_path: Path, exp_dir: Path) -> list[dict]:
    try:
        schema = load_json(schema_path)
        manifest = load_json(exp_dir / "manifest.json")
    except (OSError, ValueError) as exc:
        return [result("cerebras_bounds", "UNVERIFIED", "cannot load inputs: %s" % exc)]
    problems = []
    props = schema.get("properties", {})
    frozen_rank = manifest.get("allowed_candidate_knobs", {}).get("rank")
    schema_ranks = props.get("rank", {}).get("enum", [])
    if schema_ranks != [frozen_rank]:
        problems.append("rank enum %s vs frozen rank %s" % (schema_ranks, frozen_rank))
    frozen_layer = manifest.get("last_layer_target", {}).get("layer")
    if props.get("target_layer", {}).get("const") != frozen_layer:
        problems.append("target_layer const %r vs frozen layer %s"
                        % (props.get("target_layer", {}).get("const"), frozen_layer))
    if "eta" not in props and "strength" in props:
        problems.append("schema carries strength, not the frozen eta knob")
    if "lambda" not in props:
        problems.append("schema carries no lambda knob")
    if "lora_scale" not in props and "strength" in props:
        problems.append("schema carries strength, not the frozen lora_scale knob")
    schema_quants = props.get("quantization", {}).get("enum", [])
    if "bf16" not in schema_quants:
        problems.append("quantization enum %s omits bf16" % (schema_quants,))
    if problems:
        return [result("cerebras_bounds", "FALSIFIED",
                       "Cerebras candidate bounds do not match the frozen contract: "
                       + "; ".join(problems))]
    return [result("cerebras_bounds", "VERIFIED",
                   "candidate bounds match the frozen contract")]


# ---------------------------------------------------------------------------
# acceptance policy (reimplemented from thresholds.json, not from the controller)
# ---------------------------------------------------------------------------


def check_policy(measurements_path: Path, exp_dir: Path) -> list[dict]:
    try:
        raw = load_json(measurements_path, strict=True)
        thresholds = load_json(exp_dir / "thresholds.json")
        controls = load_json(exp_dir / "controls.json")
        canary_ids = load_json(exp_dir / "suites" / "safety_canaries.json")["canary_ids"]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return [result("policy", "UNVERIFIED", "cannot load inputs: %s" % exc)]
    receipt = raw if "measurements" in raw else {"measurements": raw, "verdict": raw.get("verdict")}
    m = receipt["measurements"]
    control_id = None
    if isinstance(raw.get("candidate"), dict):
        control_id = raw["candidate"].get("config", {}).get("control_id")
    if control_id is None and isinstance(raw.get("control_id"), str):
        control_id = raw["control_id"]
    if control_id is None:
        control_id = raw.get("candidate", {}).get("candidate_id")
        if control_id not in ("base-control", "regressed-control"):
            control_id = None
    failed: list[str] = []
    task = thresholds["task"]
    margin = thresholds["adapter_application_margin"]
    retention = thresholds["retention"]
    t = m["task"]
    if t["top1"] < float(task["top1_min"]):
        failed.append("task_top1")
    if t["contested_fix_fraction"] < float(task["contested_fix_min_fraction"]):
        failed.append("task_contested_fix")
    if t["break_fraction"] > float(task["break_max_fraction"]):
        failed.append("task_break")
    mg = m["margin"]
    threshold = float(margin["threshold"])
    if mg["threshold"] != threshold:
        failed.append("margin_threshold")
    # Fail closed: all() over an empty list is True, so an empty measurement
    # set must not pass the gate.
    if not mg["margins_adapter"] or not all(v > threshold for v in mg["margins_adapter"]):
        failed.append("margin_adapter")
    if not mg["margins_baseline"] or not all(v <= threshold for v in mg["margins_baseline"]):
        failed.append("margin_baseline")
    # Margin counts must equal the frozen counts, and each list must be as long
    # as the number of requests the measurement reports.
    for side, frozen in (("adapter", FROZEN_MARGIN_ADAPTER_REQUESTS),
                         ("baseline", FROZEN_MARGIN_BASELINE_REQUESTS)):
        if len(mg["margins_" + side]) != mg.get(side + "_requests"):
            failed.append("margin_%s_length" % side)
        if mg.get(side + "_requests") != frozen:
            failed.append("margin_%s_requests" % side)
    if m["retention_iid"]["mean_kl"] > float(retention["iid_kl_max_mean"]):
        failed.append("retention_iid_kl")
    if m["retention_iid"]["top1_agreement"] < float(retention["iid_top1_agreement_min"]):
        failed.append("retention_iid_agreement")
    if m["retention_shifted"]["mean_kl"] > float(retention["shifted_kl_max_mean"]):
        failed.append("retention_shifted_kl")
    # Fail closed: no failures only counts when every frozen canary ran.
    if m["safety"]["failures"] or m["safety"].get("canaries_run") != len(canary_ids):
        failed.append("safety_canaries")
    rb = m["rollback"]
    if rb["exact_matches"] != rb["sequences"]:
        failed.append("rollback_exact")
    if rb["sequences"] != FROZEN_ROLLBACK_SEQUENCES:
        failed.append("rollback_sequences")
    if rb["max_logit_diff"] != 0.0:
        failed.append("rollback_logit_diff")
    if control_id == "base-control":
        prose = controls["unchanged_base"]["expected"].get("task_top1", "")
        match = re.search(r"within ([0-9.]+) of the published base value ([0-9.]+)", prose)
        if not match:
            return [result("policy", "UNVERIFIED",
                           "cannot parse the base-control expectation from controls.json")]
        tol, base = float(match.group(1)), float(match.group(2))
        control_failed = []
        if abs(t["top1"] - base) > tol:
            control_failed.append("base_task_top1")
        if m["safety"]["failures"]:
            control_failed.append("base_safety")
        expected = "CONTROL_PASS" if not control_failed else "REJECT"
        claimed = receipt.get("verdict")
        if claimed is not None and claimed != expected:
            return [result("policy", "FALSIFIED",
                           "independent control check says %s (%s), receipt claims %s"
                           % (expected, control_failed, claimed))]
        return [result("policy", "VERIFIED",
                       "independent base-control check: %s (task top1 %.3f vs base %.3f +/- %.2f)"
                       % (expected, t["top1"], base, tol))]
    if control_id == "regressed-control":
        prose = controls["deliberately_regressed"]["expected"].get("task_top1", "")
        match = re.search(r"below the base value ([0-9.]+)", prose)
        base = float(match.group(1)) if match else 0.518
        expected = "REJECT"
        claimed = receipt.get("verdict")
        detail = "task top1 %.3f vs base %.3f" % (t["top1"], base)
        if t["top1"] >= base:
            return [result("policy", "FALSIFIED",
                           "regressed control did not regress (%s). Expected REJECT" % detail)]
        if claimed is not None and claimed != expected:
            return [result("policy", "FALSIFIED",
                           "independent control check says REJECT, receipt claims %s" % claimed)]
        return [result("policy", "VERIFIED",
                       "independent regressed-control check: REJECT as expected (%s)" % detail)]
    expected = "ACCEPT" if not failed else "REJECT"
    claimed = receipt.get("verdict")
    if claimed is not None and claimed != expected:
        return [result("policy", "FALSIFIED",
                       "independent policy says %s (failed gates: %s), receipt claims %s"
                       % (expected, failed or "none", claimed))]
    return [result("policy", "VERIFIED",
                   "independent policy from thresholds.json: %s (failed gates: %s)"
                   % (expected, failed or "none"))]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def run_all(args) -> list[dict]:
    out: list[dict] = []
    exp_dir = Path(args.exp_dir)
    out += check_contract(exp_dir)
    if args.harvest_meta and args.ml_manifest:
        out += check_leakage(exp_dir, Path(args.harvest_meta), Path(args.ml_manifest))
    else:
        out.append(result("split_leakage", "UNVERIFIED",
                          "no harvest meta / ml manifest supplied"))
    if args.pilot:
        out += check_margins(Path(args.pilot))
    else:
        out.append(result("margins", "UNVERIFIED", "no pilot file supplied"))
    if args.receipt:
        out += check_receipt(Path(args.receipt), exp_dir)
        out += check_policy(Path(args.receipt), exp_dir)
    else:
        out.append(result("receipt", "UNVERIFIED", "no receipt supplied"))
        out.append(result("policy", "UNVERIFIED", "no receipt supplied"))
    if args.log:
        out += check_receipt_log(Path(args.log))
        out += check_config_digests(Path(args.log))
    else:
        out.append(result("receipt_log", "UNVERIFIED", "no receipt log supplied"))
        out.append(result("config_digests", "UNVERIFIED", "no receipt log supplied"))
    if args.schema:
        out += check_cerebras_bounds(Path(args.schema), exp_dir)
    else:
        out.append(result("cerebras_bounds", "UNVERIFIED", "no Cerebras schema supplied"))
    return out


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("contract")
    p.add_argument("--exp-dir", required=True)
    p = sub.add_parser("leakage")
    p.add_argument("--exp-dir", required=True)
    p.add_argument("--harvest-meta", required=True)
    p.add_argument("--ml-manifest", required=True)
    p = sub.add_parser("margins")
    p.add_argument("--pilot", required=True)
    p = sub.add_parser("receipt")
    p.add_argument("--receipt", required=True)
    p.add_argument("--exp-dir", required=True)
    p = sub.add_parser("receipt-log")
    p.add_argument("--log", required=True)
    p = sub.add_parser("config-digests")
    p.add_argument("--log", required=True)
    p = sub.add_parser("cerebras-bounds")
    p.add_argument("--schema", required=True)
    p.add_argument("--exp-dir", required=True)
    p = sub.add_parser("policy")
    p.add_argument("--measurements", required=True)
    p.add_argument("--exp-dir", required=True)
    p = sub.add_parser("all")
    p.add_argument("--exp-dir", required=True)
    p.add_argument("--harvest-meta")
    p.add_argument("--ml-manifest")
    p.add_argument("--pilot")
    p.add_argument("--receipt")
    p.add_argument("--log")
    p.add_argument("--schema")
    args = parser.parse_args(argv)
    if args.command == "contract":
        checks = check_contract(Path(args.exp_dir))
    elif args.command == "leakage":
        checks = check_leakage(Path(args.exp_dir), Path(args.harvest_meta), Path(args.ml_manifest))
    elif args.command == "margins":
        checks = check_margins(Path(args.pilot))
    elif args.command == "receipt":
        checks = check_receipt(Path(args.receipt), Path(args.exp_dir))
    elif args.command == "receipt-log":
        checks = check_receipt_log(Path(args.log))
    elif args.command == "config-digests":
        checks = check_config_digests(Path(args.log))
    elif args.command == "cerebras-bounds":
        checks = check_cerebras_bounds(Path(args.schema), Path(args.exp_dir))
    elif args.command == "policy":
        checks = check_policy(Path(args.measurements), Path(args.exp_dir))
    elif args.command == "all":
        checks = run_all(args)
    else:  # pragma: no cover
        parser.error("unknown command")
    for check in checks:
        print(json.dumps(check, sort_keys=True))
    return 1 if any(c["verdict"] == "FALSIFIED" for c in checks) else 0


if __name__ == "__main__":
    raise SystemExit(main())
