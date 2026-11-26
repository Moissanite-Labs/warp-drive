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
import math
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


def _reject_duplicate_keys(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError("duplicate JSON key: %r" % key)
        obj[key] = value
    return obj


def parse_json_strict(text: str):
    """Strict JSON only: NaN/Infinity/-Infinity constants and duplicate
    object keys are rejected (json.loads silently keeps the last of a
    duplicate pair otherwise)."""
    return json.loads(
        text, parse_constant=_reject_constant, object_pairs_hook=_reject_duplicate_keys
    )


def load_json(path: Path):
    return parse_json_strict(path.read_text(encoding="utf-8"))


def load_jsonl(path: Path) -> list[dict]:
    """Parse a JSONL log into a list of entry objects.

    Raises ValueError (never a traceback) on non-strict JSON, duplicate
    keys, or a line that is not a JSON object; OSError propagates for an
    unreadable file.
    """
    entries = []
    for index, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            entry = parse_json_strict(line)
        except ValueError as exc:
            raise ValueError("line %d is not strict JSON: %s" % (index, exc)) from exc
        if not isinstance(entry, dict):
            raise ValueError("line %d is not a JSON object" % index)
        entries.append(entry)
    return entries


def _is_number(value) -> bool:
    """A numeric measurement: int or float, never bool, always finite.
    Astronomically large ints (10**400) overflow float conversion, so they
    are rejected here rather than raising OverflowError downstream."""
    if type(value) not in (int, float):
        return False
    try:
        return math.isfinite(value)
    except OverflowError:
        return False


def _is_int(value) -> bool:
    """An exact integer count: never bool, never float."""
    return type(value) is int


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
    if not (isinstance(manifest, dict) and isinstance(thresholds, dict)
            and isinstance(controls, dict)):
        return [result("contract", "FALSIFIED",
                       "manifest/thresholds/controls must be JSON objects")]
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
    try:
        combined = sha256_bytes(
            b"".join((exp_dir / SUITE_FILES[name]).read_bytes() for name in SUITE_ORDER)
        )
    except OSError as exc:
        bad.append("combined_suites: cannot read suite files: %s" % exc)
        combined = None
    if combined is not None and combined != digests.get("combined_suites"):
        bad.append("combined_suites: manifest %s, computed %s"
                   % (str(digests.get("combined_suites"))[:12], combined[:12]))
    else:
        good.append("combined_suites")
    if manifest.get("manifest_version") != thresholds.get("thresholds_version"):
        bad.append("manifest/thresholds versions disagree")
    if manifest.get("repair_budget_max_rounds") != thresholds.get("repair_budget_max_rounds"):
        bad.append("manifest/thresholds repair budgets disagree")
    for name in SUITE_ORDER:
        try:
            suite = load_json(exp_dir / SUITE_FILES[name])
            count = suite.get("n_cases", suite.get("n_canaries"))
            expected = manifest["suites"][name]["cases"]
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
            bad.append("suite %s unreadable: %s" % (name, exc))
            continue
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
    if not all(isinstance(x, dict) for x in (meta, mlm, audit, task)):
        return [result("split_leakage", "UNVERIFIED",
                       "harvest meta / ml manifest / audit / task suite must be JSON objects")]
    try:
        held_ids = set(mlm["held_out_ids"])
        states = meta["states"]
        held = [s for s in states if s["id"] in held_ids]
        train = [s for s in states if s["id"] not in held_ids]
    except (KeyError, TypeError, AttributeError) as exc:
        return [result("split_leakage", "UNVERIFIED", "malformed inputs: %s" % exc)]
    if not isinstance(held_ids, (set, frozenset)) or not isinstance(states, list):
        return [result("split_leakage", "UNVERIFIED", "held_out_ids/states have the wrong shape")]
    state_keys = ("id", "family", "pos_toks", "neg_toks")
    if not all(isinstance(s, dict) and all(k in s for k in state_keys)
               and isinstance(s["pos_toks"], list) and isinstance(s["neg_toks"], list)
               for s in states):
        return [result("split_leakage", "UNVERIFIED", "states entries are malformed")]
    cases = task.get("cases")
    if not isinstance(cases, list) or not all(
        isinstance(c, dict) and isinstance(c.get("positive_tokens"), list)
        and isinstance(c.get("negative_tokens"), list) for c in cases
    ):
        return [result("split_leakage", "UNVERIFIED", "task suite cases are malformed")]
    problems = []
    if not held:
        problems.append("held-out set is empty")
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
    except OSError as exc:
        return [result("margins", "UNVERIFIED", "cannot read pilot file: %s" % exc)]
    except ValueError as exc:
        # Strict JSON everywhere: a bare NaN/Infinity token in the pilot
        # file is a falsified artifact, not an unverifiable one.
        return [result("margins", "FALSIFIED", "pilot file is not strict JSON: %s" % exc)]
    if not isinstance(data, dict):
        return [result("margins", "FALSIFIED", "pilot file is not a JSON object")]
    threshold = data.get("decision_threshold_margin_midpoint")
    if not _is_number(threshold):
        return [result("margins", "FALSIFIED",
                       "decision_threshold_margin_midpoint is not a finite number "
                       "(bool rejected): %r" % (threshold,))]
    rounds = data.get("rounds", [])
    if not isinstance(rounds, list):
        return [result("margins", "FALSIFIED", "rounds is not a list")]
    rows = []
    problems = []
    for rnd in rounds:
        if not isinstance(rnd, dict):
            problems.append("a round entry is not a JSON object")
            continue
        results = rnd.get("results", [])
        if not isinstance(results, list):
            problems.append("a round results field is not a list")
            continue
        for res in results:
            if not isinstance(res, dict):
                problems.append("a round result is not a JSON object")
                continue
            margin = res.get("margin")
            if margin is None:
                continue
            # Every numeric measurement must be a finite int/float, never a
            # bool; NaN compares False against everything, so it must be
            # rejected here, not silently skipped by the gate below.
            if not _is_number(margin):
                problems.append("margin %r is not a finite number (bool/NaN/inf rejected)"
                                % (margin,))
                continue
            rows.append((res.get("requested"), float(margin)))
    if problems:
        return [result("margins", "FALSIFIED",
                       "malformed raw round results: " + ". ".join(problems))]
    triple = [m for req, m in rows if req == "triple"]
    w0 = [m for req, m in rows if req == "w0"]
    if not triple or not w0:
        return [result("margins", "FALSIFIED",
                       "pilot rounds carry no usable triple/w0 margins")]
    summary = data.get("summary", {})
    if not isinstance(summary, dict):
        return [result("margins", "FALSIFIED", "summary is not a JSON object")]
    for key in ("triple_requests", "w0_requests"):
        if not _is_int(summary.get(key)):
            problems.append("summary %s is not an exact int: %r" % (key, summary.get(key)))
    for key, edge, values in (("triple_margin_min", min(triple), triple),
                              ("w0_margin_max", max(w0), w0)):
        claimed = summary.get(key, edge)
        if not _is_number(claimed) or abs(edge - claimed) > 1e-9:
            problems.append("%s disagrees with the recomputed %r" % (key, edge))
    if len(triple) != summary.get("triple_requests"):
        problems.append("triple n=%d vs summary %s" % (len(triple), summary.get("triple_requests")))
    if len(w0) != summary.get("w0_requests"):
        problems.append("w0 n=%d vs summary %s" % (len(w0), summary.get("w0_requests")))
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
        receipt = load_json(receipt_path)
        schema = load_json(exp_dir / "receipt.schema.json")
        manifest = load_json(exp_dir / "manifest.json")
    except (OSError, ValueError) as exc:
        return [result("receipt", "FALSIFIED", "cannot load receipt or contract: %s" % exc)]
    if not isinstance(receipt, dict):
        return [result("receipt", "FALSIFIED", "receipt is not a JSON object")]
    if not isinstance(schema, dict) or not isinstance(manifest, dict):
        return [result("receipt", "FALSIFIED", "contract files are not JSON objects")]
    problems: list[str] = []
    _validate_against_schema(receipt, schema, "receipt", problems)
    if receipt.get("manifest_sha256") != sha256_file(exp_dir / "manifest.json"):
        problems.append("manifest_sha256 does not match the recomputed manifest digest")
    combined = sha256_bytes(
        b"".join((exp_dir / SUITE_FILES[name]).read_bytes() for name in SUITE_ORDER))
    if receipt.get("suite_sha256") != combined:
        problems.append("suite_sha256 does not match the recomputed combined suite digest")
    candidate = receipt.get("candidate")
    cfg = candidate.get("config", {}) if isinstance(candidate, dict) else {}
    if not isinstance(cfg, dict):
        cfg = {}
    knobs = manifest.get("allowed_candidate_knobs", {})
    if not isinstance(knobs, dict):
        knobs = {}
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
        entries = load_jsonl(log_path)
    except OSError as exc:
        return [result("receipt_log", "UNVERIFIED", "cannot read log: %s" % exc)]
    except ValueError as exc:
        return [result("receipt_log", "FALSIFIED", str(exc))]
    if not entries:
        return [result("receipt_log", "PARTIAL",
                       "empty log verifies vacuously: absence of receipts is undetectable "
                       "from the log alone")]
    prev = "0" * 64
    for index, entry in enumerate(entries, start=1):
        seq = entry.get("seq")
        # Exact int: True == 1 in Python, but a bool is not a sequence number.
        if not _is_int(seq) or seq != index:
            return [result("receipt_log", "FALSIFIED",
                           "line %d has seq %r, expected %d (gap or reorder; bools are not ints)"
                           % (index, seq, index))]
        if entry.get("prev_sha256") != prev:
            return [result("receipt_log", "FALSIFIED",
                           "line %d prev_sha256 does not match the previous entry" % index)]
        claimed = entry.get("entry_sha256")
        body = {k: v for k, v in entry.items() if k != "entry_sha256"}
        if claimed != sha256_canonical(body):
            return [result("receipt_log", "FALSIFIED",
                           "line %d entry_sha256 does not recompute" % index)]
        prev = str(claimed)
    events = [entry.get("event") for entry in entries]
    return [result("receipt_log", "VERIFIED",
                   "exact: %d entries, sequence and hash chain recompute. Events: %s"
                   % (len(entries), " -> ".join(str(e) for e in events)))]


def check_config_digests(log_path: Path) -> list[dict]:
    try:
        entries = load_jsonl(log_path)
    except OSError as exc:
        return [result("config_digests", "UNVERIFIED", "cannot read log: %s" % exc)]
    except ValueError as exc:
        return [result("config_digests", "FALSIFIED", str(exc))]
    proposed: dict[str, str] = {}
    evaluated: set[str] = set()
    recorded: set[str] = set()
    checked = 0
    for index, entry in enumerate(entries, start=1):
        event = entry.get("event")
        if not isinstance(event, str):
            return [result("config_digests", "FALSIFIED",
                           "line %d has no string event" % index)]
        candidate_id = entry.get("candidate_id")
        if event in ("candidate_proposed", "evaluated", "candidate_digest_recorded"):
            # Exact non-empty string id: no str() coercion, so None, 1, and
            # "1" can never collide or pass as an id.
            if type(candidate_id) is not str or not candidate_id.strip():
                return [result("config_digests", "FALSIFIED",
                               "line %d (%s) has no non-empty string candidate_id: %r"
                               % (index, event, candidate_id))]
        if event == "candidate_proposed":
            if candidate_id in proposed:
                # Stricter than requiring a fresh digest per evaluation: a
                # re-proposed id is rejected outright, so a second config can
                # never be evaluated under the first one's binding.
                return [result("config_digests", "FALSIFIED",
                               "candidate %s was proposed twice; re-proposal is rejected"
                               % candidate_id)]
            config = entry.get("config")
            claimed = entry.get("config_digest")
            if config is None or claimed is None:
                return [result("config_digests", "FALSIFIED",
                               "candidate_proposed for %s is missing config or config_digest"
                               % candidate_id)]
            if sha256_canonical(config) != claimed:
                return [result("config_digests", "FALSIFIED",
                               "config_digest does not recompute for %s" % candidate_id)]
            proposed[candidate_id] = claimed
            checked += 1
        elif event == "evaluated":
            evaluated.add(candidate_id)
        elif event == "candidate_digest_recorded":
            # No config is logged here. The digest must match the one
            # proposed for the same candidate, and it must have been
            # recorded before that candidate was evaluated: a digest
            # first recorded after evaluation binds nothing.
            claimed = entry.get("config_digest")
            earlier = proposed.get(candidate_id)
            if claimed is None or earlier is None:
                return [result("config_digests", "FALSIFIED",
                               "candidate_digest_recorded for %s has no matching proposal"
                               % candidate_id)]
            if claimed != earlier:
                return [result("config_digests", "FALSIFIED",
                               "digest recorded before evaluation differs from the proposed "
                               "digest for %s" % candidate_id)]
            if candidate_id in evaluated:
                return [result("config_digests", "FALSIFIED",
                               "digest for %s was first recorded after evaluation"
                               % candidate_id)]
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
    if not isinstance(schema, dict) or not isinstance(manifest, dict):
        return [result("cerebras_bounds", "UNVERIFIED",
                       "schema/manifest must be JSON objects")]
    problems = []
    props = schema.get("properties", {})
    if not isinstance(props, dict):
        return [result("cerebras_bounds", "UNVERIFIED", "schema properties is not an object")]
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


def _measurement_problems(m) -> list[str]:
    """Fail-closed structural and type validation of a measurements mapping.

    Every numeric measurement must be a finite int/float and never a bool
    (True == 1 and False == 0 in every comparison below); every count must
    be an exact int; safety failures must be a list. Missing sections or
    keys are malformed input and return problems, never a traceback.
    """
    if not isinstance(m, dict):
        return ["measurements is not a JSON object"]
    problems: list[str] = []
    for key in ("task", "margin", "retention_iid", "retention_shifted", "safety", "rollback"):
        if not isinstance(m.get(key), dict):
            problems.append("measurement section %r is missing or not an object" % key)
    if problems:
        return problems
    task = m["task"]
    for key in ("top1", "contested_fix_fraction", "break_fraction"):
        if not _is_number(task.get(key)):
            problems.append("task.%s is not a finite number (bool rejected): %r"
                            % (key, task.get(key)))
    mg = m["margin"]
    if not _is_number(mg.get("threshold")):
        problems.append("margin.threshold is not a finite number (bool rejected): %r"
                        % (mg.get("threshold"),))
    for key in ("adapter_requests", "baseline_requests"):
        if not _is_int(mg.get(key)):
            problems.append("margin.%s is not an exact integer count: %r" % (key, mg.get(key)))
    for key in ("margins_adapter", "margins_baseline"):
        values = mg.get(key)
        if not isinstance(values, list) or not all(_is_number(v) for v in values):
            problems.append("margin.%s is not a list of finite numbers (bool rejected)" % key)
    for section, key in (("retention_iid", "mean_kl"), ("retention_iid", "top1_agreement"),
                         ("retention_shifted", "mean_kl")):
        if not _is_number(m[section].get(key)):
            problems.append("%s.%s is not a finite number (bool rejected): %r"
                            % (section, key, m[section].get(key)))
    safety = m["safety"]
    if not _is_int(safety.get("canaries_run")):
        problems.append("safety.canaries_run is not an exact integer count: %r"
                        % (safety.get("canaries_run"),))
    if not isinstance(safety.get("failures"), list):
        problems.append("safety.failures is not a list: %r" % (safety.get("failures"),))
    rb = m["rollback"]
    for key in ("exact_matches", "sequences"):
        if not _is_int(rb.get(key)):
            problems.append("rollback.%s is not an exact integer count: %r" % (key, rb.get(key)))
    if not _is_number(rb.get("max_logit_diff")):
        problems.append("rollback.max_logit_diff is not a finite number (bool rejected): %r"
                        % (rb.get("max_logit_diff"),))
    return problems


def _rollback_expectation(thresholds) -> tuple[int, float]:
    """The rollback rule as stated by thresholds.json (sequences, max logit
    difference), read from the file's rule prose; the module's frozen copies
    are the fallback when the file does not state them."""
    sequences, max_diff = FROZEN_ROLLBACK_SEQUENCES, 0.0
    rule = ""
    section = thresholds.get("rollback") if isinstance(thresholds, dict) else None
    if isinstance(section, dict) and isinstance(section.get("rule"), str):
        rule = section["rule"]
    match = re.search(r"(\d+)\s+of\s+\d+\s+sequences", rule)
    if match:
        sequences = int(match.group(1))
    match = re.search(r"max logit difference\s+([0-9]*\.?[0-9]+)", rule)
    if match:
        max_diff = float(match.group(1))
    return sequences, max_diff


def _expected_control_scale(controls, control_id):
    """The expected lora_scale for a control, read from controls.json (never
    hardcoded): the base control runs with no adapter (scale 0.0), the
    regressed control's construction states its sign-flipped scale."""
    if not isinstance(controls, dict):
        return None
    if control_id == "base-control":
        entry = controls.get("unchanged_base")
        if not isinstance(entry, dict):
            return None
        adapter = entry.get("adapter")
        if adapter is None:
            return 0.0
        if isinstance(adapter, dict):
            match = re.search(r"scale\s+(-?\d+(?:\.\d+)?)", str(adapter.get("construction", "")))
            if match:
                return float(match.group(1))
        return None
    if control_id == "regressed-control":
        entry = controls.get("deliberately_regressed")
        if not isinstance(entry, dict):
            return None
        adapter = entry.get("adapter")
        if isinstance(adapter, dict):
            match = re.search(r"scale\s+(-?\d+(?:\.\d+)?)", str(adapter.get("construction", "")))
            if match:
                return float(match.group(1))
    return None


def _base_top1_expectation(controls):
    """(tolerance, base value) parsed from the unchanged_base expectation in
    controls.json; None when the file does not state them."""
    entry = controls.get("unchanged_base") if isinstance(controls, dict) else None
    expected = entry.get("expected") if isinstance(entry, dict) else None
    prose = expected.get("task_top1") if isinstance(expected, dict) else None
    match = re.search(r"within ([0-9.]+) of the published base value ([0-9.]+)", str(prose))
    if match:
        return float(match.group(1)), float(match.group(2))
    return None


def _regressed_base_value(controls):
    entry = controls.get("deliberately_regressed") if isinstance(controls, dict) else None
    expected = entry.get("expected") if isinstance(entry, dict) else None
    prose = expected.get("task_top1") if isinstance(expected, dict) else None
    match = re.search(r"below the base value ([0-9.]+)", str(prose))
    return float(match.group(1)) if match else None


def check_policy(measurements_path: Path, exp_dir: Path) -> list[dict]:
    try:
        thresholds = load_json(exp_dir / "thresholds.json")
        controls = load_json(exp_dir / "controls.json")
        canary_ids = load_json(exp_dir / "suites" / "safety_canaries.json")["canary_ids"]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return [result("policy", "UNVERIFIED", "cannot load contract files: %s" % exc)]
    if not isinstance(thresholds, dict) or not isinstance(controls, dict):
        return [result("policy", "UNVERIFIED", "thresholds/controls must be JSON objects")]
    if not isinstance(canary_ids, list) or not all(isinstance(c, str) for c in canary_ids):
        return [result("policy", "UNVERIFIED",
                       "safety_canaries.json has no usable canary id list")]
    try:
        raw = load_json(measurements_path)
    except (OSError, ValueError) as exc:
        # A candidate artifact that is missing or not strict JSON is falsified,
        # not unverifiable: the verifier's own contract files are the only
        # inputs that may be UNVERIFIED on load.
        return [result("policy", "FALSIFIED",
                       "measurements file is missing or not strict JSON: %s" % exc)]
    if not isinstance(raw, dict):
        return [result("policy", "FALSIFIED", "measurements file is not a JSON object")]
    if isinstance(raw.get("measurements"), dict):
        receipt = raw
        m = raw["measurements"]
    else:
        receipt = {"measurements": raw, "verdict": raw.get("verdict")}
        m = raw
    problems = _measurement_problems(m)
    if problems:
        return [result("policy", "FALSIFIED", "malformed measurements: " + "; ".join(problems))]
    try:
        task = thresholds["task"]
        margin = thresholds["adapter_application_margin"]
        retention = thresholds["retention"]
    except (KeyError, TypeError) as exc:
        return [result("policy", "UNVERIFIED",
                       "thresholds.json is missing policy sections: %s" % exc)]
    rb_sequences, rb_max_diff = _rollback_expectation(thresholds)
    control_id = None
    candidate = raw.get("candidate")
    if isinstance(candidate, dict):
        cfg = candidate.get("config")
        if isinstance(cfg, dict) and isinstance(cfg.get("control_id"), str):
            control_id = cfg["control_id"]
        if control_id is None and isinstance(candidate.get("candidate_id"), str):
            control_id = candidate["candidate_id"]
    if control_id is None and isinstance(raw.get("control_id"), str):
        control_id = raw["control_id"]
    if control_id not in ("base-control", "regressed-control"):
        control_id = None
    failed: list[str] = []
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
    if rb["sequences"] != rb_sequences:
        failed.append("rollback_sequences")
    if rb["max_logit_diff"] != rb_max_diff:
        failed.append("rollback_logit_diff")
    if control_id is not None:
        # Control paths must satisfy the same canary, scale, and rollback
        # requirements as any candidate; the task/margin gates are replaced
        # by the control's own preregistered expectation below.
        expected_scale = _expected_control_scale(controls, control_id)
        if expected_scale is None:
            return [result("policy", "UNVERIFIED",
                           "cannot read the expected lora_scale for %s from controls.json"
                           % control_id)]
        control_failed: list[str] = []
        if m["safety"]["canaries_run"] != len(canary_ids):
            control_failed.append("control_canaries_run=%d of %d"
                                  % (m["safety"]["canaries_run"], len(canary_ids)))
        if m["safety"]["failures"]:
            control_failed.append("control_safety_failures")
        cfg = candidate.get("config") if isinstance(candidate, dict) else None
        scale = cfg.get("lora_scale") if isinstance(cfg, dict) else None
        if not _is_number(scale) or float(scale) != expected_scale:
            control_failed.append("control_lora_scale=%r, controls.json expects %s"
                                  % (scale, expected_scale))
        if (rb["exact_matches"] != rb["sequences"] or rb["sequences"] != rb_sequences
                or rb["max_logit_diff"] != rb_max_diff):
            control_failed.append("control_rollback")
        if control_id == "base-control":
            base_expect = _base_top1_expectation(controls)
            if base_expect is None:
                return [result("policy", "UNVERIFIED",
                               "cannot parse the base-control expectation from controls.json")]
            tol, base = base_expect
            if abs(t["top1"] - base) > tol:
                control_failed.append("base_task_top1")
            if control_failed:
                return [result("policy", "FALSIFIED",
                               "base-control run violates its control requirements: %s"
                               % ", ".join(control_failed))]
            claimed = receipt.get("verdict")
            if claimed is not None and claimed != "CONTROL_PASS":
                return [result("policy", "FALSIFIED",
                               "independent control check says CONTROL_PASS, receipt claims %s"
                               % claimed)]
            return [result("policy", "VERIFIED",
                           "independent base-control check: CONTROL_PASS (task top1 %.3f vs "
                           "base %.3f +/- %.2f; canaries %d/%d; lora_scale %s; rollback %d/%d "
                           "diff %s)"
                           % (t["top1"], base, tol, m["safety"]["canaries_run"], len(canary_ids),
                              scale, rb["exact_matches"], rb["sequences"], rb["max_logit_diff"]))]
        # regressed-control
        base = _regressed_base_value(controls)
        if base is None:
            base_expect = _base_top1_expectation(controls)
            base = base_expect[1] if base_expect else None
        if base is None:
            return [result("policy", "UNVERIFIED",
                           "cannot parse the regressed-control base value from controls.json")]
        if control_failed:
            return [result("policy", "FALSIFIED",
                           "regressed-control run violates its control requirements: %s"
                           % ", ".join(control_failed))]
        detail = "task top1 %.3f vs base %.3f" % (t["top1"], base)
        if t["top1"] >= base:
            return [result("policy", "FALSIFIED",
                           "regressed control did not regress (%s). Expected REJECT" % detail)]
        claimed = receipt.get("verdict")
        if claimed is not None and claimed != "REJECT":
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


def _fail_closed(check_name: str, fn, *args) -> list[dict]:
    """Run one check fail-closed: a malformed input must produce a FALSIFIED
    verdict, never a traceback."""
    try:
        return fn(*args)
    except Exception as exc:  # noqa: BLE001 - the verifier never tracebacks
        return [result(check_name, "FALSIFIED",
                       "input rejected before a verdict could be computed: %s: %s"
                       % (type(exc).__name__, exc))]


def run_all(args) -> list[dict]:
    out: list[dict] = []
    exp_dir = Path(args.exp_dir)
    out += _fail_closed("contract", check_contract, exp_dir)
    if args.harvest_meta and args.ml_manifest:
        out += _fail_closed("split_leakage", check_leakage, exp_dir,
                            Path(args.harvest_meta), Path(args.ml_manifest))
    else:
        out.append(result("split_leakage", "UNVERIFIED",
                          "no harvest meta / ml manifest supplied"))
    if args.pilot:
        out += _fail_closed("margins", check_margins, Path(args.pilot))
    else:
        out.append(result("margins", "UNVERIFIED", "no pilot file supplied"))
    if args.receipt:
        out += _fail_closed("receipt", check_receipt, Path(args.receipt), exp_dir)
        out += _fail_closed("policy", check_policy, Path(args.receipt), exp_dir)
    else:
        out.append(result("receipt", "UNVERIFIED", "no receipt supplied"))
        out.append(result("policy", "UNVERIFIED", "no receipt supplied"))
    if args.log:
        out += _fail_closed("receipt_log", check_receipt_log, Path(args.log))
        out += _fail_closed("config_digests", check_config_digests, Path(args.log))
    else:
        out.append(result("receipt_log", "UNVERIFIED", "no receipt log supplied"))
        out.append(result("config_digests", "UNVERIFIED", "no receipt log supplied"))
    if args.schema:
        out += _fail_closed("cerebras_bounds", check_cerebras_bounds, Path(args.schema), exp_dir)
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
    dispatch = {
        "contract": lambda: check_contract(Path(args.exp_dir)),
        "leakage": lambda: check_leakage(Path(args.exp_dir), Path(args.harvest_meta),
                                         Path(args.ml_manifest)),
        "margins": lambda: check_margins(Path(args.pilot)),
        "receipt": lambda: check_receipt(Path(args.receipt), Path(args.exp_dir)),
        "receipt-log": lambda: check_receipt_log(Path(args.log)),
        "config-digests": lambda: check_config_digests(Path(args.log)),
        "cerebras-bounds": lambda: check_cerebras_bounds(Path(args.schema), Path(args.exp_dir)),
        "policy": lambda: check_policy(Path(args.measurements), Path(args.exp_dir)),
    }
    if args.command == "all":
        checks = run_all(args)
    elif args.command in dispatch:
        checks = _fail_closed(args.command.replace("-", "_"), dispatch[args.command])
    else:  # pragma: no cover
        parser.error("unknown command")
    for check in checks:
        print(json.dumps(check, sort_keys=True))
    return 1 if any(c["verdict"] == "FALSIFIED" for c in checks) else 0


if __name__ == "__main__":
    raise SystemExit(main())
