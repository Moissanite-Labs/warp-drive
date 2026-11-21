#!/usr/bin/env python3
"""Issue #4 frozen experiment contract, split-leakage audit, and Ring-0 lock (AUDIT-063).

Pure Python 3 standard library, zero floats on trust paths, zero bare asserts.
Synthesizes:
  - alphaxiv/OpenResearch FROZEN.md min_reader_version & unknown-field preservation (AUDIT-057R)
  - Aletheia v1.3.0 Ring-0 immutable section lock & Gate-8 preregistration discipline
  - warp-modeld strict duplicate-key JSON rejection & 4-layer checkpoint pinning
"""

from __future__ import annotations

from fractions import Fraction
import hashlib
import hmac
import json
import re
from typing import Any, Mapping, Sequence

CONTRACT_SCHEMA = "warp-experiment-contract/v0.1"
RECEIPT_SCHEMA = "warp-experiment-receipt/v0.1"
HARNESS_LABEL = "project-specific-weight-experiment-harness"
EXPECTED_COMPILER_REPO = "siliconcordat/weft"
MIN_READER_VERSION = 1
MAX_REPAIR_ROUNDS_CEILING = 3

SHA256_RE = re.compile(r"\A[0-9a-f]{64}\Z")
COMMIT40_RE = re.compile(r"\A[0-9a-f]{40}\Z")
LAYER_RE = re.compile(r"\Ablk\.[0-9]+\Z")

ALLOWED_QUANTIZATIONS: frozenset[str] = frozenset({"f16", "q8_0"})

RING0_FROZEN_KEYS: tuple[str, ...] = (
    "contract_schema",
    "min_reader_version",
    "harness_label",
    "base_checkpoint",
    "runtime_flags_sha256",
    "compiler_repo",
    "compiler_commit",
    "parent_lineage",
    "target_layer",
    "allowed_knobs",
    "frozen_thresholds",
    "max_repair_rounds",
    "suite_digests",
    "receipt_schema",
    "preregistration",
)

FORBIDDEN_PROPOSAL_OVERRIDE_KEYS: frozenset[str] = frozenset(
    {
        "manifest_sha256",
        "frozen_thresholds",
        "thresholds_override",
        "suite_digests",
        "max_repair_rounds",
        "receipt_schema",
        "harness_label",
        "accept_policy",
        "lora",
        "raw_lora",
    }
)


class ExperimentContractError(ValueError):
    """Fail-closed contract, split-leakage, or Ring-0 tamper error."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message

    def to_dict(self) -> dict[str, str]:
        return {"code": self.code, "message": self.message}


def canonical_json_bytes(payload: Any) -> bytes:
    """Serialize payload into deterministic canonical UTF-8 JSON bytes."""
    verify_no_floats(payload)
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def sha256_canonical(payload: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def verify_no_floats(obj: Any, path: str = "$") -> None:
    """Recursively reject any Python float on exact-contract trust paths."""
    if isinstance(obj, float):
        raise ExperimentContractError("ERR_FLOAT_FORBIDDEN", f"float forbidden at {path}: {obj!r}")
    if isinstance(obj, Mapping):
        for key, val in obj.items():
            verify_no_floats(val, f"{path}.{key}")
    elif isinstance(obj, (list, tuple)):
        for idx, val in enumerate(obj):
            verify_no_floats(val, f"{path}[{idx}]")


def loads_strict_unique_json(raw_text: str, *, forbid_floats: bool = True) -> Any:
    """Strict JSON parser rejecting duplicate object keys and optional floats."""
    if not isinstance(raw_text, str):
        raise ExperimentContractError("ERR_INVALID_JSON", "JSON input must be str")

    def _pairs_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, val in pairs:
            if key in out:
                raise ExperimentContractError("ERR_DUPLICATE_JSON_KEY", f"duplicate JSON key: {key!r}")
            out[key] = val
        return out

    try:
        parsed = json.loads(raw_text, object_pairs_hook=_pairs_hook)
    except ExperimentContractError:
        raise
    except json.JSONDecodeError as exc:
        raise ExperimentContractError("ERR_INVALID_JSON", f"malformed JSON: {exc}") from exc

    if forbid_floats:
        verify_no_floats(parsed)
    return parsed


def require_exact_int(
    value: Any,
    label: str,
    *,
    min_value: int | None = None,
    max_value: int | None = None,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ExperimentContractError("ERR_INVALID_INT", f"{label} must be exact int")
    if min_value is not None and value < min_value:
        raise ExperimentContractError("ERR_INT_RANGE", f"{label}={value} < {min_value}")
    if max_value is not None and value > max_value:
        raise ExperimentContractError("ERR_INT_RANGE", f"{label}={value} > {max_value}")
    return value


def require_non_empty_str(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ExperimentContractError("ERR_INVALID_STR", f"{label} must be non-empty str")
    return value


def require_sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.match(value) is None:
        raise ExperimentContractError("ERR_INVALID_SHA256", f"{label} must be 64-char lowercase hex")
    return value


def require_commit40(value: Any, label: str) -> str:
    if not isinstance(value, str) or COMMIT40_RE.match(value) is None:
        raise ExperimentContractError("ERR_INVALID_COMMIT", f"{label} must be 40-char lowercase hex")
    return value


def require_rational_pair(pair: Any, label: str, *, allow_zero_num: bool = True) -> Fraction:
    if not isinstance(pair, (list, tuple)) or len(pair) != 2:
        raise ExperimentContractError("ERR_INVALID_RATIONAL", f"{label} must be [num, den]")
    num = require_exact_int(pair[0], f"{label}.num", min_value=0 if allow_zero_num else 1)
    den = require_exact_int(pair[1], f"{label}.den", min_value=1)
    return Fraction(num, den)


def _normalize_split_case(case: Any, idx: int, split_name: str) -> tuple[str, str, str, tuple[str, tuple[str, ...]]]:
    if not isinstance(case, Mapping):
        raise ExperimentContractError("ERR_INVALID_CASE", f"{split_name}[{idx}] must be a mapping")
    case_id = require_non_empty_str(case.get("case_id"), f"{split_name}[{idx}].case_id")
    family_id = require_non_empty_str(case.get("family_id"), f"{split_name}[{idx}].family_id")
    prompt = require_non_empty_str(case.get("prompt"), f"{split_name}[{idx}].prompt")
    target_token = require_non_empty_str(case.get("target_token"), f"{split_name}[{idx}].target_token")
    neg_raw = case.get("negative_tokens")
    if not isinstance(neg_raw, (list, tuple)) or not neg_raw:
        raise ExperimentContractError("ERR_INVALID_CASE", f"{split_name}[{idx}].negative_tokens must be non-empty")
    neg_clean = tuple(sorted({require_non_empty_str(t, f"{split_name}[{idx}].neg") for t in neg_raw}))
    prompt_hash = hashlib.sha256(prompt.strip().encode("utf-8")).hexdigest()
    return case_id, family_id, prompt_hash, (target_token, neg_clean)


def audit_split_leakage(
    train_cases: Sequence[Mapping[str, Any]],
    heldout_cases: Sequence[Mapping[str, Any]],
    *,
    max_pair_overlap_ratio: Fraction = Fraction(0),
    raise_on_fail: bool = False,
) -> dict[str, Any]:
    """Explicit split-leakage audit closing Issue #2/#4's 98% reused token/negative-set trap."""
    if not isinstance(train_cases, (list, tuple)) or not train_cases:
        raise ExperimentContractError("ERR_EMPTY_SPLIT", "train_cases must be non-empty")
    if not isinstance(heldout_cases, (list, tuple)) or not heldout_cases:
        raise ExperimentContractError("ERR_EMPTY_SPLIT", "heldout_cases must be non-empty")
    if not isinstance(max_pair_overlap_ratio, Fraction) or max_pair_overlap_ratio < 0 or max_pair_overlap_ratio > 1:
        raise ExperimentContractError("ERR_INVALID_RATIONAL", "max_pair_overlap_ratio must be Fraction in [0, 1]")

    train_fams: set[str] = set()
    train_prompts: set[str] = set()
    train_pairs: set[tuple[str, tuple[str, ...]]] = set()
    seen_ids: set[str] = set()

    for idx, row in enumerate(train_cases):
        cid, fam, phash, pair = _normalize_split_case(row, idx, "train")
        if cid in seen_ids:
            raise ExperimentContractError("ERR_DUPLICATE_CASE_ID", f"duplicate case_id: {cid!r}")
        seen_ids.add(cid)
        train_fams.add(fam)
        train_prompts.add(phash)
        train_pairs.add(pair)

    held_fams: set[str] = set()
    prompt_overlap = 0
    pair_overlap = 0
    for idx, row in enumerate(heldout_cases):
        cid, fam, phash, pair = _normalize_split_case(row, idx, "heldout")
        if cid in seen_ids:
            raise ExperimentContractError("ERR_DUPLICATE_CASE_ID", f"duplicate case_id across splits: {cid!r}")
        seen_ids.add(cid)
        held_fams.add(fam)
        if phash in train_prompts:
            prompt_overlap += 1
        if pair in train_pairs:
            pair_overlap += 1

    fam_overlap = sorted(train_fams & held_fams)
    pair_ratio = Fraction(pair_overlap, len(heldout_cases))

    reasons: list[str] = []
    if fam_overlap:
        reasons.append(f"family_overlap:{len(fam_overlap)}")
    if prompt_overlap > 0:
        reasons.append(f"prompt_overlap:{prompt_overlap}")
    if pair_ratio > max_pair_overlap_ratio:
        reasons.append(f"pair_overlap_exceeded:{pair_ratio}>{max_pair_overlap_ratio}")

    passed = len(reasons) == 0
    result = {
        "passed": passed,
        "train_count": len(train_cases),
        "heldout_count": len(heldout_cases),
        "train_family_count": len(train_fams),
        "heldout_family_count": len(held_fams),
        "family_overlap_count": len(fam_overlap),
        "overlapping_families": fam_overlap,
        "prompt_overlap_count": prompt_overlap,
        "pair_overlap_count": pair_overlap,
        "pair_overlap_ratio_exact": str(pair_ratio),
        "max_pair_overlap_ratio_exact": str(max_pair_overlap_ratio),
        "reasons": reasons,
    }
    if raise_on_fail and not passed:
        raise ExperimentContractError("ERR_SPLIT_LEAKAGE", "; ".join(reasons))
    return result


def compute_manifest_sha256(manifest: Mapping[str, Any]) -> str:
    """Compute canonical Ring-0 SHA-256 over the frozen contract sections."""
    ring0 = {key: manifest[key] for key in RING0_FROZEN_KEYS}
    return sha256_canonical(ring0)


def validate_frozen_manifest(raw: Mapping[str, Any], *, reader_version: int = MIN_READER_VERSION) -> dict[str, Any]:
    """Validate versioned Issue #4 frozen manifest, Ring-0 digest, and FROZEN.md round-trip fence."""
    if not isinstance(raw, Mapping):
        raise ExperimentContractError("ERR_INVALID_MANIFEST", "manifest must be a mapping")
    verify_no_floats(raw)
    rver = require_exact_int(reader_version, "reader_version", min_value=1)

    for req_key in RING0_FROZEN_KEYS + ("manifest_sha256",):
        if req_key not in raw:
            raise ExperimentContractError("ERR_MISSING_FIELD", f"manifest missing required key {req_key!r}")

    if raw["contract_schema"] != CONTRACT_SCHEMA:
        raise ExperimentContractError("ERR_SCHEMA_MISMATCH", f"unsupported contract_schema {raw['contract_schema']!r}")
    min_ver = require_exact_int(raw["min_reader_version"], "min_reader_version", min_value=1)
    if rver < min_ver:
        raise ExperimentContractError("ERR_READER_TOO_OLD", f"reader_version {rver} < min_reader_version {min_ver}")
    if raw["harness_label"] != HARNESS_LABEL:
        raise ExperimentContractError("ERR_HARNESS_LABEL", f"harness_label must be {HARNESS_LABEL!r} (not W-MCP)")
    if raw["receipt_schema"] != RECEIPT_SCHEMA:
        raise ExperimentContractError("ERR_RECEIPT_SCHEMA", f"unsupported receipt_schema {raw['receipt_schema']!r}")
    if raw["compiler_repo"] != EXPECTED_COMPILER_REPO:
        raise ExperimentContractError("ERR_COMPILER_REPO", f"compiler_repo must be {EXPECTED_COMPILER_REPO!r}")
    require_commit40(raw["compiler_commit"], "compiler_commit")
    require_sha256(raw["runtime_flags_sha256"], "runtime_flags_sha256")

    target_layer = require_non_empty_str(raw["target_layer"], "target_layer")
    if LAYER_RE.match(target_layer) is None:
        raise ExperimentContractError("ERR_INVALID_TARGET_LAYER", f"target_layer must match blk.<idx>: {target_layer!r}")

    require_exact_int(raw["max_repair_rounds"], "max_repair_rounds", min_value=1, max_value=MAX_REPAIR_ROUNDS_CEILING)

    ckpt = raw["base_checkpoint"]
    if not isinstance(ckpt, Mapping):
        raise ExperimentContractError("ERR_INVALID_CHECKPOINT", "base_checkpoint must be mapping")
    require_non_empty_str(ckpt.get("model_id"), "base_checkpoint.model_id")
    for field in ("layout_sha256", "weights_sha256", "config_sha256", "tokenizer_sha256", "chat_template_sha256"):
        require_sha256(ckpt.get(field), f"base_checkpoint.{field}")

    lineage = raw["parent_lineage"]
    if not isinstance(lineage, Mapping):
        raise ExperimentContractError("ERR_INVALID_LINEAGE", "parent_lineage must be mapping")
    require_sha256(lineage.get("corpus_tree_sha256"), "parent_lineage.corpus_tree_sha256")
    dcommits = lineage.get("domain_commits")
    if not isinstance(dcommits, Mapping) or not dcommits:
        raise ExperimentContractError("ERR_INVALID_LINEAGE", "domain_commits must be non-empty mapping")
    for dom, sha in dcommits.items():
        require_non_empty_str(dom, "domain_commits key")
        require_commit40(sha, f"domain_commits[{dom}]")
    contested = lineage.get("contested_heads")
    if not isinstance(contested, list) or len(contested) > 0:
        raise ExperimentContractError("ERR_CONTESTED_LINEAGE", "contested_heads must be empty list")

    knobs = raw["allowed_knobs"]
    if not isinstance(knobs, Mapping):
        raise ExperimentContractError("ERR_INVALID_KNOBS", "allowed_knobs must be mapping")
    ranks = knobs.get("ranks")
    if not isinstance(ranks, list) or not ranks:
        raise ExperimentContractError("ERR_INVALID_KNOBS", "allowed_knobs.ranks must be non-empty list")
    for rk in ranks:
        require_exact_int(rk, "allowed_knobs.rank", min_value=1)
    s_den = require_exact_int(knobs.get("strength_den"), "allowed_knobs.strength_den", min_value=1)
    s_min = require_exact_int(knobs.get("strength_num_min"), "allowed_knobs.strength_num_min", min_value=1)
    s_max = require_exact_int(knobs.get("strength_num_max"), "allowed_knobs.strength_num_max", min_value=s_min)
    _ = (s_den, s_max)
    quants = knobs.get("quantizations")
    if not isinstance(quants, list) or not quants or any(q not in ALLOWED_QUANTIZATIONS for q in quants):
        raise ExperimentContractError("ERR_INVALID_KNOBS", "allowed_knobs.quantizations must be subset of {f16, q8_0}")

    thresh = raw["frozen_thresholds"]
    if not isinstance(thresh, Mapping):
        raise ExperimentContractError("ERR_INVALID_THRESHOLDS", "frozen_thresholds must be mapping")
    require_rational_pair(thresh.get("min_task_exact_gain"), "min_task_exact_gain", allow_zero_num=False)
    require_rational_pair(thresh.get("min_logprob_margin_delta"), "min_logprob_margin_delta", allow_zero_num=False)
    require_rational_pair(thresh.get("max_iid_retention_drop"), "max_iid_retention_drop", allow_zero_num=True)
    require_rational_pair(thresh.get("max_shifted_retention_drop"), "max_shifted_retention_drop", allow_zero_num=True)
    require_exact_int(thresh.get("max_unrelated_kl_milli"), "max_unrelated_kl_milli", min_value=0)
    safety_req = require_rational_pair(thresh.get("safety_canary_pass_required"), "safety_canary_pass_required", allow_zero_num=False)
    if safety_req != Fraction(1, 1):
        raise ExperimentContractError("ERR_SAFETY_FLOOR", "safety_canary_pass_required must be exact 1/1 (100%)")
    max_rb_diff = require_exact_int(thresh.get("max_rollback_logit_diff_milli"), "max_rollback_logit_diff_milli", min_value=0)
    if max_rb_diff != 0:
        raise ExperimentContractError("ERR_ROLLBACK_FLOOR", "max_rollback_logit_diff_milli must be exact 0")

    suites = raw["suite_digests"]
    if not isinstance(suites, Mapping):
        raise ExperimentContractError("ERR_INVALID_SUITES", "suite_digests must be mapping")
    for s_key in (
        "task_train_sha256",
        "task_heldout_sha256",
        "iid_retention_sha256",
        "shifted_retention_sha256",
        "safety_canaries_sha256",
    ):
        require_sha256(suites.get(s_key), f"suite_digests.{s_key}")

    prereg = raw["preregistration"]
    if not isinstance(prereg, Mapping):
        raise ExperimentContractError("ERR_PREREG_INVALID", "preregistration must be mapping")
    plan_commit = require_commit40(prereg.get("plan_commit"), "preregistration.plan_commit")
    if prereg.get("split_leakage_audit_passed") is not True:
        raise ExperimentContractError("ERR_PREREG_LEAKAGE", "split_leakage_audit_passed must be True")
    data_commit = prereg.get("data_commit")
    if data_commit is not None:
        require_commit40(data_commit, "preregistration.data_commit")
        if hmac.compare_digest(plan_commit, data_commit):
            raise ExperimentContractError("ERR_PREREG_SAME_COMMIT", "plan_commit must strictly precede data_commit")

    stored_sha = require_sha256(raw["manifest_sha256"], "manifest_sha256")
    computed_sha = compute_manifest_sha256(raw)
    if not hmac.compare_digest(stored_sha, computed_sha):
        raise ExperimentContractError("ERR_MANIFEST_TAMPERED", f"stored {stored_sha} != computed {computed_sha}")

    # Preserve unknown extension fields faithfully (OpenResearch FROZEN.md forward compatibility)
    return dict(raw)


def build_frozen_manifest(
    *,
    base_checkpoint: Mapping[str, Any],
    runtime_flags_sha256: str,
    compiler_commit: str,
    parent_lineage: Mapping[str, Any],
    target_layer: str,
    allowed_knobs: Mapping[str, Any],
    frozen_thresholds: Mapping[str, Any],
    max_repair_rounds: int,
    suite_digests: Mapping[str, Any],
    preregistration: Mapping[str, Any],
    extensions: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Construct, seal, and validate a canonical Issue #4 frozen experiment manifest."""
    body: dict[str, Any] = {
        "contract_schema": CONTRACT_SCHEMA,
        "min_reader_version": MIN_READER_VERSION,
        "harness_label": HARNESS_LABEL,
        "base_checkpoint": dict(base_checkpoint),
        "runtime_flags_sha256": runtime_flags_sha256,
        "compiler_repo": EXPECTED_COMPILER_REPO,
        "compiler_commit": compiler_commit,
        "parent_lineage": dict(parent_lineage),
        "target_layer": target_layer,
        "allowed_knobs": dict(allowed_knobs),
        "frozen_thresholds": dict(frozen_thresholds),
        "max_repair_rounds": max_repair_rounds,
        "suite_digests": dict(suite_digests),
        "receipt_schema": RECEIPT_SCHEMA,
        "preregistration": dict(preregistration),
    }
    body["manifest_sha256"] = compute_manifest_sha256(body)
    if extensions is not None:
        for k, v in extensions.items():
            if k in body:
                raise ExperimentContractError("ERR_EXTENSION_COLLISION", f"extension cannot overwrite frozen key {k!r}")
            body[k] = v
    return validate_frozen_manifest(body)


def _scan_forbidden_override_keys(obj: Any, path: str = "$") -> None:
    """Recursively reject forbidden Ring-0 override keys case-insensitively."""
    if isinstance(obj, Mapping):
        for key, val in obj.items():
            if str(key).lower() in FORBIDDEN_PROPOSAL_OVERRIDE_KEYS:
                raise ExperimentContractError(
                    "ERR_RING0_TAMPER",
                    f"proposal attempted forbidden override key {key!r} at {path}",
                )
            _scan_forbidden_override_keys(val, f"{path}.{key}")
    elif isinstance(obj, (list, tuple)):
        for idx, val in enumerate(obj):
            _scan_forbidden_override_keys(val, f"{path}[{idx}]")


def verify_ring0_immutability(frozen_manifest: Mapping[str, Any], proposal: Mapping[str, Any]) -> None:
    """Fail-closed Ring-0 lock: candidates cannot modify manifest, suites, thresholds, or schema."""
    if not isinstance(proposal, Mapping):
        raise ExperimentContractError("ERR_INVALID_PROPOSAL", "proposal must be a mapping")
    _scan_forbidden_override_keys(proposal)
    pinned_sha = frozen_manifest["manifest_sha256"]
    cand_contract_sha = proposal.get("contract_sha256")
    if cand_contract_sha is not None:
        if not isinstance(cand_contract_sha, str) or not hmac.compare_digest(cand_contract_sha, pinned_sha):
            raise ExperimentContractError("ERR_CONTRACT_DRIFT", "proposal contract_sha256 does not match frozen manifest")
