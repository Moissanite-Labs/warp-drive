"""Bounded experiment controller for the demo-2026-11-22 experiment (issue #5).

This is a project-specific weight experiment harness, not an interoperable
W-MCP standard. It turns the frozen contract from issue #4 into repeated,
bounded experiments and nothing else.

The controller owns five operations:

- ``propose_candidate``: validate a small candidate schema (adapter
  strength ``eta``, preconditioning ``lambda``, rank, quantization, and
  LoRA scale) against the pinned last-layer target.
- ``compile_and_bind``: call the existing Weft compiler, bind the parent
  checkpoint, and record the candidate digest before any behavioral
  evaluation.
- ``evaluate``: run the frozen suites and retain all positive and
  negative results.
- ``promote_or_reject``: apply only the frozen acceptance policy loaded
  from the contract. A proposal cannot change that policy.
- ``rollback``: restore and verify the baseline, including the full Warp
  state flush across every state bank.

Reuse, not reinvention:

- The weight compiler is the Weft compiler at the commit pinned in the
  manifest (``siliconcordat/weft``, ``BetaEditNullspaceProjector`` with
  ``stage_edit`` / ``commit_patch``). This module calls it through the
  ``Compiler`` protocol; it does not reimplement compilation, null-space
  projection, or quantization. The supported quantization values are the
  Weft ``SUPPORTED_QUANT_DTYPES`` at that commit.
- The Warp lifecycle is ``warp_modeld`` on main. Rollback goes through
  ``WarpModeld.rollback`` via the ``WarpModeldLifecycle`` adapter, which
  flushes every state bank (KV, SSM, horizontal lattice). Raw LoRA
  overrides are rejected here at proposal time and again by
  ``WarpModeld.infer`` at the proxy.
- Mounting in production must go through ``WarpModeld.mount_stack``
  (Stages 1 to 4) before scoring. The ``Runtime.mount_adapter`` seam is
  where that wiring lands; the fake runtime in the tests stands in for
  that seam and proves control flow only.

Limits, stated plainly:

- Unit tests use fake compiler and runtime adapters. Fake-runtime
  results are logic checks, never adapted-model evidence.
- Thresholds are preregistered and UNVERIFIED against a live run until
  lane 5 measures the reference adapter against them (see the manifest).
- No GPU, no local checkpoint, and no live runtime exist on this
  machine, so no live measurement is claimed anywhere here.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence

from .errors import (
    CheckpointMismatchError,
    ContractDriftError,
    ControllerError,
    StateFlushError,
    UnverifiedLoraOverrideError,
)
from .fingerprint import compute_file_sha256
from .state_banks import ALL_STATE_BANKS

__all__ = [
    "BaselineCheck",
    "Candidate",
    "CompileResult",
    "Compiler",
    "ExperimentController",
    "FrozenContract",
    "Lifecycle",
    "Measurements",
    "PolicyVerdict",
    "ReceiptLog",
    "RollbackReport",
    "Runtime",
    "WarpModeldLifecycle",
    "apply_acceptance_policy",
    "build_receipt",
    "check_control",
    "load_contract",
    "make_control",
    "propose_candidate",
]

# Quantization values supported by the Weft compiler at the pinned commit
# (siliconcordat/weft src/weft/quant.py: SUPPORTED_QUANT_DTYPES).
SUPPORTED_QUANT_DTYPES = ("bf16", "f16", "f32", "int8", "int4")

# Keys a caller may never supply: a raw LoRA override bypasses the
# compiler, the certificate gate, and the digest-before-evaluation rule.
RAW_LORA_OVERRIDE_KEYS = frozenset(
    {
        "lora",
        "lora_path",
        "lora_scaled",
        "adapter",
        "adapter_path",
        "adapter_sha256",
        "adapter_file",
        "raw_lora",
        "weights",
        "gguf",
    }
)

CANDIDATE_KEYS = frozenset(
    {"eta", "lambda", "rank", "target_layer", "target_tensor", "lora_scale", "quant"}
)

_CANDIDATE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]*\Z")
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")

SUITE_ORDER = ("task", "retention_iid", "retention_shifted", "safety_canaries")
SUITE_FILES = {
    "task": "suites/task.json",
    "retention_iid": "suites/retention_iid.json",
    "retention_shifted": "suites/retention_shifted.json",
    "safety_canaries": "suites/safety_canaries.json",
}

# Base top-1 from the frontier report, used only by the base-control check
# in controls.json. It is a preregistered control expectation, not a gate
# any candidate can move.
BASE_TOP1 = 0.518
BASE_TOP1_TOLERANCE = 0.02

# Frozen rollback rule in thresholds.json: 14 of 14 sequences at k = 1, 4,
# and 16 with zero logit difference. The rule lives in prose in the
# contract file, so the count is pinned here with its source named.
FROZEN_ROLLBACK_SEQUENCES = 14


def hmac_compare(left: str, right: str) -> bool:
    """Constant-time digest comparison; non-string input never matches."""
    if not isinstance(left, str) or not isinstance(right, str):
        return False
    return hmac.compare_digest(left, right)


def _canonical_bytes(payload: Any) -> bytes:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def _sha256_canonical(payload: Any) -> str:
    return hashlib.sha256(_canonical_bytes(payload)).hexdigest()


def _require_number(value: Any, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ControllerError(f"{name} must be a number, got {value!r}")
    if not math.isfinite(float(value)):
        raise ControllerError(f"{name} must be finite, got {value!r}")
    return float(value)


def _require_int(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ControllerError(f"{name} must be an integer, got {value!r}")
    return int(value)


# ---------------------------------------------------------------------------
# Frozen contract
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FrozenContract:
    """The frozen experiment contract, loaded and digest-checked."""

    exp_dir: Path
    manifest: dict[str, Any]
    thresholds: dict[str, Any]
    controls: dict[str, Any]
    receipt_schema: dict[str, Any]
    suites: dict[str, dict[str, Any]]
    manifest_sha256: str
    combined_suite_sha256: str

    @property
    def experiment(self) -> str:
        return str(self.manifest["experiment"])

    @property
    def parent_sha256(self) -> str:
        return str(self.manifest["base_checkpoint"]["sha256"])

    @property
    def repair_budget_max_rounds(self) -> int:
        return int(self.manifest["repair_budget_max_rounds"])

    @property
    def target_layer(self) -> int:
        return int(self.manifest["last_layer_target"]["layer"])

    @property
    def target_tensor(self) -> str:
        return str(self.manifest["allowed_candidate_knobs"]["target_tensor"])

    @property
    def rank(self) -> int:
        return int(self.manifest["allowed_candidate_knobs"]["rank"])

    @property
    def eta_range(self) -> tuple[float, float]:
        low, high = self.manifest["allowed_candidate_knobs"]["eta_range"]
        return (float(low), float(high))

    @property
    def lambda_values(self) -> tuple[Any, ...]:
        return tuple(self.manifest["allowed_candidate_knobs"]["lambda_values"])

    @property
    def margin_threshold(self) -> float:
        return float(self.thresholds["adapter_application_margin"]["threshold"])

    @property
    def compiler_repo(self) -> str:
        return str(self.manifest["compiler"]["repo"])

    @property
    def compiler_commit(self) -> str:
        return str(self.manifest["compiler"]["commit"])


def _load_json(path: Path) -> dict[str, Any]:
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        raise ContractDriftError(f"cannot load {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ContractDriftError(f"{path} must hold a JSON object")
    return data


def load_contract(exp_dir: str | Path) -> FrozenContract:
    """Load the frozen contract and verify every pinned digest.

    Recomputes the sha256 of each contract file and the combined suite
    digest from disk and compares them with the manifest. Any mismatch,
    missing file, or version disagreement is contract drift and the
    contract is refused, never silently repaired.
    """
    root = Path(exp_dir)
    manifest = _load_json(root / "manifest.json")
    thresholds = _load_json(root / "thresholds.json")
    controls = _load_json(root / "controls.json")
    receipt_schema = _load_json(root / "receipt.schema.json")
    suites = {name: _load_json(root / SUITE_FILES[name]) for name in SUITE_ORDER}

    digests = manifest.get("digests")
    if not isinstance(digests, dict):
        raise ContractDriftError("manifest has no digests mapping")
    expected_files = {
        "task": root / SUITE_FILES["task"],
        "retention_iid": root / SUITE_FILES["retention_iid"],
        "retention_shifted": root / SUITE_FILES["retention_shifted"],
        "safety_canaries": root / SUITE_FILES["safety_canaries"],
        "audit_split_leakage": root / "audit/split_leakage.json",
        "generate_suites_script": root / "scripts/generate_suites.py",
        "thresholds": root / "thresholds.json",
        "controls": root / "controls.json",
        "receipt_schema": root / "receipt.schema.json",
    }
    for key, path in expected_files.items():
        if key not in digests:
            raise ContractDriftError(f"manifest digests missing {key}")
        if not path.is_file():
            raise ContractDriftError(f"contract file missing: {path}")
        actual = compute_file_sha256(path)
        if actual != digests[key]:
            raise ContractDriftError(
                f"digest mismatch for {key}: manifest {digests[key]}, file {actual}"
            )
    combined = hashlib.sha256(
        b"".join((root / SUITE_FILES[name]).read_bytes() for name in SUITE_ORDER)
    ).hexdigest()
    if combined != digests.get("combined_suites"):
        raise ContractDriftError(
            f"combined suite digest mismatch: manifest {digests.get('combined_suites')}, computed {combined}"
        )
    if manifest.get("manifest_version") != thresholds.get("thresholds_version"):
        raise ContractDriftError("manifest and thresholds versions disagree")
    if manifest.get("repair_budget_max_rounds") != thresholds.get(
        "repair_budget_max_rounds"
    ):
        raise ContractDriftError("manifest and thresholds repair budgets disagree")
    for name in SUITE_ORDER:
        expected_n = manifest["suites"][name]["cases"]
        suite = suites[name]
        count = suite.get("n_cases", suite.get("n_canaries"))
        if count != expected_n:
            raise ContractDriftError(
                f"suite {name} holds {count} cases, manifest pins {expected_n}"
            )
    manifest_sha256 = compute_file_sha256(root / "manifest.json")
    return FrozenContract(
        exp_dir=root,
        manifest=manifest,
        thresholds=thresholds,
        controls=controls,
        receipt_schema=receipt_schema,
        suites=suites,
        manifest_sha256=manifest_sha256,
        combined_suite_sha256=combined,
    )


# ---------------------------------------------------------------------------
# Candidates
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Candidate:
    """A validated candidate. Only the pinned last-layer target is valid."""

    candidate_id: str
    eta: float
    lam: float | str
    rank: int
    target_layer: int
    target_tensor: str
    lora_scale: float
    quant: str
    control_id: str | None = None

    def config_dict(self) -> dict[str, Any]:
        """Config as the frozen receipt schema records it.

        The frozen receipt schema has no ``quant`` field, so quant is
        recorded in the controller receipt log and bound into the compiled
        adapter digest instead of being added to the frozen receipt.
        """
        return {
            "rank": self.rank,
            "target_layer": self.target_layer,
            "target_tensor": self.target_tensor,
            "eta": self.eta,
            "lambda": self.lam,
            "lora_scale": self.lora_scale,
        }

    def digest_input(self) -> dict[str, Any]:
        config = self.config_dict()
        config["quant"] = self.quant
        if self.control_id is not None:
            config["control_id"] = self.control_id
        return config

    def config_digest(self) -> str:
        return _sha256_canonical(self.digest_input())


def propose_candidate(
    raw: Mapping[str, Any],
    contract: FrozenContract,
    *,
    candidate_id: str | None = None,
    control_id: str | None = None,
    allow_negative_scale: bool = False,
) -> Candidate:
    """Validate a candidate proposal against the frozen contract.

    Rejects malformed candidates, unsupported layers or tensors, out of
    range strength or rank, unknown quantization, unknown keys, and any
    caller-supplied raw LoRA override, before compilation or activation.
    A negative LoRA scale is refused for ordinary candidates; only the
    deliberately regressed control may use it, via ``make_control``.
    """
    if not isinstance(raw, Mapping):
        raise ControllerError(f"candidate must be a mapping, got {type(raw).__name__}")
    override_keys = RAW_LORA_OVERRIDE_KEYS & set(raw)
    if override_keys:
        raise UnverifiedLoraOverrideError(
            "caller-supplied raw LoRA override rejected: "
            + ", ".join(sorted(override_keys))
        )
    unknown = set(raw) - CANDIDATE_KEYS
    if unknown:
        raise ControllerError(f"unknown candidate keys: {', '.join(sorted(unknown))}")
    if "eta" not in raw:
        raise ControllerError("candidate is missing required key: 'eta'")
    if "lora_scale" not in raw:
        raise ControllerError("candidate is missing required key: 'lora_scale'")
    eta = _require_number(raw["eta"], "eta")
    low, high = contract.eta_range
    if not low <= eta <= high:
        raise ControllerError(f"eta {eta} outside frozen range [{low}, {high}]")
    lam: float | str = raw.get("lambda", 1)
    if isinstance(lam, bool):
        raise ControllerError("lambda must be a number or 'mean_eigenvalue'")
    if isinstance(lam, str):
        if lam not in contract.lambda_values:
            raise ControllerError(f"lambda {lam!r} is not an allowed value")
    else:
        lam = _require_number(lam, "lambda")
        if lam not in contract.lambda_values:
            raise ControllerError(f"lambda {lam} is not an allowed value")
    rank = _require_int(raw.get("rank", contract.rank), "rank")
    if rank != contract.rank:
        raise ControllerError(f"rank {rank} is not the frozen rank {contract.rank}")
    target_layer = _require_int(
        raw.get("target_layer", contract.target_layer), "target_layer"
    )
    if target_layer != contract.target_layer:
        raise ControllerError(
            f"target_layer {target_layer} is not the pinned layer {contract.target_layer}"
        )
    target_tensor = raw.get("target_tensor", contract.target_tensor)
    if not isinstance(target_tensor, str) or target_tensor != contract.target_tensor:
        raise ControllerError(
            f"target_tensor {target_tensor!r} is not the pinned tensor {contract.target_tensor!r}"
        )
    lora_scale = _require_number(raw["lora_scale"], "lora_scale")
    allowed_scales = (0.0, 1.0, -1.0) if allow_negative_scale else (0.0, 1.0)
    if lora_scale not in allowed_scales:
        raise ControllerError(
            f"lora_scale {lora_scale} is not allowed; allowed scales are {list(allowed_scales)}"
        )
    quant = raw.get("quant", "bf16")
    if not isinstance(quant, str) or quant not in SUPPORTED_QUANT_DTYPES:
        raise ControllerError(
            f"quant {quant!r} is not supported by the pinned Weft compiler; "
            f"allowed: {list(SUPPORTED_QUANT_DTYPES)}"
        )
    if candidate_id is None:
        probe = {
            "rank": rank,
            "target_layer": target_layer,
            "target_tensor": target_tensor,
            "eta": eta,
            "lambda": lam,
            "lora_scale": lora_scale,
            "quant": quant,
        }
        candidate_id = "cand-" + _sha256_canonical(probe)[:12]
    elif not isinstance(candidate_id, str) or not _CANDIDATE_ID_RE.match(candidate_id):
        raise ControllerError(f"candidate_id {candidate_id!r} is not a safe id")
    return Candidate(
        candidate_id=candidate_id,
        eta=eta,
        lam=lam,
        rank=rank,
        target_layer=target_layer,
        target_tensor=target_tensor,
        lora_scale=lora_scale,
        quant=quant,
        control_id=control_id,
    )


def make_control(contract: FrozenContract, control_id: str) -> Candidate:
    """Build a preregistered control from controls.json.

    The unchanged base control applies the reference adapter at scale 0.0
    (no adapter effect). The deliberately regressed control applies it at
    scale -1.0. Both run through the same harness and the same frozen
    suites as any candidate. Their eta and lambda are harness defaults,
    recorded in the receipt log; the controls file pins only the scale.
    """
    controls = contract.controls
    if control_id == "base-control":
        if "unchanged_base" not in controls:
            raise ControllerError("controls.json has no unchanged_base control")
        return propose_candidate(
            {"eta": 0.01, "lora_scale": 0.0},
            contract,
            candidate_id="base-control",
            control_id="base-control",
        )
    if control_id == "regressed-control":
        if "deliberately_regressed" not in controls:
            raise ControllerError("controls.json has no deliberately_regressed control")
        return propose_candidate(
            {"eta": 0.01, "lora_scale": -1.0},
            contract,
            candidate_id="regressed-control",
            control_id="regressed-control",
            allow_negative_scale=True,
        )
    raise ControllerError(f"unknown control_id {control_id!r}")


# ---------------------------------------------------------------------------
# Compiler, runtime, and lifecycle seams
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CompileResult:
    """What the Weft compiler returns for one candidate."""

    adapter_sha256: str
    command: str
    command_version: str
    timing_ms: float
    compiler_repo: str
    compiler_commit: str


class Compiler(Protocol):
    """The existing Weft compiler, called once per candidate.

    A real implementation drives ``weft.compiler.BetaEditNullspaceProjector``
    at the commit pinned in the manifest (``stage_edit`` then
    ``commit_patch``), quantizes the factors with the candidate ``quant``,
    and returns the sha256 of the compiled adapter artifact. It must never
    accept a caller-supplied adapter file or digest.
    """

    def compile(self, candidate: Candidate, parent_sha256: str) -> CompileResult: ...


@dataclass(frozen=True)
class BaselineCheck:
    """Baseline log-probability restoration check after rollback.

    ``max_logit_diff`` is None until a rollback has run: the placeholder
    used before rollback carries no measured difference.
    """

    max_logit_diff: float | None
    exact_matches: int
    sequences: int


class Runtime(Protocol):
    """The frozen-suite scoring seam (llama-server behind Warp).

    A real implementation mounts through ``WarpModeld.mount_stack``
    (Stages 1 to 4) and scores through the pinned llama-server flags.
    It returns raw numbers only; the controller applies the policy.
    """

    def mount_adapter(self, adapter_sha256: str, lora_scale: float) -> float:
        """Mount the compiled adapter; returns mount time in ms."""
        ...

    def score_suite(self, suite_name: str, cases: list[dict[str, Any]]) -> dict[str, Any]:
        """Score one frozen suite; returns its raw measurement fields."""
        ...

    def probe_margins(self) -> dict[str, Any]:
        """Return adapter and baseline probe margins."""
        ...

    def verify_baseline(self) -> BaselineCheck:
        """Compare restored baseline logits with the pinned baseline."""
        ...


@dataclass(frozen=True)
class LifecycleRollback:
    """What the Warp lifecycle reports after a rollback."""

    banks_flushed: tuple[str, ...]
    slots_flushed: tuple[int, ...]


class Lifecycle(Protocol):
    """The Warp lifecycle seam for rollback."""

    def rollback(self, reason: str) -> LifecycleRollback: ...


class WarpModeldLifecycle:
    """Lifecycle adapter over a real ``WarpModeld`` instance.

    Delegates rollback to ``WarpModeld.rollback``, which zeroes LoRA
    scales and flushes every live slot across every required state bank.
    """

    def __init__(self, warp: Any) -> None:
        self._warp = warp

    def rollback(self, reason: str) -> LifecycleRollback:
        result = self._warp.rollback(reason=reason)
        banks: set[str] = set()
        for receipt in result.bank_flush_receipts:
            banks.update(receipt.banks_confirmed)
        return LifecycleRollback(
            banks_flushed=tuple(sorted(banks)),
            slots_flushed=tuple(result.slots_flushed),
        )


# ---------------------------------------------------------------------------
# Measurements and the frozen acceptance policy
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Measurements:
    """All retained results for one evaluated candidate, good and bad."""

    task_top1: float
    task_contested_fix_fraction: float
    task_break_fraction: float
    margin_threshold: float
    margins_adapter: tuple[float, ...]
    margins_baseline: tuple[float, ...]
    margin_adapter_requests: int
    margin_baseline_requests: int
    iid_mean_kl: float
    iid_top1_agreement: float
    shifted_mean_kl: float
    safety_canaries_run: int
    safety_failures: tuple[str, ...]
    rollback_exact_matches: int
    rollback_sequences: int
    rollback_max_logit_diff: float | None

    def to_receipt_dict(self) -> dict[str, Any]:
        return {
            "task": {
                "top1": self.task_top1,
                "contested_fix_fraction": self.task_contested_fix_fraction,
                "break_fraction": self.task_break_fraction,
            },
            "margin": {
                "threshold": self.margin_threshold,
                "adapter_requests": self.margin_adapter_requests,
                "baseline_requests": self.margin_baseline_requests,
                "margins_adapter": list(self.margins_adapter),
                "margins_baseline": list(self.margins_baseline),
            },
            "retention_iid": {
                "mean_kl": self.iid_mean_kl,
                "top1_agreement": self.iid_top1_agreement,
            },
            "retention_shifted": {"mean_kl": self.shifted_mean_kl},
            "safety": {
                "canaries_run": self.safety_canaries_run,
                "failures": list(self.safety_failures),
            },
            "rollback": {
                "exact_matches": self.rollback_exact_matches,
                "sequences": self.rollback_sequences,
                "max_logit_diff": self.rollback_max_logit_diff,
            },
        }


def _fraction(value: Any, name: str) -> float:
    number = _require_number(value, name)
    if not 0.0 <= number <= 1.0:
        raise ControllerError(f"{name} {number} is not a fraction in [0, 1]")
    return number


def _measurements_from_raw(
    *,
    task: Mapping[str, Any],
    margins: Mapping[str, Any],
    iid: Mapping[str, Any],
    shifted: Mapping[str, Any],
    safety: Mapping[str, Any],
    rollback: BaselineCheck,
    margin_threshold: float,
) -> Measurements:
    if _require_number(margins.get("threshold"), "margin threshold") != margin_threshold:
        raise ControllerError("runtime margin threshold does not match the frozen threshold")
    margins_adapter = tuple(
        _require_number(m, "adapter margin") for m in margins.get("margins_adapter", [])
    )
    margins_baseline = tuple(
        _require_number(m, "baseline margin") for m in margins.get("margins_baseline", [])
    )
    failures = safety.get("failures", [])
    if not isinstance(failures, list) or not all(isinstance(f, str) for f in failures):
        raise ControllerError("safety failures must be a list of strings")
    return Measurements(
        task_top1=_fraction(task.get("top1"), "task top1"),
        task_contested_fix_fraction=_fraction(
            task.get("contested_fix_fraction"), "contested fix fraction"
        ),
        task_break_fraction=_fraction(task.get("break_fraction"), "break fraction"),
        margin_threshold=margin_threshold,
        margins_adapter=margins_adapter,
        margins_baseline=margins_baseline,
        margin_adapter_requests=_require_int(
            margins.get("adapter_requests"), "adapter requests"
        ),
        margin_baseline_requests=_require_int(
            margins.get("baseline_requests"), "baseline requests"
        ),
        iid_mean_kl=_require_number(iid.get("mean_kl"), "iid mean KL"),
        iid_top1_agreement=_fraction(iid.get("top1_agreement"), "iid top-1 agreement"),
        shifted_mean_kl=_require_number(shifted.get("mean_kl"), "shifted mean KL"),
        safety_canaries_run=_require_int(safety.get("canaries_run"), "canaries run"),
        safety_failures=tuple(failures),
        rollback_exact_matches=rollback.exact_matches,
        rollback_sequences=rollback.sequences,
        rollback_max_logit_diff=rollback.max_logit_diff,
    )


@dataclass(frozen=True)
class PolicyVerdict:
    verdict: str
    failed_gates: tuple[str, ...]
    reasons: tuple[str, ...]


def apply_acceptance_policy(
    measurements: Measurements,
    thresholds: Mapping[str, Any],
    *,
    expected_canaries: int | None = None,
) -> PolicyVerdict:
    """Apply only the frozen acceptance policy.

    The thresholds mapping must come from the loaded contract. This
    function takes no caller-supplied threshold, so a proposal cannot
    change the policy. Every gate is checked; every failure is named.
    When the caller passes the pinned canary count, the safety gate
    requires exactly that many canaries to have run.
    """
    failed: list[str] = []
    reasons: list[str] = []
    task = thresholds["task"]
    if measurements.task_top1 < float(task["top1_min"]):
        failed.append("task_top1")
        reasons.append(
            f"task top1 {measurements.task_top1} is below {task['top1_min']}"
        )
    if measurements.task_contested_fix_fraction < float(task["contested_fix_min_fraction"]):
        failed.append("task_contested_fix")
        reasons.append(
            "contested fix fraction "
            f"{measurements.task_contested_fix_fraction} is below "
            f"{task['contested_fix_min_fraction']}"
        )
    if measurements.task_break_fraction > float(task["break_max_fraction"]):
        failed.append("task_break")
        reasons.append(
            f"task break fraction {measurements.task_break_fraction} is above "
            f"{task['break_max_fraction']}"
        )
    threshold = float(thresholds["adapter_application_margin"]["threshold"])
    if measurements.margin_threshold != threshold:
        failed.append("margin_threshold")
        reasons.append("measurement margin threshold does not match the frozen threshold")
    # Empty evidence is not passing evidence: all() over an empty list is
    # True, so an empty margin list with zero requests must fail the gate.
    if not measurements.margins_adapter or measurements.margin_adapter_requests <= 0:
        failed.append("margin_adapter")
        reasons.append("no adapter probe margins were measured")
    elif not all(m > threshold for m in measurements.margins_adapter):
        failed.append("margin_adapter")
        reasons.append("an adapter probe margin is at or below the frozen threshold")
    # The pilot classified the baseline cluster on the W0 side as well
    # (36 of 36 baseline requests); a baseline margin above the threshold
    # means the margin no longer separates the two clusters.
    if not measurements.margins_baseline or measurements.margin_baseline_requests <= 0:
        failed.append("margin_baseline")
        reasons.append("no baseline probe margins were measured")
    elif not all(m <= threshold for m in measurements.margins_baseline):
        failed.append("margin_baseline")
        reasons.append("a baseline probe margin is above the frozen threshold")
    retention = thresholds["retention"]
    if measurements.iid_mean_kl > float(retention["iid_kl_max_mean"]):
        failed.append("retention_iid_kl")
        reasons.append(
            f"IID mean KL {measurements.iid_mean_kl} is above "
            f"{retention['iid_kl_max_mean']}"
        )
    if measurements.iid_top1_agreement < float(retention["iid_top1_agreement_min"]):
        failed.append("retention_iid_agreement")
        reasons.append(
            "IID top-1 agreement "
            f"{measurements.iid_top1_agreement} is below "
            f"{retention['iid_top1_agreement_min']}"
        )
    if measurements.shifted_mean_kl > float(retention["shifted_kl_max_mean"]):
        failed.append("retention_shifted_kl")
        reasons.append(
            f"shifted mean KL {measurements.shifted_mean_kl} is above "
            f"{retention['shifted_kl_max_mean']}"
        )
    safety_reasons: list[str] = []
    if measurements.safety_canaries_run <= 0:
        safety_reasons.append("no safety canaries ran")
    elif (
        expected_canaries is not None
        and measurements.safety_canaries_run != expected_canaries
    ):
        safety_reasons.append(
            f"only {measurements.safety_canaries_run} of {expected_canaries} "
            "safety canaries ran"
        )
    if measurements.safety_failures:
        safety_reasons.append(
            "canary failures: " + ", ".join(measurements.safety_failures)
        )
    if safety_reasons:
        failed.append("safety_canaries")
        reasons.extend(safety_reasons)
    if measurements.rollback_sequences != FROZEN_ROLLBACK_SEQUENCES:
        failed.append("rollback_sequences")
        reasons.append(
            f"rollback ran {measurements.rollback_sequences} sequences, "
            f"the frozen rule requires {FROZEN_ROLLBACK_SEQUENCES}"
        )
    if measurements.rollback_exact_matches != measurements.rollback_sequences:
        failed.append("rollback_exact")
        reasons.append(
            "rollback reproduced only "
            f"{measurements.rollback_exact_matches} of "
            f"{measurements.rollback_sequences} baseline sequences"
        )
    if measurements.rollback_max_logit_diff != 0.0:
        failed.append("rollback_logit_diff")
        reasons.append(
            "rollback max logit difference is "
            f"{measurements.rollback_max_logit_diff}, expected 0.0"
        )
    verdict = "ACCEPT" if not failed else "REJECT"
    return PolicyVerdict(verdict=verdict, failed_gates=tuple(failed), reasons=tuple(reasons))


def check_control(
    candidate: Candidate, measurements: Measurements, contract: FrozenContract
) -> PolicyVerdict:
    """Check a preregistered control against its expected verdict.

    A control that does not produce its expected verdict fails the
    harness, not the candidate, so the reason says so.
    """
    if candidate.control_id == "base-control":
        expected = contract.controls["unchanged_base"]["expected"]
        if expected.get("verdict") != "PASS":
            raise ControllerError("controls.json base control expects a non-PASS verdict")
        failed: list[str] = []
        reasons: list[str] = []
        if abs(measurements.task_top1 - BASE_TOP1) > BASE_TOP1_TOLERANCE:
            failed.append("base_task_top1")
            reasons.append(
                f"base control task top1 {measurements.task_top1} is not within "
                f"{BASE_TOP1_TOLERANCE} of the published base {BASE_TOP1}"
            )
        expected_canaries = contract.suites["safety_canaries"].get("n_canaries")
        if measurements.safety_canaries_run <= 0:
            failed.append("base_safety")
            reasons.append("base control ran no safety canaries")
        elif (
            expected_canaries is not None
            and measurements.safety_canaries_run != expected_canaries
        ):
            failed.append("base_safety")
            reasons.append(
                f"base control ran only {measurements.safety_canaries_run} of "
                f"{expected_canaries} safety canaries"
            )
        if measurements.safety_failures:
            failed.append("base_safety")
            reasons.append("base control failed a canary; harness or base defect")
        if failed:
            return PolicyVerdict(
                verdict="REJECT",
                failed_gates=tuple(failed),
                reasons=tuple(
                    "control expectation failed (harness failure, not a candidate failure): " + r
                    for r in reasons
                ),
            )
        return PolicyVerdict(verdict="CONTROL_PASS", failed_gates=(), reasons=())
    if candidate.control_id == "regressed-control":
        expected = contract.controls["deliberately_regressed"]["expected"]
        if expected.get("verdict") != "REJECT":
            raise ControllerError("controls.json regressed control expects a non-REJECT verdict")
        if measurements.task_top1 >= BASE_TOP1:
            return PolicyVerdict(
                verdict="REJECT",
                failed_gates=("regressed_task_top1",),
                reasons=(
                    "control expectation failed (harness failure, not a candidate failure): "
                    f"regressed control task top1 {measurements.task_top1} is not below the base {BASE_TOP1}",
                ),
            )
        return PolicyVerdict(
            verdict="REJECT",
            failed_gates=("task_top1",),
            reasons=("regressed control failed the task gate as expected",),
        )
    raise ControllerError(f"candidate {candidate.candidate_id} is not a control")


# ---------------------------------------------------------------------------
# Append-only receipt log
# ---------------------------------------------------------------------------


@dataclass
class ReceiptLog:
    """Hash-chained, append-only JSONL receipt log.

    Each entry carries a sequence number, a UTC timestamp, the sha256 of
    the previous entry, and its own sha256 over the canonical entry bytes.
    The file is only ever opened for append.

    A hash chain alone cannot detect suffix truncation: a log with its
    last line deleted is still a valid shorter chain. A log is therefore
    complete only once sealed. ``seal`` appends a terminal entry that
    records the entry count and the chain head at close time, and
    ``append`` refuses to write after a seal. ``verify`` re-reads the
    whole file and requires the chain, the seal, the count, and the head
    all to agree, so any gap, edit, or truncation fails verification.
    ``verify_chain`` checks the chain alone and is the right check for a
    log still being written.
    """

    path: Path

    def append(self, event: str, **fields: Any) -> dict[str, Any]:
        entries = self.read_all() if self.path.is_file() else []
        if entries and entries[-1].get("event") == "sealed":
            raise ControllerError("receipt log is sealed; no further entries")
        prev_sha = entries[-1]["entry_sha256"] if entries else "0" * 64
        entry: dict[str, Any] = {
            "seq": len(entries) + 1,
            "ts_utc": datetime.now(timezone.utc).isoformat(),
            "event": event,
            "prev_sha256": prev_sha,
        }
        entry.update(fields)
        entry["entry_sha256"] = _sha256_canonical(entry)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as f:
            # allow_nan=False: a non-finite value fails loudly here
            # instead of writing a bare NaN token, which is not JSON.
            f.write(json.dumps(entry, sort_keys=True, allow_nan=False) + "\n")
        return entry

    def seal(self) -> dict[str, Any]:
        """Close the log with a terminal entry recording count and head."""
        entries = self.read_all() if self.path.is_file() else []
        head = entries[-1]["entry_sha256"] if entries else "0" * 64
        return self.append(
            "sealed",
            entry_count=len(entries),
            chain_head=head,
        )

    def read_all(self) -> list[dict[str, Any]]:
        if not self.path.is_file():
            return []
        entries = []
        with open(self.path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    entries.append(json.loads(line))
        return entries

    def verify_chain(self) -> bool:
        """Check sequence order and the hash chain, nothing else."""
        entries = self.read_all()
        prev_sha = "0" * 64
        for index, entry in enumerate(entries, start=1):
            if entry.get("seq") != index:
                return False
            if entry.get("prev_sha256") != prev_sha:
                return False
            claimed = entry.get("entry_sha256")
            body = {k: v for k, v in entry.items() if k != "entry_sha256"}
            if claimed != _sha256_canonical(body):
                return False
            prev_sha = str(claimed)
        return True

    def verify(self) -> bool:
        """Check the chain and require a matching terminal seal."""
        entries = self.read_all()
        if not entries or entries[-1].get("event") != "sealed":
            return False
        if not self.verify_chain():
            return False
        seal = entries[-1]
        if seal.get("entry_count") != len(entries) - 1:
            return False
        head = entries[-2]["entry_sha256"] if len(entries) > 1 else "0" * 64
        return seal.get("chain_head") == head


# ---------------------------------------------------------------------------
# Rollback report and receipt
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RollbackReport:
    """Verified rollback: full state flush plus baseline restoration."""

    banks_flushed: tuple[str, ...]
    slots_flushed: tuple[int, ...]
    baseline: BaselineCheck
    verified: bool


def build_receipt(
    *,
    contract: FrozenContract,
    candidate: Candidate,
    compile_result: CompileResult,
    measurements: Measurements,
    verdict: str,
    timings_ms: Mapping[str, float],
    environment: Mapping[str, Any],
    repair_round: int,
) -> dict[str, Any]:
    """Build one receipt matching the frozen receipt schema.

    The schema consts (llama.cpp build and commit, margin threshold,
    repair budget) are checked against the contract; a mismatch is an
    error, never a silent edit. Quant lives in the controller receipt log
    and inside the compiled adapter digest, not in the frozen receipt.
    """
    if verdict not in ("ACCEPT", "REJECT", "CONTROL_PASS"):
        raise ControllerError(f"verdict {verdict!r} is not in the frozen receipt schema")
    if repair_round > contract.repair_budget_max_rounds:
        raise ControllerError("repair round exceeds the frozen repair budget")
    runtime = contract.manifest["runtime"]
    if environment.get("llama_cpp_build") != runtime["build"]:
        raise ControllerError("receipt llama_cpp_build does not match the manifest")
    if environment.get("llama_cpp_commit") != runtime["commit"]:
        raise ControllerError("receipt llama_cpp_commit does not match the manifest")
    if measurements.margin_threshold != contract.margin_threshold:
        raise ControllerError("receipt margin threshold does not match the frozen threshold")
    return {
        "receipt_schema_version": contract.receipt_schema.get(
            "receipt_schema_version", "0.1.0"
        ),
        "manifest_sha256": contract.manifest_sha256,
        "suite_sha256": contract.combined_suite_sha256,
        "candidate": {
            "candidate_id": candidate.candidate_id,
            "config": candidate.config_dict(),
            "adapter_sha256": compile_result.adapter_sha256,
            "hash_recorded_before_evaluation": True,
        },
        "seeds": {
            "suite_generation": "deterministic",
            "noise_sample": "sorted_first_64_no_rng",
        },
        "environment": {
            "gpu": str(environment.get("gpu", "not-recorded")),
            "llama_cpp_build": runtime["build"],
            "llama_cpp_commit": runtime["commit"],
            "os": str(environment.get("os", "not-recorded")),
            "vram_mib": environment.get("vram_mib"),
        },
        "timings_ms": {
            "compile": float(timings_ms["compile"]),
            "evaluate": float(timings_ms["evaluate"]),
            "deploy": float(timings_ms["deploy"]),
        },
        "measurements": measurements.to_receipt_dict(),
        "verdict": verdict,
        "repair_round": repair_round,
    }


# ---------------------------------------------------------------------------
# Controller
# ---------------------------------------------------------------------------


@dataclass
class ExperimentController:
    """Runs bounded experiments against the frozen contract.

    One controller instance runs one experiment run: propose, compile and
    bind, evaluate, roll back, then apply the frozen policy. The candidate
    digest is written to the receipt log before ``evaluate`` is ever
    called, and the policy thresholds come only from the loaded contract.
    """

    contract: FrozenContract
    compiler: Compiler
    runtime: Runtime
    lifecycle: Lifecycle
    receipts: ReceiptLog
    environment: Mapping[str, Any] = field(default_factory=dict)

    _bound_candidate: Candidate | None = field(default=None, init=False, repr=False)
    _bound_compile: CompileResult | None = field(default=None, init=False, repr=False)
    _deploy_ms: float = field(default=0.0, init=False, repr=False)
    _evaluate_ms: float = field(default=0.0, init=False, repr=False)

    def propose(
        self, raw: Mapping[str, Any], *, candidate_id: str | None = None
    ) -> Candidate:
        try:
            candidate = propose_candidate(raw, self.contract, candidate_id=candidate_id)
        except (ControllerError, UnverifiedLoraOverrideError) as exc:
            self.receipts.append(
                "candidate_rejected",
                reason=str(exc),
                raw_keys=sorted(raw) if isinstance(raw, Mapping) else [],
            )
            raise
        self.receipts.append(
            "candidate_proposed",
            candidate_id=candidate.candidate_id,
            config=candidate.digest_input(),
            config_digest=candidate.config_digest(),
        )
        return candidate

    def propose_control(self, control_id: str) -> Candidate:
        candidate = make_control(self.contract, control_id)
        self.receipts.append(
            "candidate_proposed",
            candidate_id=candidate.candidate_id,
            control_id=control_id,
            config=candidate.digest_input(),
            config_digest=candidate.config_digest(),
        )
        return candidate

    def compile_and_bind(
        self, candidate: Candidate, *, actual_parent_sha256: str
    ) -> CompileResult:
        """Compile the candidate and bind the parent checkpoint.

        Checkpoint drift is rejected before the compiler is called. The
        compiled adapter digest is written to the receipt log before this
        method returns, so no behavioral evaluation can precede it.
        """
        if not hmac_compare(actual_parent_sha256, self.contract.parent_sha256):
            reason = (
                "checkpoint drift: actual parent digest does not match "
                "the pinned base checkpoint in the manifest"
            )
            self.receipts.append(
                "compile_rejected",
                candidate_id=candidate.candidate_id,
                reason=reason,
            )
            raise CheckpointMismatchError(reason)
        started = time.monotonic()
        result = self.compiler.compile(candidate, self.contract.parent_sha256)
        compile_ms = (time.monotonic() - started) * 1000.0
        if not _SHA256_RE.match(result.adapter_sha256 or ""):
            raise ControllerError("compiler returned a malformed adapter digest")
        if result.compiler_repo != self.contract.compiler_repo:
            raise ControllerError("compiler repo does not match the pinned compiler")
        if result.compiler_commit != self.contract.compiler_commit:
            raise ControllerError("compiler commit does not match the pinned compiler")
        # Mount before binding: a failed mount must leave the candidate
        # unbound, so evaluate() cannot score a candidate whose digest
        # receipt was never recorded.
        deploy_ms = self.runtime.mount_adapter(
            result.adapter_sha256, candidate.lora_scale
        )
        self._bound_candidate = candidate
        self._bound_compile = result
        self._deploy_ms = deploy_ms
        self.receipts.append(
            "candidate_digest_recorded",
            candidate_id=candidate.candidate_id,
            config_digest=candidate.config_digest(),
            adapter_sha256=result.adapter_sha256,
            parent_sha256=self.contract.parent_sha256,
            compiler={
                "repo": result.compiler_repo,
                "commit": result.compiler_commit,
                "command": result.command,
                "command_version": result.command_version,
            },
            compile_ms=compile_ms,
            deploy_ms=self._deploy_ms,
            hash_recorded_before_evaluation=True,
        )
        return result

    def evaluate(self) -> Measurements:
        """Run the frozen suites and retain all results.

        The candidate digest must already be recorded; evaluation refuses
        to run on an unbound candidate. Suite results are returned whole,
        positive and negative, and written to the receipt log.
        """
        if self._bound_candidate is None or self._bound_compile is None:
            raise ControllerError(
                "no bound candidate: compile_and_bind must run before evaluate"
            )
        started = time.monotonic()
        raw: dict[str, dict[str, Any]] = {}
        for name in SUITE_ORDER:
            cases = list(self.contract.suites[name].get("cases", []))
            raw[name] = self.runtime.score_suite(name, cases)
        margins = self.runtime.probe_margins()
        self._evaluate_ms = (time.monotonic() - started) * 1000.0
        # Rollback fields are filled by rollback(); until then they are
        # placeholders that promote_or_reject refuses to use. The
        # difference is null, not NaN: a NaN would serialize as a bare
        # NaN token, which is not valid JSON.
        measurements = _measurements_from_raw(
            task=raw["task"],
            margins=margins,
            iid=raw["retention_iid"],
            shifted=raw["retention_shifted"],
            safety=raw["safety_canaries"],
            rollback=BaselineCheck(
                max_logit_diff=None, exact_matches=-1, sequences=-1
            ),
            margin_threshold=self.contract.margin_threshold,
        )
        self.receipts.append(
            "evaluated",
            candidate_id=self._bound_candidate.candidate_id,
            adapter_sha256=self._bound_compile.adapter_sha256,
            measurements=measurements.to_receipt_dict(),
            evaluate_ms=self._evaluate_ms,
        )
        return measurements

    def rollback(self, reason: str = "experiment_rollback") -> RollbackReport:
        """Restore and verify the baseline, including the full state flush.

        The Warp lifecycle rollback must flush every state bank. The
        baseline is then verified by comparing restored logits with the
        pinned baseline: any nonzero difference fails verification.
        """
        rolled = self.lifecycle.rollback(reason)
        missing = [bank for bank in ALL_STATE_BANKS if bank not in rolled.banks_flushed]
        if missing:
            self.receipts.append(
                "rollback_failed",
                reason=f"state flush missed banks: {', '.join(missing)}",
                banks_flushed=list(rolled.banks_flushed),
            )
            raise StateFlushError(
                f"rollback state flush missed banks: {', '.join(missing)}"
            )
        baseline = self.runtime.verify_baseline()
        verified = (
            baseline.max_logit_diff == 0.0
            and baseline.exact_matches == baseline.sequences
            and baseline.sequences == FROZEN_ROLLBACK_SEQUENCES
        )
        report = RollbackReport(
            banks_flushed=tuple(rolled.banks_flushed),
            slots_flushed=tuple(rolled.slots_flushed),
            baseline=baseline,
            verified=verified,
        )
        self.receipts.append(
            "rollback_verified" if verified else "rollback_failed",
            reason=reason,
            banks_flushed=list(rolled.banks_flushed),
            slots_flushed=list(rolled.slots_flushed),
            baseline={
                "max_logit_diff": baseline.max_logit_diff,
                "exact_matches": baseline.exact_matches,
                "sequences": baseline.sequences,
            },
            verified=verified,
        )
        if not verified:
            raise StateFlushError(
                "rollback did not restore the baseline: "
                f"max logit difference {baseline.max_logit_diff}, "
                f"{baseline.exact_matches} of {baseline.sequences} sequences exact"
            )
        return report

    def promote_or_reject(
        self,
        candidate: Candidate,
        measurements: Measurements,
        *,
        repair_round: int = 0,
    ) -> PolicyVerdict:
        """Apply only the frozen acceptance policy to retained measurements.

        Refuses to decide on measurements whose rollback fields are still
        placeholders from ``evaluate``. A repair round past the frozen
        budget is rejected without evaluating the policy.
        """
        if repair_round > self.contract.repair_budget_max_rounds:
            verdict = PolicyVerdict(
                verdict="REJECT",
                failed_gates=("repair_budget",),
                reasons=(
                    f"repair round {repair_round} exceeds the frozen budget of "
                    f"{self.contract.repair_budget_max_rounds}",
                ),
            )
        elif measurements.rollback_sequences < 0:
            raise ControllerError(
                "cannot decide before rollback: rollback measurements are missing"
            )
        elif candidate.control_id is not None:
            verdict = check_control(candidate, measurements, self.contract)
        else:
            verdict = apply_acceptance_policy(
                measurements,
                self.contract.thresholds,
                expected_canaries=self.contract.suites["safety_canaries"].get(
                    "n_canaries"
                ),
            )
        self.receipts.append(
            "verdict",
            candidate_id=candidate.candidate_id,
            verdict=verdict.verdict,
            failed_gates=list(verdict.failed_gates),
            reasons=list(verdict.reasons),
            repair_round=repair_round,
        )
        return verdict

    def run_experiment(
        self,
        raw: Mapping[str, Any],
        *,
        actual_parent_sha256: str,
        repair_round: int = 0,
        candidate_id: str | None = None,
    ) -> tuple[PolicyVerdict, dict[str, Any]]:
        """Run one bounded experiment end to end and return verdict + receipt.

        Order is fixed: propose, compile and bind (digest recorded),
        evaluate, roll back, then decide. Any step that fails stops the
        run and leaves the failure in the receipt log. The log is sealed
        when the run ends, success or failure, so verify() can tell a
        complete log from a truncated one.
        """
        try:
            verdict, receipt = self._run_experiment_inner(
                raw,
                actual_parent_sha256=actual_parent_sha256,
                repair_round=repair_round,
                candidate_id=candidate_id,
            )
        except Exception:
            try:
                self.receipts.seal()
            except Exception:
                pass
            raise
        self.receipts.seal()
        return verdict, receipt

    def _run_experiment_inner(
        self,
        raw: Mapping[str, Any],
        *,
        actual_parent_sha256: str,
        repair_round: int = 0,
        candidate_id: str | None = None,
    ) -> tuple[PolicyVerdict, dict[str, Any]]:
        """The fixed experiment sequence, without the terminal seal."""
        if repair_round > self.contract.repair_budget_max_rounds:
            raise ControllerError(
                f"repair round {repair_round} exceeds the frozen budget of "
                f"{self.contract.repair_budget_max_rounds}"
            )
        candidate = self.propose(raw, candidate_id=candidate_id)
        compile_result = self.compile_and_bind(
            candidate, actual_parent_sha256=actual_parent_sha256
        )
        try:
            measurements = self.evaluate()
        except Exception:
            # A scoring failure must not leave the adapter mounted: roll
            # back best effort, then re-raise the scoring failure. A
            # rollback failure is recorded in the log by rollback()
            # itself; it does not replace the original error.
            try:
                self.rollback(reason="experiment_rollback")
            except Exception:
                pass
            raise
        rollback_report = self.rollback()
        complete = Measurements(
            **{
                **measurements.__dict__,
                "rollback_exact_matches": rollback_report.baseline.exact_matches,
                "rollback_sequences": rollback_report.baseline.sequences,
                "rollback_max_logit_diff": rollback_report.baseline.max_logit_diff,
            }
        )
        verdict = self.promote_or_reject(
            candidate, complete, repair_round=repair_round
        )
        receipt = build_receipt(
            contract=self.contract,
            candidate=candidate,
            compile_result=compile_result,
            measurements=complete,
            verdict=verdict.verdict,
            timings_ms={
                "compile": compile_result.timing_ms,
                "evaluate": self._evaluate_ms,
                "deploy": self._deploy_ms,
            },
            environment=self.environment,
            repair_round=repair_round,
        )
        self.receipts.append(
            "receipt",
            candidate_id=candidate.candidate_id,
            verdict=verdict.verdict,
            receipt_sha256=_sha256_canonical(receipt),
        )
        return verdict, receipt
