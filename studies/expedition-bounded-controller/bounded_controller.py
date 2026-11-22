#!/usr/bin/env python3
"""Issues #5 & #6 bounded experiment controller, monotone reconciler, and Cerebras advisory client (AUDIT-063).

Explicitly labeled `project-specific-weight-experiment-harness` (NOT standardized W-MCP).
Pure Python 3 standard library, zero floats on trust paths, zero bare asserts.

Synthesizes:
  - alphaxiv/OpenResearch monotone (Phase, Contact) reconciler lattice (385 transitions) &
    orx-signals affine clock-pair invariance (AUDIT-057R)
  - Aletheia v1.3.0 exact Fraction Pythagorean Goodhart Latch & hash-chained ledger (AUDIT-026R/034R)
  - Moissanite-Labs/warp-drive 5-op controller contract (Issue #5) & redacted Kimi-on-Cerebras
    3-call advisory boundary (Issue #6) preserving Warp's full multi-bank rollback contract.
"""

from __future__ import annotations

import copy
from fractions import Fraction
import hashlib
import hmac
import json
from typing import Any, Callable, Mapping, Protocol, Sequence

import experiment_contract as ec

INTERFACE_CLASS = ec.HARNESS_LABEL
GENESIS_HASH = "0" * 64
EXPECTED_RECEIPT_KEYS: frozenset[str] = frozenset(
    {
        "receipt_schema",
        "interface_class",
        "seq",
        "prev_receipt_sha256",
        "operation",
        "candidate_id",
        "payload",
        "receipt_sha256",
        "sig_alg",
        "key_id",
        "signature",
    }
)

# ---------------------------------------------------------------------------
# Part 1: Monotone (Phase, Contact) Controller Reconciler Lattice (385 States)
# ---------------------------------------------------------------------------

PHASE_RANK: dict[str, int] = {
    "Proposing": 0,
    "Compiling": 1,
    "Evaluating": 2,
    "Promoted": 3,
    "Rejected": 3,
    "RolledBack": 3,
    "Aborted": 3,
}

CONTACTS: tuple[str, ...] = (
    "Live",
    "Unreachable",
    "NeedsAuth",
    "Unreconciled",
    "Stopping",
)

OBSERVATIONS: tuple[str, ...] = (
    "Compiled",
    "Evaluating",
    "Promoted",
    "Rejected",
    "RolledBack",
    "Aborted",
    "AbortPending",
    "Gone",
    "Unreachable",
    "NeedsAuth",
    "Unreconciled",
)

OUTAGE_OBSERVATIONS: frozenset[str] = frozenset({"Unreachable", "NeedsAuth", "Unreconciled"})
TERMINAL_PHASES: frozenset[str] = frozenset({"Promoted", "Rejected", "RolledBack", "Aborted"})

VALID_CONTROL_ROLES: frozenset[str] = frozenset({"candidate", "unchanged_base", "regressed_control"})
VALID_PROPOSAL_KEYS: frozenset[str] = frozenset(
    {
        "candidate_id",
        "contract_sha256",
        "control_role",
        "repair_round",
        "target_layer",
        "rank",
        "strength_num",
        "strength_den",
        "quantization",
        "seed",
        "parent_candidate_id",
        "rationale",
    }
)

FORBIDDEN_EGRESS_KEYS: frozenset[str] = frozenset(
    {
        "weights",
        "weight_bytes",
        "tensor",
        "tensors",
        "gguf_bytes",
        "safetensors",
        "api_key",
        "secret",
        "secret_key",
        "private_data",
        "accept_policy",
        "thresholds_override",
        "lora",
        "raw_lora",
    }
)

ALLOWED_FAILURE_REPORT_KEYS: frozenset[str] = frozenset(
    {
        "candidate_id",
        "failures",
        "repair_round",
        "verdict",
        "failed_gate",
        "unrelated_kl_after_milli",
    }
)
ALLOWED_KNOBS_KEYS: frozenset[str] = frozenset(
    {
        "ranks",
        "strength_den",
        "strength_num_min",
        "strength_num_max",
        "quantizations",
    }
)
FAILURE_REPORT_INT_KEYS: frozenset[str] = frozenset({"repair_round", "unrelated_kl_after_milli"})
MAX_EGRESS_TOKEN_LEN = 64
MAX_FAILURE_CODES = 16
MAX_HISTORY_SUMMARY_ITEMS = 16
MAX_KNOB_LIST_LEN = 16


class ControllerError(ValueError):
    """Fail-closed controller, reconciler, or Cerebras advisory boundary error."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message

    def to_dict(self) -> dict[str, str]:
        return {"code": self.code, "message": self.message}


def is_terminal_phase(phase: str) -> bool:
    return PHASE_RANK[phase] == 3


def is_tombstone(phase: str, contact: str) -> bool:
    return is_terminal_phase(phase) and contact != "Live"


def reconcile_controller_step(phase: str, contact: str, observation: str) -> tuple[str, str, bool]:
    """Exact pure-state monotone reconciler (OpenResearch lattice adapted to warp-drive).

    Returns (next_phase, next_contact, emit_terminal_receipt).
    """
    if phase not in PHASE_RANK:
        raise ControllerError("ERR_UNKNOWN_PHASE", f"unknown phase: {phase!r}")
    if contact not in CONTACTS:
        raise ControllerError("ERR_UNKNOWN_CONTACT", f"unknown contact: {contact!r}")
    if observation not in OBSERVATIONS:
        raise ControllerError("ERR_UNKNOWN_OBSERVATION", f"unknown observation: {observation!r}")

    if is_terminal_phase(phase):
        if not is_tombstone(phase, contact):
            return phase, "Live", False
        if observation in ("Aborted", "Gone"):
            return phase, "Live", False
        if observation in OUTAGE_OBSERVATIONS:
            return phase, observation, False
        return phase, "Unreconciled", False

    if observation in OUTAGE_OBSERVATIONS:
        return phase, observation, False

    if observation == "AbortPending":
        if phase == "Proposing":
            return phase, contact, False
        return "Aborted", "Stopping", True

    if observation in TERMINAL_PHASES:
        return observation, "Live", True

    if observation == "Compiled" and phase == "Proposing":
        return "Compiling", "Live", False

    if observation == "Evaluating":
        return "Evaluating", "Live", False

    return phase, contact, False


def certify_reconciler_lattice_385() -> dict[str, Any]:
    """Exhaustively certify all 7 * 5 * 11 = 385 (Phase, Contact, Obs) transitions."""
    total = 0
    phase_regressions = 0
    terminal_swaps = 0
    outage_fabrications = 0
    duplicate_terminal_notices = 0
    tombstone_resolutions = 0

    for phase in PHASE_RANK:
        for contact in CONTACTS:
            for obs in OBSERVATIONS:
                total += 1
                nxt_phase, nxt_contact, emit_notice = reconcile_controller_step(phase, contact, obs)
                if PHASE_RANK[nxt_phase] < PHASE_RANK[phase]:
                    phase_regressions += 1
                if is_terminal_phase(phase) and nxt_phase != phase:
                    terminal_swaps += 1
                if obs in OUTAGE_OBSERVATIONS and nxt_phase != phase:
                    outage_fabrications += 1
                if is_terminal_phase(phase) and emit_notice:
                    duplicate_terminal_notices += 1
                if is_tombstone(phase, contact) and nxt_contact == "Live":
                    tombstone_resolutions += 1

    return {
        "total_transitions": total,
        "phase_regressions": phase_regressions,
        "terminal_swaps": terminal_swaps,
        "outage_fabrications": outage_fabrications,
        "duplicate_terminal_notices": duplicate_terminal_notices,
        "tombstone_resolutions": tombstone_resolutions,
        "all_invariants_sound": (
            phase_regressions == 0
            and terminal_swaps == 0
            and outage_fabrications == 0
            and duplicate_terminal_notices == 0
        ),
    }


# ---------------------------------------------------------------------------
# Part 2: Exact Rational Clock-Pair Separation & Goodhart Latch
# ---------------------------------------------------------------------------

def map_host_to_controller_exact(
    host_time: Fraction,
    host_anchor: Fraction,
    controller_anchor: Fraction,
) -> Fraction:
    """Exact rational affine clock-pair mapping (orx-signals invariant, zero float drift)."""
    if (
        not isinstance(host_time, Fraction)
        or not isinstance(host_anchor, Fraction)
        or not isinstance(controller_anchor, Fraction)
    ):
        raise ControllerError("ERR_INVALID_CLOCK", "clock timestamps must be exact Fractions")
    return host_time + (controller_anchor - host_anchor)


def build_separated_timings(
    *,
    cerebras_ms: int,
    compile_ms: int,
    local_eval_ms: int,
    deploy_rollback_ms: int,
) -> dict[str, int]:
    """Strictly separate Cerebras, compile, local eval, and deploy/rollback timings (Issue #3)."""
    c_ms = ec.require_exact_int(cerebras_ms, "cerebras_ms", min_value=0)
    k_ms = ec.require_exact_int(compile_ms, "compile_ms", min_value=0)
    e_ms = ec.require_exact_int(local_eval_ms, "local_eval_ms", min_value=0)
    d_ms = ec.require_exact_int(deploy_rollback_ms, "deploy_rollback_ms", min_value=0)
    return {
        "cerebras_ms": c_ms,
        "compile_ms": k_ms,
        "local_eval_ms": e_ms,
        "deploy_rollback_ms": d_ms,
        "total_ms": c_ms + k_ms + e_ms + d_ms,
    }


def evaluate_goodhart_latch(
    *,
    residual_before: Fraction,
    residual_after: Fraction,
    unrelated_kl_before_milli: int,
    unrelated_kl_after_milli: int,
    max_unrelated_kl_milli: int,
) -> dict[str, Any]:
    """Exact Pre-Adaptation Goodhart Latch catching ml-os#6's +55% preconditioning KL jump."""
    if not isinstance(residual_before, Fraction) or residual_before < 0:
        raise ControllerError("ERR_INVALID_METRIC", "residual_before must be non-negative Fraction")
    if not isinstance(residual_after, Fraction) or residual_after < 0:
        raise ControllerError("ERR_INVALID_METRIC", "residual_after must be non-negative Fraction")
    kl_before = ec.require_exact_int(unrelated_kl_before_milli, "unrelated_kl_before_milli", min_value=0)
    kl_after = ec.require_exact_int(unrelated_kl_after_milli, "unrelated_kl_after_milli", min_value=0)
    kl_cap = ec.require_exact_int(max_unrelated_kl_milli, "max_unrelated_kl_milli", min_value=0)

    proxy_shrank = residual_after < residual_before
    kl_inflated = kl_after > kl_before
    kl_over_cap = kl_after > kl_cap
    latch_halt = (proxy_shrank and kl_inflated) or kl_over_cap
    return {
        "proxy_shrank": proxy_shrank,
        "kl_inflated": kl_inflated,
        "kl_over_cap": kl_over_cap,
        "latch_halt": latch_halt,
        "decision": "LATCH_HALT" if latch_halt else "PASS",
    }


# ---------------------------------------------------------------------------
# Part 3: Append-Only HMAC-Signed Experiment Receipt Ledger
# ---------------------------------------------------------------------------

class SignedExperimentLedger:
    """In-memory / JSONL-exportable append-only HMAC-SHA256 hash-chained receipt log."""

    def __init__(self, secret_key: bytes, *, key_id: str = "warp-exp-hmac-v1") -> None:
        if not isinstance(secret_key, (bytes, bytearray)) or len(secret_key) < 16:
            raise ControllerError("ERR_INVALID_KEY", "secret_key must be >= 16 bytes")
        ec.require_non_empty_str(key_id, "key_id")
        self._key = bytes(secret_key)
        self.key_id = key_id
        self._records: list[dict[str, Any]] = []
        self._prev_hash = GENESIS_HASH

    @property
    def records(self) -> tuple[dict[str, Any], ...]:
        return tuple(self._records)

    @property
    def head_sha256(self) -> str:
        return self._prev_hash

    def append(self, operation: str, *, candidate_id: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        ec.require_non_empty_str(operation, "operation")
        ec.require_non_empty_str(candidate_id, "candidate_id")
        ec.verify_no_floats(payload)
        seq = len(self._records) + 1
        body = {
            "receipt_schema": ec.RECEIPT_SCHEMA,
            "interface_class": INTERFACE_CLASS,
            "seq": seq,
            "prev_receipt_sha256": self._prev_hash,
            "operation": operation,
            "candidate_id": candidate_id,
            "payload": dict(payload),
        }
        receipt_sha = ec.sha256_canonical(body)
        sig_input = f"{receipt_sha}:hmac-sha256:{self.key_id}".encode("ascii")
        sig = hmac.new(self._key, sig_input, hashlib.sha256).hexdigest()
        record = {
            **body,
            "receipt_sha256": receipt_sha,
            "sig_alg": "hmac-sha256",
            "key_id": self.key_id,
            "signature": sig,
        }
        self._records.append(record)
        self._prev_hash = receipt_sha
        return record


def verify_receipt_chain_independent(
    records: Sequence[Mapping[str, Any]],
    *,
    secret_key: bytes,
    key_id: str = "warp-exp-hmac-v1",
) -> dict[str, Any]:
    """Fail-closed hash-chain and HMAC verifier for append-only experiment receipts."""
    if not isinstance(records, (list, tuple)) or not records:
        raise ControllerError("ERR_EMPTY_LEDGER", "receipt ledger must be non-empty")
    prev = GENESIS_HASH
    for idx, rec in enumerate(records, start=1):
        if not isinstance(rec, Mapping):
            raise ControllerError("ERR_LEDGER_TAMPER", f"record {idx} is not a mapping")
        ec.verify_no_floats(rec)
        if set(rec.keys()) != EXPECTED_RECEIPT_KEYS:
            raise ControllerError("ERR_LEDGER_TAMPER", f"record {idx} unexpected or missing top-level keys")
        if rec["receipt_schema"] != ec.RECEIPT_SCHEMA or rec["interface_class"] != INTERFACE_CLASS:
            raise ControllerError("ERR_LEDGER_TAMPER", f"record {idx} schema or interface_class mismatch")
        if rec["seq"] != idx:
            raise ControllerError("ERR_LEDGER_TAMPER", f"record {idx} seq mismatch: {rec['seq']!r}")
        if not hmac.compare_digest(str(rec["prev_receipt_sha256"]), prev):
            raise ControllerError("ERR_LEDGER_TAMPER", f"record {idx} broken prev_receipt_sha256")
        body = {
            "receipt_schema": rec["receipt_schema"],
            "interface_class": rec["interface_class"],
            "seq": rec["seq"],
            "prev_receipt_sha256": rec["prev_receipt_sha256"],
            "operation": rec["operation"],
            "candidate_id": rec["candidate_id"],
            "payload": rec["payload"],
        }
        expected_sha = ec.sha256_canonical(body)
        if not hmac.compare_digest(str(rec["receipt_sha256"]), expected_sha):
            raise ControllerError("ERR_LEDGER_TAMPER", f"record {idx} receipt_sha256 mismatch")
        if rec["key_id"] != key_id or rec["sig_alg"] != "hmac-sha256":
            raise ControllerError("ERR_LEDGER_TAMPER", f"record {idx} signer mismatch")
        sig_input = f"{expected_sha}:hmac-sha256:{key_id}".encode("ascii")
        expected_sig = hmac.new(secret_key, sig_input, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(str(rec["signature"]), expected_sig):
            raise ControllerError("ERR_LEDGER_TAMPER", f"record {idx} invalid HMAC signature")
        prev = expected_sha
    return {"valid": True, "count": len(records), "head_sha256": prev}


# ---------------------------------------------------------------------------
# Part 4: 5-Op Bounded Experiment Controller (Issue #5)
# ---------------------------------------------------------------------------

class CompilerAdapter(Protocol):
    is_mock: bool

    def compile_candidate(
        self,
        *,
        manifest: Mapping[str, Any],
        proposal: Mapping[str, Any],
    ) -> dict[str, Any]: ...


class RuntimeAdapter(Protocol):
    is_mock: bool

    def evaluate_candidate(
        self,
        *,
        manifest: Mapping[str, Any],
        candidate_record: Mapping[str, Any],
    ) -> dict[str, Any]: ...

    def rollback_and_flush(
        self,
        *,
        required_state_banks: tuple[str, ...],
        reason: str,
    ) -> dict[str, Any]: ...


def required_state_banks_from_checkpoint(ckpt: Mapping[str, Any]) -> tuple[str, ...]:
    """Derive mandatory rollback state banks from the frozen base_checkpoint pin."""
    banks: list[str] = ["kv_cache"]
    if ckpt.get("has_ssm_recurrent") is True:
        banks.append("ssm_recurrent")
    if ckpt.get("has_horizontal_lattice") is True:
        banks.append("lattice_horizontal_streams")
    return tuple(banks)


def _require_signed_rational_pair(pair: Any, label: str) -> Fraction:
    if not isinstance(pair, (list, tuple)) or len(pair) != 2:
        raise ControllerError("ERR_INVALID_METRIC", f"{label} must be [num, den]")
    num = ec.require_exact_int(pair[0], f"{label}.num")
    den = ec.require_exact_int(pair[1], f"{label}.den", min_value=1)
    return Fraction(num, den)


class BoundedExperimentController:
    """Thin 5-op controller implementing Issue #5 strictly under the frozen Issue #4 contract."""

    def __init__(self, frozen_manifest: Mapping[str, Any], ledger: SignedExperimentLedger) -> None:
        self.manifest = ec.validate_frozen_manifest(frozen_manifest)
        self._pinned_manifest_sha256 = self.manifest["manifest_sha256"]
        self.ledger = ledger
        self._candidates: dict[str, dict[str, Any]] = {}
        self._used_candidate_rounds: set[int] = set()
        self._base_ckpt_digest = ec.sha256_canonical(self.manifest["base_checkpoint"])
        self._required_state_banks = required_state_banks_from_checkpoint(self.manifest["base_checkpoint"])

    def _verify_manifest_integrity(self, snapshot: Mapping[str, Any] | None = None) -> None:
        """Fail closed if internal manifest or a callback snapshot was tampered with."""
        cur_sha = ec.compute_manifest_sha256(self.manifest)
        if not hmac.compare_digest(cur_sha, self._pinned_manifest_sha256):
            raise ControllerError("ERR_MANIFEST_TAMPERED", "frozen controller manifest was mutated")
        if snapshot is not None:
            snap_sha = ec.compute_manifest_sha256(snapshot)
            if not hmac.compare_digest(snap_sha, self._pinned_manifest_sha256):
                raise ControllerError("ERR_MANIFEST_TAMPERED", "callback attempted to mutate frozen manifest snapshot")

    @property
    def base_checkpoint_digest(self) -> str:
        return self._base_ckpt_digest

    @property
    def required_state_banks(self) -> tuple[str, ...]:
        return self._required_state_banks

    def candidate_state(self, candidate_id: str) -> dict[str, Any]:
        if candidate_id not in self._candidates:
            raise ControllerError("ERR_UNKNOWN_CANDIDATE", f"unknown candidate_id: {candidate_id!r}")
        return dict(self._candidates[candidate_id])

    # Operation 1: propose_candidate
    def propose_candidate(self, proposal: Mapping[str, Any]) -> dict[str, Any]:
        self._verify_manifest_integrity()
        ec.verify_ring0_immutability(self.manifest, proposal)
        ec.verify_no_floats(proposal)

        unknown_keys = sorted(set(proposal.keys()) - VALID_PROPOSAL_KEYS)
        if unknown_keys:
            raise ControllerError("ERR_MALFORMED_CANDIDATE", f"unexpected candidate keys: {unknown_keys}")

        cid = ec.require_non_empty_str(proposal.get("candidate_id"), "candidate_id")
        if cid in self._candidates:
            raise ControllerError("ERR_DUPLICATE_CANDIDATE", f"candidate_id already exists: {cid!r}")

        role = proposal.get("control_role", "candidate")
        if role not in VALID_CONTROL_ROLES:
            raise ControllerError("ERR_INVALID_CONTROL_ROLE", f"invalid control_role: {role!r}")

        repair_round = ec.require_exact_int(proposal.get("repair_round", 0), "repair_round", min_value=0)
        if role == "candidate":
            if repair_round < 1 or repair_round > self.manifest["max_repair_rounds"]:
                raise ControllerError(
                    "ERR_REPAIR_BUDGET_EXCEEDED",
                    f"candidate repair_round {repair_round} outside [1, {self.manifest['max_repair_rounds']}]",
                )
            if repair_round in self._used_candidate_rounds:
                raise ControllerError(
                    "ERR_REPAIR_BUDGET_EXCEEDED",
                    f"candidate repair_round {repair_round} already consumed",
                )
        else:
            if repair_round != 0:
                raise ControllerError(
                    "ERR_REPAIR_BUDGET_EXCEEDED",
                    f"control role {role!r} must use repair_round=0, got {repair_round}",
                )

        target_layer = ec.require_non_empty_str(proposal.get("target_layer"), "target_layer")
        if target_layer != self.manifest["target_layer"]:
            raise ControllerError(
                "ERR_UNSUPPORTED_LAYER",
                f"target_layer {target_layer!r} != pinned {self.manifest['target_layer']!r}",
            )

        knobs = self.manifest["allowed_knobs"]
        rank = ec.require_exact_int(proposal.get("rank"), "rank", min_value=0)
        s_den = ec.require_exact_int(proposal.get("strength_den"), "strength_den", min_value=1)
        s_num = ec.require_exact_int(proposal.get("strength_num"), "strength_num", min_value=0)
        quant = ec.require_non_empty_str(proposal.get("quantization"), "quantization")
        seed = ec.require_exact_int(proposal.get("seed"), "seed", min_value=0)

        if quant not in knobs["quantizations"]:
            raise ControllerError("ERR_INVALID_QUANTIZATION", f"quantization {quant!r} not in allowed knobs")

        if role == "unchanged_base":
            if s_num != 0 or rank != 0:
                raise ControllerError("ERR_INVALID_BASE_CONTROL", "unchanged_base control requires rank=0 and strength_num=0")
        else:
            if rank not in knobs["ranks"]:
                raise ControllerError("ERR_INVALID_RANK", f"rank {rank} not in allowed {knobs['ranks']}")
            if s_den != knobs["strength_den"] or s_num < knobs["strength_num_min"] or s_num > knobs["strength_num_max"]:
                raise ControllerError(
                    "ERR_INVALID_STRENGTH",
                    f"strength {s_num}/{s_den} outside allowed [{knobs['strength_num_min']},{knobs['strength_num_max']}]/{knobs['strength_den']}",
                )

        normalized = {
            "candidate_id": cid,
            "contract_sha256": self.manifest["manifest_sha256"],
            "control_role": role,
            "repair_round": repair_round,
            "target_layer": target_layer,
            "rank": rank,
            "strength_num": s_num,
            "strength_den": s_den,
            "quantization": quant,
            "seed": seed,
            "parent_candidate_id": proposal.get("parent_candidate_id"),
            "rationale": str(proposal.get("rationale", "")),
        }
        rec = {
            "proposal": normalized,
            "phase": "Proposing",
            "contact": "Live",
            "candidate_adapter_sha256": None,
            "binding_receipt_seq": None,
            "evaluation": None,
            "eval_receipt_seq": None,
            "verdict": None,
            "rolled_back": False,
        }
        self._candidates[cid] = rec
        if role == "candidate":
            self._used_candidate_rounds.add(repair_round)
        receipt = self.ledger.append("propose_candidate", candidate_id=cid, payload=normalized)
        return {"candidate_id": cid, "phase": rec["phase"], "receipt": receipt}

    # Operation 2: compile_and_bind
    def compile_and_bind(
        self,
        candidate_id: str,
        *,
        compiler: CompilerAdapter,
        live_checkpoint_digest: str,
        live_runtime_flags_sha256: str,
    ) -> dict[str, Any]:
        self._verify_manifest_integrity()
        if candidate_id not in self._candidates:
            raise ControllerError("ERR_UNKNOWN_CANDIDATE", f"unknown candidate_id: {candidate_id!r}")
        rec = self._candidates[candidate_id]
        if rec["phase"] != "Proposing":
            raise ControllerError("ERR_INVALID_PHASE", f"compile_and_bind requires Proposing, got {rec['phase']!r}")

        if not hmac.compare_digest(live_checkpoint_digest, self._base_ckpt_digest):
            raise ControllerError("ERR_CHECKPOINT_DRIFT", "live base checkpoint digest drifted from frozen contract")
        if not hmac.compare_digest(live_runtime_flags_sha256, self.manifest["runtime_flags_sha256"]):
            raise ControllerError("ERR_RUNTIME_FLAG_DRIFT", "live runtime_flags_sha256 drifted from frozen contract")

        cb_manifest = copy.deepcopy(self.manifest)
        cb_proposal = copy.deepcopy(rec["proposal"])
        compiled = compiler.compile_candidate(manifest=cb_manifest, proposal=cb_proposal)
        self._verify_manifest_integrity(cb_manifest)
        if not isinstance(compiled, Mapping):
            raise ControllerError("ERR_MALFORMED_COMPILER_OUTPUT", "compiler output must be a mapping")
        ec.verify_no_floats(compiled)
        adapter_sha = ec.require_sha256(compiled.get("candidate_adapter_sha256"), "candidate_adapter_sha256")
        compile_ms = ec.require_exact_int(compiled.get("compile_ms"), "compile_ms", min_value=0)
        compiler_commit = ec.require_commit40(compiled.get("compiler_commit"), "compiler_commit")
        if not hmac.compare_digest(compiler_commit, self.manifest["compiler_commit"]):
            raise ControllerError("ERR_COMPILER_DRIFT", "compiler_commit mismatch against frozen contract")

        nxt_phase, nxt_contact, _ = reconcile_controller_step(rec["phase"], rec["contact"], "Compiled")
        rec["phase"] = nxt_phase
        rec["contact"] = nxt_contact
        rec["candidate_adapter_sha256"] = adapter_sha
        rec["compiler_is_mock"] = bool(compiler.is_mock)

        bind_payload = {
            "base_checkpoint_digest": self._base_ckpt_digest,
            "runtime_flags_sha256": self.manifest["runtime_flags_sha256"],
            "compiler_commit": compiler_commit,
            "candidate_adapter_sha256": adapter_sha,
            "compile_ms": compile_ms,
            "evidence_scope": "logic_check_fake_compiler" if compiler.is_mock else "live_compiler",
        }
        receipt = self.ledger.append("compile_and_bind", candidate_id=candidate_id, payload=bind_payload)
        rec["binding_receipt_seq"] = receipt["seq"]
        return {"candidate_id": candidate_id, "candidate_adapter_sha256": adapter_sha, "receipt": receipt}

    # Operation 3: evaluate
    def evaluate(
        self,
        candidate_id: str,
        *,
        runtime: RuntimeAdapter,
        live_adapter_sha256: str,
        live_checkpoint_digest: str,
    ) -> dict[str, Any]:
        self._verify_manifest_integrity()
        if candidate_id not in self._candidates:
            raise ControllerError("ERR_UNKNOWN_CANDIDATE", f"unknown candidate_id: {candidate_id!r}")
        rec = self._candidates[candidate_id]
        if rec["phase"] != "Compiling" or rec["binding_receipt_seq"] is None or rec["candidate_adapter_sha256"] is None:
            raise ControllerError("ERR_HASH_ORDER_VIOLATION", "candidate hash must be compiled and recorded before evaluate")

        bound_adapter_sha = rec["candidate_adapter_sha256"]
        if not hmac.compare_digest(live_checkpoint_digest, self._base_ckpt_digest):
            raise ControllerError("ERR_CHECKPOINT_DRIFT", "checkpoint drifted before evaluation")
        if not hmac.compare_digest(live_adapter_sha256, bound_adapter_sha):
            raise ControllerError("ERR_ADAPTER_HASH_DRIFT", "live adapter hash differs from pre-recorded compile digest")

        cb_manifest = copy.deepcopy(self.manifest)
        cb_record = copy.deepcopy(rec)
        metrics = runtime.evaluate_candidate(manifest=cb_manifest, candidate_record=cb_record)
        self._verify_manifest_integrity(cb_manifest)
        cb_sha = cb_record.get("candidate_adapter_sha256")
        if (
            not isinstance(cb_sha, str)
            or not hmac.compare_digest(cb_sha, bound_adapter_sha)
            or not hmac.compare_digest(rec["candidate_adapter_sha256"], bound_adapter_sha)
        ):
            raise ControllerError("ERR_ADAPTER_HASH_DRIFT", "runtime callback tampered with candidate_adapter_sha256")
        if not isinstance(metrics, Mapping):
            raise ControllerError("ERR_MALFORMED_RUNTIME_OUTPUT", "runtime evaluation output must be a mapping")
        ec.verify_no_floats(metrics)

        # Both task_exact_gain and logprob_margin_delta accept signed exact rational pairs
        # so regressed candidates (e.g., -5pp gain) evaluate and record REJECTED cleanly.
        task_gain = _require_signed_rational_pair(metrics.get("task_exact_gain"), "task_exact_gain")
        lp_delta = _require_signed_rational_pair(metrics.get("logprob_margin_delta"), "logprob_margin_delta")

        iid_drop = ec.require_rational_pair(metrics.get("iid_retention_drop"), "iid_retention_drop", allow_zero_num=True)
        shifted_drop = ec.require_rational_pair(metrics.get("shifted_retention_drop"), "shifted_retention_drop", allow_zero_num=True)
        safety_pass = ec.require_rational_pair(metrics.get("safety_canary_pass_rate"), "safety_canary_pass_rate", allow_zero_num=True)
        res_before = ec.require_rational_pair(metrics.get("residual_movement_before"), "residual_movement_before", allow_zero_num=True)
        res_after = ec.require_rational_pair(metrics.get("residual_movement_after"), "residual_movement_after", allow_zero_num=True)
        kl_before = ec.require_exact_int(metrics.get("unrelated_kl_before_milli"), "unrelated_kl_before_milli", min_value=0)
        kl_after = ec.require_exact_int(metrics.get("unrelated_kl_after_milli"), "unrelated_kl_after_milli", min_value=0)
        eval_ms = ec.require_exact_int(metrics.get("local_eval_ms"), "local_eval_ms", min_value=0)
        text_plausible = bool(metrics.get("text_plausible", False))

        thresh = self.manifest["frozen_thresholds"]
        latch = evaluate_goodhart_latch(
            residual_before=res_before,
            residual_after=res_after,
            unrelated_kl_before_milli=kl_before,
            unrelated_kl_after_milli=kl_after,
            max_unrelated_kl_milli=thresh["max_unrelated_kl_milli"],
        )

        nxt_phase, nxt_contact, _ = reconcile_controller_step(rec["phase"], rec["contact"], "Evaluating")
        rec["phase"] = nxt_phase
        rec["contact"] = nxt_contact

        eval_record = {
            "candidate_adapter_sha256": bound_adapter_sha,
            "live_adapter_sha256": bound_adapter_sha,
            "live_checkpoint_digest": live_checkpoint_digest,
            "binding_receipt_seq": rec["binding_receipt_seq"],
            "task_exact_gain": [task_gain.numerator, task_gain.denominator],
            "logprob_margin_delta": [lp_delta.numerator, lp_delta.denominator],
            "iid_retention_drop": [iid_drop.numerator, iid_drop.denominator],
            "shifted_retention_drop": [shifted_drop.numerator, shifted_drop.denominator],
            "safety_canary_pass_rate": [safety_pass.numerator, safety_pass.denominator],
            "unrelated_kl_before_milli": kl_before,
            "unrelated_kl_after_milli": kl_after,
            "goodhart_latch": latch,
            "text_plausible": text_plausible,
            "local_eval_ms": eval_ms,
            "evidence_scope": "logic_check_fake_runtime" if runtime.is_mock else "live_checkpoint_runtime",
        }
        rec["evaluation"] = eval_record
        receipt = self.ledger.append("evaluate", candidate_id=candidate_id, payload=eval_record)
        rec["eval_receipt_seq"] = receipt["seq"]
        return {"candidate_id": candidate_id, "evaluation": eval_record, "receipt": receipt}

    # Operation 4: promote_or_reject
    def promote_or_reject(
        self,
        candidate_id: str,
        *,
        judge_comparison: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        if candidate_id not in self._candidates:
            raise ControllerError("ERR_UNKNOWN_CANDIDATE", f"unknown candidate_id: {candidate_id!r}")
        rec = self._candidates[candidate_id]
        if rec["phase"] != "Evaluating" or rec["evaluation"] is None:
            raise ControllerError("ERR_INVALID_PHASE", f"promote_or_reject requires Evaluating, got {rec['phase']!r}")

        if judge_comparison is not None:
            ec.verify_no_floats(judge_comparison)
            ec.verify_ring0_immutability(self.manifest, judge_comparison)

        self._verify_manifest_integrity()
        ev = rec["evaluation"]
        thresh = self.manifest["frozen_thresholds"]
        role = rec["proposal"]["control_role"]

        task_gain = Fraction(ev["task_exact_gain"][0], ev["task_exact_gain"][1])
        lp_delta = Fraction(ev["logprob_margin_delta"][0], ev["logprob_margin_delta"][1])
        iid_drop = Fraction(ev["iid_retention_drop"][0], ev["iid_retention_drop"][1])
        shifted_drop = Fraction(ev["shifted_retention_drop"][0], ev["shifted_retention_drop"][1])
        safety_rate = Fraction(ev["safety_canary_pass_rate"][0], ev["safety_canary_pass_rate"][1])
        latch_halt = bool(ev["goodhart_latch"]["latch_halt"])

        min_gain = Fraction(thresh["min_task_exact_gain"][0], thresh["min_task_exact_gain"][1])
        min_lp = Fraction(thresh["min_logprob_margin_delta"][0], thresh["min_logprob_margin_delta"][1])
        max_iid = Fraction(thresh["max_iid_retention_drop"][0], thresh["max_iid_retention_drop"][1])
        max_shifted = Fraction(thresh["max_shifted_retention_drop"][0], thresh["max_shifted_retention_drop"][1])

        failures: list[str] = []
        if safety_rate != Fraction(1, 1):
            failures.append("safety_canary_failed")
        if iid_drop > max_iid:
            failures.append("iid_retention_drop_exceeded")
        if shifted_drop > max_shifted:
            failures.append("shifted_retention_drop_exceeded")
        if latch_halt:
            failures.append("goodhart_kl_latch_halted")

        if role == "unchanged_base":
            if task_gain != Fraction(0, 1):
                failures.append("unchanged_base_nonzero_task_gain")
            if lp_delta != Fraction(0, 1):
                failures.append("unchanged_base_nonzero_logprob_shift")
            if failures:
                verdict = "REJECTED"
                obs = "Rejected"
            else:
                verdict = "CONTROL_BASE_PASS"
                obs = "Rejected"  # Base control never activates an adapter; terminal non-promoted
        else:
            if task_gain < min_gain:
                failures.append("task_exact_gain_below_threshold")
            if lp_delta < min_lp:
                failures.append("logprob_margin_below_threshold")
            if role != "candidate":
                failures.append("control_role_cannot_promote")
            if failures:
                verdict = "REJECTED"
                obs = "Rejected"
            else:
                verdict = "PROMOTED"
                obs = "Promoted"

        nxt_phase, nxt_contact, _ = reconcile_controller_step(rec["phase"], rec["contact"], obs)
        rec["phase"] = nxt_phase
        rec["contact"] = nxt_contact
        rec["verdict"] = verdict

        decision_payload = {
            "verdict": verdict,
            "control_role": role,
            "failures": failures,
            "deterministic_local_authority": True,
            "judge_advisory_vote": judge_comparison.get("advisory_vote") if judge_comparison else None,
            "binding_receipt_seq": rec["binding_receipt_seq"],
            "eval_receipt_seq": rec["eval_receipt_seq"],
            "hash_recorded_before_eval": rec["binding_receipt_seq"] < rec["eval_receipt_seq"],
            "evidence_scope": ev["evidence_scope"],
        }
        receipt = self.ledger.append("promote_or_reject", candidate_id=candidate_id, payload=decision_payload)
        return {"candidate_id": candidate_id, "verdict": verdict, "failures": failures, "receipt": receipt}

    # Operation 5: rollback
    def rollback(
        self,
        candidate_id: str,
        *,
        runtime: RuntimeAdapter,
        reason: str = "controller_rollback",
        expected_state_banks: tuple[str, ...] | None = None,
    ) -> dict[str, Any]:
        self._verify_manifest_integrity()
        if candidate_id not in self._candidates:
            raise ControllerError("ERR_UNKNOWN_CANDIDATE", f"unknown candidate_id: {candidate_id!r}")
        req_banks = self._required_state_banks if expected_state_banks is None else tuple(expected_state_banks)
        missing_req = [b for b in self._required_state_banks if b not in req_banks]
        if missing_req:
            raise ControllerError(
                "ERR_INVALID_STATE_BANKS",
                f"expected_state_banks omitted checkpoint-required banks: {missing_req}",
            )
        ec.require_non_empty_str(reason, "reason")

        rb = runtime.rollback_and_flush(required_state_banks=req_banks, reason=reason)
        self._verify_manifest_integrity()
        if not isinstance(rb, Mapping):
            raise ControllerError("ERR_MALFORMED_RUNTIME_OUTPUT", "runtime rollback output must be a mapping")
        ec.verify_no_floats(rb)

        raw_flushed = rb.get("banks_flushed")
        if not isinstance(raw_flushed, (list, tuple)):
            raise ControllerError("ERR_STATE_FLUSH_INCOMPLETE", "banks_flushed must be a sequence")
        flushed = tuple(raw_flushed)
        missing_banks = [b for b in req_banks if b not in flushed]
        if missing_banks:
            raise ControllerError("ERR_STATE_FLUSH_INCOMPLETE", f"unflushed required state banks: {missing_banks}")

        logit_diff_milli = ec.require_exact_int(rb.get("baseline_logit_diff_milli"), "baseline_logit_diff_milli", min_value=0)
        if logit_diff_milli > self.manifest["frozen_thresholds"]["max_rollback_logit_diff_milli"]:
            raise ControllerError("ERR_ROLLBACK_LOGIT_DRIFT", f"baseline_logit_diff_milli={logit_diff_milli} != 0")

        rb_ms = ec.require_exact_int(rb.get("deploy_rollback_ms"), "deploy_rollback_ms", min_value=0)
        rec = self._candidates[candidate_id]
        rec["rolled_back"] = True

        rb_payload = {
            "reason": reason,
            "banks_requested": list(req_banks),
            "banks_flushed": list(flushed),
            "baseline_logit_diff_milli": logit_diff_milli,
            "baseline_logits_restored": True,
            "deploy_rollback_ms": rb_ms,
            "evidence_scope": "logic_check_fake_runtime" if runtime.is_mock else "live_checkpoint_runtime",
        }
        receipt = self.ledger.append("rollback", candidate_id=candidate_id, payload=rb_payload)
        return {"candidate_id": candidate_id, "baseline_logits_restored": True, "receipt": receipt}


# ---------------------------------------------------------------------------
# Part 5: Redacted Kimi-on-Cerebras 3-Call Advisory Client (Issue #6)
# ---------------------------------------------------------------------------

def _is_short_printable_ascii(value: Any, max_len: int = MAX_EGRESS_TOKEN_LEN) -> bool:
    return (
        type(value) is str
        and 0 < len(value) <= max_len
        and value == value.strip()
        and all(32 <= ord(ch) <= 126 for ch in value)
    )


def validate_failure_report_egress(failure_report: Any) -> dict[str, Any]:
    """Strict allowlist validator for outbound diagnose() failure_report payloads.

    Closes the egress alias bypass: only fixed structured diagnostic fields with exact
    integers or short printable-ASCII enum/code strings may cross the provider boundary.
    """
    if not isinstance(failure_report, Mapping):
        raise ControllerError("ERR_EGRESS_POLICY_VIOLATION", "failure_report must be a mapping")
    cleaned: dict[str, Any] = {}
    for k, v in failure_report.items():
        if type(k) is not str or k not in ALLOWED_FAILURE_REPORT_KEYS:
            raise ControllerError("ERR_EGRESS_POLICY_VIOLATION", f"unlisted failure_report key {k!r}")
        if k in FAILURE_REPORT_INT_KEYS:
            if type(v) is not int or v < 0:
                raise ControllerError("ERR_EGRESS_POLICY_VIOLATION", f"failure_report.{k} must be non-negative int")
            cleaned[k] = v
        elif k == "failures":
            if not isinstance(v, (list, tuple)) or len(v) > MAX_FAILURE_CODES:
                raise ControllerError("ERR_EGRESS_POLICY_VIOLATION", "failure_report.failures must be short code list")
            items: list[str] = []
            for item in v:
                if not _is_short_printable_ascii(item):
                    raise ControllerError("ERR_EGRESS_POLICY_VIOLATION", "failure_report.failures entry invalid")
                items.append(item)
            cleaned[k] = items
        else:
            if not _is_short_printable_ascii(v):
                raise ControllerError("ERR_EGRESS_POLICY_VIOLATION", f"failure_report.{k} must be short ASCII token")
            cleaned[k] = v
    return cleaned


def validate_history_summary_egress(history_summary: Any) -> list[dict[str, Any]]:
    """Strict allowlist validator for outbound propose() history_summary lists."""
    if not isinstance(history_summary, (list, tuple)) or len(history_summary) > MAX_HISTORY_SUMMARY_ITEMS:
        raise ControllerError("ERR_EGRESS_POLICY_VIOLATION", "history_summary must be bounded sequence of summary dicts")
    return [validate_failure_report_egress(entry) for entry in history_summary]


def _project_manifest_for_egress(frozen_manifest: Any, *, include_knobs: bool) -> dict[str, Any]:
    """Strict allowlist projection of frozen_manifest fields crossing the provider boundary."""
    if not isinstance(frozen_manifest, Mapping):
        raise ControllerError("ERR_EGRESS_POLICY_VIOLATION", "frozen_manifest must be a mapping")
    try:
        contract_sha = ec.require_sha256(frozen_manifest.get("manifest_sha256"), "manifest_sha256")
    except ec.ExperimentContractError as exc:
        raise ControllerError("ERR_EGRESS_POLICY_VIOLATION", str(exc)) from exc
    projected: dict[str, Any] = {"contract_sha256": contract_sha}
    if not include_knobs:
        return projected
    target_layer = frozen_manifest.get("target_layer")
    if type(target_layer) is not str or not ec.LAYER_RE.match(target_layer):
        raise ControllerError("ERR_EGRESS_POLICY_VIOLATION", "target_layer invalid for egress")
    knobs = frozen_manifest.get("allowed_knobs")
    if not isinstance(knobs, Mapping) or set(knobs.keys()) != ALLOWED_KNOBS_KEYS:
        raise ControllerError("ERR_EGRESS_POLICY_VIOLATION", "allowed_knobs must match strict allowlisted keys")
    raw_ranks = knobs["ranks"]
    if not isinstance(raw_ranks, (list, tuple)) or not (1 <= len(raw_ranks) <= MAX_KNOB_LIST_LEN):
        raise ControllerError("ERR_EGRESS_POLICY_VIOLATION", "allowed_knobs.ranks must be bounded non-empty list")
    ranks: list[int] = []
    for r in raw_ranks:
        if type(r) is not int or r < 1:
            raise ControllerError("ERR_EGRESS_POLICY_VIOLATION", "allowed_knobs.ranks entry must be positive int")
        ranks.append(r)
    s_den = knobs["strength_den"]
    s_min = knobs["strength_num_min"]
    s_max = knobs["strength_num_max"]
    if (
        type(s_den) is not int
        or s_den < 1
        or type(s_min) is not int
        or s_min < 1
        or type(s_max) is not int
        or s_max < s_min
    ):
        raise ControllerError("ERR_EGRESS_POLICY_VIOLATION", "allowed_knobs strength bounds invalid")
    raw_quants = knobs["quantizations"]
    if not isinstance(raw_quants, (list, tuple)) or not (1 <= len(raw_quants) <= MAX_KNOB_LIST_LEN):
        raise ControllerError("ERR_EGRESS_POLICY_VIOLATION", "allowed_knobs.quantizations must be bounded non-empty list")
    quants: list[str] = []
    for q in raw_quants:
        if not _is_short_printable_ascii(q):
            raise ControllerError("ERR_EGRESS_POLICY_VIOLATION", "allowed_knobs.quantizations entry invalid")
        quants.append(q)
    projected["target_layer"] = target_layer
    projected["allowed_knobs"] = {
        "ranks": ranks,
        "strength_den": s_den,
        "strength_num_min": s_min,
        "strength_num_max": s_max,
        "quantizations": quants,
    }
    return projected


def sanitize_outbound_payload(payload: Any, path: str = "$") -> None:
    """Fail-closed egress sanitizer guaranteeing Cerebras sees ONLY fixed text & metrics."""
    if isinstance(payload, Mapping):
        for k, v in payload.items():
            if str(k).lower() in FORBIDDEN_EGRESS_KEYS:
                raise ControllerError("ERR_EGRESS_POLICY_VIOLATION", f"forbidden outbound key {k!r} at {path}")
            sanitize_outbound_payload(v, f"{path}.{k}")
    elif isinstance(payload, (list, tuple)):
        for idx, v in enumerate(payload):
            sanitize_outbound_payload(v, f"{path}[{idx}]")


class CerebrasTransport(Protocol):
    transport_mode: str
    live_credentials_used: bool

    def call(self, request: Mapping[str, Any]) -> dict[str, Any]: ...


class CerebrasKimiAdvisoryClient:
    """Bounded 3-call (propose/diagnose/compare) advisory boundary with redacted receipts (Issue #6)."""

    def __init__(
        self,
        transport: CerebrasTransport,
        *,
        provider: str = "cerebras",
        expected_model: str = "kimi-k3.1-pro",
        timeout_ms: int = 10_000,
        max_retries: int = 1,
    ) -> None:
        self.transport = transport
        self.provider = ec.require_non_empty_str(provider, "provider")
        self.expected_model = ec.require_non_empty_str(expected_model, "expected_model")
        self.timeout_ms = ec.require_exact_int(timeout_ms, "timeout_ms", min_value=1)
        self.max_retries = ec.require_exact_int(max_retries, "max_retries", min_value=0, max_value=3)
        self._receipts: list[dict[str, Any]] = []

    @property
    def receipts(self) -> tuple[dict[str, Any], ...]:
        return tuple(self._receipts)

    def _record_receipt(
        self,
        *,
        call_kind: str,
        served_model: str | None,
        prompt_hash: str,
        decoding: dict[str, int],
        seed: int,
        prompt_tokens: int,
        completion_tokens: int,
        latency_ms: int,
        retries: int,
        status: str,
        error_code: str | None,
    ) -> dict[str, Any]:
        receipt = {
            "call_kind": call_kind,
            "provider": self.provider,
            "requested_model": self.expected_model,
            "served_model": served_model,
            "prompt_sha256": prompt_hash,
            "decoding_params": decoding,
            "seed": seed,
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "latency_ms": latency_ms,
            "retries": retries,
            "timeout_ms": self.timeout_ms,
            "transport_mode": self.transport.transport_mode,
            "live_credentials_used": bool(self.transport.live_credentials_used),
            "status": status,
            "error_code": error_code,
        }
        self._receipts.append(receipt)
        return receipt

    def _invoke(
        self,
        call_kind: str,
        prompt_payload: Mapping[str, Any],
        *,
        seed: int,
        max_tokens: int,
        schema_validator: Callable[[dict[str, Any]], None],
    ) -> dict[str, Any]:
        ec.verify_no_floats(prompt_payload)
        sanitize_outbound_payload(prompt_payload)
        seed_i = ec.require_exact_int(seed, "seed", min_value=0)
        max_tok = ec.require_exact_int(max_tokens, "max_tokens", min_value=1)

        prompt_hash = ec.sha256_canonical(prompt_payload)
        decoding = {"temperature_milli": 0, "max_tokens": max_tok}
        req = {
            "call_kind": call_kind,
            "provider": self.provider,
            "requested_model": self.expected_model,
            "decoding_params": decoding,
            "seed": seed_i,
            "timeout_ms": self.timeout_ms,
            "payload": dict(prompt_payload),
        }

        retries = 0
        raw_resp: dict[str, Any] | None = None
        last_err_code: str | None = None
        while retries <= self.max_retries:
            resp = self.transport.call(req)
            if not isinstance(resp, Mapping):
                last_err_code = "ERR_TRANSPORT_FAILURE"
                retries += 1
                continue
            status = resp.get("status")
            if status == "ok":
                raw_resp = dict(resp)
                break
            raw_ec = resp.get("error_code")
            last_err_code = raw_ec if _is_short_printable_ascii(raw_ec, max_len=MAX_EGRESS_TOKEN_LEN) else "ERR_TRANSPORT_FAILURE"
            retries += 1

        if raw_resp is None:
            self._record_receipt(
                call_kind=call_kind,
                served_model=None,
                prompt_hash=prompt_hash,
                decoding=decoding,
                seed=seed_i,
                prompt_tokens=0,
                completion_tokens=0,
                latency_ms=self.timeout_ms,
                retries=retries - 1,
                status="error",
                error_code=last_err_code,
            )
            raise ControllerError(last_err_code or "ERR_TRANSPORT_FAILURE", f"Cerebras transport failed for {call_kind}")

        try:
            raw_sm = raw_resp.get("served_model")
            if not _is_short_printable_ascii(raw_sm, max_len=128):
                raise ec.ExperimentContractError(
                    "ERR_MALFORMED_PROVIDER_METADATA",
                    "served_model must be printable ASCII <= 128 chars",
                )
            served_model = raw_sm
            p_tok = ec.require_exact_int(raw_resp.get("prompt_tokens", 0), "prompt_tokens", min_value=0)
            c_tok = ec.require_exact_int(raw_resp.get("completion_tokens", 0), "completion_tokens", min_value=0)
            lat_ms = ec.require_exact_int(raw_resp.get("latency_ms", 0), "latency_ms", min_value=0)
        except ec.ExperimentContractError as exc:
            raw_sm = raw_resp.get("served_model")
            safe_sm = raw_sm if _is_short_printable_ascii(raw_sm, max_len=128) else None
            self._record_receipt(
                call_kind=call_kind,
                served_model=safe_sm,
                prompt_hash=prompt_hash,
                decoding=decoding,
                seed=seed_i,
                prompt_tokens=0,
                completion_tokens=0,
                latency_ms=0,
                retries=retries,
                status="rejected",
                error_code="ERR_MALFORMED_PROVIDER_METADATA",
            )
            raise ControllerError("ERR_MALFORMED_PROVIDER_METADATA", str(exc)) from exc

        if served_model != self.expected_model:
            self._record_receipt(
                call_kind=call_kind,
                served_model=served_model,
                prompt_hash=prompt_hash,
                decoding=decoding,
                seed=seed_i,
                prompt_tokens=p_tok,
                completion_tokens=c_tok,
                latency_ms=lat_ms,
                retries=retries,
                status="rejected",
                error_code="ERR_MODEL_SUBSTITUTION",
            )
            raise ControllerError("ERR_MODEL_SUBSTITUTION", f"served_model {served_model!r} != {self.expected_model!r}")

        raw_text = raw_resp.get("content_json")
        try:
            parsed = ec.loads_strict_unique_json(raw_text, forbid_floats=True)
        except ec.ExperimentContractError as exc:
            self._record_receipt(
                call_kind=call_kind,
                served_model=served_model,
                prompt_hash=prompt_hash,
                decoding=decoding,
                seed=seed_i,
                prompt_tokens=p_tok,
                completion_tokens=c_tok,
                latency_ms=lat_ms,
                retries=retries,
                status="rejected",
                error_code="ERR_MALFORMED_ADVISORY_RESPONSE",
            )
            raise ControllerError("ERR_MALFORMED_ADVISORY_RESPONSE", str(exc)) from exc
        if not isinstance(parsed, dict):
            self._record_receipt(
                call_kind=call_kind,
                served_model=served_model,
                prompt_hash=prompt_hash,
                decoding=decoding,
                seed=seed_i,
                prompt_tokens=p_tok,
                completion_tokens=c_tok,
                latency_ms=lat_ms,
                retries=retries,
                status="rejected",
                error_code="ERR_MALFORMED_ADVISORY_RESPONSE",
            )
            raise ControllerError("ERR_MALFORMED_ADVISORY_RESPONSE", "advisory JSON response must be object")

        try:
            schema_validator(parsed)
        except ControllerError as exc:
            self._record_receipt(
                call_kind=call_kind,
                served_model=served_model,
                prompt_hash=prompt_hash,
                decoding=decoding,
                seed=seed_i,
                prompt_tokens=p_tok,
                completion_tokens=c_tok,
                latency_ms=lat_ms,
                retries=retries,
                status="rejected",
                error_code=exc.code,
            )
            raise

        receipt = self._record_receipt(
            call_kind=call_kind,
            served_model=served_model,
            prompt_hash=prompt_hash,
            decoding=decoding,
            seed=seed_i,
            prompt_tokens=p_tok,
            completion_tokens=c_tok,
            latency_ms=lat_ms,
            retries=retries,
            status="ok",
            error_code=None,
        )
        return {"parsed": parsed, "receipt": receipt}

    def propose(self, *, frozen_manifest: Mapping[str, Any], history_summary: Sequence[Mapping[str, Any]], seed: int = 101) -> dict[str, Any]:
        payload = _project_manifest_for_egress(frozen_manifest, include_knobs=True)
        payload["history_summary"] = validate_history_summary_egress(history_summary)

        def _check_propose(parsed: dict[str, Any]) -> None:
            for req in ("candidate_id", "target_layer", "rank", "strength_num", "strength_den", "quantization", "seed"):
                if req not in parsed:
                    raise ControllerError("ERR_INVALID_PROPOSAL_SCHEMA", f"propose response missing {req!r}")

        return self._invoke("propose", payload, seed=seed, max_tokens=256, schema_validator=_check_propose)

    def diagnose(
        self,
        *,
        frozen_manifest: Mapping[str, Any],
        failure_report: Mapping[str, Any],
        remaining_rounds: int,
        seed: int = 102,
    ) -> dict[str, Any]:
        rem = ec.require_exact_int(remaining_rounds, "remaining_rounds", min_value=1)
        clean_manifest = _project_manifest_for_egress(frozen_manifest, include_knobs=False)
        clean_report = validate_failure_report_egress(failure_report)
        payload = {
            "contract_sha256": clean_manifest["contract_sha256"],
            "remaining_rounds": rem,
            "failure_report": clean_report,
        }

        def _check_diagnose(parsed: dict[str, Any]) -> None:
            if "diagnosis" not in parsed or "repair_proposal" not in parsed or not isinstance(parsed["repair_proposal"], dict):
                raise ControllerError("ERR_INVALID_DIAGNOSIS_SCHEMA", "diagnose response missing diagnosis or repair_proposal")

        return self._invoke("diagnose", payload, seed=seed, max_tokens=384, schema_validator=_check_diagnose)

    def compare(
        self,
        *,
        case_id: str,
        baseline_text: str,
        adapted_text: str,
        seed: int = 103,
    ) -> dict[str, Any]:
        payload = {
            "case_id": ec.require_non_empty_str(case_id, "case_id"),
            "baseline_text": ec.require_non_empty_str(baseline_text, "baseline_text"),
            "adapted_text": ec.require_non_empty_str(adapted_text, "adapted_text"),
        }

        def _check_compare(parsed: dict[str, Any]) -> None:
            if parsed.get("advisory_vote") not in ("BETTER", "EQUAL", "WORSE"):
                raise ControllerError("ERR_INVALID_COMPARE_SCHEMA", "advisory_vote must be BETTER, EQUAL, or WORSE")

        return self._invoke("compare", payload, seed=seed, max_tokens=256, schema_validator=_check_compare)
