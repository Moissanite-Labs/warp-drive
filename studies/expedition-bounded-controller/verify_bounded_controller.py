#!/usr/bin/env python3
"""End-to-end exact-rational verification & certificate generator for AUDIT-063 (Round 6 Arm R6-3).

Exercises the complete Moissanite-Labs/warp-drive Issues #4, #5, #6 frozen experiment contract,
5-op bounded experiment controller, monotone (Phase, Contact) reconciler lattice (385 states),
redacted Kimi-on-Cerebras advisory boundary, and in-repo src/warp_modeld Stage 1/2
adapter compatibility check.

100% pure Python 3 stdlib, zero floats in JSON, zero bare asserts, zero subprocesses.
Safe under: python3 -I -B, python3 -I -O -B, python3 -I -B -W error, PYTHONHASHSEED=12345.
"""

from __future__ import annotations

import argparse
from fractions import Fraction
import hashlib
import json
import os
from pathlib import Path
import sys
from typing import Any, Mapping

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import bounded_controller as bc  # noqa: E402
import experiment_contract as ec  # noqa: E402

IN_REPO_ROOT = HERE.parent.parent
HMAC_KEY_ENV_VAR = "WARP_STUDY_HMAC_KEY"


def resolve_study_hmac_key(
    *,
    manifest_sha256: str,
    hmac_key: bytes | None = None,
) -> tuple[bytes, str]:
    """Resolve tamper-evidence-only HMAC key from parameter, env var, or deterministic fixture.

    The ledger HMAC signature in this study provides local tamper-evidence over receipts,
    not external confidentiality or production key management.
    """
    if hmac_key is not None:
        if not isinstance(hmac_key, (bytes, bytearray)) or len(hmac_key) < 16:
            raise bc.ControllerError("ERR_INVALID_KEY", "explicit hmac_key must be >= 16 bytes")
        return bytes(hmac_key), "explicit_parameter"
    env_val = os.environ.get(HMAC_KEY_ENV_VAR)
    if env_val is not None:
        raw = env_val.encode("utf-8")
        if len(raw) < 16:
            raise bc.ControllerError("ERR_INVALID_KEY", f"{HMAC_KEY_ENV_VAR} must be >= 16 UTF-8 bytes")
        return raw, f"env:{HMAC_KEY_ENV_VAR}"
    derived = hashlib.sha256(f"warp-study-tamper-evidence-only:{manifest_sha256}".encode("ascii")).digest()
    return derived, "deterministic_study_fixture"


def _require(cond: bool, msg: str) -> None:
    if not cond:
        raise RuntimeError(f"AUDIT-063 FAILURE: {msg}")


def _sha(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def build_reference_splits() -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Build (train_cases, clean_family_separated_heldout, leaky_98pct_heldout)."""
    train: list[dict[str, Any]] = []
    for i in range(50):
        train.append(
            {
                "case_id": f"train-{i:02d}",
                "family_id": f"fam-train-{i // 5:02d}",
                "prompt": f"Solve arithmetic task #{i}: compute {10 + i} + {20 + i}.",
                "target_token": f"ans_{30 + 2 * i}",
                "negative_tokens": [f"wrong_{i}_a", f"wrong_{i}_b"],
            }
        )

    # Disjoint families, disjoint prompts, disjoint target/negative-set pairs (0% leakage)
    clean_heldout: list[dict[str, Any]] = []
    for i in range(24):
        clean_heldout.append(
            {
                "case_id": f"held-clean-{i:02d}",
                "family_id": f"fam-heldout-{i // 4:02d}",
                "prompt": f"Verify formal invariant #{i}: prove monotonicity for step {100 + i}.",
                "target_token": f"proof_tok_{i}",
                "negative_tokens": [f"bad_proof_{i}_a", f"bad_proof_{i}_b"],
            }
        )

    # Mirrors ml-os#6's 98% (49/50) split-leakage trap (Issue #2 / Issue #4)
    leaky_heldout: list[dict[str, Any]] = []
    for i in range(50):
        if i < 49:
            leaky_heldout.append(
                {
                    "case_id": f"held-leaky-{i:02d}",
                    "family_id": f"fam-held-leaky-{i // 5:02d}",
                    "prompt": f"Paraphrased prompt #{i} reusing train pair.",
                    "target_token": train[i]["target_token"],
                    "negative_tokens": list(train[i]["negative_tokens"]),
                }
            )
        else:
            leaky_heldout.append(
                {
                    "case_id": "held-leaky-49",
                    "family_id": "fam-held-leaky-unique",
                    "prompt": "Sole non-overlapping heldout case.",
                    "target_token": "sole_unique_tok",
                    "negative_tokens": ["sole_neg_a", "sole_neg_b"],
                }
            )
    return train, clean_heldout, leaky_heldout


def build_reference_manifest(
    train_cases: list[dict[str, Any]],
    clean_heldout: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build canonical frozen Issue #4 manifest pinning Qwen3.5-4B Q8_0 last-layer blk.31."""
    return ec.build_frozen_manifest(
        base_checkpoint={
            "model_id": "Qwen3.5-4B-Q8_0",
            "layout_sha256": _sha("qwen35-4b-layout"),
            "weights_sha256": _sha("qwen35-4b-q8_0-gguf"),
            "config_sha256": _sha("qwen35-4b-config"),
            "tokenizer_sha256": _sha("qwen35-4b-tokenizer"),
            "chat_template_sha256": _sha("qwen35-4b-chat-template"),
            "has_ssm_recurrent": True,
            "has_horizontal_lattice": True,
            "lattice_layers": 32,
            "lattice_width": 4,
        },
        runtime_flags_sha256=_sha("llama-server-7fe450e19-lora-init-without-apply"),
        compiler_commit="a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
        parent_lineage={
            "corpus_tree_sha256": _sha("plane1-corpus-tree-2026-11-21"),
            "domain_commits": {
                "formal-verification": "111122223333444455556666777788889999aaaa",
            },
            "contested_heads": [],
        },
        target_layer="blk.31",
        allowed_knobs={
            "ranks": [4, 8, 16],
            "strength_den": 10,
            "strength_num_min": 1,
            "strength_num_max": 20,
            "quantizations": ["f16", "q8_0"],
        },
        frozen_thresholds={
            "min_task_exact_gain": [1, 20],          # >= +5pp exact task score
            "min_logprob_margin_delta": [1, 2],      # >= +0.5 logprob margin separation
            "max_iid_retention_drop": [1, 100],      # <= 1pp IID retention drop
            "max_shifted_retention_drop": [1, 50],   # <= 2pp shifted retention drop
            "max_unrelated_kl_milli": 50,            # <= 0.050 nats KL cap (catches +55% precond blowup)
            "safety_canary_pass_required": [1, 1],   # 100% safety preservation floor
            "max_rollback_logit_diff_milli": 0,      # exact 0 baseline logit restore
        },
        max_repair_rounds=3,
        suite_digests={
            "task_train_sha256": ec.sha256_canonical(train_cases),
            "task_heldout_sha256": ec.sha256_canonical(clean_heldout),
            "iid_retention_sha256": _sha("frozen-iid-retention-suite-v1"),
            "shifted_retention_sha256": _sha("frozen-shifted-retention-suite-v1"),
            "safety_canaries_sha256": _sha("frozen-os-safety-canaries-v1"),
        },
        preregistration={
            "plan_commit": "0000111122223333444455556666777788889999",
            "data_commit": "eeee111122223333444455556666777788889999",
            "split_leakage_audit_passed": True,
        },
        extensions={
            "future_ext_note": "unknown_field_preserved_under_frozen_v1",
        },
    )


class _DeterministicMockCompiler:
    """Explicitly labeled fake compiler adapter for logic-check verification (Issue #5)."""

    is_mock = True

    def compile_candidate(
        self,
        *,
        manifest: Mapping[str, Any],
        proposal: Mapping[str, Any],
    ) -> dict[str, Any]:
        adapter_sha = ec.sha256_canonical(
            {
                "manifest_sha256": manifest["manifest_sha256"],
                "candidate_id": proposal["candidate_id"],
                "rank": proposal["rank"],
                "strength_num": proposal["strength_num"],
                "strength_den": proposal["strength_den"],
                "quantization": proposal["quantization"],
                "seed": proposal["seed"],
            }
        )
        return {
            "candidate_adapter_sha256": adapter_sha,
            "compile_ms": 0 if proposal["control_role"] == "unchanged_base" else 420,
            "compiler_commit": manifest["compiler_commit"],
        }


class _DeterministicMockRuntime:
    """Explicitly labeled fake runtime adapter for logic-check verification (Issues #4/#5/#7)."""

    is_mock = True

    def __init__(self, profiles: Mapping[str, dict[str, Any]]) -> None:
        self._profiles = dict(profiles)
        self.fail_lattice_flush = False
        self.inject_logit_drift_milli = 0

    def evaluate_candidate(
        self,
        *,
        manifest: Mapping[str, Any],
        candidate_record: Mapping[str, Any],
    ) -> dict[str, Any]:
        _ = manifest
        cid = candidate_record["proposal"]["candidate_id"]
        return dict(self._profiles[cid])

    def rollback_and_flush(
        self,
        *,
        required_state_banks: tuple[str, ...],
        reason: str,
    ) -> dict[str, Any]:
        _ = reason
        flushed = (
            [b for b in required_state_banks if b != "lattice_horizontal_streams"]
            if self.fail_lattice_flush
            else list(required_state_banks)
        )
        return {
            "banks_flushed": flushed,
            "baseline_logit_diff_milli": self.inject_logit_drift_milli,
            "deploy_rollback_ms": 18,
        }


class _DeterministicMockCerebrasTransport:
    """Explicitly labeled mock Cerebras/Kimi transport (live_credentials_used=False, Issue #6)."""

    transport_mode = "mock_contract"
    live_credentials_used = False

    def __init__(self, manifest_sha: str) -> None:
        self._manifest_sha = manifest_sha
        self.mode = "normal"
        self._calls = 0

    def call(self, request: Mapping[str, Any]) -> dict[str, Any]:
        self._calls += 1
        kind = request["call_kind"]
        if self.mode == "timeout":
            return {"status": "error", "error_code": "ERR_TIMEOUT"}
        if self.mode == "substitute_model":
            return {
                "status": "ok",
                "served_model": "other-unapproved-model",
                "prompt_tokens": 120,
                "completion_tokens": 40,
                "latency_ms": 95,
                "content_json": '{"advisory_vote":"BETTER"}',
            }
        if self.mode == "malformed_json":
            return {
                "status": "ok",
                "served_model": "kimi-k3.1-pro",
                "prompt_tokens": 120,
                "completion_tokens": 12,
                "latency_ms": 80,
                "content_json": '{"advisory_vote":"BETTER","advisory_vote":"WORSE"}',
            }

        if kind == "propose":
            body = {
                "candidate_id": "cand-r1-underfit",
                "contract_sha256": self._manifest_sha,
                "control_role": "candidate",
                "repair_round": 1,
                "target_layer": "blk.31",
                "rank": 4,
                "strength_num": 5,
                "strength_den": 10,
                "quantization": "f16",
                "seed": 42,
                "rationale": "Initial low-strength rank-4 probe on pinned blk.31.",
            }
        elif kind == "diagnose":
            body = {
                "diagnosis": "Round 1 rank-4 strength 5/10 fell below log-prob margin and task thresholds; raise rank to 8 and strength to 10/10 on blk.31.",
                "repair_proposal": {
                    "candidate_id": "cand-r2-repaired",
                    "contract_sha256": self._manifest_sha,
                    "control_role": "candidate",
                    "repair_round": 2,
                    "target_layer": "blk.31",
                    "rank": 8,
                    "strength_num": 10,
                    "strength_den": 10,
                    "quantization": "f16",
                    "seed": 43,
                    "parent_candidate_id": "cand-r1-underfit",
                    "rationale": "Repair step within 3-round budget targeting blk.31.",
                },
            }
        else:
            # Deliberately returns BETTER even for the regressed plausible-text control so we prove
            # deterministic local gates remain strictly authoritative over the Cerebras judge!
            body = {
                "advisory_vote": "BETTER",
                "summary": "Surface prose reads fluently; local deterministic gates remain authoritative.",
            }
        return {
            "status": "ok",
            "served_model": "kimi-k3.1-pro",
            "prompt_tokens": 240,
            "completion_tokens": 96,
            "latency_ms": 64,
            "content_json": json.dumps(body, sort_keys=True, separators=(",", ":")),
        }


def _check_live_warp_drive_compat(
    manifest: Mapping[str, Any],
    promoted_adapter_sha: str,
    warp_repo: Path,
) -> dict[str, Any]:
    """Read-only Stage 1 & 2 compatibility check against shipped in-repo src/warp_modeld."""
    if not (warp_repo / "src" / "warp_modeld").is_dir():
        return {"checked_live_repo": False, "mode": "standalone_without_warp_modeld"}

    src_path = str(warp_repo / "src")
    added = False
    if src_path not in sys.path:
        sys.path.insert(0, src_path)
        added = True
    try:
        from warp_modeld.certificate import (
            CertificateBounds,
            FixedRadixCertificate,
            RationalBound,
            verify_stack_division_free,
        )
        from warp_modeld.fingerprint import (
            AdapterBundle,
            CheckpointFingerprint,
            Plane1Lineage,
            RuntimeFlags,
            verify_stage1,
        )

        ckpt_raw = manifest["base_checkpoint"]
        ckpt = CheckpointFingerprint(
            model_id=ckpt_raw["model_id"],
            layout_sha256=ckpt_raw["layout_sha256"],
            weights_sha256=ckpt_raw["weights_sha256"],
            config_sha256=ckpt_raw["config_sha256"],
            tokenizer_sha256=ckpt_raw["tokenizer_sha256"],
            chat_template_sha256=ckpt_raw["chat_template_sha256"],
            has_ssm_recurrent=ckpt_raw["has_ssm_recurrent"],
            has_horizontal_lattice=ckpt_raw["has_horizontal_lattice"],
            lattice_layers=ckpt_raw["lattice_layers"],
            lattice_width=ckpt_raw["lattice_width"],
        )
        lin = Plane1Lineage(
            corpus_tree_sha256=manifest["parent_lineage"]["corpus_tree_sha256"],
            domain_commits=dict(manifest["parent_lineage"]["domain_commits"]),
            contested_heads=(),
        )
        flags = RuntimeFlags(
            llama_server_commit="7fe450e19",
            quantization="Q8_0",
            ctx_size=16384,
            kv_cache_type="q8_0",
            ctx_checkpoints=0,
            swa_checkpoints=0,
            lora_init_without_apply=True,
            rope_args="",
            chat_template_args="thinking=off",
            has_horizontal_lattice=True,
            lattice_flush_supported=True,
        )
        radix = 1 << 24
        cert = FixedRadixCertificate.create(
            adapter_id="warp-exp:cand-r2-repaired",
            adapter_sha256=promoted_adapter_sha,
            base_weights_sha256=ckpt.weights_sha256,
            radix_scale=radix,
            frobenius_sq_scaled=radix,
            spectral_norm_sq_scaled=radix // 4,
            leakage_energy_scaled=radix // 1000,
            max_safety_dot_sq_scaled=radix // 10000,
        )
        bundle_dict = {
            "adapter_id": "warp-exp:cand-r2-repaired",
            "domain": "formal-verification",
            "llama_adapter_id": 0,
            "adapter_sha256": promoted_adapter_sha,
            "scale_num": 10,
            "scale_den": 10,
            "checkpoint": ckpt.to_dict(),
            "source_lineage": lin.to_dict(),
            "runtime_flags_sha256": flags.canonical_digest(),
            "derivation_digest": _sha("derivation-cand-r2-repaired"),
            "certificate": cert.to_dict(),
        }
        # Remove computed helper field not accepted by AdapterBundle.from_dict
        bundle_dict["checkpoint"].pop("config_bundle_sha256", None)
        bundle = AdapterBundle.from_dict(bundle_dict)
        s1 = verify_stage1(bundle, ckpt, lin, flags)
        bounds = CertificateBounds(
            max_frobenius_sq=RationalBound(5, 1),
            max_spectral_norm_sq=RationalBound(2, 1),
            max_leakage_energy=RationalBound(1, 100),
            max_safety_dot_sq=RationalBound(1, 1000),
        )
        s2 = verify_stack_division_free(
            [(bundle.certificate, bundle.adapter_id, bundle.adapter_sha256, bundle.scale_num, bundle.scale_den)],
            bounds,
            bounds,
            expected_base_weights_sha256=ckpt.weights_sha256,
        )
        _require(s1.adapter_id == "warp-exp:cand-r2-repaired" and len(s2.adapter_results) == 1, "warp_modeld stage1/2 fail")
        return {
            "checked_live_repo": True,
            "warp_drive_source": "in_repo_src_warp_modeld",
            "required_state_banks": list(ckpt.required_state_banks()),
            "stage1_adapter_id": s1.adapter_id,
            "stage2_adapter_count": len(s2.adapter_results),
            "stage1_and_stage2_passed": True,
        }
    finally:
        if added and src_path in sys.path:
            sys.path.remove(src_path)


def run_all(*, standalone: bool = False, hmac_key: bytes | None = None) -> dict[str, Any]:
    # 1. Split-leakage audit (98% leaky fixture rejected vs 0% family-separated frozen split passed)
    train_cases, clean_heldout, leaky_heldout = build_reference_splits()
    leaky_audit = ec.audit_split_leakage(train_cases, leaky_heldout, max_pair_overlap_ratio=Fraction(0))
    clean_audit = ec.audit_split_leakage(
        train_cases, clean_heldout, max_pair_overlap_ratio=Fraction(0), raise_on_fail=True
    )
    _require(not leaky_audit["passed"] and leaky_audit["pair_overlap_ratio_exact"] == "49/50", "expected 49/50 leak")
    _require(clean_audit["passed"] and clean_audit["pair_overlap_ratio_exact"] == "0", "expected 0 leak")

    # 2. Frozen Issue #4 manifest + FROZEN.md round-trip preservation + min_reader_version fence
    manifest = build_reference_manifest(train_cases, clean_heldout)
    roundtrip = ec.validate_frozen_manifest(manifest, reader_version=1)
    _require(roundtrip["future_ext_note"] == "unknown_field_preserved_under_frozen_v1", "FROZEN ext lost")

    # 3. Exhaustive 385-state monotone (Phase, Contact) controller reconciler + exact clock-pair invariance
    lattice_cert = bc.certify_reconciler_lattice_385()
    _require(
        lattice_cert["total_transitions"] == 385
        and lattice_cert["all_invariants_sound"]
        and lattice_cert["tombstone_resolutions"] == 32,
        "385-state lattice certification failed",
    )
    t_mapped = bc.map_host_to_controller_exact(Fraction(1005, 1), Fraction(1000, 1), Fraction(500, 1))
    _require(t_mapped == Fraction(505, 1), "affine clock pair failed")

    # 4. End-to-end 5-op bounded controller + redacted Cerebras/Kimi 3-call loop (Issues #5, #6, #7)
    resolved_key, hmac_key_source = resolve_study_hmac_key(
        manifest_sha256=manifest["manifest_sha256"],
        hmac_key=hmac_key,
    )
    ledger = bc.SignedExperimentLedger(resolved_key, key_id="warp-exp-hmac-v1")
    ctrl = bc.BoundedExperimentController(manifest, ledger)
    compiler = _DeterministicMockCompiler()
    runtime = _DeterministicMockRuntime(
        {
            "ctrl-unchanged-base": {
                "task_exact_gain": [0, 1],
                "logprob_margin_delta": [0, 1],
                "iid_retention_drop": [0, 1],
                "shifted_retention_drop": [0, 1],
                "safety_canary_pass_rate": [1, 1],
                "residual_movement_before": [1, 1],
                "residual_movement_after": [1, 1],
                "unrelated_kl_before_milli": 0,
                "unrelated_kl_after_milli": 0,
                "text_plausible": True,
                "local_eval_ms": 110,
            },
            "ctrl-regressed-plausible": {
                "task_exact_gain": [-1, 20],      # genuine -5pp negative regression (signed Fraction!)
                "logprob_margin_delta": [-3, 10], # negative log-prob margin!
                "iid_retention_drop": [3, 100],   # exceeds 1/100 cap
                "shifted_retention_drop": [1, 20],
                "safety_canary_pass_rate": [1, 1],
                "residual_movement_before": [10, 1],
                "residual_movement_after": [6, 1],    # residual shrank, YET KL jumped +55% (ml-os#6 trap!)
                "unrelated_kl_before_milli": 40,
                "unrelated_kl_after_milli": 62,       # +55% KL jump > 50 cap -> LATCH_HALT!
                "text_plausible": True,               # surface text looks plausible!
                "local_eval_ms": 140,
            },
            "cand-r1-underfit": {
                "task_exact_gain": [1, 50],       # +2pp < +5pp threshold
                "logprob_margin_delta": [1, 5],   # +0.2 < +0.5 threshold
                "iid_retention_drop": [0, 1],
                "shifted_retention_drop": [1, 200],
                "safety_canary_pass_rate": [1, 1],
                "residual_movement_before": [10, 1],
                "residual_movement_after": [10, 1],
                "unrelated_kl_before_milli": 10,
                "unrelated_kl_after_milli": 12,
                "text_plausible": True,
                "local_eval_ms": 135,
            },
            "cand-r2-repaired": {
                "task_exact_gain": [3, 40],       # +7.5pp >= +5pp
                "logprob_margin_delta": [9, 10],  # +0.9 >= +0.5
                "iid_retention_drop": [1, 200],   # 0.5pp <= 1pp
                "shifted_retention_drop": [1, 100],
                "safety_canary_pass_rate": [1, 1],
                "residual_movement_before": [10, 1],
                "residual_movement_after": [10, 1],
                "unrelated_kl_before_milli": 10,
                "unrelated_kl_after_milli": 15,
                "text_plausible": True,
                "local_eval_ms": 145,
            },
            "adv-regressed-ctrl-passing": {
                "task_exact_gain": [3, 40],
                "logprob_margin_delta": [9, 10],
                "iid_retention_drop": [0, 1],
                "shifted_retention_drop": [0, 1],
                "safety_canary_pass_rate": [1, 1],
                "residual_movement_before": [10, 1],
                "residual_movement_after": [10, 1],
                "unrelated_kl_before_milli": 10,
                "unrelated_kl_after_milli": 10,
                "text_plausible": True,
                "local_eval_ms": 50,
            },
        }
    )

    transport = _DeterministicMockCerebrasTransport(manifest["manifest_sha256"])
    kimi = bc.CerebrasKimiAdvisoryClient(transport, expected_model="kimi-k3.1-pro")
    ckpt_dig = ctrl.base_checkpoint_digest
    flags_dig = manifest["runtime_flags_sha256"]

    # 4A. Unchanged-base control -> passes ONLY as CONTROL_BASE_PASS (never promoted)
    ctrl.propose_candidate(
        {
            "candidate_id": "ctrl-unchanged-base",
            "contract_sha256": manifest["manifest_sha256"],
            "control_role": "unchanged_base",
            "repair_round": 0,
            "target_layer": "blk.31",
            "rank": 0,
            "strength_num": 0,
            "strength_den": 10,
            "quantization": "f16",
            "seed": 1,
        }
    )
    b_base = ctrl.compile_and_bind(
        "ctrl-unchanged-base", compiler=compiler, live_checkpoint_digest=ckpt_dig, live_runtime_flags_sha256=flags_dig
    )
    ctrl.evaluate(
        "ctrl-unchanged-base",
        runtime=runtime,
        live_adapter_sha256=b_base["candidate_adapter_sha256"],
        live_checkpoint_digest=ckpt_dig,
    )
    v_base = ctrl.promote_or_reject("ctrl-unchanged-base")
    _require(v_base["verdict"] == "CONTROL_BASE_PASS", f"unexpected base verdict {v_base}")

    # 4B. Deliberately regressed control with plausible text + positive Cerebras judge vote -> MUST REJECT!
    ctrl.propose_candidate(
        {
            "candidate_id": "ctrl-regressed-plausible",
            "contract_sha256": manifest["manifest_sha256"],
            "control_role": "regressed_control",
            "repair_round": 0,
            "target_layer": "blk.31",
            "rank": 8,
            "strength_num": 15,
            "strength_den": 10,
            "quantization": "f16",
            "seed": 2,
        }
    )
    b_reg = ctrl.compile_and_bind(
        "ctrl-regressed-plausible",
        compiler=compiler,
        live_checkpoint_digest=ckpt_dig,
        live_runtime_flags_sha256=flags_dig,
    )
    ctrl.evaluate(
        "ctrl-regressed-plausible",
        runtime=runtime,
        live_adapter_sha256=b_reg["candidate_adapter_sha256"],
        live_checkpoint_digest=ckpt_dig,
    )
    cmp_reg = kimi.compare(
        case_id="regressed-01",
        baseline_text="Baseline answer text.",
        adapted_text="Plausible surface text from regressed adapter.",
        seed=201,
    )
    _require(cmp_reg["parsed"]["advisory_vote"] == "BETTER", "expected positive advisory vote to test local override")
    v_reg = ctrl.promote_or_reject("ctrl-regressed-plausible", judge_comparison=cmp_reg["parsed"])
    _require(
        v_reg["verdict"] == "REJECTED" and "goodhart_kl_latch_halted" in v_reg["failures"],
        f"regressed plausible control must reject: {v_reg}",
    )

    # 4C. Round 1 (Kimi propose -> compile/hash BEFORE eval -> evaluate -> REJECTED)
    prop_r1 = kimi.propose(frozen_manifest=manifest, history_summary=[], seed=101)
    ctrl.propose_candidate(prop_r1["parsed"])
    b_r1 = ctrl.compile_and_bind(
        "cand-r1-underfit", compiler=compiler, live_checkpoint_digest=ckpt_dig, live_runtime_flags_sha256=flags_dig
    )
    ctrl.evaluate(
        "cand-r1-underfit",
        runtime=runtime,
        live_adapter_sha256=b_r1["candidate_adapter_sha256"],
        live_checkpoint_digest=ckpt_dig,
    )
    v_r1 = ctrl.promote_or_reject("cand-r1-underfit")
    _require(v_r1["verdict"] == "REJECTED", f"expected R1 REJECTED, got {v_r1}")

    # 4D. Round 2 (Kimi diagnose -> bounded repair -> compile/hash -> evaluate -> PROMOTED -> full multi-bank rollback)
    diag_r2 = kimi.diagnose(
        frozen_manifest=manifest,
        failure_report={"candidate_id": "cand-r1-underfit", "failures": v_r1["failures"]},
        remaining_rounds=2,
        seed=102,
    )
    ctrl.propose_candidate(diag_r2["parsed"]["repair_proposal"])
    b_r2 = ctrl.compile_and_bind(
        "cand-r2-repaired", compiler=compiler, live_checkpoint_digest=ckpt_dig, live_runtime_flags_sha256=flags_dig
    )
    ctrl.evaluate(
        "cand-r2-repaired",
        runtime=runtime,
        live_adapter_sha256=b_r2["candidate_adapter_sha256"],
        live_checkpoint_digest=ckpt_dig,
    )
    cmp_r2 = kimi.compare(
        case_id="repaired-01",
        baseline_text="Baseline answer text.",
        adapted_text="Improved adapted answer text.",
        seed=202,
    )
    v_r2 = ctrl.promote_or_reject("cand-r2-repaired", judge_comparison=cmp_r2["parsed"])
    _require(v_r2["verdict"] == "PROMOTED", f"expected R2 PROMOTED, got {v_r2}")
    # 5. Adversarial Trust-Boundary Matrix (Issue #7)
    adversarial: dict[str, str] = {}

    def _capture_err(label: str, fn) -> None:
        try:
            fn()
        except (ec.ExperimentContractError, bc.ControllerError) as exc:
            adversarial[label] = exc.code
            return
        raise RuntimeError(f"adversarial control failed to reject: {label}")

    # Test incomplete/kv-only rollback refusals while cand-r2-repaired is Promoted (before valid rollback transitions it to RolledBack)
    _capture_err(
        "kv_only_rollback_omitting_checkpoint_banks_rejected",
        lambda: ctrl.rollback(
            "cand-r2-repaired",
            runtime=runtime,
            expected_state_banks=("kv_cache",),
        ),
    )
    runtime.fail_lattice_flush = True
    _capture_err(
        "incomplete_multibank_lattice_flush_rejected",
        lambda: ctrl.rollback(
            "cand-r2-repaired",
            runtime=runtime,
            expected_state_banks=("kv_cache", "ssm_recurrent", "lattice_horizontal_streams"),
        ),
    )
    runtime.fail_lattice_flush = False

    rb_r2 = ctrl.rollback(
        "cand-r2-repaired",
        runtime=runtime,
        reason="issue7_verified_full_multibank_rollback",
        expected_state_banks=("kv_cache", "ssm_recurrent", "lattice_horizontal_streams"),
    )
    _require(rb_r2["baseline_logits_restored"] is True, "expected exact rollback restore")
    _require(
        ctrl.candidate_state("cand-r2-repaired")["phase"] == "RolledBack",
        "rollback must transition candidate phase to RolledBack",
    )
    _require(
        rb_r2["receipt"]["payload"]["prior_phase"] == "Promoted",
        "rollback receipt must record prior_phase == Promoted",
    )
    _capture_err(
        "second_rollback_from_rolledback_rejected",
        lambda: ctrl.rollback("cand-r2-repaired", runtime=runtime),
    )
    _capture_err(
        "rollback_from_rejected_phase_rejected",
        lambda: ctrl.rollback("cand-r1-underfit", runtime=runtime),
    )
    _capture_err(
        "egress_unbounded_int_smuggling_rejected",
        lambda: kimi.diagnose(
            frozen_manifest=manifest,
            failure_report={"repair_round": int.from_bytes(b"SECRET-LORA-BYTES\x00\xff", "big")},
            remaining_rounds=1,
        ),
    )

    _capture_err(
        "missing_contract_sha256_rejected",
        lambda: ctrl.propose_candidate(
            {
                "candidate_id": "adv-no-sha",
                "repair_round": 3,
                "target_layer": "blk.31",
                "rank": 8,
                "strength_num": 10,
                "strength_den": 10,
                "quantization": "f16",
                "seed": 9,
            }
        ),
    )
    _capture_err(
        "raw_lora_override_rejected",
        lambda: ctrl.propose_candidate(
            {
                "candidate_id": "adv-lora",
                "contract_sha256": manifest["manifest_sha256"],
                "repair_round": 3,
                "target_layer": "blk.31",
                "rank": 8,
                "strength_num": 10,
                "strength_den": 10,
                "quantization": "f16",
                "seed": 9,
                "lora": [{"id": 0, "scale": 1.0}],
            }
        ),
    )
    _capture_err(
        "nested_case_insensitive_ring0_override_rejected",
        lambda: ec.verify_ring0_immutability(
            manifest, {"LORA": [], "nested": {"thresholds_override": [0, 1]}}
        ),
    )
    _capture_err(
        "trailing_newline_digest_and_layer_rejected",
        lambda: ec.require_sha256(("a" * 64) + "\n", "sha"),
    )
    _capture_err(
        "unsupported_layer_blk12_rejected",
        lambda: ctrl.propose_candidate(
            {
                "candidate_id": "adv-layer",
                "contract_sha256": manifest["manifest_sha256"],
                "repair_round": 3,
                "target_layer": "blk.12",
                "rank": 8,
                "strength_num": 10,
                "strength_den": 10,
                "quantization": "f16",
                "seed": 9,
            }
        ),
    )
    _capture_err(
        "duplicate_repair_round1_replay_rejected",
        lambda: ctrl.propose_candidate(
            {
                "candidate_id": "adv-dup-r1",
                "contract_sha256": manifest["manifest_sha256"],
                "repair_round": 1,
                "target_layer": "blk.31",
                "rank": 8,
                "strength_num": 10,
                "strength_den": 10,
                "quantization": "f16",
                "seed": 9,
            }
        ),
    )
    _capture_err(
        "repair_round_4_budget_exceeded",
        lambda: ctrl.propose_candidate(
            {
                "candidate_id": "adv-r4",
                "contract_sha256": manifest["manifest_sha256"],
                "repair_round": 4,
                "target_layer": "blk.31",
                "rank": 8,
                "strength_num": 10,
                "strength_den": 10,
                "quantization": "f16",
                "seed": 9,
            }
        ),
    )
    _capture_err(
        "ring0_threshold_mutation_rejected",
        lambda: ctrl.propose_candidate(
            {
                "candidate_id": "adv-ring0",
                "contract_sha256": manifest["manifest_sha256"],
                "repair_round": 3,
                "target_layer": "blk.31",
                "rank": 8,
                "strength_num": 10,
                "strength_den": 10,
                "quantization": "f16",
                "seed": 9,
                "frozen_thresholds": {"min_task_exact_gain": [0, 1]},
            }
        ),
    )

    ctrl.propose_candidate(
        {
            "candidate_id": "adv-drift-cand",
            "contract_sha256": manifest["manifest_sha256"],
            "repair_round": 3,
            "target_layer": "blk.31",
            "rank": 8,
            "strength_num": 10,
            "strength_den": 10,
            "quantization": "f16",
            "seed": 99,
        }
    )
    _capture_err(
        "eval_before_hash_recorded_rejected",
        lambda: ctrl.evaluate(
            "adv-drift-cand",
            runtime=runtime,
            live_adapter_sha256=_sha("unrecorded"),
            live_checkpoint_digest=ckpt_dig,
        ),
    )
    _capture_err(
        "checkpoint_drift_rejected_before_compile",
        lambda: ctrl.compile_and_bind(
            "adv-drift-cand",
            compiler=compiler,
            live_checkpoint_digest=_sha("drifted-checkpoint"),
            live_runtime_flags_sha256=flags_dig,
        ),
    )
    b_adv = ctrl.compile_and_bind(
        "adv-drift-cand", compiler=compiler, live_checkpoint_digest=ckpt_dig, live_runtime_flags_sha256=flags_dig
    )
    _capture_err(
        "adapter_hash_drift_rejected_before_eval",
        lambda: ctrl.evaluate(
            "adv-drift-cand",
            runtime=runtime,
            live_adapter_sha256=_sha("tampered-adapter-bytes"),
            live_checkpoint_digest=ckpt_dig,
        ),
    )
    _ = b_adv

    _capture_err(
        "unhashed_extra_receipt_key_rejected",
        lambda: bc.verify_receipt_chain_independent(
            [dict(ledger.records[0], forged_verdict="PROMOTED")],
            secret_key=resolved_key,
            key_id="warp-exp-hmac-v1",
        ),
    )

    # CTRL-BYPASS-6 closure: regressed_control with passing metrics can NEVER promote!
    ctrl.propose_candidate(
        {
            "candidate_id": "adv-regressed-ctrl-passing",
            "contract_sha256": manifest["manifest_sha256"],
            "control_role": "regressed_control",
            "repair_round": 0,
            "target_layer": "blk.31",
            "rank": 8,
            "strength_num": 10,
            "strength_den": 10,
            "quantization": "f16",
            "seed": 77,
        }
    )
    b_ctrl_pass = ctrl.compile_and_bind(
        "adv-regressed-ctrl-passing",
        compiler=compiler,
        live_checkpoint_digest=ckpt_dig,
        live_runtime_flags_sha256=flags_dig,
    )
    ctrl.evaluate(
        "adv-regressed-ctrl-passing",
        runtime=runtime,
        live_adapter_sha256=b_ctrl_pass["candidate_adapter_sha256"],
        live_checkpoint_digest=ckpt_dig,
    )
    v_ctrl_pass = ctrl.promote_or_reject("adv-regressed-ctrl-passing")
    _require(
        v_ctrl_pass["verdict"] == "REJECTED" and "control_role_cannot_promote" in v_ctrl_pass["failures"],
        f"regressed_control with passing metrics must never promote: {v_ctrl_pass}",
    )
    adversarial["regressed_control_passing_metrics_blocked_from_promote"] = "control_role_cannot_promote"

    _capture_err(
        "cerebras_weight_egress_blocked",
        lambda: bc.sanitize_outbound_payload({"prompt": "hi", "weights": [1, 2, 3]}),
    )
    transport.mode = "substitute_model"
    _capture_err(
        "cerebras_silent_model_substitution_rejected",
        lambda: kimi.compare(case_id="c-sub", baseline_text="a", adapted_text="b", seed=301),
    )
    transport.mode = "malformed_json"
    _capture_err(
        "cerebras_duplicate_json_key_rejected",
        lambda: kimi.compare(case_id="c-dup", baseline_text="a", adapted_text="b", seed=302),
    )
    _require(
        kimi.receipts[-1]["status"] == "rejected"
        and kimi.receipts[-1]["error_code"] == "ERR_MALFORMED_ADVISORY_RESPONSE",
        "malformed JSON must record rejected receipt",
    )
    transport.mode = "timeout"
    _capture_err(
        "cerebras_transport_timeout_recorded",
        lambda: kimi.compare(case_id="c-to", baseline_text="a", adapted_text="b", seed=303),
    )
    transport.mode = "normal"

    # 6. Independent verification of append-only HMAC receipt chain + hash-before-eval audit
    chain_ver = bc.verify_receipt_chain_independent(ledger.records, secret_key=resolved_key, key_id="warp-exp-hmac-v1")
    cerebras_ms_total = sum(r["latency_ms"] for r in kimi.receipts if r["status"] == "ok")
    compile_ms_total = sum(
        r["payload"]["compile_ms"] for r in ledger.records if r["operation"] == "compile_and_bind"
    )
    local_eval_ms_total = sum(
        r["payload"]["local_eval_ms"] for r in ledger.records if r["operation"] == "evaluate"
    )
    deploy_rollback_ms_total = sum(
        r["payload"]["deploy_rollback_ms"] for r in ledger.records if r["operation"] == "rollback"
    )
    timings = {
        **bc.build_separated_timings(
            cerebras_ms=cerebras_ms_total,
            compile_ms=compile_ms_total,
            local_eval_ms=local_eval_ms_total,
            deploy_rollback_ms=deploy_rollback_ms_total,
        ),
        "timing_source": "aggregated_from_mock_ledger_receipts_not_wall_clock",
    }

    warp_compat = (
        {"checked_live_repo": False, "mode": "standalone_forced"}
        if standalone
        else _check_live_warp_drive_compat(manifest, b_r2["candidate_adapter_sha256"], IN_REPO_ROOT)
    )

    payload: dict[str, Any] = {
        "audit_id": "AUDIT-063",
        "arm": "R6-3",
        "interface_class": bc.INTERFACE_CLASS,
        "oracle_class": "exact+anchor",
        "honest_novelty_class": "N1",
        "evidence_boundary_disclosure": {
            "controller_runtime_mode": "logic_check_fake_runtime",
            "cerebras_transport_mode": "mock_contract",
            "live_credentials_used": False,
            "live_rtx3080_checkpoint_scored": False,
            "ledger_hmac_scope": "tamper_evidence_only_not_external_secrecy",
            "hmac_key_source": hmac_key_source,
        },
        "part1_issue4_frozen_contract": {
            "manifest_sha256": manifest["manifest_sha256"],
            "harness_label": manifest["harness_label"],
            "compiler_repo": manifest["compiler_repo"],
            "target_layer": manifest["target_layer"],
            "max_repair_rounds": manifest["max_repair_rounds"],
            "frozen_ext_roundtrip_preserved": roundtrip["future_ext_note"] == "unknown_field_preserved_under_frozen_v1",
            "leaky_98pct_split_audit": leaky_audit,
            "family_separated_split_audit": clean_audit,
        },
        "part2_reconciler_and_clock_invariants": {
            "monotone_385_lattice": lattice_cert,
            "affine_clock_pair_exact": str(t_mapped),
            "separated_timings": timings,
        },
        "part3_issue5_controller_lifecycle": {
            "unchanged_base_verdict": v_base["verdict"],
            "regressed_plausible_verdict": v_reg["verdict"],
            "regressed_plausible_failures": v_reg["failures"],
            "round1_underfit_verdict": v_r1["verdict"],
            "round2_repaired_verdict": v_r2["verdict"],
            "round2_adapter_sha256": b_r2["candidate_adapter_sha256"],
            "round2_rollback_logits_restored": rb_r2["baseline_logits_restored"],
            "round2_post_rollback_phase": ctrl.candidate_state("cand-r2-repaired")["phase"],
            "ledger_independent_verification": chain_ver,
        },
        "part4_issue6_cerebras_kimi_boundary": {
            "total_receipts": len(kimi.receipts),
            "ok_receipts": sum(1 for r in kimi.receipts if r["status"] == "ok"),
            "rejected_or_error_receipts": sum(1 for r in kimi.receipts if r["status"] != "ok"),
            "sample_redacted_receipt": kimi.receipts[0],
        },
        "part5_issue7_adversarial_matrix": adversarial,
        "part6_warp_drive_live_compatibility": warp_compat,
    }
    ec.verify_no_floats(payload)
    payload["canonical_sha256"] = ec.sha256_canonical(payload)
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="AUDIT-063 exact bounded controller & contract verifier.")
    parser.add_argument("--json", action="store_true", help="Emit canonical sorted JSON (default).")
    parser.add_argument("--standalone", action="store_true", help="Skip live warp-drive repo import check.")
    args = parser.parse_args(argv)
    res = run_all(standalone=args.standalone)
    print(json.dumps(res, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
