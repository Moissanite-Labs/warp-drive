#!/usr/bin/env python3
"""Independent executable adversarial probes for PR 13 head 1ffda956.

Uses only synthetic compiler/runtime/provider fakes. No weights or live provider evidence.
"""
from __future__ import annotations

import copy
import hashlib
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parent
STUDY = ROOT / "repo" / "studies" / "expedition-bounded-controller"
sys.path.insert(0, str(STUDY))

import bounded_controller as bc  # noqa: E402
import experiment_contract as ec  # noqa: E402
import verify_bounded_controller as fixtures  # noqa: E402

KEY = b"independent-review-key-32-bytes"
FORGED_ADAPTER_SHA = hashlib.sha256(b"post-evaluation-forgery").hexdigest()


def make_case():
    train, heldout, _ = fixtures.build_reference_splits()
    manifest = fixtures.build_reference_manifest(train, heldout)
    ledger = bc.SignedExperimentLedger(KEY)
    controller = bc.BoundedExperimentController(manifest, ledger)
    proposal = {
        "candidate_id": "review-candidate",
        "contract_sha256": manifest["manifest_sha256"],
        "control_role": "candidate",
        "repair_round": 1,
        "target_layer": "blk.31",
        "rank": 8,
        "strength_num": 10,
        "strength_den": 10,
        "quantization": "f16",
        "seed": 7,
    }
    controller.propose_candidate(proposal)
    return manifest, ledger, controller


def metrics(task_gain=None):
    return {
        "task_exact_gain": [0, 1] if task_gain is None else task_gain,
        "logprob_margin_delta": [9, 10],
        "iid_retention_drop": [0, 1],
        "shifted_retention_drop": [0, 1],
        "safety_canary_pass_rate": [1, 1],
        "residual_movement_before": [10, 1],
        "residual_movement_after": [10, 1],
        "unrelated_kl_before_milli": 10,
        "unrelated_kl_after_milli": 10,
        "text_plausible": True,
        "local_eval_ms": 1,
    }


class GoodCompiler:
    is_mock = True

    def compile_candidate(self, *, manifest, proposal):
        return {
            "candidate_adapter_sha256": hashlib.sha256(b"bound-before-evaluation").hexdigest(),
            "compile_ms": 1,
            "compiler_commit": manifest["compiler_commit"],
        }


class PolicyMutatingCompiler(GoodCompiler):
    def compile_candidate(self, *, manifest, proposal):
        # Adapter receives the live nested policy mapping, not a frozen snapshot.
        manifest["frozen_thresholds"]["min_task_exact_gain"] = [-100, 1]
        return super().compile_candidate(manifest=manifest, proposal=proposal)


class FakeRuntime:
    is_mock = True

    def __init__(self, result=None):
        self.result = metrics() if result is None else result
        self.evaluate_calls = 0
        self.rollback_result = {
            "banks_flushed": ["kv_cache", "ssm_recurrent", "lattice_horizontal_streams"],
            "baseline_logit_diff_milli": 0,
            "deploy_rollback_ms": 1,
        }

    def evaluate_candidate(self, *, manifest, candidate_record):
        self.evaluate_calls += 1
        return copy.deepcopy(self.result)

    def rollback_and_flush(self, *, required_state_banks, reason):
        return copy.deepcopy(self.rollback_result)


class HashMutatingRuntime(FakeRuntime):
    def evaluate_candidate(self, *, manifest, candidate_record):
        self.evaluate_calls += 1
        # Mutation occurs after compile_and_bind checked and receipted the hash.
        candidate_record["candidate_adapter_sha256"] = FORGED_ADAPTER_SHA
        return copy.deepcopy(self.result)


class RawResponseTransport:
    transport_mode = "mock_contract"
    live_credentials_used = False

    def __init__(self, content='{"diagnosis":"x","repair_proposal":{}}', **metadata):
        self.content = content
        self.metadata = metadata
        self.requests = []

    def call(self, request):
        self.requests.append(copy.deepcopy(request))
        response = {
            "status": "ok",
            "served_model": "kimi-k3.1-pro",
            "prompt_tokens": 1,
            "completion_tokens": 1,
            "latency_ms": 1,
            "content_json": self.content,
        }
        response.update(self.metadata)
        return response


class AdversarialReview(unittest.TestCase):
    def test_01_pre_evaluation_hash_survives_runtime_callback(self):
        manifest, ledger, ctrl = make_case()
        bound = ctrl.compile_and_bind(
            "review-candidate",
            compiler=GoodCompiler(),
            live_checkpoint_digest=ctrl.base_checkpoint_digest,
            live_runtime_flags_sha256=manifest["runtime_flags_sha256"],
        )["candidate_adapter_sha256"]
        evaluated = ctrl.evaluate(
            "review-candidate",
            runtime=HashMutatingRuntime(metrics([3, 40])),
            live_adapter_sha256=bound,
            live_checkpoint_digest=ctrl.base_checkpoint_digest,
        )
        verdict = ctrl.promote_or_reject("review-candidate")["verdict"]
        chain = bc.verify_receipt_chain_independent(ledger.records, secret_key=KEY)
        self.assertEqual(
            bound,
            evaluated["evaluation"]["candidate_adapter_sha256"],
            f"post-eval hash replaced bound hash; verdict={verdict}, valid_signed_chain={chain}",
        )

    def test_02_compiler_cannot_change_frozen_acceptance_policy(self):
        manifest, _, ctrl = make_case()
        original_policy_sha = manifest["manifest_sha256"]
        ctrl.compile_and_bind(
            "review-candidate",
            compiler=PolicyMutatingCompiler(),
            live_checkpoint_digest=ctrl.base_checkpoint_digest,
            live_runtime_flags_sha256=manifest["runtime_flags_sha256"],
        )
        bound = ctrl.candidate_state("review-candidate")["candidate_adapter_sha256"]
        ctrl.evaluate(
            "review-candidate",
            runtime=FakeRuntime(metrics([0, 1])),
            live_adapter_sha256=bound,
            live_checkpoint_digest=ctrl.base_checkpoint_digest,
        )
        verdict = ctrl.promote_or_reject("review-candidate")["verdict"]
        self.assertEqual(
            "REJECTED",
            verdict,
            f"0 task gain promoted after policy mutation; stored sha={original_policy_sha}, "
            f"recomputed={ec.compute_manifest_sha256(manifest)}, "
            f"live threshold={manifest['frozen_thresholds']['min_task_exact_gain']}",
        )

    def test_03_provider_egress_rejects_raw_adapter_alias(self):
        transport = RawResponseTransport()
        client = bc.CerebrasKimiAdvisoryClient(transport)
        manifest = fixtures.build_reference_manifest(*fixtures.build_reference_splits()[:2])
        try:
            client.diagnose(
                frozen_manifest=manifest,
                failure_report={"adapter": [0, 1, 2, 255], "repair_round": 1},
                remaining_rounds=1,
            )
        except bc.ControllerError as exc:
            self.assertEqual("ERR_EGRESS_POLICY_VIOLATION", exc.code)
        else:
            self.fail(f"synthetic raw adapter bytes reached transport: {transport.requests[0]['payload']}")
        self.assertEqual([], transport.requests)

    def test_04_malformed_provider_metadata_records_rejected_receipt(self):
        transport = RawResponseTransport(prompt_tokens="not-an-integer")
        client = bc.CerebrasKimiAdvisoryClient(transport)
        with self.assertRaises((bc.ControllerError, ec.ExperimentContractError)):
            client.compare(case_id="metadata", baseline_text="a", adapted_text="b")
        self.assertEqual(1, len(client.receipts), "metadata validation escaped before receipt recording")
        self.assertEqual("rejected", client.receipts[0]["status"])

    def test_05_nested_duplicate_provider_json_fails_closed_with_receipt(self):
        transport = RawResponseTransport(content='{"outer":{"advisory_vote":"BETTER","advisory_vote":"WORSE"}}')
        client = bc.CerebrasKimiAdvisoryClient(transport)
        with self.assertRaises(bc.ControllerError) as caught:
            client.compare(case_id="dupe", baseline_text="a", adapted_text="b")
        self.assertEqual("ERR_MALFORMED_ADVISORY_RESPONSE", caught.exception.code)
        self.assertEqual("rejected", client.receipts[-1]["status"])

    def test_06_live_adapter_mismatch_rejected_before_runtime(self):
        manifest, _, ctrl = make_case()
        bound = ctrl.compile_and_bind(
            "review-candidate",
            compiler=GoodCompiler(),
            live_checkpoint_digest=ctrl.base_checkpoint_digest,
            live_runtime_flags_sha256=manifest["runtime_flags_sha256"],
        )["candidate_adapter_sha256"]
        runtime = FakeRuntime()
        with self.assertRaises(bc.ControllerError) as caught:
            ctrl.evaluate(
                "review-candidate",
                runtime=runtime,
                live_adapter_sha256=FORGED_ADAPTER_SHA,
                live_checkpoint_digest=ctrl.base_checkpoint_digest,
            )
        self.assertEqual("ERR_ADAPTER_HASH_DRIFT", caught.exception.code)
        self.assertEqual(0, runtime.evaluate_calls)

    def test_07_multibank_rollback_rejects_missing_lattice_flush(self):
        _, _, ctrl = make_case()
        runtime = FakeRuntime()
        runtime.rollback_result["banks_flushed"] = ["kv_cache", "ssm_recurrent"]
        with self.assertRaises(bc.ControllerError) as caught:
            ctrl.rollback("review-candidate", runtime=runtime)
        self.assertEqual("ERR_STATE_FLUSH_INCOMPLETE", caught.exception.code)


if __name__ == "__main__":
    unittest.main(verbosity=2)
