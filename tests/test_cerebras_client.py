"""Lane 6 tests: Cerebras Kimi K3.1 Pro client, schema validation, receipts.

All provider calls run against the local mock server. Nothing here touches
the live Cerebras API, a GPU, or a checkpoint. Mock results are logic
checks, never model evidence.
"""

from __future__ import annotations

import unittest

from warp_modeld.cerebras_client import (
    DEFAULT_MODEL_ID,
    CerebrasKimiClient,
    validate_candidate,
    validate_comparison_inputs,
    validate_failure_report,
    validate_propose_context,
)
from warp_modeld.cerebras_prompts import (
    FIXED_PROMPT_FIXTURES,
    PROMPT_SET_VERSION,
    build_diagnose_messages,
    build_propose_messages,
    prompt_sha256,
)
from warp_modeld.errors import (
    CerebrasClientError,
    CerebrasCredentialsMissingError,
    CerebrasSchemaError,
    CerebrasTransportError,
)

from tests.mock_cerebras_server import MockCerebrasServer

API_KEY = "test-key-that-is-not-real"


def valid_candidate() -> dict[str, object]:
    return {"target_layer": "last", "strength": 0.5, "rank": 16, "quantization": "q8_0"}


def valid_context() -> dict[str, object]:
    return {
        "task_summary": "improve exact task score without losing retention",
        "baseline_metrics": {"task_exact": 0.61, "retention_iid": 0.88},
    }


def valid_report() -> dict[str, object]:
    return {
        "failed_candidate": {"target_layer": "last", "strength": 0.9, "rank": 32, "quantization": "q4_0"},
        "failed_gate": "retention_iid",
        "measurements": {"task_exact": 0.64, "retention_iid": 0.79},
        "rounds_used": 1,
    }


def make_client(server: MockCerebrasServer, **kwargs: object) -> CerebrasKimiClient:
    kwargs.setdefault("retry_delay_seconds", 0.0)
    return CerebrasKimiClient(API_KEY, base_url=server.base_url, **kwargs)  # type: ignore[arg-type]


class TestCandidateSchema(unittest.TestCase):
    def test_valid_candidate(self) -> None:
        cfg = validate_candidate(valid_candidate())
        self.assertEqual(cfg.to_dict(), valid_candidate())

    def test_strength_bounds(self) -> None:
        for bad in (0, 0.0, -0.1, 1.01, 1.5, "0.5", None, True):
            with self.subTest(bad=bad):
                payload = valid_candidate()
                payload["strength"] = bad
                with self.assertRaises(CerebrasSchemaError):
                    validate_candidate(payload)
        self.assertEqual(validate_candidate({**valid_candidate(), "strength": 1}).strength, 1.0)

    def test_rank_must_be_an_allowed_int(self) -> None:
        for bad in (3, 5, 64, 128, 16.0, "16", True, None):
            with self.subTest(bad=bad):
                payload = valid_candidate()
                payload["rank"] = bad
                with self.assertRaises(CerebrasSchemaError):
                    validate_candidate(payload)

    def test_target_layer_is_pinned_to_last(self) -> None:
        for bad in ("first", "all", "", None, 0):
            with self.subTest(bad=bad):
                payload = valid_candidate()
                payload["target_layer"] = bad
                with self.assertRaises(CerebrasSchemaError):
                    validate_candidate(payload)

    def test_quantization_allowlist(self) -> None:
        for bad in ("fp32", "q4_k_m", "Q8_0", "", None):
            with self.subTest(bad=bad):
                payload = valid_candidate()
                payload["quantization"] = bad
                with self.assertRaises(CerebrasSchemaError):
                    validate_candidate(payload)

    def test_extra_or_missing_keys_rejected(self) -> None:
        payload = valid_candidate()
        payload["scale"] = 0.5
        with self.assertRaises(CerebrasSchemaError):
            validate_candidate(payload)
        payload = valid_candidate()
        del payload["rank"]
        with self.assertRaises(CerebrasSchemaError):
            validate_candidate(payload)
        with self.assertRaises(CerebrasSchemaError):
            validate_candidate([valid_candidate()])


class TestFailureReportSchema(unittest.TestCase):
    def test_valid_report_reports_remaining_budget(self) -> None:
        cleaned = validate_failure_report(valid_report())
        self.assertEqual(cleaned["rounds_remaining"], 2)

    def test_exhausted_budget_rejected(self) -> None:
        report = valid_report()
        report["rounds_used"] = 3
        with self.assertRaises(CerebrasSchemaError):
            validate_failure_report(report)

    def test_bad_gate_and_measurements_rejected(self) -> None:
        report = valid_report()
        report["failed_gate"] = "vibes"
        with self.assertRaises(CerebrasSchemaError):
            validate_failure_report(report)
        report = valid_report()
        report["measurements"] = {"task_exact": float("nan")}
        with self.assertRaises(CerebrasSchemaError):
            validate_failure_report(report)
        report = valid_report()
        report["measurements"] = {}
        with self.assertRaises(CerebrasSchemaError):
            validate_failure_report(report)

    def test_failed_candidate_must_itself_be_valid(self) -> None:
        report = valid_report()
        bad = dict(valid_candidate())
        bad["rank"] = 128
        report["failed_candidate"] = bad
        with self.assertRaises(CerebrasSchemaError):
            validate_failure_report(report)


class TestComparisonInputs(unittest.TestCase):
    def test_valid_inputs(self) -> None:
        cleaned = validate_comparison_inputs(
            baseline_text="base", adapted_text="adapted", task_id="task-1"
        )
        self.assertEqual(cleaned["task_id"], "task-1")

    def test_empty_or_oversized_text_rejected(self) -> None:
        with self.assertRaises(CerebrasSchemaError):
            validate_comparison_inputs(baseline_text=" ", adapted_text="x", task_id="t")
        with self.assertRaises(CerebrasSchemaError):
            validate_comparison_inputs(baseline_text="x" * 4001, adapted_text="x", task_id="t")
        with self.assertRaises(CerebrasSchemaError):
            validate_comparison_inputs(baseline_text="x", adapted_text="x", task_id="")


class TestProposeDiagnoseCompare(unittest.TestCase):
    def test_propose_returns_valid_candidate_and_receipt(self) -> None:
        with MockCerebrasServer("ok_propose") as server:
            client = make_client(server)
            candidate, receipt = client.propose_candidate(valid_context())
        self.assertEqual(
            candidate.to_dict(),
            {"target_layer": "last", "strength": 0.5, "rank": 16, "quantization": "q8_0"},
        )
        self.assertEqual(receipt.call_kind, "propose")
        self.assertEqual(receipt.provider, "cerebras")
        self.assertEqual(receipt.requested_model, DEFAULT_MODEL_ID)
        self.assertEqual(receipt.served_model, "kimi-k3.1-pro")
        self.assertEqual(receipt.prompt_tokens, 120)
        self.assertEqual(receipt.completion_tokens, 25)
        self.assertEqual(receipt.total_tokens, 145)
        self.assertEqual(receipt.retries, 0)
        self.assertEqual(receipt.timeouts, 0)
        self.assertEqual(receipt.status, "ok")
        self.assertEqual(receipt.prompt_set_version, PROMPT_SET_VERSION)
        self.assertEqual(receipt.seed, 42)
        self.assertGreaterEqual(receipt.latency_ms, 0.0)
        self.assertEqual(len(receipt.prompt_sha256), 64)

    def test_diagnose_returns_repair_inside_budget(self) -> None:
        with MockCerebrasServer("ok_diagnose") as server:
            client = make_client(server)
            repair, receipt = client.diagnose_failure(valid_report())
        self.assertEqual(
            repair.to_dict(),
            {"target_layer": "last", "strength": 0.4, "rank": 8, "quantization": "q8_0"},
        )
        self.assertEqual(receipt.call_kind, "diagnose")
        self.assertNotEqual(repair.to_dict(), valid_report()["failed_candidate"])

    def test_diagnose_rejects_repair_that_repeats_failed_candidate(self) -> None:
        report = valid_report()
        report["failed_candidate"] = {
            "target_layer": "last",
            "strength": 0.4,
            "rank": 8,
            "quantization": "q8_0",
        }
        with MockCerebrasServer("ok_diagnose") as server:
            client = make_client(server)
            with self.assertRaises(CerebrasSchemaError):
                client.diagnose_failure(report)

    def test_compare_returns_advisory_verdict(self) -> None:
        with MockCerebrasServer("ok_compare") as server:
            client = make_client(server)
            verdict, receipt = client.compare_outputs(
                baseline_text="The capital of France is Paris.",
                adapted_text="The capital of France is Paris, a city on the Seine.",
                task_id="fixture-task-001",
            )
        self.assertEqual(verdict.preference, "adapted")
        self.assertEqual(verdict.confidence, "medium")
        self.assertEqual(receipt.call_kind, "compare")

    def test_seed_none_sends_no_seed_field(self) -> None:
        with MockCerebrasServer("ok_propose") as server:
            client = make_client(server, seed=None)
            _, receipt = client.propose_candidate(valid_context())
        self.assertIsNone(receipt.seed)
        self.assertNotIn("seed", server.state.requests[-1])


class TestMalformedResponses(unittest.TestCase):
    def test_each_malformed_mode_raises_schema_error(self) -> None:
        for mode in ("malformed_json", "wrong_schema", "non_json_body", "missing_choices", "empty_content"):
            with self.subTest(mode=mode):
                with MockCerebrasServer(mode) as server:
                    client = make_client(server)
                    with self.assertRaises(CerebrasSchemaError) as ctx:
                        client.propose_candidate(valid_context())
                self.assertIn("receipt", str(ctx.exception))

    def test_out_of_bounds_candidate_is_rejected_not_clamped(self) -> None:
        with MockCerebrasServer("invalid_candidate") as server:
            client = make_client(server)
            with self.assertRaises(CerebrasSchemaError):
                client.propose_candidate(valid_context())


class TestTransportFailures(unittest.TestCase):
    def test_http500_retries_then_raises_with_receipt(self) -> None:
        with MockCerebrasServer("http500") as server:
            client = make_client(server, max_retries=1)
            with self.assertRaises(CerebrasTransportError) as ctx:
                client.propose_candidate(valid_context())
        self.assertIn("receipt", str(ctx.exception))
        self.assertEqual(server.state.request_count, 2)

    def test_http429_then_ok_retries_once(self) -> None:
        with MockCerebrasServer("http429_then_ok") as server:
            client = make_client(server, max_retries=2)
            candidate, receipt = client.propose_candidate(valid_context())
        self.assertEqual(candidate.rank, 16)
        self.assertEqual(receipt.retries, 1)
        self.assertEqual(len(receipt.failures), 1)
        self.assertIn("429", receipt.failures[0])

    def test_connection_refused_raises_transport_error(self) -> None:
        client = CerebrasKimiClient(API_KEY, base_url="http://127.0.0.1:1", max_retries=0, retry_delay_seconds=0.0)
        with self.assertRaises(CerebrasTransportError) as ctx:
            client.propose_candidate(valid_context())
        self.assertIn("receipt", str(ctx.exception))

    def test_slow_server_times_out(self) -> None:
        with MockCerebrasServer("slow", slow_seconds=2.0) as server:
            client = make_client(server, timeout_seconds=0.3, max_retries=0)
            with self.assertRaises(CerebrasTransportError) as ctx:
                client.propose_candidate(valid_context())
        self.assertIn("receipt", str(ctx.exception))


class TestReceiptHonesty(unittest.TestCase):
    def test_wrong_served_model_is_recorded_not_substituted(self) -> None:
        with MockCerebrasServer("wrong_model") as server:
            client = make_client(server)
            _, receipt = client.propose_candidate(valid_context())
        self.assertEqual(receipt.requested_model, "kimi-k3.1-pro")
        self.assertEqual(receipt.served_model, "qwen-3.8-27b")

    def test_missing_usage_leaves_token_counts_none(self) -> None:
        with MockCerebrasServer("missing_usage") as server:
            client = make_client(server)
            _, receipt = client.propose_candidate(valid_context())
        self.assertIsNone(receipt.prompt_tokens)
        self.assertIsNone(receipt.completion_tokens)
        self.assertIsNone(receipt.total_tokens)

    def test_receipt_carries_no_key_and_no_prompt_text(self) -> None:
        with MockCerebrasServer("ok_propose") as server:
            client = make_client(server)
            _, receipt = client.propose_candidate(valid_context())
        blob = str(receipt.to_dict())
        self.assertNotIn(API_KEY, blob)
        self.assertNotIn("improve exact task score", blob)
        self.assertNotIn("baseline_metrics", blob)

    def test_non_https_non_localhost_base_url_rejected(self) -> None:
        with self.assertRaises(CerebrasClientError):
            CerebrasKimiClient(API_KEY, base_url="http://api.cerebras.ai/v1")
        with self.assertRaises(CerebrasClientError):
            CerebrasKimiClient(API_KEY, base_url="ftp://example.com")


class TestCredentials(unittest.TestCase):
    def test_missing_key_refuses_to_build(self) -> None:
        with self.assertRaises(CerebrasCredentialsMissingError):
            CerebrasKimiClient("")
        with self.assertRaises(CerebrasCredentialsMissingError):
            CerebrasKimiClient.from_env({})
        with self.assertRaises(CerebrasCredentialsMissingError):
            CerebrasKimiClient.from_env({"CEREBRAS_BASE_URL": "https://api.cerebras.ai/v1"})

    def test_from_env_uses_key_and_model_override(self) -> None:
        client = CerebrasKimiClient.from_env(
            {"CEREBRAS_API_KEY": "env-key", "CEREBRAS_MODEL_ID": "dedicated-endpoint-123"}
        )
        self.assertEqual(client.model_id, "dedicated-endpoint-123")


class TestFixedPromptFixtures(unittest.TestCase):
    def test_fixture_set_covers_all_three_calls(self) -> None:
        kinds = sorted(f["kind"] for f in FIXED_PROMPT_FIXTURES)
        self.assertEqual(kinds, ["compare", "diagnose", "propose"])

    def test_prompt_hash_is_stable_across_builds(self) -> None:
        context_json = '{"baseline_metrics": {"task_exact": 0.61}}'
        first = prompt_sha256(build_propose_messages(context_json))
        second = prompt_sha256(build_propose_messages(context_json))
        self.assertEqual(first, second)
        self.assertEqual(len(first), 64)

    def test_prompts_carry_no_weights_or_private_data(self) -> None:
        messages = build_propose_messages('{"baseline_metrics": {"task_exact": 0.61}}')
        blob = str(messages)
        self.assertNotIn("sk-", blob)
        self.assertNotIn(".gguf", blob)
        self.assertNotIn("/" + "home/", blob)
        report_messages = build_diagnose_messages('{"failed_gate": "task"}')
        self.assertNotIn(".gguf", str(report_messages))

    def test_propose_context_rejects_unknown_keys(self) -> None:
        with self.assertRaises(CerebrasSchemaError):
            validate_propose_context({**valid_context(), "checkpoint_path": "/tmp/model.gguf"})


if __name__ == "__main__":
    unittest.main()
