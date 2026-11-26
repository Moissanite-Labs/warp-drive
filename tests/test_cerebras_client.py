"""Lane 6 tests: Cerebras Kimi K3.1 Pro client, schema validation, receipts.

All provider calls run against the local mock server. Nothing here touches
the live Cerebras API, a GPU, or a checkpoint. Mock results are logic
checks, never model evidence.
"""

from __future__ import annotations

import io
import json
import unittest
import urllib.error
from unittest import mock

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
    return {
        "target_layer": 31,
        "target_tensor": "ffn_up",
        "eta": 0.01,
        "lambda": 1,
        "rank": 8,
        "lora_scale": 1.0,
        "quantization": "bf16",
    }


def valid_context() -> dict[str, object]:
    return {
        "task_summary": "improve exact task score without losing retention",
        "baseline_metrics": {"task_exact": 0.61, "retention_iid": 0.88},
    }


def valid_report() -> dict[str, object]:
    return {
        "failed_candidate": {
            "target_layer": 31,
            "target_tensor": "ffn_up",
            "eta": 0.02,
            "lambda": 10,
            "rank": 8,
            "lora_scale": 1.0,
            "quantization": "int4",
        },
        "failed_gate": "retention_iid",
        "measurements": {"task_exact": 0.64, "retention_iid": 0.79},
        "rounds_used": 1,
    }


def receipt_from_exception(exc: BaseException) -> dict:
    """Parse the receipt JSON out of a transport error message."""
    text = str(exc)
    marker = " (receipt: "
    start = text.index(marker) + len(marker)
    return json.loads(text[start:-1])


def make_client(server: MockCerebrasServer, **kwargs: object) -> CerebrasKimiClient:
    kwargs.setdefault("retry_delay_seconds", 0.0)
    return CerebrasKimiClient(API_KEY, base_url=server.base_url, **kwargs)  # type: ignore[arg-type]


def propose_with_served_model(served_model: object, **client_kwargs: object) -> CerebrasKimiClient:
    """Run one propose call against a patched HTTP layer that serves ``served_model``.

    Raises whatever the client raises. No socket is opened.
    """
    raw = json.dumps(
        {
            "id": "chatcmpl-patched",
            "model": served_model,
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": json.dumps(valid_candidate(), separators=(",", ":")),
                    },
                    "finish_reason": "stop",
                }
            ],
        }
    ).encode("utf-8")

    class _FakeResp:
        def __enter__(self) -> "_FakeResp":
            return self

        def __exit__(self, *args: object) -> bool:
            return False

        def read(self) -> bytes:
            return raw

    client = CerebrasKimiClient(API_KEY, base_url="http://127.0.0.1:1/v1", **client_kwargs)  # type: ignore[arg-type]
    with mock.patch("warp_modeld.cerebras_client.urllib.request.urlopen", return_value=_FakeResp()):
        client.propose_candidate(valid_context())
    return client


class TestCandidateSchema(unittest.TestCase):
    def test_valid_candidate(self) -> None:
        cfg = validate_candidate(valid_candidate())
        self.assertEqual(cfg.to_dict(), valid_candidate())
        self.assertEqual(cfg.to_controller_dict()["quant"], "bf16")

    def test_eta_bounds(self) -> None:
        for bad in (0, 0.0, -0.01, 0.0019, 0.0201, 1.0, "0.01", None, True, float("nan"), float("inf")):
            with self.subTest(bad=bad):
                payload = valid_candidate()
                payload["eta"] = bad
                with self.assertRaises(CerebrasSchemaError):
                    validate_candidate(payload)
        self.assertEqual(validate_candidate({**valid_candidate(), "eta": 0.002}).eta, 0.002)
        self.assertEqual(validate_candidate({**valid_candidate(), "eta": 0.02}).eta, 0.02)

    def test_lambda_allowlist(self) -> None:
        for good, expected in ((0.1, 0.1), (1, 1), (1.0, 1), (10, 10), (10.0, 10), ("mean_eigenvalue", "mean_eigenvalue")):
            with self.subTest(good=good):
                self.assertEqual(validate_candidate({**valid_candidate(), "lambda": good}).lam, expected)
        for bad in (0, 0.5, 7, -1, "median", "1", None, True, False, float("nan"), float("inf")):
            with self.subTest(bad=bad):
                payload = valid_candidate()
                payload["lambda"] = bad
                with self.assertRaises(CerebrasSchemaError):
                    validate_candidate(payload)

    def test_lora_scale_allowlist(self) -> None:
        for good in (0, 0.0, 1, 1.0):
            with self.subTest(good=good):
                self.assertEqual(validate_candidate({**valid_candidate(), "lora_scale": good}).lora_scale, float(good))
        for bad in (-1.0, 0.5, 2.0, "1.0", None, True, False, float("nan"), float("inf")):
            with self.subTest(bad=bad):
                payload = valid_candidate()
                payload["lora_scale"] = bad
                with self.assertRaises(CerebrasSchemaError):
                    validate_candidate(payload)

    def test_rank_must_be_frozen_rank_8(self) -> None:
        for bad in (3, 4, 16, 32, 64, 128, 8.0, "8", True, None):
            with self.subTest(bad=bad):
                payload = valid_candidate()
                payload["rank"] = bad
                with self.assertRaises(CerebrasSchemaError):
                    validate_candidate(payload)

    def test_target_layer_and_tensor_are_pinned(self) -> None:
        for bad in ("last", "first", "all", "", None, 0, 30, 31.0, True):
            with self.subTest(bad=bad):
                payload = valid_candidate()
                payload["target_layer"] = bad
                with self.assertRaises(CerebrasSchemaError):
                    validate_candidate(payload)
        for bad in ("ffn_down", "attn_q", "", None, 31):
            with self.subTest(bad=bad):
                payload = valid_candidate()
                payload["target_tensor"] = bad
                with self.assertRaises(CerebrasSchemaError):
                    validate_candidate(payload)

    def test_quantization_allowlist(self) -> None:
        for good in ("bf16", "f16", "f32", "int8", "int4"):
            with self.subTest(good=good):
                self.assertEqual(validate_candidate({**valid_candidate(), "quantization": good}).quantization, good)
        for bad in ("q8_0", "q4_0", "fp32", "q4_k_m", "BF16", "", None, 16):
            with self.subTest(bad=bad):
                payload = valid_candidate()
                payload["quantization"] = bad
                with self.assertRaises(CerebrasSchemaError):
                    validate_candidate(payload)

    def test_extra_or_missing_keys_rejected(self) -> None:
        payload = valid_candidate()
        payload["strength"] = 0.5
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
            {
                "target_layer": 31,
                "target_tensor": "ffn_up",
                "eta": 0.01,
                "lambda": 1,
                "rank": 8,
                "lora_scale": 1.0,
                "quantization": "bf16",
            },
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
            {
                "target_layer": 31,
                "target_tensor": "ffn_up",
                "eta": 0.005,
                "lambda": "mean_eigenvalue",
                "rank": 8,
                "lora_scale": 1.0,
                "quantization": "f16",
            },
        )
        self.assertEqual(receipt.call_kind, "diagnose")
        self.assertNotEqual(repair.to_dict(), valid_report()["failed_candidate"])

    def test_diagnose_rejects_repair_that_repeats_failed_candidate(self) -> None:
        report = valid_report()
        report["failed_candidate"] = {
            "target_layer": 31,
            "target_tensor": "ffn_up",
            "eta": 0.005,
            "lambda": "mean_eigenvalue",
            "rank": 8,
            "lora_scale": 1.0,
            "quantization": "f16",
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
        self.assertEqual(candidate.rank, 8)
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

    def test_http_error_receipt_redacts_key_and_pii(self) -> None:
        body = b"fake-key user@example.invalid private-text"
        error = urllib.error.HTTPError(
            "http://127.0.0.1/v1/chat/completions",
            400,
            "Bad Request",
            {},
            io.BytesIO(body),
        )
        with mock.patch("urllib.request.urlopen", side_effect=error):
            client = CerebrasKimiClient(
                API_KEY, base_url="http://127.0.0.1:1", max_retries=0, retry_delay_seconds=0.0
            )
            with self.assertRaises(CerebrasTransportError) as ctx:
                client.propose_candidate(valid_context())
        text = str(ctx.exception)
        self.assertNotIn("fake-key", text)
        self.assertNotIn("user@example.invalid", text)
        self.assertNotIn("private-text", text)
        self.assertIn("HTTP 400", text)
        receipt = receipt_from_exception(ctx.exception)
        self.assertEqual(receipt["failures"], ["HTTP 400"])

    def test_wrapped_timeouts_count_every_attempt_within_retry_budget(self) -> None:
        calls: list[int] = []

        def flaky(*args: object, **kwargs: object) -> object:
            calls.append(1)
            raise urllib.error.URLError(TimeoutError("timed out"))

        with mock.patch("urllib.request.urlopen", side_effect=flaky):
            client = CerebrasKimiClient(
                API_KEY, base_url="http://127.0.0.1:1", max_retries=2, retry_delay_seconds=0.0
            )
            with self.assertRaises(CerebrasTransportError) as ctx:
                client.propose_candidate(valid_context())
        receipt = receipt_from_exception(ctx.exception)
        self.assertEqual(len(calls), 3)
        self.assertEqual(receipt["retries"], 2)
        self.assertEqual(receipt["timeouts"], 3)

    def test_oversized_integer_is_schema_error_not_numeric_crash(self) -> None:
        huge = 10**10000
        for field_name in ("target_layer", "eta", "lambda", "rank", "lora_scale"):
            with self.subTest(field_name=field_name):
                payload = valid_candidate()
                payload[field_name] = huge
                with self.assertRaises(CerebrasSchemaError) as ctx:
                    validate_candidate(payload)
                self.assertLess(len(str(ctx.exception)), 500)


class TestReceiptHonesty(unittest.TestCase):
    def test_wrong_served_model_is_rejected_with_substitution_code_and_receipt(self) -> None:
        with MockCerebrasServer("wrong_model") as server:
            client = make_client(server)
            with self.assertRaises(CerebrasSchemaError) as ctx:
                client.propose_candidate(valid_context())
        self.assertEqual(ctx.exception.code, "ERR_CEREBRAS_MODEL_SUBSTITUTION")
        msg = str(ctx.exception)
        self.assertIn("ERR_CEREBRAS_MODEL_SUBSTITUTION", msg)
        self.assertIn('"requested_model": "kimi-k3.1-pro"', msg)
        self.assertIn('"served_model": "qwen-3.8-27b"', msg)
        self.assertIn('"status": "error"', msg)

    def test_missing_served_model_is_rejected_fail_closed(self) -> None:
        with MockCerebrasServer("missing_model") as server:
            client = make_client(server)
            with self.assertRaises(CerebrasSchemaError) as ctx:
                client.propose_candidate(valid_context())
        self.assertEqual(ctx.exception.code, "ERR_CEREBRAS_MODEL_MISSING")
        self.assertIn("ERR_CEREBRAS_MODEL_MISSING", str(ctx.exception))

    def test_invalid_ansi_oversized_or_untrimmed_served_model_is_rejected_without_leak(self) -> None:
        for bad_model in ("", "   ", " kimi-k3.1-pro ", 123, "a" * 129, "qwen\x1b[31mevil\x00"):
            raw = json.dumps(
                {
                    "id": "chatcmpl-bad",
                    "model": bad_model,
                    "choices": [
                        {
                            "index": 0,
                            "message": {
                                "role": "assistant",
                                "content": json.dumps(valid_candidate(), separators=(",", ":")),
                            },
                            "finish_reason": "stop",
                        }
                    ],
                }
            ).encode("utf-8")

            class _FakeResp:
                def __enter__(self) -> "_FakeResp":
                    return self

                def __exit__(self, *args: object) -> bool:
                    return False

                def read(self) -> bytes:
                    return raw

            client = CerebrasKimiClient(API_KEY, base_url="http://127.0.0.1:1/v1")
            with mock.patch("warp_modeld.cerebras_client.urllib.request.urlopen", return_value=_FakeResp()):
                with self.assertRaises(CerebrasSchemaError) as ctx:
                    client.propose_candidate(valid_context())
            self.assertEqual(ctx.exception.code, "ERR_CEREBRAS_MODEL_INVALID")
            msg = str(ctx.exception)
            self.assertIn('"served_model": null', msg)
            self.assertNotIn("\x1b", msg)
            self.assertNotIn("\x00", msg)

    def test_served_model_outside_printable_ascii_is_rejected(self) -> None:
        # DEL (0x7f) is the first byte above the printable range; the others
        # are non-ASCII. The embedded form must fail too, not only a bare one.
        for bad_model in ("\x7f", "kimi-k3.1-pro\x7f", "kimi-k3.1-pro\u00e9", "kimi-k3.1-pro\u2603", "\u00ff"):
            with self.subTest(bad_model=bad_model):
                with self.assertRaises(CerebrasSchemaError) as ctx:
                    propose_with_served_model(bad_model)
                self.assertEqual(ctx.exception.code, "ERR_CEREBRAS_MODEL_INVALID")

    def test_served_model_boundary_characters_are_accepted_by_the_range_check(self) -> None:
        # Space (32) and tilde (126) are inside the printable range, so a
        # served name that differs from the configured one only by them is a
        # substitution, not an invalid name.
        for served in ("kimi k3.1-pro", "kimi~k3.1-pro"):
            with self.subTest(served=served):
                with self.assertRaises(CerebrasSchemaError) as ctx:
                    propose_with_served_model(served)
                self.assertEqual(ctx.exception.code, "ERR_CEREBRAS_MODEL_SUBSTITUTION")

    def test_served_model_comparison_is_case_sensitive(self) -> None:
        for served in ("KIMI-K3.1-PRO", "Kimi-K3.1-Pro"):
            with self.subTest(served=served):
                with self.assertRaises(CerebrasSchemaError) as ctx:
                    propose_with_served_model(served)
                self.assertEqual(ctx.exception.code, "ERR_CEREBRAS_MODEL_SUBSTITUTION")
        # A configured id with capitals matches only itself, not its lowercase form.
        with self.assertRaises(CerebrasSchemaError) as ctx:
            propose_with_served_model("endpoint-abc", model_id="Endpoint-ABC")
        self.assertEqual(ctx.exception.code, "ERR_CEREBRAS_MODEL_SUBSTITUTION")
        propose_with_served_model("Endpoint-ABC", model_id="Endpoint-ABC")

    def test_invalid_served_model_value_appears_nowhere_in_the_error(self) -> None:
        marker = "ZZLEAKMARKERZZ"
        # Each value is invalid (control byte, DEL, non-ASCII, trailing space)
        # and carries the marker, so a leaked copy is found by plain text
        # whether it is raw or escaped by repr.
        for bad_model in (marker + "\x1b[31m", marker + "\x7f", marker + "\u00e9", marker + " "):
            with self.subTest(bad_model=bad_model):
                with self.assertRaises(CerebrasSchemaError) as ctx:
                    propose_with_served_model(bad_model)
                exc = ctx.exception
                self.assertEqual(exc.code, "ERR_CEREBRAS_MODEL_INVALID")
                receipt = receipt_from_exception(exc)
                self.assertIsNone(receipt["served_model"])
                self.assertEqual(receipt["error_code"], "ERR_CEREBRAS_MODEL_INVALID")
                surfaces = [
                    str(exc),
                    repr(exc),
                    repr(exc.args),
                    repr(vars(exc)),
                    json.dumps(receipt, sort_keys=True),
                    repr(receipt),
                ]
                cause = exc.__cause__
                if cause is not None:
                    surfaces += [str(cause), repr(cause), repr(vars(cause))]
                for surface in surfaces:
                    self.assertNotIn(marker, surface)

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

    def test_model_id_config_is_validated_at_construction(self) -> None:
        bad_ids = (
            "kimi-k3.1-pr\u00f6",  # non-ASCII text
            "\u2603",
            "kimi\x7f",  # DEL
            "kimi\x00pro",  # control byte
            123,  # not a string
            None,
            b"kimi-k3.1-pro",
            "",  # blank
            "   ",
            " kimi-k3.1-pro",  # untrimmed
            "kimi-k3.1-pro\n",
            "a" * 129,  # over length
        )
        for bad in bad_ids:
            with self.subTest(bad=bad):
                with self.assertRaises(CerebrasClientError) as ctx:
                    CerebrasKimiClient(API_KEY, model_id=bad)  # type: ignore[arg-type]
                self.assertEqual(type(ctx.exception), CerebrasClientError)
                self.assertEqual(ctx.exception.code, "ERR_CEREBRAS_MODEL_ID_CONFIG")
                self.assertNotIn("\u00f6", str(ctx.exception))
        # The client never reaches the network with a bad id.
        with mock.patch("warp_modeld.cerebras_client.urllib.request.urlopen") as urlopen:
            with self.assertRaises(CerebrasClientError):
                CerebrasKimiClient(API_KEY, model_id="\u00e9")
            urlopen.assert_not_called()

    def test_valid_model_ids_are_accepted(self) -> None:
        for good in (DEFAULT_MODEL_ID, "dedicated-endpoint-123", "a" * 128, "Name With Space~", "x"):
            with self.subTest(good=good):
                self.assertEqual(CerebrasKimiClient(API_KEY, model_id=good).model_id, good)

    def test_from_env_validates_model_id(self) -> None:
        for bad in ("", "  ", "mod\u00e9l", " padded", "a" * 129):
            with self.subTest(bad=bad):
                with self.assertRaises(CerebrasClientError) as ctx:
                    CerebrasKimiClient.from_env({"CEREBRAS_API_KEY": "env-key", "CEREBRAS_MODEL_ID": bad})
                self.assertEqual(ctx.exception.code, "ERR_CEREBRAS_MODEL_ID_CONFIG")
        client = CerebrasKimiClient.from_env({"CEREBRAS_API_KEY": "env-key"})
        self.assertEqual(client.model_id, DEFAULT_MODEL_ID)

    def test_from_env_rejects_non_cerebras_https_host(self) -> None:
        with self.assertRaises(CerebrasClientError):
            CerebrasKimiClient.from_env(
                {
                    "CEREBRAS_API_KEY": "env-key",
                    "CEREBRAS_BASE_URL": "https://evil.example.com/v1",
                }
            )


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


class TestDataHygiene(unittest.TestCase):
    def test_nan_constraint_rejected(self) -> None:
        with self.assertRaises(CerebrasSchemaError):
            validate_propose_context(
                {**valid_context(), "constraints": {"max": float("nan")}}
            )

    def test_infinite_constraints_rejected(self) -> None:
        for value in (float("inf"), -float("inf")):
            with self.assertRaises(CerebrasSchemaError):
                validate_propose_context(
                    {**valid_context(), "constraints": {"max": value}}
                )

    def test_clean_constraint_still_valid(self) -> None:
        cleaned = validate_propose_context(
            {**valid_context(), "constraints": {"max": 0.5}}
        )
        self.assertEqual(cleaned["constraints"], {"max": 0.5})

    def test_strict_encoder_rejects_non_finite(self) -> None:
        from warp_modeld.cerebras_client import _json_dumps

        for value in (float("nan"), float("inf"), -float("inf")):
            with self.assertRaises(ValueError):
                _json_dumps({"x": value})

    def test_subclass_float_constraint_rejected(self) -> None:
        class SubFloat(float):
            pass

        for value in (SubFloat("nan"), SubFloat("inf"), SubFloat("-inf")):
            with self.assertRaises(CerebrasSchemaError):
                validate_propose_context(
                    {**valid_context(), "constraints": {"max": value}}
                )

    def test_subclass_key_and_value_rejected(self) -> None:
        class SubInt(int):
            pass

        class SubStr(str):
            pass

        with self.assertRaises(CerebrasSchemaError):
            validate_propose_context(
                {**valid_context(), "constraints": {SubInt(1): "x"}}
            )
        with self.assertRaises(CerebrasSchemaError):
            validate_propose_context(
                {**valid_context(), "constraints": {"max": SubStr("1.0")}}
            )

    def test_huge_int_constraint_key_rejected(self) -> None:
        with self.assertRaises(CerebrasSchemaError) as ctx:
            validate_propose_context(
                {**valid_context(), "constraints": {10**5000: "x"}}
            )
        self.assertLess(len(str(ctx.exception)), 200)

    def test_huge_int_constraint_value_rejected(self) -> None:
        with self.assertRaises(CerebrasSchemaError) as ctx:
            validate_propose_context(
                {**valid_context(), "constraints": {"max": 10**5000}}
            )
        self.assertLess(len(str(ctx.exception)), 200)

    def test_plain_scalar_constraints_still_valid(self) -> None:
        cleaned = validate_propose_context(
            {**valid_context(), "constraints": {"flag": True, "max": 3, "name": "x", "ratio": 0.5}}
        )
        self.assertEqual(
            cleaned["constraints"], {"flag": True, "max": 3, "name": "x", "ratio": 0.5}
        )


if __name__ == "__main__":
    unittest.main()
