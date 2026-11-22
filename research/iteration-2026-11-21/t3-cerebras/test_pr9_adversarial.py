"""External adversarial tests for PR #9; preregistered in ADVERSARIAL_PLAN.md."""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
import unittest
from unittest import mock
import urllib.error

from warp_modeld.cerebras_client import CerebrasKimiClient, validate_candidate
from warp_modeld.errors import CerebrasSchemaError, CerebrasTransportError

API_KEY = "test-key-that-is-not-real"
PRIVATE_EMAIL = "alice@example.invalid"
PRIVATE_SUMMARY = "private acquisition planning"


def receipt_from_error(error: Exception) -> dict[str, object]:
    text = str(error)
    marker = "(receipt: "
    assert marker in text and text.endswith(")"), text
    return json.loads(text.rsplit(marker, 1)[1][:-1])


def valid_candidate() -> dict[str, object]:
    return {"target_layer": "last", "strength": 0.5, "rank": 16, "quantization": "q8_0"}


class FakeResponse:
    def __init__(self, raw: bytes) -> None:
        self.raw = raw

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self) -> bytes:
        return self.raw


class AdversarialPR9Tests(unittest.TestCase):
    def test_oversized_integer_is_schema_error_not_numeric_crash(self) -> None:
        payload = valid_candidate()
        payload["strength"] = 10 ** 10000
        with self.assertRaises(CerebrasSchemaError):
            validate_candidate(payload)

    def test_wrapped_timeouts_count_every_attempt_within_retry_budget(self) -> None:
        client = CerebrasKimiClient(API_KEY, max_retries=2, retry_delay_seconds=0.0)
        timeout = urllib.error.URLError(TimeoutError("timed out"))
        with mock.patch(
            "warp_modeld.cerebras_client.urllib.request.urlopen", side_effect=timeout
        ) as urlopen:
            with self.assertRaises(CerebrasTransportError) as caught:
                client.propose_candidate({"task_summary": "bounded mock timeout"})
        self.assertEqual(urlopen.call_count, 3)
        receipt = receipt_from_error(caught.exception)
        self.assertEqual(receipt["retries"], 2)
        self.assertEqual(receipt["timeouts"], 3)

    def test_http_error_receipt_redacts_key_and_pii(self) -> None:
        class Handler(BaseHTTPRequestHandler):
            requests = 0

            def log_message(self, *args: object) -> None:
                pass

            def do_POST(self) -> None:  # noqa: N802
                type(self).requests += 1
                length = int(self.headers.get("Content-Length") or 0)
                self.rfile.read(length)
                detail = f"echo {API_KEY}; {PRIVATE_EMAIL}; {PRIVATE_SUMMARY}"
                raw = json.dumps({"error": {"message": detail}}).encode("utf-8")
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            client = CerebrasKimiClient(
                API_KEY,
                base_url=f"http://127.0.0.1:{server.server_address[1]}",
                max_retries=2,
                retry_delay_seconds=0.0,
            )
            with self.assertRaises(CerebrasTransportError) as caught:
                client.propose_candidate({"task_summary": PRIVATE_SUMMARY})
            self.assertEqual(Handler.requests, 1)
            text = str(caught.exception)
            receipt = receipt_from_error(caught.exception)
            serialized_receipt = json.dumps(receipt)
            for marker in (API_KEY, PRIVATE_EMAIL, PRIVATE_SUMMARY):
                with self.subTest(marker=marker):
                    self.assertNotIn(marker, text)
                    self.assertNotIn(marker, serialized_receipt)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_duplicate_candidate_key_is_rejected_end_to_end(self) -> None:
        duplicate_content = (
            '{"target_layer":"last","strength":0.5,'
            '"rank":16,"rank":32,"quantization":"q8_0"}'
        )
        outer = {
            "model": "kimi-k3.1-pro",
            "choices": [{"message": {"role": "assistant", "content": duplicate_content}}],
        }
        client = CerebrasKimiClient(API_KEY, max_retries=0, retry_delay_seconds=0.0)
        with mock.patch(
            "warp_modeld.cerebras_client.urllib.request.urlopen",
            return_value=FakeResponse(json.dumps(outer).encode("utf-8")),
        ) as urlopen:
            with self.assertRaises(CerebrasSchemaError):
                client.propose_candidate({"task_summary": "duplicate key check"})
        self.assertEqual(urlopen.call_count, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
