"""Data hygiene checks for the local llama client. Fake transport only.

No live llama-server, GPU, or checkpoint is used. These are input-boundary
logic checks, never adapted-model evidence.
"""

import unittest

from warp_modeld.llama_client import (
    LlamaClientError,
    LlamaServerClient,
    _require_adapter_scale,
)


def _client(payload):
    client = LlamaServerClient("http://127.0.0.1:8080")
    client._request = lambda method, path, body=None: payload
    return client


class TestLoraAdapterCoercions(unittest.TestCase):
    def test_list_rejects_bool_id(self) -> None:
        client = _client([{"id": True, "scale": 1.0}])
        with self.assertRaises(LlamaClientError):
            client.list_lora_adapters()

    def test_list_rejects_nan_scale_string(self) -> None:
        client = _client([{"id": 1, "scale": "nan"}])
        with self.assertRaises(LlamaClientError):
            client.list_lora_adapters()

    def test_list_rejects_infinity_scale(self) -> None:
        client = _client([{"id": 1, "scale": float("inf")}])
        with self.assertRaises(LlamaClientError):
            client.list_lora_adapters()

    def test_list_accepts_clean_entry(self) -> None:
        client = _client([{"id": 1, "scale": 1.0}])
        adapters = client.list_lora_adapters()
        self.assertEqual(adapters[0].id, 1)
        self.assertEqual(adapters[0].scale, 1.0)

    def test_set_rejects_bool_id(self) -> None:
        client = _client({"result": "ok"})
        with self.assertRaises(LlamaClientError):
            client.set_lora_adapters([{"id": True, "scale": 1.0}])

    def test_set_rejects_nan_scale_string(self) -> None:
        client = _client({"result": "ok"})
        with self.assertRaises(LlamaClientError):
            client.set_lora_adapters([{"id": 1, "scale": "nan"}])

    def test_set_accepts_clean_entry(self) -> None:
        seen = {}
        client = LlamaServerClient("http://127.0.0.1:8080")

        def capture(method, path, body=None):
            seen["body"] = body
            return {"result": "ok"}

        client._request = capture
        result = client.set_lora_adapters([{"id": 1, "scale": 1.0}])
        self.assertEqual(result, {"result": "ok"})
        self.assertEqual(seen["body"], [{"id": 1, "scale": 1.0}])

class TestWD60ReviewFindings(unittest.TestCase):
    """WD60-01 + non-blocking lora coercion findings from the PR #60 review."""

    def test_require_adapter_scale_rejects_huge_int(self) -> None:
        for value in (10**400, 10**5000):
            with self.assertRaises(LlamaClientError):
                _require_adapter_scale(value)

    def test_list_rejects_huge_int_scale(self) -> None:
        client = _client([{"id": 1, "scale": 10**5000}])
        with self.assertRaises(LlamaClientError):
            client.list_lora_adapters()

    def test_set_rejects_huge_int_scale(self) -> None:
        client = _client({"result": "ok"})
        with self.assertRaises(LlamaClientError):
            client.set_lora_adapters([{"id": 1, "scale": 10**400}])

    def test_set_rejects_malformed_entries(self) -> None:
        client = _client({"result": "ok"})
        for bad in ([{"id": 1}], [{"scale": 1.0}], ["bad"], [None], [123]):
            with self.assertRaises(LlamaClientError):
                client.set_lora_adapters(bad)

    def test_list_rejects_non_str_path(self) -> None:
        for bad_path in (10**5000, 123, None, ["x"]):
            client = _client([{"id": 1, "scale": 1.0, "path": bad_path}])
            with self.assertRaises(LlamaClientError):
                client.list_lora_adapters()

    def test_list_accepts_str_path(self) -> None:
        client = _client([{"id": 1, "scale": 1.0, "path": "/tmp/a.gguf"}])
        adapters = client.list_lora_adapters()
        self.assertEqual(adapters[0].path, "/tmp/a.gguf")

    def _capturing_client(self, payload):
        seen = {}
        client = LlamaServerClient("http://127.0.0.1:8080")

        def capture(method, path, body=None):
            seen["body"] = body
            return payload

        client._request = capture
        return client, seen

    def test_chat_completion_rejects_coercible_lora(self) -> None:
        client = _client({"choices": []})
        for bad_lora in ([{"id": True, "scale": 1.0}], [{"id": 1, "scale": "1.0"}], ["bad"]):
            with self.assertRaises(LlamaClientError):
                client.chat_completion([{"role": "user", "content": "hi"}], lora=bad_lora)

    def test_completion_rejects_coercible_lora(self) -> None:
        client = _client({"choices": []})
        for bad_lora in ([{"id": True, "scale": 1.0}], [{"id": 1, "scale": "1.0"}], ["bad"]):
            with self.assertRaises(LlamaClientError):
                client.completion("hi", lora=bad_lora)

    def test_chat_completion_accepts_clean_lora(self) -> None:
        client, seen = self._capturing_client({"choices": []})
        client.chat_completion(
            [{"role": "user", "content": "hi"}], lora=[{"id": 2, "scale": 0.5}]
        )
        self.assertEqual(seen["body"]["lora"], [{"id": 2, "scale": 0.5}])

    def test_completion_accepts_clean_lora(self) -> None:
        client, seen = self._capturing_client({"choices": []})
        client.completion("hi", lora=[{"id": 2, "scale": 1}])
        self.assertEqual(seen["body"]["lora"], [{"id": 2, "scale": 1.0}])


if __name__ == "__main__":
    unittest.main()
