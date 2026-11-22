"""Data hygiene checks for the local llama client. Fake transport only.

No live llama-server, GPU, or checkpoint is used. These are input-boundary
logic checks, never adapted-model evidence.
"""

import unittest

from warp_modeld.llama_client import LlamaClientError, LlamaServerClient


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


if __name__ == "__main__":
    unittest.main()
