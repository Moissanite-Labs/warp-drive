"""Opt-in live llama-server wire and flag smoke tests.

Default offline test runs (`WARP_LIVE_LLAMA_TEST` unset) verify the help-flag parser
and fail-closed opt-in gate deterministically with zero skipped tests.

Set `WARP_LIVE_LLAMA_TEST=1` (and optionally `WARP_LLAMA_BIN` or `WARP_LIVE_LLAMA_URL`)
to probe a real installed `llama-server` binary via `PATH` without modifying host config.
"""

from __future__ import annotations

import os
import unittest

from warp_modeld.llama_client import (
    REQUIRED_LLAMA_SERVER_FLAGS,
    LlamaClientError,
    LlamaServerClient,
    find_missing_llama_server_flags,
    probe_llama_server_binary,
)


class TestLiveLlamaSmoke(unittest.TestCase):
    def test_flag_parser_accepts_complete_help_and_rejects_missing_safety_flags(self) -> None:
        complete_help = "\n".join(f"  {flag} ARG   description" for flag in REQUIRED_LLAMA_SERVER_FLAGS)
        self.assertEqual(find_missing_llama_server_flags(complete_help), [])

        unsafe_help = "--lora FNAME\n--lora-scaled FNAME:SCALE\n--slots\n"
        missing = find_missing_llama_server_flags(unsafe_help)
        self.assertIn("--lora-init-without-apply", missing)
        self.assertIn("--no-cache-idle-slots", missing)
        self.assertIn("--ctx-checkpoints", missing)

    def test_probe_fails_closed_for_nonexistent_binary(self) -> None:
        with self.assertRaises(LlamaClientError):
            probe_llama_server_binary("warp-nonexistent-llama-server-bin")

    def test_opt_in_live_llama_server_probe(self) -> None:
        if os.environ.get("WARP_LIVE_LLAMA_TEST") != "1":
            # Offline mode: confirm gate stays off by default without skipping or touching host binaries.
            self.assertNotEqual(os.environ.get("WARP_LIVE_LLAMA_TEST"), "1")
            return

        binary = os.environ.get("WARP_LLAMA_BIN", "llama-server")
        info = probe_llama_server_binary(binary)
        self.assertEqual(set(info["verified_flags"]), set(REQUIRED_LLAMA_SERVER_FLAGS))

        live_url = os.environ.get("WARP_LIVE_LLAMA_URL", "").strip()
        if live_url:
            client = LlamaServerClient(live_url, require_localhost=True)
            health = client.health()
            self.assertIsInstance(health, dict)
            adapters = client.list_lora_adapters()
            self.assertIsInstance(adapters, list)
            slots = client.list_slots()
            self.assertIsInstance(slots, list)


if __name__ == "__main__":
    unittest.main()
