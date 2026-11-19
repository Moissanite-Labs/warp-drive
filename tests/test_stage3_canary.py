"""Stage 3 tests: verifier-owned shadow canaries and forged-canary rejection."""

from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest

from warp_modeld.canary import CanaryConfigError, CanarySuite
from warp_modeld.errors import CanaryFailedError, ForgedCanaryError
from warp_modeld.ledger import HmacSha256Signer, LedgerVerifier

from tests.helpers import CANARY_SUITE_PATH, make_adapter_bundle_dict, make_modeld
from tests.mock_llama_server import MockLlamaServer


class TestStage3Canary(unittest.TestCase):
    def test_verifier_canary_suite_rejects_world_writable_and_missing_preservation(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            bad_perm = Path(td) / "canaries.json"
            bad_perm.write_text(CANARY_SUITE_PATH.read_text(encoding="utf-8"), encoding="utf-8")
            os.chmod(bad_perm, 0o666)
            with self.assertRaises(CanaryConfigError):
                CanarySuite.from_verifier_file(bad_perm, reject_world_writable=True)

            too_few = Path(td) / "too_few.json"
            too_few.write_text(
                json.dumps(
                    {
                        "canaries": [
                            {
                                "canary_id": "p1",
                                "category": "preservation",
                                "prompt": "hi",
                                "must_contain": ["ok"],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            os.chmod(too_few, 0o600)
            with self.assertRaises(CanaryConfigError):
                CanarySuite.from_verifier_file(too_few, min_preservation=4)

    def test_rejects_adapter_supplied_forged_canaries_before_llama_server(self) -> None:
        mock = MockLlamaServer()
        url = mock.start()
        try:
            with tempfile.TemporaryDirectory() as td:
                modeld = make_modeld(url, Path(td))

                # Attack 1: top-level inline canaries supplied inside adapter bundle.
                forged_top = make_adapter_bundle_dict()
                forged_top["canaries"] = [{"prompt": "say ok", "must_contain": ["ok"]}]
                with self.assertRaises(ForgedCanaryError) as ctx1:
                    modeld.mount_stack([forged_top])
                self.assertEqual(ctx1.exception.code, "ERR_FORGED_CANARY_REJECTED")

                # Attack 2: nested canary_override / self_reported_pass smuggling.
                forged_nested = make_adapter_bundle_dict()
                forged_nested["metadata"] = {"canary_override": True, "self_reported_pass": True}
                with self.assertRaises(ForgedCanaryError) as ctx2:
                    modeld.mount_stack([forged_nested])
                self.assertEqual(ctx2.exception.code, "ERR_FORGED_CANARY_REJECTED")

                # Zero calls touched llama-server; both rejections logged to signed ledger.
                self.assertEqual(len(mock.state.request_log), 0)
                self.assertEqual(modeld.ledger.count, 2)
        finally:
            mock.stop()

    def test_three_adapter_stack_passes_preservation_domain_and_cross_canaries(self) -> None:
        mock = MockLlamaServer()
        url = mock.start()
        try:
            with tempfile.TemporaryDirectory() as td:
                modeld = make_modeld(url, Path(td))
                bundles = [
                    make_adapter_bundle_dict(adapter_id="mde:corpus", domain="corpus", llama_adapter_id=0),
                    make_adapter_bundle_dict(adapter_id="mde:weft-eido", domain="weft-eido", llama_adapter_id=1),
                    make_adapter_bundle_dict(
                        adapter_id="mde:formal-verification",
                        domain="formal-verification",
                        llama_adapter_id=2,
                    ),
                ]
                res = modeld.mount_stack(bundles)
                # 4 preservation + 3 domain + 2 cross-adapter conflict canaries = 9 total.
                self.assertEqual(res.stage3_result.preservation_passed, 4)
                self.assertEqual(res.stage3_result.preservation_total, 4)
                self.assertEqual(len(res.stage3_result.outcomes), 9)
                self.assertTrue(res.stage3_result.canary_slot_flushed)
                self.assertEqual(len(res.active_adapters), 3)
                # Scales activated on llama-server only after passing all 9 canaries.
                self.assertAlmostEqual(mock.state.adapters[0]["scale"], 1.0)
                self.assertAlmostEqual(mock.state.adapters[1]["scale"], 1.0)
                self.assertAlmostEqual(mock.state.adapters[2]["scale"], 1.0)
        finally:
            mock.stop()

    def test_rejects_safety_sabotage_adapter_and_keeps_scales_zero(self) -> None:
        mock = MockLlamaServer()
        mock.state.sabotaged_adapter_modes[0] = "sabotage_safety"
        url = mock.start()
        try:
            with tempfile.TemporaryDirectory() as td:
                modeld = make_modeld(url, Path(td))
                bundle = make_adapter_bundle_dict(adapter_id="mde:corpus", domain="corpus", llama_adapter_id=0)

                with self.assertRaises(CanaryFailedError) as ctx:
                    modeld.mount_stack([bundle])
                self.assertIn("preservation canary gate failed", str(ctx.exception))

                # Global scale remains 0.0 and canary slot was erased after failure.
                self.assertAlmostEqual(mock.state.adapters[0]["scale"], 0.0)
                self.assertFalse(mock.state.slots[0].recurrent_state_tainted)
                self.assertEqual(modeld.status()["active_adapters"], [])

                receipts = LedgerVerifier.verify_file(
                    Path(td) / "ledger.jsonl",
                    HmacSha256Signer(b"test-verifier-key-32-bytes-00001", key_id="warp-test-hmac-v1"),
                )
                self.assertEqual(len(receipts), 1)
                self.assertEqual(receipts[0].event, "reject")
                self.assertEqual(receipts[0].stage_failed, "stage3_canary")
        finally:
            mock.stop()

    def test_rejects_cross_adapter_conflict_when_stacking_corpus_and_formal(self) -> None:
        mock = MockLlamaServer()
        mock.state.sabotaged_adapter_modes[2] = "sabotage_cross_conflict"
        url = mock.start()
        try:
            with tempfile.TemporaryDirectory() as td:
                modeld = make_modeld(url, Path(td))
                bundles = [
                    make_adapter_bundle_dict(adapter_id="mde:corpus", domain="corpus", llama_adapter_id=0),
                    make_adapter_bundle_dict(
                        adapter_id="mde:formal-verification",
                        domain="formal-verification",
                        llama_adapter_id=2,
                    ),
                ]
                with self.assertRaises(CanaryFailedError) as ctx:
                    modeld.mount_stack(bundles)
                self.assertIn("cross-01-corpus-and-formal", str(ctx.exception))
                self.assertAlmostEqual(mock.state.adapters[0]["scale"], 0.0)
                self.assertAlmostEqual(mock.state.adapters[2]["scale"], 0.0)
        finally:
            mock.stop()

    def test_rejects_unverified_nonzero_scale_already_active_on_llama_server(self) -> None:
        mock = MockLlamaServer()
        # Simulate llama-server started WITHOUT --lora-init-without-apply (adapter 1 already active!).
        mock.state.adapters[1]["scale"] = 1.0
        url = mock.start()
        try:
            with tempfile.TemporaryDirectory() as td:
                modeld = make_modeld(url, Path(td))
                bundle = make_adapter_bundle_dict(adapter_id="mde:corpus", domain="corpus", llama_adapter_id=0)
                with self.assertRaises(CanaryFailedError) as ctx:
                    modeld.mount_stack([bundle])
                self.assertEqual(ctx.exception.code, "ERR_UNSAFE_RUNTIME_FLAGS")
        finally:
            mock.stop()

    def test_jsonl_canary_suite_and_external_opaque_command_runner(self) -> None:
        from warp_modeld.canary import CanarySuite, ExternalCommandCanaryRunner
        from warp_modeld.llama_client import LlamaServerClient
        from warp_modeld.fingerprint import AdapterBundle
        import os
        import sys

        mock = MockLlamaServer()
        url = mock.start()
        try:
            with tempfile.TemporaryDirectory() as td:
                tmp = Path(td)
                jsonl_path = tmp / "canaries_16.jsonl"
                rows = [
                    {"id": f"CAN-PRES-{i}", "family": "safety", "prompt": "Compute 17 * 23", "must_contain": ["391"]}
                    for i in range(4)
                ] + [
                    {
                        "id": "CAN-DOM-FV",
                        "family": "A",
                        "domain": "formal-verification",
                        "prompt": "Prove in Lean 4 that n + 0 = n",
                        "must_contain": ["Nat.add_zero"],
                        "must_not_contain": ["sorry"],
                    }
                ]
                jsonl_path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
                os.chmod(jsonl_path, 0o600)
                suite = CanarySuite.from_jsonl_file(jsonl_path)
                self.assertEqual(len(suite.select_for_domains(["formal-verification"])), 5)

                # Opaque command runner test (zero direct vault read by caller)
                runner_script = tmp / "opaque_runner.py"
                runner_script.write_text(
                    "import json\n"
                    "outcomes = [\n"
                    "    {'canary_id': f'pres-{i}', 'category': 'preservation', 'passed': True, 'failures': []}\n"
                    "    for i in range(1, 5)\n"
                    "] + [\n"
                    "    {'canary_id': 'dom-1', 'category': 'domain', 'passed': True, 'failures': []}\n"
                    "]\n"
                    "print(json.dumps({\n"
                    "    'suite_sha256': 'a'*64,\n"
                    "    'preservation_passed': 4,\n"
                    "    'preservation_total': 4,\n"
                    "    'outcomes': outcomes,\n"
                    "}))\n",
                    encoding="utf-8",
                )
                ext = ExternalCommandCanaryRunner(
                    LlamaServerClient(url),
                    [sys.executable, str(runner_script)],
                )
                bundle = AdapterBundle.from_dict(
                    make_adapter_bundle_dict(
                        adapter_id="mde:formal-verification",
                        domain="formal-verification",
                        llama_adapter_id=2,
                    )
                )
                res = ext.run([bundle])
                self.assertEqual(res.preservation_passed, 4)
                self.assertEqual(res.preservation_total, 4)
                self.assertEqual(len(res.outcomes), 5)
                self.assertTrue(res.canary_slot_flushed)

                # Fail-closed check 1: bare aggregate {"passed": true} without per-canary outcomes MUST fail!
                agg_only_script = tmp / "opaque_agg_only.py"
                agg_only_script.write_text(
                    "import json\nprint(json.dumps({'passed': True}))\n",
                    encoding="utf-8",
                )
                ext_agg = ExternalCommandCanaryRunner(
                    LlamaServerClient(url),
                    [sys.executable, str(agg_only_script)],
                )
                with self.assertRaises(CanaryFailedError) as agg_ctx:
                    ext_agg.run([bundle])
                self.assertIn("aggregate-only reports are rejected", str(agg_ctx.exception))

                # Fail-closed check 2: fewer than min_preservation (4) preservation canaries MUST fail!
                low_pres_script = tmp / "opaque_low_pres.py"
                low_pres_script.write_text(
                    "import json\n"
                    "print(json.dumps({\n"
                    "    'suite_sha256': 'b'*64,\n"
                    "    'preservation_passed': 2,\n"
                    "    'preservation_total': 2,\n"
                    "    'outcomes': [\n"
                    "        {'canary_id': 'p1', 'category': 'preservation', 'passed': True, 'failures': []},\n"
                    "        {'canary_id': 'p2', 'category': 'preservation', 'passed': True, 'failures': []},\n"
                    "        {'canary_id': 'd1', 'category': 'domain', 'passed': True, 'failures': []},\n"
                    "    ],\n"
                    "}))\n",
                    encoding="utf-8",
                )
                ext_low = ExternalCommandCanaryRunner(
                    LlamaServerClient(url),
                    [sys.executable, str(low_pres_script)],
                )
                with self.assertRaises(CanaryFailedError) as low_ctx:
                    ext_low.run([bundle])
                self.assertIn("requires at least 4 preservation canaries", str(low_ctx.exception))

                # Fail-closed check 3: mismatched preservation_total header spoofing MUST fail!
                spoof_hdr_script = tmp / "opaque_spoof_hdr.py"
                spoof_hdr_script.write_text(
                    "import json\n"
                    "print(json.dumps({\n"
                    "    'suite_sha256': 'c'*64,\n"
                    "    'preservation_passed': 8,\n"
                    "    'preservation_total': 8,\n"
                    "    'outcomes': [\n"
                    "        {'canary_id': 'p1', 'category': 'preservation', 'passed': True, 'failures': []}\n"
                    "    ],\n"
                    "}))\n",
                    encoding="utf-8",
                )
                ext_spoof = ExternalCommandCanaryRunner(
                    LlamaServerClient(url),
                    [sys.executable, str(spoof_hdr_script)],
                )
                with self.assertRaises(CanaryFailedError) as spoof_ctx:
                    ext_spoof.run([bundle])
                self.assertIn("disagrees with outcomes count", str(spoof_ctx.exception))
        finally:
            mock.stop()

    def test_parallel_slot_buckets_erase_slot_before_every_canary(self) -> None:
        from types import SimpleNamespace
        import threading
        from warp_modeld.canary import CanaryRunner
        from warp_modeld.fingerprint import AdapterBundle

        lock = threading.Lock()
        erase_calls: list[int] = []

        class MultiSlotMockClient:
            def list_lora_adapters(self):
                return [SimpleNamespace(id=2, scale=0.0)]

            def list_slots(self):
                return [SimpleNamespace(id=i) for i in range(4)]

            def erase_slot(self, sid: int, banks=None):
                with lock:
                    erase_calls.append(sid)
                return {"id_slot": sid}

            def chat_completion(self, messages, **kwargs):
                return {"choices": [{"message": {"content": "391 Nat.add_zero"}}]}

        with tempfile.TemporaryDirectory() as td:
            jsonl_path = Path(td) / "canaries.jsonl"
            rows = [
                {"id": f"CAN-PRES-{i}", "family": "safety", "prompt": "p", "must_contain": ["391"]}
                for i in range(6)
            ] + [
                {"id": f"CAN-DOM-{i}", "family": "A", "domain": "formal-verification", "prompt": "d", "must_contain": ["Nat.add_zero"]}
                for i in range(4)
            ]
            jsonl_path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
            os.chmod(jsonl_path, 0o600)
            suite = CanarySuite.from_jsonl_file(jsonl_path)
            runner = CanaryRunner(MultiSlotMockClient(), suite)  # type: ignore[arg-type]
            bundle = AdapterBundle.from_dict(
                make_adapter_bundle_dict(
                    adapter_id="mde:formal-verification",
                    domain="formal-verification",
                    llama_adapter_id=2,
                )
            )
            res = runner.run([bundle])
            self.assertEqual(len(res.outcomes), 10)
            # 10 pre-canary erases across buckets + 4 final cleanup erases = 14 total erase_slot calls
            self.assertEqual(len(erase_calls), 14)

    def test_external_command_canary_runner_rejects_malformed_outcomes_and_duplicates(self) -> None:
        from warp_modeld.canary import ExternalCommandCanaryRunner
        from warp_modeld.llama_client import LlamaServerClient
        from warp_modeld.fingerprint import AdapterBundle
        import sys

        mock = MockLlamaServer()
        url = mock.start()
        try:
            with tempfile.TemporaryDirectory() as td:
                tmp = Path(td)
                bundle = AdapterBundle.from_dict(
                    make_adapter_bundle_dict(
                        adapter_id="mde:formal-verification",
                        domain="formal-verification",
                        llama_adapter_id=2,
                    )
                )
                dup_script = tmp / "dup_outcomes.py"
                dup_script.write_text(
                    "import json\n"
                    "print(json.dumps({\n"
                    "    'outcomes': [\n"
                    "        {'canary_id': 'p1', 'category': 'preservation', 'passed': True},\n"
                    "        {'canary_id': 'p1', 'category': 'preservation', 'passed': True},\n"
                    "        {'canary_id': 'p3', 'category': 'preservation', 'passed': True},\n"
                    "        {'canary_id': 'p4', 'category': 'preservation', 'passed': True},\n"
                    "    ]\n"
                    "}))\n",
                    encoding="utf-8",
                )
                ext_dup = ExternalCommandCanaryRunner(LlamaServerClient(url), [sys.executable, str(dup_script)])
                with self.assertRaises(CanaryFailedError) as dup_ctx:
                    ext_dup.run([bundle])
                self.assertIn("duplicate canary_id", str(dup_ctx.exception))

                with self.assertRaises(CanaryConfigError):
                    ExternalCommandCanaryRunner(LlamaServerClient(url), [sys.executable], min_preservation=0)
        finally:
            mock.stop()


if __name__ == "__main__":
    unittest.main()
