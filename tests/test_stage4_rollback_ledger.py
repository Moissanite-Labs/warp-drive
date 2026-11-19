"""Stage 4 tests: O(1) kill-switch, hybrid recurrent-state flush, and signed ledger tamper detection."""

from __future__ import annotations

import gc
import json
from pathlib import Path
import tempfile
import unittest

from warp_modeld.errors import (
    KillSwitchEngagedError,
    LedgerTamperError,
    StateFlushError,
    UnverifiedLoraOverrideError,
)
from warp_modeld.fingerprint import Plane1Lineage
from warp_modeld.ledger import HmacSha256Signer, LedgerVerifier, SignedLedger, repair_ledger
from warp_modeld.llama_client import LlamaServerClient

from tests.helpers import fake_sha, make_adapter_bundle_dict, make_lineage, make_modeld
from tests.mock_llama_server import MockLlamaServer


class TestStage4RollbackAndLedger(unittest.TestCase):
    def test_contrast_unflushed_slot_leaks_recurrent_state_while_warp_rollback_prevents_it(self) -> None:
        mock = MockLlamaServer()
        url = mock.start()
        try:
            # First prove the mock detects residual DeltaNet recurrent-state leakage if slot is NOT erased.
            raw_client = LlamaServerClient(url)
            raw_client.chat_completion(
                [{"role": "user", "content": "hello with lora"}],
                lora=[{"id": 0, "scale": 1.0}],
                id_slot=0,
            )
            leaked_reply = raw_client.chat_completion(
                [{"role": "user", "content": "after lora without flush"}],
                lora=[],
                id_slot=0,
            )
            self.assertIn(
                "[RESIDUAL_RECURRENT_LEAK:lora=0]",
                leaked_reply["choices"][0]["message"]["content"],
            )

            # Now test warp-modeld: mount -> infer -> O(1) rollback -> infer clean W0 with zero leakage.
            with tempfile.TemporaryDirectory() as td:
                modeld = make_modeld(url, Path(td))
                bundle = make_adapter_bundle_dict(adapter_id="mde:corpus", domain="corpus", llama_adapter_id=0)
                mount_res = modeld.mount_stack([bundle])
                self.assertIsNotNone(mount_res.slot_manifest_digest)

                active_out = modeld.infer([{"role": "user", "content": "active adapter turn"}])
                self.assertIn("[ACTIVE_LORA:0]", active_out["response"]["choices"][0]["message"]["content"])
                self.assertTrue(mock.state.slots[0].recurrent_state_tainted)

                rb = modeld.rollback(reason="operator_test_rollback", engage_kill_switch=False)
                self.assertEqual(rb.slots_flushed, (0, 1))
                self.assertAlmostEqual(mock.state.adapters[0]["scale"], 0.0)
                self.assertFalse(mock.state.slots[0].recurrent_state_tainted)
                self.assertFalse(mock.state.slots[1].recurrent_state_tainted)

                clean_out = modeld.infer([{"role": "user", "content": "post rollback base turn"}])
                content = clean_out["response"]["choices"][0]["message"]["content"]
                self.assertIn("[BASE_W0]", content)
                self.assertNotIn("RESIDUAL_RECURRENT_LEAK", content)
                self.assertEqual(clean_out["active_lora"], [])
        finally:
            mock.stop()

    def test_kill_switch_blocks_remount_and_never_auto_remounts_on_reset(self) -> None:
        mock = MockLlamaServer()
        url = mock.start()
        try:
            with tempfile.TemporaryDirectory() as td:
                modeld = make_modeld(url, Path(td))
                bundle = make_adapter_bundle_dict()
                modeld.mount_stack([bundle])

                ks = modeld.rollback(reason="emergency_stop", engage_kill_switch=True)
                self.assertTrue(ks.kill_switch_engaged)
                self.assertEqual(ks.receipt.event, "kill_switch")

                with self.assertRaises(KillSwitchEngagedError):
                    modeld.mount_stack([bundle])

                status_after = modeld.reset_kill_switch("human-approved-reset")
                self.assertFalse(status_after["kill_switch_engaged"])
                # Must remain cleanly unmounted on W0 until a fresh Stage 1-4 mount runs.
                self.assertEqual(status_after["active_adapters"], [])
        finally:
            mock.stop()

    def test_plane1_lineage_update_and_learning_toggle_auto_unload_and_flush(self) -> None:
        mock = MockLlamaServer()
        url = mock.start()
        try:
            with tempfile.TemporaryDirectory() as td:
                modeld = make_modeld(url, Path(td))
                bundle = make_adapter_bundle_dict()
                modeld.mount_stack([bundle])
                modeld.infer([{"role": "user", "content": "taint slot"}])

                # A new Plane 1 corpus commit makes active adapter stale -> automatic rollback + slot flush.
                new_lineage = Plane1Lineage(
                    corpus_tree_sha256=fake_sha("newer-corpus-commit"),
                    domain_commits=make_lineage().domain_commits,
                )
                rb = modeld.update_pinned_lineage(new_lineage)
                self.assertIsNotNone(rb)
                assert rb is not None
                self.assertEqual(rb.reason, "stale_lineage_auto_unload")
                self.assertEqual(modeld.status()["active_adapters"], [])
                self.assertFalse(mock.state.slots[0].recurrent_state_tainted)

                # Re-pin original lineage, remount, then flip learning off (.mep/learning = off).
                modeld.update_pinned_lineage(make_lineage())
                modeld.mount_stack([bundle])
                rb2 = modeld.set_learning_enabled(False)
                self.assertIsNotNone(rb2)
                assert rb2 is not None
                self.assertEqual(rb2.reason, "learning_disabled")
                with self.assertRaises(KillSwitchEngagedError):
                    modeld.mount_stack([bundle])
        finally:
            mock.stop()

    def test_failed_slot_flush_quarantines_daemon_instead_of_serving_tainted_state(self) -> None:
        mock = MockLlamaServer()
        url = mock.start()
        try:
            with tempfile.TemporaryDirectory() as td:
                modeld = make_modeld(url, Path(td))
                modeld.mount_stack([make_adapter_bundle_dict()])
                modeld.infer([{"role": "user", "content": "populate recurrent state"}])

                # Simulate backend failing to clear hybrid recurrent state on slot 0.
                mock.state.sticky_taint_slot_ids.add(0)
                with self.assertRaises(StateFlushError):
                    modeld.rollback(reason="test_sticky_taint")

                self.assertTrue(modeld.status()["state_quarantined"])
                # Daemon fails closed on inference instead of serving contaminated recurrent state!
                with self.assertRaises(StateFlushError):
                    modeld.infer([{"role": "user", "content": "should fail closed"}])
        finally:
            mock.stop()

    def test_http_500_on_slot_erase_also_quarantines_daemon(self) -> None:
        mock = MockLlamaServer()
        url = mock.start()
        try:
            with tempfile.TemporaryDirectory() as td:
                modeld = make_modeld(url, Path(td))
                modeld.mount_stack([make_adapter_bundle_dict()])
                mock.state.fail_erase_slot_ids.add(1)
                with self.assertRaises(StateFlushError):
                    modeld.rollback(reason="test_http_500_erase")
                # Force immediate GC so any unclosed HTTPError emits ResourceWarning under -W error.
                gc.collect()
                self.assertTrue(modeld.status()["state_quarantined"])
                with self.assertRaises(StateFlushError):
                    modeld.infer([{"role": "user", "content": "blocked"}])
        finally:
            mock.stop()

    def test_rejects_raw_lora_override_in_infer(self) -> None:
        mock = MockLlamaServer()
        url = mock.start()
        try:
            with tempfile.TemporaryDirectory() as td:
                modeld = make_modeld(url, Path(td))
                with self.assertRaises(UnverifiedLoraOverrideError):
                    modeld.infer(
                        [{"role": "user", "content": "sneaky override"}],
                        raw_params={"messages": [], "lora": [{"id": 0, "scale": 1.0}]},
                    )
        finally:
            mock.stop()

    def test_signed_jsonl_ledger_chain_and_tamper_detection(self) -> None:
        mock = MockLlamaServer()
        url = mock.start()
        key = b"test-verifier-key-32-bytes-00001"
        signer = HmacSha256Signer(key, key_id="warp-test-hmac-v1")
        try:
            with tempfile.TemporaryDirectory() as td:
                ledger_path = Path(td) / "ledger.jsonl"
                modeld = make_modeld(url, Path(td), signer_key=key)
                modeld.mount_stack([make_adapter_bundle_dict()])
                modeld.rollback(reason="clean_stop")

                receipts = LedgerVerifier.verify_file(ledger_path, signer)
                self.assertEqual([r.event for r in receipts], ["mount", "rollback"])
                self.assertEqual(receipts[1].prev_receipt_sha256, receipts[0].receipt_sha256)

                # Restarting SignedLedger on intact file resumes sequence seamlessly.
                reopened = SignedLedger(ledger_path, signer)
                self.assertEqual(reopened.count, 2)
                self.assertEqual(reopened.head_sha256, receipts[1].receipt_sha256)

                # Wrong signing key fails verification.
                wrong_signer = HmacSha256Signer(b"different-secret-key-32-bytes-99", key_id="warp-test-hmac-v1")
                with self.assertRaises(LedgerTamperError):
                    LedgerVerifier.verify_file(ledger_path, wrong_signer)

                # Tampering 1 field in line 1 breaks receipt_sha256 and signature checks.
                lines = ledger_path.read_text(encoding="utf-8").splitlines()
                rec0 = json.loads(lines[0])
                rec0["reason"] = "tampered_reason"
                tampered_path = Path(td) / "tampered.jsonl"
                tampered_path.write_text("\n".join([json.dumps(rec0), lines[1]]) + "\n", encoding="utf-8")
                with self.assertRaises(LedgerTamperError):
                    LedgerVerifier.verify_file(tampered_path, signer)

                # Deleting line 1 breaks sequence and genesis hash chain.
                truncated_path = Path(td) / "truncated.jsonl"
                truncated_path.write_text(lines[1] + "\n", encoding="utf-8")
                with self.assertRaises(LedgerTamperError):
                    LedgerVerifier.verify_file(truncated_path, signer)

                # Boolean seq (True == 1 in Python) must be rejected.
                bool_seq = json.loads(lines[0])
                bool_seq["seq"] = True
                bool_path = Path(td) / "bool_seq.jsonl"
                bool_path.write_text(json.dumps(bool_seq) + "\n", encoding="utf-8")
                with self.assertRaises(LedgerTamperError):
                    LedgerVerifier.verify_file(bool_path, signer)

                # Unexpected extra key smuggled onto a signed line must be rejected.
                extra_key = json.loads(lines[0])
                extra_key["smuggled"] = "payload"
                extra_path = Path(td) / "extra_key.jsonl"
                extra_path.write_text(json.dumps(extra_key) + "\n", encoding="utf-8")
                with self.assertRaises(LedgerTamperError):
                    LedgerVerifier.verify_file(extra_path, signer)

                # Explicit operator repair preserves broken ledger read-only and reseeds cleanly.
                archive_dir = Path(td) / "archive"
                with self.assertRaises(ValueError):
                    repair_ledger(tampered_path, archive_dir, signer, confirmation="short")
                repaired = repair_ledger(tampered_path, archive_dir, signer, confirmation="root-approved-reseed")
                self.assertTrue(repaired["ok"])
                archived = Path(repaired["archived_path"])
                self.assertTrue(archived.is_file())
                self.assertEqual(archived.stat().st_mode & 0o777, 0o400)
                self.assertEqual(LedgerVerifier.verify_file(tampered_path, signer), [])
        finally:
            mock.stop()


if __name__ == "__main__":
    unittest.main()
