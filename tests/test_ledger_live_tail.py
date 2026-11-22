"""Live-handle ledger tail checks. Local files and a local HMAC key only.

No live endpoint, GPU, model, or paid provider is used. These are logic
checks, never deployment evidence.
"""

import json
import tempfile
import unittest
from pathlib import Path

from warp_modeld.errors import LedgerTamperError
from warp_modeld.ledger import HmacSha256Signer, LedgerVerifier, SignedLedger

KEY = b"test-ledger-key-32-bytes-000000000000"


def _append(ledger: SignedLedger, event: str = "mount"):
    return ledger.append(
        event,
        checkpoint_fingerprint_sha256="a" * 64,
        runtime_flags_sha256="b" * 64,
        slot_manifest_digest=None,
    )


class TestLiveLedgerTail(unittest.TestCase):
    def test_tamper_after_open_blocks_append(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "ledger.jsonl"
            signer = HmacSha256Signer(KEY, key_id="warp-test-hmac-v1")
            ledger = SignedLedger(path, signer)
            _append(ledger)
            _append(ledger, "rollback")

            lines = path.read_text(encoding="utf-8").splitlines()
            entry = json.loads(lines[0])
            entry["reason"] = "tampered_reason"
            lines[0] = json.dumps(entry, sort_keys=True, separators=(",", ":"))
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")

            with self.assertRaises(LedgerTamperError):
                _append(ledger, "reject")
            self.assertEqual(len(path.read_text(encoding="utf-8").splitlines()), 2)
            with self.assertRaises(LedgerTamperError):
                LedgerVerifier.verify_file(path, signer)

    def test_clean_handle_appends_and_verifies(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "ledger.jsonl"
            signer = HmacSha256Signer(KEY, key_id="warp-test-hmac-v1")
            ledger = SignedLedger(path, signer)
            first = _append(ledger)
            second = _append(ledger, "rollback")

            self.assertEqual(second.seq, 2)
            self.assertEqual(second.prev_receipt_sha256, first.receipt_sha256)
            self.assertEqual(len(LedgerVerifier.verify_file(path, signer)), 2)


if __name__ == "__main__":
    unittest.main()
