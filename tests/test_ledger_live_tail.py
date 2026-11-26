"""Live-handle ledger tail checks. Local files and a local HMAC key only.

No live endpoint, GPU, model, or paid provider is used. These are logic
checks, never deployment evidence.
"""

import json
import shutil
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


def _rewrite_line(path: Path, line_index: int, field: str, value: str) -> None:
    lines = path.read_text(encoding="utf-8").splitlines()
    entry = json.loads(lines[line_index])
    entry[field] = value
    lines[line_index] = json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


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


class TestVerifyFileFailClosedWD6101(unittest.TestCase):
    """WD61-01: every on-disk tamper mode must surface as LedgerTamperError."""

    def test_directory_substitution_raises_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            signer = HmacSha256Signer(KEY, key_id="warp-test-hmac-v1")
            dir_path = Path(td) / "ledger.jsonl"
            dir_path.mkdir()
            with self.assertRaises(LedgerTamperError):
                LedgerVerifier.verify_file(dir_path, signer)

            live_path = Path(td) / "live.jsonl"
            ledger = SignedLedger(live_path, signer)
            _append(ledger)
            live_path.unlink()
            live_path.mkdir()
            with self.assertRaises(LedgerTamperError):
                _append(ledger, "reject")

    def test_non_utf8_bytes_raise_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "ledger.jsonl"
            signer = HmacSha256Signer(KEY, key_id="warp-test-hmac-v1")
            ledger = SignedLedger(path, signer)
            _append(ledger)
            path.write_bytes(b"\xff\xfe\x00\n")

            with self.assertRaises(LedgerTamperError):
                LedgerVerifier.verify_file(path, signer)
            with self.assertRaises(LedgerTamperError):
                _append(ledger, "reject")
            self.assertEqual(path.read_bytes(), b"\xff\xfe\x00\n")

    def test_non_ascii_hash_and_signature_fields_raise_tamper(self) -> None:
        signer = HmacSha256Signer(KEY, key_id="warp-test-hmac-v1")
        self.assertFalse(signer.verify(b"payload", "\u00e9" * 64))
        for field in ("prev_receipt_sha256", "receipt_sha256", "signature"):
            with tempfile.TemporaryDirectory() as td:
                path = Path(td) / "ledger.jsonl"
                ledger = SignedLedger(path, signer)
                _append(ledger)
                _append(ledger, "rollback")
                _rewrite_line(path, 0, field, "\u00e9" * 64)

                with self.assertRaises(LedgerTamperError, msg=field):
                    LedgerVerifier.verify_file(path, signer)
                with self.assertRaises(LedgerTamperError, msg=field):
                    _append(ledger, "reject")
                self.assertEqual(len(path.read_text(encoding="utf-8").splitlines()), 2)

    def test_missing_file_on_live_handle_raises_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "ledger.jsonl"
            signer = HmacSha256Signer(KEY, key_id="warp-test-hmac-v1")
            ledger = SignedLedger(path, signer)
            _append(ledger)
            _append(ledger, "rollback")
            path.unlink()

            with self.assertRaises(LedgerTamperError) as ctx:
                _append(ledger, "reject")
            self.assertIn("missing or out of sequence", str(ctx.exception))

            # Control: a fresh count==0 handle with no file on disk still appends.
            fresh_path = Path(td) / "fresh.jsonl"
            fresh = SignedLedger(fresh_path, signer)
            _append(fresh)
            self.assertEqual(fresh.count, 1)


class TestUndisturbedTailGuardsWD6102(unittest.TestCase):
    """WD61-02: kill each guard in _require_undisturbed_tail with a valid on-disk chain."""

    def test_external_write_on_fresh_handle_blocks_append(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "ledger.jsonl"
            other_path = Path(td) / "other.jsonl"
            signer = HmacSha256Signer(KEY, key_id="warp-test-hmac-v1")
            fresh = SignedLedger(path, signer)
            self.assertEqual(fresh.count, 0)

            other = SignedLedger(other_path, signer)
            _append(other)
            shutil.copyfile(other_path, path)

            with self.assertRaises(LedgerTamperError) as ctx:
                _append(fresh, "reject")
            self.assertIn("unknown to this handle", str(ctx.exception))
            self.assertEqual(len(path.read_text(encoding="utf-8").splitlines()), 1)

    def test_truncated_tail_blocks_append(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "ledger.jsonl"
            signer = HmacSha256Signer(KEY, key_id="warp-test-hmac-v1")
            ledger = SignedLedger(path, signer)
            _append(ledger)
            _append(ledger, "rollback")

            lines = path.read_text(encoding="utf-8").splitlines()
            path.write_text(lines[0] + "\n", encoding="utf-8")

            with self.assertRaises(LedgerTamperError) as ctx:
                _append(ledger, "reject")
            self.assertIn("missing or out of sequence", str(ctx.exception))
            self.assertEqual(len(path.read_text(encoding="utf-8").splitlines()), 1)

    def test_unlinked_then_external_append_blocks_append(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "ledger.jsonl"
            other_path = Path(td) / "other.jsonl"
            signer = HmacSha256Signer(KEY, key_id="warp-test-hmac-v1")
            ledger = SignedLedger(path, signer)
            _append(ledger)
            _append(ledger, "rollback")
            path.unlink()

            other = SignedLedger(other_path, signer)
            _append(other)
            shutil.copyfile(other_path, path)

            with self.assertRaises(LedgerTamperError) as ctx:
                _append(ledger, "reject")
            self.assertIn("missing or out of sequence", str(ctx.exception))
            self.assertEqual(len(path.read_text(encoding="utf-8").splitlines()), 1)

    def test_same_length_resigned_chain_blocks_append(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "ledger.jsonl"
            other_path = Path(td) / "other.jsonl"
            signer = HmacSha256Signer(KEY, key_id="warp-test-hmac-v1")
            ledger = SignedLedger(path, signer)
            _append(ledger)
            _append(ledger, "rollback")

            other = SignedLedger(other_path, signer)
            _append(other, "reject")
            _append(other, "kill_switch")
            self.assertNotEqual(other.head_sha256, ledger.head_sha256)
            shutil.copyfile(other_path, path)

            with self.assertRaises(LedgerTamperError) as ctx:
                _append(ledger, "reject")
            self.assertIn("head changed", str(ctx.exception))
            self.assertEqual(len(path.read_text(encoding="utf-8").splitlines()), 2)


if __name__ == "__main__":
    unittest.main()
