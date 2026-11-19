"""Stage 4 append-only hash-chained signed JSONL receipt ledger."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
from typing import Any, Protocol, Sequence

from .errors import LedgerTamperError

GENESIS_HASH = "0" * 64
VALID_EVENTS = frozenset({"mount", "reject", "rollback", "kill_switch"})


def _canonical_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


class ReceiptSigner(Protocol):
    algorithm: str
    key_id: str

    def sign(self, payload: bytes) -> str: ...

    def verify(self, payload: bytes, signature: str) -> bool: ...


class HmacSha256Signer:
    """Zero-dependency constant-time HMAC-SHA256 signer held outside L4."""

    algorithm = "hmac-sha256"

    def __init__(self, secret_key: bytes, *, key_id: str = "warp-ledger-hmac-v1") -> None:
        if not isinstance(secret_key, (bytes, bytearray)) or len(secret_key) < 16:
            raise ValueError("secret_key must be at least 16 bytes")
        if not key_id.strip():
            raise ValueError("key_id must be non-empty")
        self._key = bytes(secret_key)
        self.key_id = key_id

    def sign(self, payload: bytes) -> str:
        return hmac.new(self._key, payload, hashlib.sha256).hexdigest()

    def verify(self, payload: bytes, signature: str) -> bool:
        expected = self.sign(payload)
        return isinstance(signature, str) and hmac.compare_digest(expected, signature)


@dataclass(frozen=True)
class LedgerReceipt:
    seq: int
    timestamp_utc: str
    event: str
    prev_receipt_sha256: str
    checkpoint_fingerprint_sha256: str
    runtime_flags_sha256: str
    slot_manifest_digest: str | None
    adapters: tuple[dict[str, Any], ...]
    stage_failed: str | None
    error_code: str | None
    reason: str
    slots_flushed: tuple[int, ...]
    details: dict[str, Any]
    receipt_sha256: str
    sig_alg: str
    key_id: str
    signature: str

    def body_dict(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "timestamp_utc": self.timestamp_utc,
            "event": self.event,
            "prev_receipt_sha256": self.prev_receipt_sha256,
            "checkpoint_fingerprint_sha256": self.checkpoint_fingerprint_sha256,
            "runtime_flags_sha256": self.runtime_flags_sha256,
            "slot_manifest_digest": self.slot_manifest_digest,
            "adapters": list(self.adapters),
            "stage_failed": self.stage_failed,
            "error_code": self.error_code,
            "reason": self.reason,
            "slots_flushed": list(self.slots_flushed),
            "details": self.details,
        }

    def to_dict(self) -> dict[str, Any]:
        out = self.body_dict()
        out.update(
            {
                "receipt_sha256": self.receipt_sha256,
                "sig_alg": self.sig_alg,
                "key_id": self.key_id,
                "signature": self.signature,
            }
        )
        return out


class LedgerVerifier:
    """Verifies chain continuity, canonical hashes, and signatures of a JSONL ledger."""

    @staticmethod
    def verify_file(path: str | Path, signer: ReceiptSigner) -> list[LedgerReceipt]:
        file_path = Path(path)
        if not file_path.exists():
            return []

        receipts: list[LedgerReceipt] = []
        expected_prev = GENESIS_HASH
        expected_seq = 1

        raw_text = file_path.read_text(encoding="utf-8")
        if not raw_text.strip():
            return []

        for line_no, raw_line in enumerate(raw_text.splitlines(), start=1):
            if not raw_line.strip():
                raise LedgerTamperError(f"ledger line {line_no}: unexpected blank line")
            try:
                record = json.loads(raw_line)
            except json.JSONDecodeError as exc:
                raise LedgerTamperError(f"ledger line {line_no}: invalid JSON: {exc}") from exc

            if not isinstance(record, dict):
                raise LedgerTamperError(f"ledger line {line_no}: record must be a JSON object")

            required = (
                "seq",
                "timestamp_utc",
                "event",
                "prev_receipt_sha256",
                "checkpoint_fingerprint_sha256",
                "runtime_flags_sha256",
                "slot_manifest_digest",
                "adapters",
                "stage_failed",
                "error_code",
                "reason",
                "slots_flushed",
                "details",
                "receipt_sha256",
                "sig_alg",
                "key_id",
                "signature",
            )
            required_set = set(required)
            record_keys = set(record.keys())
            missing_keys = sorted(required_set - record_keys)
            if missing_keys:
                raise LedgerTamperError(f"ledger line {line_no}: missing field(s) {missing_keys}")
            extra_keys = sorted(record_keys - required_set)
            if extra_keys:
                raise LedgerTamperError(f"ledger line {line_no}: unexpected extra field(s) {extra_keys}")

            if isinstance(record["seq"], bool) or not isinstance(record["seq"], int) or record["seq"] != expected_seq:
                raise LedgerTamperError(
                    f"ledger line {line_no}: expected integer seq {expected_seq}, got {record['seq']!r}"
                )
            if not isinstance(record["slots_flushed"], list) or any(
                isinstance(s, bool) or not isinstance(s, int) for s in record["slots_flushed"]
            ):
                raise LedgerTamperError(f"ledger line {line_no}: slots_flushed must be a list of integers")
            if record["event"] not in VALID_EVENTS:
                raise LedgerTamperError(f"ledger line {line_no}: invalid event '{record['event']}'")
            if not hmac.compare_digest(str(record["prev_receipt_sha256"]), expected_prev):
                raise LedgerTamperError(
                    f"ledger line {line_no}: prev_receipt_sha256 mismatch "
                    f"(expected {expected_prev}, got {record['prev_receipt_sha256']})"
                )

            body = {
                "seq": record["seq"],
                "timestamp_utc": record["timestamp_utc"],
                "event": record["event"],
                "prev_receipt_sha256": record["prev_receipt_sha256"],
                "checkpoint_fingerprint_sha256": record["checkpoint_fingerprint_sha256"],
                "runtime_flags_sha256": record["runtime_flags_sha256"],
                "slot_manifest_digest": record["slot_manifest_digest"],
                "adapters": record["adapters"],
                "stage_failed": record["stage_failed"],
                "error_code": record["error_code"],
                "reason": record["reason"],
                "slots_flushed": record["slots_flushed"],
                "details": record["details"],
            }
            body_bytes = _canonical_bytes(body)
            recomputed_sha = hashlib.sha256(body_bytes).hexdigest()
            if not hmac.compare_digest(str(record["receipt_sha256"]), recomputed_sha):
                raise LedgerTamperError(f"ledger line {line_no}: receipt_sha256 mismatch (body tampered)")

            if record["sig_alg"] != signer.algorithm or record["key_id"] != signer.key_id:
                raise LedgerTamperError(
                    f"ledger line {line_no}: signer mismatch ({record['sig_alg']}/{record['key_id']})"
                )

            sig_input = f"{record['receipt_sha256']}:{record['sig_alg']}:{record['key_id']}".encode("ascii")
            if not signer.verify(sig_input, str(record["signature"])):
                raise LedgerTamperError(f"ledger line {line_no}: invalid cryptographic signature")

            receipt = LedgerReceipt(
                seq=int(record["seq"]),
                timestamp_utc=str(record["timestamp_utc"]),
                event=str(record["event"]),
                prev_receipt_sha256=str(record["prev_receipt_sha256"]),
                checkpoint_fingerprint_sha256=str(record["checkpoint_fingerprint_sha256"]),
                runtime_flags_sha256=str(record["runtime_flags_sha256"]),
                slot_manifest_digest=record["slot_manifest_digest"],
                adapters=tuple(record["adapters"]),
                stage_failed=record["stage_failed"],
                error_code=record["error_code"],
                reason=str(record["reason"]),
                slots_flushed=tuple(int(s) for s in record["slots_flushed"]),
                details=dict(record["details"]),
                receipt_sha256=recomputed_sha,
                sig_alg=str(record["sig_alg"]),
                key_id=str(record["key_id"]),
                signature=str(record["signature"]),
            )
            receipts.append(receipt)
            expected_prev = recomputed_sha
            expected_seq += 1

        return receipts


class SignedLedger:
    """Append-only signed JSONL ledger with fail-closed startup chain verification."""

    def __init__(self, path: str | Path, signer: ReceiptSigner) -> None:
        self.path = Path(path)
        self.signer = signer
        self.path.parent.mkdir(parents=True, exist_ok=True)

        existing = LedgerVerifier.verify_file(self.path, self.signer)
        if existing:
            self._next_seq = existing[-1].seq + 1
            self._prev_hash = existing[-1].receipt_sha256
        else:
            self._next_seq = 1
            self._prev_hash = GENESIS_HASH

    @property
    def head_sha256(self) -> str:
        return self._prev_hash

    @property
    def count(self) -> int:
        return self._next_seq - 1

    def append(
        self,
        event: str,
        *,
        checkpoint_fingerprint_sha256: str,
        runtime_flags_sha256: str,
        slot_manifest_digest: str | None,
        adapters: Sequence[dict[str, Any]] = (),
        stage_failed: str | None = None,
        error_code: str | None = None,
        reason: str = "",
        slots_flushed: Sequence[int] = (),
        details: dict[str, Any] | None = None,
    ) -> LedgerReceipt:
        if event not in VALID_EVENTS:
            raise ValueError(f"unsupported ledger event: {event}")

        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        adapters_list = [dict(a) for a in adapters]
        flushed_list = [int(s) for s in slots_flushed]
        details_dict = dict(details or {})

        body = {
            "seq": self._next_seq,
            "timestamp_utc": timestamp,
            "event": event,
            "prev_receipt_sha256": self._prev_hash,
            "checkpoint_fingerprint_sha256": checkpoint_fingerprint_sha256,
            "runtime_flags_sha256": runtime_flags_sha256,
            "slot_manifest_digest": slot_manifest_digest,
            "adapters": adapters_list,
            "stage_failed": stage_failed,
            "error_code": error_code,
            "reason": reason,
            "slots_flushed": flushed_list,
            "details": details_dict,
        }
        receipt_sha256 = hashlib.sha256(_canonical_bytes(body)).hexdigest()
        sig_input = f"{receipt_sha256}:{self.signer.algorithm}:{self.signer.key_id}".encode("ascii")
        signature = self.signer.sign(sig_input)

        receipt = LedgerReceipt(
            seq=self._next_seq,
            timestamp_utc=timestamp,
            event=event,
            prev_receipt_sha256=self._prev_hash,
            checkpoint_fingerprint_sha256=checkpoint_fingerprint_sha256,
            runtime_flags_sha256=runtime_flags_sha256,
            slot_manifest_digest=slot_manifest_digest,
            adapters=tuple(adapters_list),
            stage_failed=stage_failed,
            error_code=error_code,
            reason=reason,
            slots_flushed=tuple(flushed_list),
            details=details_dict,
            receipt_sha256=receipt_sha256,
            sig_alg=self.signer.algorithm,
            key_id=self.signer.key_id,
            signature=signature,
        )

        line = json.dumps(receipt.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
        fd = os.open(self.path, flags, 0o600)
        try:
            os.write(fd, line.encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)

        self._next_seq += 1
        self._prev_hash = receipt_sha256
        return receipt
