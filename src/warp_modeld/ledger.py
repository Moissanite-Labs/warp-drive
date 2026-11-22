"""Stage 4 append-only hash-chained signed JSONL receipt ledger."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
from typing import Any, Protocol, Sequence

from .errors import LedgerTamperError

GENESIS_HASH = "0" * 64
VALID_EVENTS = frozenset({"mount", "reject", "rollback", "kill_switch"})
REDACTED_PLACEHOLDER = "[REDACTED]"

_SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----"
        ),
        REDACTED_PLACEHOLDER,
    ),
    (
        re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"),
        REDACTED_PLACEHOLDER,
    ),
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), REDACTED_PLACEHOLDER),
    (re.compile(r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{16,}\b"), REDACTED_PLACEHOLDER),
    (re.compile(r"(?i)\b(Bearer\s+)[A-Za-z0-9._~+/=-]{16,}"), r"\1" + REDACTED_PLACEHOLDER),
    (
        re.compile(
            r'(?i)(\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|private[_-]?key|password)\s*[:=]\s*)'
            r'(?!sha256:)(?!\[REDACTED\])["\']?([^\s"\',;}{]{8,})["\']?'
        ),
        r"\1" + REDACTED_PLACEHOLDER,
    ),
)


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate JSON key rejected: {key!r}")
        out[key] = value
    return out


def _reject_nonfinite_json(token: str) -> Any:
    raise ValueError(f"non-finite JSON constant rejected: {token!r}")


def _loads_strict_json(raw_text: str) -> Any:
    return json.loads(
        raw_text,
        object_pairs_hook=_reject_duplicate_json_keys,
        parse_constant=_reject_nonfinite_json,
    )


def _redact_secrets(value: Any) -> Any:
    """Recursively redact credential-like patterns before JSON serialization."""
    if isinstance(value, str):
        out = value
        for pat, repl in _SECRET_PATTERNS:
            out = pat.sub(repl, out)
        return out
    if isinstance(value, dict):
        return {
            (_redact_secrets(k) if isinstance(k, str) else k): _redact_secrets(v)
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [_redact_secrets(item) for item in value]
    if isinstance(value, tuple):
        return [_redact_secrets(item) for item in value]
    return value


def _write_all_and_fsync(fd: int, data: bytes) -> None:
    view = memoryview(data)
    written = 0
    while written < len(view):
        n = os.write(fd, view[written:])
        if n <= 0:
            raise OSError("short write returned 0 bytes")
        written += n
    os.fsync(fd)


def _canonical_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


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
        if raw_text == "":
            return []
        if not raw_text.strip():
            raise LedgerTamperError("ledger file contains only whitespace (tampered or wiped)")

        for line_no, raw_line in enumerate(raw_text.splitlines(), start=1):
            if not raw_line.strip():
                raise LedgerTamperError(f"ledger line {line_no}: unexpected blank line")
            try:
                record = _loads_strict_json(raw_line)
            except (json.JSONDecodeError, ValueError) as exc:
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

            if type(record["seq"]) is not int or record["seq"] != expected_seq:
                raise LedgerTamperError(
                    f"ledger line {line_no}: expected integer seq {expected_seq}, got {record['seq']!r}"
                )
            if not isinstance(record["slots_flushed"], list) or any(
                type(s) is not int for s in record["slots_flushed"]
            ):
                raise LedgerTamperError(f"ledger line {line_no}: slots_flushed must be a list of integers")
            if not isinstance(record["adapters"], list) or not isinstance(record["details"], dict):
                raise LedgerTamperError(f"ledger line {line_no}: adapters must be a list and details must be an object")
            if not isinstance(record["timestamp_utc"], str) or not isinstance(record["reason"], str):
                raise LedgerTamperError(f"ledger line {line_no}: timestamp_utc and reason must be strings")
            if not isinstance(record["event"], str) or record["event"] not in VALID_EVENTS:
                raise LedgerTamperError(f"ledger line {line_no}: invalid event '{record['event']}'")
            if not isinstance(record["prev_receipt_sha256"], str) or not hmac.compare_digest(
                record["prev_receipt_sha256"], expected_prev
            ):
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
            if not isinstance(record["receipt_sha256"], str) or not hmac.compare_digest(
                record["receipt_sha256"], recomputed_sha
            ):
                raise LedgerTamperError(f"ledger line {line_no}: receipt_sha256 mismatch (body tampered)")

            if record["sig_alg"] != signer.algorithm or record["key_id"] != signer.key_id:
                raise LedgerTamperError(
                    f"ledger line {line_no}: signer mismatch ({record['sig_alg']}/{record['key_id']})"
                )

            sig_input = f"{record['receipt_sha256']}:{record['sig_alg']}:{record['key_id']}".encode("ascii")
            if not isinstance(record["signature"], str) or not signer.verify(sig_input, record["signature"]):
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
        adapters_list = [_redact_secrets(dict(a)) for a in adapters]
        flushed_list = [int(s) for s in slots_flushed]
        safe_reason = str(_redact_secrets(reason))
        details_dict = _redact_secrets(dict(details or {}))

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
            "reason": safe_reason,
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
            reason=safe_reason,
            slots_flushed=tuple(flushed_list),
            details=details_dict,
            receipt_sha256=receipt_sha256,
            sig_alg=self.signer.algorithm,
            key_id=self.signer.key_id,
            signature=signature,
        )

        line = (
            json.dumps(
                receipt.to_dict(),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            )
            + "\n"
        )
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
        fd = os.open(self.path, flags, 0o600)
        try:
            _write_all_and_fsync(fd, line.encode("utf-8"))
        finally:
            os.close(fd)

        self._next_seq += 1
        self._prev_hash = receipt_sha256
        return receipt


def repair_ledger(
    ledger_path: str | Path,
    archive_dir: str | Path,
    signer: ReceiptSigner,
    *,
    confirmation: str,
) -> dict[str, Any]:
    """Explicit operator-only ledger repair that preserves prior history read-only before reseeding.

    Never deletes or overwrites prior ledger evidence. Moves any existing ledger file into a
    timestamped read-only archive with a SHA-256 digest file, then initializes a fresh ledger.
    """
    if not isinstance(confirmation, str) or len(confirmation.strip()) < 8:
        raise ValueError("explicit operator confirmation (at least 8 chars) is required for ledger repair")

    src = Path(ledger_path)
    arch_root = Path(archive_dir)
    arch_root.mkdir(parents=True, exist_ok=True)

    archived_path: str | None = None
    archived_sha256: str | None = None

    if src.exists():
        raw = src.read_bytes()
        archived_sha256 = hashlib.sha256(raw).hexdigest()
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        dest = arch_root / f"{src.stem}.{stamp}.archived.jsonl"
        excl_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        dest_fd = os.open(dest, excl_flags, 0o400)
        try:
            _write_all_and_fsync(dest_fd, raw)
        finally:
            os.close(dest_fd)
        os.chmod(dest, 0o400)
        digest_file = arch_root / f"{src.stem}.{stamp}.archived.sha256"
        digest_bytes = f"{archived_sha256}  {dest.name}\n".encode("utf-8")
        dig_fd = os.open(digest_file, excl_flags, 0o400)
        try:
            _write_all_and_fsync(dig_fd, digest_bytes)
        finally:
            os.close(dig_fd)
        os.chmod(digest_file, 0o400)
        src.unlink()
        archived_path = str(dest)

    fresh = SignedLedger(src, signer)
    return {
        "ok": True,
        "archived_path": archived_path,
        "archived_sha256": archived_sha256,
        "new_ledger_path": str(fresh.path),
        "new_head_sha256": fresh.head_sha256,
    }
