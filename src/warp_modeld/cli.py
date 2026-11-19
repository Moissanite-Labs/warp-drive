"""Command-line interface for warp-modeld."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import signal
import sys
import threading
from typing import Sequence

from .canary import CanarySuite
from .certificate import CertificateBounds, FixedRadixCertificate, verify_division_free
from .errors import WarpError
from .fingerprint import CheckpointFingerprint, Plane1Lineage, RuntimeFlags
from .ledger import HmacSha256Signer, LedgerVerifier, SignedLedger
from .llama_client import LlamaServerClient
from .server import WarpUnixRpcServer
from .verifier import WarpModeld


def _load_key_bytes(key_file: Path) -> bytes:
    raw = key_file.read_bytes().strip()
    if len(raw) < 16:
        raise ValueError(f"signing key in {key_file} must be at least 16 bytes")
    return raw


def _cmd_serve(args: argparse.Namespace) -> int:
    cfg = json.loads(Path(args.config).read_text(encoding="utf-8"))
    checkpoint = CheckpointFingerprint.from_dict(cfg["checkpoint"])
    lineage = Plane1Lineage.from_dict(cfg["pinned_lineage"])
    runtime_flags = RuntimeFlags.from_dict(cfg["runtime_flags"])
    single_bounds = CertificateBounds.from_dict(cfg["single_bounds"])
    joint_bounds = CertificateBounds.from_dict(cfg["joint_bounds"])

    canary_suite = CanarySuite.from_verifier_file(
        cfg["canary_suite_path"],
        expected_sha256=cfg.get("canary_suite_sha256"),
    )
    key_bytes = _load_key_bytes(Path(cfg["ledger_key_path"]))
    signer = HmacSha256Signer(key_bytes, key_id=str(cfg.get("ledger_key_id", "warp-ledger-hmac-v1")))
    ledger = SignedLedger(cfg["ledger_path"], signer)
    llama = LlamaServerClient(
        cfg["llama_server_url"],
        timeout_seconds=float(cfg.get("llama_timeout_seconds", 10.0)),
        require_localhost=bool(cfg.get("require_localhost", True)),
    )

    modeld = WarpModeld(
        pinned_checkpoint=checkpoint,
        pinned_lineage=lineage,
        live_runtime_flags=runtime_flags,
        single_bounds=single_bounds,
        joint_bounds=joint_bounds,
        canary_suite=canary_suite,
        llama_client=llama,
        ledger=ledger,
        canary_slot_id=int(cfg.get("canary_slot_id", 0)),
    )

    server = WarpUnixRpcServer(
        cfg["socket_path"],
        modeld,
        socket_mode=int(str(cfg.get("socket_mode", "0600")), 8),
    )

    stop_event = threading.Event()

    def _handle_signal(_signum: int, _frame: object) -> None:
        stop_event.set()

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)
    server.start()
    try:
        while not stop_event.is_set():
            stop_event.wait(timeout=0.5)
    finally:
        server.stop()
    return 0


def _cmd_verify_ledger(args: argparse.Namespace) -> int:
    key_bytes = _load_key_bytes(Path(args.key_file))
    signer = HmacSha256Signer(key_bytes, key_id=args.key_id)
    receipts = LedgerVerifier.verify_file(args.ledger, signer)
    print(
        json.dumps(
            {
                "ok": True,
                "receipts_verified": len(receipts),
                "head_sha256": receipts[-1].receipt_sha256 if receipts else "0" * 64,
            }
        )
    )
    return 0


def _cmd_check_certificate(args: argparse.Namespace) -> int:
    cert = FixedRadixCertificate.from_dict(json.loads(Path(args.cert).read_text(encoding="utf-8")))
    bounds = CertificateBounds.from_dict(json.loads(Path(args.bounds).read_text(encoding="utf-8")))
    res = verify_division_free(cert, bounds)
    print(
        json.dumps(
            {
                "ok": True,
                "adapter_id": res.adapter_id,
                "cert_sha256": res.cert_sha256,
                "elapsed_us": round(res.elapsed_ns / 1000.0, 2),
            }
        )
    )
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="warp-modeld", description="L3 fail-closed inference gatekeeper")
    sub = parser.add_subparsers(dest="command", required=True)

    serve_p = sub.add_parser("serve", help="Run warp-modeld Unix socket daemon")
    serve_p.add_argument("--config", required=True, help="Path to daemon JSON config")
    serve_p.set_defaults(func=_cmd_serve)

    ledger_p = sub.add_parser("verify-ledger", help="Verify hash chain and signatures of a JSONL ledger")
    ledger_p.add_argument("--ledger", required=True, help="Path to JSONL ledger file")
    ledger_p.add_argument("--key-file", required=True, help="Path to HMAC key file")
    ledger_p.add_argument("--key-id", default="warp-ledger-hmac-v1", help="Expected signing key ID")
    ledger_p.set_defaults(func=_cmd_verify_ledger)

    cert_p = sub.add_parser("check-certificate", help="Run division-free Stage 2 FixedRadixCertificate check")
    cert_p.add_argument("--cert", required=True, help="Path to certificate JSON")
    cert_p.add_argument("--bounds", required=True, help="Path to bounds JSON")
    cert_p.set_defaults(func=_cmd_check_certificate)

    parsed = parser.parse_args(argv)
    try:
        return int(parsed.func(parsed))
    except (WarpError, ValueError, OSError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
