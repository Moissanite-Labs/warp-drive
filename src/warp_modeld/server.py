"""Local Unix domain socket JSON-RPC 2.0 server and client for warp-modeld."""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
import socket
import socketserver
import threading
from typing import Any

from .errors import WarpError
from .fingerprint import Plane1Lineage
from .verifier import WarpModeld

MAX_REQUEST_BYTES = 2 * 1024 * 1024  # 2 MiB hard frame ceiling


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate JSON key rejected: {key!r}")
        out[key] = value
    return out


def loads_strict_json(raw_text: str) -> Any:
    """Parse JSON while failing closed on duplicate object keys."""
    return json.loads(raw_text, object_pairs_hook=_reject_duplicate_json_keys)


class _WarpRpcHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        server: _WarpUnixStreamServer = self.server  # type: ignore[assignment]
        while True:
            raw_line = self.rfile.readline(MAX_REQUEST_BYTES + 1)
            if not raw_line:
                return
            if len(raw_line) > MAX_REQUEST_BYTES:
                self._send(
                    {
                        "jsonrpc": "2.0",
                        "id": None,
                        "error": {"code": -32600, "message": "request exceeds 2 MiB ceiling"},
                    }
                )
                return
            response = server.dispatch_line(raw_line)
            self._send(response)

    def _send(self, payload: dict[str, Any]) -> None:
        wire = (json.dumps(payload, separators=(",", ":"), ensure_ascii=True) + "\n").encode("utf-8")
        self.wfile.write(wire)
        self.wfile.flush()


class _WarpUnixStreamServer(socketserver.ThreadingUnixStreamServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, socket_path: str, modeld: WarpModeld) -> None:
        self.modeld = modeld
        super().__init__(socket_path, _WarpRpcHandler)

    def dispatch_line(self, raw_line: bytes) -> dict[str, Any]:
        req_id: Any = None
        try:
            req = loads_strict_json(raw_line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            return {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": f"invalid JSON: {exc}"},
            }

        if not isinstance(req, dict):
            return {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32600, "message": "request must be a JSON object"},
            }

        req_id = req.get("id")
        method = req.get("method")
        params = req.get("params", {})
        if not isinstance(method, str) or not isinstance(params, dict):
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32600, "message": "method must be a string and params must be an object"},
            }

        try:
            result = self._dispatch_method(method, params)
            return {"jsonrpc": "2.0", "id": req_id, "result": result}
        except WarpError as exc:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {
                    "code": -32000,
                    "message": str(exc),
                    "data": exc.to_dict(),
                },
            }
        except KeyError as exc:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32602, "message": f"missing parameter: {exc}"},
            }
        except Exception as exc:  # pragma: no cover - defensive fail-closed boundary
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32603, "message": f"internal error: {exc}"},
            }

    def _dispatch_method(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        if method == "wmcp_checkpoint_identify":
            return self.modeld.identify_checkpoint()

        if method == "wmcp_slot_status":
            return self.modeld.status()

        if method == "wmcp_slot_mount":
            res = self.modeld.mount_stack(
                params["bundles"],
                raw_composed_certificate=params.get("composed_certificate"),
                expected_zone_manifest_id=params.get("zone_manifest_id"),
            )
            return {
                "slot_manifest_digest": res.slot_manifest_digest,
                "active_adapters": list(res.active_adapters),
                "slots_flushed": list(res.slots_flushed),
                "bank_flush_receipts": [r.to_dict() for r in res.bank_flush_receipts],
                "stage2_elapsed_ns": res.stage2_result.elapsed_ns,
                "canaries_passed": len(res.stage3_result.outcomes),
                "zone_manifest_id": self.modeld.pinned_zone_manifest_id,
                "receipt": res.receipt.to_dict(),
            }

        if method == "wmcp_slot_unmount":
            res = self.modeld.rollback(
                reason=str(params.get("reason", "wmcp_slot_unmount")),
                engage_kill_switch=False,
            )
            return {
                "reason": res.reason,
                "kill_switch_engaged": res.kill_switch_engaged,
                "slots_flushed": list(res.slots_flushed),
                "bank_flush_receipts": [r.to_dict() for r in res.bank_flush_receipts],
                "elapsed_ms": res.elapsed_ms,
                "receipt": res.receipt.to_dict(),
            }

        if method == "warp_kill_switch":
            res = self.modeld.rollback(
                reason=str(params.get("reason", "operator_kill_switch")),
                engage_kill_switch=True,
            )
            return {
                "reason": res.reason,
                "kill_switch_engaged": res.kill_switch_engaged,
                "slots_flushed": list(res.slots_flushed),
                "bank_flush_receipts": [r.to_dict() for r in res.bank_flush_receipts],
                "elapsed_ms": res.elapsed_ms,
                "receipt": res.receipt.to_dict(),
            }

        if method == "warp_reset_kill_switch":
            return self.modeld.reset_kill_switch(str(params.get("confirmation", "")))

        if method == "warp_set_learning":
            enabled = bool(params["enabled"])
            rb = self.modeld.set_learning_enabled(enabled)
            return {
                "status": self.modeld.status(),
                "rollback_receipt": rb.receipt.to_dict() if rb is not None else None,
            }

        if method == "warp_update_lineage":
            new_lineage = Plane1Lineage.from_dict(params["lineage"])
            rb = self.modeld.update_pinned_lineage(new_lineage)
            return {
                "status": self.modeld.status(),
                "rollback_receipt": rb.receipt.to_dict() if rb is not None else None,
            }

        if method == "warp_update_zone_manifest":
            if "zone_manifest" in params:
                target = params["zone_manifest"]
            elif "zone_manifest_id" in params:
                target = params["zone_manifest_id"]
            else:
                raise KeyError("zone_manifest or zone_manifest_id")
            rb = self.modeld.update_zone_manifest(target)
            return {
                "status": self.modeld.status(),
                "rollback_receipt": rb.receipt.to_dict() if rb is not None else None,
            }

        if method == "warp_infer":
            messages = params["messages"]
            if not isinstance(messages, list):
                raise WarpError("messages must be a list", code="ERR_INVALID_PARAMS", stage="stage4_proxy")
            return self.modeld.infer(
                messages,
                temperature=float(params.get("temperature", 0.0)),
                seed=int(params.get("seed", 42)),
                max_tokens=int(params.get("max_tokens", 256)),
                raw_params=params,
                expected_zone_manifest_id=params.get("zone_manifest_id"),
            )

        if method == "warp_complete":
            prompt = params["prompt"]
            if not isinstance(prompt, str):
                raise WarpError("prompt must be a string", code="ERR_INVALID_PARAMS", stage="stage4_proxy")
            return self.modeld.complete(
                prompt,
                temperature=float(params.get("temperature", 0.0)),
                seed=int(params.get("seed", 42)),
                n_predict=int(params.get("n_predict", 64)),
                raw_params=params,
                expected_zone_manifest_id=params.get("zone_manifest_id"),
            )

        raise WarpError(f"unknown RPC method: {method}", code="ERR_METHOD_NOT_FOUND", stage="rpc")


class WarpUnixRpcServer:
    """Lifecycle wrapper around the local Unix socket RPC server."""

    def __init__(self, socket_path: str | Path, modeld: WarpModeld, *, socket_mode: int = 0o600) -> None:
        self.socket_path = Path(socket_path)
        self.modeld = modeld
        self.socket_mode = socket_mode
        self._server: _WarpUnixStreamServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self.socket_path.parent.mkdir(parents=True, exist_ok=True)
        if self.socket_path.exists():
            self.socket_path.unlink()
        self._server = _WarpUnixStreamServer(str(self.socket_path), self.modeld)
        os.chmod(self.socket_path, self.socket_mode)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True, name="warp-modeld-rpc")
        self._thread.start()

    def serve_forever(self) -> None:
        self.socket_path.parent.mkdir(parents=True, exist_ok=True)
        if self.socket_path.exists():
            self.socket_path.unlink()
        self._server = _WarpUnixStreamServer(str(self.socket_path), self.modeld)
        os.chmod(self.socket_path, self.socket_mode)
        try:
            self._server.serve_forever()
        finally:
            self.stop()

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None
        try:
            self.socket_path.unlink(missing_ok=True)
        except OSError as exc:
            logging.getLogger(__name__).warning("failed to remove socket %s: %s", self.socket_path, exc)


class WarpUnixRpcClient:
    """Minimal newline-delimited JSON-RPC 2.0 client over a local Unix socket."""

    def __init__(self, socket_path: str | Path, *, timeout_seconds: float = 10.0) -> None:
        self.socket_path = str(socket_path)
        self.timeout_seconds = timeout_seconds
        self._next_id = 1

    def call(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        req_id = self._next_id
        self._next_id += 1
        payload = {"jsonrpc": "2.0", "id": req_id, "method": method, "params": params or {}}
        wire = (json.dumps(payload, separators=(",", ":"), ensure_ascii=True) + "\n").encode("utf-8")

        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(self.timeout_seconds)
            sock.connect(self.socket_path)
            sock.sendall(wire)
            chunks: list[bytes] = []
            while True:
                data = sock.recv(65536)
                if not data:
                    break
                chunks.append(data)
                if b"\n" in data:
                    break

        raw_resp = b"".join(chunks).splitlines()[0]
        return json.loads(raw_resp.decode("utf-8"))
