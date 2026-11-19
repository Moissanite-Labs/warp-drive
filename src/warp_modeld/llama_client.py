"""Stdlib HTTP client speaking the llama-server LoRA, slots, and chat completions API."""

from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any
import urllib.error
import urllib.parse
import urllib.request

from .errors import WarpError


class LlamaClientError(WarpError):
    code = "ERR_LLAMA_BACKEND"
    stage = "backend"


@dataclass(frozen=True)
class LlamaAdapterInfo:
    id: int
    path: str
    scale: float


@dataclass(frozen=True)
class LlamaSlotInfo:
    id: int
    is_processing: bool
    n_decoded: int
    active_lora_ids: tuple[int, ...] = ()
    recurrent_state_tainted: bool = False


class LlamaServerClient:
    """HTTP client targeting a local llama-server started with --lora-init-without-apply."""

    def __init__(
        self,
        base_url: str,
        *,
        timeout_seconds: float = 10.0,
        require_localhost: bool = True,
    ) -> None:
        parsed = urllib.parse.urlparse(base_url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise LlamaClientError(f"invalid llama-server URL: {base_url}")
        if require_localhost and parsed.hostname not in ("127.0.0.1", "localhost", "::1"):
            raise LlamaClientError(
                f"refusing non-localhost llama-server endpoint {parsed.hostname} when require_localhost=True"
            )
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds

    def _request(self, method: str, path: str, body: Any | None = None) -> Any:
        url = f"{self.base_url}{path}"
        data: bytes | None = None
        headers = {"Accept": "application/json"}
        if body is not None:
            data = json.dumps(body, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
            headers["Content-Type"] = "application/json"

        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
                raw = resp.read()
                if not raw:
                    return {}
                return json.loads(raw.decode("utf-8"))
        except urllib.error.HTTPError as exc:
            try:
                detail = exc.read().decode("utf-8", errors="replace")
            finally:
                exc.close()
            raise LlamaClientError(f"llama-server HTTP {exc.code} on {method} {path}: {detail}") from exc
        except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
            raise LlamaClientError(f"llama-server request failed on {method} {path}: {exc}") from exc

    def health(self) -> dict[str, Any]:
        res = self._request("GET", "/health")
        if not isinstance(res, dict):
            raise LlamaClientError("unexpected /health payload from llama-server")
        return res

    def list_lora_adapters(self) -> list[LlamaAdapterInfo]:
        res = self._request("GET", "/lora-adapters")
        if not isinstance(res, list):
            raise LlamaClientError("unexpected /lora-adapters payload from llama-server")
        adapters: list[LlamaAdapterInfo] = []
        for entry in res:
            if not isinstance(entry, dict) or "id" not in entry:
                raise LlamaClientError("malformed adapter item in /lora-adapters")
            adapters.append(
                LlamaAdapterInfo(
                    id=int(entry["id"]),
                    path=str(entry.get("path", "")),
                    scale=float(entry.get("scale", 0.0)),
                )
            )
        return adapters

    def set_lora_adapters(self, adapters: list[dict[str, Any]]) -> dict[str, Any]:
        payload = [{"id": int(item["id"]), "scale": float(item["scale"])} for item in adapters]
        res = self._request("POST", "/lora-adapters", payload)
        return res if isinstance(res, dict) else {"result": res}

    def list_slots(self) -> list[LlamaSlotInfo]:
        res = self._request("GET", "/slots")
        if not isinstance(res, list):
            raise LlamaClientError("unexpected /slots payload from llama-server")
        slots: list[LlamaSlotInfo] = []
        for entry in res:
            if not isinstance(entry, dict) or "id" not in entry:
                raise LlamaClientError("malformed slot entry in /slots")
            active_ids = tuple(int(x) for x in entry.get("active_lora_ids", []))
            slots.append(
                LlamaSlotInfo(
                    id=int(entry["id"]),
                    is_processing=bool(entry.get("is_processing", False)),
                    n_decoded=int(entry.get("n_decoded", 0)),
                    active_lora_ids=active_ids,
                    recurrent_state_tainted=bool(entry.get("recurrent_state_tainted", False)),
                )
            )
        return slots

    def erase_slot(self, slot_id: int) -> dict[str, Any]:
        res = self._request("POST", f"/slots/{int(slot_id)}?action=erase", {})
        return res if isinstance(res, dict) else {"result": res}

    def chat_completion(
        self,
        messages: list[dict[str, str]],
        *,
        lora: list[dict[str, Any]],
        temperature: float = 0.0,
        seed: int = 42,
        max_tokens: int = 256,
        cache_prompt: bool = False,
        id_slot: int | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "messages": messages,
            "temperature": temperature,
            "seed": seed,
            "max_tokens": max_tokens,
            "cache_prompt": cache_prompt,
            "lora": [{"id": int(a["id"]), "scale": float(a["scale"])} for a in lora],
        }
        if id_slot is not None:
            payload["id_slot"] = int(id_slot)
        res = self._request("POST", "/v1/chat/completions", payload)
        if not isinstance(res, dict):
            raise LlamaClientError("unexpected /v1/chat/completions payload from llama-server")
        return res
