"""Local HTTP mock of the Cerebras OpenAI-compatible chat completions API.

Serves POST /v1/chat/completions with canned OpenAI-shaped responses.
Modes switch the failure the client must survive:

- ok_propose / ok_diagnose / ok_compare: schema-valid canned replies.
- invalid_candidate: a candidate outside the allowed bounds. The client
  must reject it, never clamp it silently.
- malformed_json: message content is not JSON.
- wrong_schema: message content is JSON but not a candidate object.
- non_json_body: the HTTP body itself is not JSON.
- missing_choices: a response object with no choices array.
- empty_content: a choice whose message content is empty.
- wrong_model: a valid reply that reports a different served model id.
  The receipt must record the served id, not the requested one.
- missing_usage: a valid reply with no usage block. Token counts stay None.
- http500: every request fails with 500.
- http429_then_ok: first request fails with 429, the next succeeds.
- slow: sleeps longer than the client timeout before replying.
"""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
import time
from typing import Any


def _chat_response(*, content: str, model: str = "kimi-k3.1-pro", usage: dict[str, int] | None = None) -> dict[str, Any]:
    body: dict[str, Any] = {
        "id": "chatcmpl-mock",
        "object": "chat.completion",
        "created": 1793000000,
        "model": model,
        "choices": [{"index": 0, "message": {"role": "assistant", "content": content}, "finish_reason": "stop"}],
    }
    if usage is not None:
        body["usage"] = usage
    return body


MODE_CONTENT: dict[str, str] = {
    "ok_propose": json.dumps(
        {"target_layer": "last", "strength": 0.5, "rank": 16, "quantization": "q8_0"},
        separators=(",", ":"),
    ),
    "ok_diagnose": json.dumps(
        {"target_layer": "last", "strength": 0.4, "rank": 8, "quantization": "q8_0"},
        separators=(",", ":"),
    ),
    "ok_compare": json.dumps(
        {"preference": "adapted", "reason": "The adapted text adds the river detail without changing the fact.", "confidence": "medium"},
        separators=(",", ":"),
    ),
    "invalid_candidate": json.dumps(
        {"target_layer": "last", "strength": 1.5, "rank": 128, "quantization": "fp32"},
        separators=(",", ":"),
    ),
    "malformed_json": "{not json",
    "wrong_schema": json.dumps({"guess": "a bigger rank would help"}, separators=(",", ":")),
}

DEFAULT_USAGE = {"prompt_tokens": 120, "completion_tokens": 25, "total_tokens": 145}


class MockCerebrasState:
    def __init__(self, mode: str = "ok_propose", *, slow_seconds: float = 0.0) -> None:
        self.mode = mode
        self.slow_seconds = slow_seconds
        self.requests: list[dict[str, Any]] = []
        self.request_count = 0


def _make_handler(state: MockCerebrasState) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args: Any) -> None:
            pass

        def _send(self, status: int, payload: bytes, content_type: str = "application/json") -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length) if length else b""
            try:
                body = json.loads(raw.decode("utf-8")) if raw else {}
            except ValueError:
                body = {"_unparsable": True}
            state.requests.append(body if isinstance(body, dict) else {"_unparsable": True})
            state.request_count += 1
            if self.path != "/v1/chat/completions":
                self._send(404, json.dumps({"error": "not found"}).encode("utf-8"))
                return
            if state.mode == "slow":
                time.sleep(state.slow_seconds)
            if state.mode == "http500":
                self._send(500, json.dumps({"error": {"message": "mock server error"}}).encode("utf-8"))
                return
            if state.mode == "http429_then_ok":
                if state.request_count == 1:
                    self._send(429, json.dumps({"error": {"message": "mock rate limit"}}).encode("utf-8"))
                    return
                payload = _chat_response(content=MODE_CONTENT["ok_propose"], usage=dict(DEFAULT_USAGE))
                self._send(200, json.dumps(payload).encode("utf-8"))
                return
            if state.mode == "non_json_body":
                self._send(200, b"this is not json", "text/plain")
                return
            if state.mode == "missing_choices":
                self._send(200, json.dumps({"id": "x", "model": "kimi-k3.1-pro", "choices": []}).encode("utf-8"))
                return
            if state.mode == "empty_content":
                payload = _chat_response(content="   ", usage=dict(DEFAULT_USAGE))
                self._send(200, json.dumps(payload).encode("utf-8"))
                return
            if state.mode == "wrong_model":
                payload = _chat_response(
                    content=MODE_CONTENT["ok_propose"], model="qwen-3.8-27b", usage=dict(DEFAULT_USAGE)
                )
                self._send(200, json.dumps(payload).encode("utf-8"))
                return
            if state.mode == "missing_model":
                payload = _chat_response(content=MODE_CONTENT["ok_propose"], usage=dict(DEFAULT_USAGE))
                payload.pop("model", None)
                self._send(200, json.dumps(payload).encode("utf-8"))
                return
            if state.mode == "missing_usage":
                payload = _chat_response(content=MODE_CONTENT["ok_propose"], usage=None)
                self._send(200, json.dumps(payload).encode("utf-8"))
                return
            content = MODE_CONTENT.get(state.mode, MODE_CONTENT["ok_propose"])
            payload = _chat_response(content=content, usage=dict(DEFAULT_USAGE))
            self._send(200, json.dumps(payload).encode("utf-8"))

    return Handler


class MockCerebrasServer:
    """Threaded local stand-in for api.cerebras.ai. No network leaves the host."""

    def __init__(self, mode: str = "ok_propose", *, slow_seconds: float = 0.0) -> None:
        self.state = MockCerebrasState(mode, slow_seconds=slow_seconds)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _make_handler(self.state))
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)

    def __enter__(self) -> "MockCerebrasServer":
        self.thread.start()
        return self

    def __exit__(self, *args: Any) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    @property
    def base_url(self) -> str:
        host, port = self.server.server_address[:2]
        return f"http://{host}:{port}"
