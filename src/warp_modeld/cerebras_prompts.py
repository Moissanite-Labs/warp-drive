"""Fixed prompt fixtures for the Cerebras Kimi K3.1 Pro client (lane 6).

Every prompt the client sends is built from the fixed templates in this
module plus validated structured input (numbers and short labels only).
No weights, no checkpoint bytes, and no private data ever enter a prompt.
The controller in lane 5 calls the client; the client never decides
acceptance. Deterministic local scores stay authoritative.

Prompt set version: ``cerebras-kimi-v2``.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

PROMPT_SET_VERSION = "cerebras-kimi-v2"

SYSTEM_PROMPT = (
    "You are a bounded configuration proposer for a last-layer adapter "
    "experiment. Reply with one JSON object only. Never include weights, "
    "file paths, credentials, or text outside the requested JSON object."
)

PROPOSE_USER_TEMPLATE = (
    "Propose one candidate adapter configuration for the pinned last-layer "
    "target. Context (structured measurements only):\n{context_json}\n"
    "Reply with one JSON object with exactly these keys: "
    "target_layer (integer, must be 31), target_tensor (string, must be "
    "\"ffn_up\"), eta (number in [0.002, 0.02]), lambda (one of 0.1, 1, 10, "
    "\"mean_eigenvalue\"), rank (integer, must be 8), lora_scale (number, "
    "one of 0.0 or 1.0), quantization (string, one of \"bf16\", \"f16\", "
    "\"f32\", \"int8\", \"int4\"). No other keys."
)

DIAGNOSE_USER_TEMPLATE = (
    "A candidate failed a deterministic gate. Propose one repair candidate "
    "inside the remaining repair budget. Failure report (structured "
    "measurements only):\n{report_json}\n"
    "Reply with one JSON object with exactly these keys: "
    "target_layer (integer, must be 31), target_tensor (string, must be "
    "\"ffn_up\"), eta (number in [0.002, 0.02]), lambda (one of 0.1, 1, 10, "
    "\"mean_eigenvalue\"), rank (integer, must be 8), lora_scale (number, "
    "one of 0.0 or 1.0), quantization (string, one of \"bf16\", \"f16\", "
    "\"f32\", \"int8\", \"int4\"). No other keys. "
    "Do not repeat the failed candidate unchanged."
)

COMPARE_USER_TEMPLATE = (
    "Compare two fixed textual outputs for task {task_id}. "
    "Baseline output:\n{baseline_text}\nAdapted output:\n{adapted_text}\n"
    "Reply with one JSON object with exactly these keys: preference "
    "(string, one of \"baseline\", \"adapted\", \"tie\"), reason (string, at "
    "most 280 characters), confidence (string, one of \"low\", \"medium\", "
    "\"high\"). No other keys. This comparison is advisory only. "
    "Deterministic task scores decide acceptance."
)


def prompt_sha256(messages: list[dict[str, str]]) -> str:
    """Hash the exact prompt text sent. Receipts carry this hash, never the text."""
    canonical = json.dumps(messages, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def build_propose_messages(context_json: str) -> list[dict[str, str]]:
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": PROPOSE_USER_TEMPLATE.format(context_json=context_json)},
    ]


def build_diagnose_messages(report_json: str) -> list[dict[str, str]]:
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": DIAGNOSE_USER_TEMPLATE.format(report_json=report_json)},
    ]


def build_compare_messages(*, task_id: str, baseline_text: str, adapted_text: str) -> list[dict[str, str]]:
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {
            "role": "user",
            "content": COMPARE_USER_TEMPLATE.format(
                task_id=task_id, baseline_text=baseline_text, adapted_text=adapted_text
            ),
        },
    ]


def _fixture_context() -> dict[str, Any]:
    return {
        "task_summary": "fixed fixture: improve exact task score without losing retention",
        "baseline_metrics": {"task_exact": 0.61, "retention_iid": 0.88, "retention_shifted": 0.71},
        "constraints": {"target_layer": 31, "target_tensor": "ffn_up", "max_repair_rounds": 3},
    }


def _fixture_report() -> dict[str, Any]:
    return {
        "failed_candidate": {
            "target_layer": 31,
            "target_tensor": "ffn_up",
            "eta": 0.02,
            "lambda": 10,
            "rank": 8,
            "lora_scale": 1.0,
            "quantization": "int4",
        },
        "failed_gate": "retention_iid",
        "measurements": {"task_exact": 0.64, "retention_iid": 0.79, "retention_shifted": 0.70},
        "rounds_used": 1,
    }


# Fixed prompt fixture set. Tests run the mock against these exact inputs
# so a prompt change shows up as a hash change, not a silent drift.
FIXED_PROMPT_FIXTURES: tuple[dict[str, Any], ...] = (
    {"name": "propose-baseline", "kind": "propose", "context": _fixture_context()},
    {"name": "diagnose-retention", "kind": "diagnose", "report": _fixture_report()},
    {
        "name": "compare-short",
        "kind": "compare",
        "task_id": "fixture-task-001",
        "baseline_text": "The capital of France is Paris.",
        "adapted_text": "The capital of France is Paris, a city on the Seine.",
    },
)
