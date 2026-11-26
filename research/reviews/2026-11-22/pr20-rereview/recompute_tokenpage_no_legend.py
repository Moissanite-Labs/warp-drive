#!/usr/bin/env python3
"""Bounded, zero-dependency recomputation from the pinned tokenpage raw QA bytes."""
from collections import Counter
from pathlib import Path
import hashlib
import json
import math

SOURCE_COMMIT = "a694232ecd2dca2b568e7c6dda8d38e3515dcf78"
EXPECTED_RAW_SHA256 = "8cc8f1ce33be37a2d2ece4b5dab0722db5772460478551bb2007d319b0508334"
RAW = Path(__file__).with_name("tokenpage-raw-qa.jsonl")
OUT = Path(__file__).with_name("tokenpage-recompute.json")
FIELD_ORDER = ("title", "priority", "scope", "criteria", "dependency")


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def kl_for_cell(rows):
    by_field = {field: [] for field in FIELD_ORDER}
    for row in rows:
        require(row["field"] in by_field, f"unexpected field: {row['field']}")
        by_field[row["field"]].append(row)
    result = 0.0
    counts = {}
    for field in FIELD_ORDER:
        cell = by_field[field]
        require(len(cell) == 24, f"{field}: expected 24 rows, got {len(cell)}")
        counts[field] = len(cell)
        n = len(cell)
        gold_counts = Counter(int(row["gold"]) for row in cell)
        empirical_entropy = -sum(
            (frequency / n) * math.log2(frequency / n)
            for frequency in gold_counts.values()
        )
        mean_negative_log_probability = -sum(
            math.log2(max(float(row["p_gold"]), 1e-12)) for row in cell
        ) / n
        result += empirical_entropy - mean_negative_log_probability
    return result, counts


raw_bytes = RAW.read_bytes()
raw_sha256 = hashlib.sha256(raw_bytes).hexdigest()
require(raw_sha256 == EXPECTED_RAW_SHA256, "pinned raw QA SHA-256 mismatch")
rows = [json.loads(line) for line in raw_bytes.decode("utf-8").splitlines() if line]
require(len(rows) == 952, f"expected 952 total raw QA rows, got {len(rows)}")

values = {}
per_field_counts = {}
for has_legend in (False, True):
    selected = [
        row for row in rows
        if isinstance(row.get("msg"), int)
        and 0 <= row["msg"] < 24
        and row.get("fmt") == "glyph_g1"
        and row.get("legend") is has_legend
    ]
    require(len(selected) == 120, f"legend={has_legend}: expected 120 rows, got {len(selected)}")
    key = "with_legend" if has_legend else "no_legend"
    values[key], per_field_counts[key] = kl_for_cell(selected)

rounded_delta = round(round(values["with_legend"], 4) - round(values["no_legend"], 4), 4)
require(values["no_legend"] == -6.651510759217704, "unexpected no-legend recomputation")
require(values["with_legend"] == -4.8844556181300325, "unexpected with-legend recomputation")
require(rounded_delta == 1.767, "unexpected rounded delta")
output = {
    "schema": "independent-tokenpage-raw-qa-recompute/v1",
    "source_repository": "Moissanite-Labs/tokenpage",
    "source_commit": SOURCE_COMMIT,
    "source_path": "studies/expedition-proper-kl-audit/data/tokenpage_pr5/raw_qa_qwen1.5b.jsonl",
    "raw_qa_sha256": raw_sha256,
    "raw_qa_bytes": len(raw_bytes),
    "raw_qa_rows": len(rows),
    "selected_g1_qa_rows": 240,
    "cell_rows": {"no_legend": 120, "with_legend": 120},
    "per_field_rows": per_field_counts,
    "unrounded_unfloored_empirical_kl_bits": values,
    "rounded_legend_delta_bits": rounded_delta,
    "comparison": {
        "matches_preserved_machine_receipt_no_legend": values["no_legend"] == -6.651510759217704,
        "contradictory_prose_no_legend": -6.651419738969508,
        "prose_value_reproduced": values["no_legend"] == -6.651419738969508,
        "prose_minus_recomputed": -6.651419738969508 - values["no_legend"],
    },
    "scope": "numerical recomputation only; no harness rerun, model execution, or prose edit",
}
text = json.dumps(output, indent=2, sort_keys=True) + "\n"
OUT.write_text(text, encoding="utf-8")
print(text, end="")
print("receipt_sha256=" + hashlib.sha256(text.encode("utf-8")).hexdigest())
