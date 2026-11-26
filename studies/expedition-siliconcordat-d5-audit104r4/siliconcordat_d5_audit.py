#!/usr/bin/env python3
"""AUDIT-104 Dual-Mode CLI & Provenance Certifier for `siliconcordat#5` + `#15`/`#16`/`#18`.

Modes:
  - Default (`--live`): Reads raw `discussion_5_raw.json` and `discussion_5_full.md` directly
    from `--intake-root` (default: `../intake-siliconcordat-d5`), verifies exact byte counts
    and SHA-256 digests fail-closed (rejecting symlinks and path escapes), scans all pseudocode
    defect witnesses live, executes all 3 Law-2b `aletheia v2.1+` pure-Q invariants, and emits
    `execution_mode: "live_portal_recount"`, `live_portal_recounted: true`.
  - `--standalone`: Explicit offline fixture replay emitting `execution_mode:
    "standalone_fixture_replay"`, `live_portal_recounted: false` with identical `payload_sha256`.
    Missing live inputs NEVER silently fall back to standalone mode.

Zero floats, zero bare asserts, 100% Python 3 stdlib.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
from typing import Any

_SCRIPT_DIR = str(Path(__file__).resolve().parent)
if _SCRIPT_DIR not in sys.path:
    sys.path.insert(0, _SCRIPT_DIR)

import siliconcordat_d5_oracle as oracle  # noqa: E402
from siliconcordat_d5_oracle import CordatAuditError, _require  # noqa: E402

SCHEMA_VERSION = "audit-104.siliconcordat-d5.v1"
AUDIT_ID = "AUDIT-104"
HONEST_TIER = "N0"

PINNED_RAW_JSON_SHA256 = "e5c2b543f7a2cec2a3db56d34f890bdbf5e7cfc658e6fe737439acfc20d73b27"
PINNED_RAW_JSON_BYTES = 309530
PINNED_FULL_MD_SHA256 = "7cd8d8b7eeb7b174bfc40ff7affa6a58353e670ee9572ee16ba3ce160002e950"
PINNED_FULL_MD_BYTES = 296398

DEFAULT_PINS: dict[str, Any] = {
    "discussion_5_raw_json_sha256": PINNED_RAW_JSON_SHA256,
    "discussion_5_raw_json_bytes": PINNED_RAW_JSON_BYTES,
    "discussion_5_full_md_sha256": PINNED_FULL_MD_SHA256,
    "discussion_5_full_md_bytes": PINNED_FULL_MD_BYTES,
}
_EXPECTED_PIN_KEYS = frozenset(DEFAULT_PINS.keys())

# Exact live-recounted portal summary pinned from intake-siliconcordat-d5.
# Used ONLY when `--standalone` is explicitly passed (`live_portal_recounted: false`).
STANDALONE_PINNED_PORTAL: dict[str, Any] = {
    "author": "ahrazzle",
    "created_at": "2026-10-31T07:21:31Z",
    "discussion_number": 5,
    "markdown_line_count": 3891,
    "pseudocode_defect_counts": {
        "comment11_uninitialized_mov_cr3_rax": 2,
        "replies73_101_hash_sum_collision_bug": 7,
        "reply112_fake_fpga_bitstream_magic": 2,
        "reply91_adaptive_decay_blowup_formula": 1,
        "reply91_symp_matrix_scalar_overwrite": 4,
    },
    "pseudocode_defect_total": 16,
    "replies": 20,
    "spliceware_marker_count": 1,
    "title": "the agentic age",
    "top_level_comments": 11,
    "total_entries_incl_op": 32,
    "updated_at": "2026-11-18T04:09:30Z",
}


def canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def canonical_sha256(obj: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(obj)).hexdigest()


def _require_contained_file(root: Path, child: Path, label: str) -> Path:
    _require(not child.is_symlink(), f"symlink-refused:{label}")
    resolved_root = root.resolve()
    resolved_child = child.resolve()
    _require(resolved_child.is_relative_to(resolved_root), f"escape-refused:{label}")
    _require(resolved_child.is_file(), f"file-missing:{label}")
    return resolved_child


def _strict_typed_equal(a: Any, b: Any) -> bool:
    """Recursive exact-type equality distinguishing bool from int (True != 1)."""
    if type(a) is not type(b):
        return False
    if isinstance(a, dict):
        return len(a) == len(b) and all(k in b and _strict_typed_equal(v, b[k]) for k, v in a.items())
    if isinstance(a, (list, tuple)):
        return len(a) == len(b) and all(_strict_typed_equal(x, y) for x, y in zip(a, b))
    return a == b


def verify_portal_provenance(
    intake_root: Path, expected_pins: dict[str, Any] | None = None
) -> tuple[dict[str, Any], Path, Path]:
    """Fail-closed provenance check of staged `intake-siliconcordat-d5` files."""
    pins = DEFAULT_PINS if expected_pins is None else expected_pins
    _require(isinstance(pins, dict) and set(pins.keys()) == _EXPECTED_PIN_KEYS, "pins-keys-exact")
    _require(intake_root.is_dir() and not intake_root.is_symlink(), "intake-root-missing")

    raw_json = _require_contained_file(intake_root, intake_root / "discussion_5_raw.json", "discussion_5_raw.json")
    full_md = _require_contained_file(intake_root, intake_root / "discussion_5_full.md", "discussion_5_full.md")

    raw_bytes = raw_json.read_bytes()
    md_bytes = full_md.read_bytes()
    raw_sha = hashlib.sha256(raw_bytes).hexdigest()
    md_sha = hashlib.sha256(md_bytes).hexdigest()

    _require(len(raw_bytes) == pins["discussion_5_raw_json_bytes"], "pin-mismatch:raw_json_bytes")
    _require(raw_sha == pins["discussion_5_raw_json_sha256"], "pin-mismatch:raw_json_sha256")
    _require(len(md_bytes) == pins["discussion_5_full_md_bytes"], "pin-mismatch:full_md_bytes")
    _require(md_sha == pins["discussion_5_full_md_sha256"], "pin-mismatch:full_md_sha256")

    prov = {
        "discussion_5_raw_json_sha256": raw_sha,
        "discussion_5_raw_json_bytes": len(raw_bytes),
        "discussion_5_full_md_sha256": md_sha,
        "discussion_5_full_md_bytes": len(md_bytes),
        "companion_issues_audited": [
            "Moissanite-Labs/siliconcordat#15",
            "Moissanite-Labs/siliconcordat#16",
            "Moissanite-Labs/siliconcordat#18",
        ],
        "pinned_inputs_verified": True,
    }
    return prov, raw_json, full_md


def assemble_certificate(
    portal: dict[str, Any],
    invariants: dict[str, Any],
    audit_gate: dict[str, Any],
    provenance: dict[str, Any],
    execution_mode: str,
    live_portal_recounted: bool,
) -> dict[str, Any]:
    """Assemble deterministic fail-closed AUDIT-104 certificate envelope."""
    oracle.reject_floats(portal, "portal")
    oracle.reject_floats(invariants, "invariants")
    oracle.reject_floats(audit_gate, "audit_gate")
    oracle.reject_floats(provenance, "provenance")
    _require(
        execution_mode in ("live_portal_recount", "standalone_fixture_replay"),
        f"invalid-exec-mode:{execution_mode}",
    )
    _require(type(live_portal_recounted) is bool, "live-flag-bool")
    _require(
        live_portal_recounted == (execution_mode == "live_portal_recount"),
        "live-flag-mode-mismatch",
    )
    _require(
        isinstance(provenance, dict)
        and type(provenance.get("pinned_inputs_verified")) is bool
        and provenance["pinned_inputs_verified"] == live_portal_recounted,
        "provenance-live-mismatch",
    )
    recomputed_gate = oracle.certify_siliconcordat_d5_audit(portal, invariants)
    _require(
        _strict_typed_equal(audit_gate, recomputed_gate) and recomputed_gate["certified"],
        "audit-gate-not-certified",
    )

    core_payload = {
        "portal_summary": portal,
        "law2b_invariants": invariants,
        "audit_gate": audit_gate,
    }
    payload_sha = canonical_sha256(core_payload)

    envelope: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "audit_id": AUDIT_ID,
        "honest_tier": HONEST_TIER,
        "execution_mode": execution_mode,
        "live_portal_recounted": live_portal_recounted,
        "provenance": provenance,
        "portal_summary": portal,
        "law2b_invariants": invariants,
        "audit_gate": audit_gate,
        "payload_sha256": payload_sha,
    }
    envelope["certificate_sha256"] = canonical_sha256(envelope)
    return envelope


def run_live_audit(intake_root: Path, expected_pins: dict[str, Any] | None = None) -> dict[str, Any]:
    """Run live raw-portal recount, defect scan, all 3 Law-2b invariants, and fail-closed gate."""
    provenance, raw_json, full_md = verify_portal_provenance(intake_root, expected_pins=expected_pins)
    portal = oracle.parse_discussion_5_portal(raw_json, full_md)
    invariants = oracle.run_reference_invariants()
    audit_gate = oracle.certify_siliconcordat_d5_audit(portal, invariants)
    return assemble_certificate(
        portal=portal,
        invariants=invariants,
        audit_gate=audit_gate,
        provenance=provenance,
        execution_mode="live_portal_recount",
        live_portal_recounted=True,
    )


def run_standalone_replay() -> dict[str, Any]:
    """Explicit offline fixture replay (re-runs all 3 pure-Q invariants; pins portal summary)."""
    portal = json.loads(json.dumps(STANDALONE_PINNED_PORTAL))
    invariants = oracle.run_reference_invariants()
    audit_gate = oracle.certify_siliconcordat_d5_audit(portal, invariants)
    provenance = {
        "discussion_5_raw_json_sha256": PINNED_RAW_JSON_SHA256,
        "discussion_5_raw_json_bytes": PINNED_RAW_JSON_BYTES,
        "discussion_5_full_md_sha256": PINNED_FULL_MD_SHA256,
        "discussion_5_full_md_bytes": PINNED_FULL_MD_BYTES,
        "companion_issues_audited": [
            "Moissanite-Labs/siliconcordat#15",
            "Moissanite-Labs/siliconcordat#16",
            "Moissanite-Labs/siliconcordat#18",
        ],
        "pinned_inputs_verified": False,
        "replay_note": "Offline fixture replay; raw portal files were NOT re-read in this invocation.",
    }
    return assemble_certificate(
        portal=portal,
        invariants=invariants,
        audit_gate=audit_gate,
        provenance=provenance,
        execution_mode="standalone_fixture_replay",
        live_portal_recounted=False,
    )


def format_human_summary(cert: dict[str, Any]) -> str:
    p = cert["portal_summary"]
    inv = cert["law2b_invariants"]
    r91 = inv["reply91_decay_refutation"]
    ah_ok = inv["invariant_a_anti_homogenization"]["diverse_with_rogue_outlier_blocked"]
    ah_bad = inv["invariant_a_anti_homogenization"]["monoculture_echo_chamber_vetoed"]
    rt = inv["invariant_b_monotone_ratchet"]["trace_witness"]
    cg = inv["invariant_b_monotone_ratchet"]["calibration_gap_witness"]
    sp_ok = inv["invariant_c_splicer_protocol"]["compliant_graft_witness"]
    sp_bad = inv["invariant_c_splicer_protocol"]["adversarial_violation_witness"]
    lines = [
        f"AUDIT-104 siliconcordat#5 + #15/#16/#18 Law-2b Extraction ({cert['honest_tier']})",
        f"Execution Mode : {cert['execution_mode']} (live_portal_recounted={cert['live_portal_recounted']})",
        f"Certified      : {cert['audit_gate']['certified']}",
        f"Portal #5      : {p['top_level_comments']} comments + {p['replies']} replies + OP = {p['total_entries_incl_op']} entries, "
        f"{p['markdown_line_count']} lines, {p['pseudocode_defect_total']} pseudocode defects detected",
        f"Reply 9.1 Bug  : mult={r91['d5_reply91_multiplier']} ({r91['d5_reply91_multiplier_dec4']}x sign-flip blowup) vs Law-2b {r91['law2b_bounded_mult_at_calm']}..{r91['law2b_bounded_mult_at_peak']}",
        f"Invariant A    : diverse_pass={ah_ok['gate_passed']} (selected={ah_ok['selected_candidate_id']}, D2={ah_ok['effective_diversity_d2']}), monoculture_veto={not ah_bad['gate_passed']}",
        f"Invariant B    : steps={rt['total_steps']} (committed={rt['committed_count']}, edge_snaps={rt['rollback_count']}, spent={rt['total_spent']} of {rt['budget_max']}); "
        f"#16 gap proved={cg['calibration_gap_proved']} (perm drift^2={cg['perm_drift_sq']} R2={cg['perm_r2']} vs flip drift^2={cg['flip_drift_sq']} R2={cg['flip_r2']})",
        f"Invariant C    : compliant_graft={sp_ok['compliant']}, adversarial_violations={len(sp_bad['violations'])}",
        f"Payload SHA256 : {cert['payload_sha256']}",
        f"Cert SHA256    : {cert['certificate_sha256']}",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="AUDIT-104 pure-Q siliconcordat#5 + #15/#16/#18 certifier")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--live", action="store_true", help="Recount raw portal files from --intake-root (default)")
    mode.add_argument(
        "--standalone",
        action="store_true",
        help="Offline fixture replay (explicitly marks live_portal_recounted=false)",
    )
    default_intake = Path(__file__).resolve().parent.parent / "intake-siliconcordat-d5"
    parser.add_argument("--intake-root", type=Path, default=default_intake, help="Path to staged portal directory")
    parser.add_argument("--json", action="store_true", help="Emit canonical JSON certificate to stdout")
    parser.add_argument("--write-cert", type=Path, default=None, help="Write canonical JSON certificate to file")
    args = parser.parse_args(argv)

    if args.standalone:
        cert = run_standalone_replay()
    else:
        cert = run_live_audit(args.intake_root)

    rendered = json.dumps(cert, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    if args.write_cert is not None:
        args.write_cert.write_text(rendered, encoding="utf-8")

    if args.json:
        sys.stdout.write(rendered)
    else:
        sys.stdout.write(format_human_summary(cert) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
