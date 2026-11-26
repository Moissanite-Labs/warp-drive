#!/usr/bin/env python3
r"""Wave 2 Round 6 — Arm R6-4 (`AUDIT-064`): Governed Weight Iteration & Multi-Bank State Isolation Bridge.

Zero-float pure Python 3 stdlib (`int`, `fractions.Fraction`) bridge for `Moissanite-Labs/warp-drive`
(Issue `#3`, `state_banks.py`, `verifier.py`, `fingerprint.py`, `canary.py`, `test_lattice_state_isolation.py`),
uniting:
  - Pillar 1: Live-reproduced multi-bank state-isolation & flush defects (`WD-SB-01`..`WD-SB-04`) on
              `warp-drive main@e3899d3` + hardened fail-closed multi-bank flush gates.
  - Pillar 2: Exact pure-Q 3-layer hybrid GDN+KV+Lattice causal propagation theorems (`WI-1`..`WI-3`)
              paired with live zero-float empirical census of all 32 layers & 72,553 direct circuit wires
              of `Qwen3.5-4B` (`4b.html`, `AUDIT-059`) explaining `ml-os#6`'s `blk.31` isolation.
  - Pillar 3: Exact pure-Q Fisher-KL vs. Euclidean residual inversion theorem (`WI-4`, explaining
              `ml-os#6`'s `+55%` preconditioning KL jump), exact Hessian group-scale bloat vs. certified
              split (`WI-5`, `siliquant#24`), `LoReS` GDN decay persistence (`AUDIT-058R`), and argmax-text
              vs. log-prob margin blindness (`WI-6`).
  - Pillar 4: Zero-float Issue `#3` governed weight-iteration candidate verifier (pre-eval hash binding,
              division-free `FixedRadixCertificate` cross-multiplication, unchanged-base control,
              Fisher-Schur `blk.31` promotion, and fail-closed rejection of plausible-text regressions,
              preconditioned KL blow-ups, raw LoRA overrides, and incomplete SSM/lattice flushes).

Strict invariants:
  - 100% pure Python 3 stdlib (zero numpy/torch/scipy, zero external runtime deps).
  - ZERO floats anywhere in JSON certificates or core exact math.
  - ZERO bare `assert` statements (100% `-O` immune).
  - Read-only against local clones (sets `sys.dont_write_bytecode = True` before any repo import).
  - Runs both live-anchored (when local clones exist) and `--standalone` (zero external clones needed).
"""

from __future__ import annotations

import argparse
import base64
from collections import Counter
from dataclasses import dataclass
from fractions import Fraction
import hashlib
import hmac
import json
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile
from typing import Any, Mapping, Sequence

sys.dont_write_bytecode = True

# =============================================================================
# 0. Exact Guard Primitives & Pure-Q Matrix / Bunch-Kaufman / Schur Engine
# =============================================================================

STATE_BANK_KV = "kv_cache"
STATE_BANK_SSM = "ssm_recurrent"
STATE_BANK_LATTICE = "lattice_horizontal_streams"
ALL_STATE_BANKS: tuple[str, ...] = (
    STATE_BANK_KV,
    STATE_BANK_SSM,
    STATE_BANK_LATTICE,
)
VALID_STATE_BANK_SET = frozenset(ALL_STATE_BANKS)

EXPECTED_WARP_DRIVE_SHA = "e3899d3e0ef7697052e74e7a4f99f510d2b63ad5"
EXPECTED_QWEN_4B_HTML_SHA = "cfc229397e1e98d46ccaa270295bcb02114159bfb2ed79cc77f7f6262220f22d"

QMat = tuple[tuple[Fraction, ...], ...]
QVec = tuple[Fraction, ...]


class WarpIterationAuditError(ValueError):
    """Typed R1/R3/R5 fail-closed error carrying a machine-readable error code."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(f"[{code}] {message}")


def require(cond: bool, code: str, message: str) -> None:
    if not cond:
        raise WarpIterationAuditError(code, message)


def is_exact_int(x: object) -> bool:
    return type(x) is int


def to_q(x: object) -> Fraction:
    if isinstance(x, Fraction):
        return x
    require(is_exact_int(x), "BAD_SCALAR", f"Expected int or Fraction, got {type(x).__name__}")
    return Fraction(x)  # type: ignore[arg-type]


def frac_str(q: Fraction) -> str:
    return f"{q.numerator}/{q.denominator}"


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def sha256_canonical(obj: Any) -> str:
    return hashlib.sha256(canonical_json(obj).encode("utf-8")).hexdigest()


def qvec(items: Sequence[object]) -> QVec:
    require(len(items) > 0, "EMPTY_VEC", "Vector must be non-empty")
    return tuple(to_q(v) for v in items)


def qmat(rows: Sequence[Sequence[object]]) -> QMat:
    require(len(rows) > 0, "EMPTY_MAT", "Matrix must be non-empty")
    cols = len(rows[0])
    require(cols > 0, "EMPTY_COL", "Matrix must have at least one column")
    out: list[tuple[Fraction, ...]] = []
    for row in rows:
        require(len(row) == cols, "RAGGED_MAT", "All matrix rows must share identical length")
        out.append(tuple(to_q(v) for v in row))
    return tuple(out)


def qeye(n: int) -> QMat:
    require(is_exact_int(n) and n > 0, "BAD_DIM", "Dimension must be a positive int")
    return tuple(tuple(Fraction(1 if i == j else 0) for j in range(n)) for i in range(n))


def qtranspose(m: QMat) -> QMat:
    return tuple(tuple(m[r][c] for r in range(len(m))) for c in range(len(m[0])))


def qdot(a: QVec, b: QVec) -> Fraction:
    require(len(a) == len(b), "DOT_SHAPE", "Vector dot product dimension mismatch")
    return sum((x * y for x, y in zip(a, b)), Fraction(0))


def qmatvec(m: QMat, v: QVec) -> QVec:
    require(len(m[0]) == len(v), "MATVEC_SHAPE", "Matrix-vector dimension mismatch")
    return tuple(sum((m[r][c] * v[c] for c in range(len(v))), Fraction(0)) for r in range(len(m)))


def qmul(a: QMat, b: QMat) -> QMat:
    require(len(a[0]) == len(b), "MUL_SHAPE", "Matrix multiplication dimension mismatch")
    k_dim = len(b)
    cols = len(b[0])
    return tuple(
        tuple(sum((a[i][k] * b[k][j] for k in range(k_dim)), Fraction(0)) for j in range(cols))
        for i in range(len(a))
    )


def qadd(a: QMat, b: QMat) -> QMat:
    require(len(a) == len(b) and len(a[0]) == len(b[0]), "ADD_SHAPE", "Matrix addition shape mismatch")
    return tuple(tuple(a[r][c] + b[r][c] for c in range(len(a[0]))) for r in range(len(a)))


def qsub(a: QMat, b: QMat) -> QMat:
    require(len(a) == len(b) and len(a[0]) == len(b[0]), "SUB_SHAPE", "Matrix subtraction shape mismatch")
    return tuple(tuple(a[r][c] - b[r][c] for c in range(len(a[0]))) for r in range(len(a)))


def qscale(s: Fraction, m: QMat) -> QMat:
    return tuple(tuple(s * v for v in row) for row in m)


def qfrob_sq(m: QMat) -> Fraction:
    return sum((v * v for row in m for v in row), Fraction(0))


def qvec_norm_sq(v: QVec) -> Fraction:
    return sum((x * x for x in v), Fraction(0))


def is_symmetric(m: QMat) -> bool:
    n = len(m)
    if n != len(m[0]):
        return False
    for i in range(n):
        for j in range(i + 1, n):
            if m[i][j] != m[j][i]:
                return False
    return True


def op_krein_inertia(m: QMat) -> tuple[int, int, int]:
    """Exact pure-Q Bunch-Kaufman symmetric congruence inertia (n_+, n_0, n_-)."""
    require(is_symmetric(m), "NOT_SYM", "Krein inertia requires a symmetric matrix")
    n = len(m)
    a = [list(row) for row in m]
    n_pos = n_zero = n_neg = 0
    k = 0
    while k < n:
        if a[k][k] != 0:
            piv = a[k][k]
            if piv > 0:
                n_pos += 1
            else:
                n_neg += 1
            for i in range(k + 1, n):
                f = a[i][k] / piv
                if f != 0:
                    for j in range(i, n):
                        val = a[i][j] - f * a[k][j]
                        a[i][j] = val
                        a[j][i] = val
            k += 1
            continue

        # Search for non-zero diagonal in remaining submatrix
        swap_diag = -1
        for i in range(k + 1, n):
            if a[i][i] != 0:
                swap_diag = i
                break
        if swap_diag != -1:
            a[k], a[swap_diag] = a[swap_diag], a[k]
            for r in range(n):
                a[r][k], a[r][swap_diag] = a[r][swap_diag], a[r][k]
            continue

        # Search for non-zero off-diagonal (hyperbolic 2x2 pivot -> +1, -1)
        off_idx = -1
        for i in range(k + 1, n):
            if a[k][i] != 0:
                off_idx = i
                break
        if off_idx == -1:
            n_zero += 1
            k += 1
            continue

        if off_idx != k + 1:
            a[k + 1], a[off_idx] = a[off_idx], a[k + 1]
            for r in range(n):
                a[r][k + 1], a[r][off_idx] = a[r][off_idx], a[r][k + 1]
        b = a[k][k + 1]
        n_pos += 1
        n_neg += 1
        for i in range(k + 2, n):
            c0 = a[i][k]
            c1 = a[i][k + 1]
            for j in range(i, n):
                d0 = a[k][j]
                d1 = a[k + 1][j]
                val = a[i][j] - (c0 * d1 + c1 * d0) / b
                a[i][j] = val
                a[j][i] = val
        k += 2
    return (n_pos, n_zero, n_neg)


def qsolve(a: QMat, b: QMat) -> QMat:
    """Exact Gauss-Jordan linear solver A X = B over Q."""
    n = len(a)
    require(n == len(a[0]) and len(b) == n, "SOLVE_SHAPE", "Linear solve shape mismatch")
    m = len(b[0])
    aug = [list(a[i]) + list(b[i]) for i in range(n)]
    for col in range(n):
        piv = -1
        for r in range(col, n):
            if aug[r][col] != 0:
                piv = r
                break
        require(piv != -1, "SINGULAR_MAT", "Singular matrix in qsolve")
        if piv != col:
            aug[col], aug[piv] = aug[piv], aug[col]
        pv = aug[col][col]
        aug[col] = [v / pv for v in aug[col]]
        for r in range(n):
            if r != col and aug[r][col] != 0:
                f = aug[r][col]
                aug[r] = [aug[r][j] - f * aug[col][j] for j in range(n + m)]
    return tuple(tuple(row[n:]) for row in aug)


def op_schur_complement(m: QMat, elim: tuple[int, ...]) -> QMat:
    """Exact invertible symmetric Schur complement M ⧄ elim over Q."""
    require(is_symmetric(m), "SCHUR_NOT_SYM", "Schur complement requires symmetric matrix")
    n = len(m)
    require(len(set(elim)) == len(elim), "SCHUR_DUP_IDX", "Duplicate elimination index")
    for idx in elim:
        require(is_exact_int(idx) and 0 <= idx < n, "SCHUR_BAD_IDX", "Elimination index out of range")
    keep = tuple(i for i in range(n) if i not in elim)
    require(len(keep) > 0, "SCHUR_EMPTY_KEEP", "Schur complement requires non-empty kept block")
    if not elim:
        return m
    m_kk = tuple(tuple(m[i][j] for j in keep) for i in keep)
    m_ke = tuple(tuple(m[i][j] for j in elim) for i in keep)
    m_ee = tuple(tuple(m[i][j] for j in elim) for i in elim)
    m_ek = tuple(tuple(m[i][j] for j in keep) for i in elim)
    x = qsolve(m_ee, m_ek)
    return qsub(m_kk, qmul(m_ke, x))


# =============================================================================
# 1. Pillar 1 — Hardened Multi-Bank State Isolation Gates (Closing WD-SB-01..04)
# =============================================================================

@dataclass(frozen=True)
class HardenedStateBankStatus:
    """Fail-closed per-slot state-bank status closing WD-SB-02."""

    bank: str
    tainted: bool
    active_lora_ids: tuple[int, ...] = ()
    tokens_or_layers: int = 0
    capability_tag: int | None = None
    zone_manifest_id: str | None = None

    def __post_init__(self) -> None:
        require(self.bank in VALID_STATE_BANK_SET, "BAD_BANK_NAME", f"Unknown state bank: {self.bank!r}")
        require(type(self.tainted) is bool, "BAD_TAINT_TYPE", "tainted must be strict bool")
        require(is_exact_int(self.tokens_or_layers) and self.tokens_or_layers >= 0, "BAD_TOKENS_COUNT", "tokens_or_layers must be non-negative int")
        for aid in self.active_lora_ids:
            require(is_exact_int(aid) and aid >= 0, "BAD_LORA_ID", "active_lora_ids must be non-negative ints")
        if self.capability_tag is not None:
            require(is_exact_int(self.capability_tag) and 0 <= self.capability_tag <= 255, "BAD_CAP_TAG", "capability_tag must be int in [0, 255]")

    @property
    def is_clean(self) -> bool:
        return (not self.tainted) and (len(self.active_lora_ids) == 0) and self.tokens_or_layers == 0


@dataclass(frozen=True)
class HardenedBankFlushReceipt:
    """Fail-closed per-slot flush receipt closing WD-SB-01 & WD-SB-02."""

    slot_id: int
    banks_requested: tuple[str, ...]
    banks_confirmed: tuple[str, ...]
    zone_manifest_id: str | None
    verified_clean: bool

    def __post_init__(self) -> None:
        require(is_exact_int(self.slot_id) and self.slot_id >= 0, "BAD_SLOT_ID", "slot_id must be non-negative int")
        require(len(self.banks_requested) > 0, "EMPTY_BANKS_REQ", "banks_requested must be non-empty")
        for b in self.banks_requested:
            require(b in VALID_STATE_BANK_SET, "BAD_REQ_BANK", f"Unknown requested bank: {b!r}")
        for b in self.banks_confirmed:
            require(b in VALID_STATE_BANK_SET, "BAD_CONF_BANK", f"Unknown confirmed bank: {b!r}")
        require(type(self.verified_clean) is bool, "BAD_CLEAN_FLAG", "verified_clean must be strict bool")
        if self.verified_clean:
            missing = [b for b in self.banks_requested if b not in self.banks_confirmed]
            require(len(missing) == 0, "CLEAN_WITHOUT_CONFIRMATION", f"Cannot mark verified_clean with missing banks: {missing}")


def validate_lattice_checkpoint_dims(
    *,
    has_horizontal_lattice: bool,
    lattice_layers: int,
    lattice_width: int,
) -> bool:
    """Closes WD-SB-03: enforces BOTH lattice_layers > 0 AND lattice_width > 0 when enabled."""
    require(type(has_horizontal_lattice) is bool, "BAD_LAT_FLAG", "has_horizontal_lattice must be strict bool")
    require(is_exact_int(lattice_layers) and lattice_layers >= 0, "BAD_LAT_LAYERS", "lattice_layers must be non-negative int")
    require(is_exact_int(lattice_width) and lattice_width >= 0, "BAD_LAT_WIDTH", "lattice_width must be non-negative int")
    if has_horizontal_lattice:
        require(lattice_layers > 0 and lattice_width > 0, "ZERO_LATTICE_DIM", "Horizontal lattice requires positive layers AND width")
    else:
        require(lattice_layers == 0 and lattice_width == 0, "NONZERO_DISABLED_LATTICE", "Disabled horizontal lattice must have zero layers and width")
    return True


def verify_multibank_flush_strict(
    *,
    required_banks: Sequence[str],
    pre_slot_ids: Sequence[int],
    erase_responses: Mapping[int, Mapping[str, Any]],
    post_slots: Sequence[Mapping[str, Any]],
    zone_manifest_id: str | None = None,
) -> tuple[HardenedBankFlushReceipt, ...]:
    """Fail-closed multi-bank flush verifier closing WD-SB-01, WD-SB-02, and WD-SB-04.

    Enforces ALL of:
      1. Non-empty `required_banks` (valid names) and non-empty `pre_slot_ids`.
      2. Explicit backend confirmation of EVERY bank in `required_banks` (including `ssm_recurrent`,
         not just `lattice_horizontal_streams` — closing WD-SB-01!).
      3. Exact slot-set coverage between `pre_slot_ids` and `post_slots` AND `is_processing == False`.
      4. Explicit post-erase cleanliness of EVERY required bank in `post_slot["state_banks"]`
         (absent bank status fails closed — closing WD-SB-01 & WD-SB-04!).
    """
    req_tuple = tuple(required_banks)
    require(len(req_tuple) > 0, "EMPTY_REQ_BANKS", "required_banks must be non-empty")
    for b in req_tuple:
        require(b in VALID_STATE_BANK_SET, "BAD_REQ_BANK", f"Unknown bank in required_banks: {b!r}")
    pre_ids = tuple(pre_slot_ids)
    require(len(pre_ids) > 0, "EMPTY_PRE_SLOTS", "pre_slot_ids must be non-empty")
    for sid in pre_ids:
        require(is_exact_int(sid) and sid >= 0, "BAD_SLOT_ID", "Slot id must be non-negative int")

    confirmed_map: dict[int, tuple[str, ...]] = {}
    for sid in pre_ids:
        require(sid in erase_responses, "MISSING_ERASE_RESP", f"Missing erase response for slot {sid}")
        raw_conf = erase_responses[sid].get("banks_flushed")
        require(isinstance(raw_conf, (list, tuple)), "BAD_BANKS_FLUSHED", f"Slot {sid} erase missing banks_flushed list")
        conf = tuple(str(b) for b in raw_conf)
        missing = [b for b in req_tuple if b not in conf]
        require(len(missing) == 0, "MISSING_CONFIRMED_BANKS", f"Slot {sid} missing confirmed banks: {missing}")
        confirmed_map[sid] = conf

    post_by_id: dict[int, Mapping[str, Any]] = {}
    for pslot in post_slots:
        psid = pslot.get("id")
        require(is_exact_int(psid) and psid >= 0, "BAD_POST_SLOT_ID", "Post slot missing valid integer id")
        post_by_id[psid] = pslot  # type: ignore[index]

    require(set(pre_ids).issubset(set(post_by_id.keys())), "POST_SLOT_MISSING", "Post-erase /slots omitted flushed slot(s)")

    receipts: list[HardenedBankFlushReceipt] = []
    for sid in pre_ids:
        pslot = post_by_id[sid]
        require(pslot.get("is_processing") is False, "SLOT_STILL_PROCESSING", f"Slot {sid} still processing during flush check")
        raw_banks = pslot.get("state_banks")
        require(isinstance(raw_banks, Mapping), "MISSING_STATE_BANKS", f"Slot {sid} post-erase missing state_banks map")
        for bname in req_tuple:
            require(bname in raw_banks, "MISSING_BANK_STATUS", f"Slot {sid} post-erase missing required bank status '{bname}'")
            bdata = raw_banks[bname]
            require(isinstance(bdata, Mapping), "BAD_BANK_STATUS", f"Slot {sid} bank '{bname}' status not a mapping")
            status = HardenedStateBankStatus(
                bank=bname,
                tainted=bdata.get("tainted"),  # type: ignore[arg-type]
                active_lora_ids=tuple(bdata.get("active_lora_ids", ())),
                tokens_or_layers=bdata.get("tokens_or_layers", 0),  # type: ignore[arg-type]
                capability_tag=bdata.get("capability_tag"),
                zone_manifest_id=bdata.get("zone_manifest_id"),
            )
            require(status.is_clean, "BANK_STILL_TAINTED", f"Slot {sid} bank '{bname}' retained taint after erase")
        receipts.append(
            HardenedBankFlushReceipt(
                slot_id=sid,
                banks_requested=req_tuple,
                banks_confirmed=confirmed_map[sid],
                zone_manifest_id=zone_manifest_id,
                verified_clean=True,
            )
        )
    return tuple(receipts)


def run_live_warp_drive_bug_reproducers(
    warp_repo: Path,
    *,
    expected_sha: str = EXPECTED_WARP_DRIVE_SHA,
) -> dict[str, Any]:
    """Read-only live reproduction of WD-SB-01..04 against Moissanite-Labs/warp-drive@e3899d3."""
    if not warp_repo.is_dir():
        return {"available": False, "mode": "standalone_offline"}

    head_sha = subprocess.check_output(["git", "-C", str(warp_repo), "rev-parse", "HEAD"], text=True).strip()
    dirty = subprocess.check_output(["git", "-C", str(warp_repo), "status", "--porcelain"], text=True).strip()
    if head_sha != expected_sha or dirty != "":
        return {"available": False, "mode": "sha_or_dirty_mismatch", "head_sha": head_sha, "dirty": bool(dirty)}

    src_dir = str(warp_repo / "src")
    repo_dir = str(warp_repo)
    for p in (src_dir, repo_dir):
        if p not in sys.path:
            sys.path.insert(0, p)

    from warp_modeld.canary import CanaryRunner, CanarySuite  # type: ignore[import-not-found]
    from warp_modeld.fingerprint import AdapterBundle, CheckpointFingerprint, RuntimeFlags  # type: ignore[import-not-found]
    from warp_modeld.ledger import HmacSha256Signer, SignedLedger  # type: ignore[import-not-found]
    from warp_modeld.llama_client import LlamaServerClient  # type: ignore[import-not-found]
    from warp_modeld.state_banks import BankFlushReceipt, StateBankStatus  # type: ignore[import-not-found]
    from warp_modeld.verifier import WarpModeld  # type: ignore[import-not-found]
    from tests.helpers import (  # type: ignore[import-not-found]
        CANARY_SUITE_PATH,
        fake_sha,
        make_adapter_bundle_dict,
        make_joint_bounds,
        make_lineage,
        make_single_bounds,
    )
    from tests.mock_llama_server import MockLlamaServer  # type: ignore[import-not-found]

    # Live repro 1: WD-SB-01 (has_ssm_recurrent=True, has_horizontal_lattice=False, stock KV-only backend)
    ckpt_ssm = CheckpointFingerprint(
        model_id="Qwen3.5-4B-GDN-Hybrid",
        layout_sha256=fake_sha("layout-q35"),
        weights_sha256=fake_sha("weights-q35"),
        config_sha256=fake_sha("config-q35"),
        tokenizer_sha256=fake_sha("tok-q35"),
        chat_template_sha256=fake_sha("chat-q35"),
        has_ssm_recurrent=True,
        has_horizontal_lattice=False,
        lattice_layers=0,
        lattice_width=0,
    )
    flags_ssm = RuntimeFlags(
        llama_server_commit="7fe450e19",
        quantization="Q8_0",
        ctx_size=16384,
        kv_cache_type="q8_0",
        ctx_checkpoints=0,
        swa_checkpoints=0,
        lora_init_without_apply=True,
    )
    mock_stock = MockLlamaServer(has_ssm_recurrent=False, lattice_layers=0)
    url1 = mock_stock.start()
    wd_sb_01_repro = False
    wd_sb_01_receipt: dict[str, Any] = {}
    try:
        with tempfile.TemporaryDirectory() as td:
            bundle = make_adapter_bundle_dict(
                adapter_id="mde:corpus",
                domain="corpus",
                llama_adapter_id=0,
                checkpoint=ckpt_ssm,
                lineage=make_lineage(),
                runtime_flags=flags_ssm,
            )
            bundle["checkpoint"]["has_ssm_recurrent"] = True
            signer = HmacSha256Signer(b"audit064-ssm-repro-key-32bytes01", key_id="a64")
            md = WarpModeld(
                pinned_checkpoint=ckpt_ssm,
                pinned_lineage=make_lineage(),
                live_runtime_flags=flags_ssm,
                single_bounds=make_single_bounds(),
                joint_bounds=make_joint_bounds(),
                canary_suite=CanarySuite.from_verifier_file(CANARY_SUITE_PATH),
                llama_client=LlamaServerClient(url1),
                ledger=SignedLedger(Path(td) / "ledger.jsonl", signer),
            )
            md.mount_stack([bundle])
            md.infer([{"role": "user", "content": "populate hybrid ssm state"}])
            rb = md.rollback(reason="audit064_wd_sb_01")
            r0 = rb.bank_flush_receipts[0].to_dict()
            wd_sb_01_receipt = {
                "slot_id": r0["slot_id"],
                "banks_requested": r0["banks_requested"],
                "banks_confirmed": r0["banks_confirmed"],
                "verified_clean": r0["verified_clean"],
            }
            wd_sb_01_repro = (
                STATE_BANK_SSM in r0["banks_requested"]
                and STATE_BANK_SSM not in r0["banks_confirmed"]
                and r0["verified_clean"] is True
            )
    finally:
        mock_stock.stop()

    # Live repro 2: WD-SB-02 (StateBankStatus & BankFlushReceipt lack __post_init__ invariants)
    bad_rec = BankFlushReceipt(
        slot_id=0,
        banks_requested=(STATE_BANK_KV, STATE_BANK_SSM, STATE_BANK_LATTICE),
        banks_confirmed=(),
        zone_manifest_id=None,
        verified_clean=True,
    )
    bad_stat = StateBankStatus(bank="nonexistent_bank", tainted=False, active_lora_ids=(), tokens_or_layers=False)
    wd_sb_02_repro = (
        bad_rec.verified_clean is True
        and len(bad_rec.banks_confirmed) == 0
        and bad_stat.is_clean is True
    )

    # Live repro 3: WD-SB-03 (CheckpointFingerprint allows has_horizontal_lattice=True with lattice_width=0)
    ckpt_w0 = CheckpointFingerprint(
        model_id="Lattice-Zero-Width",
        layout_sha256=fake_sha("l0"),
        weights_sha256=fake_sha("w0"),
        config_sha256=fake_sha("c0"),
        tokenizer_sha256=fake_sha("t0"),
        chat_template_sha256=fake_sha("ch0"),
        has_horizontal_lattice=True,
        lattice_layers=24,
        lattice_width=0,
    )
    wd_sb_03_repro = ckpt_w0.has_horizontal_lattice is True and ckpt_w0.lattice_width == 0

    # Live repro 4: WD-SB-04 (CanaryRunner ignores erase_slot return & post-slot taint on kv_only_erase)
    mock_c = MockLlamaServer(has_ssm_recurrent=True, lattice_layers=24)
    url4 = mock_c.start()
    wd_sb_04_repro = False
    try:
        ckpt_lat = CheckpointFingerprint(
            model_id="Lattice-Canary-Test",
            layout_sha256=fake_sha("lc"),
            weights_sha256=fake_sha("wc"),
            config_sha256=fake_sha("cc"),
            tokenizer_sha256=fake_sha("tc"),
            chat_template_sha256=fake_sha("chc"),
            has_ssm_recurrent=True,
            has_horizontal_lattice=True,
            lattice_layers=24,
            lattice_width=256,
        )
        flags_lat = RuntimeFlags(
            llama_server_commit="7fe450e19",
            quantization="Q4_K_M",
            ctx_size=16384,
            kv_cache_type="q8_0",
            ctx_checkpoints=0,
            swa_checkpoints=0,
            lora_init_without_apply=True,
            has_horizontal_lattice=True,
            lattice_flush_supported=True,
        )
        b_lat = make_adapter_bundle_dict(
            adapter_id="mde:corpus",
            domain="corpus",
            llama_adapter_id=0,
            checkpoint=ckpt_lat,
            lineage=make_lineage(),
            runtime_flags=flags_lat,
        )
        b_lat["checkpoint"]["has_ssm_recurrent"] = True
        b_lat["checkpoint"]["has_horizontal_lattice"] = True
        b_lat["checkpoint"]["lattice_layers"] = 24
        b_lat["checkpoint"]["lattice_width"] = 256
        mock_c.state.kv_only_erase_slot_ids.update({0, 1})
        runner = CanaryRunner(LlamaServerClient(url4), CanarySuite.from_verifier_file(CANARY_SUITE_PATH))
        cres = runner.run([AdapterBundle.from_dict(b_lat)], required_state_banks=ckpt_lat.required_state_banks())
        wd_sb_04_repro = (
            cres.canary_slot_flushed is True
            and mock_c.state.slots[0].lattice_state_tainted is True
            and mock_c.state.slots[1].lattice_state_tainted is True
        )
    finally:
        mock_c.stop()

    return {
        "available": True,
        "warp_drive_head_sha": head_sha,
        "clean_read_only": True,
        "WD_SB_01_ssm_flush_gap_reproduced": wd_sb_01_repro,
        "WD_SB_01_signed_receipt_sample": wd_sb_01_receipt,
        "WD_SB_02_missing_state_bank_invariants_reproduced": wd_sb_02_repro,
        "WD_SB_03_zero_lattice_width_accepted_reproduced": wd_sb_03_repro,
        "WD_SB_04_canary_ignores_partial_erase_reproduced": wd_sb_04_repro,
        "all_4_bugs_live_reproduced": wd_sb_01_repro and wd_sb_02_repro and wd_sb_03_repro and wd_sb_04_repro,
    }


# =============================================================================
# 2. Pillar 2 — Multi-Bank Causal Propagation (WI-1..WI-3) & Qwen3.5-4B 4b.html Census
# =============================================================================

def simulate_hybrid_3layer_exact(
    *,
    edit_layer: int,
    delta_w: QMat,
    active_steps: tuple[bool, ...],
    has_horizontal_lattice: bool,
    flush_before_step: int | None = None,
    flush_banks: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Exact pure-Q 3-layer hybrid GDN (L0) + KV-cache (L1) + Terminal/Lattice (L2) state trajectory.

    Models a 3-layer causal hybrid block over Q^2:
      - L0 (GDN recurrent state S in Q^{2x2}):
            v_t = (W0_v + a_t * dW0) x_t
            S_t = (3/4) S_{t-1} (I - (1/2) k_t k_t^T) + (1/2) v_t k_t^T
            h1_t = x_t + S_t q_t
      - L1 (KV cache accumulating past h1_tau):
            kv_t = kv_{t-1} + h1_t,  h2_t = h1_t + (1/2) kv_t / count_t
      - L2 (blk.last, matching blk.31, plus optional Latent Lattice horizontal stream H2):
            y_t = (W2 + a_t * dW2) h2_t + (1/2) H2_t  (if has_horizontal_lattice)
            H2_{t+1} = (1/2) H2_t + (1/2) y_t         (if has_horizontal_lattice)
            logits_t = U y_t
    """
    require(edit_layer in (-1, 0, 2), "BAD_EDIT_LAYER", "edit_layer must be -1 (base), 0 (early), or 2 (terminal)")
    require(len(delta_w) == 2 and len(delta_w[0]) == 2, "BAD_DELTA_SHAPE", "delta_w must be 2x2")
    require(len(active_steps) > 0, "EMPTY_STEPS", "active_steps must be non-empty")

    inputs: tuple[QVec, ...] = (
        qvec([1, 0]),
        qvec([0, 1]),
        qvec([1, 1]),
        qvec([1, -1]),
    )
    w0_v = qmat([[1, 0], [0, 1]])
    w2_base = qmat([[1, Fraction(1, 2)], [0, 1]])
    u_head = qmat([[2, 1], [-1, 2]])
    gamma_gdn = Fraction(3, 4)
    beta_gdn = Fraction(1, 2)
    zero2 = qmat([[0, 0], [0, 0]])

    s_gdn = zero2
    kv_sum = qvec([0, 0])
    kv_count = 0
    h_lat = qvec([0, 0])

    logits_trace: list[QVec] = []
    ssm_trace: list[QMat] = []
    kv_trace: list[QVec] = []
    lat_trace: list[QVec] = []
    h2_trace: list[QVec] = []

    for t, is_active in enumerate(active_steps):
        if flush_before_step is not None and t == flush_before_step:
            if STATE_BANK_SSM in flush_banks:
                s_gdn = zero2
            if STATE_BANK_KV in flush_banks:
                kv_sum = qvec([0, 0])
                kv_count = 0
            if STATE_BANK_LATTICE in flush_banks:
                h_lat = qvec([0, 0])

        x_t = inputs[t % len(inputs)]
        k_t = x_t
        q_t = x_t
        dw0 = delta_w if (is_active and edit_layer == 0) else zero2
        dw2 = delta_w if (is_active and edit_layer == 2) else zero2

        # Layer 0: exact Gated DeltaNet recurrent update
        v_t = qmatvec(qadd(w0_v, dw0), x_t)
        kk_t = tuple(tuple(k_t[i] * k_t[j] for j in range(2)) for i in range(2))
        vk_t = tuple(tuple(v_t[i] * k_t[j] for j in range(2)) for i in range(2))
        s_gdn = qadd(
            qscale(gamma_gdn, qmul(s_gdn, qsub(qeye(2), qscale(beta_gdn, kk_t)))),
            qscale(beta_gdn, vk_t),
        )
        s_q = qmatvec(s_gdn, q_t)
        h1_t = qvec([x_t[0] + s_q[0], x_t[1] + s_q[1]])

        # Layer 1: exact KV-cache accumulation
        kv_sum = qvec([kv_sum[0] + h1_t[0], kv_sum[1] + h1_t[1]])
        kv_count += 1
        kv_mean = qvec([kv_sum[0] / kv_count, kv_sum[1] / kv_count])
        h2_t = qvec([h1_t[0] + Fraction(1, 2) * kv_mean[0], h1_t[1] + Fraction(1, 2) * kv_mean[1]])

        # Layer 2: terminal blk.last + optional Latent Lattice horizontal stream
        y_lin = qmatvec(qadd(w2_base, dw2), h2_t)
        if has_horizontal_lattice:
            y_t = qvec([y_lin[0] + Fraction(1, 2) * h_lat[0], y_lin[1] + Fraction(1, 2) * h_lat[1]])
            h_lat = qvec([Fraction(1, 2) * h_lat[0] + Fraction(1, 2) * y_t[0], Fraction(1, 2) * h_lat[1] + Fraction(1, 2) * y_t[1]])
        else:
            y_t = y_lin

        logits_t = qmatvec(u_head, y_t)
        logits_trace.append(logits_t)
        ssm_trace.append(s_gdn)
        kv_trace.append(kv_sum)
        lat_trace.append(h_lat)
        h2_trace.append(h2_t)

    return {
        "logits": logits_trace,
        "ssm": ssm_trace,
        "kv": kv_trace,
        "lattice": lat_trace,
        "h2": h2_trace,
    }


def _vec_diff_sq(a: QVec, b: QVec) -> Fraction:
    return sum(((x - y) * (x - y) for x, y in zip(a, b)), Fraction(0))


def verify_pillar2_causal_propagation() -> dict[str, Any]:
    """Proves Theorems WI-1, WI-2, WI-3 over pure Q."""
    dw = qmat([[Fraction(1, 2), Fraction(0)], [Fraction(1, 4), Fraction(1, 2)]])
    steps_rb = (True, True, False)  # active on t=0,1; rollback scale->0 on t=2

    # Base trajectories (no horizontal lattice vs with horizontal lattice)
    base_nolat = simulate_hybrid_3layer_exact(edit_layer=-1, delta_w=dw, active_steps=(False, False, False), has_horizontal_lattice=False)
    base_nolat_flushed = simulate_hybrid_3layer_exact(
        edit_layer=-1, delta_w=dw, active_steps=(False, False, False), has_horizontal_lattice=False,
        flush_before_step=2, flush_banks=(STATE_BANK_KV, STATE_BANK_SSM),
    )
    base_lat_flushed = simulate_hybrid_3layer_exact(
        edit_layer=-1, delta_w=dw, active_steps=(False, False, False), has_horizontal_lattice=True,
        flush_before_step=2, flush_banks=ALL_STATE_BANKS,
    )
    base_lat_kvonly = simulate_hybrid_3layer_exact(
        edit_layer=-1, delta_w=dw, active_steps=(False, False, False), has_horizontal_lattice=True,
        flush_before_step=2, flush_banks=(STATE_BANK_KV, STATE_BANK_SSM),
    )

    # WI-1: Terminal layer (blk.last, no horizontal lattice) -> ZERO KV/SSM taint, EXACT 1/1 first-order gain, ZERO no-flush rollback error!
    term_nolat = simulate_hybrid_3layer_exact(edit_layer=2, delta_w=dw, active_steps=steps_rb, has_horizontal_lattice=False)
    wi1_ssm_taint_t1 = qfrob_sq(qsub(term_nolat["ssm"][1], base_nolat["ssm"][1]))
    wi1_kv_taint_t1 = _vec_diff_sq(term_nolat["kv"][1], base_nolat["kv"][1])
    wi1_rb_err_noflush = _vec_diff_sq(term_nolat["logits"][2], base_nolat["logits"][2])
    # Check exact first-order logit gain prediction at t=1: delta_z == U @ dw @ h2_base[1]
    u_head = qmat([[2, 1], [-1, 2]])
    pred_dz_t1 = qmatvec(u_head, qmatvec(dw, base_nolat["h2"][1]))
    live_dz_t1 = qvec([term_nolat["logits"][1][i] - base_nolat["logits"][1][i] for i in range(2)])
    wi1_exact_first_order = (live_dz_t1 == pred_dz_t1)

    # WI-2: Earlier layer (L0, identical ||dW||_F^2) -> NONZERO SSM & KV taint, NONZERO no-flush rollback leak, ZERO after full flush!
    early_noflush = simulate_hybrid_3layer_exact(edit_layer=0, delta_w=dw, active_steps=steps_rb, has_horizontal_lattice=False)
    early_flushed = simulate_hybrid_3layer_exact(
        edit_layer=0, delta_w=dw, active_steps=steps_rb, has_horizontal_lattice=False,
        flush_before_step=2, flush_banks=(STATE_BANK_KV, STATE_BANK_SSM),
    )
    wi2_ssm_taint_t1 = qfrob_sq(qsub(early_noflush["ssm"][1], base_nolat["ssm"][1]))
    wi2_kv_taint_t1 = _vec_diff_sq(early_noflush["kv"][1], base_nolat["kv"][1])
    wi2_rb_err_noflush = _vec_diff_sq(early_noflush["logits"][2], base_nolat["logits"][2])
    wi2_rb_err_flushed = _vec_diff_sq(early_flushed["logits"][2], base_nolat_flushed["logits"][2])

    # WI-3: Terminal layer WITH Latent Lattice horizontal stream (arXiv:2611.21608) ->
    # EVEN terminal layer leaks after KV+SSM-only flush; requires FULL 3-bank flush!
    term_lat_kvonly = simulate_hybrid_3layer_exact(
        edit_layer=2, delta_w=dw, active_steps=steps_rb, has_horizontal_lattice=True,
        flush_before_step=2, flush_banks=(STATE_BANK_KV, STATE_BANK_SSM),
    )
    term_lat_full = simulate_hybrid_3layer_exact(
        edit_layer=2, delta_w=dw, active_steps=steps_rb, has_horizontal_lattice=True,
        flush_before_step=2, flush_banks=ALL_STATE_BANKS,
    )
    wi3_kv_ssm_only_leak = _vec_diff_sq(term_lat_kvonly["logits"][2], base_lat_kvonly["logits"][2])
    wi3_full_3bank_err = _vec_diff_sq(term_lat_full["logits"][2], base_lat_flushed["logits"][2])

    all_ok = (
        wi1_ssm_taint_t1 == 0
        and wi1_kv_taint_t1 == 0
        and wi1_rb_err_noflush == 0
        and wi1_exact_first_order
        and wi2_ssm_taint_t1 > 0
        and wi2_kv_taint_t1 > 0
        and wi2_rb_err_noflush > 0
        and wi2_rb_err_flushed == 0
        and wi3_kv_ssm_only_leak > 0
        and wi3_full_3bank_err == 0
    )

    return {
        "verified": all_ok,
        "shared_delta_frob_sq": frac_str(qfrob_sq(dw)),
        "WI1_terminal_layer_no_lattice": {
            "ssm_taint_norm_sq_t1": frac_str(wi1_ssm_taint_t1),
            "kv_taint_norm_sq_t1": frac_str(wi1_kv_taint_t1),
            "first_order_gain_exact_match": wi1_exact_first_order,
            "no_flush_rollback_logit_err_sq": frac_str(wi1_rb_err_noflush),
        },
        "WI2_early_layer_cross_token_taint": {
            "ssm_taint_norm_sq_t1": frac_str(wi2_ssm_taint_t1),
            "kv_taint_norm_sq_t1": frac_str(wi2_kv_taint_t1),
            "no_flush_rollback_logit_err_sq": frac_str(wi2_rb_err_noflush),
            "full_kv_ssm_flush_rollback_err_sq": frac_str(wi2_rb_err_flushed),
        },
        "WI3_terminal_layer_with_horizontal_lattice_arXiv2611_21608": {
            "kv_and_ssm_only_flush_leak_err_sq": frac_str(wi3_kv_ssm_only_leak),
            "full_3bank_flush_rollback_err_sq": frac_str(wi3_full_3bank_err),
            "proves_multibank_contract_non_relaxable": (wi3_kv_ssm_only_leak > 0 and wi3_full_3bank_err == 0),
        },
    }


def parse_qwen35_4b_empirical_census(
    html_path: Path,
    *,
    expected_sha: str = EXPECTED_QWEN_4B_HTML_SHA,
) -> dict[str, Any]:
    """Exact zero-float census of Qwen3.5-4B (4b.html, 32 layers, 294,912 neurons, 72,553 circuit wires)."""
    if not html_path.is_file():
        return {"available": False, "mode": "standalone_offline"}

    raw_bytes = html_path.read_bytes()
    actual_sha = hashlib.sha256(raw_bytes).hexdigest()
    if actual_sha != expected_sha:
        return {"available": False, "mode": "sha_mismatch", "sha256": actual_sha}

    txt = raw_bytes.decode("utf-8")
    m = re.search(r"const\s+DATA\s*=\s*(\{.*?\});\s*\n", txt, re.S)
    if m is None:
        return {"available": False, "mode": "parse_failed"}

    d = json.loads(m.group(1))
    layers = int(d["layers"])
    width = int(d["width"])
    total_n = int(d["n"])
    st = d["structures"]
    ids = struct.unpack(f"<{total_n}H", base64.b64decode(st["ids"]))
    fam_of = st["familyOf"]
    reg_of = st["regionOf"]
    regions = [str(r["name"]) for r in st["regions"]]
    share = base64.b64decode(d["share"])
    bridges = base64.b64decode(st["bridges"])

    # 1. Decode all 72,553 direct neuron-to-neuron circuit wires (writer -> reader, 3-byte uint24 each)
    n_wires = len(bridges) // 6
    out_by_l: Counter[int] = Counter()
    in_by_l: Counter[int] = Counter()
    backward_wires = 0
    same_layer_wires = 0
    for k in range(0, len(bridges), 6):
        w_idx = bridges[k] | (bridges[k + 1] << 8) | (bridges[k + 2] << 16)
        r_idx = bridges[k + 3] | (bridges[k + 4] << 8) | (bridges[k + 5] << 16)
        wl = w_idx // width
        rl = r_idx // width
        out_by_l[wl] += 1
        in_by_l[rl] += 1
        if rl < wl:
            backward_wires += 1
        elif rl == wl:
            same_layer_wires += 1

    # 2. Exact per-layer dark-shadow density & code firing share (byte 2 = code)
    dark_by_l: list[int] = []
    code_sum_by_l: list[int] = []
    for l in range(layers):
        base = l * width
        dk = sum(1 for c in range(width) if ids[base + c] == 65535 or fam_of[ids[base + c]] < 0)
        cs = sum(share[3 * (base + c) + 2] for c in range(width))
        dark_by_l.append(dk)
        code_sum_by_l.append(cs)

    total_dark = sum(dark_by_l)
    l31_dark = dark_by_l[31]
    rest_dark = total_dark - l31_dark
    l31_dark_rank = sorted(range(layers), key=lambda l: (-dark_by_l[l], l)).index(31) + 1
    l31_code_rank = sorted(range(layers), key=lambda l: (-code_sum_by_l[l], l)).index(31) + 1
    l31_in_wire_rank = sorted(range(layers), key=lambda l: (-in_by_l[l], l)).index(31) + 1
    max_out_wire_layer = max(range(layers), key=lambda l: (out_by_l[l], -l))

    # 3. Exact 4-layer hybrid GDN/GQA periodicity (l%4 in {0,1,2,3}) both globally & excluding L28..L31!
    mod4_all = [sum(dark_by_l[l] for l in range(layers) if l % 4 == r) for r in range(4)]
    mod4_excl_last_blk = [sum(dark_by_l[l] for l in range(28) if l % 4 == r) for r in range(4)]
    mod4_strict_mono_all = mod4_all[0] < mod4_all[1] < mod4_all[2] < mod4_all[3]
    mod4_strict_mono_28 = mod4_excl_last_blk[0] < mod4_excl_last_blk[1] < mod4_excl_last_blk[2] < mod4_excl_last_blk[3]

    # 4. Exact L31 region enrichments (Single letters and capitals & Math notation)
    region_enrich: dict[str, dict[str, Any]] = {}
    for target in ("Single letters and capitals", "Math notation: algebra and geometry"):
        ri = regions.index(target)
        c31 = sum(1 for c in range(width) if ids[31 * width + c] != 65535 and fam_of[ids[31 * width + c]] >= 0 and reg_of[ids[31 * width + c]] == ri)
        crest = sum(
            1
            for l in range(31)
            for c in range(width)
            if ids[l * width + c] != 65535 and fam_of[ids[l * width + c]] >= 0 and reg_of[ids[l * width + c]] == ri
        )
        region_enrich[target] = {
            "L31_count": c31,
            "L00_to_L30_count": crest,
            "enrichment_ratio_exact": frac_str(Fraction(c31 * 31, crest)),
        }

    return {
        "available": True,
        "source_file": "qwen-neuron-map-site/4b.html",
        "sha256": actual_sha,
        "layers": layers,
        "width": width,
        "total_neurons": total_n,
        "direct_circuit_wires_total": n_wires,
        "strict_forward_dag_verified": (backward_wires == 0 and same_layer_wires == 0),
        "L31_blk31_profile": {
            "outgoing_circuit_wires": out_by_l[31],
            "incoming_circuit_wires": in_by_l[31],
            "incoming_wire_rank": l31_in_wire_rank,
            "incoming_wire_share_exact": frac_str(Fraction(in_by_l[31], n_wires)),
            "L30_outgoing_wires_contrast": out_by_l[30],
            "max_outgoing_wire_layer": max_out_wire_layer,
            "max_outgoing_wires_count": out_by_l[max_out_wire_layer],
            "dark_neurons": l31_dark,
            "dark_fraction_exact": frac_str(Fraction(l31_dark, width)),
            "dark_rank_of_32": l31_dark_rank,
            "dark_enrichment_vs_L00_to_L30_exact": frac_str(Fraction(l31_dark * 31, rest_dark)),
            "code_share_rank_of_32": l31_code_rank,
            "code_share_exact": frac_str(Fraction(code_sum_by_l[31], 255 * width)),
            "region_enrichments": region_enrich,
        },
        "hybrid_3_to_1_gdn_gqa_mod4_periodicity": {
            "dark_counts_all_32_layers_mod4": mod4_all,
            "strict_monotone_0_lt_1_lt_2_lt_3_all": mod4_strict_mono_all,
            "dark_counts_L00_to_L27_mod4": mod4_excl_last_blk,
            "strict_monotone_0_lt_1_lt_2_lt_3_excl_last_block": mod4_strict_mono_28,
        },
    }


# =============================================================================
# 3. Pillar 3 — Exact Fisher-KL Preconditioning Trap (WI-4), Hessian Bloat (WI-5)
#               & Log-Prob Margin vs. Argmax Blindness (WI-6) + LoReS/siliquant
# =============================================================================

def exact_fisher_matrix_in_residual_space(probs: QVec, u_mat: QMat) -> QMat:
    """Compute exact pure-Q Fisher-KL curvature F_p = U^T (diag(p) - p p^T) U."""
    v_dim = len(probs)
    require(sum(probs, Fraction(0)) == 1, "PROBS_SUM_NEQ_1", "Probabilities must sum to 1")
    for p in probs:
        require(p > 0, "NONPOS_PROB", "Probabilities must be strictly positive")
    require(len(u_mat) == v_dim, "U_ROW_MISMATCH", "Unembedding rows must match probability dimension")
    sigma_p = tuple(
        tuple((probs[i] if i == j else Fraction(0)) - probs[i] * probs[j] for j in range(v_dim))
        for i in range(v_dim)
    )
    return qmul(qtranspose(u_mat), qmul(sigma_p, u_mat))


def exact_quadratic_fisher_kl(delta_h: QVec, fisher_mat: QMat) -> Fraction:
    """Exact second-order Fisher-KL divergence (1/2) delta_h^T F_p delta_h."""
    require(is_symmetric(fisher_mat), "FISHER_NOT_SYM", "Fisher matrix must be symmetric")
    require(len(delta_h) == len(fisher_mat), "FISHER_VEC_SHAPE", "delta_h dimension mismatch")
    return Fraction(1, 2) * qdot(delta_h, qmatvec(fisher_mat, delta_h))


def exact_2bit_weighted_group_mse(weights: QVec, diag_h: QVec, *, scale_by_sqrt_h: bool) -> Fraction:
    """Exact pure-Q 2-bit symmetric group quantization H-weighted MSE over grid {-2,-1,0,1,2}.

    Requires exact rational square roots sqrt(H_i) passed as `sqrt_h` values via `diag_h`
    being perfect squares (`h_i = s_i^2`); here `diag_h` is the exact rational scale factor `s_i = sqrt(H_i)`.
    """
    require(len(weights) == len(diag_h) and len(weights) > 0, "GROUP_SHAPE", "weights and sqrt_h must share positive length")
    for s in diag_h:
        require(s > 0, "BAD_SQRT_H", "sqrt(H_i) must be strictly positive")
    scaled = tuple(w * s if scale_by_sqrt_h else w for w, s in zip(weights, diag_h))
    max_abs = max((abs(v) for v in scaled), default=Fraction(0))
    require(max_abs > 0, "ZERO_GROUP", "Weight group must be non-zero")
    step = max_abs / 2
    total_mse = Fraction(0)
    for w, s, v in zip(weights, diag_h, scaled):
        # Deterministic exact nearest-integer rounding in [-2, 2] (half-to-even via Fraction rounding)
        q_idx = max(-2, min(2, round(v / step)))
        v_hat = q_idx * step
        w_hat = (v_hat / s) if scale_by_sqrt_h else v_hat
        err = w - w_hat
        total_mse += (s * s) * (err * err)
    return total_mse


def verify_pillar3_preconditioning_and_lattice_bridge() -> dict[str, Any]:
    """Proves Theorems WI-4 (Preconditioning +78.2% KL trap), WI-5 (Hessian bloat vs split), WI-6 (Margin vs Argmax)."""
    # --- WI-4: Exact pure-Q Fisher-KL vs Euclidean Residual Inversion ---
    probs = qvec([Fraction(1, 2), Fraction(1, 4), Fraction(1, 4)])
    # U columns: u0=(2,-1,-1)^T [small F_00=9/4], u1=(0,7,-7)^T [large F_11=49/2], u2=(1,1,1)^T [softmax gauge ker(F_p)]
    u_unrel = qmat([
        [2, 0, 1],
        [-1, 7, 1],
        [-1, -7, 1],
    ])
    f_p = exact_fisher_matrix_in_residual_space(probs, u_unrel)
    f_inertia = op_krein_inertia(f_p)
    # Exact Schur complement of F_p eliminating high-curvature block (0,1) certifies ker(F_p) = span(e_2) has 0 curvature!
    f_schur_ker = op_schur_complement(f_p, (0, 1))

    g_task = qvec([1, 2, 1])
    dh_raw = qvec([1, 0, 0])
    dh_pre = qvec([Fraction(1, 5), Fraction(2, 5), 0])  # Euclidean min-norm in span(e0, e1) -> 5x smaller ||dh||^2!
    dh_schur = qvec([0, 0, 1])  # Fisher-Schur kernel projection -> 0 unrelated KL!

    gain_raw = qdot(g_task, dh_raw)
    gain_pre = qdot(g_task, dh_pre)
    gain_schur = qdot(g_task, dh_schur)
    norm2_raw = qvec_norm_sq(dh_raw)
    norm2_pre = qvec_norm_sq(dh_pre)
    norm2_schur = qvec_norm_sq(dh_schur)
    kl_raw = exact_quadratic_fisher_kl(dh_raw, f_p)
    kl_pre = exact_quadratic_fisher_kl(dh_pre, f_p)
    kl_schur = exact_quadratic_fisher_kl(dh_schur, f_p)
    kl_ratio_pre_over_raw = kl_pre / kl_raw  # 401/225 = +78.22% > +55%!

    wi4_ok = (
        f_inertia == (2, 1, 0)
        and f_schur_ker == qmat([[0]])
        and gain_raw == gain_pre == gain_schur == Fraction(1)
        and norm2_pre == Fraction(1, 5) < norm2_raw == Fraction(1)
        and kl_pre == Fraction(401, 200)
        and kl_raw == Fraction(9, 8)
        and kl_ratio_pre_over_raw == Fraction(401, 225) > Fraction(155, 100)
        and kl_schur == Fraction(0)
    )

    # --- WI-5: Exact Pure-Q Quantization Twin (siliquant#24 Hessian Group-Scale Bloat vs Certified Split) ---
    w_grp = qvec([Fraction(1), Fraction(3, 8), Fraction(3, 8), Fraction(3, 8)])
    sqrt_h = qvec([Fraction(4), Fraction(1), Fraction(1), Fraction(1)])  # H = diag(16, 1, 1, 1)
    mse_unweighted = exact_2bit_weighted_group_mse(w_grp, sqrt_h, scale_by_sqrt_h=False)  # 3/64
    mse_naive_hess = exact_2bit_weighted_group_mse(w_grp, sqrt_h, scale_by_sqrt_h=True)   # 27/64 (9x bloat!)
    mse_split_quiet = exact_2bit_weighted_group_mse(w_grp[1:], sqrt_h[1:], scale_by_sqrt_h=False)  # 0/1!

    # Anchored exact siliquant#24 & AUDIT-058R lattice/GDN persistence laws:
    g_e8_over_z = Fraction(929, 1080)       # E8_Had / Z exact SR MSE ratio (+0.654 dB)
    e8_voronoi_l1_sq = Fraction(64, 9)      # (8/3)^2 < 8 (Cauchy-Schwarz)
    leech_worst_over_z24 = Fraction(1, 3)   # Leech24 worst-case energy vs Z^24
    alpha_slow = Fraction(63, 64)           # Slow-decay GDN head
    gdn_half_life_44 = alpha_slow ** 44     # > 1/2 (takes >44 tokens just to halve if WD-SB-01 skips SSM flush!)
    gdn_rtn_over_sr = (Fraction(1) + alpha_slow) / (Fraction(1) - alpha_slow)  # 127/1

    wi5_ok = (
        mse_unweighted == Fraction(3, 64)
        and mse_naive_hess == Fraction(27, 64)
        and mse_naive_hess / mse_unweighted == Fraction(9)
        and mse_split_quiet == Fraction(0)
        and e8_voronoi_l1_sq < Fraction(8)
        and gdn_half_life_44 > Fraction(1, 2)
        and gdn_rtn_over_sr == Fraction(127)
    )

    # --- WI-6: Exact Log-Prob Margin vs. Argmax Text Blindness (ml-os#6 84/84 vs 36/36) ---
    logits_base = qvec([Fraction(5), Fraction(5, 2), Fraction(0)])
    logits_regressed = qvec([Fraction(11, 4), Fraction(5, 2), Fraction(0)])
    argmax_base = max(range(3), key=lambda i: logits_base[i])
    argmax_reg = max(range(3), key=lambda i: logits_regressed[i])
    margin_base = logits_base[0] - logits_base[1]       # 5/2
    margin_reg = logits_regressed[0] - logits_regressed[1]  # 1/4 (-90% margin drop!)
    wi6_ok = (argmax_base == argmax_reg == 0) and (margin_base == Fraction(5, 2)) and (margin_reg == Fraction(1, 4))

    return {
        "verified": wi4_ok and wi5_ok and wi6_ok,
        "WI4_fisher_kl_preconditioning_inversion": {
            "fisher_matrix_diag": [frac_str(f_p[i][i]) for i in range(3)],
            "fisher_krein_inertia": list(f_inertia),
            "schur_kernel_curvature": frac_str(f_schur_ker[0][0]),
            "shared_target_gain": frac_str(gain_raw),
            "raw_euclidean_norm_sq": frac_str(norm2_raw),
            "preconditioned_euclidean_norm_sq": frac_str(norm2_pre),
            "raw_unrelated_fisher_kl": frac_str(kl_raw),
            "preconditioned_unrelated_fisher_kl": frac_str(kl_pre),
            "kl_inflation_ratio_pre_over_raw": frac_str(kl_ratio_pre_over_raw),
            "fisher_schur_unrelated_kl": frac_str(kl_schur),
        },
        "WI5_siliquant_hessian_bloat_and_gdn_persistence": {
            "unweighted_2bit_H_mse": frac_str(mse_unweighted),
            "naive_hessian_2bit_H_mse": frac_str(mse_naive_hess),
            "hessian_bloat_factor": frac_str(mse_naive_hess / mse_unweighted),
            "certified_outlier_split_H_mse": frac_str(mse_split_quiet),
            "e8_had_over_z_sr_mse_ratio": frac_str(g_e8_over_z),
            "e8_voronoi_l1_radius_sq": frac_str(e8_voronoi_l1_sq),
            "leech24_worst_case_over_z24": frac_str(leech_worst_over_z24),
            "gdn_slow_decay_alpha": frac_str(alpha_slow),
            "gdn_unflushed_taint_at_step_44_gt_half": gdn_half_life_44 > Fraction(1, 2),
            "gdn_rtn_over_sr_amplification": frac_str(gdn_rtn_over_sr),
        },
        "WI6_margin_vs_argmax_blindness": {
            "argmax_identical": argmax_base == argmax_reg,
            "base_logit_margin": frac_str(margin_base),
            "regressed_logit_margin": frac_str(margin_reg),
            "margin_retention_ratio": frac_str(margin_reg / margin_base),
        },
    }


# =============================================================================
# 4. Pillar 4 — Issue #3 Exact Zero-Float Governed Weight-Iteration Gate
# =============================================================================

def verify_fixed_radix_bound(value_scaled: int, radix_scale: int, limit_num: int, limit_den: int) -> bool:
    """Exact division-free cross-multiplication matching warp_modeld/certificate.py."""
    require(is_exact_int(value_scaled) and value_scaled >= 0, "CERT_BAD_VAL", "value_scaled must be non-negative int")
    require(is_exact_int(radix_scale) and radix_scale > 0, "CERT_BAD_RADIX", "radix_scale must be positive int")
    require(is_exact_int(limit_num) and limit_num >= 0, "CERT_BAD_LNUM", "limit_num must be non-negative int")
    require(is_exact_int(limit_den) and limit_den > 0, "CERT_BAD_LDEN", "limit_den must be positive int")
    return value_scaled * limit_den <= limit_num * radix_scale


def evaluate_governed_candidate(
    *,
    candidate_id: str,
    committed_hash: str,
    payload: Mapping[str, Any],
    allowed_target_layer: str,
    frob_limit: tuple[int, int],
    min_margin_gain: Fraction,
    max_unrelated_kl: Fraction,
    required_banks: Sequence[str],
    flush_receipts: Sequence[HardenedBankFlushReceipt],
) -> dict[str, Any]:
    """Fail-closed Issue #3 candidate gate enforcing hash order, layer lock, exact cert, margin, KL & flush."""
    require(isinstance(candidate_id, str) and len(candidate_id.strip()) > 0, "BAD_CAND_ID", "candidate_id must be non-empty")
    require(isinstance(committed_hash, str) and len(committed_hash) == 64, "BAD_COMMIT_HASH", "committed_hash must be 64-hex sha256")
    require("raw_lora_override" not in payload, "ERR_UNVERIFIED_LORA_OVERRIDE", "Raw LoRA override forbidden")

    actual_hash = sha256_canonical(dict(payload))
    require(hmac.compare_digest(actual_hash, committed_hash), "ERR_CANDIDATE_HASH_DRIFT", "Pre-eval candidate hash mismatch")

    target_layer = payload.get("target_layer")
    require(target_layer == allowed_target_layer, "ERR_UNSUPPORTED_LAYER", f"Target layer {target_layer!r} != allowed {allowed_target_layer!r}")

    scale_num = payload.get("scale_num")
    scale_den = payload.get("scale_den")
    require(is_exact_int(scale_num) and scale_num >= 0, "BAD_SCALE_NUM", "scale_num must be non-negative int")
    require(is_exact_int(scale_den) and scale_den > 0, "BAD_SCALE_DEN", "scale_den must be positive int")

    frob_ok = verify_fixed_radix_bound(
        payload["frob_sq_scaled"], payload["radix_scale"], frob_limit[0], frob_limit[1]
    )
    require(frob_ok, "ERR_CERT_FROB_EXCEEDED", "Candidate exceeded Stage-2 Frobenius fixed-radix bound")

    margin_delta = Fraction(str(payload["margin_delta"]))
    unrelated_kl = Fraction(str(payload["unrelated_fisher_kl"]))
    require(unrelated_kl >= 0, "BAD_KL", "unrelated_fisher_kl must be non-negative")

    # Unchanged-base control (scale == 0): must have zero shift & zero KL
    if scale_num == 0:
        require(margin_delta == 0 and unrelated_kl == 0, "ERR_BASE_CONTROL_DRIFT", "Unchanged-base control must have zero shift and zero KL")
        return {
            "candidate_id": candidate_id,
            "verdict": "CONTROL_BASE_PASS",
            "candidate_hash": actual_hash,
            "margin_delta": frac_str(margin_delta),
            "unrelated_fisher_kl": frac_str(unrelated_kl),
        }

    # Non-zero candidate: reject plausible-text margin regressions & unrelated KL blow-ups!
    require(margin_delta >= min_margin_gain, "ERR_MARGIN_REGRESSION", f"Margin delta {margin_delta} < floor {min_margin_gain}")
    require(unrelated_kl <= max_unrelated_kl, "ERR_UNRELATED_KL_EXCEEDED", f"Unrelated KL {unrelated_kl} > budget {max_unrelated_kl}")

    # Mandatory verified multi-bank flush receipt before promotion!
    require(len(flush_receipts) > 0, "ERR_MISSING_FLUSH_RECEIPT", "Promotion requires verified multi-bank flush receipts")
    req_set = set(required_banks)
    for rec in flush_receipts:
        require(rec.verified_clean and req_set.issubset(set(rec.banks_confirmed)), "ERR_MULTIBANK_FLUSH_INCOMPLETE", "Flush receipt incomplete")

    return {
        "candidate_id": candidate_id,
        "verdict": "PROMOTE",
        "candidate_hash": actual_hash,
        "margin_delta": frac_str(margin_delta),
        "unrelated_fisher_kl": frac_str(unrelated_kl),
        "banks_verified": list(required_banks),
    }


def verify_pillar4_governed_iteration() -> dict[str, Any]:
    """Exercises Issue #3's exact 3-candidate + adversarial-rejection lifecycle over pure Q."""
    req_banks = (STATE_BANK_KV, STATE_BANK_SSM)
    clean_receipts = verify_multibank_flush_strict(
        required_banks=req_banks,
        pre_slot_ids=(0, 1),
        erase_responses={
            0: {"banks_flushed": [STATE_BANK_KV, STATE_BANK_SSM]},
            1: {"banks_flushed": [STATE_BANK_KV, STATE_BANK_SSM]},
        },
        post_slots=(
            {
                "id": 0,
                "is_processing": False,
                "state_banks": {
                    STATE_BANK_KV: {"tainted": False, "active_lora_ids": [], "tokens_or_layers": 0},
                    STATE_BANK_SSM: {"tainted": False, "active_lora_ids": [], "tokens_or_layers": 0},
                },
            },
            {
                "id": 1,
                "is_processing": False,
                "state_banks": {
                    STATE_BANK_KV: {"tainted": False, "active_lora_ids": [], "tokens_or_layers": 0},
                    STATE_BANK_SSM: {"tainted": False, "active_lora_ids": [], "tokens_or_layers": 0},
                },
            },
        ),
    )

    def _run_cand(cid: str, payload: dict[str, Any], *, tamper_hash: bool = False) -> dict[str, Any]:
        h = sha256_canonical(payload)
        if tamper_hash:
            h = ("0" if h[0] != "0" else "1") + h[1:]
        try:
            return evaluate_governed_candidate(
                candidate_id=cid,
                committed_hash=h,
                payload=payload,
                allowed_target_layer="blk.31",
                frob_limit=(2, 1),
                min_margin_gain=Fraction(1, 4),
                max_unrelated_kl=Fraction(1, 2),
                required_banks=req_banks,
                flush_receipts=clean_receipts,
            )
        except WarpIterationAuditError as exc:
            return {"candidate_id": cid, "verdict": "REJECTED", "error_code": exc.code}

    c0 = _run_cand("C0_unchanged_base", {
        "target_layer": "blk.31", "scale_num": 0, "scale_den": 1,
        "radix_scale": 65536, "frob_sq_scaled": 0, "margin_delta": "0/1", "unrelated_fisher_kl": "0/1",
    })
    c1 = _run_cand("C1_blk31_fisher_schur", {
        "target_layer": "blk.31", "scale_num": 1, "scale_den": 1,
        "radix_scale": 65536, "frob_sq_scaled": 65536, "margin_delta": "1/1", "unrelated_fisher_kl": "0/1",
    })
    c2 = _run_cand("C2_regressed_plausible_text", {
        "target_layer": "blk.31", "scale_num": 1, "scale_den": 1,
        "radix_scale": 65536, "frob_sq_scaled": 16384, "margin_delta": "-9/4", "unrelated_fisher_kl": "0/1",
        "argmax_text_preserved": True,
    })
    c3 = _run_cand("C3_preconditioned_kl_blowup", {
        "target_layer": "blk.31", "scale_num": 1, "scale_den": 1,
        "radix_scale": 65536, "frob_sq_scaled": 13107, "margin_delta": "1/1", "unrelated_fisher_kl": "401/200",
    })
    c4 = _run_cand("C4_early_layer_blocked", {
        "target_layer": "blk.26", "scale_num": 1, "scale_den": 1,
        "radix_scale": 65536, "frob_sq_scaled": 16384, "margin_delta": "1/1", "unrelated_fisher_kl": "0/1",
    })
    c5 = _run_cand("C5_hash_drift_blocked", {
        "target_layer": "blk.31", "scale_num": 1, "scale_den": 1,
        "radix_scale": 65536, "frob_sq_scaled": 65536, "margin_delta": "1/1", "unrelated_fisher_kl": "0/1",
    }, tamper_hash=True)
    c6 = _run_cand("C6_raw_lora_override_blocked", {
        "target_layer": "blk.31", "scale_num": 1, "scale_den": 1,
        "radix_scale": 65536, "frob_sq_scaled": 65536, "margin_delta": "1/1", "unrelated_fisher_kl": "0/1",
        "raw_lora_override": [{"id": 0, "scale": 1.0}],
    })

    all_ok = (
        c0["verdict"] == "CONTROL_BASE_PASS"
        and c1["verdict"] == "PROMOTE"
        and c2.get("error_code") == "ERR_MARGIN_REGRESSION"
        and c3.get("error_code") == "ERR_UNRELATED_KL_EXCEEDED"
        and c4.get("error_code") == "ERR_UNSUPPORTED_LAYER"
        and c5.get("error_code") == "ERR_CANDIDATE_HASH_DRIFT"
        and c6.get("error_code") == "ERR_UNVERIFIED_LORA_OVERRIDE"
    )
    return {
        "verified": all_ok,
        "candidates": [c0, c1, c2, c3, c4, c5, c6],
    }


# =============================================================================
# 5. Master Driver
# =============================================================================

def run_all(*, standalone: bool = False) -> dict[str, Any]:
    here = Path(__file__).resolve().parent
    warp_repo = here.parent / "repos" / "warp-drive"
    qwen_4b_html = here.parents[1] / "round5" / "repos" / "qwen-neuron-map-site" / "4b.html"

    p2_causal = verify_pillar2_causal_propagation()
    p3_prec = verify_pillar3_preconditioning_and_lattice_bridge()
    p4_gov = verify_pillar4_governed_iteration()

    if standalone:
        p1_live: dict[str, Any] = {"available": False, "mode": "standalone_offline"}
        p2_4b: dict[str, Any] = {"available": False, "mode": "standalone_offline"}
    else:
        p1_live = run_live_warp_drive_bug_reproducers(warp_repo)
        p2_4b = parse_qwen35_4b_empirical_census(qwen_4b_html)

    live_ok = True
    if p1_live.get("available"):
        live_ok = live_ok and bool(p1_live.get("all_4_bugs_live_reproduced"))
    if p2_4b.get("available"):
        blk31 = p2_4b["L31_blk31_profile"]
        mod4 = p2_4b["hybrid_3_to_1_gdn_gqa_mod4_periodicity"]
        live_ok = live_ok and bool(
            p2_4b["strict_forward_dag_verified"]
            and blk31["outgoing_circuit_wires"] == 0
            and blk31["incoming_wire_rank"] == 1
            and blk31["dark_rank_of_32"] == 1
            and blk31["code_share_rank_of_32"] == 1
            and mod4["strict_monotone_0_lt_1_lt_2_lt_3_all"]
            and mod4["strict_monotone_0_lt_1_lt_2_lt_3_excl_last_block"]
        )

    all_ok = p2_causal["verified"] and p3_prec["verified"] and p4_gov["verified"] and live_ok
    has_live = bool(p1_live.get("available") or p2_4b.get("available"))

    payload: dict[str, Any] = {
        "schema": "aletheia.wave2.round6.arm_r6_4.warp_weight_iteration_bridge.v1",
        "audit_id": "AUDIT-064",
        "oracle_class": "exact+anchor" if has_live else "exact",
        "honest_novelty": "N1",
        "verdict": "WARP_WEIGHT_ITERATION_BRIDGE_ALL_VERIFIED" if all_ok else "FAILED",
        "pinned_read_only_anchors": {
            "Moissanite-Labs/warp-drive": EXPECTED_WARP_DRIVE_SHA,
            "qwen-neuron-map/4b.html": EXPECTED_QWEN_4B_HTML_SHA,
        },
        "pillar_1_multibank_state_isolation_audit": {
            "live_reproducers": p1_live,
            "hardened_gate_targets": ["WD-SB-01", "WD-SB-02", "WD-SB-03", "WD-SB-04"],
        },
        "pillar_2_blk31_causal_and_qwen35_4b_census": {
            "exact_causal_propagation": p2_causal,
            "qwen35_4b_empirical_census": p2_4b,
        },
        "pillar_3_preconditioning_kl_and_lattice_bridge": p3_prec,
        "pillar_4_issue3_governed_iteration_gate": p4_gov,
    }
    payload["canonical_sha256"] = sha256_canonical(payload)
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Wave 2 Round 6 Arm R6-4 (AUDIT-064) Weight-Iteration & Multi-Bank Bridge")
    parser.add_argument("--json", action="store_true", help="Emit canonical zero-float JSON certificate to stdout")
    parser.add_argument("--standalone", action="store_true", help="Run exact pure-math suite without local clones")
    parser.add_argument("--write-cert", type=Path, default=None, help="Write canonical JSON certificate to path")
    args = parser.parse_args(argv)

    res = run_all(standalone=args.standalone)
    text = json.dumps(res, indent=2, sort_keys=True, allow_nan=False) + "\n"
    if args.write_cert is not None:
        args.write_cert.write_text(text, encoding="utf-8")
    if args.json:
        sys.stdout.write(text)
    else:
        print(f"Verdict: {res['verdict']}")
        print(f"Oracle:  {res['oracle_class']}")
        print(f"SHA-256: {res['canonical_sha256']}")
    return 0 if res["verdict"] == "WARP_WEIGHT_ITERATION_BRIDGE_ALL_VERIFIED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
