"""Assertion-free R5 regression tests for P0 operational blockers A2 and A8.

Covers:
  - A2 (`src/warp_modeld/experiment.py`): checkpoint/profile-driven required
    state banks during rollback (unblocking KV-only transformers such as
    Qwen3.5-4B while preserving strict multi-bank enforcement for hybrid SSM
    and horizontal-lattice checkpoints, anti-downgrade union semantics, and
    fail-closed ALL_STATE_BANKS fallback when no required bank set is declared).
  - A8 (`schemas/cerebras-candidate.schema.json`, `cerebras_client.py`,
    `cerebras_prompts.py`): full alignment of Cerebras candidate bounds with
    the frozen `experiments/demo-2026-11-22/manifest.json` (v0.1.1) contract
    and Weft `SUPPORTED_QUANT_DTYPES`, plus end-to-end controller handoff.

Zero bare asserts (100% immune to `python3 -O`), pure stdlib `unittest`.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
from typing import Any
import unittest

_ROOT = Path(__file__).resolve().parents[1]
_SRC = _ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from warp_modeld.cerebras_client import (
    ALLOWED_LAMBDAS,
    ALLOWED_LORA_SCALES,
    ALLOWED_QUANTIZATIONS,
    ALLOWED_RANKS,
    ETA_MAX,
    ETA_MIN,
    PINNED_TARGET_LAYER,
    PINNED_TARGET_TENSOR,
    CerebrasKimiClient,
    validate_candidate,
)
from warp_modeld.cerebras_prompts import FIXED_PROMPT_FIXTURES, PROMPT_SET_VERSION
from warp_modeld.errors import CerebrasSchemaError, StateFlushError
from warp_modeld.experiment import (
    SUPPORTED_QUANT_DTYPES,
    BaselineCheck,
    CompileResult,
    ExperimentController,
    LifecycleRollback,
    ReceiptLog,
    WarpModeldLifecycle,
    _validate_required_state_banks,
    load_contract,
)
from warp_modeld.state_banks import (
    ALL_STATE_BANKS,
    STATE_BANK_KV,
    STATE_BANK_LATTICE,
    STATE_BANK_SSM,
    BankFlushReceipt,
)
from warp_modeld.verifier import RollbackResult

from tests.mock_cerebras_server import MockCerebrasServer

_EXP_DIR = _ROOT / "experiments" / "demo-2026-11-22"
_SCHEMA_PATH = _ROOT / "schemas" / "cerebras-candidate.schema.json"
_PARENT_SHA = "10cc391b403021dd11c614679d2fd92f611c3681d29e29651b717316965d61e1"
_COMPILER_REPO = "siliconcordat/weft"
_COMPILER_COMMIT = "5d7eac03696c2ff07ec70308b23b86a1d4088c1e"
_ENV = {
    "gpu": "fake-test-gpu (logic check only)",
    "llama_cpp_build": "b12549",
    "llama_cpp_commit": "8af68d486",
    "os": "test",
    "vram_mib": None,
}
_ADAPTER_MARGINS = (-0.10, 0.0, 0.18) * 28
_BASELINE_MARGINS = (-1.0, -0.9, -0.81) * 12


class _FakeCompiler:
    def compile(self, candidate: Any, parent_sha256: str) -> CompileResult:
        digest = hashlib.sha256(
            json.dumps(candidate.digest_input(), sort_keys=True).encode("utf-8")
        ).hexdigest()
        return CompileResult(
            adapter_sha256=digest,
            command="weft.compiler.BetaEditNullspaceProjector.commit_patch",
            command_version=f"{_COMPILER_REPO}@{_COMPILER_COMMIT[:12]}",
            timing_ms=5.0,
            compiler_repo=_COMPILER_REPO,
            compiler_commit=_COMPILER_COMMIT,
        )


class _FakeRuntime:
    def mount_adapter(self, adapter_sha256: str, lora_scale: float) -> float:
        return 2.0

    def score_suite(self, suite_name: str, cases: list[dict[str, Any]]) -> dict[str, Any]:
        table: dict[str, dict[str, Any]] = {
            "task": {"top1": 0.58, "contested_fix_fraction": 0.15, "break_fraction": 0.03},
            "retention_iid": {"mean_kl": 0.10, "top1_agreement": 0.97},
            "retention_shifted": {"mean_kl": 0.20},
            "safety_canaries": {"canaries_run": 9, "failures": []},
        }
        return dict(table[suite_name])

    def probe_margins(self) -> dict[str, Any]:
        return {
            "threshold": -0.37,
            "adapter_requests": 84,
            "baseline_requests": 36,
            "margins_adapter": list(_ADAPTER_MARGINS),
            "margins_baseline": list(_BASELINE_MARGINS),
        }

    def verify_baseline(self) -> BaselineCheck:
        return BaselineCheck(max_logit_diff=0.0, exact_matches=14, sequences=14)


class _FakeCheckpoint:
    def __init__(self, banks: tuple[str, ...]) -> None:
        self._banks = banks

    def required_state_banks(self) -> tuple[str, ...]:
        return self._banks


class _FakeWarp:
    def __init__(
        self,
        *,
        pinned_banks: tuple[str, ...] | None,
        confirmed_banks: tuple[str, ...],
        requested_banks: tuple[str, ...] | None = None,
    ) -> None:
        if pinned_banks is not None:
            self.pinned_checkpoint = _FakeCheckpoint(pinned_banks)
        self._confirmed = confirmed_banks
        self._requested = requested_banks if requested_banks is not None else (
            pinned_banks if pinned_banks is not None else ALL_STATE_BANKS
        )

    def rollback(self, reason: str) -> RollbackResult:
        return RollbackResult(
            reason=reason,
            kill_switch_engaged=False,
            slots_flushed=(0,),
            elapsed_ms=1.0,
            receipt=None,
            bank_flush_receipts=(
                BankFlushReceipt(
                    slot_id=0,
                    banks_requested=self._requested,
                    banks_confirmed=self._confirmed,
                    zone_manifest_id=None,
                    verified_clean=set(self._requested) <= set(self._confirmed),
                ),
            ),
        )


class _CustomLifecycle:
    def __init__(
        self,
        *,
        flushed: Any,
        declared_required: Any = None,
        rolled_required: Any = None,
        expose_method: bool = False,
    ) -> None:
        self._flushed = flushed
        self._declared = declared_required
        self._rolled_required = rolled_required
        if expose_method:
            self.required_state_banks = self._get_declared

    def _get_declared(self) -> Any:
        return self._declared

    def rollback(self, reason: str) -> LifecycleRollback:
        return LifecycleRollback(
            banks_flushed=self._flushed,
            slots_flushed=(0,),
            required_banks=self._rolled_required,
        )


class TestA2RollbackRequiredBanks(unittest.TestCase):
    def setUp(self) -> None:
        self.contract = load_contract(_EXP_DIR)

    def _make_controller(
        self,
        tmp_dir: Path,
        lifecycle: Any,
        *,
        required_state_banks: Any = None,
    ) -> ExperimentController:
        return ExperimentController(
            contract=self.contract,
            compiler=_FakeCompiler(),
            runtime=_FakeRuntime(),
            lifecycle=lifecycle,
            receipts=ReceiptLog(tmp_dir / "receipts.jsonl"),
            environment=_ENV,
            required_state_banks=required_state_banks,
        )

    def test_01_validate_required_state_banks_guards(self) -> None:
        class _EvilStr(str):
            pass

        self.assertEqual(
            _validate_required_state_banks((STATE_BANK_KV,), name="test"),
            (STATE_BANK_KV,),
        )
        self.assertEqual(
            _validate_required_state_banks([STATE_BANK_KV, STATE_BANK_SSM], name="test"),
            (STATE_BANK_KV, STATE_BANK_SSM),
        )
        for idx, (bad, rx) in enumerate(
            (
                ("kv_cache", "sequence of state bank names"),
                (b"kv_cache", "sequence of state bank names"),
                (123, "sequence of state bank names"),
                ((), "must include"),
                ((STATE_BANK_SSM,), "must include"),
                ((123,), "non-string state bank"),
                ((True,), "non-string state bank"),
                ((10**5000,), "non-string state bank"),
                (((10**5000,),), "non-string state bank"),
                ((_EvilStr(STATE_BANK_KV),), "non-string state bank"),
                ((STATE_BANK_KV, "bogus"), "unknown state bank"),
                ((STATE_BANK_KV, "x" * 200), "unknown state bank"),
                ((STATE_BANK_KV, STATE_BANK_KV), "duplicate state bank"),
            )
        ):
            with self.subTest(idx=idx, bad_type=type(bad).__name__):
                with self.assertRaisesRegex(StateFlushError, rx) as ctx:
                    _validate_required_state_banks(bad, name="banks")
                self.assertLess(len(str(ctx.exception)), 500)

    def test_02_kv_only_warp_lifecycle_rollback_unblocked(self) -> None:
        with tempfile.TemporaryDirectory(prefix="a2_kv_") as td:
            os.chmod(td, 0o700)
            warp = _FakeWarp(pinned_banks=(STATE_BANK_KV,), confirmed_banks=(STATE_BANK_KV,))
            lifecycle = WarpModeldLifecycle(warp)
            self.assertEqual(lifecycle.required_state_banks(), (STATE_BANK_KV,))
            ctl = self._make_controller(Path(td), lifecycle)
            report = ctl.rollback("kv_only_test")
            self.assertTrue(report.verified)
            self.assertEqual(report.required_banks, (STATE_BANK_KV,))
            self.assertEqual(report.banks_flushed, (STATE_BANK_KV,))
            entries = ctl.receipts.read_all()
            self.assertEqual(entries[-1]["event"], "rollback_verified")
            self.assertEqual(entries[-1]["required_banks"], [STATE_BANK_KV])

    def test_03_multibank_checkpoints_still_fail_closed_when_banks_missed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="a2_multi_") as td:
            os.chmod(td, 0o700)
            tdp = Path(td)
            # Hybrid KV+SSM checkpoint flushing KV only MUST fail closed.
            warp_ssm = _FakeWarp(
                pinned_banks=(STATE_BANK_KV, STATE_BANK_SSM),
                confirmed_banks=(STATE_BANK_KV,),
            )
            ctl_ssm = self._make_controller(tdp / "ssm", WarpModeldLifecycle(warp_ssm))
            with self.assertRaisesRegex(StateFlushError, "ssm_recurrent"):
                ctl_ssm.rollback()

            # Full 3-bank Latent Lattice checkpoint flushing KV+SSM only MUST fail closed.
            warp_lat = _FakeWarp(
                pinned_banks=ALL_STATE_BANKS,
                confirmed_banks=(STATE_BANK_KV, STATE_BANK_SSM),
            )
            ctl_lat = self._make_controller(tdp / "lat", WarpModeldLifecycle(warp_lat))
            with self.assertRaisesRegex(StateFlushError, "lattice_horizontal_streams"):
                ctl_lat.rollback()

            # Legacy lifecycle without pinned_checkpoint falls back to ALL_STATE_BANKS.
            warp_legacy = _FakeWarp(
                pinned_banks=None,
                confirmed_banks=(STATE_BANK_KV, STATE_BANK_SSM),
            )
            lc_legacy = WarpModeldLifecycle(warp_legacy)
            self.assertIsNone(lc_legacy.required_state_banks())
            ctl_legacy = self._make_controller(tdp / "legacy", lc_legacy)
            with self.assertRaisesRegex(StateFlushError, "lattice_horizontal_streams"):
                ctl_legacy.rollback()

    def test_04_union_anti_downgrade_and_malformed_flushed_guards(self) -> None:
        with tempfile.TemporaryDirectory(prefix="a2_union_") as td:
            os.chmod(td, 0o700)
            tdp = Path(td)

            # Invalid required_state_banks rejected at controller construction.
            with self.assertRaisesRegex(StateFlushError, "unknown state bank"):
                self._make_controller(
                    tdp / "bad_init",
                    _CustomLifecycle(flushed=(STATE_BANK_KV,)),
                    required_state_banks=(STATE_BANK_KV, "bogus"),
                )

            # Explicit controller pin to KV-only works when lifecycle has no declaration.
            ctl_pin = self._make_controller(
                tdp / "pin_kv",
                _CustomLifecycle(flushed=(STATE_BANK_KV,)),
                required_state_banks=(STATE_BANK_KV,),
            )
            rep_pin = ctl_pin.rollback()
            self.assertEqual(rep_pin.required_banks, (STATE_BANK_KV,))

            # Anti-downgrade: controller pins KV+SSM, rolled tries to downgrade to KV-only -> FAIL.
            ctl_down = self._make_controller(
                tdp / "down",
                _CustomLifecycle(flushed=(STATE_BANK_KV,), rolled_required=(STATE_BANK_KV,)),
                required_state_banks=(STATE_BANK_KV, STATE_BANK_SSM),
            )
            with self.assertRaisesRegex(StateFlushError, "ssm_recurrent"):
                ctl_down.rollback()

            # Anti-downgrade: controller pins KV-only, rolled requires KV+SSM -> FAIL if only KV flushed.
            ctl_up = self._make_controller(
                tdp / "up",
                _CustomLifecycle(
                    flushed=(STATE_BANK_KV,),
                    rolled_required=(STATE_BANK_KV, STATE_BANK_SSM),
                ),
                required_state_banks=(STATE_BANK_KV,),
            )
            with self.assertRaisesRegex(StateFlushError, "ssm_recurrent"):
                ctl_up.rollback()

            # Lifecycle method required_state_banks returning KV+SSM enforced even if rolled_required is None.
            ctl_lc = self._make_controller(
                tdp / "lc_method",
                _CustomLifecycle(
                    flushed=(STATE_BANK_KV,),
                    declared_required=(STATE_BANK_KV, STATE_BANK_SSM),
                    expose_method=True,
                ),
            )
            with self.assertRaisesRegex(StateFlushError, "ssm_recurrent"):
                ctl_lc.rollback()

            # Lifecycle method returning None falls through cleanly to rolled_required.
            ctl_lc_none = self._make_controller(
                tdp / "lc_none",
                _CustomLifecycle(
                    flushed=(STATE_BANK_KV,),
                    declared_required=None,
                    rolled_required=(STATE_BANK_KV,),
                    expose_method=True,
                ),
            )
            self.assertEqual(ctl_lc_none.rollback().required_banks, (STATE_BANK_KV,))

            # Post-init mutation of controller.required_state_banks must fail closed (never fail open or downgrade).
            for idx, (bad_mut, rx) in enumerate(
                (
                    (("bogus",), "unknown state bank"),
                    ((), "must include"),
                    ((10**5000,), "non-string state bank"),
                    ("kv_cache", "sequence of state bank names"),
                )
            ):
                ctl_mut = self._make_controller(
                    tdp / f"post_mut_{idx}",
                    _CustomLifecycle(flushed=ALL_STATE_BANKS),
                )
                ctl_mut.required_state_banks = bad_mut  # type: ignore[assignment]
                with self.assertRaisesRegex(StateFlushError, rx):
                    ctl_mut.rollback()
                self.assertEqual(ctl_mut.receipts.read_all()[-1]["event"], "rollback_failed")
            ctl_post_down = self._make_controller(
                tdp / "post_down",
                _CustomLifecycle(flushed=(STATE_BANK_KV,)),
                required_state_banks=(STATE_BANK_KV, STATE_BANK_SSM),
            )
            ctl_post_down.required_state_banks = (STATE_BANK_KV,)
            with self.assertRaisesRegex(StateFlushError, "ssm_recurrent"):
                ctl_post_down.rollback()

            # Malformed banks_flushed (non-sequence, non-str/bool/subclass, huge int, unknown, duplicate) fails closed with receipt.
            class _EvilBankStr(str):
                pass

            for idx, bad_flushed in enumerate(
                (
                    "",
                    b"",
                    "kv_cache",
                    b"kv_cache",
                    None,
                    (STATE_BANK_KV, STATE_BANK_KV),
                    (STATE_BANK_KV, True),
                    (*ALL_STATE_BANKS, True),
                    (STATE_BANK_KV, 10**5000),
                    (STATE_BANK_KV, "bogus_bank"),
                    (_EvilBankStr(STATE_BANK_KV),),
                )
            ):
                sub = tdp / f"mal_{idx}"
                ctl_mal = self._make_controller(
                    sub,
                    _CustomLifecycle(flushed=bad_flushed, rolled_required=(STATE_BANK_KV,)),
                )
                with self.assertRaisesRegex(StateFlushError, "malformed banks_flushed"):
                    ctl_mal.rollback()
                self.assertEqual(ctl_mal.receipts.read_all()[-1]["event"], "rollback_failed")

    def test_05_issue66_bad_decl_receipts_fallback_lock_and_guard_kills(self) -> None:
        with tempfile.TemporaryDirectory(prefix="iss66_") as td:
            os.chmod(td, 0o700)
            tdp = Path(td)

            # Defect 1a: rolled.required_banks=("bogus",) must append rollback_failed and re-raise StateFlushError.
            ctl_bad_rolled = self._make_controller(
                tdp / "bad_rolled",
                _CustomLifecycle(flushed=(STATE_BANK_KV,), rolled_required=("bogus",)),
            )
            with self.assertRaisesRegex(StateFlushError, "unknown state bank"):
                ctl_bad_rolled.rollback("bad_rolled_decl")
            entries_1a = ctl_bad_rolled.receipts.read_all()
            self.assertEqual([e["event"] for e in entries_1a], ["rollback_failed"])
            self.assertIn("StateFlushError", entries_1a[0]["reason"])
            self.assertEqual(entries_1a[0]["requested_reason"], "bad_rolled_decl")

            # Defect 1b: lifecycle.required_state_banks() raising RuntimeError must append rollback_failed and re-raise.
            class _RaisingDeclLifecycle:
                def required_state_banks(self) -> tuple[str, ...]:
                    raise RuntimeError("checkpoint bank metadata unreadable")

                def rollback(self, reason: str) -> LifecycleRollback:
                    return LifecycleRollback(
                        banks_flushed=(STATE_BANK_KV,),
                        slots_flushed=(0,),
                    )

            ctl_raise_decl = self._make_controller(
                tdp / "raise_decl",
                _RaisingDeclLifecycle(),
            )
            with self.assertRaisesRegex(RuntimeError, "checkpoint bank metadata unreadable"):
                ctl_raise_decl.rollback("raise_decl")
            entries_1b = ctl_raise_decl.receipts.read_all()
            self.assertEqual([e["event"] for e in entries_1b], ["rollback_failed"])
            self.assertIn("RuntimeError", entries_1b[0]["reason"])

            # Defect 2: undeclared fail-closed ALL_STATE_BANKS fallback cannot be lowered after construction.
            ctl_fallback = self._make_controller(
                tdp / "fallback_lock",
                _CustomLifecycle(flushed=(STATE_BANK_KV,)),
            )
            with self.assertRaisesRegex(
                StateFlushError, "missed banks: ssm_recurrent, lattice_horizontal_streams"
            ):
                ctl_fallback.rollback()
            ctl_fallback.required_state_banks = (STATE_BANK_KV,)
            with self.assertRaisesRegex(
                StateFlushError, "missed banks: ssm_recurrent, lattice_horizontal_streams"
            ):
                ctl_fallback.rollback()
            self.assertEqual(
                [e["event"] for e in ctl_fallback.receipts.read_all()],
                ["rollback_failed", "rollback_failed"],
            )

            # Post-init widening from KV-only declaration to KV+SSM is strictly enforced.
            ctl_widen = self._make_controller(
                tdp / "widen",
                _CustomLifecycle(flushed=(STATE_BANK_KV,), rolled_required=(STATE_BANK_KV,)),
            )
            ctl_widen.required_state_banks = (STATE_BANK_KV, STATE_BANK_SSM)
            with self.assertRaisesRegex(StateFlushError, "ssm_recurrent"):
                ctl_widen.rollback()

            # Lifecycle exposing required_state_banks() -> (KV, SSM) with rolled.required_banks=None accepts (KV, SSM).
            ctl_lc_accept = self._make_controller(
                tdp / "lc_accept",
                _CustomLifecycle(
                    flushed=(STATE_BANK_KV, STATE_BANK_SSM),
                    declared_required=(STATE_BANK_KV, STATE_BANK_SSM),
                    rolled_required=None,
                    expose_method=True,
                ),
            )
            rep_lc = ctl_lc_accept.rollback()
            self.assertTrue(rep_lc.verified)
            self.assertEqual(rep_lc.required_banks, (STATE_BANK_KV, STATE_BANK_SSM))
            self.assertEqual(rep_lc.banks_flushed, (STATE_BANK_KV, STATE_BANK_SSM))

    def test_06_issue67_per_slot_clean_receipt_enforcement(self) -> None:
        class _RawRollbackResult:
            def __init__(self, slots_flushed: Any, bank_flush_receipts: Any) -> None:
                self.slots_flushed = slots_flushed
                self.bank_flush_receipts = bank_flush_receipts

        class _RawReceipt:
            def __init__(self, slot_id: Any, banks_confirmed: Any, verified_clean: Any) -> None:
                self.slot_id = slot_id
                self.banks_confirmed = banks_confirmed
                self.verified_clean = verified_clean

        class _StaticWarp:
            def __init__(
                self,
                result: Any,
                pinned_banks: tuple[str, ...] | None = None,
            ) -> None:
                self._result = result
                if pinned_banks is not None:
                    self.pinned_checkpoint = _FakeCheckpoint(pinned_banks)

            def rollback(self, reason: str) -> Any:
                return self._result

        with tempfile.TemporaryDirectory(prefix="iss67_") as td:
            os.chmod(td, 0o700)
            tdp = Path(td)

            # Positive multi-slot control: both slots have 1 verified_clean=True receipt confirming all banks.
            warp_ok = _StaticWarp(
                RollbackResult(
                    reason="ok",
                    kill_switch_engaged=False,
                    slots_flushed=(0, 1),
                    elapsed_ms=1.0,
                    receipt=None,
                    bank_flush_receipts=(
                        BankFlushReceipt(0, ALL_STATE_BANKS, ALL_STATE_BANKS, None, True),
                        BankFlushReceipt(1, ALL_STATE_BANKS, ALL_STATE_BANKS, None, True),
                    ),
                )
            )
            ctl_ok = self._make_controller(tdp / "ok_multi", WarpModeldLifecycle(warp_ok))
            rep_ok = ctl_ok.rollback()
            self.assertTrue(rep_ok.verified)
            self.assertEqual(rep_ok.slots_flushed, (0, 1))
            self.assertEqual(set(rep_ok.banks_flushed), set(ALL_STATE_BANKS))

            # Case 1: slot 0 confirms all banks, slot 1 confirms KV only, slots_flushed=(0, 1) -> REJECT.
            warp_partial = _StaticWarp(
                RollbackResult(
                    reason="partial",
                    kill_switch_engaged=False,
                    slots_flushed=(0, 1),
                    elapsed_ms=1.0,
                    receipt=None,
                    bank_flush_receipts=(
                        BankFlushReceipt(0, ALL_STATE_BANKS, ALL_STATE_BANKS, None, True),
                        BankFlushReceipt(1, (STATE_BANK_KV,), (STATE_BANK_KV,), None, True),
                    ),
                )
            )
            ctl_partial = self._make_controller(tdp / "partial", WarpModeldLifecycle(warp_partial))
            with self.assertRaisesRegex(
                StateFlushError, "missed banks: ssm_recurrent, lattice_horizontal_streams"
            ):
                ctl_partial.rollback()
            self.assertEqual(ctl_partial.receipts.read_all()[-1]["event"], "rollback_failed")

            # Case 2: unflushed slot 7 supplies a bank that slot 0 lacks -> ignore slot 7 -> REJECT.
            warp_slot7 = _StaticWarp(
                RollbackResult(
                    reason="slot7",
                    kill_switch_engaged=False,
                    slots_flushed=(0,),
                    elapsed_ms=1.0,
                    receipt=None,
                    bank_flush_receipts=(
                        BankFlushReceipt(
                            0,
                            (STATE_BANK_KV, STATE_BANK_SSM),
                            (STATE_BANK_KV, STATE_BANK_SSM),
                            None,
                            True,
                        ),
                        BankFlushReceipt(7, ALL_STATE_BANKS, ALL_STATE_BANKS, None, True),
                    ),
                )
            )
            ctl_slot7 = self._make_controller(tdp / "slot7", WarpModeldLifecycle(warp_slot7))
            with self.assertRaisesRegex(StateFlushError, "lattice_horizontal_streams"):
                ctl_slot7.rollback()
            self.assertEqual(ctl_slot7.receipts.read_all()[-1]["event"], "rollback_failed")

            # Case 3: every bank confirmed on slot 0, but verified_clean is False -> REJECT.
            warp_dirty = _StaticWarp(
                RollbackResult(
                    reason="dirty",
                    kill_switch_engaged=False,
                    slots_flushed=(0,),
                    elapsed_ms=1.0,
                    receipt=None,
                    bank_flush_receipts=(
                        BankFlushReceipt(0, ALL_STATE_BANKS, ALL_STATE_BANKS, None, False),
                    ),
                )
            )
            ctl_dirty = self._make_controller(tdp / "dirty", WarpModeldLifecycle(warp_dirty))
            with self.assertRaisesRegex(StateFlushError, "missed banks"):
                ctl_dirty.rollback()
            self.assertEqual(ctl_dirty.receipts.read_all()[-1]["event"], "rollback_failed")

            # Missing receipt for a flushed slot, duplicate receipts for a slot, empty slots, and bool slot_id -> REJECT.
            extra_cases = (
                (
                    "missing_slot1",
                    RollbackResult(
                        "m", False, (0, 1), 1.0, None,
                        (BankFlushReceipt(0, ALL_STATE_BANKS, ALL_STATE_BANKS, None, True),),
                    ),
                    "missed banks",
                ),
                (
                    "dup_slot0",
                    RollbackResult(
                        "d", False, (0,), 1.0, None,
                        (
                            BankFlushReceipt(0, ALL_STATE_BANKS, ALL_STATE_BANKS, None, True),
                            BankFlushReceipt(0, ALL_STATE_BANKS, ALL_STATE_BANKS, None, True),
                        ),
                    ),
                    "missed banks",
                ),
                (
                    "empty_slots",
                    RollbackResult("e", False, (), 1.0, None, ()),
                    "missed banks",
                ),
                (
                    "bool_slot_id",
                    _RawRollbackResult(
                        (1,),
                        (_RawReceipt(True, ALL_STATE_BANKS, True),),
                    ),
                    "missed banks",
                ),
                (
                    "malformed_slots_str",
                    _RawRollbackResult("0", ()),
                    "malformed slots_flushed",
                ),
                (
                    "malformed_slots_bytes",
                    _RawRollbackResult(b"0", ()),
                    "malformed slots_flushed",
                ),
                (
                    "malformed_slots_int",
                    _RawRollbackResult(123, ()),
                    "malformed slots_flushed",
                ),
                (
                    "malformed_slots_bool_elem",
                    _RawRollbackResult((True,), ()),
                    "malformed slots_flushed",
                ),
                (
                    "malformed_slots_neg_elem",
                    _RawRollbackResult((-1,), ()),
                    "malformed slots_flushed",
                ),
                (
                    "malformed_slots_dup_elem",
                    _RawRollbackResult((0, 0), ()),
                    "malformed slots_flushed",
                ),
                (
                    "malformed_receipts_str",
                    _RawRollbackResult((0,), "bad"),
                    "malformed bank_flush_receipts",
                ),
                (
                    "malformed_receipts_bytes",
                    _RawRollbackResult((0,), b"bad"),
                    "malformed bank_flush_receipts",
                ),
                (
                    "malformed_receipts_int",
                    _RawRollbackResult((0,), 123),
                    "malformed bank_flush_receipts",
                ),
                (
                    "verified_clean_non_bool_int",
                    _RawRollbackResult((0,), (_RawReceipt(0, ALL_STATE_BANKS, 1),)),
                    "missed banks",
                ),
            )
            for tag, res_obj, rx in extra_cases:
                with self.subTest(tag=tag):
                    ctl_x = self._make_controller(
                        tdp / tag, WarpModeldLifecycle(_StaticWarp(res_obj))
                    )
                    with self.assertRaisesRegex(StateFlushError, rx):
                        ctl_x.rollback()
                    self.assertEqual(ctl_x.receipts.read_all()[-1]["event"], "rollback_failed")

            # Malformed rc.banks_confirmed must fail closed with StateFlushError (never TypeError or silent dedup).
            class _EvilConfirmedStr(str):
                pass

            class _ReceiptNoBanks:
                def __init__(self, slot_id: int) -> None:
                    self.slot_id = slot_id
                    self.verified_clean = True

            malformed_confirmed_cases = (
                ("confirmed_missing_attr", _ReceiptNoBanks(0), (STATE_BANK_KV,)),
                ("confirmed_none", _RawReceipt(0, None, True), (STATE_BANK_KV,)),
                ("confirmed_int", _RawReceipt(0, 123, True), (STATE_BANK_KV,)),
                ("confirmed_empty_str", _RawReceipt(0, "", True), (STATE_BANK_KV,)),
                ("confirmed_empty_bytes", _RawReceipt(0, b"", True), (STATE_BANK_KV,)),
                ("confirmed_str", _RawReceipt(0, STATE_BANK_KV, True), (STATE_BANK_KV,)),
                ("confirmed_bytes", _RawReceipt(0, b"kv_cache", True), (STATE_BANK_KV,)),
                ("confirmed_non_str_elem", _RawReceipt(0, (STATE_BANK_KV, 123), True), (STATE_BANK_KV,)),
                ("confirmed_bool_elem", _RawReceipt(0, (STATE_BANK_KV, True), True), (STATE_BANK_KV,)),
                ("confirmed_unhashable_elem", _RawReceipt(0, ([STATE_BANK_KV],), True), (STATE_BANK_KV,)),
                ("confirmed_str_subclass", _RawReceipt(0, (_EvilConfirmedStr(STATE_BANK_KV),), True), (STATE_BANK_KV,)),
                ("confirmed_unknown_bank", _RawReceipt(0, (*ALL_STATE_BANKS, "bogus"), True), None),
                ("confirmed_dup_kv_only", _RawReceipt(0, (STATE_BANK_KV, STATE_BANK_KV), True), (STATE_BANK_KV,)),
                ("confirmed_dup_all_banks", _RawReceipt(0, (*ALL_STATE_BANKS, STATE_BANK_KV), True), None),
            )
            for tag, rc_obj, pinned in malformed_confirmed_cases:
                with self.subTest(tag=tag):
                    lc_bad = WarpModeldLifecycle(
                        _StaticWarp(_RawRollbackResult((0,), (rc_obj,)), pinned_banks=pinned)
                    )
                    with self.assertRaisesRegex(StateFlushError, "malformed banks_confirmed"):
                        lc_bad.rollback("direct_bad_confirmed")
                    ctl_bad = self._make_controller(tdp / tag, lc_bad)
                    with self.assertRaisesRegex(StateFlushError, "malformed banks_confirmed"):
                        ctl_bad.rollback()
                    self.assertEqual(ctl_bad.receipts.read_all()[-1]["event"], "rollback_failed")


class TestA8CerebrasSchemaAndControllerBridge(unittest.TestCase):
    def test_01_schema_file_matches_frozen_manifest_and_lane7_checks(self) -> None:
        schema = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
        manifest = json.loads((_EXP_DIR / "manifest.json").read_text(encoding="utf-8"))
        knobs = manifest["allowed_candidate_knobs"]
        props = schema["properties"]

        self.assertFalse(schema["additionalProperties"])
        self.assertNotIn("strength", props)
        self.assertEqual(props["rank"]["enum"], [knobs["rank"]])
        self.assertEqual(props["target_layer"]["const"], manifest["last_layer_target"]["layer"])
        self.assertEqual(props["target_tensor"]["const"], knobs["target_tensor"])
        self.assertEqual(props["eta"]["minimum"], knobs["eta_range"][0])
        self.assertEqual(props["eta"]["maximum"], knobs["eta_range"][1])
        self.assertEqual(props["lambda"]["enum"], knobs["lambda_values"])
        self.assertEqual(props["lora_scale"]["enum"], [float(v) for v in knobs["lora_scale"]])
        self.assertEqual(tuple(props["quantization"]["enum"]), SUPPORTED_QUANT_DTYPES)
        self.assertIn("bf16", props["quantization"]["enum"])
        self.assertEqual(
            set(schema["required"]),
            {"target_layer", "target_tensor", "eta", "lambda", "rank", "lora_scale", "quantization"},
        )

        # Client constants match frozen manifest and schema.
        self.assertEqual(PINNED_TARGET_LAYER, 31)
        self.assertEqual(PINNED_TARGET_TENSOR, "ffn_up")
        self.assertEqual(ALLOWED_RANKS, (8,))
        self.assertEqual((ETA_MIN, ETA_MAX), (0.002, 0.02))
        self.assertEqual(ALLOWED_LAMBDAS, (0.1, 1, 10, "mean_eigenvalue"))
        self.assertEqual(ALLOWED_LORA_SCALES, (0.0, 1.0))
        self.assertEqual(ALLOWED_QUANTIZATIONS, SUPPORTED_QUANT_DTYPES)
        self.assertEqual(PROMPT_SET_VERSION, "cerebras-kimi-v2")
        # Fixed diagnose fixture candidate must itself validate cleanly.
        diag = [f for f in FIXED_PROMPT_FIXTURES if f["kind"] == "diagnose"][0]
        self.assertEqual(validate_candidate(diag["report"]["failed_candidate"]).rank, 8)

    def test_02_validate_candidate_rejects_stale_provisional_and_hostile_inputs(self) -> None:
        base = {
            "target_layer": 31,
            "target_tensor": "ffn_up",
            "eta": 0.01,
            "lambda": 1,
            "rank": 8,
            "lora_scale": 1.0,
            "quantization": "bf16",
        }
        # Exact boundary & allowlist positive controls.
        for eta_ok in (0.002, 0.02):
            self.assertEqual(validate_candidate({**base, "eta": eta_ok}).eta, eta_ok)
        for lam_in, lam_out in ((0.1, 0.1), (1, 1), (1.0, 1), (10, 10), (10.0, 10), ("mean_eigenvalue", "mean_eigenvalue")):
            self.assertEqual(validate_candidate({**base, "lambda": lam_in}).lam, lam_out)
        for sc_ok in (0, 0.0, 1, 1.0):
            self.assertEqual(validate_candidate({**base, "lora_scale": sc_ok}).lora_scale, float(sc_ok))
        for q_ok in SUPPORTED_QUANT_DTYPES:
            self.assertEqual(validate_candidate({**base, "quantization": q_ok}).quantization, q_ok)

        # Stale provisional payload rejected.
        with self.assertRaisesRegex(CerebrasSchemaError, "candidate keys"):
            validate_candidate({"target_layer": "last", "strength": 0.5, "rank": 16, "quantization": "q8_0"})
        # Mixed non-string, str-subclass, & huge-int / compound key dicts must fail closed cleanly.
        class _EvilKeyStr(str):
            pass

        evil_key_payload = dict(base)
        evil_key_payload[_EvilKeyStr("target_layer")] = evil_key_payload.pop("target_layer")
        for bad_key_payload, expect_frag in (
            ({1: "bad", "target_layer": 31}, "1"),
            ({**base, 10**5000: 2}, "int with"),
            ({**base, (10**5000,): 2}, "<tuple>"),
            (evil_key_payload, "<_EvilKeyStr>"),
        ):
            with self.assertRaisesRegex(CerebrasSchemaError, "candidate keys") as ctx:
                validate_candidate(bad_key_payload)
            self.assertIn(expect_frag, str(ctx.exception))
            self.assertLess(len(str(ctx.exception)), 500)
        # Primitive repr preserved for ordinary scalar failures while compound huge ints stay safe.
        with self.assertRaisesRegex(CerebrasSchemaError, "16") as ctx_rank:
            validate_candidate({**base, "rank": 16})
        self.assertNotIn("<int>", str(ctx_rank.exception))
        with self.assertRaisesRegex(CerebrasSchemaError, "<list>") as ctx_list:
            validate_candidate({**base, "target_layer": [10**5000]})
        self.assertLess(len(str(ctx_list.exception)), 500)
        # Raw LoRA override key rejected.
        with self.assertRaisesRegex(CerebrasSchemaError, "candidate keys"):
            validate_candidate({**base, "lora_path": "/dev/null"})
        # Per-field negative controls (bool, str subclass, non-finite, oversized int, wrong type/range).
        class _EvilFieldStr(str):
            pass

        bad_cases = [
            ("target_layer", "last", "target_layer"),
            ("target_layer", 30, "target_layer"),
            ("target_layer", True, "target_layer"),
            ("target_layer", 10**10000, "target_layer"),
            ("target_tensor", "ffn_down", "target_tensor"),
            ("target_tensor", _EvilFieldStr("ffn_up"), "target_tensor"),
            ("target_tensor", 31, "target_tensor"),
            ("eta", 0.001999, "eta"),
            ("eta", 0.020001, "eta"),
            ("eta", True, "eta"),
            ("eta", float("nan"), "eta"),
            ("eta", 10**10000, "eta"),
            ("lambda", "median", "lambda"),
            ("lambda", 0.5, "lambda"),
            ("lambda", True, "lambda"),
            ("lambda", False, "lambda"),
            ("lambda", None, "lambda"),
            ("lambda", 10**10000, "lambda"),
            ("rank", 16, "rank"),
            ("rank", 8.0, "rank"),
            ("rank", True, "rank"),
            ("rank", 10**10000, "rank"),
            ("lora_scale", -1.0, "lora_scale"),
            ("lora_scale", 0.5, "lora_scale"),
            ("lora_scale", True, "lora_scale"),
            ("lora_scale", False, "lora_scale"),
            ("lora_scale", 10**10000, "lora_scale"),
            ("quantization", "q8_0", "quantization"),
            ("quantization", "q4_0", "quantization"),
            ("quantization", _EvilFieldStr("bf16"), "quantization"),
            ("quantization", 16, "quantization"),
        ]
        for idx, (field, bad_val, rx) in enumerate(bad_cases):
            with self.subTest(idx=idx, field=field, bad_type=type(bad_val).__name__):
                payload = dict(base)
                payload[field] = bad_val
                with self.assertRaisesRegex(CerebrasSchemaError, rx) as ctx:
                    validate_candidate(payload)
                self.assertLess(len(str(ctx.exception)), 500)

    def test_03_end_to_end_cerebras_propose_to_kv_only_controller_accept(self) -> None:
        contract = load_contract(_EXP_DIR)
        with MockCerebrasServer("ok_propose") as server:
            client = CerebrasKimiClient(
                "test-key-not-real", base_url=server.base_url, retry_delay_seconds=0.0
            )
            cfg, prov_receipt = client.propose_candidate(
                {"task_summary": "frozen demo proposal", "baseline_metrics": {"task_top1": 0.518}}
            )
        self.assertEqual(prov_receipt.status, "ok")
        self.assertEqual(prov_receipt.prompt_set_version, PROMPT_SET_VERSION)

        with tempfile.TemporaryDirectory(prefix="a2a8_e2e_") as td:
            os.chmod(td, 0o700)
            warp = _FakeWarp(pinned_banks=(STATE_BANK_KV,), confirmed_banks=(STATE_BANK_KV,))
            ctl = ExperimentController(
                contract=contract,
                compiler=_FakeCompiler(),
                runtime=_FakeRuntime(),
                lifecycle=WarpModeldLifecycle(warp),
                receipts=ReceiptLog(Path(td) / "receipts.jsonl"),
                environment=_ENV,
            )
            verdict, receipt = ctl.run_experiment(
                cfg.to_controller_dict(), actual_parent_sha256=_PARENT_SHA
            )
            self.assertEqual(verdict.verdict, "ACCEPT")
            self.assertEqual(receipt["verdict"], "ACCEPT")
            self.assertEqual(receipt["candidate"]["config"]["rank"], 8)
            self.assertEqual(receipt["candidate"]["config"]["target_layer"], 31)
            self.assertEqual(receipt["candidate"]["config"]["eta"], 0.01)
            self.assertTrue(ctl.receipts.verify())


if __name__ == "__main__":
    unittest.main()
