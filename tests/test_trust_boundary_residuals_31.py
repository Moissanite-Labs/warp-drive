"""Regression tests for trust-boundary residuals tracked in issue 31.

Each test in the mutation group kills exactly one one-line mutation from
issue 31. The last two tests pin the two fail-open residuals found by the
triage probes: a dirty KV bank that still signed verified_clean, and a
canary client without list_slots that was treated as clean.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest import mock
from typing import Any

from warp_modeld.canary import (
    CanaryRunner,
    CanarySpec,
    CanarySuite,
    ExternalCommandCanaryRunner,
    _erase_slot_and_confirm,
    _is_slot_clean_for_banks,
)
from warp_modeld.cli import _cmd_serve
from warp_modeld.errors import CanaryFailedError, LatticeFlushError, StateFlushError
from warp_modeld.fingerprint import AdapterBundle, CheckpointFingerprint
from warp_modeld.ledger import HmacSha256Signer, LedgerVerifier, SignedLedger
from warp_modeld.llama_client import LlamaClientError
from warp_modeld.state_banks import (
    STATE_BANK_KV,
    STATE_BANK_LATTICE,
    STATE_BANK_SSM,
    StateBankStatus,
)
from warp_modeld.verifier import WarpModeld

from tests.helpers import (
    CANARY_SUITE_PATH,
    make_adapter_bundle_dict,
    make_checkpoint,
    make_joint_bounds,
    make_lineage,
    make_runtime_flags,
    make_single_bounds,
)


def _clean_slot(
    slot_id: int = 0,
    *,
    state_banks: dict[str, StateBankStatus] | None = None,
    **overrides: Any,
) -> SimpleNamespace:
    banks = (
        state_banks
        if state_banks is not None
        else {STATE_BANK_KV: StateBankStatus(bank=STATE_BANK_KV, tainted=False)}
    )
    base: dict[str, Any] = {
        "id": slot_id,
        "is_processing": False,
        "recurrent_state_tainted": False,
        "lattice_state_tainted": False,
        "ssm_state_tainted": False,
        "lattice_layers_tainted": 0,
        "active_lora_ids": (),
        "n_decoded": 0,
        "n_prompt_tokens_cache": 0,
        "state_banks": banks,
    }
    base.update(overrides)
    return SimpleNamespace(**base)


def _tiny_suite() -> CanarySuite:
    specs = tuple(
        CanarySpec(
            canary_id=f"pres-0{i}",
            category="preservation",
            prompt=f"Check {i}",
            must_contain=("OK_CANARY_PASS",),
            min_chars=4,
            max_chars=64,
        )
        for i in range(1, 5)
    ) + (
        CanarySpec(
            canary_id="dom-01-corpus",
            category="domain",
            domains=("corpus",),
            prompt="Check corpus",
            must_contain=("OK_CANARY_PASS",),
            min_chars=4,
            max_chars=64,
        ),
    )
    return CanarySuite(
        suite_sha256="b" * 64,
        canaries=specs,
        source_path="unit-memory-residuals",
    )


def _sample_bundle() -> AdapterBundle:
    return AdapterBundle.from_dict(make_adapter_bundle_dict())


def _build_modeld(td: str, client: Any, *, has_ssm: bool = False, has_lattice: bool = False) -> WarpModeld:
    base = make_checkpoint()
    ckpt = CheckpointFingerprint(
        model_id=base.model_id,
        layout_sha256=base.layout_sha256,
        weights_sha256=base.weights_sha256,
        config_sha256=base.config_sha256,
        tokenizer_sha256=base.tokenizer_sha256,
        chat_template_sha256=base.chat_template_sha256,
        safetensors_provenance_sha256=base.safetensors_provenance_sha256,
        has_ssm_recurrent=has_ssm,
        has_horizontal_lattice=has_lattice,
        lattice_layers=4 if has_lattice else 0,
        lattice_width=8 if has_lattice else 0,
    )
    signer = HmacSha256Signer(b"residuals-test-key-32-bytes-0001", key_id="k1")
    return WarpModeld(
        pinned_checkpoint=ckpt,
        pinned_lineage=make_lineage(),
        live_runtime_flags=make_runtime_flags(),
        single_bounds=make_single_bounds(),
        joint_bounds=make_joint_bounds(),
        canary_suite=_tiny_suite(),
        llama_client=client,
        ledger=SignedLedger(Path(td) / "ledger.jsonl", signer),
    )


class TestIssue31MutationKills(unittest.TestCase):
    def test_cli_serve_forwards_allow_legacy_flag_into_warpmodeld(self) -> None:
        # Mutation 1: dropping the cli.py forwarding line must fail this test.
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            key_path = tmp / "key.bin"
            key_path.write_bytes(b"0123456789abcdef0123456789abcdef")
            cfg: dict[str, Any] = {
                "checkpoint": make_checkpoint().to_dict(),
                "pinned_lineage": make_lineage().to_dict(),
                "runtime_flags": make_runtime_flags().to_dict(),
                "single_bounds": {
                    "max_frobenius_sq": {"num": 5, "den": 1},
                    "max_spectral_norm_sq": {"num": 2, "den": 1},
                    "max_leakage_energy": {"num": 1, "den": 100},
                    "max_safety_dot_sq": {"num": 1, "den": 1000},
                },
                "joint_bounds": {
                    "max_frobenius_sq": {"num": 20, "den": 1},
                    "max_spectral_norm_sq": {"num": 8, "den": 1},
                    "max_leakage_energy": {"num": 1, "den": 20},
                    "max_safety_dot_sq": {"num": 1, "den": 200},
                },
                "canary_suite_path": str(CANARY_SUITE_PATH),
                "ledger_key_path": str(key_path),
                "ledger_path": str(tmp / "ledger.jsonl"),
                "llama_server_url": "http://127.0.0.1:8080",
                "socket_path": str(tmp / "warp.sock"),
                "allow_legacy_implicit_kv_flush": True,
            }
            cfg["checkpoint"].pop("config_bundle_sha256", None)
            cfg_path = tmp / "cfg.json"
            cfg_path.write_text(json.dumps(cfg), encoding="utf-8")

            captured: dict[str, Any] = {}

            class _CapturingServer:
                def __init__(self, *args: Any, **kwargs: Any) -> None:
                    captured["modeld"] = args[1] if len(args) > 1 else kwargs.get("modeld")
                    raise RuntimeError("captured_modeld")

            with mock.patch("warp_modeld.cli.WarpUnixRpcServer", _CapturingServer):
                with self.assertRaisesRegex(RuntimeError, "captured_modeld"):
                    _cmd_serve(SimpleNamespace(config=str(cfg_path)))

            modeld = captured["modeld"]
            self.assertIsInstance(modeld, WarpModeld)
            self.assertTrue(modeld.allow_legacy_implicit_kv_flush)
            self.assertTrue(modeld.canary_runner.allow_legacy_implicit_kv_flush)

    def test_list_slots_error_means_slot_not_clean(self) -> None:
        # Mutation 2: returning True on LlamaClientError must fail this test.
        class _BoomSlotsClient:
            def list_slots(self) -> list[Any]:
                raise LlamaClientError("simulated /slots transport failure")

            def erase_slot(self, slot_id: int, banks: Any = None) -> dict[str, Any]:
                return {"banks_flushed": [STATE_BANK_KV]}

        client = _BoomSlotsClient()
        self.assertFalse(_is_slot_clean_for_banks(client, 0, (STATE_BANK_KV,)))  # type: ignore[arg-type]
        self.assertFalse(
            _erase_slot_and_confirm(
                client,  # type: ignore[arg-type]
                0,
                erase_banks=None,
                expected_banks=(STATE_BANK_KV,),
            )
        )

    def test_external_runner_passes_banks_to_erase_slot(self) -> None:
        # Mutation 3: passing erase_banks=None in the external runner must fail.
        suite_sha = hashlib.sha256(b"opaque-suite-residuals").hexdigest()
        payload = {
            "suite_sha256": suite_sha,
            "preservation_passed": 4,
            "preservation_total": 4,
            "outcomes": [
                {"canary_id": "pres-01", "category": "preservation", "passed": True, "failures": []},
                {"canary_id": "pres-02", "category": "preservation", "passed": True, "failures": []},
                {"canary_id": "pres-03", "category": "preservation", "passed": True, "failures": []},
                {"canary_id": "pres-04", "category": "preservation", "passed": True, "failures": []},
                {
                    "canary_id": "dom-01",
                    "category": "domain",
                    "domain": "corpus",
                    "passed": True,
                    "failures": [],
                },
            ],
        }
        cmd = (
            sys.executable,
            "-I",
            "-B",
            "-c",
            f"import json; print(json.dumps({payload!r}))",
        )
        clean_banks = {
            STATE_BANK_KV: StateBankStatus(bank=STATE_BANK_KV, tainted=False),
            STATE_BANK_SSM: StateBankStatus(bank=STATE_BANK_SSM, tainted=False),
        }

        class _RecordingClient:
            base_url = "http://127.0.0.1:8080"

            def __init__(self) -> None:
                self.erase_banks_seen: list[Any] = []

            def list_lora_adapters(self) -> list[Any]:
                return [SimpleNamespace(id=0, path="/nonexistent/adapter.gguf", scale=0.0)]

            def list_slots(self) -> list[Any]:
                return [_clean_slot(0, state_banks=dict(clean_banks))]

            def erase_slot(self, slot_id: int, banks: Any = None) -> dict[str, Any]:
                self.erase_banks_seen.append(banks)
                return {"banks_flushed": [STATE_BANK_KV, STATE_BANK_SSM]}

        client = _RecordingClient()
        result = ExternalCommandCanaryRunner(
            client,  # type: ignore[arg-type]
            cmd,
            suite_sha256_hint=suite_sha,
        ).run([_sample_bundle()], required_state_banks=(STATE_BANK_KV, STATE_BANK_SSM))
        self.assertTrue(result.canary_slot_flushed)
        self.assertTrue(client.erase_banks_seen)
        for seen in client.erase_banks_seen:
            self.assertEqual(seen, (STATE_BANK_KV, STATE_BANK_SSM))

    def test_multi_slot_safe_erase_failure_propagates_in_finally(self) -> None:
        # Mutation 4: discarding the _safe_erase result must fail this test.
        # The tiny suite has 5 specs, so the first 5 erases are per-canary
        # erases. Erase calls after that are the finally cleanup erases.
        suite = _tiny_suite()
        bundle = _sample_bundle()

        class _MultiSlotClient:
            base_url = "http://127.0.0.1:8080"

            def __init__(self) -> None:
                self._lock = threading.Lock()
                self.erase_calls = 0

            def list_lora_adapters(self) -> list[Any]:
                return [SimpleNamespace(id=0, path="/nonexistent/adapter.gguf", scale=0.0)]

            def list_slots(self) -> list[Any]:
                return [_clean_slot(0), _clean_slot(1)]

            def erase_slot(self, slot_id: int, banks: Any = None) -> dict[str, Any]:
                with self._lock:
                    self.erase_calls += 1
                    call_no = self.erase_calls
                if call_no > 5 and slot_id == 1:
                    return {"banks_flushed": []}
                return {"banks_flushed": [STATE_BANK_KV]}

            def chat_completion(
                self, messages: list[dict[str, str]], **kwargs: Any
            ) -> dict[str, Any]:
                return {"choices": [{"message": {"content": "OK_CANARY_PASS"}}]}

        client = _MultiSlotClient()
        with self.assertRaises(CanaryFailedError):
            CanaryRunner(client, suite).run(  # type: ignore[arg-type]
                [bundle], required_state_banks=(STATE_BANK_KV,)
            )
        self.assertEqual(client.erase_calls, 7)

    def test_flush_all_slots_reports_post_erase_missing_slot(self) -> None:
        # Mutation 5: disabling the missing-slot check must fail this test.
        class _MissingPostSlotClient:
            def __init__(self) -> None:
                self._calls = 0

            def list_slots(self) -> list[Any]:
                self._calls += 1
                if self._calls == 1:
                    return [_clean_slot(0)]
                return []

            def erase_slot(self, slot_id: int, banks: Any = None) -> dict[str, Any]:
                return {"banks_flushed": [STATE_BANK_KV]}

        with tempfile.TemporaryDirectory() as td:
            modeld = _build_modeld(td, _MissingPostSlotClient(), has_ssm=False)
            with self.assertRaisesRegex(StateFlushError, "missing pre-erase"):
                modeld._flush_all_slots()


class TestResidualFailOpens(unittest.TestCase):
    def test_flush_all_slots_rejects_dirty_kv_bank_after_erase(self) -> None:
        clean_ssm = StateBankStatus(bank=STATE_BANK_SSM, tainted=False)
        clean_kv = StateBankStatus(bank=STATE_BANK_KV, tainted=False)
        dirty_cases = {
            "tokens_or_layers_5": StateBankStatus(
                bank=STATE_BANK_KV, tainted=False, tokens_or_layers=5
            ),
            "tainted": StateBankStatus(bank=STATE_BANK_KV, tainted=True),
        }

        def make_client(after_banks: dict[str, StateBankStatus]) -> Any:
            class _Client:
                def list_slots(self) -> list[Any]:
                    return [_clean_slot(0, state_banks=dict(after_banks))]

                def erase_slot(self, slot_id: int, banks: Any = None) -> dict[str, Any]:
                    return {"banks_flushed": [STATE_BANK_KV, STATE_BANK_SSM]}

            return _Client()

        for label, dirty_kv in dirty_cases.items():
            with self.subTest(kv_case=label):
                self.assertFalse(dirty_kv.is_clean)
                with tempfile.TemporaryDirectory() as td:
                    modeld = _build_modeld(
                        td,
                        make_client(
                            {STATE_BANK_KV: dirty_kv, STATE_BANK_SSM: clean_ssm}
                        ),
                        has_ssm=True,
                    )
                    with self.assertRaises(StateFlushError):
                        modeld._flush_all_slots()

        # Positive control: both banks clean after erase still passes.
        with tempfile.TemporaryDirectory() as td:
            modeld = _build_modeld(
                td,
                make_client({STATE_BANK_KV: clean_kv, STATE_BANK_SSM: clean_ssm}),
                has_ssm=True,
            )
            flushed, receipts = modeld._flush_all_slots()
            self.assertEqual(flushed, (0,))
            self.assertTrue(receipts[0].verified_clean)

    def test_client_without_list_slots_is_not_clean(self) -> None:
        class _NoListSlotsClient:
            def erase_slot(self, slot_id: int, banks: Any = None) -> dict[str, Any]:
                return {"banks_flushed": [STATE_BANK_KV]}

        client = _NoListSlotsClient()
        self.assertFalse(hasattr(client, "list_slots"))
        self.assertFalse(_is_slot_clean_for_banks(client, 0, (STATE_BANK_KV,)))  # type: ignore[arg-type]
        self.assertFalse(
            _erase_slot_and_confirm(
                client,  # type: ignore[arg-type]
                0,
                erase_banks=None,
                expected_banks=(STATE_BANK_KV,),
            )
        )

    def test_kv_only_flush_rejects_dirty_non_required_banks_and_flags(self) -> None:
        clean_kv = StateBankStatus(bank=STATE_BANK_KV, tainted=False)
        dirty_ssm = StateBankStatus(bank=STATE_BANK_SSM, tainted=True)
        dirty_lattice = StateBankStatus(bank=STATE_BANK_LATTICE, tainted=True)

        def make_client(banks: dict[str, StateBankStatus], **flags: Any) -> Any:
            class _Client:
                def list_slots(self) -> list[Any]:
                    return [_clean_slot(0, state_banks=dict(banks), **flags)]

                def erase_slot(self, slot_id: int, banks: Any = None) -> dict[str, Any]:
                    return {"banks_flushed": [STATE_BANK_KV]}

            return _Client()

        cases = {
            "extra_dirty_ssm_bank": ({STATE_BANK_KV: clean_kv, STATE_BANK_SSM: dirty_ssm}, {}),
            "extra_dirty_lattice_bank": ({STATE_BANK_KV: clean_kv, STATE_BANK_LATTICE: dirty_lattice}, {}),
            "top_level_ssm_taint": ({STATE_BANK_KV: clean_kv}, {"ssm_state_tainted": True}),
            "top_level_lattice_taint": ({STATE_BANK_KV: clean_kv}, {"lattice_state_tainted": True}),
            "lattice_layers_taint": ({STATE_BANK_KV: clean_kv}, {"lattice_layers_tainted": 1}),
        }
        for label, (banks, flags) in cases.items():
            with self.subTest(case=label):
                with tempfile.TemporaryDirectory() as td:
                    modeld = _build_modeld(td, make_client(banks, **flags))
                    with self.assertRaises((StateFlushError, LatticeFlushError)):
                        modeld._flush_all_slots()

        with tempfile.TemporaryDirectory() as td:
            modeld = _build_modeld(td, make_client({STATE_BANK_KV: clean_kv}))
            flushed, receipts = modeld._flush_all_slots()
            self.assertEqual(flushed, (0,))
            self.assertTrue(receipts[0].verified_clean)

    def test_kv_only_rollback_signs_no_verified_clean_receipt_when_dirty(self) -> None:
        # Public rollback path: a dirty non-required bank or top-level taint must
        # raise StateFlushError and the signed ledger must not contain any
        # bank_flush_receipts entry claiming verified_clean=True.
        clean_kv = StateBankStatus(bank=STATE_BANK_KV, tainted=False)
        dirty_ssm = StateBankStatus(bank=STATE_BANK_SSM, tainted=True)
        dirty_lattice = StateBankStatus(bank=STATE_BANK_LATTICE, tainted=True)
        cases = {
            "extra_dirty_ssm_bank": ({STATE_BANK_KV: clean_kv, STATE_BANK_SSM: dirty_ssm}, {}),
            "extra_dirty_lattice_bank": ({STATE_BANK_KV: clean_kv, STATE_BANK_LATTICE: dirty_lattice}, {}),
            "top_level_ssm_taint": ({STATE_BANK_KV: clean_kv}, {"ssm_state_tainted": True}),
            "top_level_lattice_taint": ({STATE_BANK_KV: clean_kv}, {"lattice_state_tainted": True}),
        }

        def make_client(banks: dict[str, StateBankStatus], **flags: Any) -> Any:
            class _Client:
                def list_lora_adapters(self) -> list[Any]:
                    return []

                def list_slots(self) -> list[Any]:
                    return [_clean_slot(0, state_banks=dict(banks), **flags)]

                def erase_slot(self, slot_id: int, banks: Any = None) -> dict[str, Any]:
                    return {"banks_flushed": [STATE_BANK_KV]}

            return _Client()

        for label, (banks, flags) in cases.items():
            with self.subTest(case=label):
                with tempfile.TemporaryDirectory() as td:
                    ledger_path = Path(td) / "ledger.jsonl"
                    modeld = _build_modeld(td, make_client(banks, **flags))
                    with self.assertRaises(StateFlushError):
                        modeld.rollback(reason="review_blocker_probe")
                    signer = HmacSha256Signer(b"residuals-test-key-32-bytes-0001", key_id="k1")
                    receipts = LedgerVerifier.verify_file(ledger_path, signer)
                    self.assertTrue(receipts)
                    for receipt in receipts:
                        self.assertEqual(receipt.event, "reject")
                        bank_receipts = receipt.details.get("bank_flush_receipts") or []
                        for bank_receipt in bank_receipts:
                            self.assertFalse(bank_receipt.get("verified_clean"))

    def test_kv_only_flush_rejects_omitted_kv_bank_and_non_dict_state_banks(self) -> None:
        # Pins the `bank_status is None` branch of the required-bank check
        # (omitted kv_cache key) and the isinstance guard on state_banks.
        clean_ssm = StateBankStatus(bank=STATE_BANK_SSM, tainted=False)
        cases = {
            "empty_state_banks": {},
            "only_ssm_bank": {STATE_BANK_SSM: clean_ssm},
            "non_dict_state_banks": [],
        }

        def make_client(state_banks: Any) -> Any:
            class _Client:
                def list_slots(self) -> list[Any]:
                    return [_clean_slot(0, state_banks=state_banks)]

                def erase_slot(self, slot_id: int, banks: Any = None) -> dict[str, Any]:
                    return {"banks_flushed": [STATE_BANK_KV]}

            return _Client()

        for label, banks in cases.items():
            with self.subTest(case=label):
                with tempfile.TemporaryDirectory() as td:
                    modeld = _build_modeld(td, make_client(banks))
                    with self.assertRaises(StateFlushError):
                        modeld._flush_all_slots()

    def test_client_with_list_slots_none_is_not_clean(self) -> None:
        class _NoneListSlotsClient:
            list_slots = None

            def erase_slot(self, slot_id: int, banks: Any = None) -> dict[str, Any]:
                return {"banks_flushed": [STATE_BANK_KV]}

        client = _NoneListSlotsClient()
        self.assertFalse(_is_slot_clean_for_banks(client, 0, (STATE_BANK_KV,)))  # type: ignore[arg-type]


class TestWD41FlushFailClosedWitnesses(unittest.TestCase):
    """WD41-04 witnesses: _flush_all_slots must fail closed with its own error types."""

    def test_flush_all_slots_with_list_slots_none_raises_flush_error(self) -> None:
        class _NoneListSlots:
            list_slots = None

            def erase_slot(self, slot_id: int, banks: Any = None) -> dict[str, Any]:
                return {"banks_flushed": [STATE_BANK_KV]}

        with tempfile.TemporaryDirectory() as td:
            modeld = _build_modeld(td, _NoneListSlots())
            with self.assertRaises(StateFlushError):
                modeld._flush_all_slots()

    def test_flush_all_slots_without_list_slots_attribute_raises_flush_error(self) -> None:
        class _NoListSlots:
            def erase_slot(self, slot_id: int, banks: Any = None) -> dict[str, Any]:
                return {"banks_flushed": [STATE_BANK_KV]}

        with tempfile.TemporaryDirectory() as td:
            modeld = _build_modeld(td, _NoListSlots())
            with self.assertRaises(StateFlushError):
                modeld._flush_all_slots()

    def test_flush_all_slots_lattice_without_list_slots_raises_lattice_error(self) -> None:
        class _NoListSlots:
            def erase_slot(self, slot_id: int, banks: Any = None) -> dict[str, Any]:
                return {"banks_flushed": [STATE_BANK_KV, STATE_BANK_LATTICE]}

        with tempfile.TemporaryDirectory() as td:
            modeld = _build_modeld(td, _NoListSlots(), has_lattice=True)
            with self.assertRaises(LatticeFlushError):
                modeld._flush_all_slots()

    def test_flush_all_slots_with_state_banks_none_raises_flush_error(self) -> None:
        class _Client:
            def list_slots(self) -> list[Any]:
                slot = _clean_slot(0)
                slot.state_banks = None
                return [slot]

            def erase_slot(self, slot_id: int, banks: Any = None) -> dict[str, Any]:
                return {"banks_flushed": [STATE_BANK_KV]}

        with tempfile.TemporaryDirectory() as td:
            modeld = _build_modeld(td, _Client())
            with self.assertRaises(StateFlushError):
                modeld._flush_all_slots()

    def test_flush_all_slots_with_none_bank_entry_raises_flush_error(self) -> None:
        clean_kv = StateBankStatus(bank=STATE_BANK_KV, tainted=False)

        class _Client:
            def list_slots(self) -> list[Any]:
                slot = _clean_slot(0)
                slot.state_banks = {STATE_BANK_KV: clean_kv, STATE_BANK_SSM: None}
                return [slot]

            def erase_slot(self, slot_id: int, banks: Any = None) -> dict[str, Any]:
                return {"banks_flushed": [STATE_BANK_KV]}

        with tempfile.TemporaryDirectory() as td:
            modeld = _build_modeld(td, _Client())
            with self.assertRaises(StateFlushError):
                modeld._flush_all_slots()

    def test_is_slot_clean_for_banks_with_none_bank_entry_returns_false(self) -> None:
        class _Client:
            def list_slots(self) -> list[Any]:
                slot = _clean_slot(0)
                slot.state_banks = {
                    STATE_BANK_KV: StateBankStatus(bank=STATE_BANK_KV, tainted=False),
                    STATE_BANK_SSM: None,
                }
                return [slot]

        self.assertFalse(_is_slot_clean_for_banks(_Client(), 0, (STATE_BANK_KV,)))  # type: ignore[arg-type]

    def test_canary_runner_with_list_slots_none_fails_closed(self) -> None:
        class _NoneListSlotsClient:
            list_slots = None

            def list_lora_adapters(self) -> list[Any]:
                return [SimpleNamespace(id=0, path="/nonexistent/adapter.gguf", scale=0.0)]

            def erase_slot(self, slot_id: int, banks: Any = None) -> dict[str, Any]:
                return {"banks_flushed": [STATE_BANK_KV]}

            def chat_completion(self, messages: list[dict[str, str]], **kwargs: Any) -> dict[str, Any]:
                return {"choices": [{"message": {"content": "OK_CANARY_PASS"}}]}

        with tempfile.TemporaryDirectory() as td:
            client = _NoneListSlotsClient()
            with self.assertRaises(CanaryFailedError):
                CanaryRunner(client, _tiny_suite()).run(  # type: ignore[arg-type]
                    [_sample_bundle()], required_state_banks=(STATE_BANK_KV,)
                )


if __name__ == "__main__":
    unittest.main()
