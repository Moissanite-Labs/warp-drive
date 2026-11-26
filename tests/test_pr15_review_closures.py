"""Targeted single-guard and adversarial regression tests closing PR #15 review findings.

Covers:
  - Singleton and multi-adapter composed-certificate exact equality/triangle checks for
    all 4 metrics (frobenius_sq, spectral_norm_sq, leakage_energy, max_safety_dot_sq)
    under unequal rational weights, unequal radix scales, and reduced/unreduced scales.
  - POSIX leading-slash collapsing (`//`, `///`, `//<protected>`, symlink-to-`/` with `/`)
    in `blueprints/sandbox/warp-sandbox-exec.sh`.
  - Every single-guard check in `state_banks.py`, `verifier.py` (including empty `/slots`
    and `allow_legacy_implicit_kv_flush` matrix), `cli.py`, `CanaryRunner`, and
    `ExternalCommandCanaryRunner` (pre-run & post-run erase verification).
  - Study R5 suites (`test_weft_cross_audit_r5.py`, `test_warp_drive_runtime_r5.py`).
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
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
)
from warp_modeld.certificate import (
    CertificateBounds,
    FixedRadixCertificate,
    RationalBound,
    stack_composition_digest,
    verify_stack_division_free,
)
from warp_modeld.cli import _cmd_serve
from warp_modeld.errors import (
    CanaryFailedError,
    CertificateError,
    LatticeFlushError,
    StateFlushError,
)
from warp_modeld.fingerprint import AdapterBundle, CheckpointFingerprint, RuntimeFlags
from warp_modeld.ledger import HmacSha256Signer, SignedLedger
from warp_modeld.state_banks import (
    STATE_BANK_KV,
    STATE_BANK_LATTICE,
    STATE_BANK_SSM,
    BankFlushReceipt,
    StateBankStatus,
)
from warp_modeld.verifier import WarpModeld

from tests.helpers import (
    CANARY_SUITE_PATH,
    REPO_ROOT,
    fake_sha,
    make_adapter_bundle_dict,
    make_checkpoint,
    make_joint_bounds,
    make_lineage,
    make_runtime_flags,
    make_single_bounds,
)


def _clean_slot(slot_id: int = 0, **overrides: Any) -> SimpleNamespace:
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
        "state_banks": {
            STATE_BANK_KV: StateBankStatus(bank=STATE_BANK_KV, tainted=False),
        },
    }
    base.update(overrides)
    return SimpleNamespace(**base)


class _StubCanaryLlamaClient:
    """Minimal deterministic stub llama-server client for single-guard isolation tests."""

    def __init__(
        self,
        *,
        erase_responses: list[Any] | None = None,
        slots_factory: Any = None,
        base_url: str = "http://127.0.0.1:8080",
    ) -> None:
        self.base_url = base_url
        self._erase_responses = (
            list(erase_responses)
            if erase_responses is not None
            else [{"id_slot": 0, "erased": True, "banks_flushed": [STATE_BANK_KV]}]
        )
        self._erase_idx = 0
        self.erase_calls = 0
        self._slots_factory = slots_factory

    def list_lora_adapters(self) -> list[Any]:
        return [SimpleNamespace(id=0, path="/nonexistent/adapter.gguf", scale=0.0)]

    def set_lora_adapters(self, adapters: list[dict[str, Any]]) -> dict[str, Any]:
        return {"status": "ok"}

    def list_slots(self) -> list[Any]:
        if self._slots_factory is not None:
            return self._slots_factory(self.erase_calls)
        return [_clean_slot(0)]

    def erase_slot(self, slot_id: int, *, banks: Any = None) -> Any:
        self.erase_calls += 1
        idx = min(self._erase_idx, len(self._erase_responses) - 1)
        self._erase_idx += 1
        return self._erase_responses[idx]

    def chat_completion(self, messages: list[dict[str, str]], **kwargs: Any) -> dict[str, Any]:
        return {"choices": [{"message": {"content": "OK_CANARY_PASS"}}]}


def _tiny_canary_suite() -> CanarySuite:
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
        suite_sha256="a" * 64,
        canaries=specs,
        source_path="unit-memory",
    )


def _sample_bundle() -> AdapterBundle:
    return AdapterBundle.from_dict(make_adapter_bundle_dict())


class TestSingletonComposedCertificateClosures(unittest.TestCase):
    def _make_singleton_case(
        self,
        *,
        scale_num: int,
        scale_den: int,
        adapter_radix: int,
        composed_radix: int,
        frob: int,
        spec: int,
        leak: int,
        safety: int,
    ) -> tuple[
        list[tuple[FixedRadixCertificate, str, str, int, int]],
        FixedRadixCertificate,
        str,
        CertificateBounds,
    ]:
        ckpt = make_checkpoint()
        asha = fake_sha(f"singleton-{scale_num}-{scale_den}-{adapter_radix}-{composed_radix}")
        cert = FixedRadixCertificate.create(
            adapter_id="mde:corpus",
            adapter_sha256=asha,
            base_weights_sha256=ckpt.weights_sha256,
            radix_scale=adapter_radix,
            frobenius_sq_scaled=frob,
            spectral_norm_sq_scaled=spec,
            leakage_energy_scaled=leak,
            max_safety_dot_sq_scaled=safety,
        )
        # Exact scaled value on composed_radix: v_c = v * scale_num^2 * composed_radix / (adapter_radix * scale_den^2)
        den = adapter_radix * scale_den * scale_den
        c_frob = (frob * scale_num * scale_num * composed_radix) // den
        c_spec = (spec * scale_num * scale_num * composed_radix) // den
        c_leak = (leak * scale_num * scale_num * composed_radix) // den
        c_safe = (safety * scale_num * scale_num * composed_radix) // den
        self.assertEqual(c_frob * den, frob * scale_num * scale_num * composed_radix)
        self.assertEqual(c_spec * den, spec * scale_num * scale_num * composed_radix)
        self.assertEqual(c_leak * den, leak * scale_num * scale_num * composed_radix)
        self.assertEqual(c_safe * den, safety * scale_num * scale_num * composed_radix)

        stack_sha = stack_composition_digest([("mde:corpus", asha, scale_num, scale_den)])
        composed = FixedRadixCertificate.create(
            adapter_id="composed_stack",
            adapter_sha256=stack_sha,
            base_weights_sha256=ckpt.weights_sha256,
            radix_scale=composed_radix,
            frobenius_sq_scaled=c_frob,
            spectral_norm_sq_scaled=c_spec,
            leakage_energy_scaled=c_leak,
            max_safety_dot_sq_scaled=c_safe,
        )
        bounds = CertificateBounds(
            max_frobenius_sq=RationalBound(50, 1),
            max_spectral_norm_sq=RationalBound(50, 1),
            max_leakage_energy=RationalBound(10, 1),
            max_safety_dot_sq=RationalBound(10, 1),
        )
        return [(cert, "mde:corpus", asha, scale_num, scale_den)], composed, ckpt.weights_sha256, bounds

    def test_singleton_composed_rejects_forged_leakage_and_safety_dot_across_weights_and_radices(self) -> None:
        configs = (
            # Unit scale, identical radix
            (1, 1, 10000, 10000, 1600, 400, 120, 40),
            # Unreduced rational unit scale (1000/1000) with unequal radices (10000 vs 25000)
            (1000, 1000, 10000, 25000, 1600, 400, 120, 40),
            # Unequal non-unit weight (3/2 -> s^2 = 9/4) with unequal radices (10000 vs 16000)
            (3, 2, 10000, 16000, 1600, 400, 120, 40),
            # Unreduced rational weight (6/4 == 3/2) with unequal radices (10000 vs 16000)
            (6, 4, 10000, 16000, 1600, 400, 120, 40),
        )
        for snum, sden, r_a, r_c, frob, spec, leak, safe in configs:
            with self.subTest(scale=f"{snum}/{sden}", r_a=r_a, r_c=r_c):
                items, composed, base_sha, bounds = self._make_singleton_case(
                    scale_num=snum,
                    scale_den=sden,
                    adapter_radix=r_a,
                    composed_radix=r_c,
                    frob=frob,
                    spec=spec,
                    leak=leak,
                    safety=safe,
                )
                ok = verify_stack_division_free(
                    items,
                    bounds,
                    bounds,
                    expected_base_weights_sha256=base_sha,
                    composed_certificate=composed,
                )
                self.assertTrue(ok.composed_cert_verified)

                # Zero forgery on every single metric MUST be rejected!
                for field_name in (
                    "frobenius_sq_scaled",
                    "spectral_norm_sq_scaled",
                    "leakage_energy_scaled",
                    "max_safety_dot_sq_scaled",
                ):
                    kwargs: dict[str, Any] = {
                        "adapter_id": composed.adapter_id,
                        "adapter_sha256": composed.adapter_sha256,
                        "base_weights_sha256": composed.base_weights_sha256,
                        "radix_scale": composed.radix_scale,
                        "frobenius_sq_scaled": composed.frobenius_sq_scaled,
                        "spectral_norm_sq_scaled": composed.spectral_norm_sq_scaled,
                        "leakage_energy_scaled": composed.leakage_energy_scaled,
                        "max_safety_dot_sq_scaled": composed.max_safety_dot_sq_scaled,
                    }
                    kwargs[field_name] = 0
                    if field_name == "frobenius_sq_scaled":
                        kwargs["spectral_norm_sq_scaled"] = 0
                    forged = FixedRadixCertificate.create(**kwargs)
                    with self.assertRaises(CertificateError):
                        verify_stack_division_free(
                            items,
                            bounds,
                            bounds,
                            expected_base_weights_sha256=base_sha,
                            composed_certificate=forged,
                        )

                # Off-by-1 understatement AND overstatement on leakage and safety_dot MUST be rejected!
                for field_name in ("leakage_energy_scaled", "max_safety_dot_sq_scaled"):
                    for delta in (-1, 1):
                        kwargs = {
                            "adapter_id": composed.adapter_id,
                            "adapter_sha256": composed.adapter_sha256,
                            "base_weights_sha256": composed.base_weights_sha256,
                            "radix_scale": composed.radix_scale,
                            "frobenius_sq_scaled": composed.frobenius_sq_scaled,
                            "spectral_norm_sq_scaled": composed.spectral_norm_sq_scaled,
                            "leakage_energy_scaled": composed.leakage_energy_scaled,
                            "max_safety_dot_sq_scaled": composed.max_safety_dot_sq_scaled,
                        }
                        kwargs[field_name] = kwargs[field_name] + delta
                        forged = FixedRadixCertificate.create(**kwargs)
                        with self.assertRaises(CertificateError):
                            verify_stack_division_free(
                                items,
                                bounds,
                                bounds,
                                expected_base_weights_sha256=base_sha,
                                composed_certificate=forged,
                            )


class TestSandboxLeadingSlashClosures(unittest.TestCase):
    def test_double_slash_root_protected_and_symlink_trailing_slash_rejected(self) -> None:
        sandbox = REPO_ROOT / "blueprints" / "sandbox" / "warp-sandbox-exec.sh"

        for bad_root in ("//", "///"):
            res = subprocess.run(
                ["bash", str(sandbox), bad_root, "echo", "nope"],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(res.returncode, 126, msg=res.stderr)
            self.assertIn("ERR_SANDBOX_WORKTREE", res.stderr)

        if Path("/boot").is_dir():
            res_boot = subprocess.run(
                ["bash", str(sandbox), "//boot", "echo", "nope"],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(res_boot.returncode, 126, msg=res_boot.stderr)
            self.assertIn("ERR_SANDBOX_WORKTREE", res_boot.stderr)

        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            root_link = tmp / "link_to_root"
            os.symlink("/", root_link)
            for arg in (f"{root_link}/", str(root_link)):
                res = subprocess.run(
                    ["bash", str(sandbox), arg, "echo", "nope"],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(res.returncode, 126, msg=res.stderr)
                self.assertIn("ERR_SANDBOX_WORKTREE", res.stderr)

            # Portable denylist test: copy script with a real temp dir added to denylist so
            # //<protected> is guaranteed to exist on every Linux/macOS host.
            denied_dir = (tmp / "protected_dir").resolve()
            denied_dir.mkdir()
            allowed_dir = (tmp / "allowed_wt").resolve()
            allowed_dir.mkdir()
            denied_link = tmp / "link_to_denied"
            os.symlink(str(denied_dir), denied_link)

            script_copy = tmp / "warp-sandbox-copy.sh"
            patched = sandbox.read_text(encoding="utf-8").replace(
                "    /efi; do",
                f"    /efi \\\n    {denied_dir}; do",
            )
            self.assertIn(str(denied_dir), patched)
            script_copy.write_text(patched, encoding="utf-8")

            double_denied = "//" + str(denied_dir).lstrip("/")
            triple_denied = "///" + str(denied_dir).lstrip("/")
            for bad_arg in (str(denied_dir), double_denied, triple_denied, f"{denied_link}/"):
                res = subprocess.run(
                    ["bash", str(script_copy), bad_arg, "echo", "nope"],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(res.returncode, 126, msg=f"arg={bad_arg} stderr={res.stderr}")
                self.assertIn("ERR_SANDBOX_WORKTREE", res.stderr, msg=f"arg={bad_arg} stderr={res.stderr}")

            # Negative control: allowed_dir does NOT fail ERR_SANDBOX_WORKTREE
            env_ctrl = dict(os.environ)
            env_ctrl["WARP_REQUIRE_SECCOMP_BPF"] = "1"
            env_ctrl.pop("WARP_SECCOMP_BPF_PATH", None)
            ctrl_res = subprocess.run(
                ["bash", str(script_copy), str(allowed_dir), "echo", "ok"],
                capture_output=True,
                text=True,
                env=env_ctrl,
                check=False,
            )
            self.assertNotIn("ERR_SANDBOX_WORKTREE", ctrl_res.stderr)

            # Simulate POSIX/macOS `pwd -P` returning leading `//` or `//<denied_dir>` on Linux too!
            for sim_pwd in ("//", double_denied):
                sim_script = tmp / "warp-sandbox-sim-pwd.sh"
                sim_text = patched.replace(
                    "set -euo pipefail",
                    f"set -euo pipefail\npwd() {{ printf '%s\\n' '{sim_pwd}'; }}",
                    1,
                )
                sim_script.write_text(sim_text, encoding="utf-8")
                sim_res = subprocess.run(
                    ["bash", str(sim_script), str(allowed_dir), "echo", "nope"],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(sim_res.returncode, 126, msg=f"sim_pwd={sim_pwd} stderr={sim_res.stderr}")
                self.assertIn("ERR_SANDBOX_WORKTREE", sim_res.stderr, msg=f"sim_pwd={sim_pwd} stderr={sim_res.stderr}")


class TestStateBankReceiptSingleGuards(unittest.TestCase):
    def test_state_bank_status_and_receipt_duplicate_and_unrequested_guards(self) -> None:
        # Clean control passes
        ok_status = StateBankStatus(bank=STATE_BANK_KV, tainted=False, active_lora_ids=(0, 1))
        self.assertEqual(ok_status.active_lora_ids, (0, 1))

        # state_banks.py:44-64 — every StateBankStatus __post_init__ guard
        with self.assertRaises(StateFlushError):
            StateBankStatus(bank="mystery_bank", tainted=False)
        with self.assertRaises(StateFlushError):
            StateBankStatus(bank=STATE_BANK_KV, tainted=False, active_lora_ids=(0, 0))
        with self.assertRaises(StateFlushError):
            StateBankStatus(bank=STATE_BANK_KV, tainted=1)  # type: ignore[arg-type]
        with self.assertRaises(StateFlushError):
            StateBankStatus(bank=STATE_BANK_KV, tainted=False, active_lora_ids=[0])  # type: ignore[arg-type]
        with self.assertRaises(StateFlushError):
            StateBankStatus(bank=STATE_BANK_KV, tainted=False, active_lora_ids=(-1,))
        with self.assertRaises(StateFlushError):
            StateBankStatus(bank=STATE_BANK_KV, tainted=False, tokens_or_layers=-1)
        with self.assertRaises(StateFlushError):
            StateBankStatus(bank=STATE_BANK_KV, tainted=False, capability_tag=256)
        with self.assertRaises(StateFlushError):
            StateBankStatus(bank=STATE_BANK_KV, tainted=False, zone_manifest_id="bad-zm")

        # Clean receipt control passes
        ok_rec = BankFlushReceipt(
            slot_id=0,
            banks_requested=(STATE_BANK_KV,),
            banks_confirmed=(STATE_BANK_KV,),
            zone_manifest_id=None,
            verified_clean=True,
        )
        self.assertTrue(ok_rec.verified_clean)

        # state_banks.py:93-122 — every BankFlushReceipt __post_init__ guard
        with self.assertRaises(StateFlushError):
            BankFlushReceipt(slot_id=0, banks_requested=(STATE_BANK_KV, STATE_BANK_SSM), banks_confirmed=(STATE_BANK_KV,), zone_manifest_id=None, verified_clean=True)
        with self.assertRaises(StateFlushError):
            BankFlushReceipt(slot_id=-1, banks_requested=(STATE_BANK_KV,), banks_confirmed=(STATE_BANK_KV,), zone_manifest_id=None, verified_clean=True)
        with self.assertRaises(StateFlushError):
            BankFlushReceipt(slot_id=0, banks_requested=(), banks_confirmed=(), zone_manifest_id=None, verified_clean=False)
        with self.assertRaises(StateFlushError):
            BankFlushReceipt(slot_id=0, banks_requested=(STATE_BANK_KV,), banks_confirmed=[STATE_BANK_KV], zone_manifest_id=None, verified_clean=True)  # type: ignore[arg-type]
        with self.assertRaises(StateFlushError):
            BankFlushReceipt(slot_id=0, banks_requested=("mystery_bank",), banks_confirmed=(), zone_manifest_id=None, verified_clean=False)
        with self.assertRaisesRegex(StateFlushError, "invalid confirmed bank"):
            BankFlushReceipt(slot_id=0, banks_requested=(STATE_BANK_KV,), banks_confirmed=("mystery_bank",), zone_manifest_id=None, verified_clean=False)
        with self.assertRaises(StateFlushError):
            BankFlushReceipt(slot_id=0, banks_requested=(STATE_BANK_KV,), banks_confirmed=(STATE_BANK_KV,), zone_manifest_id="bad-zm", verified_clean=True)
        with self.assertRaises(StateFlushError):
            BankFlushReceipt(slot_id=0, banks_requested=(STATE_BANK_KV,), banks_confirmed=(STATE_BANK_KV,), zone_manifest_id=None, verified_clean=1)  # type: ignore[arg-type]
        # state_banks.py:99 — duplicate banks_requested
        with self.assertRaises(StateFlushError):
            BankFlushReceipt(
                slot_id=0,
                banks_requested=(STATE_BANK_KV, STATE_BANK_KV),
                banks_confirmed=(STATE_BANK_KV,),
                zone_manifest_id=None,
                verified_clean=True,
            )

        # state_banks.py:104 — duplicate banks_confirmed
        with self.assertRaises(StateFlushError):
            BankFlushReceipt(
                slot_id=0,
                banks_requested=(STATE_BANK_KV,),
                banks_confirmed=(STATE_BANK_KV, STATE_BANK_KV),
                zone_manifest_id=None,
                verified_clean=True,
            )

        # state_banks.py:110 — unrequested bank in banks_confirmed
        with self.assertRaises(StateFlushError):
            BankFlushReceipt(
                slot_id=0,
                banks_requested=(STATE_BANK_KV,),
                banks_confirmed=(STATE_BANK_KV, STATE_BANK_SSM),
                zone_manifest_id=None,
                verified_clean=True,
            )


class TestVerifierFlushAndLegacyFlagSingleGuards(unittest.TestCase):
    def _build_modeld(
        self,
        td: str,
        client: Any,
        *,
        has_ssm: bool = False,
        has_lattice: bool = False,
        allow_legacy_implicit_kv_flush: bool = False,
    ) -> WarpModeld:
        base_ckpt = make_checkpoint()
        ckpt = CheckpointFingerprint(
            model_id=base_ckpt.model_id,
            layout_sha256=base_ckpt.layout_sha256,
            weights_sha256=base_ckpt.weights_sha256,
            config_sha256=base_ckpt.config_sha256,
            tokenizer_sha256=base_ckpt.tokenizer_sha256,
            chat_template_sha256=base_ckpt.chat_template_sha256,
            safetensors_provenance_sha256=base_ckpt.safetensors_provenance_sha256,
            has_ssm_recurrent=has_ssm,
            has_horizontal_lattice=has_lattice,
            lattice_layers=4 if has_lattice else 0,
            lattice_width=16 if has_lattice else 0,
        )
        base_flags = make_runtime_flags()
        flags = RuntimeFlags(
            llama_server_commit=base_flags.llama_server_commit,
            quantization=base_flags.quantization,
            ctx_size=base_flags.ctx_size,
            kv_cache_type=base_flags.kv_cache_type,
            ctx_checkpoints=base_flags.ctx_checkpoints,
            swa_checkpoints=base_flags.swa_checkpoints,
            lora_init_without_apply=base_flags.lora_init_without_apply,
            rope_args=base_flags.rope_args,
            chat_template_args=base_flags.chat_template_args,
            has_horizontal_lattice=has_lattice,
            lattice_flush_supported=has_lattice,
        )
        signer = HmacSha256Signer(b"verifier-guard-key-32-bytes-0001", key_id="k1")
        return WarpModeld(
            pinned_checkpoint=ckpt,
            pinned_lineage=make_lineage(),
            live_runtime_flags=flags,
            single_bounds=make_single_bounds(),
            joint_bounds=make_joint_bounds(),
            canary_suite=_tiny_canary_suite(),
            llama_client=client,
            ledger=SignedLedger(Path(td) / "ledger.jsonl", signer),
            allow_legacy_implicit_kv_flush=allow_legacy_implicit_kv_flush,
        )

    def test_empty_slots_fails_closed_for_kv_and_lattice(self) -> None:
        empty_client = _StubCanaryLlamaClient(slots_factory=lambda _n: [])
        with tempfile.TemporaryDirectory() as td:
            m_kv = self._build_modeld(td, empty_client, has_ssm=False, has_lattice=False)
            with self.assertRaises(StateFlushError):
                m_kv.rollback(reason="empty_slots_kv")
            self.assertTrue(m_kv.status()["state_quarantined"])

        with tempfile.TemporaryDirectory() as td:
            m_lat = self._build_modeld(td, empty_client, has_ssm=True, has_lattice=True)
            with self.assertRaises(LatticeFlushError):
                m_lat.rollback(reason="empty_slots_lattice")
            self.assertTrue(m_lat.status()["state_quarantined"])

    def test_erase_response_non_dict_legacy_flag_and_kv_bank_confirmation_guards(self) -> None:
        # 1. verifier.py:280 — non-dict erase response fails with StateFlushError (never AttributeError, never passes)
        for legacy_flag in (False, True):
            with tempfile.TemporaryDirectory() as td:
                client = _StubCanaryLlamaClient(erase_responses=["not-a-dict"])
                modeld = self._build_modeld(td, client, allow_legacy_implicit_kv_flush=legacy_flag)
                with self.assertRaises(StateFlushError):
                    modeld.rollback(reason="non_dict_resp")

        # 2. verifier.py:283 — default allow_legacy_implicit_kv_flush=False rejects omitted banks_flushed on KV-only!
        with tempfile.TemporaryDirectory() as td:
            client = _StubCanaryLlamaClient(erase_responses=[{"id_slot": 0, "erased": True}])
            modeld = self._build_modeld(td, client, allow_legacy_implicit_kv_flush=False)
            with self.assertRaises(StateFlushError):
                modeld.rollback(reason="default_fail_closed_kv")

        # 3. verifier.py:283 — opt-in allow_legacy_implicit_kv_flush=True allows omitted banks_flushed on KV-only
        #    end-to-end across BOTH CanaryRunner (Stage 3) and _flush_all_slots (Stage 4 + rollback)!
        with tempfile.TemporaryDirectory() as td:
            client = _StubCanaryLlamaClient(erase_responses=[{"id_slot": 0, "erased": True}])
            modeld = self._build_modeld(td, client, allow_legacy_implicit_kv_flush=True)
            mount_res = modeld.mount_stack([make_adapter_bundle_dict()])
            self.assertEqual(mount_res.slots_flushed, (0,))
            self.assertEqual(mount_res.bank_flush_receipts[0].banks_confirmed, (STATE_BANK_KV,))
            rb_res = modeld.rollback(reason="legacy_opt_in_kv_ok")
            self.assertEqual(rb_res.bank_flush_receipts[0].banks_confirmed, (STATE_BANK_KV,))

        # 4. verifier.py:283 — dropping `raw_confirmed is None` caught: non-list, non-None banks_flushed fails!
        with tempfile.TemporaryDirectory() as td:
            client = _StubCanaryLlamaClient(erase_responses=[{"id_slot": 0, "erased": True, "banks_flushed": "kv_cache"}])
            modeld = self._build_modeld(td, client, allow_legacy_implicit_kv_flush=True)
            with self.assertRaises(StateFlushError):
                modeld.rollback(reason="non_list_non_none_banks")

        # 5. verifier.py:283 — even with allow_legacy_implicit_kv_flush=True, SSM & lattice still fail closed
        #    with confirmed=[] (never implicitly fabricating kv_cache)!
        with tempfile.TemporaryDirectory() as td:
            client = _StubCanaryLlamaClient(erase_responses=[{"id_slot": 0, "erased": True}])
            m_ssm = self._build_modeld(td, client, has_ssm=True, allow_legacy_implicit_kv_flush=True)
            with self.assertRaisesRegex(StateFlushError, r"confirmed=\[\]"):
                m_ssm.rollback(reason="ssm_never_legacy_kv")

        with tempfile.TemporaryDirectory() as td:
            client = _StubCanaryLlamaClient(erase_responses=[{"id_slot": 0, "erased": True}])
            m_lat = self._build_modeld(td, client, has_ssm=False, has_lattice=True, allow_legacy_implicit_kv_flush=True)
            with self.assertRaisesRegex(LatticeFlushError, r"confirmed=\[\]"):
                m_lat.rollback(reason="lattice_never_legacy_kv")

        # 6. verifier.py:288-289 — KV-only explicit empty banks_flushed=[] fails closed directly at erase confirmation!
        for legacy_flag in (False, True):
            with tempfile.TemporaryDirectory() as td:
                client = _StubCanaryLlamaClient(erase_responses=[{"id_slot": 0, "erased": True, "banks_flushed": []}])
                modeld = self._build_modeld(td, client, allow_legacy_implicit_kv_flush=legacy_flag)
                with self.assertRaisesRegex(StateFlushError, "erase failed to confirm required state banks"):
                    modeld.rollback(reason="kv_empty_confirmed_list")

    def test_cli_serve_rejects_non_bool_allow_legacy_implicit_kv_flush(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            key_path = tmp / "key.bin"
            key_path.write_bytes(b"0123456789abcdef0123456789abcdef")
            cfg = {
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
                "allow_legacy_implicit_kv_flush": "true",
            }
            cfg["checkpoint"].pop("config_bundle_sha256", None)
            cfg_path = tmp / "cfg.json"
            cfg_path.write_text(json.dumps(cfg), encoding="utf-8")
            with mock.patch("warp_modeld.cli.WarpUnixRpcServer", side_effect=RuntimeError("must_not_start_server")):
                with self.assertRaisesRegex(ValueError, "allow_legacy_implicit_kv_flush"):
                    _cmd_serve(SimpleNamespace(config=str(cfg_path)))


class TestCanaryRunnerSingleGuardClosures(unittest.TestCase):
    def test_canary_runner_single_guard_matrix_and_legacy_flag(self) -> None:
        suite = _tiny_canary_suite()
        bundle = _sample_bundle()

        # Baseline control passes with required_state_banks=None (default kv_cache)
        ok_client = _StubCanaryLlamaClient()
        res_ok = CanaryRunner(ok_client, suite).run([bundle])
        self.assertTrue(res_ok.canary_slot_flushed)

        # Default kv_cache expected bank rejects empty banks_flushed=[] when required_state_banks=None
        empty_banks_client = _StubCanaryLlamaClient(
            erase_responses=[{"id_slot": 0, "erased": True, "banks_flushed": []}]
        )
        with self.assertRaises(CanaryFailedError):
            CanaryRunner(empty_banks_client, suite).run([bundle])

        # Non-list banks_flushed and non-dict erase response fail closed
        for bad_resp in (
            "not-a-dict",
            {"id_slot": 0, "erased": True, "banks_flushed": "kv_cache"},
            {"id_slot": 0, "erased": True, "banks_flushed": None},
        ):
            with self.subTest(bad_resp=bad_resp):
                c = _StubCanaryLlamaClient(erase_responses=[bad_resp])
                with self.assertRaises(CanaryFailedError):
                    CanaryRunner(c, suite).run([bundle], required_state_banks=(STATE_BANK_KV,))

        # Missing slot in /slots
        for missing_slots in ([], [_clean_slot(99)]):
            with self.subTest(missing_slots=len(missing_slots)):
                c = _StubCanaryLlamaClient(slots_factory=lambda _n, ms=missing_slots: ms)
                with self.assertRaises(CanaryFailedError):
                    CanaryRunner(c, suite).run([bundle], required_state_banks=(STATE_BANK_KV,))

        # Every single clean-slot condition isolated individually
        clean_kv = StateBankStatus(bank=STATE_BANK_KV, tainted=False)
        dirty_kv = StateBankStatus(bank=STATE_BANK_KV, tainted=True)
        dirty_ssm = StateBankStatus(bank=STATE_BANK_SSM, tainted=True)
        bad_slot_cases: tuple[tuple[str, dict[str, Any]], ...] = (
            ("is_processing", {"is_processing": True}),
            ("recurrent_state_tainted", {"recurrent_state_tainted": True}),
            ("lattice_state_tainted", {"lattice_state_tainted": True}),
            ("ssm_state_tainted", {"ssm_state_tainted": True}),
            ("lattice_layers_tainted", {"lattice_layers_tainted": 1}),
            ("active_lora_ids", {"active_lora_ids": (0,)}),
            ("n_decoded", {"n_decoded": 1}),
            ("n_prompt_tokens_cache", {"n_prompt_tokens_cache": 1}),
            ("state_banks_not_dict", {"state_banks": None}),
            ("expected_bank_missing", {"state_banks": {}}),
            ("expected_bank_dirty", {"state_banks": {STATE_BANK_KV: dirty_kv}}),
            ("extra_reported_bank_dirty", {"state_banks": {STATE_BANK_KV: clean_kv, STATE_BANK_SSM: dirty_ssm}}),
        )
        for label, overrides in bad_slot_cases:
            with self.subTest(condition=label):
                # Keep initial slot enumeration clean, fail ONLY on post-erase check
                c = _StubCanaryLlamaClient(
                    slots_factory=lambda n, ov=overrides: [_clean_slot(0)] if n == 0 else [_clean_slot(0, **ov)]
                )
                with self.assertRaises(CanaryFailedError):
                    CanaryRunner(c, suite).run([bundle], required_state_banks=(STATE_BANK_KV,))

        # Post-canary finally cleanup erase failure (first 5 pre-canary erases OK, final cleanup #6 fails!)
        c_final = _StubCanaryLlamaClient(
            erase_responses=[
                {"id_slot": 0, "erased": True, "banks_flushed": [STATE_BANK_KV]},
                {"id_slot": 0, "erased": True, "banks_flushed": [STATE_BANK_KV]},
                {"id_slot": 0, "erased": True, "banks_flushed": [STATE_BANK_KV]},
                {"id_slot": 0, "erased": True, "banks_flushed": [STATE_BANK_KV]},
                {"id_slot": 0, "erased": True, "banks_flushed": [STATE_BANK_KV]},
                {"id_slot": 0, "erased": True, "banks_flushed": []},
            ]
        )
        with self.assertRaises(CanaryFailedError):
            CanaryRunner(c_final, suite).run([bundle], required_state_banks=(STATE_BANK_KV,))

        # allow_legacy_implicit_kv_flush=True works on KV-only omitted banks_flushed, fails on non-list or multi-bank
        c_leg_ok = _StubCanaryLlamaClient(erase_responses=[{"id_slot": 0, "erased": True}])
        res_leg = CanaryRunner(c_leg_ok, suite, allow_legacy_implicit_kv_flush=True).run(
            [bundle], required_state_banks=(STATE_BANK_KV,)
        )
        self.assertTrue(res_leg.canary_slot_flushed)

        c_leg_bad_str = _StubCanaryLlamaClient(erase_responses=[{"id_slot": 0, "erased": True, "banks_flushed": "kv_cache"}])
        with self.assertRaises(CanaryFailedError):
            CanaryRunner(c_leg_bad_str, suite, allow_legacy_implicit_kv_flush=True).run(
                [bundle], required_state_banks=(STATE_BANK_KV,)
            )

        c_leg_ssm = _StubCanaryLlamaClient(erase_responses=[{"id_slot": 0, "erased": True}])
        with self.assertRaises(CanaryFailedError):
            CanaryRunner(c_leg_ssm, suite, allow_legacy_implicit_kv_flush=True).run(
                [bundle], required_state_banks=(STATE_BANK_KV, STATE_BANK_SSM)
            )
        self.assertFalse(
            _erase_slot_and_confirm(
                _StubCanaryLlamaClient(erase_responses=[{"id_slot": 0, "erased": True}]),
                0,
                erase_banks=None,
                expected_banks=(),
                allow_legacy_implicit_kv_flush=True,
            )
        )


class TestExternalCommandCanaryRunnerSingleGuardClosures(unittest.TestCase):
    def _external_cmd(self, suite_sha: str, marker_file: Path | None = None) -> tuple[str, ...]:
        payload = {
            "suite_sha256": suite_sha,
            "preservation_passed": 4,
            "preservation_total": 4,
            "outcomes": [
                {"canary_id": "pres-01", "category": "preservation", "passed": True, "failures": []},
                {"canary_id": "pres-02", "category": "preservation", "passed": True, "failures": []},
                {"canary_id": "pres-03", "category": "preservation", "passed": True, "failures": []},
                {"canary_id": "pres-04", "category": "preservation", "passed": True, "failures": []},
                {"canary_id": "dom-01", "category": "domain", "domain": "corpus", "passed": True, "failures": []},
            ],
        }
        code = (
            "import json, pathlib, sys; "
            + (f"pathlib.Path({str(marker_file)!r}).write_text('ran', encoding='utf-8'); " if marker_file else "")
            + f"print(json.dumps({payload!r}))"
        )
        return (sys.executable, "-I", "-B", "-c", code)

    def test_external_canary_runner_single_guard_matrix_prerun_postrun_and_legacy_flag(self) -> None:
        suite_sha = hashlib.sha256(b"opaque-suite-v1").hexdigest()
        bundle = _sample_bundle()
        cmd = self._external_cmd(suite_sha)

        # Clean baseline passes (with required_state_banks=None default kv_cache)
        ok_client = _StubCanaryLlamaClient()
        res_ok = ExternalCommandCanaryRunner(ok_client, cmd, suite_sha256_hint=suite_sha).run([bundle])
        self.assertTrue(res_ok.canary_slot_flushed)

        # Default kv_cache expected bank rejects empty banks_flushed=[] when required_state_banks=None
        with self.assertRaises(CanaryFailedError):
            ExternalCommandCanaryRunner(
                _StubCanaryLlamaClient(erase_responses=[{"id_slot": 0, "erased": True, "banks_flushed": []}]),
                cmd,
                suite_sha256_hint=suite_sha,
            ).run([bundle])

        # Non-list banks_flushed and non-dict erase response fail closed
        for bad_resp in (
            "not-a-dict",
            {"id_slot": 0, "erased": True, "banks_flushed": "kv_cache"},
            {"id_slot": 0, "erased": True, "banks_flushed": None},
        ):
            with self.subTest(bad_resp=bad_resp):
                with self.assertRaises(CanaryFailedError):
                    ExternalCommandCanaryRunner(
                        _StubCanaryLlamaClient(erase_responses=[bad_resp]),
                        cmd,
                        suite_sha256_hint=suite_sha,
                    ).run([bundle], required_state_banks=(STATE_BANK_KV,))

        # Missing slot in /slots after erase
        with self.assertRaises(CanaryFailedError):
            ExternalCommandCanaryRunner(
                _StubCanaryLlamaClient(slots_factory=lambda n: [_clean_slot(0)] if n == 0 else []),
                cmd,
                suite_sha256_hint=suite_sha,
            ).run([bundle], required_state_banks=(STATE_BANK_KV,))

        # Every single clean-slot condition isolated individually
        clean_kv = StateBankStatus(bank=STATE_BANK_KV, tainted=False)
        dirty_kv = StateBankStatus(bank=STATE_BANK_KV, tainted=True)
        dirty_ssm = StateBankStatus(bank=STATE_BANK_SSM, tainted=True)
        bad_slot_cases: tuple[tuple[str, dict[str, Any]], ...] = (
            ("is_processing", {"is_processing": True}),
            ("recurrent_state_tainted", {"recurrent_state_tainted": True}),
            ("lattice_state_tainted", {"lattice_state_tainted": True}),
            ("ssm_state_tainted", {"ssm_state_tainted": True}),
            ("lattice_layers_tainted", {"lattice_layers_tainted": 1}),
            ("active_lora_ids", {"active_lora_ids": (0,)}),
            ("n_decoded", {"n_decoded": 1}),
            ("n_prompt_tokens_cache", {"n_prompt_tokens_cache": 1}),
            ("state_banks_not_dict", {"state_banks": None}),
            ("expected_bank_missing", {"state_banks": {}}),
            ("expected_bank_dirty", {"state_banks": {STATE_BANK_KV: dirty_kv}}),
            ("extra_reported_bank_dirty", {"state_banks": {STATE_BANK_KV: clean_kv, STATE_BANK_SSM: dirty_ssm}}),
        )
        for label, overrides in bad_slot_cases:
            with self.subTest(condition=label):
                c = _StubCanaryLlamaClient(
                    slots_factory=lambda n, ov=overrides: [_clean_slot(0)] if n == 0 else [_clean_slot(0, **ov)]
                )
                with self.assertRaises(CanaryFailedError):
                    ExternalCommandCanaryRunner(c, cmd, suite_sha256_hint=suite_sha).run(
                        [bundle], required_state_banks=(STATE_BANK_KV,)
                    )

        # Pre-run erase check specifically: fails call #1, succeeds call #2; external command must NOT run!
        with tempfile.TemporaryDirectory() as td:
            marker = Path(td) / "should_not_run.marker"
            cmd_marked = self._external_cmd(suite_sha, marker_file=marker)
            c_pre = _StubCanaryLlamaClient(
                erase_responses=[
                    {"id_slot": 0, "erased": True, "banks_flushed": []},
                    {"id_slot": 0, "erased": True, "banks_flushed": [STATE_BANK_KV]},
                ]
            )
            with self.assertRaises(CanaryFailedError):
                ExternalCommandCanaryRunner(c_pre, cmd_marked, suite_sha256_hint=suite_sha).run(
                    [bundle], required_state_banks=(STATE_BANK_KV,)
                )
            self.assertFalse(marker.exists())

            # Post-run erase check specifically: call #1 succeeds (command runs!), call #2 fails -> CanaryFailedError!
            marker_post = Path(td) / "post_ran.marker"
            cmd_post = self._external_cmd(suite_sha, marker_file=marker_post)
            c_post = _StubCanaryLlamaClient(
                erase_responses=[
                    {"id_slot": 0, "erased": True, "banks_flushed": [STATE_BANK_KV]},
                    {"id_slot": 0, "erased": True, "banks_flushed": []},
                ]
            )
            with self.assertRaises(CanaryFailedError):
                ExternalCommandCanaryRunner(c_post, cmd_post, suite_sha256_hint=suite_sha).run(
                    [bundle], required_state_banks=(STATE_BANK_KV,)
                )
            self.assertTrue(marker_post.exists())

        # allow_legacy_implicit_kv_flush=True on ExternalCommandCanaryRunner
        c_leg_ok = _StubCanaryLlamaClient(erase_responses=[{"id_slot": 0, "erased": True}])
        res_leg = ExternalCommandCanaryRunner(
            c_leg_ok, cmd, suite_sha256_hint=suite_sha, allow_legacy_implicit_kv_flush=True
        ).run([bundle], required_state_banks=(STATE_BANK_KV,))
        self.assertTrue(res_leg.canary_slot_flushed)

        c_leg_ssm = _StubCanaryLlamaClient(erase_responses=[{"id_slot": 0, "erased": True}])
        with self.assertRaises(CanaryFailedError):
            ExternalCommandCanaryRunner(
                c_leg_ssm, cmd, suite_sha256_hint=suite_sha, allow_legacy_implicit_kv_flush=True
            ).run([bundle], required_state_banks=(STATE_BANK_KV, STATE_BANK_SSM))


class TestStandaloneStudySuitesInRepo(unittest.TestCase):
    def test_study_r5_suites_pass_isolated(self) -> None:
        study_dir = REPO_ROOT / "studies" / "expedition-trust-boundary-verifier"
        for script_name in ("test_weft_cross_audit_r5.py", "test_warp_drive_runtime_r5.py"):
            with self.subTest(script=script_name):
                res = subprocess.run(
                    [sys.executable, "-I", "-B", "-W", "error", str(study_dir / script_name)],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(res.returncode, 0, msg=f"{script_name} failed:\n{res.stdout}\n{res.stderr}")


if __name__ == "__main__":
    unittest.main()
