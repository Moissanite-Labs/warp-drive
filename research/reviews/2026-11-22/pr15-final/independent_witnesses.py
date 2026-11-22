"""Independent executable witnesses for final PR #15 head; no shipped test reuse."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from warp_modeld.canary import _erase_slot_and_confirm
from warp_modeld.certificate import (
    CertificateBounds,
    FixedRadixCertificate,
    RationalBound,
    stack_composition_digest,
    verify_stack_division_free,
)
from warp_modeld.errors import CertificateError, LatticeFlushError, StateFlushError
from warp_modeld.ledger import HmacSha256Signer, repair_ledger
from warp_modeld.state_banks import STATE_BANK_KV, STATE_BANK_LATTICE, STATE_BANK_SSM, StateBankStatus
from warp_modeld.verifier import WarpModeld
import warp_modeld.ledger as ledger_module

REPO = Path("/tmp/warp-pr15-final-review")
SANDBOX = REPO / "blueprints/sandbox/warp-sandbox-exec.sh"


class CertificateWitnesses(unittest.TestCase):
    def test_singleton_zero_forgery_rejected_for_each_metric_end_to_end(self) -> None:
        base_sha = "11" * 32
        adapter_sha = "22" * 32
        scale_num, scale_den = 3, 2
        adapter = FixedRadixCertificate.create(
            adapter_id="independent:singleton",
            adapter_sha256=adapter_sha,
            base_weights_sha256=base_sha,
            radix_scale=1000,
            frobenius_sq_scaled=400,
            spectral_norm_sq_scaled=100,
            leakage_energy_scaled=20,
            max_safety_dot_sq_scaled=10,
        )
        stack_sha = stack_composition_digest([
            ("independent:singleton", adapter_sha, scale_num, scale_den)
        ])
        # s^2=9/4 and composed radix=4000: each scaled value is multiplied by 9.
        composed = FixedRadixCertificate.create(
            adapter_id="composed_stack",
            adapter_sha256=stack_sha,
            base_weights_sha256=base_sha,
            radix_scale=4000,
            frobenius_sq_scaled=3600,
            spectral_norm_sq_scaled=900,
            leakage_energy_scaled=180,
            max_safety_dot_sq_scaled=90,
        )
        items = [(adapter, "independent:singleton", adapter_sha, scale_num, scale_den)]
        bounds = CertificateBounds(
            max_frobenius_sq=RationalBound(100, 1),
            max_spectral_norm_sq=RationalBound(100, 1),
            max_leakage_energy=RationalBound(100, 1),
            max_safety_dot_sq=RationalBound(100, 1),
        )
        control = verify_stack_division_free(
            items, bounds, bounds,
            expected_base_weights_sha256=base_sha,
            composed_certificate=composed,
        )
        self.assertTrue(control.composed_cert_verified)
        fields = (
            "frobenius_sq_scaled",
            "spectral_norm_sq_scaled",
            "leakage_energy_scaled",
            "max_safety_dot_sq_scaled",
        )
        error_aliases = {
            "frobenius_sq_scaled": "composed_frobenius_sq",
            "spectral_norm_sq_scaled": "composed_spectral_norm_sq",
            "leakage_energy_scaled": "composed_leakage_energy",
            "max_safety_dot_sq_scaled": "composed_max_safety_dot_sq",
        }
        for field in fields:
            with self.subTest(metric=field):
                values = {name: getattr(composed, name) for name in fields}
                values[field] = 0
                if field == "frobenius_sq_scaled":
                    # Preserve the certificate's spectral<=Frobenius invariant so the
                    # composed singleton Frobenius check is reached first.
                    values["spectral_norm_sq_scaled"] = 0
                forged = FixedRadixCertificate.create(
                    adapter_id=composed.adapter_id,
                    adapter_sha256=composed.adapter_sha256,
                    base_weights_sha256=composed.base_weights_sha256,
                    radix_scale=composed.radix_scale,
                    **values,
                )
                with self.assertRaisesRegex(
                    CertificateError,
                    rf"inconsistent single-adapter composed certificate {error_aliases[field]}",
                ):
                    verify_stack_division_free(
                        items, bounds, bounds,
                        expected_base_weights_sha256=base_sha,
                        composed_certificate=forged,
                    )


class SandboxWitnesses(unittest.TestCase):
    def run_sandbox(self, script: Path, worktree: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", str(script), worktree, "echo", "MUST_NOT_EXECUTE"],
            text=True, capture_output=True, check=False, timeout=10,
        )

    def test_root_leading_slash_protected_and_symlink_paths(self) -> None:
        for root in ("/", "//", "///", "////"):
            with self.subTest(root=root):
                res = self.run_sandbox(SANDBOX, root)
                self.assertEqual(res.returncode, 126, (res.stdout, res.stderr))
                self.assertIn("refusing root directory", res.stderr)
                self.assertNotIn("MUST_NOT_EXECUTE", res.stdout)
        with tempfile.TemporaryDirectory() as td_raw:
            td = Path(td_raw).resolve()
            denied = td / "protected"
            denied.mkdir()
            allowed = td / "allowed"
            allowed.mkdir()
            modified = SANDBOX.read_text(encoding="utf-8").replace(
                "    /efi; do", f"    /efi \\\n    {denied}; do",
            )
            self.assertIn(str(denied), modified)
            script = td / "sandbox-with-temp-deny.sh"
            script.write_text(modified, encoding="utf-8")
            denied_text = str(denied)
            args = [
                denied_text,
                "/" + denied_text,
                "//" + denied_text.lstrip("/"),
                "///" + denied_text.lstrip("/"),
                "////" + denied_text.lstrip("/"),
            ]
            link = td / "denied-link"
            link.symlink_to(denied, target_is_directory=True)
            args.extend([str(link), str(link) + "/"])
            # A parent of an explicitly denied directory also overlaps it.
            args.append(str(td))
            for arg in args:
                with self.subTest(arg=arg):
                    res = self.run_sandbox(script, arg)
                    self.assertEqual(res.returncode, 126, (res.stdout, res.stderr))
                    self.assertIn("ERR_SANDBOX_WORKTREE", res.stderr)
                    self.assertNotIn("MUST_NOT_EXECUTE", res.stdout)
            control = self.run_sandbox(script, str(allowed))
            self.assertNotIn("ERR_SANDBOX_WORKTREE", control.stderr)
            self.assertNotIn("MUST_NOT_EXECUTE", control.stdout)
            # This macOS host has no bubblewrap; reaching the unavailable error proves
            # the allowed path passed canonicalization and denylist validation.
            self.assertIn("ERR_SANDBOX_UNAVAILABLE", control.stderr)

    def test_macos_shell_file_resolver_multi_hop_and_loop(self) -> None:
        text = SANDBOX.read_text(encoding="utf-8")
        functions = text[text.index("normalize_abs_path()"):text.index("if ! WORKTREE_REAL=")]
        with tempfile.TemporaryDirectory() as td_raw:
            td = Path(td_raw).resolve()
            real = td / "real.txt"
            real.write_text("evidence", encoding="utf-8")
            second = td / "second"
            first = td / "first"
            second.symlink_to("real.txt")
            first.symlink_to("second")
            harness = td / "resolver-harness.sh"
            harness.write_text(
                "#!/usr/bin/env bash\nset -euo pipefail\n" + functions + "\nresolve_existing_file \"$1\"\n",
                encoding="utf-8",
            )
            resolved = subprocess.run(
                ["bash", str(harness), str(first)], text=True, capture_output=True,
                check=False, timeout=10,
            )
            self.assertEqual(resolved.returncode, 0, resolved.stderr)
            self.assertEqual(resolved.stdout.strip(), str(real))
            loop_a, loop_b = td / "loop-a", td / "loop-b"
            loop_a.symlink_to("loop-b")
            loop_b.symlink_to("loop-a")
            loop = subprocess.run(
                ["bash", str(harness), str(loop_a)], text=True, capture_output=True,
                check=False, timeout=10,
            )
            self.assertEqual(loop.returncode, 1)


def clean_slot(slot_id: int = 0) -> SimpleNamespace:
    return SimpleNamespace(
        id=slot_id,
        is_processing=False,
        recurrent_state_tainted=False,
        lattice_state_tainted=False,
        ssm_state_tainted=False,
        lattice_layers_tainted=0,
        active_lora_ids=(),
        n_decoded=0,
        n_prompt_tokens_cache=0,
        state_banks={
            STATE_BANK_KV: StateBankStatus(STATE_BANK_KV, False),
            STATE_BANK_SSM: StateBankStatus(STATE_BANK_SSM, False),
            STATE_BANK_LATTICE: StateBankStatus(STATE_BANK_LATTICE, False),
        },
    )


class StubClient:
    def __init__(self, response, slots=None) -> None:
        self.response = response
        self.slots = [clean_slot()] if slots is None else slots
        self.erase_calls = []

    def erase_slot(self, slot_id: int, *, banks=None):
        self.erase_calls.append((slot_id, banks))
        return self.response

    def list_slots(self):
        return list(self.slots)


def bare_modeld(client: StubClient, banks: tuple[str, ...], legacy: bool) -> SimpleNamespace:
    return SimpleNamespace(
        pinned_checkpoint=SimpleNamespace(required_state_banks=lambda: banks),
        llama_client=client,
        allow_legacy_implicit_kv_flush=legacy,
        pinned_zone_manifest_id=None,
    )


class FlushWitnesses(unittest.TestCase):
    def test_empty_slots_fail_before_any_erase(self) -> None:
        cases = [
            ((STATE_BANK_KV,), StateFlushError),
            ((STATE_BANK_KV, STATE_BANK_SSM), StateFlushError),
            ((STATE_BANK_KV, STATE_BANK_LATTICE), LatticeFlushError),
        ]
        for banks, error_cls in cases:
            for legacy in (False, True):
                with self.subTest(banks=banks, legacy=legacy):
                    client = StubClient({"banks_flushed": list(banks)}, slots=[])
                    with self.assertRaisesRegex(error_cls, "empty slot list"):
                        WarpModeld._flush_all_slots(bare_modeld(client, banks, legacy))
                    self.assertEqual(client.erase_calls, [])

    def test_strict_legacy_kv_confirmation_matrix_canary_and_verifier(self) -> None:
        omitted = {"id_slot": 0, "erased": True}
        self.assertFalse(_erase_slot_and_confirm(
            StubClient(omitted), 0, erase_banks=None, expected_banks=(STATE_BANK_KV,),
        ))
        self.assertTrue(_erase_slot_and_confirm(
            StubClient(omitted), 0, erase_banks=None, expected_banks=(STATE_BANK_KV,),
            allow_legacy_implicit_kv_flush=True,
        ))
        self.assertFalse(_erase_slot_and_confirm(
            StubClient(omitted), 0, erase_banks=(STATE_BANK_KV, STATE_BANK_SSM),
            expected_banks=(STATE_BANK_KV, STATE_BANK_SSM),
            allow_legacy_implicit_kv_flush=True,
        ))
        for malformed in (
            {"banks_flushed": []},
            {"banks_flushed": "kv_cache"},
            "not-a-dict",
        ):
            for legacy in (False, True):
                with self.subTest(malformed=malformed, legacy=legacy):
                    self.assertFalse(_erase_slot_and_confirm(
                        StubClient(malformed), 0, erase_banks=None,
                        expected_banks=(STATE_BANK_KV,), allow_legacy_implicit_kv_flush=legacy,
                    ))
        with self.assertRaises(StateFlushError):
            WarpModeld._flush_all_slots(bare_modeld(StubClient(omitted), (STATE_BANK_KV,), False))
        flushed, receipts = WarpModeld._flush_all_slots(
            bare_modeld(StubClient(omitted), (STATE_BANK_KV,), True)
        )
        self.assertEqual(flushed, (0,))
        self.assertEqual(receipts[0].banks_confirmed, (STATE_BANK_KV,))
        with self.assertRaises(StateFlushError):
            WarpModeld._flush_all_slots(
                bare_modeld(StubClient(omitted), (STATE_BANK_KV, STATE_BANK_SSM), True)
            )


class LedgerRepairWitnesses(unittest.TestCase):
    def test_o_excl_writes_two_fsyncs_and_read_only_archive(self) -> None:
        raw = b'{"independent":"damaged-ledger"}\n'
        with tempfile.TemporaryDirectory() as td_raw:
            td = Path(td_raw)
            src, archive = td / "ledger.jsonl", td / "archive"
            src.write_bytes(raw)
            signer = HmacSha256Signer(b"independent-ledger-key-32-bytes")
            open_calls = []
            fsync_fds = []
            real_open, real_fsync = ledger_module.os.open, ledger_module.os.fsync

            def recording_open(path, flags, mode):
                open_calls.append((os.fspath(path), flags, mode))
                return real_open(path, flags, mode)

            def recording_fsync(fd):
                fsync_fds.append(fd)
                return real_fsync(fd)

            with mock.patch.object(ledger_module.os, "open", recording_open), mock.patch.object(
                ledger_module.os, "fsync", recording_fsync
            ):
                result = repair_ledger(src, archive, signer, confirmation="independent-confirm")
            self.assertFalse(src.exists())
            self.assertEqual(len(open_calls), 2)
            self.assertEqual(len(fsync_fds), 2)
            for _, flags, mode in open_calls:
                self.assertTrue(flags & os.O_EXCL)
                self.assertTrue(flags & os.O_CREAT)
                self.assertEqual(stat.S_IMODE(mode), 0o400)
            archived = Path(result["archived_path"])
            digest = archived.with_suffix(".sha256")
            self.assertEqual(archived.read_bytes(), raw)
            self.assertEqual(stat.S_IMODE(archived.stat().st_mode), 0o400)
            self.assertEqual(stat.S_IMODE(digest.stat().st_mode), 0o400)
            expected_sha = hashlib.sha256(raw).hexdigest()
            self.assertEqual(result["archived_sha256"], expected_sha)
            self.assertEqual(digest.read_text(encoding="utf-8"), f"{expected_sha}  {archived.name}\n")

    def test_real_o_excl_collision_preserves_existing_archive_and_source(self) -> None:
        raw = b"same damaged source\n"
        real_datetime = ledger_module.datetime

        class FrozenDateTime:
            @classmethod
            def now(cls, tz=None):
                return real_datetime(2026, 11, 22, 12, 0, 0, 0, tzinfo=tz)

        with tempfile.TemporaryDirectory() as td_raw:
            td = Path(td_raw)
            src, archive = td / "ledger.jsonl", td / "archive"
            signer = HmacSha256Signer(b"independent-ledger-key-32-bytes")
            with mock.patch.object(ledger_module, "datetime", FrozenDateTime):
                src.write_bytes(raw)
                first = repair_ledger(src, archive, signer, confirmation="independent-confirm")
                archived = Path(first["archived_path"])
                src.write_bytes(raw)
                with self.assertRaises(FileExistsError):
                    repair_ledger(src, archive, signer, confirmation="independent-confirm")
            self.assertEqual(archived.read_bytes(), raw)
            self.assertTrue(src.exists())
            self.assertEqual(src.read_bytes(), raw)

    def test_fsync_failure_does_not_unlink_source(self) -> None:
        with tempfile.TemporaryDirectory() as td_raw:
            td = Path(td_raw)
            src, archive = td / "ledger.jsonl", td / "archive"
            src.write_bytes(b"preserve me\n")
            signer = HmacSha256Signer(b"independent-ledger-key-32-bytes")
            with mock.patch.object(ledger_module, "_write_all_and_fsync", side_effect=OSError("injected fsync failure")):
                with self.assertRaisesRegex(OSError, "injected fsync failure"):
                    repair_ledger(src, archive, signer, confirmation="independent-confirm")
            self.assertTrue(src.exists())
            self.assertEqual(src.read_bytes(), b"preserve me\n")


if __name__ == "__main__":
    unittest.main(verbosity=2)
