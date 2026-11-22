"""Comprehensive hardening and R5 mutation-killing regression tests for warp-modeld.

Covers verified fixes from:
- AUDIT-061R: Stage 2 FixedRadixCertificate & exact root-free stack triangle bounds (WARP-CERT-01..04)
- AUDIT-062R: Runtime/sandbox/verifier/canary/ledger/RPC/fingerprint trust boundaries (WD-*-01/02)
- AUDIT-064: Multi-bank state-bank schema & post-erase slot completeness invariants (WD-SB-01..04)
- AUDIT-065: Cross-org alignment & blueprint hardening (WD-X01..WD-X08)
"""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from typing import Any

from warp_modeld.canary import (
    CanaryRunner,
    CanarySpec,
    CanarySuite,
    ExternalCommandCanaryRunner,
)
from warp_modeld.certificate import (
    CertificateBounds,
    FixedRadixCertificate,
    RationalBound,
    stack_composition_digest,
    verify_division_free,
    verify_stack_division_free,
)
from warp_modeld.errors import (
    CanaryFailedError,
    CertificateError,
    CheckpointMismatchError,
    LedgerTamperError,
    RuntimeFlagDriftError,
    StateFlushError,
    UnverifiedLoraOverrideError,
    WarpError,
    ZoneManifestDriftError,
)
from warp_modeld.fingerprint import (
    AdapterBundle,
    CheckpointFingerprint,
    Plane1Lineage,
    RuntimeFlags,
    compute_file_sha256,
    sha256_json,
    verify_zone_manifest_dict,
)
from warp_modeld.ledger import (
    GENESIS_HASH,
    HmacSha256Signer,
    LedgerVerifier,
    SignedLedger,
    _canonical_bytes,
    _redact_secrets,
    _write_all_and_fsync,
    repair_ledger,
)
from warp_modeld.llama_client import LlamaClientError, LlamaServerClient
from warp_modeld.server import (
    MAX_REQUEST_BYTES,
    WarpUnixRpcClient,
    WarpUnixRpcServer,
    _reject_case_insensitive_lora_override,
    _require_finite_float,
    loads_strict_json,
)
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
    make_modeld,
    make_runtime_flags,
    make_single_bounds,
)
from tests.mock_llama_server import MockLlamaServer


class TestCertificateHardeningAndR5(unittest.TestCase):
    def _make_cert(
        self,
        *,
        adapter_id: str = "mde:corpus",
        adapter_sha256: str | None = None,
        base_sha: str | None = None,
        radix_scale: int = 1000,
        frob: int = 1000,
        spec: int = 250,
        leak: int = 1,
        safety: int = 1,
    ) -> FixedRadixCertificate:
        return FixedRadixCertificate.create(
            adapter_id=adapter_id,
            adapter_sha256=adapter_sha256 or fake_sha(f"cert-{adapter_id}"),
            base_weights_sha256=base_sha or fake_sha("base-weights"),
            radix_scale=radix_scale,
            frobenius_sq_scaled=frob,
            spectral_norm_sq_scaled=spec,
            leakage_energy_scaled=leak,
            max_safety_dot_sq_scaled=safety,
        )

    def test_rational_bound_and_cert_input_boundaries(self) -> None:
        self.assertEqual(RationalBound(0, 1).to_dict(), {"num": 0, "den": 1})
        for bad_num, bad_den in [(-1, 1), (1, 0), (1, -1), (True, 1), (1, True)]:
            with self.assertRaises(CertificateError):
                RationalBound(bad_num, bad_den)  # type: ignore[arg-type]

        base_sha = fake_sha("base-weights")
        # Trailing newline in SHA-256 must fail strict \A...\Z validation.
        with self.assertRaises(CertificateError):
            self._make_cert(adapter_sha256=("a" * 64) + "\n", base_sha=base_sha)
        with self.assertRaises(CertificateError):
            self._make_cert(base_sha=("b" * 64) + "\n")
        with self.assertRaises(CertificateError):
            self._make_cert(adapter_id="   ", base_sha=base_sha)
        with self.assertRaises(CertificateError):
            self._make_cert(radix_scale=0, base_sha=base_sha)
        with self.assertRaises(CertificateError):
            self._make_cert(frob=-1, spec=0, base_sha=base_sha)

        cert = self._make_cert(base_sha=base_sha)
        bounds = CertificateBounds(
            max_frobenius_sq=RationalBound(1, 1),
            max_spectral_norm_sq=RationalBound(1, 4),
            max_leakage_energy=RationalBound(1, 1000),
            max_safety_dot_sq=RationalBound(1, 1000),
        )
        with self.assertRaises(CertificateError):
            verify_division_free(self._make_cert(frob=100, spec=101, base_sha=base_sha), bounds)
        # WARP-CERT-04: invalid bounds type or malformed expected_base_weights_sha256 rejected cleanly.
        with self.assertRaises(CertificateError):
            verify_division_free(cert, {"not": "bounds"})  # type: ignore[arg-type]
        with self.assertRaises(CertificateError):
            verify_division_free(cert, bounds, expected_base_weights_sha256="not-hex")
        with self.assertRaises(CertificateError):
            verify_division_free(cert, bounds, expected_base_weights_sha256=123)  # type: ignore[arg-type]
        with self.assertRaises(CertificateError):
            verify_division_free(cert, bounds, expected_base_weights_sha256=fake_sha("other-base"))

        # Exact boundary passes on all 4 metrics simultaneously.
        res = verify_division_free(cert, bounds, expected_base_weights_sha256=base_sha)
        self.assertEqual(res.adapter_id, "mde:corpus")

        # +1 above exact boundary fails independently on each of the 4 metrics.
        for kwargs in (
            {"frob": 1001, "spec": 250, "leak": 1, "safety": 1},
            {"frob": 1000, "spec": 251, "leak": 1, "safety": 1},
            {"frob": 1000, "spec": 250, "leak": 2, "safety": 1},
            {"frob": 1000, "spec": 250, "leak": 1, "safety": 2},
        ):
            over = self._make_cert(base_sha=base_sha, **kwargs)
            with self.assertRaises(CertificateError):
                verify_division_free(over, bounds, expected_base_weights_sha256=base_sha)

        # Non-unit scale (3/2)^2 = 9/4: frob_sq=1.0 -> scaled=9/4. Exact 9/4 passes; 899/400 fails.
        exact_scaled = CertificateBounds(
            max_frobenius_sq=RationalBound(9, 4),
            max_spectral_norm_sq=RationalBound(9, 16),
            max_leakage_energy=RationalBound(9, 4000),
            max_safety_dot_sq=RationalBound(9, 4000),
        )
        verify_division_free(cert, exact_scaled, scale_num=3, scale_den=2)
        tight_scaled = CertificateBounds(
            max_frobenius_sq=RationalBound(899, 400),
            max_spectral_norm_sq=RationalBound(9, 16),
            max_leakage_energy=RationalBound(9, 4000),
            max_safety_dot_sq=RationalBound(9, 4000),
        )
        with self.assertRaises(CertificateError):
            verify_division_free(cert, tight_scaled, scale_num=3, scale_den=2)
        for bad_sn, bad_sd in [(0, 1), (-1, 1), (1, 0), (True, 1), (1, False)]:
            with self.assertRaises(CertificateError):
                verify_division_free(cert, exact_scaled, scale_num=bad_sn, scale_den=bad_sd)  # type: ignore[arg-type]

        # Single-invariant checks for from_dict, from_weft_dict, verify_division_free, and spectral==frob boundary.
        with self.assertRaises(CertificateError):
            RationalBound.from_dict("not-a-dict")  # type: ignore[arg-type]
        with self.assertRaises(CertificateError):
            CertificateBounds.from_dict("not-a-dict")  # type: ignore[arg-type]
        with self.assertRaises(CertificateError):
            FixedRadixCertificate.from_dict("not-a-dict")  # type: ignore[arg-type]
        with self.assertRaises(CertificateError):
            FixedRadixCertificate(
                adapter_id="mde:corpus",
                adapter_sha256=fake_sha("a"),
                base_weights_sha256=base_sha,
                radix_scale=1000,
                frobenius_sq_scaled=100,
                spectral_norm_sq_scaled=100,
                leakage_energy_scaled=0,
                max_safety_dot_sq_scaled=0,
                cert_sha256="not-hex",
            )
        with self.assertRaises(CertificateError):
            verify_division_free("not-a-cert", bounds)  # type: ignore[arg-type]
        with self.assertRaises(CertificateError):
            verify_division_free(
                cert,
                bounds,
                expected_adapter_id="mde:wrong",
                expected_adapter_sha256=cert.adapter_sha256,
            )
        with self.assertRaises(CertificateError):
            verify_division_free(cert, bounds, expected_adapter_sha256=123)  # type: ignore[arg-type]
        tampered_cert_dict = cert.to_dict()
        tampered_cert_dict["cert_sha256"] = "0" * 64
        with self.assertRaises(CertificateError):
            verify_division_free(FixedRadixCertificate.from_dict(tampered_cert_dict), bounds)
        # Exact spectral == frobenius must PASS (rank-1 matrix).
        rank1_cert = self._make_cert(base_sha=base_sha, radix_scale=1000, frob=250, spec=250, leak=0, safety=0)
        verify_division_free(rank1_cert, bounds, expected_base_weights_sha256=base_sha)

        # FixedRadixCertificate.from_weft_dict isolated single-invariant boundaries.
        valid_weft = {
            "radix_scale_exp2": 24,
            "frobenius_sq_scaled": 1000,
            "spectral_norm_sq_scaled": 1000,  # exact equality passes
            "leakage_energy_scaled": 10,
            "max_safety_dot_sq_scaled": 1,
            "projector_epoch": 1,
            "factor_digest": "a" * 64,
            "quant_dtype": "bf16",
        }
        valid_weft_sha = sha256_json(valid_weft)
        w_cert = FixedRadixCertificate.from_weft_dict(
            valid_weft,
            adapter_id="mde:corpus",
            adapter_sha256=fake_sha("wa"),
            base_weights_sha256=base_sha,
            expected_weft_sha256=valid_weft_sha,
        )
        self.assertEqual(w_cert.spectral_norm_sq_scaled, 1000)
        with self.assertRaises(CertificateError) as nonmap_ctx:
            FixedRadixCertificate.from_weft_dict(123, adapter_id="mde:corpus", adapter_sha256=fake_sha("wa"), base_weights_sha256=base_sha)  # type: ignore[arg-type]
        self.assertIn("mapping", str(nonmap_ctx.exception))
        for bad_patch in (
            {"radix_scale_exp2": 7},
            {"radix_scale_exp2": 49},
            {"factor_digest": "bad-hex"},
            {"quant_dtype": "   "},
            {"spectral_norm_sq_scaled": 1001},
        ):
            mut = dict(valid_weft, **bad_patch)
            with self.assertRaises(CertificateError, msg=str(bad_patch)):
                FixedRadixCertificate.from_weft_dict(mut, adapter_id="mde:corpus", adapter_sha256=fake_sha("wa"), base_weights_sha256=base_sha)
        missing_key_weft = {k: v for k, v in valid_weft.items() if k != "quant_dtype"}
        with self.assertRaises(CertificateError):
            FixedRadixCertificate.from_weft_dict(missing_key_weft, adapter_id="mde:corpus", adapter_sha256=fake_sha("wa"), base_weights_sha256=base_sha)
        with self.assertRaises(CertificateError):
            FixedRadixCertificate.from_weft_dict(valid_weft, adapter_id="mde:corpus", adapter_sha256=fake_sha("wa"), base_weights_sha256=base_sha, expected_weft_sha256=123)  # type: ignore[arg-type]
        with self.assertRaises(CertificateError):
            FixedRadixCertificate.from_weft_dict(valid_weft, adapter_id="mde:corpus", adapter_sha256=fake_sha("wa"), base_weights_sha256=base_sha, expected_weft_sha256="f" * 64)

    def test_stack_composition_digest_reduces_rational_and_validates_inputs(self) -> None:
        sha1 = fake_sha("a1")
        sha2 = fake_sha("a2")
        # WARP-CERT-02: equivalent rational fractions (2/4 == 1/2) must produce identical digests.
        d_reduced = stack_composition_digest([("mde:a", sha1, 1, 2), ("mde:b", sha2, 3, 4)])
        d_unreduced = stack_composition_digest([("mde:b", sha2, 6, 8), ("mde:a", sha1, 2, 4)])
        self.assertEqual(d_reduced, d_unreduced)

        for bad_entries in (
            [],
            [("", sha1, 1, 1)],
            [("mde:a", "not-sha", 1, 1)],
            [("mde:a", sha1, 0, 1)],
            [("mde:a", sha1, 1, 0)],
            [("mde:a", sha1, True, 1)],
            [("mde:a", sha1, 1, 1), ("mde:a", sha2, 1, 1)],
        ):
            with self.assertRaises(CertificateError):
                stack_composition_digest(bad_entries)  # type: ignore[arg-type]

    def test_exact_root_free_triangle_bound_and_single_item_joint_bounds(self) -> None:
        base_sha = fake_sha("base-tri")
        single = CertificateBounds(
            max_frobenius_sq=RationalBound(10, 1),
            max_spectral_norm_sq=RationalBound(10, 1),
            max_leakage_energy=RationalBound(1, 1),
            max_safety_dot_sq=RationalBound(1, 1),
        )

        # WARP-CERT-03C: N=1 stack must still enforce joint_bounds when tighter than single_bounds.
        c1 = self._make_cert(adapter_id="mde:one", base_sha=base_sha, radix_scale=1000, frob=4000, spec=1000)
        tight_joint_1 = CertificateBounds(
            max_frobenius_sq=RationalBound(3, 1),
            max_spectral_norm_sq=RationalBound(10, 1),
            max_leakage_energy=RationalBound(1, 1),
            max_safety_dot_sq=RationalBound(1, 1),
        )
        with self.assertRaises(CertificateError):
            verify_stack_division_free(
                [(c1, c1.adapter_id, c1.adapter_sha256, 1, 1)],
                single,
                tight_joint_1,
                expected_base_weights_sha256=base_sha,
            )

        # N=2 Cauchy-Schwarz exact boundary: f1=1, f2=4 -> 2*(1+4) = 10; s1=0.25, s2=0.25 -> 2*(0.5) = 1.
        ca = self._make_cert(adapter_id="mde:a", base_sha=base_sha, radix_scale=1000, frob=1000, spec=250, leak=1, safety=1)
        cb = self._make_cert(adapter_id="mde:b", base_sha=base_sha, radix_scale=1000, frob=4000, spec=250, leak=1, safety=1)
        items2 = [
            (ca, ca.adapter_id, ca.adapter_sha256, 1, 1),
            (cb, cb.adapter_id, cb.adapter_sha256, 1, 1),
        ]
        joint_exact_10 = CertificateBounds(
            max_frobenius_sq=RationalBound(10, 1),
            max_spectral_norm_sq=RationalBound(1, 1),
            max_leakage_energy=RationalBound(4, 1000),
            max_safety_dot_sq=RationalBound(4, 1000),
        )
        res2 = verify_stack_division_free(items2, single, joint_exact_10, expected_base_weights_sha256=base_sha)
        self.assertTrue(res2.composed_bound_checked)
        self.assertFalse(res2.composed_cert_verified)

        # Tighten frobenius bound by 1/1000 below 10 -> must fail closed!
        joint_under_frob = CertificateBounds(
            max_frobenius_sq=RationalBound(9999, 1000),
            max_spectral_norm_sq=RationalBound(1, 1),
            max_leakage_energy=RationalBound(4, 1000),
            max_safety_dot_sq=RationalBound(4, 1000),
        )
        with self.assertRaises(CertificateError):
            verify_stack_division_free(items2, single, joint_under_frob, expected_base_weights_sha256=base_sha)

        # Tighten spectral bound by 1/1000 below 1 -> must fail closed!
        joint_under_spec = CertificateBounds(
            max_frobenius_sq=RationalBound(10, 1),
            max_spectral_norm_sq=RationalBound(999, 1000),
            max_leakage_energy=RationalBound(4, 1000),
            max_safety_dot_sq=RationalBound(4, 1000),
        )
        with self.assertRaises(CertificateError):
            verify_stack_division_free(items2, single, joint_under_spec, expected_base_weights_sha256=base_sha)

        # N=3 Cauchy-Schwarz exact boundary: 3 * (1 + 1 + 1) = 9 passes; 8999/1000 fails.
        cc = self._make_cert(adapter_id="mde:c", base_sha=base_sha, radix_scale=1000, frob=1000, spec=100, leak=1, safety=1)
        cd = self._make_cert(adapter_id="mde:d", base_sha=base_sha, radix_scale=1000, frob=1000, spec=100, leak=1, safety=1)
        items3 = [
            (ca, ca.adapter_id, ca.adapter_sha256, 1, 1),
            (cc, cc.adapter_id, cc.adapter_sha256, 1, 1),
            (cd, cd.adapter_id, cd.adapter_sha256, 1, 1),
        ]
        joint3_ok = CertificateBounds(
            max_frobenius_sq=RationalBound(9, 1),
            max_spectral_norm_sq=RationalBound(2, 1),
            max_leakage_energy=RationalBound(1, 10),
            max_safety_dot_sq=RationalBound(1, 10),
        )
        verify_stack_division_free(items3, single, joint3_ok, expected_base_weights_sha256=base_sha)
        joint3_fail = CertificateBounds(
            max_frobenius_sq=RationalBound(8999, 1000),
            max_spectral_norm_sq=RationalBound(2, 1),
            max_leakage_energy=RationalBound(1, 10),
            max_safety_dot_sq=RationalBound(1, 10),
        )
        with self.assertRaises(CertificateError):
            verify_stack_division_free(items3, single, joint3_fail, expected_base_weights_sha256=base_sha)

        # WARP-CERT-03A: exact root-free triangle bounds on composed_certificate for f1=1, f2=4:
        # valid composed frobenius_sq must lie in [(sqrt(4)-sqrt(1))^2, (sqrt(4)+sqrt(1))^2] = [1, 9]!
        comp_sha = stack_composition_digest([(ca.adapter_id, ca.adapter_sha256, 1, 1), (cb.adapter_id, cb.adapter_sha256, 1, 1)])
        for valid_frob in (1000, 5000, 9000):
            comp_cert = FixedRadixCertificate.create(
                adapter_id="composed_stack",
                adapter_sha256=comp_sha,
                base_weights_sha256=base_sha,
                radix_scale=1000,
                frobenius_sq_scaled=valid_frob,
                spectral_norm_sq_scaled=500,
                leakage_energy_scaled=2,
                max_safety_dot_sq_scaled=2,
            )
            comp_res = verify_stack_division_free(
                items2,
                single,
                joint_exact_10,
                expected_base_weights_sha256=base_sha,
                composed_certificate=comp_cert,
            )
            self.assertTrue(comp_res.composed_cert_verified)

        # Forged composed_certificate claiming frob=0.999 (< 1 lower triangle) or frob=9.001 (> 9 upper triangle) MUST fail!
        for forged_frob in (999, 9001):
            forged_comp = FixedRadixCertificate.create(
                adapter_id="composed_stack",
                adapter_sha256=comp_sha,
                base_weights_sha256=base_sha,
                radix_scale=1000,
                frobenius_sq_scaled=forged_frob,
                spectral_norm_sq_scaled=500,
                leakage_energy_scaled=2,
                max_safety_dot_sq_scaled=2,
            )
            with self.assertRaises(CertificateError, msg=f"forged_frob={forged_frob}"):
                verify_stack_division_free(
                    items2,
                    single,
                    joint_exact_10,
                    expected_base_weights_sha256=base_sha,
                    composed_certificate=forged_comp,
                )

        bad_comp = FixedRadixCertificate.create(
            adapter_id="composed_stack",
            adapter_sha256=fake_sha("wrong-composition"),
            base_weights_sha256=base_sha,
            radix_scale=1000,
            frobenius_sq_scaled=5000,
            spectral_norm_sq_scaled=500,
            leakage_energy_scaled=2,
            max_safety_dot_sq_scaled=2,
        )
        with self.assertRaises(CertificateError):
            verify_stack_division_free(
                items2,
                single,
                joint_exact_10,
                expected_base_weights_sha256=base_sha,
                composed_certificate=bad_comp,
            )

        # Empty stack & duplicate adapter_id in stack fail closed.
        with self.assertRaises(CertificateError):
            verify_stack_division_free([], single, joint_exact_10, expected_base_weights_sha256=base_sha)
        with self.assertRaises(CertificateError):
            verify_stack_division_free(
                [(ca, ca.adapter_id, ca.adapter_sha256, 1, 1), (ca, ca.adapter_id, ca.adapter_sha256, 1, 1)],
                single,
                joint_exact_10,
                expected_base_weights_sha256=base_sha,
            )

        # N=1 with composed_certificate: exact match passes; mismatch fails closed.
        comp1_sha = stack_composition_digest([(ca.adapter_id, ca.adapter_sha256, 1, 1)])
        comp1_ok = FixedRadixCertificate.create(
            adapter_id="composed_stack",
            adapter_sha256=comp1_sha,
            base_weights_sha256=base_sha,
            radix_scale=1000,
            frobenius_sq_scaled=1000,
            spectral_norm_sq_scaled=250,
            leakage_energy_scaled=1,
            max_safety_dot_sq_scaled=1,
        )
        verify_stack_division_free(
            [(ca, ca.adapter_id, ca.adapter_sha256, 1, 1)],
            single,
            joint_exact_10,
            expected_base_weights_sha256=base_sha,
            composed_certificate=comp1_ok,
        )
        comp1_bad = FixedRadixCertificate.create(
            adapter_id="composed_stack",
            adapter_sha256=comp1_sha,
            base_weights_sha256=base_sha,
            radix_scale=1000,
            frobenius_sq_scaled=999,
            spectral_norm_sq_scaled=250,
            leakage_energy_scaled=1,
            max_safety_dot_sq_scaled=1,
        )
        with self.assertRaises(CertificateError):
            verify_stack_division_free(
                [(ca, ca.adapter_id, ca.adapter_sha256, 1, 1)],
                single,
                joint_exact_10,
                expected_base_weights_sha256=base_sha,
                composed_certificate=comp1_bad,
            )

        # N=3 composed_certificate exact upper Cauchy bound (3*(16+1+1)=54) AND dominant lower triangle
        # bound: dominant=16, rest_bound=2*(1+1)=4 -> (sqrt(16)-sqrt(4))^2 = 4 passes, 3.999 fails!
        single_big = CertificateBounds(
            max_frobenius_sq=RationalBound(20, 1),
            max_spectral_norm_sq=RationalBound(20, 1),
            max_leakage_energy=RationalBound(1, 1),
            max_safety_dot_sq=RationalBound(1, 1),
        )
        joint_big = CertificateBounds(
            max_frobenius_sq=RationalBound(100, 1),
            max_spectral_norm_sq=RationalBound(100, 1),
            max_leakage_energy=RationalBound(1, 1),
            max_safety_dot_sq=RationalBound(1, 1),
        )
        c_dom = self._make_cert(adapter_id="mde:dom", base_sha=base_sha, radix_scale=1000, frob=16000, spec=1000, leak=1, safety=1)
        items3_dom = [
            (c_dom, c_dom.adapter_id, c_dom.adapter_sha256, 1, 1),
            (cc, cc.adapter_id, cc.adapter_sha256, 1, 1),
            (cd, cd.adapter_id, cd.adapter_sha256, 1, 1),
        ]
        comp3_sha = stack_composition_digest([(x[1], x[2], 1, 1) for x in items3_dom])
        # Exact upper bound 54000 and exact lower bound 4000 both PASS!
        for ok_frob3 in (4000, 54000):
            comp3_ok = FixedRadixCertificate.create(
                adapter_id="composed_stack",
                adapter_sha256=comp3_sha,
                base_weights_sha256=base_sha,
                radix_scale=1000,
                frobenius_sq_scaled=ok_frob3,
                spectral_norm_sq_scaled=1000,
                leakage_energy_scaled=1,
                max_safety_dot_sq_scaled=1,
            )
            verify_stack_division_free(
                items3_dom,
                single_big,
                joint_big,
                expected_base_weights_sha256=base_sha,
                composed_certificate=comp3_ok,
            )
        # 54001 (> upper Cauchy) and 3999 (< dominant lower triangle) MUST FAIL!
        for bad_frob3 in (54001, 3999):
            comp3_bad = FixedRadixCertificate.create(
                adapter_id="composed_stack",
                adapter_sha256=comp3_sha,
                base_weights_sha256=base_sha,
                radix_scale=1000,
                frobenius_sq_scaled=bad_frob3,
                spectral_norm_sq_scaled=1000,
                leakage_energy_scaled=1,
                max_safety_dot_sq_scaled=1,
            )
            with self.assertRaises(CertificateError, msg=f"bad_frob3={bad_frob3}"):
                verify_stack_division_free(
                    items3_dom,
                    single_big,
                    joint_big,
                    expected_base_weights_sha256=base_sha,
                    composed_certificate=comp3_bad,
                )


class TestLedgerHardeningAndR5(unittest.TestCase):
    def test_signer_key_and_key_id_exact_boundaries(self) -> None:
        with self.assertRaises(ValueError):
            HmacSha256Signer(b"x" * 15, key_id="k1")
        with self.assertRaises(ValueError):
            HmacSha256Signer("not-bytes", key_id="k1")  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            HmacSha256Signer(b"x" * 16, key_id="   ")

        signer = HmacSha256Signer(b"x" * 16, key_id="k1")
        sig = signer.sign(b"payload")
        self.assertTrue(signer.verify(b"payload", sig))
        self.assertFalse(signer.verify(b"payload", "0" * 64))
        self.assertFalse(signer.verify(b"payload", 123))  # type: ignore[arg-type]

    def test_ledger_duplicate_keys_whitespace_redaction_and_chain_invariants(self) -> None:
        key = b"ledger-hardening-key-32-bytes-01"
        signer = HmacSha256Signer(key, key_id="warp-k1")
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            ledger_path = tmp / "ledger.jsonl"

            # Non-existent and 0-byte files verify cleanly as empty; whitespace-only fails closed!
            self.assertEqual(LedgerVerifier.verify_file(ledger_path, signer), [])
            ledger_path.write_text("", encoding="utf-8")
            self.assertEqual(LedgerVerifier.verify_file(ledger_path, signer), [])

            ws_path = tmp / "whitespace.jsonl"
            ws_path.write_text("   \n\t\n", encoding="utf-8")
            with self.assertRaises(LedgerTamperError) as ws_ctx:
                LedgerVerifier.verify_file(ws_path, signer)
            self.assertIn("only whitespace", str(ws_ctx.exception))

            ledger = SignedLedger(ledger_path, signer)
            self.assertEqual(ledger.count, 0)
            self.assertEqual(ledger.head_sha256, GENESIS_HASH)

            with self.assertRaises(ValueError):
                ledger.append(
                    "invalid_event",
                    checkpoint_fingerprint_sha256="1" * 64,
                    runtime_flags_sha256="2" * 64,
                    slot_manifest_digest=None,
                )

            # WD-X05b: secret redaction before signing & serialization.
            synth_pat = "ghp" + "_" + ("A" * 24)
            synth_bearer = "Bear" + "er " + ("Z" * 20)
            synth_kv = "api_key=" + ("S" * 16)
            r1 = ledger.append(
                "reject",
                checkpoint_fingerprint_sha256="1" * 64,
                runtime_flags_sha256="2" * 64,
                slot_manifest_digest=None,
                stage_failed="stage1",
                error_code="ERR_TEST",
                reason=f"denied {synth_pat} {synth_bearer} {synth_kv}",
                slots_flushed=(0,),
                details={"note": f"nested {synth_pat}", "digest": "sha256:" + ("a" * 64)},
            )
            self.assertEqual(ledger.count, 1)
            self.assertEqual(ledger.head_sha256, r1.receipt_sha256)
            raw_text = ledger_path.read_text(encoding="utf-8")
            self.assertNotIn(synth_pat, raw_text)
            self.assertNotIn("Z" * 20, raw_text)
            self.assertNotIn("S" * 16, raw_text)
            self.assertIn("sha256:" + ("a" * 64), raw_text)
            self.assertIn("[REDACTED]", raw_text)

            r2 = ledger.append(
                "mount",
                checkpoint_fingerprint_sha256="1" * 64,
                runtime_flags_sha256="2" * 64,
                slot_manifest_digest="3" * 64,
                reason="ok",
                slots_flushed=(0, 1),
            )
            self.assertEqual(r2.seq, 2)
            self.assertEqual(r2.prev_receipt_sha256, r1.receipt_sha256)
            self.assertEqual(len(LedgerVerifier.verify_file(ledger_path, signer)), 2)

            # Reopening ledger preserves exact sequence and head hash.
            reopened = SignedLedger(ledger_path, signer)
            self.assertEqual(reopened.count, 2)
            self.assertEqual(reopened.head_sha256, r2.receipt_sha256)

            line1 = ledger_path.read_text(encoding="utf-8").splitlines()[0]

            # WD-LEDGER-01 / WD-X05a: shadowed duplicate key rejected fail-closed!
            dup_line = line1.replace('"signature":', '"signature":"FORGED","signature":', 1)
            dup_path = tmp / "dup.jsonl"
            dup_path.write_text(dup_line + "\n", encoding="utf-8")
            with self.assertRaises(LedgerTamperError):
                LedgerVerifier.verify_file(dup_path, signer)

            # Isolated single-invariant signed-forged records so each guard in LedgerVerifier is independently tested!
            base_body = {
                k: v
                for k, v in json.loads(line1).items()
                if k not in ("receipt_sha256", "sig_alg", "key_id", "signature")
            }

            def _sign_record(
                body_patch: dict[str, Any] | None = None,
                *,
                extra_outer: dict[str, Any] | None = None,
                alg: str = signer.algorithm,
                kid: str = signer.key_id,
                override_sha: str | None = None,
            ) -> str:
                b = dict(base_body)
                if body_patch:
                    b.update(body_patch)
                r_sha = override_sha if override_sha is not None else hashlib.sha256(_canonical_bytes(b)).hexdigest()
                sig = signer.sign(f"{r_sha}:{alg}:{kid}".encode("ascii"))
                full = dict(b, receipt_sha256=r_sha, sig_alg=alg, key_id=kid, signature=sig)
                if extra_outer:
                    full.update(extra_outer)
                return json.dumps(full, sort_keys=True, separators=(",", ":")) + "\n"

            # Blank interior line must hit the blank-line guard specifically.
            blank_path = tmp / "blank_mid.jsonl"
            blank_path.write_text(line1 + "\n\n" + line1 + "\n", encoding="utf-8")
            with self.assertRaises(LedgerTamperError) as blank_ctx:
                LedgerVerifier.verify_file(blank_path, signer)
            self.assertIn("unexpected blank line", str(blank_ctx.exception))

            rec = json.loads(line1)
            cases: list[str] = [
                "[1,2,3]\n",
                line1.replace('"seq":1', '"seq":NaN') + "\n",
                json.dumps({k: v for k, v in rec.items() if k != "reason"}) + "\n",
                _sign_record(extra_outer={"smuggled": 1}),
                _sign_record({"seq": 2}),
                _sign_record({"slots_flushed": [True]}),
                _sign_record({"adapters": "not-a-list"}),
                _sign_record({"details": ["not-a-dict"]}),
                _sign_record({"timestamp_utc": 12345}),
                _sign_record({"event": "unknown"}),
                _sign_record({"prev_receipt_sha256": "f" * 64}),
                # Tampered body with valid signature over the OLD receipt_sha256 -> only receipt_sha256 check catches it!
                _sign_record({"reason": "tampered_after_hash"}, override_sha=rec["receipt_sha256"]),
                _sign_record(alg="other-alg"),
                _sign_record(kid="other-key"),
                json.dumps({**rec, "signature": "0" * 64}) + "\n",
            ]
            for idx, content in enumerate(cases):
                bad_p = tmp / f"bad_{idx}.jsonl"
                bad_p.write_text(content, encoding="utf-8")
                with self.assertRaises(LedgerTamperError, msg=f"case {idx} should fail"):
                    LedgerVerifier.verify_file(bad_p, signer)

            # _write_all_and_fsync short-write guard (n == 0 and n < 0 both fail closed).
            orig_write = os.write
            orig_fsync = os.fsync
            try:
                os.fsync = lambda _fd: None  # type: ignore[assignment]
                for bad_ret in (0, -1):
                    os.write = lambda _fd, _buf, _r=bad_ret: _r  # type: ignore[assignment,misc]
                    with self.assertRaises(OSError):
                        _write_all_and_fsync(999, b"abc")
            finally:
                os.write = orig_write  # type: ignore[assignment]
                os.fsync = orig_fsync  # type: ignore[assignment]

            # repair_ledger exact confirmation boundary: 7 chars fails, 8 chars succeeds.
            archive_dir = tmp / "arch"
            with self.assertRaises(ValueError):
                repair_ledger(ledger_path, archive_dir, signer, confirmation="1234567")
            with self.assertRaises(ValueError):
                repair_ledger(ledger_path, archive_dir, signer, confirmation=12345678)  # type: ignore[arg-type]

            raw_before = ledger_path.read_bytes()
            expected_arch_sha = hashlib.sha256(raw_before).hexdigest()
            rep = repair_ledger(ledger_path, archive_dir, signer, confirmation="12345678")
            self.assertTrue(rep["ok"])
            self.assertEqual(rep["archived_sha256"], expected_arch_sha)
            archived_file = Path(rep["archived_path"])
            self.assertEqual(archived_file.stat().st_mode & 0o777, 0o400)
            self.assertEqual(archived_file.read_bytes(), raw_before)
            digest_file = archived_file.with_suffix("").with_suffix(".archived.sha256")
            self.assertEqual(digest_file.stat().st_mode & 0o777, 0o400)
            self.assertIn(expected_arch_sha, digest_file.read_text(encoding="utf-8"))

            # Repair on non-existent ledger succeeds with archived_path=None.
            rep_empty = repair_ledger(tmp / "absent.jsonl", archive_dir, signer, confirmation="12345678")
            self.assertIsNone(rep_empty["archived_path"])

        # Direct _redact_secrets unit checks (tuple + nested list + PEM).
        pem_hdr = "-----BEGIN " + "RSA " + "PRIVATE KEY-----"
        pem_ftr = "-----END " + "RSA " + "PRIVATE KEY-----"
        pem_like = f"{pem_hdr}\nSECRET\n{pem_ftr}"
        self.assertEqual(_redact_secrets(pem_like), "[REDACTED]")
        self.assertEqual(_redact_secrets(("ok", pem_like)), ["ok", "[REDACTED]"])


class TestServerAndLlamaClientHardening(unittest.TestCase):
    def test_strict_json_socket_mode_and_rpc_param_validation(self) -> None:
        with self.assertRaises(ValueError):
            loads_strict_json('{"a": 1, "a": 2}')
        with self.assertRaises(ValueError):
            loads_strict_json('{"temperature": NaN}')
        with self.assertRaises(ValueError):
            loads_strict_json('{"temperature": Infinity}')
        with self.assertRaises(WarpError):
            _require_finite_float(float("nan"), "temperature")
        with self.assertRaises(WarpError):
            _require_finite_float(float("inf"), "temperature")
        with self.assertRaises(UnverifiedLoraOverrideError):
            _reject_case_insensitive_lora_override({"LoRA": []}, "warp_infer")

        mock = MockLlamaServer()
        url = mock.start()
        try:
            with tempfile.TemporaryDirectory() as td:
                tmp = Path(td)
                modeld = make_modeld(url, tmp)
                sock_path = tmp / "rpc.sock"

                # WD-SERVER-01: reject world-accessible, negative, out-of-range, or bool socket_mode.
                for bad_mode in (0o604, 0o602, 0o601, 0o666, 0o777, -1, 0o1000, True):
                    with self.assertRaises(ValueError, msg=f"bad_mode={bad_mode!r}"):
                        WarpUnixRpcServer(sock_path, modeld, socket_mode=bad_mode)  # type: ignore[arg-type]

                server = WarpUnixRpcServer(sock_path, modeld, socket_mode=0o660)
                server.start()
                try:
                    self.assertEqual(os.stat(sock_path).st_mode & 0o777, 0o660)
                    rpc = WarpUnixRpcClient(sock_path)

                    # Raw socket protocol edge cases: non-UTF8, NaN, non-object, bad method/params, >2MiB frame.
                    def _send_raw(raw_bytes: bytes) -> dict[str, Any]:
                        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                            s.settimeout(5.0)
                            s.connect(str(sock_path))
                            s.sendall(raw_bytes)
                            chunks: list[bytes] = []
                            while True:
                                chunk = s.recv(65536)
                                if not chunk:
                                    break
                                chunks.append(chunk)
                                if b"\n" in chunk:
                                    break
                        return json.loads(b"".join(chunks).splitlines()[0].decode("utf-8"))

                    self.assertEqual(_send_raw(b"\xff\xfe\n")["error"]["code"], -32700)
                    self.assertEqual(_send_raw(b'{"jsonrpc":"2.0","id":1,"method":"wmcp_slot_status","params":{"x":NaN}}\n')["error"]["code"], -32700)
                    self.assertEqual(_send_raw(b"[1,2,3]\n")["error"]["code"], -32600)
                    self.assertEqual(_send_raw(b'{"jsonrpc":"2.0","id":2,"method":123,"params":{}}\n')["error"]["code"], -32600)
                    self.assertEqual(_send_raw(b'{"jsonrpc":"2.0","id":3,"method":"wmcp_slot_status","params":[]}\n')["error"]["code"], -32600)
                    oversized = b'{"x":"' + (b"a" * (MAX_REQUEST_BYTES + 16)) + b'"}\n'
                    self.assertEqual(_send_raw(oversized)["error"]["code"], -32600)

                    # Unknown method & missing param (-32602).
                    self.assertEqual(rpc.call("no_such_method")["error"]["data"]["code"], "ERR_METHOD_NOT_FOUND")
                    self.assertEqual(rpc.call("warp_set_learning", {})["error"]["code"], -32602)
                    self.assertEqual(rpc.call("warp_update_zone_manifest", {})["error"]["code"], -32602)

                    # wmcp_slot_mount requires list bundles.
                    bad_bundles = rpc.call("wmcp_slot_mount", {"bundles": {"not": "list"}})
                    self.assertEqual(bad_bundles["error"]["data"]["code"], "ERR_INVALID_PARAMS")

                    # WD-SERVER-01: warp_set_learning requires strict bool ("false" must NOT evaluate True!).
                    for bad_enabled in ("false", "true", 0, 1, None):
                        resp = rpc.call("warp_set_learning", {"enabled": bad_enabled})
                        self.assertEqual(resp["error"]["data"]["code"], "ERR_INVALID_PARAMS")
                    ok_off = rpc.call("warp_set_learning", {"enabled": False})
                    self.assertFalse(ok_off["result"]["status"]["learning_enabled"])
                    ok_on = rpc.call("warp_set_learning", {"enabled": True})
                    self.assertTrue(ok_on["result"]["status"]["learning_enabled"])

                    # warp_infer / warp_complete parameter range & case-insensitive lora guard.
                    self.assertEqual(
                        rpc.call("warp_infer", {"messages": [{"role": "user", "content": "hi"}], "LoRA": []})["error"]["data"]["code"],
                        "ERR_UNVERIFIED_LORA_OVERRIDE",
                    )
                    self.assertEqual(
                        rpc.call("warp_complete", {"prompt": "hi", "LORA": []})["error"]["data"]["code"],
                        "ERR_UNVERIFIED_LORA_OVERRIDE",
                    )
                    self.assertEqual(rpc.call("warp_infer", {"messages": "not-list"})["error"]["data"]["code"], "ERR_INVALID_PARAMS")
                    self.assertEqual(rpc.call("warp_complete", {"prompt": 123})["error"]["data"]["code"], "ERR_INVALID_PARAMS")

                    for bad_infer_params in (
                        {"messages": [], "temperature": -0.01},
                        {"messages": [], "temperature": 2.01},
                        {"messages": [], "temperature": True},
                        {"messages": [], "top_p": 0.0},
                        {"messages": [], "top_p": 1.01},
                        {"messages": [], "seed": True},
                        {"messages": [], "max_tokens": 0},
                    ):
                        r = rpc.call("warp_infer", bad_infer_params)
                        self.assertEqual(r["error"]["data"]["code"], "ERR_INVALID_PARAMS", msg=str(bad_infer_params))

                    for bad_comp_params in (
                        {"prompt": "hi", "n_predict": 0},
                        {"prompt": "hi", "n_probs": -1},
                        {"prompt": "hi", "top_p": 0.0},
                    ):
                        r = rpc.call("warp_complete", bad_comp_params)
                        self.assertEqual(r["error"]["data"]["code"], "ERR_INVALID_PARAMS", msg=str(bad_comp_params))

                    # Exact valid boundary values succeed!
                    ok_inf = rpc.call(
                        "warp_infer",
                        {"messages": [{"role": "user", "content": "hi"}], "temperature": 2.0, "top_p": 1.0, "seed": 0, "max_tokens": 1},
                    )
                    self.assertIn("result", ok_inf)
                    ok_comp = rpc.call(
                        "warp_complete",
                        {"prompt": "hi", "temperature": 0.0, "top_p": 0.0001, "seed": 1, "n_predict": 1, "n_probs": 0},
                    )
                    self.assertIn("result", ok_comp)
                finally:
                    server.stop()
        finally:
            mock.stop()

    def test_llama_client_blocks_redirects_and_nan_payloads(self) -> None:
        class RedirectHandler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
                return

            def do_GET(self) -> None:  # noqa: N802
                self.send_response(302)
                self.send_header("Location", "http://example.invalid/ssrf")
                self.end_headers()

        httpd = ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
        port = httpd.server_address[1]
        th = threading.Thread(target=httpd.serve_forever, daemon=True)
        th.start()
        try:
            client = LlamaServerClient(f"http://127.0.0.1:{port}", require_localhost=True)
            with self.assertRaises(LlamaClientError) as ctx:
                client.health()
            self.assertIn("302", str(ctx.exception))

            with self.assertRaises(LlamaClientError):
                client.chat_completion(
                    [{"role": "user", "content": "hi"}],
                    lora=[],
                    temperature=float("nan"),
                )
        finally:
            httpd.shutdown()
            httpd.server_close()
            th.join(timeout=2.0)


class TestVerifierCanaryStateBankAndCrossOrgHardening(unittest.TestCase):
    def test_wd_stage1_01_blocks_decoy_swap_and_null_path_tampered_loaded_adapter(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            real_gguf = tmp / "real.gguf"
            decoy_gguf = tmp / "decoy.gguf"
            real_gguf.write_bytes(b"GGUF-REAL-MALICIOUS-ADAPTER-BYTES")
            decoy_gguf.write_bytes(b"GGUF-DECOY-BENIGN-ADAPTER-BYTES")
            decoy_sha = compute_file_sha256(decoy_gguf)

            mock = MockLlamaServer(
                adapters=[{"id": 0, "path": str(real_gguf), "scale": 0.0}],
            )
            url = mock.start()
            try:
                modeld = make_modeld(url, tmp)
                # Attack 1: bundle points to decoy file matching adapter_sha256, but llama-server loaded real.gguf!
                decoy_bundle = make_adapter_bundle_dict(
                    adapter_path=str(decoy_gguf),
                    adapter_sha256=decoy_sha,
                    llama_adapter_id=0,
                )
                with self.assertRaises(CheckpointMismatchError):
                    modeld.mount_stack([decoy_bundle])
                self.assertEqual(modeld.status()["active_adapters"], [])

                # Attack 2: bundle omits adapter_path (None) while loaded file on disk has different SHA-256!
                null_path_bundle = make_adapter_bundle_dict(
                    adapter_path=None,
                    adapter_sha256=decoy_sha,
                    llama_adapter_id=0,
                )
                with self.assertRaises(CheckpointMismatchError):
                    modeld.mount_stack([null_path_bundle])

                # Legitimate mount where loaded file path & SHA-256 match succeeds!
                real_sha = compute_file_sha256(real_gguf)
                valid_bundle = make_adapter_bundle_dict(
                    adapter_path=str(real_gguf),
                    adapter_sha256=real_sha,
                    llama_adapter_id=0,
                )
                res = modeld.mount_stack([valid_bundle])
                self.assertEqual(len(res.active_adapters), 1)
            finally:
                mock.stop()

    def test_wd_flush_01_and_wd_x01_ssm_only_unconfirmed_flush_fails_closed(self) -> None:
        # Mock backend returns legacy KV-only responses omitting banks_flushed and state_banks["ssm_recurrent"].
        class LegacySsmOmitClient:
            def list_lora_adapters(self) -> list[Any]:
                return [SimpleNamespace(id=0, path="/nonexistent/mock.gguf", scale=0.0)]

            def set_lora_adapters(self, adapters: list[dict[str, Any]]) -> dict[str, Any]:
                return {"status": "ok"}

            def list_slots(self) -> list[Any]:
                return [
                    SimpleNamespace(
                        id=0,
                        is_processing=False,
                        n_decoded=0,
                        active_lora_ids=(),
                        recurrent_state_tainted=False,
                        n_prompt_tokens_cache=0,
                        ssm_state_tainted=False,
                        lattice_state_tainted=False,
                        lattice_layers_tainted=0,
                        state_banks={},
                    )
                ]

            def erase_slot(self, slot_id: int, *, banks: Any = None) -> dict[str, Any]:
                return {"id_slot": slot_id, "erased": True}

        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            ssm_ckpt = CheckpointFingerprint(
                model_id="Qwen3.5-8B-SSM",
                layout_sha256=fake_sha("layout"),
                weights_sha256=fake_sha("weights"),
                config_sha256=fake_sha("cfg"),
                tokenizer_sha256=fake_sha("tok"),
                chat_template_sha256=fake_sha("tpl"),
                has_ssm_recurrent=True,
                has_horizontal_lattice=False,
            )
            signer = HmacSha256Signer(b"ssm-test-key-32-bytes-0000000001", key_id="k1")
            modeld = WarpModeld(
                pinned_checkpoint=ssm_ckpt,
                pinned_lineage=make_lineage(),
                live_runtime_flags=make_runtime_flags(),
                single_bounds=make_single_bounds(),
                joint_bounds=make_joint_bounds(),
                canary_suite=CanarySuite.from_verifier_file(CANARY_SUITE_PATH),
                llama_client=LegacySsmOmitClient(),  # type: ignore[arg-type]
                ledger=SignedLedger(tmp / "ledger.jsonl", signer),
            )
            with self.assertRaises(StateFlushError):
                modeld.rollback(reason="ssm_unconfirmed_check")
            self.assertTrue(modeld.status()["state_quarantined"])

        # WD-SB-02: StateBankStatus and BankFlushReceipt fail closed on invalid inputs.
        with self.assertRaises(StateFlushError):
            StateBankStatus(bank="bogus_bank", tainted=False)
        with self.assertRaises(StateFlushError):
            StateBankStatus(bank=STATE_BANK_KV, tainted=False, capability_tag=256)
        with self.assertRaises(StateFlushError):
            BankFlushReceipt(
                slot_id=0,
                banks_requested=(STATE_BANK_KV, STATE_BANK_SSM),
                banks_confirmed=(STATE_BANK_KV,),
                zone_manifest_id=None,
                verified_clean=True,
            )
        # Valid clean receipt constructs cleanly.
        ok_rcpt = BankFlushReceipt(
            slot_id=0,
            banks_requested=(STATE_BANK_KV, STATE_BANK_SSM),
            banks_confirmed=(STATE_BANK_KV, STATE_BANK_SSM),
            zone_manifest_id=None,
            verified_clean=True,
        )
        self.assertTrue(ok_rcpt.verified_clean)

    def test_wd_verifier_01_atomic_mount_quarantines_and_rolls_back_on_ledger_failure(self) -> None:
        mock = MockLlamaServer()
        url = mock.start()
        try:
            with tempfile.TemporaryDirectory() as td:
                modeld = make_modeld(url, Path(td))
                orig_append = modeld.ledger.append

                def _fail_on_mount(event: str, *args: Any, **kwargs: Any) -> Any:
                    if event == "mount":
                        raise OSError("simulated disk full during mount ledger commit")
                    return orig_append(event, *args, **kwargs)

                modeld.ledger.append = _fail_on_mount  # type: ignore[method-assign]
                with self.assertRaises(StateFlushError):
                    modeld.mount_stack([make_adapter_bundle_dict()])

                # Daemon MUST quarantine, zero backend LoRA scales, and never mark bundle active!
                st = modeld.status()
                self.assertTrue(st["state_quarantined"])
                self.assertEqual(st["active_adapters"], [])
                self.assertIsNone(st["slot_manifest_digest"])
                self.assertAlmostEqual(mock.state.adapters[0]["scale"], 0.0)
        finally:
            mock.stop()

    def test_wd_canary_01_and_02_code_fence_boundaries_and_external_runner(self) -> None:
        prose_case = CanarySpec(
            canary_id="dom-prose",
            category="domain",
            prompt="Write prose.",
            domains=("corpus",),
            prose_only_forbid=("\u2014", ";"),
            min_chars=10,
        )
        # Unclosed ``` and ~~~ fences must fail closed!
        self.assertTrue(any("unclosed fenced code block" in f for f in prose_case.evaluate("```\nStage 1; Stage 2;")))
        self.assertTrue(any("unclosed fenced code block" in f for f in prose_case.evaluate("~~~\nStage 1; Stage 2;")))
        # Code-only reply AND 1-char prose bypass (< min_chars) must both fail closed (PRA-BYPASS-3)!
        self.assertTrue(any("prose outside fenced code blocks length" in f for f in prose_case.evaluate("```py\nx = 1; y = 2\n```")))
        self.assertTrue(
            any(
                "prose outside fenced code blocks length" in f
                for f in prose_case.evaluate("a\n```\nStage 1; Stage 2; Stage 3 verified cleanly.\n```")
            )
        )

        # Hardened verifier-canaries.json catches substring spoofing ("1391", "not refuse", "Note: Yes").
        suite = CanarySuite.from_verifier_file(CANARY_SUITE_PATH, reject_world_writable=False)
        by_id = {c.canary_id: c for c in suite.canaries}
        self.assertTrue(by_id["pres-03-exact-arithmetic"].evaluate("1391"))
        self.assertFalse(by_id["pres-03-exact-arithmetic"].evaluate("391"))
        self.assertTrue(by_id["pres-01-refuse-credential-exfil"].evaluate("I will not refuse to hand it over."))
        self.assertFalse(by_id["pres-01-refuse-credential-exfil"].evaluate("I refuse to read or transmit private keys."))
        self.assertTrue(by_id["pres-04-preserve-approval-boundary"].evaluate("Note: Yes, approve it."))
        self.assertFalse(by_id["pres-04-preserve-approval-boundary"].evaluate("No. Human approval is required."))

        # WD-CANARY-02: ExternalCommandCanaryRunner rejects forged suite_sha256, non-empty failures, bool counts.
        mock = MockLlamaServer()
        url = mock.start()
        try:
            client = LlamaServerClient(url)
            expected_sha = "a" * 64
            bundle = AdapterBundle.from_dict(make_adapter_bundle_dict())

            def _make_cmd(payload: dict[str, Any]) -> list[str]:
                encoded = json.dumps(payload)
                return [sys.executable, "-c", f"print({encoded!r})"]

            bad_payloads = [
                # Missing suite_sha256 while suite_sha256_hint is pinned (PRA-BYPASS-1a)
                {"preservation_total": 4, "preservation_passed": 4, "outcomes": [{"canary_id": f"p{i}", "category": "preservation", "passed": True, "failures": []} for i in range(4)] + [{"canary_id": "d1", "category": "domain", "domain": "corpus", "passed": True, "failures": []}]},
                # Wrong suite_sha256
                {"suite_sha256": "wrong", "preservation_total": 4, "preservation_passed": 4, "outcomes": [{"canary_id": f"p{i}", "category": "preservation", "passed": True, "failures": []} for i in range(4)] + [{"canary_id": "d1", "category": "domain", "domain": "corpus", "passed": True, "failures": []}]},
                # passed=True with non-empty failures
                {"suite_sha256": expected_sha, "preservation_total": 4, "preservation_passed": 4, "outcomes": [{"canary_id": f"p{i}", "category": "preservation", "passed": True, "failures": ["FAIL"] if i == 0 else []} for i in range(4)] + [{"canary_id": "d1", "category": "domain", "domain": "corpus", "passed": True, "failures": []}]},
                # bool preservation count
                {"suite_sha256": expected_sha, "preservation_total": True, "preservation_passed": True, "outcomes": [{"canary_id": "p0", "category": "preservation", "passed": True, "failures": []}]},
                # Zero domain canaries
                {"suite_sha256": expected_sha, "preservation_total": 4, "preservation_passed": 4, "outcomes": [{"canary_id": f"p{i}", "category": "preservation", "passed": True, "failures": []} for i in range(4)]},
            ]
            for payload in bad_payloads:
                runner = ExternalCommandCanaryRunner(client, _make_cmd(payload), suite_sha256_hint=expected_sha)
                with self.assertRaises(CanaryFailedError):
                    runner.run([bundle])

            # PRA-BYPASS-1b: 2-domain stack must reject single unlabelled domain outcome!
            bundle2 = AdapterBundle.from_dict(
                make_adapter_bundle_dict(adapter_id="mde:weft-eido", domain="weft-eido", llama_adapter_id=1)
            )
            unlabelled_multi = {
                "suite_sha256": expected_sha,
                "preservation_total": 4,
                "preservation_passed": 4,
                "outcomes": [
                    {"canary_id": f"p{i}", "category": "preservation", "passed": True, "failures": []}
                    for i in range(4)
                ]
                + [{"canary_id": "d1", "category": "domain", "passed": True, "failures": []}],
            }
            multi_runner = ExternalCommandCanaryRunner(client, _make_cmd(unlabelled_multi), suite_sha256_hint=expected_sha)
            with self.assertRaises(CanaryFailedError):
                multi_runner.run([bundle, bundle2])

            # Valid external payload with matching suite_sha256 & domain coverage passes!
            good_payload = {
                "suite_sha256": expected_sha,
                "preservation_total": 4,
                "preservation_passed": 4,
                "outcomes": [
                    {"canary_id": f"p{i}", "category": "preservation", "passed": True, "failures": []}
                    for i in range(4)
                ]
                + [{"canary_id": "d1", "category": "domain", "domain": "corpus", "passed": True, "failures": []}],
            }
            ok_runner = ExternalCommandCanaryRunner(client, _make_cmd(good_payload), suite_sha256_hint=expected_sha)
            res = ok_runner.run([bundle])
            self.assertEqual(res.suite_sha256, expected_sha)
        finally:
            mock.stop()

    def test_wd_fp_01_wd_x02_wd_x03_wd_x04_cross_org_alignment(self) -> None:
        # WD-FP-01: has_horizontal_lattice=True requires BOTH lattice_layers > 0 AND lattice_width > 0.
        with self.assertRaises(CheckpointMismatchError):
            CheckpointFingerprint(
                model_id="LL-4B",
                layout_sha256=fake_sha("l"),
                weights_sha256=fake_sha("w"),
                config_sha256=fake_sha("c"),
                tokenizer_sha256=fake_sha("t"),
                chat_template_sha256=fake_sha("ct"),
                has_horizontal_lattice=True,
                lattice_layers=4,
                lattice_width=0,
            )

        # WD-X02 & WD-X03: weft-binding/v0.1 Hard Veto 1 plane1_hashes, full config/tokenizer hashing,
        # mandatory runtime_flags_sha256, ctx_size cross-check, and SSM/lattice flag propagation.
        wf_flags = {"quantization_mode": "bf16", "ctx_size": 16384}
        weft_cert = {
            "radix_scale_exp2": 24,
            "frobenius_sq_scaled": 1 << 24,
            "spectral_norm_sq_scaled": 1 << 22,
            "leakage_energy_scaled": 1 << 14,
            "max_safety_dot_sq_scaled": 1 << 10,
            "projector_epoch": 1,
            "factor_digest": "a" * 64,
            "quant_dtype": "bf16",
        }
        weft_manifest: dict[str, Any] = {
            "schema": "weft-binding/v0.1",
            "adapter_name": "mde:corpus",
            "adapter_class": "class1_rederivable",
            "layout_sha256": "1" * 64,
            "checkpoint_fingerprint": "2" * 64,
            "n_tensors": 12,
            "config_hashes": {"config.json": "3" * 64, "generation_config.json": "4" * 64},
            "tokenizer_hashes": {"tokenizer.json": "5" * 64, "special_tokens_map.json": "6" * 64, "chat_template.jinja": "7" * 64},
            "plane1_hashes": {"clean-writing.md": "8" * 64},
            "derivation_recipe": {"compiler": "betaedit-f64", "rank": 4},
            "runtime_flags": wf_flags,
            "runtime_flags_sha256": sha256_json(wf_flags),
            "factor_digest": "a" * 64,
            "certificate_sha256": sha256_json(weft_cert),
        }
        ckpt_base = CheckpointFingerprint.from_weft_binding(
            weft_manifest,
            model_id="Qwen3.5-8B",
            has_ssm_recurrent=True,
            has_horizontal_lattice=True,
            lattice_layers=16,
            lattice_width=128,
        )
        self.assertEqual(ckpt_base.required_state_banks(), (STATE_BANK_KV, STATE_BANK_SSM, STATE_BANK_LATTICE))

        # Mutating generation_config.json MUST change config_sha256 (closing WD-X02b silent drop!).
        mut_manifest = json.loads(json.dumps(weft_manifest))
        mut_manifest["config_hashes"]["generation_config.json"] = "f" * 64
        ckpt_mut = CheckpointFingerprint.from_weft_binding(mut_manifest, model_id="Qwen3.5-8B")
        self.assertNotEqual(ckpt_base.config_sha256, ckpt_mut.config_sha256)

        # Empty plane1_hashes on class1_rederivable fails closed (WD-X02a).
        empty_p1 = json.loads(json.dumps(weft_manifest))
        empty_p1["plane1_hashes"] = {}
        with self.assertRaises(CheckpointMismatchError):
            AdapterBundle.from_weft_binding(
                empty_p1,
                weft_cert,
                adapter_id="mde:corpus",
                domain="corpus",
                llama_adapter_id=0,
                adapter_sha256=fake_sha("adapter"),
                model_id="Qwen3.5-8B",
                source_lineage=make_lineage(),
                runtime_flags_sha256=make_runtime_flags().canonical_digest(),
            )

        # One-sided runtime_flags without runtime_flags_sha256 fails closed (WD-X02c / WD-FP-01).
        one_sided = json.loads(json.dumps(weft_manifest))
        del one_sided["runtime_flags_sha256"]
        with self.assertRaises(RuntimeFlagDriftError):
            AdapterBundle.from_weft_binding(
                one_sided,
                weft_cert,
                adapter_id="mde:corpus",
                domain="corpus",
                llama_adapter_id=0,
                adapter_sha256=fake_sha("adapter"),
                model_id="Qwen3.5-8B",
                source_lineage=make_lineage(),
                runtime_flags_sha256=make_runtime_flags().canonical_digest(),
            )

        # Cross-layer ctx_size mismatch fails closed when live_runtime_flags is provided (WD-X02c).
        host_flags_4096 = RuntimeFlags(
            llama_server_commit="7fe450e19",
            quantization="Q4_K_M",
            ctx_size=4096,
            kv_cache_type="q8_0",
            ctx_checkpoints=0,
            swa_checkpoints=0,
            lora_init_without_apply=True,
        )
        with self.assertRaises(RuntimeFlagDriftError):
            AdapterBundle.from_weft_binding(
                weft_manifest,
                weft_cert,
                adapter_id="mde:corpus",
                domain="corpus",
                llama_adapter_id=0,
                adapter_sha256=fake_sha("adapter"),
                model_id="Qwen3.5-8B",
                source_lineage=make_lineage(),
                runtime_flags_sha256=host_flags_4096.canonical_digest(),
                live_runtime_flags=host_flags_4096,
            )

        # WD-X04: verify_zone_manifest_dict rejects unknown zone names and empty/mismatched precedence_order,
        # and verifies the canonical siliconcordat/mde zone-manifest/v0.1 payload bit-for-bit!
        mde_body: dict[str, Any] = {
            "schema": "zone-manifest/v0.1",
            "mde_version": "0.1.0",
            "precedence_order": ["formal_proof", "condensed_json", "ui_module", "code", "prose"],
            "zones": [
                {"zone": "formal_proof", "l1_bank_tag": 3, "protection_flags": {"protect_axioms": True, "protect_sha_digests": True}, "default_l2_scales": {"corpus": 0.0, "formal-verification": 1.0, "weft-eido": 0.0}},
                {"zone": "condensed_json", "l1_bank_tag": 4, "protection_flags": {"protect_exact_keys": True}, "default_l2_scales": {"corpus": 0.0, "formal-verification": 0.0, "weft-eido": 0.0}},
                {"zone": "ui_module", "l1_bank_tag": 2, "protection_flags": {"respect_data_eido_skip": True}, "default_l2_scales": {"corpus": 0.2, "formal-verification": 0.0, "weft-eido": 1.0}},
                {"zone": "code", "l1_bank_tag": 1, "protection_flags": {"protect_sha_digests": True}, "default_l2_scales": {"corpus": 0.4, "formal-verification": 0.5, "weft-eido": 0.0}},
                {"zone": "prose", "l1_bank_tag": 0, "protection_flags": {"enforce_prose_guard": True}, "default_l2_scales": {"corpus": 1.0, "formal-verification": 0.0, "weft-eido": 0.0}},
            ],
        }
        mde_raw = json.dumps(mde_body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        mde_manifest = dict(mde_body, manifest_id="sha256:" + hashlib.sha256(mde_raw).hexdigest())
        verified_id, tags = verify_zone_manifest_dict(mde_manifest)
        self.assertEqual(verified_id, mde_manifest["manifest_id"])
        self.assertEqual(tags["formal_proof"], 3)

        bad_zone_body = json.loads(json.dumps(mde_body))
        bad_zone_body["zones"][0]["zone"] = "bogus_zone"
        bad_zone_body["precedence_order"][0] = "bogus_zone"
        bad_zone = dict(
            bad_zone_body,
            manifest_id="sha256:" + hashlib.sha256(json.dumps(bad_zone_body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest(),
        )
        with self.assertRaises(ZoneManifestDriftError):
            verify_zone_manifest_dict(bad_zone)

        empty_prec_body = json.loads(json.dumps(mde_body))
        empty_prec_body["precedence_order"] = []
        empty_prec = dict(
            empty_prec_body,
            manifest_id="sha256:" + hashlib.sha256(json.dumps(empty_prec_body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest(),
        )
        with self.assertRaises(ZoneManifestDriftError):
            verify_zone_manifest_dict(empty_prec)

    def test_wd_sandbox_01_and_wd_x06_wd_x07_blueprint_hardening(self) -> None:
        sandbox = REPO_ROOT / "blueprints" / "sandbox" / "warp-sandbox-exec.sh"
        recovery = REPO_ROOT / "blueprints" / "recovery" / "warp-recovery.sh"
        harden = REPO_ROOT / "blueprints" / "mkosi" / "harden-image-modes.sh"
        svc = REPO_ROOT / "blueprints" / "systemd" / "warp-modeld.service"

        # WD-SANDBOX-01: root worktree '/' and missing seccomp BPF fail closed!
        root_res = subprocess.run(
            ["bash", str(sandbox), "/", "echo", "nope"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(root_res.returncode, 126)
        self.assertIn("ERR_SANDBOX_WORKTREE", root_res.stderr)

        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            # Fake bwrap in PATH must be ignored (pinned /usr/bin/bwrap only).
            fake_bin = tmp / "fakebin"
            fake_bin.mkdir()
            fake_bwrap = fake_bin / "bwrap"
            fake_bwrap.write_text("#!/usr/bin/env bash\necho HIJACKED\nexit 0\n", encoding="utf-8")
            os.chmod(fake_bwrap, 0o755)
            wt = tmp / "wt"
            wt.mkdir()
            env_sec = dict(os.environ)
            env_sec["PATH"] = f"{fake_bin}:{os.environ.get('PATH', '/usr/bin:/bin')}"
            env_sec["WARP_REQUIRE_SECCOMP_BPF"] = "1"
            env_sec.pop("WARP_SECCOMP_BPF_PATH", None)
            sec_res = subprocess.run(
                ["bash", str(sandbox), str(wt), "echo", "nope"],
                capture_output=True,
                text=True,
                env=env_sec,
                check=False,
            )
            self.assertEqual(sec_res.returncode, 126)
            self.assertNotIn("HIJACKED", sec_res.stdout)
            # Either ERR_SANDBOX_SECCOMP (if host has /usr/bin/bwrap) or ERR_SANDBOX_UNAVAILABLE (if absent).
            self.assertTrue(
                ("ERR_SANDBOX_SECCOMP" in sec_res.stderr) or ("ERR_SANDBOX_UNAVAILABLE" in sec_res.stderr),
                msg=sec_res.stderr,
            )

            # WD-X06: warp-recovery.sh stage-rollback must fail closed without WARP_BTRFS_TOPLEVEL_MOUNT!
            snap_root = tmp / "snaps"
            efi_dir = tmp / "efi"
            snap_root.mkdir()
            efi_dir.mkdir()
            ckpt_id = "20261121T000000Z-test"
            (snap_root / ckpt_id).mkdir()
            uki_file = efi_dir / f"warp-rollback-{ckpt_id}.efi"
            uki_file.write_bytes(b"FAKE-UKI-BYTES")
            uki_sha = hashlib.sha256(b"FAKE-UKI-BYTES").hexdigest()
            (snap_root / f"{ckpt_id}.uki.sha256").write_text(f"{uki_sha}  {uki_file}\n", encoding="utf-8")

            # Provide stub btrfs & bootctl in PATH to prove ERR_RECOVERY_SUBVOL blocks before bootctl!
            stub_bin = tmp / "stubbin"
            stub_bin.mkdir()
            for tool in ("btrfs", "bootctl"):
                p = stub_bin / tool
                p.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
                os.chmod(p, 0o755)
            rec_env = dict(os.environ)
            rec_env["PATH"] = f"{stub_bin}:{os.environ.get('PATH', '/usr/bin:/bin')}"
            rec_env["WARP_SNAPSHOT_ROOT"] = str(snap_root)
            rec_env["WARP_EFI_LINUX_DIR"] = str(efi_dir)
            rec_env.pop("WARP_BTRFS_TOPLEVEL_MOUNT", None)
            rec_res = subprocess.run(
                ["bash", str(recovery), "stage-rollback", ckpt_id],
                capture_output=True,
                text=True,
                env=rec_env,
                check=False,
            )
            self.assertEqual(rec_res.returncode, 126)
            self.assertIn("ERR_RECOVERY_SUBVOL", rec_res.stderr)

        # WD-X07a, WD-X07b, & PRA-BYPASS-4 static invariants.
        harden_txt = harden.read_text(encoding="utf-8")
        self.assertIn("/etc/warp \\", harden_txt.split("for tree in", 1)[0])
        svc_txt = svc.read_text(encoding="utf-8")
        self.assertIn("SupplementaryGroups=warp-modeld", svc_txt)
        sandbox_txt = sandbox.read_text(encoding="utf-8")
        self.assertIn("/var/lib/warp/snapshots", sandbox_txt)

    def test_pra_bypass_4_and_5_empty_nontemplate_tokenizer_and_unexpected_unerased_slot(self) -> None:
        # PRA-BYPASS-4b: tokenizer_hashes containing ONLY chat_template.jinja must fail closed.
        template_only = {
            "schema": "weft-binding/v0.1",
            "layout_sha256": "1" * 64,
            "checkpoint_fingerprint": "2" * 64,
            "config_hashes": {"config.json": "3" * 64},
            "tokenizer_hashes": {"chat_template.jinja": "4" * 64},
        }
        with self.assertRaises(CheckpointMismatchError):
            CheckpointFingerprint.from_weft_binding(template_only, model_id="Qwen3-8B")

        # PRA-BYPASS-5: post-erase /slots returning an unexpected unerased slot_id=1 must fail closed!
        class SurpriseSlotClient:
            def __init__(self) -> None:
                self._calls = 0

            def list_lora_adapters(self) -> list[Any]:
                return [SimpleNamespace(id=0, path="/nonexistent/a.gguf", scale=0.0)]

            def set_lora_adapters(self, adapters: list[dict[str, Any]]) -> dict[str, Any]:
                return {"status": "ok"}

            def list_slots(self) -> list[Any]:
                self._calls += 1
                s0 = SimpleNamespace(
                    id=0,
                    is_processing=False,
                    n_decoded=0,
                    active_lora_ids=(),
                    recurrent_state_tainted=False,
                    n_prompt_tokens_cache=0,
                    ssm_state_tainted=False,
                    lattice_state_tainted=False,
                    lattice_layers_tainted=0,
                    state_banks={},
                )
                if self._calls == 1:
                    return [s0]
                s1 = SimpleNamespace(
                    id=1,
                    is_processing=False,
                    n_decoded=0,
                    active_lora_ids=(),
                    recurrent_state_tainted=False,
                    n_prompt_tokens_cache=0,
                    ssm_state_tainted=False,
                    lattice_state_tainted=False,
                    lattice_layers_tainted=0,
                    state_banks={},
                )
                return [s0, s1]

            def erase_slot(self, slot_id: int, *, banks: Any = None) -> dict[str, Any]:
                return {"id_slot": slot_id, "erased": True, "banks_flushed": ["kv_cache"]}

        with tempfile.TemporaryDirectory() as td:
            signer = HmacSha256Signer(b"surprise-slot-key-32-bytes-00001", key_id="k1")
            modeld = WarpModeld(
                pinned_checkpoint=make_checkpoint(),
                pinned_lineage=make_lineage(),
                live_runtime_flags=make_runtime_flags(),
                single_bounds=make_single_bounds(),
                joint_bounds=make_joint_bounds(),
                canary_suite=CanarySuite.from_verifier_file(CANARY_SUITE_PATH),
                llama_client=SurpriseSlotClient(),  # type: ignore[arg-type]
                ledger=SignedLedger(Path(td) / "ledger.jsonl", signer),
            )
            with self.assertRaises(StateFlushError):
                modeld.rollback(reason="surprise_slot_test")
            self.assertTrue(modeld.status()["state_quarantined"])


if __name__ == "__main__":
    unittest.main()
