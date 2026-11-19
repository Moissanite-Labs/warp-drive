"""Stage 2 tests: exact integer division-free FixedRadixCertificate verifier."""

from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from warp_modeld.certificate import (
    FixedRadixCertificate,
    stack_composition_digest,
    verify_division_free,
    verify_stack_division_free,
)
from warp_modeld.errors import CertificateError

from tests.helpers import (
    fake_sha,
    make_adapter_bundle_dict,
    make_checkpoint,
    make_joint_bounds,
    make_modeld,
    make_single_bounds,
)
from tests.mock_llama_server import MockLlamaServer


class TestStage2Certificate(unittest.TestCase):
    def test_valid_certificate_passes_under_1ms(self) -> None:
        radix = 1 << 24
        ckpt = make_checkpoint()
        asha = fake_sha("adapter-ok")
        cert = FixedRadixCertificate.create(
            adapter_id="mde:corpus",
            adapter_sha256=asha,
            base_weights_sha256=ckpt.weights_sha256,
            radix_scale=radix,
            frobenius_sq_scaled=radix * 2,
            spectral_norm_sq_scaled=radix,
            leakage_energy_scaled=radix // 200,
            max_safety_dot_sq_scaled=radix // 2000,
        )
        res = verify_division_free(
            cert,
            make_single_bounds(),
            expected_adapter_id="mde:corpus",
            expected_adapter_sha256=asha,
            expected_base_weights_sha256=ckpt.weights_sha256,
        )
        # Measure median across 9 warm calls so OS scheduling jitter never flakes; must stay well under 1ms.
        timings = [
            verify_division_free(
                cert,
                make_single_bounds(),
                expected_adapter_id="mde:corpus",
                expected_adapter_sha256=asha,
                expected_base_weights_sha256=ckpt.weights_sha256,
            ).elapsed_ns
            for _ in range(9)
        ]
        self.assertTrue(res.passed)
        self.assertLess(sorted(timings)[len(timings) // 2], 1_000_000)

    def test_exact_boundary_passes_and_plus_one_fails_without_rounding_drift(self) -> None:
        # Exact rational bound: max_leakage_energy = 1/100; choose radix_scale = 10**18 so float64 loses precision!
        radix = 10**18
        ckpt = make_checkpoint()
        asha = fake_sha("adapter-boundary")
        exact_limit = radix // 100  # 10**16

        cert_exact = FixedRadixCertificate.create(
            adapter_id="mde:corpus",
            adapter_sha256=asha,
            base_weights_sha256=ckpt.weights_sha256,
            radix_scale=radix,
            frobenius_sq_scaled=radix,
            spectral_norm_sq_scaled=radix // 2,
            leakage_energy_scaled=exact_limit,
            max_safety_dot_sq_scaled=0,
        )
        self.assertTrue(verify_division_free(cert_exact, make_single_bounds()).passed)

        # Adding 1 ULP at 10^-18 scale would be invisible to IEEE-754 float64,
        # but exact integer cross-multiplication catches it cleanly.
        cert_over = FixedRadixCertificate.create(
            adapter_id="mde:corpus",
            adapter_sha256=asha,
            base_weights_sha256=ckpt.weights_sha256,
            radix_scale=radix,
            frobenius_sq_scaled=radix,
            spectral_norm_sq_scaled=radix // 2,
            leakage_energy_scaled=exact_limit + 1,
            max_safety_dot_sq_scaled=0,
        )
        with self.assertRaises(CertificateError):
            verify_division_free(cert_over, make_single_bounds())

    def test_rejects_forged_digest_and_transplanted_certificate(self) -> None:
        raw = make_adapter_bundle_dict()
        cert_dict = dict(raw["certificate"])
        # Mutate leakage without recomputing cert_sha256 (forged payload).
        cert_dict["leakage_energy_scaled"] = 0
        forged = FixedRadixCertificate.from_dict(cert_dict)
        with self.assertRaises(CertificateError):
            verify_division_free(forged, make_single_bounds())

        # Valid certificate for adapter A transplanted onto adapter B.
        valid_a = FixedRadixCertificate.from_dict(raw["certificate"])
        with self.assertRaises(CertificateError):
            verify_division_free(
                valid_a,
                make_single_bounds(),
                expected_adapter_id="mde:weft-eido",
                expected_adapter_sha256=fake_sha("different-adapter"),
                expected_base_weights_sha256=make_checkpoint().weights_sha256,
            )

    def test_rejects_float_bool_negative_and_inconsistent_norms(self) -> None:
        base = make_adapter_bundle_dict()["certificate"]
        for bad_patch in (
            {"radix_scale": 0},
            {"radix_scale": -1},
            {"frobenius_sq_scaled": -5},
            {"frobenius_sq_scaled": 1.5},
            {"leakage_energy_scaled": True},
        ):
            mutated = dict(base)
            mutated.update(bad_patch)
            with self.subTest(bad_patch=bad_patch):
                with self.assertRaises(CertificateError):
                    FixedRadixCertificate.from_dict(mutated)

        # spectral_norm_sq > frobenius_sq is mathematically impossible for any real matrix.
        impossible = FixedRadixCertificate.create(
            adapter_id="mde:corpus",
            adapter_sha256=fake_sha("imp"),
            base_weights_sha256=make_checkpoint().weights_sha256,
            radix_scale=1000,
            frobenius_sq_scaled=500,
            spectral_norm_sq_scaled=600,
            leakage_energy_scaled=0,
            max_safety_dot_sq_scaled=0,
        )
        with self.assertRaises(CertificateError):
            verify_division_free(impossible, make_single_bounds())

    def test_multi_adapter_stack_catches_composed_bound_smuggling(self) -> None:
        ckpt = make_checkpoint()
        radix = 10000
        # Each individual adapter has frobenius_sq = 4.5 (<= single bound 5.0),
        # but stacking 3 adapters at scale 1.0 gives Cauchy-Schwarz upper bound 3 * (4.5 + 4.5 + 4.5) = 40.5 > 20.0!
        items = []
        for idx, name in enumerate(("mde:corpus", "mde:weft-eido", "mde:formal-verification")):
            asha = fake_sha(f"heavy-{idx}")
            cert = FixedRadixCertificate.create(
                adapter_id=name,
                adapter_sha256=asha,
                base_weights_sha256=ckpt.weights_sha256,
                radix_scale=radix,
                frobenius_sq_scaled=45000,
                spectral_norm_sq_scaled=10000,
                leakage_energy_scaled=10,
                max_safety_dot_sq_scaled=1,
            )
            items.append((cert, name, asha, 1000, 1000))

        with self.assertRaises(CertificateError):
            verify_stack_division_free(
                items,
                make_single_bounds(),
                make_joint_bounds(),
                expected_base_weights_sha256=ckpt.weights_sha256,
            )

    def test_multi_adapter_stack_with_composed_certificate_passes_under_1ms(self) -> None:
        ckpt = make_checkpoint()
        radix = 1 << 24
        items = []
        keys = []
        for idx, name in enumerate(("mde:corpus", "mde:weft-eido", "mde:formal-verification")):
            asha = fake_sha(f"clean-{idx}")
            cert = FixedRadixCertificate.create(
                adapter_id=name,
                adapter_sha256=asha,
                base_weights_sha256=ckpt.weights_sha256,
                radix_scale=radix,
                frobenius_sq_scaled=radix,  # 1.0 each -> Cauchy upper = 3 * 3.0 = 9.0 <= 20.0
                spectral_norm_sq_scaled=radix // 4,
                leakage_energy_scaled=radix // 1000,
                max_safety_dot_sq_scaled=radix // 10000,
            )
            items.append((cert, name, asha, 1000, 1000))
            keys.append((name, asha, 1000, 1000))

        composed = FixedRadixCertificate.create(
            adapter_id="composed_stack",
            adapter_sha256=stack_composition_digest(keys),
            base_weights_sha256=ckpt.weights_sha256,
            radix_scale=radix,
            frobenius_sq_scaled=radix * 3,
            spectral_norm_sq_scaled=radix,
            leakage_energy_scaled=radix // 400,
            max_safety_dot_sq_scaled=radix // 4000,
        )
        res = verify_stack_division_free(
            items,
            make_single_bounds(),
            make_joint_bounds(),
            expected_base_weights_sha256=ckpt.weights_sha256,
            composed_certificate=composed,
        )
        timings = [
            verify_stack_division_free(
                items,
                make_single_bounds(),
                make_joint_bounds(),
                expected_base_weights_sha256=ckpt.weights_sha256,
                composed_certificate=composed,
            ).elapsed_ns
            for _ in range(9)
        ]
        self.assertTrue(res.composed_bound_checked)
        self.assertTrue(res.composed_cert_verified)
        self.assertLess(sorted(timings)[len(timings) // 2], 1_000_000)

    def test_stage2_forged_cert_never_touches_llama_server(self) -> None:
        mock = MockLlamaServer()
        url = mock.start()
        try:
            with tempfile.TemporaryDirectory() as td:
                modeld = make_modeld(url, Path(td))
                forged_bundle = make_adapter_bundle_dict()
                forged_bundle["certificate"]["leakage_energy_scaled"] = 0  # invalidates cert_sha256

                with self.assertRaises(CertificateError):
                    modeld.mount_stack([forged_bundle])

                self.assertEqual(len(mock.state.request_log), 0)
                self.assertEqual(modeld.ledger.count, 1)
        finally:
            mock.stop()

    def test_single_adapter_inflated_scale_bypass_fails_closed_before_llama_server(self) -> None:
        mock = MockLlamaServer()
        url = mock.start()
        try:
            with tempfile.TemporaryDirectory() as td:
                modeld = make_modeld(url, Path(td))
                radix = 10000
                # Tiny unscaled adapter (frobenius_sq = 0.01, well below single bound 5.0),
                # but scale = 10000/1 gives effective squared Frobenius norm 1,000,000 >> 5.0!
                inflated = make_adapter_bundle_dict(
                    scale_num=10000,
                    scale_den=1,
                    radix_scale=radix,
                    frobenius_sq_scaled=100,
                    spectral_norm_sq_scaled=50,
                    leakage_energy_scaled=1,
                    max_safety_dot_sq_scaled=1,
                )
                with self.assertRaises(CertificateError):
                    modeld.mount_stack([inflated])

                # Must fail closed in Stage 2 with ZERO HTTP calls to llama-server.
                self.assertEqual(len(mock.state.request_log), 0)
                self.assertEqual(modeld.ledger.count, 1)
        finally:
            mock.stop()

    def test_scaled_exact_integer_boundary_single_and_multi(self) -> None:
        ckpt = make_checkpoint()
        radix = 10000
        asha = fake_sha("scaled-boundary")
        cert = FixedRadixCertificate.create(
            adapter_id="mde:corpus",
            adapter_sha256=asha,
            base_weights_sha256=ckpt.weights_sha256,
            radix_scale=radix,
            frobenius_sq_scaled=radix,  # 1.0
            spectral_norm_sq_scaled=radix // 4,  # 0.25
            leakage_energy_scaled=radix // 1000,  # 0.001
            max_safety_dot_sq_scaled=radix // 10000,  # 0.0001
        )
        # scale = 2/1 -> scaled frobenius_sq = 4.0 <= 5.0, spectral = 1.0 <= 2.0, leakage = 0.004 <= 0.01 -> PASS.
        res_ok = verify_division_free(cert, make_single_bounds(), scale_num=2, scale_den=1)
        self.assertTrue(res_ok.passed)

        # scale = 3/1 -> scaled frobenius_sq = 9.0 > 5.0 -> FAIL.
        with self.assertRaises(CertificateError):
            verify_division_free(cert, make_single_bounds(), scale_num=3, scale_den=1)

        # Multi-adapter stack where one adapter's scaled norm violates single_bounds -> FAIL.
        asha2 = fake_sha("scaled-peer")
        cert2 = FixedRadixCertificate.create(
            adapter_id="mde:weft-eido",
            adapter_sha256=asha2,
            base_weights_sha256=ckpt.weights_sha256,
            radix_scale=radix,
            frobenius_sq_scaled=radix // 10,
            spectral_norm_sq_scaled=radix // 20,
            leakage_energy_scaled=1,
            max_safety_dot_sq_scaled=1,
        )
        with self.assertRaises(CertificateError):
            verify_stack_division_free(
                [
                    (cert, "mde:corpus", asha, 3, 1),
                    (cert2, "mde:weft-eido", asha2, 1, 1),
                ],
                make_single_bounds(),
                make_joint_bounds(),
                expected_base_weights_sha256=ckpt.weights_sha256,
            )


if __name__ == "__main__":
    unittest.main()
