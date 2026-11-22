"""Tests for the Siliquant to Stage 2 fixed-radix certificate bridge."""

from __future__ import annotations

import copy
import os
import tempfile
import textwrap
import unittest
from pathlib import Path

from warp_modeld.certificate import verify_division_free
from warp_modeld.errors import CertificateError
from warp_modeld.siliquant_bridge import (
    generate_fixed_radix_certificate,
    ingest_weft_certificate,
    load_siliquant_checker,
    verify_codebook_pick,
    verify_siliquant_bridge,
)

from tests.helpers import fake_sha, make_single_bounds

ADAPTER = "mde:corpus"
ADAPTER_SHA = fake_sha("siliquant-adapter")
BASE_SHA = fake_sha("siliquant-base")
RADIX = 1 << 32
EPOCH = 3
FACTOR = fake_sha("factor-digest")
QUANT = "siliquant_4_5"


def _valid_payload() -> dict:
    return generate_fixed_radix_certificate(
        ADAPTER,
        ADAPTER_SHA,
        BASE_SHA,
        frobenius_sq=RADIX,            # 1.0
        spectral_norm_sq=RADIX // 4,   # 0.25
        leakage_energy=RADIX // 1000,  # 0.001
        max_safety_dot_sq=RADIX // 10000,
        radix_scale_exp2=32,
        projector_epoch=EPOCH,
        factor_digest=FACTOR,
        quant_dtype=QUANT,
    )


def _verify(payload: dict, **overrides):
    kwargs = dict(
        expected_adapter_id=ADAPTER,
        expected_adapter_sha256=ADAPTER_SHA,
        expected_base_weights_sha256=BASE_SHA,
    )
    kwargs.update(overrides)
    return verify_siliquant_bridge(payload, make_single_bounds(), **kwargs)


class TestGenerateAndIngest(unittest.TestCase):
    def test_valid_payload_passes_stage2(self) -> None:
        self.assertTrue(_verify(_valid_payload()).passed)

    def test_generated_payload_matches_from_weft_dict_fields(self) -> None:
        payload = _valid_payload()
        cert = ingest_weft_certificate(payload)
        self.assertEqual(cert.radix_scale, RADIX)
        self.assertEqual(cert.frobenius_sq_scaled, RADIX)
        self.assertEqual(cert.spectral_norm_sq_scaled, RADIX // 4)
        self.assertEqual(cert.adapter_id, ADAPTER)

    def test_payload_is_deterministic(self) -> None:
        self.assertEqual(_valid_payload(), _valid_payload())

    def test_spectral_above_frobenius_rejected_at_generation(self) -> None:
        with self.assertRaises(CertificateError):
            generate_fixed_radix_certificate(
                ADAPTER, ADAPTER_SHA, BASE_SHA,
                frobenius_sq=100, spectral_norm_sq=101,
                leakage_energy=0, max_safety_dot_sq=0,
                projector_epoch=EPOCH, factor_digest=FACTOR, quant_dtype=QUANT,
            )

    def test_float_inputs_rejected(self) -> None:
        for field in ("frobenius_sq", "spectral_norm_sq", "leakage_energy", "max_safety_dot_sq"):
            kwargs = dict(
                frobenius_sq=RADIX, spectral_norm_sq=RADIX // 4,
                leakage_energy=RADIX // 1000, max_safety_dot_sq=RADIX // 10000,
            )
            kwargs[field] = 1.0
            with self.subTest(field=field):
                with self.assertRaises(CertificateError):
                    generate_fixed_radix_certificate(
                        ADAPTER, ADAPTER_SHA, BASE_SHA,
                        projector_epoch=EPOCH, factor_digest=FACTOR, quant_dtype=QUANT,
                        **kwargs,
                    )

    def test_radix_exp2_out_of_range_rejected(self) -> None:
        for exp2 in (7, 49, 0, -1):
            with self.subTest(exp2=exp2):
                with self.assertRaises(CertificateError):
                    generate_fixed_radix_certificate(
                        ADAPTER, ADAPTER_SHA, BASE_SHA,
                        frobenius_sq=1, spectral_norm_sq=1,
                        leakage_energy=0, max_safety_dot_sq=0,
                        radix_scale_exp2=exp2,
                        projector_epoch=EPOCH, factor_digest=FACTOR, quant_dtype=QUANT,
                    )


class TestTamperedAndInflated(unittest.TestCase):
    def test_edited_body_field_without_resign_is_rejected(self) -> None:
        payload = _valid_payload()
        payload["leakage_energy_scaled"] = 0
        with self.assertRaises(CertificateError):
            ingest_weft_certificate(payload)

    def test_edited_weft_sha_is_rejected(self) -> None:
        payload = _valid_payload()
        payload["weft_sha256"] = fake_sha("forged-weft")
        with self.assertRaises(CertificateError):
            ingest_weft_certificate(payload)

    def test_inflated_and_resigned_is_rejected_by_bounds(self) -> None:
        # An attacker recomputes weft_sha256 after inflating frobenius past the 5.0 bound.
        inflated = generate_fixed_radix_certificate(
            ADAPTER, ADAPTER_SHA, BASE_SHA,
            frobenius_sq=6 * RADIX, spectral_norm_sq=RADIX // 4,
            leakage_energy=RADIX // 1000, max_safety_dot_sq=RADIX // 10000,
            projector_epoch=EPOCH, factor_digest=FACTOR, quant_dtype=QUANT,
        )
        self.assertTrue(ingest_weft_certificate(inflated).frobenius_sq_scaled == 6 * RADIX)
        with self.assertRaises(CertificateError):
            _verify(inflated)

    def test_scale_inflation_is_rejected_by_bounds(self) -> None:
        with self.assertRaises(CertificateError):
            _verify(_valid_payload(), scale_num=3, scale_den=1)

    def test_transplanted_adapter_is_rejected(self) -> None:
        with self.assertRaises(CertificateError):
            _verify(_valid_payload(), expected_adapter_sha256=fake_sha("other-adapter"))

    def test_wrong_base_weights_is_rejected(self) -> None:
        with self.assertRaises(CertificateError):
            _verify(_valid_payload(), expected_base_weights_sha256=fake_sha("other-base"))

    def test_missing_identity_field_is_rejected(self) -> None:
        payload = _valid_payload()
        del payload["adapter_sha256"]
        with self.assertRaises(CertificateError):
            ingest_weft_certificate(payload)

    def test_bool_in_integer_field_is_rejected(self) -> None:
        payload = _valid_payload()
        payload["frobenius_sq_scaled"] = True
        payload["weft_sha256"] = payload["weft_sha256"]
        with self.assertRaises(CertificateError):
            ingest_weft_certificate(payload)


FAKE_CHECKER_OK = textwrap.dedent(
    '''
    def identities():
        return True

    def pi_bounds_hold():
        return True

    def check(cert):
        return []
    '''
)

FAKE_CHECKER_REJECT = FAKE_CHECKER_OK.replace("return []", 'return ["the pick is not certainly ahead"]')


class TestCodebookReceipt(unittest.TestCase):
    def _write_checker(self, td: str, body: str) -> Path:
        path = Path(td) / "check_certificate.py"
        path.write_text(body)
        return path

    def _receipt(self) -> dict:
        return {"certificate": {"budget": [1, 1], "candidates": [], "pick": 0}}

    def test_accepted_receipt_passes_bridge(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            checker = self._write_checker(td, FAKE_CHECKER_OK)
            self.assertEqual(verify_codebook_pick(self._receipt(), checker), 0)
            self.assertTrue(
                _verify(_valid_payload(), codebook_receipt=self._receipt(), checker_path=checker).passed
            )

    def test_rejected_receipt_fails_bridge(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            checker = self._write_checker(td, FAKE_CHECKER_REJECT)
            with self.assertRaises(CertificateError):
                _verify(_valid_payload(), codebook_receipt=self._receipt(), checker_path=checker)

    def test_receipt_without_checker_path_is_rejected(self) -> None:
        with self.assertRaises(CertificateError):
            _verify(_valid_payload(), codebook_receipt=self._receipt())

    def test_missing_checker_file_fails_closed(self) -> None:
        with self.assertRaises(CertificateError):
            verify_codebook_pick(self._receipt(), "/nonexistent/check_certificate.py")

    def test_checker_missing_callable_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            checker = self._write_checker(td, "def check(cert):\n    return []\n")
            with self.assertRaises(CertificateError):
                load_siliquant_checker(checker)

    def test_malformed_receipt_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            checker = self._write_checker(td, FAKE_CHECKER_OK)
            with self.assertRaises(CertificateError):
                verify_codebook_pick({"pick": 0}, checker)


@unittest.skipUnless(os.environ.get("SILIQUANT_CHECKER_PATH"), "set SILIQUANT_CHECKER_PATH to run")
class TestRealSiliquantChecker(unittest.TestCase):
    def test_real_checker_self_checks_hold(self) -> None:
        checker = load_siliquant_checker(os.environ["SILIQUANT_CHECKER_PATH"])
        self.assertTrue(checker.identities())
        self.assertTrue(checker.pi_bounds_hold())


if __name__ == "__main__":
    unittest.main()
