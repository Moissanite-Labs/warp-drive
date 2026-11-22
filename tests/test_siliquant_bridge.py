"""Tests for the verifier-owned SiliQuant to Stage 2 fixed-radix certificate bridge."""

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
    CodebookPickVerification,
    SiliquantExpectations,
    checker_sha256,
    codebook_receipt_sha256,
    generate_fixed_radix_certificate,
    ingest_weft_certificate,
    load_siliquant_checker,
    verify_codebook_pick,
    verify_siliquant_bridge,
    weft_body_sha256,
)

from tests.helpers import fake_sha, make_single_bounds

ADAPTER = "mde:corpus"
ADAPTER_SHA = fake_sha("siliquant-adapter")
BASE_SHA = fake_sha("siliquant-base")
RADIX = 1 << 32
EPOCH = 3
FACTOR = fake_sha("factor-digest")
QUANT = "siliquant_4_5"
ARM = "E8:p2"
BUDGET = (9, 2)


def _valid_payload(quant_dtype: str = QUANT) -> dict:
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
        quant_dtype=quant_dtype,
    )


def _stage2(payload: dict, **overrides) -> object:
    kwargs = dict(
        expected_adapter_id=ADAPTER,
        expected_adapter_sha256=ADAPTER_SHA,
        expected_base_weights_sha256=BASE_SHA,
    )
    kwargs.update(overrides)
    return verify_division_free(ingest_weft_certificate(payload), make_single_bounds(), **kwargs)


def _receipt() -> dict:
    candidate = {
        "arm": ARM,
        "size": 8,
        "codewords": "256",
        "terms": {
            "count": "8",
            "groups": "1",
            "sum_sq": "8",
            "top_cube": "1",
            "top_ball": "1",
            "top_cross": "1",
        },
    }
    return {"certificate": {"budget": list(BUDGET), "candidates": [candidate], "pick": 0}}


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


def _write_checker(td: str, body: str = FAKE_CHECKER_OK) -> Path:
    path = Path(td) / "check_certificate.py"
    path.write_text(body)
    return path


def _expect(
    payload: dict,
    receipt: dict,
    checker_path: Path,
    **overrides,
) -> SiliquantExpectations:
    cert = receipt["certificate"]
    values = dict(
        quant_dtype=payload["quant_dtype"],
        projector_epoch=payload["projector_epoch"],
        factor_digest=payload["factor_digest"],
        weft_sha256=payload["weft_sha256"],
        arm=cert["candidates"][cert["pick"]]["arm"],
        budget=tuple(cert["budget"]),
        receipt_sha256=codebook_receipt_sha256(receipt),
        checker_sha256=checker_sha256(checker_path),
    )
    values.update(overrides)
    return SiliquantExpectations(**values)


def _bridge(
    payload: dict,
    receipt: dict,
    checker_path: Path,
    **expectation_overrides,
):
    return verify_siliquant_bridge(
        payload,
        make_single_bounds(),
        expected=_expect(payload, receipt, checker_path, **expectation_overrides),
        expected_adapter_id=ADAPTER,
        expected_adapter_sha256=ADAPTER_SHA,
        expected_base_weights_sha256=BASE_SHA,
        codebook_receipt=receipt,
        checker_path=checker_path,
    )


class TestGenerateAndIngest(unittest.TestCase):
    def test_valid_payload_passes_stage2(self) -> None:
        self.assertTrue(_stage2(_valid_payload()).passed)

    def test_generated_payload_matches_from_weft_dict_fields(self) -> None:
        payload = _valid_payload()
        cert = ingest_weft_certificate(payload)
        self.assertEqual(cert.radix_scale, RADIX)
        self.assertEqual(cert.frobenius_sq_scaled, RADIX)
        self.assertEqual(cert.spectral_norm_sq_scaled, RADIX // 4)
        self.assertEqual(cert.adapter_id, ADAPTER)

    def test_public_weft_digest_matches_generated_digest(self) -> None:
        payload = _valid_payload()
        body = {key: payload[key] for key in (
            "radix_scale_exp2", "frobenius_sq_scaled", "spectral_norm_sq_scaled",
            "leakage_energy_scaled", "max_safety_dot_sq_scaled", "projector_epoch",
            "factor_digest", "quant_dtype",
        )}
        self.assertEqual(weft_body_sha256(body), payload["weft_sha256"])

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

    def test_unsupported_quantization_rejected_at_generation(self) -> None:
        with self.assertRaises(CertificateError):
            _valid_payload("bf16")

    def test_extra_payload_field_is_rejected(self) -> None:
        payload = _valid_payload()
        payload["unbound_evidence"] = {}
        with self.assertRaises(CertificateError):
            ingest_weft_certificate(payload)


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

    def test_wrong_expected_weft_sha_is_rejected(self) -> None:
        with self.assertRaises(CertificateError):
            ingest_weft_certificate(_valid_payload(), expected_weft_sha256=fake_sha("other-weft"))

    def test_inflated_and_resigned_is_rejected_by_bounds(self) -> None:
        # An attacker recomputes weft_sha256 after inflating frobenius past the 5.0 bound.
        inflated = generate_fixed_radix_certificate(
            ADAPTER, ADAPTER_SHA, BASE_SHA,
            frobenius_sq=6 * RADIX, spectral_norm_sq=RADIX // 4,
            leakage_energy=RADIX // 1000, max_safety_dot_sq=RADIX // 10000,
            projector_epoch=EPOCH, factor_digest=FACTOR, quant_dtype=QUANT,
        )
        self.assertEqual(ingest_weft_certificate(inflated).frobenius_sq_scaled, 6 * RADIX)
        with self.assertRaises(CertificateError):
            _stage2(inflated)

    def test_scale_inflation_is_rejected_by_bounds(self) -> None:
        with self.assertRaises(CertificateError):
            _stage2(_valid_payload(), scale_num=3, scale_den=1)

    def test_transplanted_adapter_is_rejected(self) -> None:
        with self.assertRaises(CertificateError):
            _stage2(_valid_payload(), expected_adapter_sha256=fake_sha("other-adapter"))

    def test_wrong_base_weights_is_rejected(self) -> None:
        with self.assertRaises(CertificateError):
            _stage2(_valid_payload(), expected_base_weights_sha256=fake_sha("other-base"))

    def test_missing_identity_field_is_rejected(self) -> None:
        payload = _valid_payload()
        del payload["adapter_sha256"]
        with self.assertRaises(CertificateError):
            ingest_weft_certificate(payload)

    def test_bool_in_integer_field_is_rejected(self) -> None:
        payload = _valid_payload()
        payload["frobenius_sq_scaled"] = True
        with self.assertRaises(CertificateError):
            ingest_weft_certificate(payload)


class TestCodebookReceipt(unittest.TestCase):
    def test_accepted_receipt_returns_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            checker = _write_checker(td)
            receipt = _receipt()
            result = verify_codebook_pick(
                receipt,
                checker,
                expected_checker_sha256=checker_sha256(checker),
                expected_receipt_sha256=codebook_receipt_sha256(receipt),
                expected_arm=ARM,
                expected_budget=BUDGET,
            )
            self.assertIsInstance(result, CodebookPickVerification)
            self.assertEqual(result.pick, 0)
            self.assertEqual(result.arm, ARM)
            self.assertEqual(result.budget, BUDGET)
            self.assertEqual(result.checker_sha256, checker_sha256(checker))
            self.assertEqual(result.receipt_sha256, codebook_receipt_sha256(receipt))

    def test_rejected_receipt_fails_bridge(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            checker = _write_checker(td, FAKE_CHECKER_REJECT)
            with self.assertRaises(CertificateError):
                _bridge(_valid_payload(), _receipt(), checker)

    def test_receipt_without_checker_path_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            checker = _write_checker(td)
            payload = _valid_payload()
            with self.assertRaises(CertificateError):
                verify_siliquant_bridge(
                    payload,
                    make_single_bounds(),
                    expected=_expect(payload, _receipt(), checker),
                    expected_adapter_id=ADAPTER,
                    expected_adapter_sha256=ADAPTER_SHA,
                    expected_base_weights_sha256=BASE_SHA,
                    codebook_receipt=_receipt(),
                    checker_path=None,
                )

    def test_receipt_without_evidence_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            checker = _write_checker(td)
            payload = _valid_payload()
            with self.assertRaises(CertificateError):
                verify_siliquant_bridge(
                    payload,
                    make_single_bounds(),
                    expected=_expect(payload, _receipt(), checker),
                    expected_adapter_id=ADAPTER,
                    expected_adapter_sha256=ADAPTER_SHA,
                    expected_base_weights_sha256=BASE_SHA,
                    codebook_receipt=None,
                    checker_path=checker,
                )

    def test_missing_checker_file_fails_closed(self) -> None:
        with self.assertRaises(CertificateError):
            verify_codebook_pick(
                _receipt(),
                "/nonexistent/check_certificate.py",
                expected_checker_sha256=fake_sha("checker"),
                expected_receipt_sha256=codebook_receipt_sha256(_receipt()),
            )

    def test_checker_missing_callable_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            checker = _write_checker(td, "def check(cert):\n    return []\n")
            with self.assertRaises(CertificateError):
                load_siliquant_checker(checker, expected_checker_sha256=checker_sha256(checker))

    def test_malformed_receipt_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            checker = _write_checker(td)
            with self.assertRaises(CertificateError):
                verify_codebook_pick(
                    {"pick": 0},
                    checker,
                    expected_checker_sha256=checker_sha256(checker),
                    expected_receipt_sha256=fake_sha("receipt"),
                )

    def test_bool_pick_is_rejected_before_checker(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            checker = _write_checker(td)
            receipt = _receipt()
            receipt["certificate"]["pick"] = False
            with self.assertRaises(CertificateError):
                verify_codebook_pick(
                    receipt,
                    checker,
                    expected_checker_sha256=checker_sha256(checker),
                    expected_receipt_sha256=codebook_receipt_sha256(receipt),
                )

    def test_wrong_receipt_digest_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            checker = _write_checker(td)
            with self.assertRaises(CertificateError):
                _bridge(_valid_payload(), _receipt(), checker, receipt_sha256=fake_sha("other-receipt"))

    def test_wrong_checker_digest_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            checker = _write_checker(td)
            with self.assertRaises(CertificateError):
                _bridge(_valid_payload(), _receipt(), checker, checker_sha256=fake_sha("other-checker"))

    def test_wrong_arm_and_budget_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            checker = _write_checker(td)
            with self.assertRaises(CertificateError):
                _bridge(_valid_payload(), _receipt(), checker, arm="E8:p1")
            with self.assertRaises(CertificateError):
                _bridge(_valid_payload(), _receipt(), checker, budget=(1, 1))

    def test_receipt_for_another_matrix_is_rejected_by_digest(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            checker = _write_checker(td)
            other = _receipt()
            other["certificate"]["candidates"][0]["terms"]["sum_sq"] = "9"
            with self.assertRaises(CertificateError):
                _bridge(_valid_payload(), other, checker, receipt_sha256=codebook_receipt_sha256(_receipt()))

    def test_valid_bridge_returns_all_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            checker = _write_checker(td)
            result = _bridge(_valid_payload(), _receipt(), checker)
            self.assertTrue(result.passed)
            self.assertEqual(result.quant_dtype, QUANT)
            self.assertEqual(result.projector_epoch, EPOCH)
            self.assertEqual(result.factor_digest, FACTOR)
            self.assertEqual(result.codebook.receipt_sha256, codebook_receipt_sha256(_receipt()))
            self.assertEqual(result.codebook.checker_sha256, checker_sha256(checker))


class TestFormatAndPayloadBinding(unittest.TestCase):
    def test_mismatched_quantization_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            checker = _write_checker(td)
            payload = _valid_payload()
            changed = dict(payload, quant_dtype="siliquant_e8")
            changed["weft_sha256"] = weft_body_sha256(
                {key: changed[key] for key in (
                    "radix_scale_exp2", "frobenius_sq_scaled", "spectral_norm_sq_scaled",
                    "leakage_energy_scaled", "max_safety_dot_sq_scaled", "projector_epoch",
                    "factor_digest", "quant_dtype",
                )}
            )
            with self.assertRaises(CertificateError):
                _bridge(changed, _receipt(), checker, quant_dtype=QUANT)

    def test_mismatched_epoch_and_factor_digest_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            checker = _write_checker(td)
            payload = _valid_payload()
            with self.assertRaises(CertificateError):
                _bridge(payload, _receipt(), checker, projector_epoch=EPOCH + 1)
            with self.assertRaises(CertificateError):
                _bridge(payload, _receipt(), checker, factor_digest=fake_sha("other-factor"))

    def test_mismatched_weft_digest_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            checker = _write_checker(td)
            with self.assertRaises(CertificateError):
                _bridge(_valid_payload(), _receipt(), checker, weft_sha256=fake_sha("other-weft"))


@unittest.skipUnless(os.environ.get("SILIQUANT_CHECKER_PATH"), "set SILIQUANT_CHECKER_PATH to run")
class TestRealSiliquantChecker(unittest.TestCase):
    def test_real_checker_self_checks_and_synthetic_receipt(self) -> None:
        checker = Path(os.environ["SILIQUANT_CHECKER_PATH"])
        module, digest = load_siliquant_checker(checker, expected_checker_sha256=checker_sha256(checker))
        self.assertTrue(module.identities())
        self.assertTrue(module.pi_bounds_hold())
        result = _bridge(_valid_payload(), _receipt(), checker)
        self.assertTrue(result.passed)
        self.assertEqual(result.codebook.checker_sha256, digest)
        self.assertEqual(result.codebook.pick, 0)

    def test_real_checker_rejects_bool_pick(self) -> None:
        checker = Path(os.environ["SILIQUANT_CHECKER_PATH"])
        receipt = _receipt()
        receipt["certificate"]["pick"] = False
        with self.assertRaises(CertificateError):
            verify_codebook_pick(
                receipt,
                checker,
                expected_checker_sha256=checker_sha256(checker),
                expected_receipt_sha256=codebook_receipt_sha256(receipt),
            )


if __name__ == "__main__":
    unittest.main()
