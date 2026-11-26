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
    WEFT_BODY_FIELDS,
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
        radix_scale_exp2=payload["radix_scale_exp2"],
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


def _body_of(payload: dict) -> dict:
    return {key: payload[key] for key in WEFT_BODY_FIELDS}


def _expectations_kwargs(**overrides) -> dict:
    base = dict(
        quant_dtype=QUANT,
        radix_scale_exp2=32,
        projector_epoch=EPOCH,
        factor_digest=FACTOR,
        weft_sha256=fake_sha("weft"),
        arm=ARM,
        budget=BUDGET,
        receipt_sha256=fake_sha("receipt"),
        checker_sha256=fake_sha("checker"),
    )
    base.update(overrides)
    return base


class TestWD41ReviewWitnesses(unittest.TestCase):
    """Regression tests for the blocking WD41-01..WD41-06 witnesses from review abu-aska."""

    # --- WD41-01: weft_sha256 is mandatory and validated on the default path ---

    def test_weft_sha256_none_fails_closed_on_default_path(self) -> None:
        payload = _valid_payload()
        payload["weft_sha256"] = None
        with self.assertRaises(CertificateError):
            ingest_weft_certificate(payload)

    def test_tampered_metrics_with_none_weft_sha_fail_closed(self) -> None:
        # Review witness: frobenius inflated and leakage zeroed with weft_sha256=None
        # used to return a valid certificate (fail-open).
        payload = _valid_payload()
        payload["frobenius_sq_scaled"] = 999 * RADIX
        payload["leakage_energy_scaled"] = 0
        payload["weft_sha256"] = None
        with self.assertRaises(CertificateError):
            ingest_weft_certificate(payload)

    def test_malformed_weft_sha256_raises_certificate_error_not_typeerror(self) -> None:
        for bad in (None, 123, "é" * 64, "\ud800" * 64):
            with self.subTest(bad=ascii(bad)[:24]):
                payload = _valid_payload()
                payload["weft_sha256"] = bad
                with self.assertRaises(CertificateError):
                    ingest_weft_certificate(payload)
                with self.assertRaises(CertificateError):
                    ingest_weft_certificate(payload, expected_weft_sha256=fake_sha("expected"))

    # --- WD41-02: checker self-checks and findings are strictly typed ---

    @staticmethod
    def _checker_body(check_return: str, identities: str = "True", pi: str = "True") -> str:
        return (
            "def identities():\n    return " + identities + "\n\n"
            "def pi_bounds_hold():\n    return " + pi + "\n\n"
            "def check(cert):\n    return " + check_return + "\n"
        )

    def _pick(self, checker: Path) -> None:
        receipt = _receipt()
        verify_codebook_pick(
            receipt,
            checker,
            expected_checker_sha256=checker_sha256(checker),
            expected_receipt_sha256=codebook_receipt_sha256(receipt),
        )

    def test_falsy_check_findings_fail_closed(self) -> None:
        for ret in ("None", "0", "False", '""'):
            with self.subTest(check_return=ret):
                with tempfile.TemporaryDirectory() as td:
                    checker = _write_checker(td, self._checker_body(ret))
                    with self.assertRaises(CertificateError):
                        self._pick(checker)

    def test_truthy_non_bool_self_checks_fail_closed(self) -> None:
        for identities, pi in (('"FAIL"', "True"), ("True", '"NO"')):
            with self.subTest(identities=identities, pi=pi):
                with tempfile.TemporaryDirectory() as td:
                    checker = _write_checker(td, self._checker_body("[]", identities, pi))
                    with self.assertRaises(CertificateError):
                        self._pick(checker)

    def test_non_sliceable_findings_raise_certificate_error_not_typeerror(self) -> None:
        for ret in ("{'bad'}", "1"):
            with self.subTest(check_return=ret):
                with tempfile.TemporaryDirectory() as td:
                    checker = _write_checker(td, self._checker_body(ret))
                    with self.assertRaises(CertificateError):
                        self._pick(checker)

    # --- WD41-03: checker path is pinned, symlink-free and type-validated ---

    def test_unpinned_checker_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            checker = _write_checker(td)
            with self.assertRaises(CertificateError):
                load_siliquant_checker(checker)

    def test_symlinked_checker_is_never_executed(self) -> None:
        marker_body = (
            FAKE_CHECKER_OK
            + "\nfrom pathlib import Path as _P\n_P(__file__).with_name('EXECUTED').write_text('yes')\n"
        )
        with tempfile.TemporaryDirectory() as td:
            real = _write_checker(td, marker_body)
            link = Path(td) / "link_checker.py"
            link.symlink_to(real)
            # Even with the digest pinned to the symlink target, the symlink is refused.
            with self.assertRaises(CertificateError):
                load_siliquant_checker(link, expected_checker_sha256=checker_sha256(real))
            self.assertFalse((Path(td) / "EXECUTED").exists())

    def test_symlinked_ancestor_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            real_dir = Path(td) / "real"
            real_dir.mkdir()
            real = _write_checker(str(real_dir))
            link_dir = Path(td) / "linkdir"
            link_dir.symlink_to(real_dir, target_is_directory=True)
            with self.assertRaises(CertificateError):
                load_siliquant_checker(
                    link_dir / "check_certificate.py",
                    expected_checker_sha256=checker_sha256(real),
                )

    def test_non_path_checker_inputs_raise_certificate_error(self) -> None:
        for bad in (123, None, b"/tmp/checker.py", "/tmp/\ud800.py", "/tmp/a\x00b.py"):
            with self.subTest(bad=ascii(bad)[:24]):
                with self.assertRaises(CertificateError):
                    load_siliquant_checker(bad, expected_checker_sha256=fake_sha("c"))  # type: ignore[arg-type]
                with self.assertRaises(CertificateError):
                    checker_sha256(bad)  # type: ignore[arg-type]

    # --- WD41-05: digit caps, NaN rejection, lone-surrogate rejection ---

    def test_huge_decimal_strings_and_ints_raise_certificate_error(self) -> None:
        receipt = _receipt()
        receipt["certificate"]["candidates"][0]["terms"]["sum_sq"] = "9" * 4301
        with self.assertRaises(CertificateError):
            codebook_receipt_sha256(receipt)
        receipt = _receipt()
        receipt["certificate"]["candidates"][0]["terms"]["sum_sq"] = 10 ** 5000
        with self.assertRaises(CertificateError):
            codebook_receipt_sha256(receipt)
        receipt = _receipt()
        receipt["certificate"]["budget"] = [10 ** 5000, 1]
        with self.assertRaises(CertificateError):
            codebook_receipt_sha256(receipt)

    def test_generate_rejects_huge_radix_and_norms_with_certificate_error(self) -> None:
        with self.assertRaises(CertificateError):
            generate_fixed_radix_certificate(
                ADAPTER, ADAPTER_SHA, BASE_SHA,
                frobenius_sq=RADIX, spectral_norm_sq=RADIX // 4,
                leakage_energy=0, max_safety_dot_sq=0,
                radix_scale_exp2=10 ** 5000,
                projector_epoch=EPOCH, factor_digest=FACTOR, quant_dtype=QUANT,
            )
        with self.assertRaises(CertificateError):
            generate_fixed_radix_certificate(
                ADAPTER, ADAPTER_SHA, BASE_SHA,
                frobenius_sq=10 ** 5000, spectral_norm_sq=10 ** 5000,
                leakage_energy=0, max_safety_dot_sq=0,
                projector_epoch=EPOCH, factor_digest=FACTOR, quant_dtype=QUANT,
            )

    def test_weft_body_sha256_rejects_nan_and_huge_ints(self) -> None:
        body = _body_of(_valid_payload())
        body["frobenius_sq_scaled"] = float("nan")
        with self.assertRaises(CertificateError):
            weft_body_sha256(body)
        body = _body_of(_valid_payload())
        body["frobenius_sq_scaled"] = 10 ** 5000
        with self.assertRaises(CertificateError):
            weft_body_sha256(body)

    def test_lone_surrogate_adapter_id_rejected(self) -> None:
        with self.assertRaises(CertificateError):
            generate_fixed_radix_certificate(
                "mde:\ud800", ADAPTER_SHA, BASE_SHA,
                frobenius_sq=RADIX, spectral_norm_sq=RADIX // 4,
                leakage_energy=RADIX // 1000, max_safety_dot_sq=RADIX // 10000,
                projector_epoch=EPOCH, factor_digest=FACTOR, quant_dtype=QUANT,
            )
        payload = _valid_payload()
        payload["adapter_id"] = "mde:\ud800"
        with self.assertRaises(CertificateError):
            ingest_weft_certificate(payload)

    # --- WD41-06: quant/arm coherence, positive budget, pinned radix_scale_exp2 ---

    def test_expectations_reject_incoherent_quant_dtype_and_arm(self) -> None:
        SiliquantExpectations(**_expectations_kwargs())
        SiliquantExpectations(**_expectations_kwargs(quant_dtype="siliquant_e8", arm="E8:p1"))
        for arm in ("X", "Z8:p1", "Z8:p2"):
            with self.subTest(arm=arm):
                with self.assertRaises(CertificateError):
                    SiliquantExpectations(**_expectations_kwargs(quant_dtype="siliquant_e8", arm=arm))

    def test_expectations_reject_non_positive_budget_and_bad_radix(self) -> None:
        for bad in ((-5, 1), (0, 1), (1, 0), (-1, -1)):
            with self.subTest(budget=bad):
                with self.assertRaises(CertificateError):
                    SiliquantExpectations(**_expectations_kwargs(budget=bad))
                receipt = _receipt()
                receipt["certificate"]["budget"] = list(bad)
                with self.assertRaises(CertificateError):
                    codebook_receipt_sha256(receipt)
        for bad_exp2 in (0, 7, 49, "32", True):
            with self.subTest(radix_scale_exp2=bad_exp2):
                with self.assertRaises(CertificateError):
                    SiliquantExpectations(**_expectations_kwargs(radix_scale_exp2=bad_exp2))

    def test_radix_scale_exp2_pinning_rejects_relabeled_payload(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            checker = _write_checker(td)
            # Inflated frobenius that the 5.0 bound rejects at exp2=32 but that would
            # pass if the payload could relabel its own radix scale to 48.
            relabeled = generate_fixed_radix_certificate(
                ADAPTER, ADAPTER_SHA, BASE_SHA,
                frobenius_sq=100 * (1 << 32), spectral_norm_sq=(1 << 32) // 4,
                leakage_energy=0, max_safety_dot_sq=0,
                radix_scale_exp2=48,
                projector_epoch=EPOCH, factor_digest=FACTOR, quant_dtype=QUANT,
            )
            with self.assertRaises(CertificateError):
                _bridge(relabeled, _receipt(), checker, radix_scale_exp2=32)
            # Control: only an explicitly pinned exp2=48 gets past the radix pin.
            result = _bridge(relabeled, _receipt(), checker, radix_scale_exp2=48)
            self.assertTrue(result.passed)

    def test_bridge_rejects_incoherent_expectations_end_to_end(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            checker = _write_checker(td)
            with self.assertRaises(CertificateError):
                _bridge(_valid_payload(), _receipt(), checker, quant_dtype="siliquant_e8", arm="X")


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
