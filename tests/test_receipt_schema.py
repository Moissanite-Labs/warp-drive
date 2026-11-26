"""Receipt schema load and validation checks.

The controller runs against local fakes only. No live model, GPU, paid
provider, or network backend is used.

This module must import and run on a stdlib-only Python: the jsonschema
validator tests are skipped when jsonschema is not installed, and the
structural checks below only need the standard library. The fakes from
tests.test_experiment_controller (which imports pytest) are imported
lazily inside the jsonschema-gated tests only.
"""

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

try:
    from jsonschema import Draft7Validator, ValidationError
except ImportError:  # stdlib-only environment: validator tests skip below
    Draft7Validator = None
    ValidationError = None

from warp_modeld.experiment import ExperimentController, ReceiptLog, load_contract

ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "experiments" / "demo-2026-11-22"
SCHEMA_PATH = DEMO / "receipt.schema.json"

REQUIRES_JSONSCHEMA = unittest.skipUnless(
    Draft7Validator is not None, "jsonschema is not installed"
)


def _load_schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def _const_permits(prop, value) -> bool:
    """Stdlib-only reading of a JSON Schema const constraint."""
    if isinstance(prop, dict) and "const" in prop:
        return value == prop["const"]
    if isinstance(prop, str):
        return value == prop
    return False


def _run_fake_experiment_receipt() -> dict:
    """Emit one real receipt through the fake controller."""
    from tests.test_experiment_controller import (
        ENVIRONMENT,
        EXP,
        PARENT_SHA,
        FakeCompiler,
        FakeLifecycle,
        FakeRuntime,
    )

    contract = load_contract(EXP)
    with tempfile.TemporaryDirectory() as td:
        controller = ExperimentController(
            contract=contract,
            compiler=FakeCompiler(),
            runtime=FakeRuntime(),
            lifecycle=FakeLifecycle(),
            receipts=ReceiptLog(Path(td) / "receipts.jsonl"),
            environment=ENVIRONMENT,
        )
        verdict, receipt = controller.run_experiment(
            {"eta": 0.01, "lambda": 1, "lora_scale": 1.0, "quant": "bf16"},
            actual_parent_sha256=PARENT_SHA,
        )
        assert verdict.verdict == "ACCEPT"
        return receipt


class TestReceiptSchema(unittest.TestCase):
    def test_receipt_schema_version_is_const_010(self) -> None:
        schema = _load_schema()
        self.assertEqual(
            schema["properties"]["receipt_schema_version"], {"const": "0.1.0"}
        )

    def test_version_011_not_permitted_by_schema(self) -> None:
        prop = _load_schema()["properties"]["receipt_schema_version"]
        self.assertTrue(_const_permits(prop, "0.1.0"))
        self.assertFalse(_const_permits(prop, "0.1.1"))

    @REQUIRES_JSONSCHEMA
    def test_schema_loads(self) -> None:
        Draft7Validator.check_schema(_load_schema())

    @REQUIRES_JSONSCHEMA
    def test_emitted_receipt_validates(self) -> None:
        validator = Draft7Validator(_load_schema())
        validator.validate(_run_fake_experiment_receipt())

    @REQUIRES_JSONSCHEMA
    def test_emitted_receipt_with_version_011_fails(self) -> None:
        validator = Draft7Validator(_load_schema())
        receipt = _run_fake_experiment_receipt()
        receipt["receipt_schema_version"] = "0.1.1"
        self.assertFalse(validator.is_valid(receipt))
        with self.assertRaises(ValidationError):
            validator.validate(receipt)

    def test_manifest_digest_and_checksum(self) -> None:
        manifest_bytes = (DEMO / "manifest.json").read_bytes()
        recorded = (DEMO / "manifest.sha256").read_text(encoding="utf-8").split()[0]
        self.assertEqual(hashlib.sha256(manifest_bytes).hexdigest(), recorded)

        manifest = json.loads(manifest_bytes)
        schema_digest = hashlib.sha256(SCHEMA_PATH.read_bytes()).hexdigest()
        self.assertEqual(manifest["digests"]["receipt_schema"], schema_digest)
        self.assertEqual(manifest["manifest_version"], "0.1.2")


if __name__ == "__main__":
    unittest.main()
