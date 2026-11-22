"""Receipt schema load and validation checks.

The controller runs against local fakes only. No live model, GPU, paid
provider, or network backend is used.
"""

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft7Validator

from tests.test_experiment_controller import (
    ENVIRONMENT,
    EXP,
    PARENT_SHA,
    FakeCompiler,
    FakeLifecycle,
    FakeRuntime,
)
from warp_modeld.experiment import ExperimentController, ReceiptLog, load_contract

ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "experiments" / "demo-2026-11-22"
SCHEMA_PATH = DEMO / "receipt.schema.json"


class TestReceiptSchema(unittest.TestCase):
    def test_schema_loads(self) -> None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft7Validator.check_schema(schema)

    def test_emitted_receipt_validates(self) -> None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        validator = Draft7Validator(schema)
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
            self.assertEqual(verdict.verdict, "ACCEPT")
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
