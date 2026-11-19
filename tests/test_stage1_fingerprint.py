"""Stage 1 tests: 4-layer checkpoint, Plane 1 lineage, and 5th runtime-flag digest."""

from __future__ import annotations

import hashlib
from pathlib import Path
import tempfile
import unittest

from warp_modeld.errors import (
    CheckpointMismatchError,
    ContestedLineageError,
    RuntimeFlagDriftError,
    StaleLineageError,
)
from warp_modeld.fingerprint import AdapterBundle, Plane1Lineage, RuntimeFlags, verify_stage1

from tests.helpers import (
    fake_sha,
    make_adapter_bundle_dict,
    make_checkpoint,
    make_lineage,
    make_modeld,
    make_runtime_flags,
)
from tests.mock_llama_server import MockLlamaServer


class TestStage1Fingerprint(unittest.TestCase):
    def test_valid_stage1_with_disk_file_verification(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            adapter_file = Path(td) / "corpus-f16.gguf"
            raw_bytes = b"GGUF-mock-f16-lora-weights-bytes"
            adapter_file.write_bytes(raw_bytes)
            digest = hashlib.sha256(raw_bytes).hexdigest()

            raw = make_adapter_bundle_dict(adapter_path=str(adapter_file), adapter_sha256=digest)
            bundle = AdapterBundle.from_dict(raw)
            report = verify_stage1(bundle, make_checkpoint(), make_lineage(), make_runtime_flags())
            self.assertEqual(report.adapter_id, "mde:corpus")
            self.assertTrue(report.adapter_file_verified)

    def test_rejects_on_disk_adapter_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            adapter_file = Path(td) / "corpus-f16.gguf"
            adapter_file.write_bytes(b"original-bytes")
            digest = hashlib.sha256(b"original-bytes").hexdigest()
            adapter_file.write_bytes(b"tampered-bytes")

            bundle = AdapterBundle.from_dict(
                make_adapter_bundle_dict(adapter_path=str(adapter_file), adapter_sha256=digest)
            )
            with self.assertRaises(CheckpointMismatchError):
                verify_stage1(bundle, make_checkpoint(), make_lineage(), make_runtime_flags())

    def test_rejects_every_checkpoint_layer_mismatch(self) -> None:
        for field in (
            "layout_sha256",
            "weights_sha256",
            "config_sha256",
            "tokenizer_sha256",
            "chat_template_sha256",
            "safetensors_provenance_sha256",
        ):
            raw = make_adapter_bundle_dict()
            raw["checkpoint"][field] = fake_sha(f"mutated-{field}")
            bundle = AdapterBundle.from_dict(raw)
            with self.subTest(field=field):
                with self.assertRaises(CheckpointMismatchError):
                    verify_stage1(bundle, make_checkpoint(), make_lineage(), make_runtime_flags())

    def test_rejects_stale_lineage_corpus_and_domain_commit(self) -> None:
        raw_corpus_drift = make_adapter_bundle_dict()
        raw_corpus_drift["source_lineage"]["corpus_tree_sha256"] = fake_sha("older-corpus-tree")
        with self.assertRaises(StaleLineageError) as ctx:
            verify_stage1(
                AdapterBundle.from_dict(raw_corpus_drift),
                make_checkpoint(),
                make_lineage(),
                make_runtime_flags(),
            )
        self.assertEqual(ctx.exception.code, "ERR_STALE_LINEAGE")

        raw_domain_drift = make_adapter_bundle_dict()
        raw_domain_drift["source_lineage"]["domain_commits"]["corpus"] = "deadbeef0123456789"
        with self.assertRaises(StaleLineageError):
            verify_stage1(
                AdapterBundle.from_dict(raw_domain_drift),
                make_checkpoint(),
                make_lineage(),
                make_runtime_flags(),
            )

    def test_rejects_contested_plane1_heads(self) -> None:
        pinned = Plane1Lineage(
            corpus_tree_sha256=make_lineage().corpus_tree_sha256,
            domain_commits=make_lineage().domain_commits,
            contested_heads=("head-a", "head-b"),
        )
        bundle = AdapterBundle.from_dict(make_adapter_bundle_dict())
        with self.assertRaises(ContestedLineageError) as ctx:
            verify_stage1(bundle, make_checkpoint(), pinned, make_runtime_flags())
        self.assertEqual(ctx.exception.code, "ERR_CONTESTED_LINEAGE")

    def test_rejects_runtime_flag_drift_and_unsafe_lora_init(self) -> None:
        bundle = AdapterBundle.from_dict(make_adapter_bundle_dict())

        # Drifted ctx_size on live llama-server fails Stage 1.
        drifted_flags = RuntimeFlags(
            llama_server_commit="7fe450e19",
            quantization="Q4_K_M",
            ctx_size=32768,
            kv_cache_type="q8_0",
            ctx_checkpoints=0,
            swa_checkpoints=0,
            lora_init_without_apply=True,
            chat_template_args="thinking=off",
        )
        with self.assertRaises(RuntimeFlagDriftError) as ctx:
            verify_stage1(bundle, make_checkpoint(), make_lineage(), drifted_flags)
        self.assertEqual(ctx.exception.code, "ERR_RUNTIME_FLAG_DRIFT")

        # Missing --lora-init-without-apply fails closed immediately.
        unsafe_flags = RuntimeFlags(
            llama_server_commit="7fe450e19",
            quantization="Q4_K_M",
            ctx_size=16384,
            kv_cache_type="q8_0",
            ctx_checkpoints=0,
            swa_checkpoints=0,
            lora_init_without_apply=False,
            chat_template_args="thinking=off",
        )
        with self.assertRaises(RuntimeFlagDriftError) as unsafe_ctx:
            verify_stage1(bundle, make_checkpoint(), make_lineage(), unsafe_flags)
        self.assertEqual(unsafe_ctx.exception.code, "ERR_UNSAFE_RUNTIME_FLAGS")

    def test_stage1_failure_never_touches_llama_server_gpu(self) -> None:
        mock = MockLlamaServer()
        url = mock.start()
        try:
            with tempfile.TemporaryDirectory() as td:
                modeld = make_modeld(url, Path(td))
                stale = make_adapter_bundle_dict()
                stale["source_lineage"]["corpus_tree_sha256"] = fake_sha("stale-tree")

                with self.assertRaises(StaleLineageError):
                    modeld.mount_stack([stale])

                # Stage 1 MUST fail closed before making a single HTTP call to llama-server.
                self.assertEqual(len(mock.state.request_log), 0)
                self.assertEqual(modeld.ledger.count, 1)
        finally:
            mock.stop()

    def test_rejects_duplicate_llama_adapter_id_in_stack(self) -> None:
        mock = MockLlamaServer()
        url = mock.start()
        try:
            with tempfile.TemporaryDirectory() as td:
                modeld = make_modeld(url, Path(td))
                a = make_adapter_bundle_dict(adapter_id="mde:corpus", domain="corpus", llama_adapter_id=0)
                b = make_adapter_bundle_dict(adapter_id="mde:weft-eido", domain="weft-eido", llama_adapter_id=0)
                with self.assertRaises(Exception) as ctx:
                    modeld.mount_stack([a, b])
                self.assertEqual(getattr(ctx.exception, "code", None), "ERR_DUPLICATE_ADAPTER_ID")
                self.assertEqual(len(mock.state.request_log), 0)
        finally:
            mock.stop()


if __name__ == "__main__":
    unittest.main()
